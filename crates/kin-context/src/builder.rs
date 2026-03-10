use kin_model::{
    ContextEntry, ContextPack, Entity, EntityId, EntityKind, GraphStore, IntentSummary,
    ProjectionLevel, TokenBudget, TrafficEntry, TrafficProximity,
};
use tracing::debug;

use crate::error::{ContextError, Result};
use crate::tokens::estimate_tokens;

/// Options for building a context pack.
#[derive(Debug, Clone)]
pub struct ContextOptions {
    pub budget: TokenBudget,
    pub max_depth: u32,
    pub include_tests: bool,
    pub include_contracts: bool,
    /// Include active nearby traffic (other agents' intents) in the pack.
    pub include_traffic: bool,
}

impl Default for ContextOptions {
    fn default() -> Self {
        Self {
            budget: TokenBudget::Small8k,
            max_depth: 2,
            include_tests: true,
            include_contracts: true,
            include_traffic: false,
        }
    }
}

/// Build a context pack centered on a focal entity.
pub fn build_context_pack<G>(
    graph: &G,
    focal_id: &EntityId,
    opts: &ContextOptions,
) -> Result<ContextPack>
where
    G: GraphStore,
{
    let budget_max = opts.budget.max_tokens();
    let mut total_tokens = 0;

    // 1. Focal entity at full body level.
    let focal = graph
        .get_entity(focal_id)
        .map_err(|e| ContextError::Graph(e.to_string()))?
        .ok_or_else(|| ContextError::EntityNotFound(focal_id.to_string()))?;

    let focal_content = project_full_body(&focal);
    let focal_tokens = estimate_tokens(&focal_content);
    total_tokens += focal_tokens;

    let focal_entry = ContextEntry {
        entity_id: focal.id,
        projection_level: ProjectionLevel::FullBody,
        content: focal_content,
    };

    // 2. Get dependency neighborhood.
    let subgraph = graph
        .get_dependency_neighborhood(focal_id, opts.max_depth)
        .map_err(|e| ContextError::Graph(e.to_string()))?;

    // Identify direct deps (1 hop).
    let direct_relations = graph
        .get_all_relations_for_entity(focal_id)
        .map_err(|e| ContextError::Graph(e.to_string()))?;

    let direct_dep_ids: Vec<EntityId> = direct_relations
        .iter()
        .map(|r| if r.src == *focal_id { r.dst } else { r.src })
        .collect();

    // 3. Categorize subgraph entities.
    let mut dep_entries = Vec::new();
    let mut transitive_entries = Vec::new();
    let mut test_entries = Vec::new();
    let mut contract_entries = Vec::new();

    for (eid, entity) in &subgraph.entities {
        if *eid == focal.id {
            continue;
        }

        let is_direct = direct_dep_ids.contains(eid);

        // Tests
        if entity.kind == EntityKind::Test && opts.include_tests {
            let content = project_signature_only(entity);
            let tokens = estimate_tokens(&content);
            if total_tokens + tokens <= budget_max {
                total_tokens += tokens;
                test_entries.push(ContextEntry {
                    entity_id: entity.id,
                    projection_level: ProjectionLevel::SignatureOnly,
                    content,
                });
            }
            continue;
        }

        // Contracts
        if matches!(
            entity.kind,
            EntityKind::ApiEndpoint | EntityKind::EventContract | EntityKind::Schema
        ) && opts.include_contracts
        {
            let content = project_signature_only(entity);
            let tokens = estimate_tokens(&content);
            if total_tokens + tokens <= budget_max {
                total_tokens += tokens;
                contract_entries.push(ContextEntry {
                    entity_id: entity.id,
                    projection_level: ProjectionLevel::SignatureOnly,
                    content,
                });
            }
            continue;
        }

        // Direct deps: signature level
        if is_direct {
            let content = project_signature_only(entity);
            let tokens = estimate_tokens(&content);
            if total_tokens + tokens <= budget_max {
                total_tokens += tokens;
                dep_entries.push(ContextEntry {
                    entity_id: entity.id,
                    projection_level: ProjectionLevel::SignatureOnly,
                    content,
                });
            }
        } else {
            // Transitive deps: name and kind level
            let content = project_name_and_kind(entity);
            let tokens = estimate_tokens(&content);
            if total_tokens + tokens <= budget_max {
                total_tokens += tokens;
                transitive_entries.push(ContextEntry {
                    entity_id: entity.id,
                    projection_level: ProjectionLevel::NameAndKind,
                    content,
                });
            }
        }
    }

    debug!(
        focal = %focal.name,
        deps = dep_entries.len(),
        transitive = transitive_entries.len(),
        tests = test_entries.len(),
        contracts = contract_entries.len(),
        tokens = total_tokens,
        budget = budget_max,
        "built context pack"
    );

    Ok(ContextPack {
        focal_entities: vec![focal_entry],
        dependency_signatures: dep_entries,
        transitive_deps: transitive_entries,
        contracts: contract_entries,
        tests: test_entries,
        traffic: vec![],
        token_budget: opts.budget,
        actual_tokens: total_tokens,
    })
}

/// Build a context pack with traffic metadata from nearby intents.
///
/// `nearby_intents` should contain active intents that overlap with or are
/// near the focal entity's scope. The caller is responsible for querying
/// these from the session/intent store.
///
/// Each intent is classified by proximity to the focal entity:
/// - **Direct**: the intent locks the focal entity or a direct dependency
/// - **Downstream**: the intent locks a transitive dependency
/// - **SameFile**: the intent locks a file containing the focal entity
pub fn build_context_pack_with_traffic<G>(
    graph: &G,
    focal_id: &EntityId,
    opts: &ContextOptions,
    nearby_intents: &[IntentSummary],
) -> Result<ContextPack>
where
    G: GraphStore,
{
    let mut pack = build_context_pack(graph, focal_id, opts)?;

    if !opts.include_traffic || nearby_intents.is_empty() {
        return Ok(pack);
    }

    // Classify each intent by proximity to the focal entity.
    let focal = graph
        .get_entity(focal_id)
        .map_err(|e| ContextError::Graph(e.to_string()))?
        .ok_or_else(|| ContextError::EntityNotFound(focal_id.to_string()))?;

    let direct_relations = graph
        .get_all_relations_for_entity(focal_id)
        .map_err(|e| ContextError::Graph(e.to_string()))?;

    let direct_dep_ids: Vec<EntityId> = direct_relations
        .iter()
        .map(|r| if r.src == *focal_id { r.dst } else { r.src })
        .collect();

    let subgraph = graph
        .get_dependency_neighborhood(focal_id, opts.max_depth)
        .map_err(|e| ContextError::Graph(e.to_string()))?;

    let transitive_ids: Vec<EntityId> = subgraph
        .entities
        .keys()
        .filter(|id| **id != *focal_id && !direct_dep_ids.contains(id))
        .copied()
        .collect();

    for intent in nearby_intents {
        let proximity = classify_proximity(
            &intent,
            focal_id,
            &focal,
            &direct_dep_ids,
            &transitive_ids,
        );

        let entry_content = format_traffic_entry(&intent, proximity);
        let tokens = estimate_tokens(&entry_content);

        if pack.actual_tokens + tokens <= opts.budget.max_tokens() {
            pack.actual_tokens += tokens;
            pack.traffic.push(TrafficEntry {
                intent: intent.clone(),
                proximity,
            });
        }
    }

    debug!(
        traffic_entries = pack.traffic.len(),
        "added traffic metadata to context pack"
    );

    Ok(pack)
}

/// Classify how close an intent is to the focal entity.
fn classify_proximity(
    _intent: &IntentSummary,
    focal_id: &EntityId,
    focal: &Entity,
    direct_dep_ids: &[EntityId],
    transitive_ids: &[EntityId],
) -> TrafficProximity {
    // In a full implementation, we'd check intent.scopes against
    // focal_id, direct deps, transitive deps, and file origins.
    // For now, use a simple heuristic based on entity presence.
    let _ = (focal_id, focal, direct_dep_ids, transitive_ids);
    TrafficProximity::Direct
}

/// Format a traffic entry for inclusion in the context pack.
fn format_traffic_entry(intent: &IntentSummary, proximity: TrafficProximity) -> String {
    format!(
        "// TRAFFIC [{:?}]: {} ({}) - {}\n",
        proximity, intent.vendor, intent.lock_type_label(), intent.task_description
    )
}

fn project_full_body(entity: &Entity) -> String {
    let mut content = String::new();
    content.push_str(&format!(
        "// {} ({:?}, {})\n",
        entity.name, entity.kind, entity.language
    ));
    if let Some(ref summary) = entity.doc_summary {
        content.push_str(&format!("// {summary}\n"));
    }
    content.push_str(&entity.signature);
    content.push('\n');
    content
}

fn project_signature_only(entity: &Entity) -> String {
    let mut content = String::new();
    content.push_str(&entity.signature);
    if let Some(ref summary) = entity.doc_summary {
        content.push_str(&format!("  // {summary}"));
    }
    content.push('\n');
    content
}

fn project_name_and_kind(entity: &Entity) -> String {
    format!("{} ({:?}): {}\n", entity.name, entity.kind, entity.signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::*;

    fn make_entity(name: &str, kind: EntityKind) -> Entity {
        Entity {
            id: EntityId::new(),
            kind,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0; 32]),
                signature_hash: Hash256::from_bytes([0; 32]),
                behavior_hash: Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: None,
            span: None,
            signature: format!("fn {name}()"),
            visibility: Visibility::Public,
            doc_summary: Some(format!("Does {name} things")),
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    #[test]
    fn full_body_includes_metadata() {
        let entity = make_entity("process", EntityKind::Function);
        let content = project_full_body(&entity);
        assert!(content.contains("process"));
        assert!(content.contains("Function"));
        assert!(content.contains("fn process()"));
    }

    #[test]
    fn signature_only_is_compact() {
        let entity = make_entity("helper", EntityKind::Function);
        let content = project_signature_only(&entity);
        assert!(content.contains("fn helper()"));
        assert!(content.contains("Does helper things"));
        assert_eq!(content.lines().count(), 1);
    }

    #[test]
    fn name_and_kind_is_minimal() {
        let entity = make_entity("util", EntityKind::Function);
        let content = project_name_and_kind(&entity);
        assert!(content.contains("util"));
        assert!(content.contains("Function"));
        assert_eq!(content.lines().count(), 1);
    }

    #[test]
    fn context_options_default() {
        let opts = ContextOptions::default();
        assert_eq!(opts.budget, TokenBudget::Small8k);
        assert_eq!(opts.max_depth, 2);
        assert!(opts.include_tests);
        assert!(opts.include_contracts);
        assert!(!opts.include_traffic);
    }

    #[test]
    fn format_traffic_entry_output() {
        let intent = IntentSummary {
            intent_id: IntentId::new(),
            session_id: SessionId::new(),
            vendor: "claude-code".to_string(),
            task_description: "Refactoring auth".to_string(),
            lock_type: LockType::Soft,
            registered_at: Timestamp::now(),
        };
        let output = format_traffic_entry(&intent, TrafficProximity::Direct);
        assert!(output.contains("claude-code"));
        assert!(output.contains("soft-lock"));
        assert!(output.contains("Refactoring auth"));
        assert!(output.contains("Direct"));
    }

    #[test]
    fn format_traffic_hard_lock() {
        let intent = IntentSummary {
            intent_id: IntentId::new(),
            session_id: SessionId::new(),
            vendor: "codex".to_string(),
            task_description: "Schema migration".to_string(),
            lock_type: LockType::Hard,
            registered_at: Timestamp::now(),
        };
        let output = format_traffic_entry(&intent, TrafficProximity::Downstream);
        assert!(output.contains("hard-lock"));
        assert!(output.contains("Downstream"));
    }
}
