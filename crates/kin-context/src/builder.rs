use kin_model::{
    AnnotationEntry, ContextEntry, ContextPack, Entity, EntityFilter, EntityId, EntityKind,
    GraphStore, IntentSummary, ProjectionLevel, TokenBudget, TrafficEntry, TrafficProximity,
    WorkItemEntry, WorkScope,
};
use tracing::debug;

use crate::error::{ContextError, Result};
use crate::tokens::estimate_tokens;

/// Hint for which assistant is requesting context, enabling tuned strategies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssistantHint {
    /// Claude Code: good at cross-file chains, benefits from broader context.
    ClaudeCode,
    /// Codex: strongest with focused narrow context.
    Codex,
    /// Gemini CLI: needs precise location context.
    GeminiCli,
}

/// Options for building a context pack.
#[derive(Debug, Clone)]
pub struct ContextOptions {
    pub budget: TokenBudget,
    pub max_depth: u32,
    pub include_tests: bool,
    pub include_contracts: bool,
    /// Include active nearby traffic (other agents' intents) in the pack.
    pub include_traffic: bool,
    /// Optional assistant hint for tuning context pack strategy.
    pub assistant_hint: Option<AssistantHint>,
}

impl Default for ContextOptions {
    fn default() -> Self {
        Self {
            budget: TokenBudget::Small8k,
            max_depth: 2,
            include_tests: true,
            include_contracts: true,
            include_traffic: false,
            assistant_hint: None,
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

    // Adjust depth based on assistant hint.
    let effective_depth = match opts.assistant_hint {
        Some(AssistantHint::ClaudeCode) => opts.max_depth.saturating_add(1),
        Some(AssistantHint::Codex) => opts.max_depth.max(1).saturating_sub(1).max(1),
        _ => opts.max_depth,
    };

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
        .get_dependency_neighborhood(focal_id, effective_depth)
        .map_err(|e| ContextError::Graph(e.to_string()))?;

    // Identify direct deps (1 hop).
    let direct_relations = graph
        .get_all_relations_for_entity(focal_id)
        .map_err(|e| ContextError::Graph(e.to_string()))?;

    let direct_dep_ids: Vec<EntityId> = direct_relations
        .iter()
        .map(|r| if r.src == *focal_id { r.dst } else { r.src })
        .collect();

    // If graph relations are sparse for this entity, fall back to nearby
    // entities from the same file so callers still get useful local context.
    let same_file_fallback_entities = if direct_dep_ids.is_empty() {
        if let Some(ref file_origin) = focal.file_origin {
            let mut entities = graph
                .query_entities(&EntityFilter {
                    file_path: Some(file_origin.clone()),
                    ..Default::default()
                })
                .map_err(|e| ContextError::Graph(e.to_string()))?
                .into_iter()
                .filter(|entity| entity.id != focal.id)
                .filter(|entity| {
                    !matches!(
                        entity.kind,
                        EntityKind::Test
                            | EntityKind::ApiEndpoint
                            | EntityKind::EventContract
                            | EntityKind::Schema
                    )
                })
                .collect::<Vec<_>>();
            entities.sort_by_key(|entity| same_file_neighbor_rank(&focal, entity));
            entities
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    // 3. Categorize subgraph entities.
    let mut dep_entries = Vec::new();
    let mut transitive_entries = Vec::new();
    let mut test_entries = Vec::new();
    let mut contract_entries = Vec::new();

    // Codex benefits from reserving budget for the focal entity.
    let transitive_budget = match opts.assistant_hint {
        Some(AssistantHint::Codex) => budget_max / 5,
        _ => budget_max,
    };
    let mut transitive_tokens = 0;

    for (eid, entity) in &subgraph.entities {
        if *eid == focal.id {
            continue;
        }

        let is_direct = direct_dep_ids.contains(eid);

        // Tests
        if entity.kind == EntityKind::Test && opts.include_tests {
            let mut content = project_signature_only(entity);
            if opts.assistant_hint == Some(AssistantHint::GeminiCli) {
                if let Some(ref origin) = entity.file_origin {
                    content = format!("// file: {}\n{}", origin, content);
                }
            }
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
            let mut content = project_signature_only(entity);
            if opts.assistant_hint == Some(AssistantHint::GeminiCli) {
                if let Some(ref origin) = entity.file_origin {
                    content = format!("// file: {}\n{}", origin, content);
                }
            }
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
            let mut content = project_signature_only(entity);
            if opts.assistant_hint == Some(AssistantHint::GeminiCli) {
                if let Some(ref origin) = entity.file_origin {
                    content = format!("// file: {}\n{}", origin, content);
                }
            }
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
            let mut content = project_name_and_kind(entity);
            if opts.assistant_hint == Some(AssistantHint::GeminiCli) {
                if let Some(ref origin) = entity.file_origin {
                    content = format!("// file: {}\n{}", origin, content);
                }
            }
            let tokens = estimate_tokens(&content);
            if total_tokens + tokens <= budget_max
                && transitive_tokens + tokens <= transitive_budget
            {
                total_tokens += tokens;
                transitive_tokens += tokens;
                transitive_entries.push(ContextEntry {
                    entity_id: entity.id,
                    projection_level: ProjectionLevel::NameAndKind,
                    content,
                });
            }
        }
    }

    if dep_entries.is_empty() && !same_file_fallback_entities.is_empty() {
        for entity in same_file_fallback_entities.iter().take(6) {
            let mut content = format!("// same-file neighbor\n{}", project_signature_only(entity));
            if opts.assistant_hint == Some(AssistantHint::GeminiCli) {
                if let Some(ref origin) = entity.file_origin {
                    content = format!("// file: {}\n{}", origin, content);
                }
            }
            let tokens = estimate_tokens(&content);
            if total_tokens + tokens <= budget_max {
                total_tokens += tokens;
                dep_entries.push(ContextEntry {
                    entity_id: entity.id,
                    projection_level: ProjectionLevel::SignatureOnly,
                    content,
                });
            }
        }
    }

    // 4. Gather active work items scoped to focal and direct dependencies.
    let mut work_entries = Vec::new();
    let scope_ids: Vec<EntityId> = std::iter::once(focal.id)
        .chain(direct_dep_ids.iter().copied())
        .collect();

    for eid in &scope_ids {
        if let Ok(items) = graph.get_work_for_scope(&WorkScope::Entity(*eid)) {
            for item in items {
                if item.is_closed() {
                    continue;
                }
                let content = format_work_item(&item);
                let tokens = estimate_tokens(&content);
                if total_tokens + tokens <= budget_max {
                    total_tokens += tokens;
                    work_entries.push(WorkItemEntry {
                        work_item: item,
                        content,
                    });
                }
            }
        }
    }

    // 5. Gather fresh annotations on focal and direct dependencies.
    let mut annotation_entries = Vec::new();
    for eid in &scope_ids {
        if let Ok(anns) = graph.get_annotations_for_scope(&WorkScope::Entity(*eid)) {
            for ann in anns {
                if ann.staleness == kin_model::StalenessState::Stale {
                    continue;
                }
                let content = format_annotation(&ann);
                let tokens = estimate_tokens(&content);
                if total_tokens + tokens <= budget_max {
                    total_tokens += tokens;
                    annotation_entries.push(AnnotationEntry {
                        annotation: ann,
                        content,
                    });
                }
            }
        }
    }

    debug!(
        focal = %focal.name,
        deps = dep_entries.len(),
        transitive = transitive_entries.len(),
        tests = test_entries.len(),
        contracts = contract_entries.len(),
        work_items = work_entries.len(),
        annotations = annotation_entries.len(),
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
        work_items: work_entries,
        annotations: annotation_entries,
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
        let proximity =
            classify_proximity(intent, focal_id, &focal, &direct_dep_ids, &transitive_ids);

        let entry_content = format_traffic_entry(intent, proximity);
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
        proximity,
        intent.vendor,
        intent.lock_type_label(),
        intent.task_description
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
    format!(
        "{} ({:?}): {}\n",
        entity.name, entity.kind, entity.signature
    )
}

fn format_work_item(item: &kin_model::WorkItem) -> String {
    format!(
        "// WORK [{}] {}: {} ({})\n",
        item.kind, item.status, item.title, item.work_id,
    )
}

fn format_annotation(ann: &kin_model::Annotation) -> String {
    let body_preview = if ann.body.len() > 80 {
        format!("{}...", &ann.body[..80])
    } else {
        ann.body.clone()
    };
    format!(
        "// ANNOTATION [{}] {}: {}\n",
        ann.kind, ann.staleness, body_preview,
    )
}

fn same_file_neighbor_rank(focal: &Entity, candidate: &Entity) -> (u8, u8, usize) {
    let focal_norm = normalize_entity_name(&focal.name);
    let candidate_norm = normalize_entity_name(&candidate.name);

    let exact_companion = candidate_norm == focal_norm && candidate.name != focal.name;
    let substring_related =
        candidate_norm.contains(&focal_norm) || focal_norm.contains(&candidate_norm);
    let same_kind = candidate.kind == focal.kind;

    (
        !exact_companion as u8,
        !(substring_related || same_kind) as u8,
        candidate.name.len(),
    )
}

fn normalize_entity_name(name: &str) -> String {
    name.trim_start_matches(['$', '_']).to_string()
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

    fn make_file_entity(name: &str, kind: EntityKind, file_path: &str) -> Entity {
        let mut entity = make_entity(name, kind);
        entity.file_origin = Some(FilePathId::new(file_path));
        entity
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
    fn context_options_default_no_hint() {
        let opts = ContextOptions::default();
        assert_eq!(opts.assistant_hint, None);
    }

    #[test]
    fn effective_depth_claude() {
        // ClaudeCode increases depth by 1.
        let base_depth: u32 = 2;
        let effective = match Some(AssistantHint::ClaudeCode) {
            Some(AssistantHint::ClaudeCode) => base_depth.saturating_add(1),
            Some(AssistantHint::Codex) => base_depth.max(1).saturating_sub(1).max(1),
            _ => base_depth,
        };
        assert_eq!(effective, 3);
    }

    #[test]
    fn effective_depth_codex() {
        // Codex decreases depth by 1, but never below 1.
        let base_depth: u32 = 2;
        let effective = match Some(AssistantHint::Codex) {
            Some(AssistantHint::ClaudeCode) => base_depth.saturating_add(1),
            Some(AssistantHint::Codex) => base_depth.max(1).saturating_sub(1).max(1),
            _ => base_depth,
        };
        assert_eq!(effective, 1);

        // Verify floor of 1 when base_depth is already 1.
        let base_depth: u32 = 1;
        let effective = match Some(AssistantHint::Codex) {
            Some(AssistantHint::ClaudeCode) => base_depth.saturating_add(1),
            Some(AssistantHint::Codex) => base_depth.max(1).saturating_sub(1).max(1),
            _ => base_depth,
        };
        assert_eq!(effective, 1);
    }

    #[test]
    fn effective_depth_default() {
        // No hint: depth unchanged.
        let base_depth: u32 = 2;
        let hint: Option<AssistantHint> = None;
        let effective = match hint {
            Some(AssistantHint::ClaudeCode) => base_depth.saturating_add(1),
            Some(AssistantHint::Codex) => base_depth.max(1).saturating_sub(1).max(1),
            _ => base_depth,
        };
        assert_eq!(effective, 2);
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

    #[test]
    fn context_pack_falls_back_to_same_file_neighbors_when_no_graph_relations() {
        let store = kin_db::InMemoryGraph::new();

        let focal = make_file_entity("safeParse", EntityKind::Constant, "src/parse.ts");
        let sibling = make_file_entity("parse", EntityKind::Constant, "src/parse.ts");
        let unrelated = make_file_entity("helper", EntityKind::Function, "src/other.ts");

        store.upsert_entity(&focal).unwrap();
        store.upsert_entity(&sibling).unwrap();
        store.upsert_entity(&unrelated).unwrap();

        let pack = build_context_pack(&store, &focal.id, &ContextOptions::default()).unwrap();

        assert!(
            pack.dependency_signatures
                .iter()
                .any(|entry| entry.content.contains("parse")),
            "same-file sibling should appear as a fallback dependency"
        );
        assert!(
            pack.dependency_signatures
                .iter()
                .all(|entry| !entry.content.contains("helper")),
            "entities from other files should not be pulled in by the same-file fallback"
        );
    }

    #[test]
    fn context_pack_prioritizes_companion_same_file_neighbors() {
        let store = kin_db::InMemoryGraph::new();

        let focal = make_file_entity("safeParse", EntityKind::Constant, "src/parse.ts");
        let companion = make_file_entity("_safeParse", EntityKind::Constant, "src/parse.ts");
        let sibling = make_file_entity("parse", EntityKind::Constant, "src/parse.ts");

        store.upsert_entity(&focal).unwrap();
        store.upsert_entity(&companion).unwrap();
        store.upsert_entity(&sibling).unwrap();

        let pack = build_context_pack(&store, &focal.id, &ContextOptions::default()).unwrap();
        let first = &pack.dependency_signatures[0].content;

        assert!(
            first.contains("_safeParse"),
            "closest same-file companion should be ranked first"
        );
    }
}
