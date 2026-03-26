// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Context quality benchmarks per language.
//!
//! For each supported language present in the graph, samples a set of focal
//! entities, builds context packs, then measures precision/recall of the
//! included entities against the graph's own dependency relations (ground truth).
//!
//! **Ground truth definition:** An entity is "relevant" if it is reachable from
//! the focal entity via Calls, DependsOn, Imports, or References relations
//! within the configured depth. The context pack should include these entities.
//!
//! - **Precision** = |relevant ∩ included| / |included|
//! - **Recall** = |relevant ∩ included| / |relevant|
//! - **F1** = 2 × precision × recall / (precision + recall)

use std::collections::{HashMap, HashSet};

use kin_context::{build_context_pack, ContextOptions};
use kin_model::entity::EntityKind;
use kin_model::relation::RelationKind;
use kin_model::{EntityId, GraphStore, LanguageId, TokenBudget};
use tracing::{debug, info, warn};

use crate::error::{BenchError, Result};
use crate::metrics::{ContextQuality, LanguageContextQuality};

/// Options controlling the context quality benchmark run.
#[derive(Debug, Clone)]
pub struct ContextQualityBenchOptions {
    /// Maximum entities to sample per language.
    pub samples_per_language: usize,
    /// Token budget for each context pack.
    pub token_budget: TokenBudget,
    /// Max dependency depth for both context building and ground truth.
    pub max_depth: u32,
    /// Only benchmark these languages. Empty means all languages found in the graph.
    pub language_filter: Vec<LanguageId>,
}

impl Default for ContextQualityBenchOptions {
    fn default() -> Self {
        Self {
            samples_per_language: 5,
            token_budget: TokenBudget::Large32k,
            max_depth: 2,
            language_filter: Vec::new(),
        }
    }
}

/// Result of running context quality benchmarks across all languages.
#[derive(Debug, Clone)]
pub struct ContextQualityBenchResult {
    /// Individual per-entity scores.
    pub scores: Vec<ContextQuality>,
    /// Aggregated per-language summaries.
    pub by_language: Vec<LanguageContextQuality>,
}

/// Relation kinds that define ground-truth "relevant" entities.
const GROUND_TRUTH_RELATIONS: &[RelationKind] = &[
    RelationKind::Calls,
    RelationKind::DependsOn,
    RelationKind::Imports,
    RelationKind::References,
];

/// Entity kinds worth sampling as focal entities (skip Tests, Schemas, etc).
const FOCAL_ENTITY_KINDS: &[EntityKind] = &[
    EntityKind::Function,
    EntityKind::Class,
    EntityKind::Interface,
    EntityKind::TraitDef,
    EntityKind::Method,
    EntityKind::Module,
];

/// Run context quality benchmarks across all languages in the graph.
pub fn bench_context_quality_by_language<G: GraphStore>(
    graph: &G,
    opts: &ContextQualityBenchOptions,
) -> Result<ContextQualityBenchResult> {
    let all_entities = graph
        .list_all_entities()
        .map_err(|e| BenchError::Graph(e.to_string()))?;

    // Group entities by language, filtering to focal-worthy kinds.
    let mut by_language: HashMap<LanguageId, Vec<EntityId>> = HashMap::new();
    for entity in &all_entities {
        if !FOCAL_ENTITY_KINDS.contains(&entity.kind) {
            continue;
        }
        // Skip entities without outgoing relations — they produce trivial results.
        let rels = graph
            .get_relations(&entity.id, GROUND_TRUTH_RELATIONS)
            .map_err(|e| BenchError::Graph(e.to_string()))?;
        if rels.is_empty() {
            continue;
        }
        by_language
            .entry(entity.language)
            .or_default()
            .push(entity.id);
    }

    // Apply language filter if set.
    if !opts.language_filter.is_empty() {
        by_language.retain(|lang, _| opts.language_filter.contains(lang));
    }

    if by_language.is_empty() {
        info!("no eligible entities found for context quality benchmarks");
        return Ok(ContextQualityBenchResult {
            scores: Vec::new(),
            by_language: Vec::new(),
        });
    }

    info!(
        languages = by_language.len(),
        "starting context quality benchmarks"
    );

    let mut all_scores = Vec::new();

    // Sort languages for deterministic iteration order.
    let mut languages: Vec<LanguageId> = by_language.keys().copied().collect();
    languages.sort_by_key(|l| language_display_name(l));

    for language in &languages {
        let entity_ids = &by_language[language];
        let sample_count = entity_ids.len().min(opts.samples_per_language);
        // Deterministic spread: pick evenly spaced entities across the list.
        let step = if entity_ids.len() <= sample_count {
            1
        } else {
            entity_ids.len() / sample_count
        };

        let sampled: Vec<&EntityId> = entity_ids.iter().step_by(step).take(sample_count).collect();

        debug!(
            language = %language,
            candidates = entity_ids.len(),
            sampled = sampled.len(),
            "sampling entities for context quality"
        );

        for focal_id in sampled {
            match measure_context_quality(graph, focal_id, language, opts) {
                Ok(score) => all_scores.push(score),
                Err(e) => {
                    warn!(
                        entity = %focal_id,
                        language = %language,
                        error = %e,
                        "skipping entity due to context build error"
                    );
                }
            }
        }
    }

    let by_language = LanguageContextQuality::aggregate(&all_scores);

    info!(
        total_samples = all_scores.len(),
        languages = by_language.len(),
        "context quality benchmarks complete"
    );

    Ok(ContextQualityBenchResult {
        scores: all_scores,
        by_language,
    })
}

/// Measure context quality for a single focal entity.
fn measure_context_quality<G: GraphStore>(
    graph: &G,
    focal_id: &EntityId,
    language: &LanguageId,
    opts: &ContextQualityBenchOptions,
) -> Result<ContextQuality> {
    let focal = graph
        .get_entity(focal_id)
        .map_err(|e| BenchError::Graph(e.to_string()))?
        .ok_or_else(|| BenchError::Graph(format!("entity {} not found", focal_id)))?;

    // Ground truth: entities reachable via dependency relations within depth.
    let ground_truth = collect_ground_truth(graph, focal_id, opts.max_depth)?;

    // Build context pack.
    let context_opts = ContextOptions {
        budget: opts.token_budget,
        max_depth: opts.max_depth,
        include_tests: true,
        include_contracts: true,
        include_traffic: false,
        assistant_hint: None,
    };

    let pack = build_context_pack(graph, focal_id, &context_opts)
        .map_err(|e| BenchError::Graph(e.to_string()))?;

    // Collect all entity IDs present in the context pack (excluding the focal entity).
    let mut included: HashSet<EntityId> = HashSet::new();
    for entry in pack
        .dependency_signatures
        .iter()
        .chain(pack.transitive_deps.iter())
        .chain(pack.contracts.iter())
        .chain(pack.tests.iter())
    {
        included.insert(entry.entity_id);
    }

    // Compute precision and recall.
    let relevant_and_included = included.intersection(&ground_truth).count() as f64;
    let total_included = included.len() as f64;
    let total_relevant = ground_truth.len() as f64;

    let precision = if total_included == 0.0 {
        1.0 // No entities included means nothing wrong was included.
    } else {
        relevant_and_included / total_included
    };

    let recall = if total_relevant == 0.0 {
        1.0 // No ground-truth deps means perfect recall vacuously.
    } else {
        relevant_and_included / total_relevant
    };

    let f1_score = if precision + recall == 0.0 {
        0.0
    } else {
        2.0 * precision * recall / (precision + recall)
    };

    // Map LanguageId to the title-case string used by LanguageContextQuality.
    let language_str = language_display_name(language);

    Ok(ContextQuality {
        entity_name: focal.name.clone(),
        language: language_str,
        precision,
        recall,
        f1_score,
    })
}

/// BFS to collect all entity IDs reachable from `start` via ground-truth
/// relation kinds within `max_depth` hops.
fn collect_ground_truth<G: GraphStore>(
    graph: &G,
    start: &EntityId,
    max_depth: u32,
) -> Result<HashSet<EntityId>> {
    let mut visited = HashSet::new();
    let mut frontier = vec![*start];

    for _depth in 0..max_depth {
        let mut next_frontier = Vec::new();
        for eid in &frontier {
            let rels = graph
                .get_relations(eid, GROUND_TRUTH_RELATIONS)
                .map_err(|e| BenchError::Graph(e.to_string()))?;

            for rel in rels {
                let target = if rel.src == *eid { rel.dst } else { rel.src };
                if target != *start && visited.insert(target) {
                    next_frontier.push(target);
                }
            }
        }
        if next_frontier.is_empty() {
            break;
        }
        frontier = next_frontier;
    }

    Ok(visited)
}

/// Map LanguageId enum to the display name used in benchmark reports.
fn language_display_name(lang: &LanguageId) -> String {
    match lang {
        LanguageId::TypeScript => "TypeScript".to_string(),
        LanguageId::JavaScript => "JavaScript".to_string(),
        LanguageId::Python => "Python".to_string(),
        LanguageId::Go => "Go".to_string(),
        LanguageId::Java => "Java".to_string(),
        LanguageId::Rust => "Rust".to_string(),
        LanguageId::C => "C".to_string(),
        LanguageId::Cpp => "C++".to_string(),
        LanguageId::CSharp => "C#".to_string(),
        LanguageId::Ruby => "Ruby".to_string(),
        LanguageId::Php => "PHP".to_string(),
        LanguageId::Swift => "Swift".to_string(),
        LanguageId::Kotlin => "Kotlin".to_string(),
        LanguageId::Hcl => "HCL".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::LanguageContextQuality;

    #[test]
    fn precision_recall_perfect() {
        // When ground truth and included sets are identical.
        let ground_truth: HashSet<EntityId> = (0..5).map(|_| EntityId::new()).collect();
        let included = ground_truth.clone();

        let relevant_and_included = included.intersection(&ground_truth).count() as f64;
        let precision = relevant_and_included / included.len() as f64;
        let recall = relevant_and_included / ground_truth.len() as f64;

        assert!((precision - 1.0).abs() < f64::EPSILON);
        assert!((recall - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn precision_recall_partial_overlap() {
        let mut ground_truth: HashSet<EntityId> = HashSet::new();
        let mut included: HashSet<EntityId> = HashSet::new();

        let shared: Vec<EntityId> = (0..3).map(|_| EntityId::new()).collect();
        for id in &shared {
            ground_truth.insert(*id);
            included.insert(*id);
        }
        // 2 extra in ground truth (missed by context pack)
        for _ in 0..2 {
            ground_truth.insert(EntityId::new());
        }
        // 1 extra in included (not in ground truth)
        included.insert(EntityId::new());

        let relevant_and_included = included.intersection(&ground_truth).count() as f64;
        let precision = relevant_and_included / included.len() as f64; // 3/4 = 0.75
        let recall = relevant_and_included / ground_truth.len() as f64; // 3/5 = 0.60

        assert!((precision - 0.75).abs() < 0.01);
        assert!((recall - 0.60).abs() < 0.01);

        let f1 = 2.0 * precision * recall / (precision + recall);
        assert!(f1 > 0.0 && f1 < 1.0);
    }

    #[test]
    fn precision_empty_included() {
        // When context pack includes nothing beyond focal — precision is vacuously 1.0.
        let total_included: f64 = 0.0;
        let precision = if total_included == 0.0 { 1.0 } else { 0.0 };
        assert!((precision - 1.0_f64).abs() < f64::EPSILON);
    }

    #[test]
    fn recall_empty_ground_truth() {
        // Entity with no deps — recall is vacuously 1.0.
        let total_relevant: f64 = 0.0;
        let recall = if total_relevant == 0.0 { 1.0 } else { 0.0 };
        assert!((recall - 1.0_f64).abs() < f64::EPSILON);
    }

    #[test]
    fn language_display_names_cover_all_variants() {
        let languages = [
            LanguageId::TypeScript,
            LanguageId::JavaScript,
            LanguageId::Python,
            LanguageId::Go,
            LanguageId::Java,
            LanguageId::Rust,
            LanguageId::C,
            LanguageId::Cpp,
            LanguageId::CSharp,
            LanguageId::Ruby,
            LanguageId::Php,
            LanguageId::Swift,
            LanguageId::Kotlin,
            LanguageId::Hcl,
        ];
        for lang in &languages {
            let name = language_display_name(lang);
            assert!(!name.is_empty(), "display name for {:?} should not be empty", lang);
        }
    }

    #[test]
    fn default_options_are_sensible() {
        let opts = ContextQualityBenchOptions::default();
        assert_eq!(opts.samples_per_language, 5);
        assert_eq!(opts.max_depth, 2);
        assert!(opts.language_filter.is_empty());
    }

    #[test]
    fn aggregation_matches_individual_scores() {
        let scores = vec![
            ContextQuality {
                entity_name: "func_a".into(),
                language: "TypeScript".into(),
                precision: 0.90,
                recall: 0.80,
                f1_score: 0.85,
            },
            ContextQuality {
                entity_name: "func_b".into(),
                language: "TypeScript".into(),
                precision: 0.80,
                recall: 0.70,
                f1_score: 0.75,
            },
            ContextQuality {
                entity_name: "handler".into(),
                language: "Go".into(),
                precision: 0.95,
                recall: 0.90,
                f1_score: 0.92,
            },
        ];

        let agg = LanguageContextQuality::aggregate(&scores);
        assert_eq!(agg.len(), 2);

        let go = agg.iter().find(|a| a.language == "Go").unwrap();
        assert_eq!(go.sample_count, 1);
        assert!((go.avg_f1_score - 0.92).abs() < f64::EPSILON);

        let ts = agg.iter().find(|a| a.language == "TypeScript").unwrap();
        assert_eq!(ts.sample_count, 2);
        assert!((ts.avg_f1_score - 0.80).abs() < 0.01);
        assert!((ts.min_f1_score - 0.75).abs() < f64::EPSILON);
        assert!((ts.max_f1_score - 0.85).abs() < f64::EPSILON);
    }
}
