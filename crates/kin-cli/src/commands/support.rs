// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};
use kin_model::GraphStats;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::graph_health::GraphHealthReport;

#[derive(Debug, Serialize, Deserialize)]
pub struct SupportJson {
    total_entities: usize,
    total_relations: usize,
    file_layout_count: usize,
    shallow_file_count: usize,
    structured_artifact_count: usize,
    opaque_artifact_count: usize,
    file_hash_count: usize,
    text_indexed_entity_count: usize,
    text_index_coverage_percent: f64,
    indexed_embedding_count: usize,
    pending_embedding_count: usize,
    embedding_coverage_percent: f64,
    work_item_count: usize,
    test_case_count: usize,
    review_count: usize,
    session_count: usize,
    entity_counts: BTreeMap<String, usize>,
    relation_counts: BTreeMap<String, usize>,
    parse_completeness_counts: BTreeMap<String, usize>,
    role_counts: BTreeMap<String, usize>,
    health: GraphHealthReport,
}

impl SupportJson {
    pub fn from_parts(stats: &GraphStats, health: GraphHealthReport) -> Self {
        Self {
            total_entities: stats.total_entities,
            total_relations: stats.total_relations,
            file_layout_count: stats.file_layout_count,
            shallow_file_count: stats.shallow_file_count,
            structured_artifact_count: stats.structured_artifact_count,
            opaque_artifact_count: stats.opaque_artifact_count,
            file_hash_count: stats.file_hash_count,
            text_indexed_entity_count: stats.text_indexed_entity_count,
            text_index_coverage_percent: stats.text_index_coverage_percent,
            indexed_embedding_count: stats.indexed_embedding_count,
            pending_embedding_count: stats.pending_embedding_count,
            embedding_coverage_percent: stats.embedding_coverage_percent,
            work_item_count: stats.work_item_count,
            test_case_count: stats.test_case_count,
            review_count: stats.review_count,
            session_count: stats.session_count,
            entity_counts: stats
                .entity_counts
                .iter()
                .map(|(k, v)| (k.clone(), *v))
                .collect(),
            relation_counts: stats
                .relation_counts
                .iter()
                .map(|(k, v)| (k.clone(), *v))
                .collect(),
            parse_completeness_counts: stats
                .parse_completeness_counts
                .iter()
                .map(|(k, v)| (k.clone(), *v))
                .collect(),
            role_counts: stats
                .role_counts
                .iter()
                .map(|(k, v)| (k.clone(), *v))
                .collect(),
            health,
        }
    }
}

pub fn inspect_support_graph(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
) -> Result<SupportJson> {
    let health = super::graph_health::inspect_graph(layout, graph)?;
    let stats = graph.graph_stats();
    Ok(SupportJson::from_parts(&stats, health))
}

pub async fn run(json: bool) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;

    let report = run_daemon_support(&layout).await?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        for line in render_support_json(&report) {
            println!("{line}");
        }
    }

    Ok(())
}

async fn run_daemon_support(layout: &kin_core::KinLayout) -> Result<SupportJson> {
    let daemon_url = std::env::var("KIN_DAEMON_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(Some)
        .unwrap_or(crate::daemon_client::resolve_daemon_url(layout).await?);
    let base_url = daemon_url.ok_or_else(|| {
        anyhow::anyhow!("Kin daemon is required for support but no daemon endpoint is available")
    })?;
    let client = crate::daemon_client::DaemonClient::from_base_url(base_url)?;
    client.support().await.context("daemon support failed")
}

#[cfg(test)]
fn render_support_report(stats: &GraphStats, health: &GraphHealthReport) -> Vec<String> {
    render_support_json(&SupportJson::from_parts(stats, health.clone()))
}

fn render_support_json(report: &SupportJson) -> Vec<String> {
    let mut lines = vec![
        "Graph observability".to_string(),
        format!("  total entities: {}", report.total_entities),
        format!("  total relations: {}", report.total_relations),
        format!("  file layouts: {}", report.file_layout_count),
        format!("  shallow files: {}", report.shallow_file_count),
        format!(
            "  structured artifacts: {}",
            report.structured_artifact_count
        ),
        format!("  opaque artifacts: {}", report.opaque_artifact_count),
        format!("  file hashes: {}", report.file_hash_count),
        format!(
            "  text index coverage: {} / {} entities ({:.1}%)",
            report.text_indexed_entity_count,
            report.total_entities,
            report.text_index_coverage_percent
        ),
        format!(
            "  embedding coverage: {} / {} entities ({:.1}%)",
            report.indexed_embedding_count,
            report.total_entities,
            report.embedding_coverage_percent
        ),
        format!("  pending embeddings: {}", report.pending_embedding_count),
        format!("  work items: {}", report.work_item_count),
        format!("  test cases: {}", report.test_case_count),
        format!("  reviews: {}", report.review_count),
        format!("  sessions: {}", report.session_count),
        format!(
            "  semantic relations (excluding CoChanges): {} ({:.2} rels/entity)",
            report.health.semantic_relation_count,
            report.health.semantic_relation_density_excluding_cochanges
        ),
    ];

    lines.push(String::new());
    lines.push("Entity kinds".to_string());
    lines.extend(render_counts(&report.entity_counts));

    lines.push(String::new());
    lines.push("Entity roles".to_string());
    if report.role_counts.is_empty() {
        lines.push("  (none)".to_string());
    } else {
        // Render as: Entities: 1234 (source: 456, test: 234, external: 345, ...)
        let total = report.total_entities;
        let mut parts: Vec<String> = Vec::new();
        let mut sorted: Vec<_> = report.role_counts.iter().collect();
        sorted.sort_by(|(a, _), (b, _)| a.cmp(b));
        for (role, count) in sorted {
            parts.push(format!("{}: {}", role.to_lowercase(), count));
        }
        lines.push(format!("  total: {} ({})", total, parts.join(", ")));
    }

    lines.push(String::new());
    lines.push("Relation kinds".to_string());
    lines.extend(render_counts(&report.relation_counts));

    lines.push(String::new());
    lines.push("Parse completeness".to_string());
    lines.extend(render_counts(&report.parse_completeness_counts));

    lines.push(String::new());
    lines.push("Health".to_string());
    lines.push(format!(
        "  supported entity-source files: {}",
        report.health.supported_entity_source_file_count
    ));
    lines.push(format!(
        "  supported shallow-syntax files: {}",
        report.health.supported_shallow_source_file_count
    ));
    lines.push(format!(
        "  contaminated paths: {}",
        report.health.contaminated_path_count
    ));
    if !report.health.contaminated_paths_sample.is_empty() {
        lines.push(format!(
            "  contamination sample: {}",
            report.health.contaminated_paths_sample.join(", ")
        ));
    }
    if report.health.critical_issues.is_empty() && report.health.warnings.is_empty() {
        lines.push("  no graph health issues detected".to_string());
    } else {
        for issue in &report.health.critical_issues {
            lines.push(format!("  critical: {issue}"));
        }
        for warning in &report.health.warnings {
            lines.push(format!("  warning: {warning}"));
        }
    }

    lines
}

fn render_counts(counts: &BTreeMap<String, usize>) -> Vec<String> {
    let mut entries: Vec<_> = counts.iter().collect();
    entries.sort_by(|(a, _), (b, _)| a.cmp(b));
    if entries.is_empty() {
        return vec!["  (none)".to_string()];
    }

    entries
        .into_iter()
        .map(|(name, count)| format!("  {name}: {count}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{render_support_report, SupportJson};
    use crate::commands::graph_health::GraphHealthReport;
    use kin_model::GraphStats;
    use std::collections::HashMap;

    #[test]
    fn human_report_renders_sorted_counts() {
        let stats = GraphStats {
            entity_counts: HashMap::from([("Class".to_string(), 1), ("Function".to_string(), 2)]),
            relation_counts: HashMap::from([("Calls".to_string(), 3), ("Imports".to_string(), 1)]),
            parse_completeness_counts: HashMap::from([
                ("full".to_string(), 2),
                ("partial".to_string(), 1),
            ]),
            shallow_file_count: 4,
            file_layout_count: 3,
            structured_artifact_count: 5,
            opaque_artifact_count: 6,
            file_hash_count: 7,
            text_indexed_entity_count: 2,
            text_index_coverage_percent: 66.7,
            indexed_embedding_count: 1,
            pending_embedding_count: 1,
            embedding_coverage_percent: 33.3,
            work_item_count: 8,
            test_case_count: 9,
            review_count: 10,
            session_count: 11,
            total_entities: 3,
            total_relations: 4,
            role_counts: HashMap::from([("Source".to_string(), 2), ("Test".to_string(), 1)]),
        };

        let health = GraphHealthReport {
            supported_entity_source_file_count: 2,
            supported_shallow_source_file_count: 1,
            graph_empty_for_supported_inputs: false,
            contaminated_entity_count: 0,
            contaminated_non_entity_count: 0,
            contaminated_file_hash_count: 0,
            contaminated_path_count: 0,
            contaminated_paths_sample: Vec::new(),
            test_role_entity_count: 1,
            test_case_count: 9,
            cochange_relation_count: 0,
            semantic_relation_count: 4,
            semantic_relation_density_excluding_cochanges: 1.33,
            critical_issues: Vec::new(),
            warnings: vec!["1 files are still shallow-tracked".to_string()],
        };

        let rendered = render_support_report(&stats, &health);
        assert_eq!(
            rendered,
            vec![
                "Graph observability".to_string(),
                "  total entities: 3".to_string(),
                "  total relations: 4".to_string(),
                "  file layouts: 3".to_string(),
                "  shallow files: 4".to_string(),
                "  structured artifacts: 5".to_string(),
                "  opaque artifacts: 6".to_string(),
                "  file hashes: 7".to_string(),
                "  text index coverage: 2 / 3 entities (66.7%)".to_string(),
                "  embedding coverage: 1 / 3 entities (33.3%)".to_string(),
                "  pending embeddings: 1".to_string(),
                "  work items: 8".to_string(),
                "  test cases: 9".to_string(),
                "  reviews: 10".to_string(),
                "  sessions: 11".to_string(),
                "  semantic relations (excluding CoChanges): 4 (1.33 rels/entity)".to_string(),
                String::new(),
                "Entity kinds".to_string(),
                "  Class: 1".to_string(),
                "  Function: 2".to_string(),
                String::new(),
                "Entity roles".to_string(),
                "  total: 3 (source: 2, test: 1)".to_string(),
                String::new(),
                "Relation kinds".to_string(),
                "  Calls: 3".to_string(),
                "  Imports: 1".to_string(),
                String::new(),
                "Parse completeness".to_string(),
                "  full: 2".to_string(),
                "  partial: 1".to_string(),
                String::new(),
                "Health".to_string(),
                "  supported entity-source files: 2".to_string(),
                "  supported shallow-syntax files: 1".to_string(),
                "  contaminated paths: 0".to_string(),
                "  warning: 1 files are still shallow-tracked".to_string(),
            ]
        );
    }

    #[test]
    fn json_payload_preserves_counts() {
        let stats = GraphStats {
            entity_counts: HashMap::from([("Function".to_string(), 2)]),
            relation_counts: HashMap::from([("Calls".to_string(), 1)]),
            parse_completeness_counts: HashMap::from([("full".to_string(), 1)]),
            shallow_file_count: 1,
            file_layout_count: 1,
            structured_artifact_count: 2,
            opaque_artifact_count: 3,
            file_hash_count: 4,
            text_indexed_entity_count: 1,
            text_index_coverage_percent: 50.0,
            indexed_embedding_count: 1,
            pending_embedding_count: 0,
            embedding_coverage_percent: 50.0,
            work_item_count: 5,
            test_case_count: 6,
            review_count: 7,
            session_count: 8,
            total_entities: 2,
            total_relations: 1,
            role_counts: HashMap::from([("Source".to_string(), 2)]),
        };

        let payload = SupportJson::from_parts(
            &stats,
            GraphHealthReport {
                supported_entity_source_file_count: 1,
                supported_shallow_source_file_count: 0,
                graph_empty_for_supported_inputs: false,
                contaminated_entity_count: 0,
                contaminated_non_entity_count: 0,
                contaminated_file_hash_count: 0,
                contaminated_path_count: 0,
                contaminated_paths_sample: Vec::new(),
                test_role_entity_count: 0,
                test_case_count: 6,
                cochange_relation_count: 0,
                semantic_relation_count: 1,
                semantic_relation_density_excluding_cochanges: 0.5,
                critical_issues: Vec::new(),
                warnings: Vec::new(),
            },
        );
        assert_eq!(payload.total_entities, 2);
        assert_eq!(payload.total_relations, 1);
        assert_eq!(payload.file_layout_count, 1);
        assert_eq!(payload.text_indexed_entity_count, 1);
        assert_eq!(payload.indexed_embedding_count, 1);
        assert_eq!(payload.entity_counts.get("Function"), Some(&2));
        assert_eq!(payload.relation_counts.get("Calls"), Some(&1));
        assert_eq!(payload.parse_completeness_counts.get("full"), Some(&1));
        assert_eq!(payload.health.supported_entity_source_file_count, 1);
        assert_eq!(payload.health.semantic_relation_count, 1);
    }
}
