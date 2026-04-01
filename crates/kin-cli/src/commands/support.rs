// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use kin_model::GraphStats;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Serialize)]
struct SupportJson {
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
}

impl From<&GraphStats> for SupportJson {
    fn from(stats: &GraphStats) -> Self {
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
        }
    }
}

pub async fn run(json: bool) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;

    let snapshot = crate::backend::open_snapshot_daemon_first_read_only(&layout).await?;
    let stats = snapshot.graph().graph_stats();

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&SupportJson::from(&stats))?
        );
    } else {
        for line in render_support_report(&stats) {
            println!("{line}");
        }
    }

    Ok(())
}

fn render_support_report(stats: &GraphStats) -> Vec<String> {
    let mut lines = vec![
        "Graph observability".to_string(),
        format!("  total entities: {}", stats.total_entities),
        format!("  total relations: {}", stats.total_relations),
        format!("  file layouts: {}", stats.file_layout_count),
        format!("  shallow files: {}", stats.shallow_file_count),
        format!(
            "  structured artifacts: {}",
            stats.structured_artifact_count
        ),
        format!("  opaque artifacts: {}", stats.opaque_artifact_count),
        format!("  file hashes: {}", stats.file_hash_count),
        format!(
            "  text index coverage: {} / {} entities ({:.1}%)",
            stats.text_indexed_entity_count,
            stats.total_entities,
            stats.text_index_coverage_percent
        ),
        format!(
            "  embedding coverage: {} / {} entities ({:.1}%)",
            stats.indexed_embedding_count, stats.total_entities, stats.embedding_coverage_percent
        ),
        format!("  pending embeddings: {}", stats.pending_embedding_count),
        format!("  work items: {}", stats.work_item_count),
        format!("  test cases: {}", stats.test_case_count),
        format!("  reviews: {}", stats.review_count),
        format!("  sessions: {}", stats.session_count),
    ];

    lines.push(String::new());
    lines.push("Entity kinds".to_string());
    lines.extend(render_counts(&stats.entity_counts));

    lines.push(String::new());
    lines.push("Entity roles".to_string());
    if stats.role_counts.is_empty() {
        lines.push("  (none)".to_string());
    } else {
        // Render as: Entities: 1234 (source: 456, test: 234, external: 345, ...)
        let total = stats.total_entities;
        let mut parts: Vec<String> = Vec::new();
        let mut sorted: Vec<_> = stats.role_counts.iter().collect();
        sorted.sort_by(|(a, _), (b, _)| a.cmp(b));
        for (role, count) in sorted {
            parts.push(format!("{}: {}", role.to_lowercase(), count));
        }
        lines.push(format!("  total: {} ({})", total, parts.join(", ")));
    }

    lines.push(String::new());
    lines.push("Relation kinds".to_string());
    lines.extend(render_counts(&stats.relation_counts));

    lines.push(String::new());
    lines.push("Parse completeness".to_string());
    lines.extend(render_counts(&stats.parse_completeness_counts));

    lines
}

fn render_counts(counts: &std::collections::HashMap<String, usize>) -> Vec<String> {
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

        let rendered = render_support_report(&stats);
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

        let payload = SupportJson::from(&stats);
        assert_eq!(payload.total_entities, 2);
        assert_eq!(payload.total_relations, 1);
        assert_eq!(payload.file_layout_count, 1);
        assert_eq!(payload.text_indexed_entity_count, 1);
        assert_eq!(payload.indexed_embedding_count, 1);
        assert_eq!(payload.entity_counts.get("Function"), Some(&2));
        assert_eq!(payload.relation_counts.get("Calls"), Some(&1));
        assert_eq!(payload.parse_completeness_counts.get("full"), Some(&1));
    }
}
