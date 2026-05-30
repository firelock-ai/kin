// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use kin_model::{EntityStore, GraphStats};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use super::init::{collect_source_files, is_repo_owned_graph_path};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GraphHealthReport {
    pub supported_entity_source_file_count: usize,
    pub supported_shallow_source_file_count: usize,
    pub graph_empty_for_supported_inputs: bool,
    pub contaminated_entity_count: usize,
    pub contaminated_non_entity_count: usize,
    pub contaminated_file_hash_count: usize,
    pub contaminated_path_count: usize,
    pub contaminated_paths_sample: Vec<String>,
    pub test_role_entity_count: usize,
    pub test_case_count: usize,
    pub cochange_relation_count: usize,
    pub semantic_relation_count: usize,
    pub semantic_relation_density_excluding_cochanges: f64,
    pub critical_issues: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SupportedInputCounts {
    entity_source: usize,
    shallow_source: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ContaminationSummary {
    entity_count: usize,
    non_entity_count: usize,
    file_hash_count: usize,
    path_count: usize,
    path_samples: Vec<String>,
}

pub(crate) fn inspect_graph(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
) -> Result<GraphHealthReport> {
    let stats = graph.graph_stats();
    let supported_inputs = collect_supported_inputs(layout)?;
    let contamination = collect_contamination(graph)?;
    Ok(build_graph_health_report(
        &stats,
        &supported_inputs,
        &contamination,
    ))
}

fn collect_supported_inputs(layout: &kin_core::KinLayout) -> Result<SupportedInputCounts> {
    let source_root = kin_core::source_dir(layout);
    let all_files = collect_source_files(&source_root)?;
    let mut entity_source = 0usize;
    let mut shallow_source = 0usize;

    for file in all_files {
        match kin_index::FileClassifier::classify(&file) {
            kin_index::FileClassification::EntitySource => entity_source += 1,
            kin_index::FileClassification::ShallowSyntax { language_hint } => {
                if kin_parser::get_shallow_grammar(&language_hint).is_some() {
                    shallow_source += 1;
                }
            }
            kin_index::FileClassification::StructuredArtifact(_)
            | kin_index::FileClassification::OpaqueArtifact { .. } => {}
        }
    }

    Ok(SupportedInputCounts {
        entity_source,
        shallow_source,
    })
}

fn collect_contamination(graph: &kin_db::InMemoryGraph) -> Result<ContaminationSummary> {
    let mut path_set = BTreeSet::new();
    let mut contaminated_entity_count = 0usize;
    let mut contaminated_non_entity_count = 0usize;

    for entity in graph.list_all_entities()? {
        if let Some(file_origin) = entity.file_origin {
            if !is_repo_owned_graph_path(&file_origin.0) {
                contaminated_entity_count += 1;
                path_set.insert(file_origin.0);
            }
        }
    }

    for shallow in graph.list_shallow_files()? {
        if !is_repo_owned_graph_path(&shallow.file_id.0) {
            contaminated_non_entity_count += 1;
            path_set.insert(shallow.file_id.0);
        }
    }

    for artifact in graph.list_structured_artifacts()? {
        if !is_repo_owned_graph_path(&artifact.file_id.0) {
            contaminated_non_entity_count += 1;
            path_set.insert(artifact.file_id.0);
        }
    }

    for artifact in graph.list_opaque_artifacts()? {
        if !is_repo_owned_graph_path(&artifact.file_id.0) {
            contaminated_non_entity_count += 1;
            path_set.insert(artifact.file_id.0);
        }
    }

    let contaminated_file_hash_paths: Vec<_> = graph
        .indexed_file_paths()
        .into_iter()
        .filter(|path| !is_repo_owned_graph_path(path))
        .collect();
    for path in &contaminated_file_hash_paths {
        path_set.insert(path.clone());
    }

    Ok(ContaminationSummary {
        entity_count: contaminated_entity_count,
        non_entity_count: contaminated_non_entity_count,
        file_hash_count: contaminated_file_hash_paths.len(),
        path_count: path_set.len(),
        path_samples: path_set.into_iter().take(8).collect(),
    })
}

fn build_graph_health_report(
    stats: &GraphStats,
    supported_inputs: &SupportedInputCounts,
    contamination: &ContaminationSummary,
) -> GraphHealthReport {
    let test_role_entity_count = stats.role_counts.get("Test").copied().unwrap_or(0);
    let cochange_relation_count = stats.relation_counts.get("CoChanges").copied().unwrap_or(0);
    let semantic_relation_count = stats
        .total_relations
        .saturating_sub(cochange_relation_count);
    let semantic_density = if stats.total_entities == 0 {
        0.0
    } else {
        semantic_relation_count as f64 / stats.total_entities as f64
    };

    let graph_empty_for_supported_inputs = (supported_inputs.entity_source > 0
        && stats.total_entities == 0)
        || (supported_inputs.shallow_source > 0 && stats.shallow_file_count == 0);

    let mut critical_issues = Vec::new();
    let mut warnings = Vec::new();

    if supported_inputs.entity_source > 0 && stats.total_entities == 0 {
        critical_issues.push(format!(
            "supported entity-source files present ({}) but the graph contains zero entities",
            supported_inputs.entity_source
        ));
    }

    if supported_inputs.shallow_source > 0 && stats.shallow_file_count == 0 {
        critical_issues.push(format!(
            "supported shallow-syntax files present ({}) but the graph contains zero shallow files",
            supported_inputs.shallow_source
        ));
    }

    if contamination.path_count > 0 {
        critical_issues.push(format!(
            "graph contains {} skipped/generated/internal paths",
            contamination.path_count
        ));
    }

    if test_role_entity_count > 0 && stats.test_case_count == 0 {
        warnings.push(format!(
            "graph contains {} Test-role entities but no verification test-case catalog",
            test_role_entity_count
        ));
    }

    if stats.total_entities > 0 && stats.total_relations == 0 {
        warnings.push("graph has entities but zero relations".to_string());
    }

    if stats.shallow_file_count > 0 {
        warnings.push(format!(
            "{} files are still shallow-tracked",
            stats.shallow_file_count
        ));
    }

    if semantic_relation_count == 0 && stats.total_entities > 0 {
        warnings.push("graph has no semantic relations beyond CoChanges".to_string());
    } else if stats.total_entities > 100 && semantic_density < 0.1 {
        warnings.push(format!(
            "semantic relation density excluding CoChanges is very low ({semantic_density:.2} rels/entity)"
        ));
    }

    if stats.pending_embedding_count > 0 {
        warnings.push(format!(
            "{} embeddings are still pending",
            stats.pending_embedding_count
        ));
    }

    GraphHealthReport {
        supported_entity_source_file_count: supported_inputs.entity_source,
        supported_shallow_source_file_count: supported_inputs.shallow_source,
        graph_empty_for_supported_inputs,
        contaminated_entity_count: contamination.entity_count,
        contaminated_non_entity_count: contamination.non_entity_count,
        contaminated_file_hash_count: contamination.file_hash_count,
        contaminated_path_count: contamination.path_count,
        contaminated_paths_sample: contamination.path_samples.clone(),
        test_role_entity_count,
        test_case_count: stats.test_case_count,
        cochange_relation_count,
        semantic_relation_count,
        semantic_relation_density_excluding_cochanges: semantic_density,
        critical_issues,
        warnings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn stats() -> GraphStats {
        GraphStats {
            entity_counts: HashMap::new(),
            relation_counts: HashMap::new(),
            parse_completeness_counts: HashMap::new(),
            shallow_file_count: 0,
            structured_artifact_count: 0,
            opaque_artifact_count: 0,
            file_layout_count: 0,
            file_hash_count: 0,
            text_indexed_entity_count: 0,
            text_index_coverage_percent: 0.0,
            indexed_embedding_count: 0,
            pending_embedding_count: 0,
            embedding_coverage_percent: 0.0,
            work_item_count: 0,
            test_case_count: 0,
            review_count: 0,
            session_count: 0,
            total_entities: 0,
            total_relations: 0,
            role_counts: HashMap::new(),
        }
    }

    #[test]
    fn health_report_flags_empty_graph_for_supported_inputs() {
        let stats = stats();
        let supported_inputs = SupportedInputCounts {
            entity_source: 3,
            shallow_source: 1,
        };
        let contamination = ContaminationSummary {
            entity_count: 0,
            non_entity_count: 0,
            file_hash_count: 0,
            path_count: 0,
            path_samples: Vec::new(),
        };

        let report = build_graph_health_report(&stats, &supported_inputs, &contamination);

        assert!(report.graph_empty_for_supported_inputs);
        assert_eq!(report.critical_issues.len(), 2);
        assert!(report
            .critical_issues
            .iter()
            .any(|issue| issue.contains("entity-source files present (3)")));
        assert!(report
            .critical_issues
            .iter()
            .any(|issue| issue.contains("shallow-syntax files present (1)")));
    }

    #[test]
    fn health_report_flags_contamination_and_missing_test_cases() {
        let mut stats = stats();
        stats.total_entities = 12;
        stats.total_relations = 9;
        stats.role_counts.insert("Test".to_string(), 4);
        stats.relation_counts.insert("CoChanges".to_string(), 8);

        let report = build_graph_health_report(
            &stats,
            &SupportedInputCounts {
                entity_source: 2,
                shallow_source: 0,
            },
            &ContaminationSummary {
                entity_count: 1,
                non_entity_count: 2,
                file_hash_count: 1,
                path_count: 3,
                path_samples: vec!["out/generated.rs".to_string()],
            },
        );

        assert_eq!(report.contaminated_path_count, 3);
        assert_eq!(report.semantic_relation_count, 1);
        assert!(report
            .critical_issues
            .iter()
            .any(|issue| issue.contains("skipped/generated/internal paths")));
        assert!(report
            .warnings
            .iter()
            .any(|issue| issue.contains("no verification test-case catalog")));
    }
}
