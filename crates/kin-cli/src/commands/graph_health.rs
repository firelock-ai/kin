// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use kin_model::{
    ArtifactKind, EntityStore, FilePathId, GraphStats, Hash256, RepoPath, ResolvedTree, TreeEntry,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use super::repository_authority::RequestRepositoryAuthority;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RepositoryArtifactCoverage {
    /// Complete repository-v6 workspace membership, independent of language
    /// support or semantic relationships.
    pub authority_artifact_count: usize,
    /// Exact tree currently carried by the derived query graph.
    pub graph_tree_artifact_count: usize,
    /// Whether the derived graph carries the same stable artifact identities,
    /// byte-exact paths, entry kinds, modes, and content identities.
    pub repository_tree_in_sync: bool,
    /// UTF-8 regular files that can carry one query-facing enrichment facet.
    pub enrichable_artifact_count: usize,
    /// Enrichable artifacts with at least one persisted facet.
    pub enriched_artifact_count: usize,
    /// Symlinks, gitlinks, and non-UTF-8 paths that remain exact tree truth but
    /// do not currently have a `FilePathId` enrichment surface.
    pub exact_only_artifact_count: usize,
    /// Enrichable artifacts still waiting for a facet.
    ///
    /// Absence is not a defect under the current substrate. No admission path
    /// writes the facet layer: exact Git admission binds entity and relation
    /// deltas derived from supported sources and nothing else. Facets are
    /// written one file at a time, after admission, by the reconcile loop, the
    /// commit path, and projection. Every coverage level from none to full is
    /// therefore a reachable healthy state, so this count describes progress
    /// rather than divergence.
    pub missing_enrichment_path_count: usize,
    pub conflicting_enrichment_path_count: usize,
    pub stale_enrichment_path_count: usize,
    pub content_mismatch_path_count: usize,
    pub orphan_entity_count: usize,
    /// Whether every enrichable artifact carries exactly one agreeing facet.
    ///
    /// This is a coverage observation, not the health verdict: a repository
    /// whose enrichment is still pending is incomplete and healthy. The
    /// verdict lives in `critical_issues`, which keys on facets that exist and
    /// disagree with exact tree truth.
    pub complete: bool,
    pub issue_paths_sample: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GraphHealthReport {
    pub repository_artifact_coverage: RepositoryArtifactCoverage,
    pub supported_entity_source_file_count: usize,
    pub supported_shallow_source_file_count: usize,
    /// Whether supported sources were admitted while the graph derived neither
    /// an entity layer nor a single facet.
    ///
    /// Informational and JSON-only by design: it moves no verdict, no note, and
    /// no exit code. Every coverage level is a reachable healthy state under
    /// the current substrate, so keying a verdict on this would fail closed on
    /// repositories that are merely early. Consumers read it from the report.
    pub graph_empty_for_supported_inputs: bool,
    pub contaminated_entity_count: usize,
    pub contaminated_non_entity_count: usize,
    pub contaminated_path_count: usize,
    pub contaminated_paths_sample: Vec<String>,
    pub test_role_entity_count: usize,
    pub test_case_count: usize,
    pub cochange_relation_count: usize,
    pub semantic_relation_count: usize,
    pub semantic_relation_density_excluding_cochanges: f64,
    /// Reference-edge completeness per language: call sites and import
    /// statements the parser read, against the edges the graph resolved.
    ///
    /// The counters beside it all describe what the graph holds. This is the one
    /// that describes what it is missing, which is what no surface reported when
    /// `graph validate` passed on a graph missing 16 imports and roughly 40
    /// cross-file call edges.
    #[serde(default)]
    pub reference_edge_coverage: kin_core::reference_coverage::ReferenceEdgeCoverage,
    pub critical_issues: Vec<String>,
    pub warnings: Vec<String>,
    /// Observations that describe a healthy graph rather than a defect. They
    /// are reported separately so a first import does not present expected
    /// absences as problems.
    #[serde(default)]
    pub notes: Vec<String>,
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
    path_count: usize,
    path_samples: Vec<String>,
}

pub(crate) fn inspect_graph(
    authority: &RequestRepositoryAuthority,
    graph: &kin_db::InMemoryGraph,
) -> Result<GraphHealthReport> {
    inspect_graph_with_pending_embeddings(authority, graph, None)
}

/// Build the report against a pending count the caller already sampled.
///
/// The status surface prints a coverage counter and this report's pending
/// warning in one response. Sampling coverage twice for that response lets an
/// embed batch complete between the two reads, so the warning names a pending
/// count the counter beside it contradicts by exactly one batch. The two are
/// not even drawn from the same population: `graph_stats().pending_embedding_count`
/// counts entity ids while `embedding_status()` counts retrievable keys, so
/// they can disagree at a single instant with no race at all. Whoever renders
/// both takes one sample and hands it here so the two cannot disagree. Callers
/// that render no counter pass `None` and keep the report's own sample.
pub(crate) fn inspect_graph_with_pending_embeddings(
    authority: &RequestRepositoryAuthority,
    graph: &kin_db::InMemoryGraph,
    pending_embeddings: Option<usize>,
) -> Result<GraphHealthReport> {
    let entities = graph.list_all_entities()?;
    inspect_graph_with_entities(authority, graph, &entities, pending_embeddings)
}

/// Build the report against an entity listing the caller already took.
///
/// `list_all_entities` clones every entity in the graph out from under a lock,
/// and a `graph status` response needs the same listing the report does. Taking
/// it once and passing it here is what keeps one response from cloning the
/// whole entity table three times: once for the renderer's counters, once for
/// this report, and once more inside contamination collection.
pub(crate) fn inspect_graph_with_entities(
    authority: &RequestRepositoryAuthority,
    graph: &kin_db::InMemoryGraph,
    entities: &[kin_model::Entity],
    pending_embeddings: Option<usize>,
) -> Result<GraphHealthReport> {
    let stats = graph.graph_stats();
    // One resolved-tree clone for the whole report, for the same reason.
    let resolved_tree = graph.resolved_tree();
    let supported_inputs = collect_supported_inputs(&resolved_tree);
    let contamination = collect_contamination(graph, entities)?;
    let artifact_coverage = collect_repository_artifact_coverage(authority, graph, &resolved_tree)?;
    // Parse coverage rides on the reference-edge coverage type rather than
    // beside it, because that module is the one graph-completeness vocabulary
    // and a reader must not be handed two sections with two denominators. The
    // census is collected separately because the reference collector starts
    // from the entity table, and a file that produced no entity is invisible to
    // it by construction: that is exactly the population a parse hole lives in.
    let reference_edge_coverage =
        kin_core::reference_coverage::collect_reference_edge_coverage(graph)?
            .with_parse_coverage(kin_core::reference_coverage::collect_parse_coverage(graph)?);
    Ok(build_graph_health_report(
        &stats,
        &supported_inputs,
        &contamination,
        artifact_coverage,
        pending_embeddings,
        reference_edge_coverage,
    ))
}

#[derive(Default)]
struct EnrichmentFacets {
    count: usize,
    /// Opaque facets record the exact blob identity of the bytes they describe,
    /// so a stored hash that differs from the tree's is a disagreement.
    opaque_hashes: Vec<Hash256>,
    /// Structured facets record the hash of NORMALIZED content, not of the
    /// bytes. The extractors exist to make formatting-only changes invisible to
    /// the dependency graph, so this hash is not blob identity and equals it
    /// only when a file's normalization happens to be the identity. Checking it
    /// means re-deriving the same normalization from the authoritative body.
    structured: Vec<(ArtifactKind, Hash256)>,
}

/// Coverage against the authority this request reads at.
///
/// Takes the request's authority rather than its binding because
/// [`ActiveRepositoryAuthority::open`] re-verifies every persisted body against
/// its content address, so it costs whatever the whole store is worth. A server
/// that has already paid for one open at the publication this request reads
/// hands it over here; a one-shot caller still opens for itself.
fn collect_repository_artifact_coverage(
    authority: &RequestRepositoryAuthority,
    graph: &kin_db::InMemoryGraph,
    graph_tree: &ResolvedTree,
) -> Result<RepositoryArtifactCoverage> {
    let authority = authority.open()?;
    let workspace = authority.workspace()?;
    workspace.validate()?;
    collect_repository_artifact_coverage_for_tree(&workspace.tree, graph, graph_tree, &|hash| {
        authority.load_source_blob(hash)
    })
}

/// Whether a structured facet still describes the body the tree names.
///
/// Re-derives the extractor's own normalization from the authoritative body and
/// compares that, because the stored hash is the normalized hash. Extraction
/// failure falls back to blob identity exactly as the writer does, so a file the
/// extractor cannot read is checked on the same terms it was written on.
fn structured_facet_disagrees(
    kind: ArtifactKind,
    stored: Hash256,
    path: &str,
    blob_hash: Hash256,
    body: &[u8],
) -> bool {
    let expected = kin_index::extract_artifact(kind, body, &FilePathId::new(path))
        .map(|artifact| artifact.content_hash)
        .unwrap_or(blob_hash);
    stored != expected
}

fn collect_repository_artifact_coverage_for_tree(
    authority_tree: &ResolvedTree,
    graph: &kin_db::InMemoryGraph,
    graph_tree: &ResolvedTree,
    read_body: &dyn Fn(Hash256) -> Result<Vec<u8>>,
) -> Result<RepositoryArtifactCoverage> {
    let repository_tree_in_sync = *graph_tree == *authority_tree;

    let mut issue_paths = BTreeSet::new();
    if !repository_tree_in_sync {
        collect_tree_divergence_paths(authority_tree, graph_tree, &mut issue_paths);
    }

    let mut facets = BTreeMap::<String, EnrichmentFacets>::new();
    for layout in graph.list_file_layouts()? {
        facets.entry(layout.file_id.0).or_default().count += 1;
    }
    for shallow in graph.list_shallow_files()? {
        facets.entry(shallow.file_id.0).or_default().count += 1;
    }
    for artifact in graph.list_structured_artifacts()? {
        let facet = facets.entry(artifact.file_id.0).or_default();
        facet.count += 1;
        facet
            .structured
            .push((artifact.kind, artifact.content_hash));
    }
    for artifact in graph.list_opaque_artifacts()? {
        let facet = facets.entry(artifact.file_id.0).or_default();
        facet.count += 1;
        facet.opaque_hashes.push(artifact.content_hash);
    }

    let mut enrichable_artifact_count = 0usize;
    let mut enriched_artifact_count = 0usize;
    let mut exact_only_artifact_count = 0usize;
    let mut missing_enrichment_paths = BTreeSet::new();
    let mut conflicting_enrichment_paths = BTreeSet::new();
    let mut content_mismatch_paths = BTreeSet::new();

    for artifact in authority_tree.artifacts_by_path() {
        let (Some(path), TreeEntry::Blob { hash, .. }) = (artifact.path.as_utf8(), artifact.entry)
        else {
            exact_only_artifact_count += 1;
            continue;
        };
        enrichable_artifact_count += 1;
        match facets.get(path) {
            None => {
                missing_enrichment_paths.insert(path.to_string());
            }
            Some(facet) => {
                enriched_artifact_count += 1;
                if facet.count != 1 {
                    conflicting_enrichment_paths.insert(path.to_string());
                }
                let mut disagrees = facet
                    .opaque_hashes
                    .iter()
                    .any(|content_hash| *content_hash != hash);
                if !disagrees && !facet.structured.is_empty() {
                    // Read only for the few kinds that carry a normalized hash,
                    // and only once per path however many facets it has.
                    let body = read_body(hash)?;
                    disagrees = facet.structured.iter().any(|(kind, stored)| {
                        structured_facet_disagrees(*kind, *stored, path, hash, &body)
                    });
                }
                if disagrees {
                    content_mismatch_paths.insert(path.to_string());
                }
            }
        }
    }

    let mut stale_enrichment_paths = BTreeSet::new();
    for path in facets.keys() {
        let exact_blob_exists = RepoPath::from_utf8(path.clone())
            .ok()
            .and_then(|path| authority_tree.artifact_at_path(&path))
            .is_some_and(|artifact| matches!(artifact.entry, TreeEntry::Blob { .. }));
        if !exact_blob_exists {
            stale_enrichment_paths.insert(path.clone());
        }
    }

    let mut orphan_entity_count = 0usize;
    for entity in graph.list_all_entities()? {
        let Some(file_origin) = entity.file_origin else {
            continue;
        };
        let exact_blob_exists = RepoPath::from_utf8(file_origin.0.clone())
            .ok()
            .and_then(|path| authority_tree.artifact_at_path(&path))
            .is_some_and(|artifact| matches!(artifact.entry, TreeEntry::Blob { .. }));
        if !exact_blob_exists {
            orphan_entity_count += 1;
            issue_paths.insert(file_origin.0);
        }
    }

    // Paths still waiting for a facet are deliberately absent from the issue
    // sample. They are healthy, and naming them beside real divergence is how
    // an operator learns to skim past the sample.
    issue_paths.extend(conflicting_enrichment_paths.iter().cloned());
    issue_paths.extend(stale_enrichment_paths.iter().cloned());
    issue_paths.extend(content_mismatch_paths.iter().cloned());

    let complete = repository_tree_in_sync
        && missing_enrichment_paths.is_empty()
        && conflicting_enrichment_paths.is_empty()
        && stale_enrichment_paths.is_empty()
        && content_mismatch_paths.is_empty()
        && orphan_entity_count == 0;

    Ok(RepositoryArtifactCoverage {
        authority_artifact_count: authority_tree.len(),
        graph_tree_artifact_count: graph_tree.len(),
        repository_tree_in_sync,
        enrichable_artifact_count,
        enriched_artifact_count,
        exact_only_artifact_count,
        missing_enrichment_path_count: missing_enrichment_paths.len(),
        conflicting_enrichment_path_count: conflicting_enrichment_paths.len(),
        stale_enrichment_path_count: stale_enrichment_paths.len(),
        content_mismatch_path_count: content_mismatch_paths.len(),
        orphan_entity_count,
        complete,
        issue_paths_sample: issue_paths.into_iter().take(8).collect(),
    })
}

fn collect_tree_divergence_paths(
    authority_tree: &ResolvedTree,
    graph_tree: &ResolvedTree,
    issue_paths: &mut BTreeSet<String>,
) {
    for artifact in authority_tree.artifacts() {
        if graph_tree.get(&artifact.artifact_id) != Some(artifact) {
            issue_paths.insert(artifact.path.to_string());
        }
    }
    for artifact in graph_tree.artifacts() {
        if authority_tree.get(&artifact.artifact_id) != Some(artifact) {
            issue_paths.insert(artifact.path.to_string());
        }
    }
}

fn collect_supported_inputs(resolved_tree: &ResolvedTree) -> SupportedInputCounts {
    let mut entity_source = 0usize;
    let mut shallow_source = 0usize;

    for artifact in resolved_tree.artifacts_by_path() {
        if !matches!(artifact.entry, TreeEntry::Blob { .. }) {
            continue;
        }
        let Some(path) = artifact.path.as_utf8() else {
            continue;
        };
        match kin_index::FileClassifier::classify(Path::new(path)) {
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

    SupportedInputCounts {
        entity_source,
        shallow_source,
    }
}

fn collect_contamination(
    graph: &kin_db::InMemoryGraph,
    entities: &[kin_model::Entity],
) -> Result<ContaminationSummary> {
    let mut path_set = BTreeSet::new();
    let mut contaminated_entity_count = 0usize;
    let mut contaminated_non_entity_count = 0usize;

    for entity in entities {
        if let Some(file_origin) = &entity.file_origin {
            if !kin_index::should_index_repo_relative_path(Path::new(&file_origin.0)) {
                contaminated_entity_count += 1;
                path_set.insert(file_origin.0.clone());
            }
        }
    }

    for shallow in graph.list_shallow_files()? {
        if !kin_index::should_index_repo_relative_path(Path::new(&shallow.file_id.0)) {
            contaminated_non_entity_count += 1;
            path_set.insert(shallow.file_id.0);
        }
    }

    for artifact in graph.list_structured_artifacts()? {
        if !kin_index::should_index_repo_relative_path(Path::new(&artifact.file_id.0)) {
            contaminated_non_entity_count += 1;
            path_set.insert(artifact.file_id.0);
        }
    }

    for artifact in graph.list_opaque_artifacts()? {
        if !kin_index::should_index_repo_relative_path(Path::new(&artifact.file_id.0)) {
            contaminated_non_entity_count += 1;
            path_set.insert(artifact.file_id.0);
        }
    }

    Ok(ContaminationSummary {
        entity_count: contaminated_entity_count,
        non_entity_count: contaminated_non_entity_count,
        path_count: path_set.len(),
        path_samples: path_set.into_iter().take(8).collect(),
    })
}

fn build_graph_health_report(
    stats: &GraphStats,
    supported_inputs: &SupportedInputCounts,
    contamination: &ContaminationSummary,
    artifact_coverage: RepositoryArtifactCoverage,
    pending_embeddings: Option<usize>,
    reference_edge_coverage: kin_core::reference_coverage::ReferenceEdgeCoverage,
) -> GraphHealthReport {
    let test_role_entity_count = stats.role_counts.get("Test").copied().unwrap_or(0);
    let cochange_relation_count = stats.relation_counts.get("CoChanges").copied().unwrap_or(0);
    let coverage_relation_count = stats.relation_counts.get("Covers").copied().unwrap_or(0);
    let semantic_relation_count = stats
        .total_relations
        .saturating_sub(cochange_relation_count);
    let semantic_density = if stats.total_entities == 0 {
        0.0
    } else {
        semantic_relation_count as f64 / stats.total_entities as f64
    };

    // A supported source file may legitimately contain no entities, and bytes
    // with a parser-looking extension may correctly route to an opaque facet.
    // Health therefore never keys on relationship counts. It does account for
    // the entity layer, because exact admission builds that layer and no facet
    // layer at all: a repository with entities derived from its supported
    // sources is not an empty graph, whatever its facet coverage is.
    let graph_empty_for_supported_inputs = (supported_inputs.entity_source > 0
        || supported_inputs.shallow_source > 0)
        && artifact_coverage.enriched_artifact_count == 0
        && stats.total_entities == 0;

    let mut critical_issues = Vec::new();
    let mut warnings = Vec::new();
    let mut notes = Vec::new();

    if !artifact_coverage.repository_tree_in_sync {
        critical_issues.push(format!(
            "derived graph tree has {} artifacts but repository authority has {}",
            artifact_coverage.graph_tree_artifact_count, artifact_coverage.authority_artifact_count
        ));
    }

    // Pending enrichment is expected, so it is reported and never promoted to
    // a failure. Nothing in the current substrate produces a facet at
    // admission, and the paths that do produce them work one file at a time,
    // so a health surface that failed on absence would fail on every healthy
    // repository until the last file happened to be touched. What remains
    // fail-closed is every facet that exists and disagrees with exact tree
    // truth, below.
    if artifact_coverage.missing_enrichment_path_count > 0 {
        notes.push(format!(
            "{} of {} admitted regular files have no query-facing enrichment facet yet; \
             authority admission binds the entity layer only and facets are written per file \
             after it",
            artifact_coverage.missing_enrichment_path_count,
            artifact_coverage.enrichable_artifact_count
        ));
    }

    if artifact_coverage.conflicting_enrichment_path_count > 0 {
        critical_issues.push(format!(
            "{} admitted regular files have conflicting enrichment facets",
            artifact_coverage.conflicting_enrichment_path_count
        ));
    }

    if artifact_coverage.stale_enrichment_path_count > 0 {
        critical_issues.push(format!(
            "{} enrichment paths are absent from the exact repository tree",
            artifact_coverage.stale_enrichment_path_count
        ));
    }

    if artifact_coverage.content_mismatch_path_count > 0 {
        critical_issues.push(format!(
            "{} artifact facets disagree with exact repository content identity",
            artifact_coverage.content_mismatch_path_count
        ));
    }

    if artifact_coverage.orphan_entity_count > 0 {
        critical_issues.push(format!(
            "{} entities refer to files absent from the exact repository tree",
            artifact_coverage.orphan_entity_count
        ));
    }

    if contamination.path_count > 0 {
        critical_issues.push(format!(
            "graph contains {} skipped/generated/internal paths",
            contamination.path_count
        ));
    }

    // Test-role entities without a catalog are the normal shape of a repository
    // that has never run `kin verify`; only surviving coverage relationships
    // prove a catalog existed and is now gone.
    if test_role_entity_count > 0 && stats.test_case_count == 0 {
        if coverage_relation_count > 0 {
            warnings.push(format!(
                "graph contains {} Test-role entities and {} Covers relations, but the verification test-case catalog is empty",
                test_role_entity_count, coverage_relation_count
            ));
        } else {
            notes.push(format!(
                "graph contains {} Test-role entities; no verification test-case catalog has been recorded yet",
                test_role_entity_count
            ));
        }
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

    // One sample rules both surfaces when the caller took one, so the warning
    // can never name a pending count the counter beside it has already moved
    // past.
    let pending_embeddings = pending_embeddings.unwrap_or(stats.pending_embedding_count);
    if pending_embeddings > 0 {
        warnings.push(format!("{pending_embeddings} embeddings are still pending"));
    }

    GraphHealthReport {
        repository_artifact_coverage: artifact_coverage,
        supported_entity_source_file_count: supported_inputs.entity_source,
        supported_shallow_source_file_count: supported_inputs.shallow_source,
        graph_empty_for_supported_inputs,
        contaminated_entity_count: contamination.entity_count,
        contaminated_non_entity_count: contamination.non_entity_count,
        contaminated_path_count: contamination.path_count,
        contaminated_paths_sample: contamination.path_samples.clone(),
        test_role_entity_count,
        test_case_count: stats.test_case_count,
        cochange_relation_count,
        semantic_relation_count,
        semantic_relation_density_excluding_cochanges: semantic_density,
        reference_edge_coverage,
        critical_issues,
        warnings,
        notes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serve exactly the bodies a fixture stages, and refuse anything else.
    ///
    /// A coverage pass reads a body only to re-derive a structured facet's
    /// normalization, so an unexpected read fails the test rather than being
    /// answered with something invented.
    fn staged_bodies(bodies: [(Hash256, &'static [u8]); 1]) -> impl Fn(Hash256) -> Result<Vec<u8>> {
        let bodies: BTreeMap<Hash256, Vec<u8>> = bodies
            .into_iter()
            .map(|(hash, body)| (hash, body.to_vec()))
            .collect();
        move |hash| {
            bodies
                .get(&hash)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("fixture stages no body for {hash}"))
        }
    }

    /// No body is available, so any read at all fails the test.
    fn no_bodies() -> impl Fn(Hash256) -> Result<Vec<u8>> {
        |hash| Err(anyhow::anyhow!("fixture stages no body for {hash}"))
    }
    use std::collections::HashMap;

    fn complete_coverage() -> RepositoryArtifactCoverage {
        RepositoryArtifactCoverage {
            authority_artifact_count: 0,
            graph_tree_artifact_count: 0,
            repository_tree_in_sync: true,
            enrichable_artifact_count: 0,
            enriched_artifact_count: 0,
            exact_only_artifact_count: 0,
            missing_enrichment_path_count: 0,
            conflicting_enrichment_path_count: 0,
            stale_enrichment_path_count: 0,
            content_mismatch_path_count: 0,
            orphan_entity_count: 0,
            complete: true,
            issue_paths_sample: Vec::new(),
        }
    }

    fn stats() -> GraphStats {
        GraphStats {
            entity_counts: HashMap::new(),
            relation_counts: HashMap::new(),
            parse_completeness_counts: HashMap::new(),
            shallow_file_count: 0,
            structured_artifact_count: 0,
            opaque_artifact_count: 0,
            file_layout_count: 0,
            working_tree_entry_count: 0,
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
    fn health_report_does_not_require_entities_for_supported_inputs() {
        let stats = stats();
        let supported_inputs = SupportedInputCounts {
            entity_source: 3,
            shallow_source: 1,
        };
        let contamination = ContaminationSummary {
            entity_count: 0,
            non_entity_count: 0,
            path_count: 0,
            path_samples: Vec::new(),
        };
        let coverage = RepositoryArtifactCoverage {
            authority_artifact_count: 4,
            graph_tree_artifact_count: 4,
            enrichable_artifact_count: 4,
            enriched_artifact_count: 4,
            ..complete_coverage()
        };

        let report = build_graph_health_report(
            &stats,
            &supported_inputs,
            &contamination,
            coverage,
            None,
            Default::default(),
        );

        assert!(!report.graph_empty_for_supported_inputs);
        assert!(report.critical_issues.is_empty());
    }

    fn test_role_stats() -> GraphStats {
        let mut stats = stats();
        stats.total_entities = 12;
        stats.total_relations = 9;
        stats.role_counts.insert("Test".to_string(), 4);
        stats.relation_counts.insert("CoChanges".to_string(), 8);
        stats
    }

    fn contamination_report(stats: &GraphStats) -> GraphHealthReport {
        build_graph_health_report(
            stats,
            &SupportedInputCounts {
                entity_source: 2,
                shallow_source: 0,
            },
            &ContaminationSummary {
                entity_count: 1,
                non_entity_count: 2,
                path_count: 3,
                path_samples: vec!["out/generated.rs".to_string()],
            },
            complete_coverage(),
            None,
            Default::default(),
        )
    }

    #[test]
    fn health_report_flags_contamination() {
        let report = contamination_report(&test_role_stats());

        assert_eq!(report.contaminated_path_count, 3);
        assert_eq!(report.semantic_relation_count, 1);
        assert!(report
            .critical_issues
            .iter()
            .any(|issue| issue.contains("skipped/generated/internal paths")));
    }

    #[test]
    fn absent_test_case_catalog_without_coverage_edges_is_a_note() {
        let report = contamination_report(&test_role_stats());

        assert!(report
            .notes
            .iter()
            .any(|note| note.contains("no verification test-case catalog has been recorded yet")));
        assert!(!report
            .warnings
            .iter()
            .any(|issue| issue.contains("test-case catalog")));
    }

    #[test]
    fn absent_test_case_catalog_with_surviving_coverage_edges_is_a_warning() {
        let mut stats = test_role_stats();
        stats.relation_counts.insert("Covers".to_string(), 5);
        let report = contamination_report(&stats);

        assert!(report
            .warnings
            .iter()
            .any(|issue| issue.contains("5 Covers relations")
                && issue.contains("verification test-case catalog is empty")));
        assert!(!report
            .notes
            .iter()
            .any(|note| note.contains("test-case catalog")));
    }

    #[test]
    fn populated_test_case_catalog_reports_neither_note_nor_warning() {
        let mut stats = test_role_stats();
        stats.test_case_count = 7;
        stats.relation_counts.insert("Covers".to_string(), 5);

        let report = contamination_report(&stats);

        assert!(!report
            .warnings
            .iter()
            .any(|issue| issue.contains("test-case catalog")));
        assert!(!report
            .notes
            .iter()
            .any(|note| note.contains("test-case catalog")));
    }

    #[test]
    fn artifact_coverage_is_independent_of_semantic_relationships() {
        let mut stats = stats();
        stats.total_entities = 2;
        let coverage = RepositoryArtifactCoverage {
            authority_artifact_count: 5,
            graph_tree_artifact_count: 5,
            repository_tree_in_sync: true,
            enrichable_artifact_count: 4,
            enriched_artifact_count: 4,
            exact_only_artifact_count: 1,
            ..complete_coverage()
        };

        let report = build_graph_health_report(
            &stats,
            &SupportedInputCounts {
                entity_source: 0,
                shallow_source: 0,
            },
            &ContaminationSummary {
                entity_count: 0,
                non_entity_count: 0,
                path_count: 0,
                path_samples: Vec::new(),
            },
            coverage,
            None,
            Default::default(),
        );

        assert!(report.repository_artifact_coverage.complete);
        assert!(report.critical_issues.is_empty());
        assert_eq!(report.semantic_relation_count, 0);
    }

    fn empty_supported_inputs() -> SupportedInputCounts {
        SupportedInputCounts {
            entity_source: 0,
            shallow_source: 0,
        }
    }

    fn no_contamination() -> ContaminationSummary {
        ContaminationSummary {
            entity_count: 0,
            non_entity_count: 0,
            path_count: 0,
            path_samples: Vec::new(),
        }
    }

    #[test]
    fn artifact_coverage_divergence_is_critical_and_sampled() {
        let coverage = RepositoryArtifactCoverage {
            authority_artifact_count: 3,
            graph_tree_artifact_count: 2,
            repository_tree_in_sync: false,
            enrichable_artifact_count: 3,
            enriched_artifact_count: 2,
            exact_only_artifact_count: 0,
            missing_enrichment_path_count: 1,
            conflicting_enrichment_path_count: 0,
            stale_enrichment_path_count: 0,
            content_mismatch_path_count: 1,
            orphan_entity_count: 0,
            complete: false,
            issue_paths_sample: vec!["unknown.custom".to_string()],
        };
        let report = build_graph_health_report(
            &stats(),
            &empty_supported_inputs(),
            &no_contamination(),
            coverage,
            None,
            Default::default(),
        );

        assert!(!report.repository_artifact_coverage.complete);
        assert!(report
            .critical_issues
            .iter()
            .any(|issue| issue.contains("repository authority has 3")));
        assert!(report
            .critical_issues
            .iter()
            .any(|issue| issue.contains("disagree with exact repository content identity")));
    }

    #[test]
    fn pending_enrichment_is_a_note_rather_than_a_failure() {
        let coverage = RepositoryArtifactCoverage {
            authority_artifact_count: 3,
            graph_tree_artifact_count: 3,
            enrichable_artifact_count: 3,
            enriched_artifact_count: 0,
            missing_enrichment_path_count: 3,
            complete: false,
            ..complete_coverage()
        };

        let report = build_graph_health_report(
            &stats(),
            &SupportedInputCounts {
                entity_source: 3,
                shallow_source: 0,
            },
            &no_contamination(),
            coverage,
            None,
            Default::default(),
        );

        assert!(report.critical_issues.is_empty());
        assert!(report
            .notes
            .iter()
            .any(|note| note.contains("3 of 3 admitted regular files have no query-facing")));
    }

    #[test]
    fn an_entity_layer_without_facets_is_not_an_empty_graph() {
        let mut entity_stats = stats();
        entity_stats.total_entities = 9;
        entity_stats.total_relations = 7;
        let coverage = RepositoryArtifactCoverage {
            authority_artifact_count: 7,
            graph_tree_artifact_count: 7,
            enrichable_artifact_count: 7,
            enriched_artifact_count: 0,
            missing_enrichment_path_count: 7,
            complete: false,
            ..complete_coverage()
        };

        let report = build_graph_health_report(
            &entity_stats,
            &SupportedInputCounts {
                entity_source: 7,
                shallow_source: 0,
            },
            &no_contamination(),
            coverage,
            None,
            Default::default(),
        );

        assert!(!report.graph_empty_for_supported_inputs);
        assert!(report.critical_issues.is_empty());
    }

    #[test]
    fn supported_inputs_with_no_entities_and_no_facets_is_an_empty_graph() {
        let coverage = RepositoryArtifactCoverage {
            authority_artifact_count: 2,
            graph_tree_artifact_count: 2,
            enrichable_artifact_count: 2,
            enriched_artifact_count: 0,
            missing_enrichment_path_count: 2,
            complete: false,
            ..complete_coverage()
        };

        let report = build_graph_health_report(
            &stats(),
            &SupportedInputCounts {
                entity_source: 2,
                shallow_source: 0,
            },
            &no_contamination(),
            coverage,
            None,
            Default::default(),
        );

        assert!(report.graph_empty_for_supported_inputs);
    }

    #[test]
    fn arbitrary_repository_members_are_covered_without_relationships() {
        use kin_model::{
            ArtifactId, ArtifactKind, FilePathId, LocatedEntry, OpaqueArtifact, ResolvedArtifact,
            TransactionDelta, TreeDelta,
        };

        // A real body, because the facet under test is derived from one. A
        // fabricated hash could only be checked against a fabricated facet, and
        // that pairing is what let an impossible expectation stand.
        let compose_body: &[u8] =
            b"# operational compose\nservices:\n  app:\n    image: kin:test\n";
        let compose_hash = kin_blobs::digest(compose_body);
        let unknown_hash = Hash256::from_bytes([0x22; 32]);
        let symlink_target_hash = Hash256::from_bytes([0x33; 32]);
        let compose_id = ArtifactId::new();
        let unknown_id = ArtifactId::new();
        let symlink_id = ArtifactId::new();
        let compose_path = RepoPath::from_utf8("compose.yaml").unwrap();
        let unknown_path = RepoPath::from_utf8("assets/unknown.custom").unwrap();
        let symlink_path = RepoPath::from_utf8("current-config").unwrap();
        let tree = ResolvedTree::from_artifacts([
            ResolvedArtifact::new(
                compose_id,
                compose_path.clone(),
                TreeEntry::blob(compose_hash, false),
            ),
            ResolvedArtifact::new(
                unknown_id,
                unknown_path.clone(),
                TreeEntry::blob(unknown_hash, false),
            ),
            ResolvedArtifact::new(
                symlink_id,
                symlink_path.clone(),
                TreeEntry::symlink(symlink_target_hash),
            ),
        ])
        .unwrap();
        let graph = kin_db::InMemoryGraph::new();
        graph
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas: Vec::new(),
                relation_deltas: Vec::new(),
                tree_deltas: vec![
                    TreeDelta::Added {
                        artifact_id: compose_id,
                        new: LocatedEntry::new(compose_path, TreeEntry::blob(compose_hash, false)),
                    },
                    TreeDelta::Added {
                        artifact_id: unknown_id,
                        new: LocatedEntry::new(unknown_path, TreeEntry::blob(unknown_hash, false)),
                    },
                    TreeDelta::Added {
                        artifact_id: symlink_id,
                        new: LocatedEntry::new(
                            symlink_path,
                            TreeEntry::symlink(symlink_target_hash),
                        ),
                    },
                ],
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            })
            .unwrap();
        // Exactly the facet the extractor writes for these bytes, hash and all.
        let compose_facet = kin_index::extract_artifact(
            ArtifactKind::ComposeFile,
            compose_body,
            &FilePathId::new("compose.yaml"),
        )
        .unwrap();
        assert_ne!(
            compose_facet.content_hash, compose_hash,
            "the fixture only proves anything while normalization actually moves the hash"
        );
        graph.upsert_structured_artifact(&compose_facet).unwrap();
        graph
            .upsert_opaque_artifact(&OpaqueArtifact {
                file_id: FilePathId::new("assets/unknown.custom"),
                content_hash: unknown_hash,
                mime_type: None,
                text_preview: None,
            })
            .unwrap();

        let graph_tree = graph.resolved_tree();
        let coverage = collect_repository_artifact_coverage_for_tree(
            &tree,
            &graph,
            &graph_tree,
            &staged_bodies([(compose_hash, compose_body)]),
        )
        .unwrap();

        assert!(coverage.complete);
        assert!(coverage.repository_tree_in_sync);
        assert_eq!(coverage.authority_artifact_count, 3);
        assert_eq!(coverage.enrichable_artifact_count, 2);
        assert_eq!(coverage.enriched_artifact_count, 2);
        assert_eq!(coverage.exact_only_artifact_count, 1);
        assert_eq!(graph.graph_stats().total_relations, 0);
    }

    #[test]
    fn coverage_rejects_conflicting_stale_and_wrong_content_facets() {
        use kin_model::{
            ArtifactId, FilePathId, LocatedEntry, OpaqueArtifact, ResolvedArtifact,
            StructuredArtifact, TransactionDelta, TreeDelta,
        };

        let exact_hash = Hash256::from_bytes([0x41; 32]);
        let wrong_hash = Hash256::from_bytes([0x42; 32]);
        let artifact_id = ArtifactId::new();
        let ghost_id = ArtifactId::new();
        let path = RepoPath::from_utf8("compose.yaml").unwrap();
        let ghost_path = RepoPath::from_utf8("ghost.bin").unwrap();
        let tree = ResolvedTree::from_artifacts([ResolvedArtifact::new(
            artifact_id,
            path.clone(),
            TreeEntry::blob(exact_hash, false),
        )])
        .unwrap();
        let graph = kin_db::InMemoryGraph::new();
        graph
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas: Vec::new(),
                relation_deltas: Vec::new(),
                tree_deltas: vec![
                    TreeDelta::Added {
                        artifact_id,
                        new: LocatedEntry::new(path, TreeEntry::blob(exact_hash, false)),
                    },
                    TreeDelta::Added {
                        artifact_id: ghost_id,
                        new: LocatedEntry::new(ghost_path, TreeEntry::blob(wrong_hash, false)),
                    },
                ],
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            })
            .unwrap();
        graph
            .upsert_structured_artifact(&StructuredArtifact {
                file_id: FilePathId::new("compose.yaml"),
                kind: kin_model::ArtifactKind::ComposeFile,
                content_hash: exact_hash,
                text_preview: None,
            })
            .unwrap();
        graph
            .upsert_opaque_artifact(&OpaqueArtifact {
                file_id: FilePathId::new("compose.yaml"),
                content_hash: wrong_hash,
                mime_type: None,
                text_preview: None,
            })
            .unwrap();
        graph
            .upsert_opaque_artifact(&OpaqueArtifact {
                file_id: FilePathId::new("ghost.bin"),
                content_hash: wrong_hash,
                mime_type: Some("application/octet-stream".to_string()),
                text_preview: None,
            })
            .unwrap();

        let coverage = collect_repository_artifact_coverage_for_tree(
            &tree,
            &graph,
            &graph.resolved_tree(),
            &no_bodies(),
        )
        .unwrap();

        assert!(!coverage.complete);
        assert_eq!(coverage.conflicting_enrichment_path_count, 1);
        assert_eq!(coverage.content_mismatch_path_count, 1);
        assert_eq!(coverage.stale_enrichment_path_count, 1);
        assert_eq!(
            coverage.issue_paths_sample,
            vec!["compose.yaml".to_string(), "ghost.bin".to_string()]
        );
    }

    #[test]
    fn content_change_atomically_retires_source_and_shallow_facets() {
        use kin_model::{
            ArtifactId, FileLayout, FilePathId, ImportSection, LocatedEntry, ParseCompleteness,
            ResolvedArtifact, ShallowTrackedFile, TransactionDelta, TreeDelta,
        };

        let old_hash = Hash256::from_bytes([0x51; 32]);
        let new_hash = Hash256::from_bytes([0x52; 32]);
        let artifact_id = ArtifactId::new();
        let path = RepoPath::from_utf8("src/lib.rs").unwrap();
        let file_id = FilePathId::new("src/lib.rs");
        let graph = kin_db::InMemoryGraph::new();
        graph
            .apply_transaction_delta(&TransactionDelta {
                tree_deltas: vec![TreeDelta::Added {
                    artifact_id,
                    new: LocatedEntry::new(path.clone(), TreeEntry::blob(old_hash, false)),
                }],
                ..TransactionDelta::default()
            })
            .unwrap();
        graph
            .upsert_file_layout(&FileLayout {
                file_id: file_id.clone(),
                parse_completeness: ParseCompleteness::Full,
                imports: ImportSection {
                    byte_range: 0..0,
                    items: Vec::new(),
                },
                regions: Vec::new(),
            })
            .unwrap();
        graph
            .upsert_shallow_file(&ShallowTrackedFile {
                file_id: file_id.clone(),
                language_hint: "rust".to_string(),
                declaration_count: 1,
                import_count: 0,
                syntax_hash: old_hash,
                signature_hash: Some(old_hash),
                declaration_names: vec!["old_definition".to_string()],
                import_paths: Vec::new(),
            })
            .unwrap();

        graph
            .apply_transaction_delta(&TransactionDelta {
                tree_deltas: vec![TreeDelta::Updated {
                    artifact_id,
                    old: LocatedEntry::new(path.clone(), TreeEntry::blob(old_hash, false)),
                    new: LocatedEntry::new(path.clone(), TreeEntry::blob(new_hash, false)),
                }],
                ..TransactionDelta::default()
            })
            .unwrap();

        assert!(graph.get_file_layout(&file_id).unwrap().is_none());
        assert!(graph.get_shallow_file(&file_id).unwrap().is_none());
        let authority_tree = ResolvedTree::from_artifacts([ResolvedArtifact::new(
            artifact_id,
            path,
            TreeEntry::blob(new_hash, false),
        )])
        .unwrap();
        let coverage = collect_repository_artifact_coverage_for_tree(
            &authority_tree,
            &graph,
            &graph.resolved_tree(),
            &no_bodies(),
        )
        .unwrap();
        assert_eq!(coverage.missing_enrichment_path_count, 1);
        assert_eq!(coverage.content_mismatch_path_count, 0);
        assert_eq!(coverage.stale_enrichment_path_count, 0);
    }

    /// Build the tree and graph for one structured file, with the facet the
    /// caller supplies rather than the one the extractor would write.
    fn workflow_coverage(body: &'static [u8], facet_hash: Hash256) -> RepositoryArtifactCoverage {
        use kin_model::{
            ArtifactId, LocatedEntry, ResolvedArtifact, StructuredArtifact, TransactionDelta,
            TreeDelta,
        };

        let path = RepoPath::from_utf8(".github/workflows/ci.yml").unwrap();
        let artifact_id = ArtifactId::new();
        let hash = kin_blobs::digest(body);
        let tree = ResolvedTree::from_artifacts([ResolvedArtifact::new(
            artifact_id,
            path.clone(),
            TreeEntry::blob(hash, false),
        )])
        .unwrap();
        let graph = kin_db::InMemoryGraph::new();
        graph
            .apply_transaction_delta(&TransactionDelta {
                tree_deltas: vec![TreeDelta::Added {
                    artifact_id,
                    new: LocatedEntry::new(path, TreeEntry::blob(hash, false)),
                }],
                ..TransactionDelta::default()
            })
            .unwrap();
        graph
            .upsert_structured_artifact(&StructuredArtifact {
                file_id: FilePathId::new(".github/workflows/ci.yml"),
                kind: ArtifactKind::CiConfig,
                content_hash: facet_hash,
                text_preview: None,
            })
            .unwrap();
        collect_repository_artifact_coverage_for_tree(
            &tree,
            &graph,
            &graph.resolved_tree(),
            &staged_bodies([(hash, body)]),
        )
        .unwrap()
    }

    /// An admitted workflow file whose facet is exactly what its extractor
    /// wrote is healthy.
    ///
    /// The extractors normalize on purpose, so that formatting-only edits do not
    /// move the dependency graph, and a CI config's stored hash is the hash of
    /// that normalized text. Comparing it to blob identity asserted an equality
    /// the facet never claimed, and every real workflow file failed it: a single
    /// trailing newline is enough to separate the two hashes.
    #[test]
    fn a_workflow_facet_written_by_its_own_extractor_agrees_with_the_tree() {
        let body: &[u8] = b"# a comment normalization drops\nname: CI\non:\n  push:\n";
        let facet = kin_index::extract_artifact(
            ArtifactKind::CiConfig,
            body,
            &FilePathId::new(".github/workflows/ci.yml"),
        )
        .unwrap();
        assert_ne!(
            facet.content_hash,
            kin_blobs::digest(body),
            "the fixture only proves anything while normalization actually moves the hash"
        );

        let coverage = workflow_coverage(body, facet.content_hash);
        assert_eq!(coverage.content_mismatch_path_count, 0);
        assert!(coverage.complete);
    }

    /// The control. A facet left behind by an edit describes bytes the tree no
    /// longer names, and that still has to be loud: the check keeps its whole
    /// point, which is catching enrichment that has fallen behind authority.
    #[test]
    fn a_workflow_facet_left_behind_by_an_edit_still_disagrees() {
        let stale = kin_index::extract_artifact(
            ArtifactKind::CiConfig,
            b"name: CI\non:\n  pull_request:\n",
            &FilePathId::new(".github/workflows/ci.yml"),
        )
        .unwrap();

        let coverage = workflow_coverage(
            b"# a comment normalization drops\nname: CI\non:\n  push:\n",
            stale.content_hash,
        );
        assert_eq!(coverage.content_mismatch_path_count, 1);
        assert!(!coverage.complete);
        assert_eq!(
            coverage.issue_paths_sample,
            vec![".github/workflows/ci.yml".to_string()]
        );
    }

    /// Formatting-only edits are what the normalization exists to absorb, so a
    /// facet stays valid across one. This is the behavior that makes the exact
    /// comparison wrong rather than merely strict.
    #[test]
    fn a_workflow_facet_survives_a_formatting_only_edit() {
        let facet = kin_index::extract_artifact(
            ArtifactKind::CiConfig,
            b"name: CI\non:\n  push:\n",
            &FilePathId::new(".github/workflows/ci.yml"),
        )
        .unwrap();

        let coverage = workflow_coverage(
            b"# added a comment\n\nname: CI   \non:\n  push:\n",
            facet.content_hash,
        );
        assert_eq!(
            coverage.content_mismatch_path_count, 0,
            "a comment, a blank line, and trailing spaces are exactly what the extractor absorbs"
        );
        assert!(coverage.complete);
    }
}
