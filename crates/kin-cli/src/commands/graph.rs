// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::{BTreeMap, HashMap, HashSet};

use anyhow::{Context, Result};
use kin_mcp::handlers::common::presentation_span_lines;
use kin_model::{
    Entity, EntityId, EntityKind, EntityRole, EntityStore, GraphStore, Hash256, RelationKind,
};
use serde::{Deserialize, Serialize};

use super::graph_health::{inspect_graph, inspect_graph_with_entities};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum GraphCommandRequest {
    Status,
    Validate,
    Inspect { name: String },
    Source { entity: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphCommandResponse {
    #[serde(default)]
    pub lines: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<GraphSourceRecord>,
    /// Reference-edge completeness, per language, for the status and validate
    /// surfaces.
    ///
    /// Carried structurally as well as in `lines` so a consumer reads the metric
    /// rather than parsing prose out of a terminal rendering. Optional because a
    /// subcommand that measures nothing (inspect, source) has none to report and
    /// an older daemon sends none at all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference_edge_coverage: Option<kin_core::reference_coverage::ReferenceEdgeCoverage>,
    /// The relation-kind census set beside the one this store last recorded.
    ///
    /// Carried structurally as well as in `lines` so `kin doctor` reads the
    /// comparison rather than parsing prose out of a terminal rendering, which
    /// is how the reference-edge coverage beside it reaches the same surface.
    /// Optional because a subcommand that compares nothing has none to report
    /// and an older daemon sends none at all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relation_census: Option<kin_core::relation_census::RelationCensusComparison>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphSourceRecord {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub language: String,
    pub file_path: String,
    /// 1-based inclusive presentation lines, converted from the graph's 0-based
    /// span rows at construction. This record is only ever printed or serialized
    /// to an agent, so it carries the editor convention; `start_byte`/`end_byte`
    /// stay in the graph's own domain because they are offsets, not positions.
    pub start_line: u32,
    pub end_line: u32,
    pub start_byte: usize,
    pub end_byte: usize,
    pub signature: String,
    pub body: String,
    /// Whether the span that cut `body` was proven to describe these exact bytes
    /// (`kin_mcp::handlers::common::SpanCoherence::label`).
    ///
    /// A provable mismatch never reaches here, because it fails the read. What this
    /// distinguishes is a verified pair from one the graph recorded no digest for,
    /// so a caller about to restate this body as an edit can tell which it has.
    pub span_coherence: String,
}

/// The three distinguishable results of resolving an entity's source for
/// `get_entity_source` / `get_entity_body`.
///
/// Callers (agents especially) must be able to tell these apart: a source they
/// can act on, an ID that does not exist (retrying it is pointless), and a real
/// entity that simply has no source body attached to graph truth. Collapsing
/// the latter two into one opaque "missing source" message makes agents retry
/// invented or stale IDs and probe adjacent ones, which burns their tool-call
/// budget for no gain.
#[derive(Debug, Clone)]
pub enum EntitySourceOutcome {
    /// The entity resolved and its source body was read from graph-owned truth.
    Found(GraphSourceRecord),
    /// The query resolved to no entity. Non-retryable: the ID is invalid or
    /// stale. The string is an agent-facing explanation.
    NotFound(String),
    /// The entity resolved but has no source body in graph truth (no file
    /// origin or no source span). Distinct from [`EntitySourceOutcome::NotFound`]
    /// — the ID is valid, there is simply nothing to return.
    NoSource(String),
}

/// `kin graph status` — quick health check of the semantic graph.
pub async fn status() -> Result<()> {
    let layout = crate::commands::require_repository_layout()?;
    let mut response = run_daemon_graph(&layout, &GraphCommandRequest::Status).await?;
    append_freshness_line(
        &mut response.lines,
        &kin_core::last_admission::read(&layout),
        chrono::Utc::now(),
    );
    // And which projection is showing that truth as files. Read here rather
    // than asked of the daemon for the same reason freshness is: the daemon
    // reports the graph it holds, and whether this host has a mount or an
    // injected shim is a property of the machine the CLI is standing on.
    response.lines.push(format!(
        "ℹ {}",
        crate::commands::projection::status_line(layout.root())
    ));
    print_graph_response(response)
}

/// State how fresh the graph truth being reported actually is.
///
/// Read here rather than asked of the daemon, the same way the MCP path reads
/// the durable authority-head marker straight off disk. The daemon's own report
/// is scoped to the graph it holds in memory, and freshness is a property of the
/// store on disk, which the CLI is standing in.
///
/// Appended unconditionally. Every other line in this report can be absent when
/// there is nothing to say, but "how old is this" has no such state: a report
/// that stays silent about freshness is exactly what let a months-behind store
/// answer with a clean bill of health. When the record is missing or unreadable
/// the line says the freshness is unknown, which is a different and more useful
/// answer than nothing.
fn append_freshness_line(
    lines: &mut Vec<String>,
    freshness: &kin_core::last_admission::LastAdmissionRead,
    now: chrono::DateTime<chrono::Utc>,
) {
    lines.push(String::new());
    lines.push(format!("ℹ graph truth: {}", freshness.describe(now)));
}

/// `kin graph validate` — structural integrity checks.
pub async fn validate() -> Result<()> {
    let layout = crate::commands::require_repository_layout()?;
    print_graph_response(run_daemon_graph(&layout, &GraphCommandRequest::Validate).await?)
}

/// `kin graph inspect <entity>` — look up an entity (by name or UUID) and show its relations.
///
/// In `--json` mode, the full `GraphCommandResponse` ({lines, error}) is emitted
/// as JSON. A missing-entity response (response.error set) is emitted with exit
/// 0, matching the graceful behavior of `get_context_pack` and `graph source --json`.
/// This lets an LLM agent recover from a hallucinated UUID instead of treating
/// the tool call as a hard CLI failure.
pub async fn inspect(name: String, json: bool) -> Result<()> {
    let layout = crate::commands::require_repository_layout()?;
    let response = run_daemon_graph(&layout, &GraphCommandRequest::Inspect { name }).await?;
    if json {
        // SP-23 graceful-error: emit the full response (lines + error) as JSON
        // with exit 0 even when entity is missing.
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "lines": response.lines,
                "error": response.error,
            }))?
        );
        return Ok(());
    }
    print_graph_response(response)
}

/// `kin graph source <entity>` — print the exact implementation body.
///
/// In `--json` mode, a missing-entity response (HTTP 200 with `error` set) is
/// emitted as `{"error": "..."}` on stdout with exit code 0, matching the
/// graceful behavior of `get_context_pack`. This lets an LLM agent recover from
/// a hallucinated UUID by treating the tool call as a structured "not found"
/// response rather than a hard CLI failure. Non-JSON mode keeps the existing
/// exit-1-on-error behavior for shell-script compatibility.
pub async fn source(entity: String, json: bool) -> Result<()> {
    let layout = crate::commands::require_repository_layout()?;
    let response = run_daemon_graph(&layout, &GraphCommandRequest::Source { entity }).await?;
    if json {
        if let Some(error) = response.error {
            // SP-23 graceful-error: emit structured {"error": "..."} on stdout
            // and exit 0 so the model can recover from a fabricated UUID.
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({ "error": error }))?
            );
            return Ok(());
        }
        let source = response
            .source
            .ok_or_else(|| anyhow::anyhow!("daemon source response did not include source"))?;
        println!("{}", serde_json::to_string_pretty(&source)?);
        return Ok(());
    }
    print_graph_response(response)
}

/// `kin graph body <entity>` — alias for `kin graph source <entity>`.
pub async fn body(entity: String, json: bool) -> Result<()> {
    source(entity, json).await
}

async fn run_daemon_graph(
    layout: &kin_core::KinLayout,
    request: &GraphCommandRequest,
) -> Result<GraphCommandResponse> {
    let daemon_url = std::env::var("KIN_DAEMON_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(Some)
        .unwrap_or(crate::daemon_client::resolve_daemon_url(layout).await?);
    let base_url = daemon_url
        .ok_or_else(|| crate::daemon_client::daemon_required_error("graph commands", layout))?;
    let client = crate::daemon_client::DaemonClient::from_base_url(base_url)?;
    client
        .graph_command(request)
        .await
        .map_err(|e| anyhow::anyhow!("daemon graph command failed: {e:#}"))
}

fn print_graph_response(response: GraphCommandResponse) -> Result<()> {
    for line in response.lines {
        println!("{line}");
    }
    if let Some(error) = response.error {
        anyhow::bail!(error);
    }
    Ok(())
}

/// Render a graph command.
///
/// `reconcile` is the running daemon's account of what its reconciliation loop
/// has actually admitted. It is a separate argument rather than something
/// derived from the graph because it cannot be derived from the graph: a store
/// whose every admission has failed for two days holds a graph that is
/// internally perfect and simply out of date, and every content check here
/// passes on it. That is how `kin graph status` came to report no issues on a
/// store the daemon had been failing to admit since Aug 6.
///
/// `authority` is how this command reaches durable repository state. It is a
/// [`RequestRepositoryAuthority`](super::repository_authority::RequestRepositoryAuthority)
/// rather than a binding because opening durable authority re-verifies every
/// persisted body against its content address, and a long-lived server that has
/// already opened at the publication this request reads should not pay for it
/// again per request. `status` used to take a bare binding and so opened the
/// whole store on every call, which is where most of its wall time went.
pub fn execute_graph_command(
    authority: &super::repository_authority::RequestRepositoryAuthority,
    graph: &kin_db::InMemoryGraph,
    request: &GraphCommandRequest,
    reconcile: &crate::commands::resources::ReconcileHealth,
    embedding_runtime: &crate::commands::resources::EmbedRuntimeState,
    census: &kin_core::relation_census::CensusContext,
) -> Result<GraphCommandResponse> {
    execute_graph_command_for_store(
        authority,
        graph,
        request,
        reconcile,
        embedding_runtime,
        census,
        None,
    )
}

/// The same command, told which store on disk it is reporting about.
///
/// Separate from [`execute_graph_command`] rather than an extra parameter on it
/// because the store is knowable only to a caller that holds the layout, which
/// today is the daemon and nobody else. Every other caller, including this
/// module's own tests, asks the same question about a graph it already has in
/// hand and has no `.kin` directory to name.
pub fn execute_graph_command_for_store(
    authority: &super::repository_authority::RequestRepositoryAuthority,
    graph: &kin_db::InMemoryGraph,
    request: &GraphCommandRequest,
    reconcile: &crate::commands::resources::ReconcileHealth,
    embedding_runtime: &crate::commands::resources::EmbedRuntimeState,
    census: &kin_core::relation_census::CensusContext,
    kin_root: Option<&std::path::Path>,
) -> Result<GraphCommandResponse> {
    match request {
        GraphCommandRequest::Status => build_graph_status_response_for_store(
            authority,
            graph,
            reconcile,
            embedding_runtime,
            census,
            kin_root,
        ),
        GraphCommandRequest::Validate => build_graph_validate_response(authority, graph),
        GraphCommandRequest::Inspect { name } => build_graph_inspect_response(graph, name),
        GraphCommandRequest::Source { entity } => {
            build_graph_source_response(authority, graph, entity)
        }
    }
}

/// Whether coverage counters describe an attached vector index.
///
/// With no index attached, `embedding_status` answers `indexed = 0` for every
/// retrievable object. That zero is structural; `vector_index_stats()` is the
/// call that distinguishes an index that is absent from one that is measured.
#[cfg(feature = "vector")]
fn embedding_coverage_is_measured(graph: &kin_db::InMemoryGraph) -> bool {
    graph.vector_index_stats().is_some()
}

/// Without vector support there is no index to attach and no structural zero
/// to guard against; the legacy rendering stays.
#[cfg(not(feature = "vector"))]
fn embedding_coverage_is_measured(_graph: &kin_db::InMemoryGraph) -> bool {
    true
}

/// The whole-graph relation totals the completeness section reports beside its
/// per-language reference rows.
///
/// Artifact-level import edges are not reachable from an entity-rooted
/// traversal, so they are derived as the difference between the graph-wide
/// count of a kind and the entity-rooted count the caller already has.
fn graph_relation_totals(
    graph: &kin_db::InMemoryGraph,
    entity_relation_counts: &HashMap<RelationKind, usize>,
    entity_relations: usize,
    cross_file_relations: usize,
) -> kin_core::reference_coverage::GraphRelationTotals {
    let stats = graph.graph_stats();
    let artifact_import_relations: usize = [RelationKind::Imports, RelationKind::Includes]
        .into_iter()
        .map(|kind| {
            let graph_wide = stats
                .relation_counts
                .get(&format!("{kind:?}"))
                .copied()
                .unwrap_or(0);
            let entity_rooted = entity_relation_counts.get(&kind).copied().unwrap_or(0);
            graph_wide.saturating_sub(entity_rooted)
        })
        .sum();

    kin_core::reference_coverage::GraphRelationTotals {
        entity_relations,
        cross_file_entity_relations: cross_file_relations,
        artifact_import_relations,
    }
}

/// The relation-kind census, in the one form the durable record and the status
/// row both read.
///
/// Formatting lives here rather than at each call site because the recorded
/// census and the compared census have to key on the same strings. A record
/// written as `UsesType` and read as `uses_type` would report every kind as
/// vanished and every kind as new on the same screen.
fn kind_census(counts: &HashMap<RelationKind, usize>) -> BTreeMap<String, u64> {
    counts
        .iter()
        .map(|(kind, count)| (format!("{kind:?}"), *count as u64))
        .collect()
}

/// Take the entity-rooted relation-kind census of `graph`.
///
/// Entity-rooted, and de-duplicated by relation id, because that is exactly
/// what the `Entity-to-entity relation kinds` line reports: an edge reachable
/// from both endpoints is one edge. A census taken any other way would compare
/// a different measurement against the printed one and report movement that
/// never happened.
///
/// Deliberately not `graph_stats()`, which counts the whole relation table and
/// probes the text and vector indexes once per entity on the way. Those probes
/// are the cost `kin graph status` is already known for, and the writers of this
/// record are a sweep and a commit, neither of which should pay it.
pub fn measure_relation_census(graph: &kin_db::InMemoryGraph) -> Result<BTreeMap<String, u64>> {
    Ok(measure_relation_census_with_entities(graph)?.0)
}

/// The census above, and the entity count it was taken beside.
///
/// One walk for both, because the pair is only interpretable if the two numbers
/// describe the same graph at the same instant. The entity count is partitioned
/// exactly as the `Entities:` line partitions it, external reference targets
/// excluded, so "the entity count held at 783" in a census warning names the
/// number the reader is looking at rather than a second total nothing prints.
/// Counting external targets here would move this number every time an import
/// resolved differently and turn that into a claim about this repository's own
/// code.
pub fn measure_relation_census_with_entities(
    graph: &kin_db::InMemoryGraph,
) -> Result<(BTreeMap<String, u64>, u64)> {
    let mut counts: HashMap<RelationKind, usize> = HashMap::new();
    let mut seen = HashSet::new();
    let mut defined: u64 = 0;
    for entity in graph.list_all_entities()? {
        if !kin_index::is_external_reference_target(&entity) {
            defined += 1;
        }
        for relation in graph.get_all_relations_for_entity(&entity.id)? {
            if seen.insert(relation.id) {
                *counts.entry(relation.kind).or_insert(0) += 1;
            }
        }
    }
    Ok((kind_census(&counts), defined))
}

/// The one line that answers "how much of this repository can I query".
///
/// Pure so both arms are testable without a store. A repository with nothing
/// admitted has no fraction to state and says so rather than printing a ratio
/// over zero, which is the shape this line exists to stop producing.
fn repository_coverage_line(files_with_entities: usize, admitted: usize) -> String {
    if admitted == 0 {
        return "Repository coverage: no files admitted yet, so there is no coverage fraction to \
                report"
            .to_string();
    }
    format!(
        "Repository coverage: {files_with_entities} of {admitted} admitted files produced \
         entities ({:.0}%)",
        (files_with_entities as f64 / admitted as f64) * 100.0
    )
}

/// The status renderer as every test asks for it, about a graph with no store
/// named beside it.
///
/// A wrapper rather than a defaulted argument so a test that has no `.kin`
/// directory keeps the spelling it had, and so the store-aware path is the one
/// that has to say which store it means.
#[cfg(test)]
fn build_graph_status_response(
    authority: &super::repository_authority::RequestRepositoryAuthority,
    graph: &kin_db::InMemoryGraph,
    reconcile: &crate::commands::resources::ReconcileHealth,
    embedding_runtime: &crate::commands::resources::EmbedRuntimeState,
    census: &kin_core::relation_census::CensusContext,
) -> Result<GraphCommandResponse> {
    build_graph_status_response_for_store(
        authority,
        graph,
        reconcile,
        embedding_runtime,
        census,
        None,
    )
}

fn build_graph_status_response_for_store(
    authority: &super::repository_authority::RequestRepositoryAuthority,
    graph: &kin_db::InMemoryGraph,
    reconcile: &crate::commands::resources::ReconcileHealth,
    embedding_runtime: &crate::commands::resources::EmbedRuntimeState,
    census: &kin_core::relation_census::CensusContext,
    kin_root: Option<&std::path::Path>,
) -> Result<GraphCommandResponse> {
    // One sample for every embedding line in this response. The counter below
    // and the health warning used to sample coverage independently, and an
    // embed batch completing between the two reads made the warning name a
    // pending count the counter beside it contradicted by exactly one batch
    // (the v0.5.21 battery caught 1 of 12 paired readings disagreeing by 512).
    let embed_status = graph.embedding_status();
    let coverage_is_measured = embedding_coverage_is_measured(graph) || embed_status.total == 0;
    // One listing for this whole response. It feeds both the counters below and
    // the health report, which used to take its own and clone every entity in
    // the graph a second time.
    let entities = graph.list_all_entities()?;
    let mut health =
        inspect_graph_with_entities(authority, graph, &entities, Some(embed_status.pending))?;

    // An external reference target is a node this repository references without
    // owning: no file, no span, no signature, and a uniform kind. Counting it
    // among the entities this repository holds would report documentation
    // coverage falling with no change to documentation, put a fabricated bucket
    // in the kind histogram, and make the entity and file totals stop
    // corresponding. It is counted on its own line instead, so it is disclosed
    // rather than either hidden or folded into a claim about this repository's
    // own code.
    let (defined, external_targets): (Vec<&Entity>, Vec<&Entity>) = entities
        .iter()
        .partition(|e| !kin_index::is_external_reference_target(e));
    let entity_count = defined.len();

    // Role counts, over the entities this repository defines. Role
    // classification is a statement about a repository's own files, and the
    // warning below reads these counts to decide whether the classifier ran at
    // all.
    let mut role_counts: HashMap<EntityRole, usize> = HashMap::new();
    for e in &defined {
        *role_counts.entry(e.role).or_insert(0) += 1;
    }

    // Kind counts
    let mut kind_counts: HashMap<EntityKind, usize> = HashMap::new();
    for e in &defined {
        *kind_counts.entry(e.kind).or_insert(0) += 1;
    }

    // Relation counts by kind. Entity-rooted traversal only reaches edges whose
    // src and dst are both entities, so this total is narrower than the whole
    // relation table, which also carries artifact-, test-, contract-, work-, and
    // verification-run-anchored edges. Both totals are reported below, each
    // labeled with the scope it counts.
    let mut relation_counts: HashMap<RelationKind, usize> = HashMap::new();
    let mut seen_relation_ids = HashSet::new();
    let mut total_relations = 0usize;
    // Whether an edge crosses a file boundary is the fact that decides whether
    // this graph can answer what calls what, and it is invisible in the
    // relation-kind histogram: a `Calls` total says nothing about how many of
    // those calls left the file they were written in. Both endpoints are
    // resolved through the entity's own file origin, so an edge is only counted
    // as cross-file when the graph knows both files and they differ.
    let origin_by_entity: HashMap<kin_model::EntityId, (&str, kin_model::LanguageId)> = entities
        .iter()
        .filter_map(|e| {
            e.file_origin
                .as_ref()
                .map(|file| (e.id, (file.0.as_str(), e.language)))
        })
        .collect();
    let mut cross_file_relations = 0usize;
    for e in &entities {
        for rel in graph.get_all_relations_for_entity(&e.id)? {
            if seen_relation_ids.insert(rel.id) {
                *relation_counts.entry(rel.kind).or_insert(0) += 1;
                total_relations += 1;
                let crossing =
                    rel.src
                        .as_entity()
                        .zip(rel.dst.as_entity())
                        .is_some_and(|(src, dst)| {
                            match (origin_by_entity.get(&src), origin_by_entity.get(&dst)) {
                                (Some((src_file, _)), Some((dst_file, _))) => src_file != dst_file,
                                _ => false,
                            }
                        });
                if crossing {
                    cross_file_relations += 1;
                }
            }
        }
    }

    // One completeness statement for this response, assembled where the counts
    // already exist. The all-kinds totals are counted here rather than re-walked
    // inside the collector, so every edge is counted once, and the
    // language-server probe is attached here rather than in kin-core, which
    // measures graph truth and never probes the host.
    let coverage =
        std::mem::take(&mut health.reference_edge_coverage).with_totals(graph_relation_totals(
            graph,
            &relation_counts,
            total_relations,
            cross_file_relations,
        ));
    // Read the readiness a process with the right to spawn already established,
    // rather than probing the host from a query path. When nobody has published,
    // the rows are left at their default, which is unknown: an empty map would
    // read as every server missing, and reporting a gap nothing looked for is
    // the mistake this whole area exists to stop.
    health.reference_edge_coverage =
        match kin_mcp::edge_coverage::published_language_server_readiness() {
            Some(readiness) => coverage.with_language_servers(&readiness),
            None => coverage,
        };

    // File count
    let unique_files: HashSet<_> = entities
        .iter()
        .filter_map(|e| e.file_origin.as_ref().map(|f| f.0.clone()))
        .collect();

    // Doc summary coverage
    let with_docs = defined.iter().filter(|e| e.doc_summary.is_some()).count();

    let mut lines = Vec::new();
    lines.push("=== Graph Health ===".to_string());
    lines.push(String::new());
    // Name the view before the number. This counter and the one `kin status`
    // prints are two different measurements of one store, and a reader given
    // both bare totals has no way to tell which denominator applies to the
    // coverage question they are actually asking. Each surface states what it
    // counts, and the reconciliation below states why they differ.
    lines.push(format!(
        "Entities: {} (live query graph, definitions this repository owns)  |  Entity-to-entity \
         relations: {}  |  Files: {} (files those entities originate in)",
        entity_count,
        total_relations,
        unique_files.len()
    ));
    // The answer to the first question anyone asks after a conversion, stated
    // once, with a label.
    //
    // Four counters on this screen bear on repository coverage (files that
    // produced entities, supported inputs, admitted files, files awaiting an
    // enrichment facet) and none of them said which one answers it. A stranger
    // reading `Files: 66` beside `Supported inputs: 141` beside `213 admitted
    // regular files` concluded, correctly, that the output could not tell them
    // what fraction of the repository they could query. Anyone who cannot
    // answer that has no way to calibrate how much to trust an empty result.
    let admitted = health
        .repository_artifact_coverage
        .enrichable_artifact_count;
    let supported = health.supported_entity_source_file_count;
    lines.push(repository_coverage_line(unique_files.len(), admitted));
    // Why the other counters differ, as arithmetic rather than an inference left
    // to the reader. `Supported inputs` is an upper bound on coverage and was
    // read as a contradiction of it.
    if admitted > 0 && supported >= unique_files.len() {
        lines.push(format!(
            "  of the {admitted} admitted, {supported} carry a full language adapter; {} of \
             those produced no entity",
            supported - unique_files.len()
        ));
    }
    lines.push(format!(
        "Entity-to-entity rels/entity: {:.2}",
        if entity_count == 0 {
            0.0
        } else {
            total_relations as f64 / entity_count as f64
        }
    ));
    // The reconciliation between this surface and `kin status`, stated as
    // arithmetic rather than left to the reader.
    //
    // These two totals counted the same store and disagreed by 45 on the
    // 0.5.36 evidence store, with nothing on either surface acknowledging a
    // second view existed. The excluded set is not a rounding difference: the
    // partition above drops external reference targets from `entity_count` on
    // purpose (counting a node this repository merely references would report
    // documentation coverage falling with no change to documentation), while
    // durable authority enrichment replays every semantic identity it admitted
    // and so counts them. Naming the excluded count beside the total is what
    // makes the two surfaces add up.
    lines.push(format!(
        "External reference targets: {} (referenced elsewhere, not defined here, and excluded \
         from the entity total above; `kin status` reports durable authority enrichment, a \
         different view that counts them, so its entity total is the larger of the two)",
        external_targets.len()
    ));
    lines.push(String::new());

    // Roles
    let role_order = [
        (EntityRole::Source, "source"),
        (EntityRole::Test, "test"),
        (EntityRole::External, "external"),
        (EntityRole::Docs, "docs"),
        (EntityRole::Generated, "generated"),
        (EntityRole::Vendored, "vendored"),
    ];
    let role_parts: Vec<String> = role_order
        .iter()
        .filter_map(|(role, label)| role_counts.get(role).map(|c| format!("{label}: {c}")))
        .collect();
    lines.push(format!("Roles: {}", role_parts.join(", ")));

    // Relation types
    let mut rel_pairs: Vec<_> = relation_counts.iter().collect();
    rel_pairs.sort_by(|a, b| b.1.cmp(a.1));
    let rel_parts: Vec<String> = rel_pairs
        .iter()
        .map(|(kind, count)| format!("{:?}: {}", kind, count))
        .collect();
    lines.push(format!(
        "Entity-to-entity relation kinds: {}",
        rel_parts.join(", ")
    ));
    // The line above is a census, and until this one existed it was compared to
    // nothing. A store that lost an entire relation kind printed the histogram
    // that proved it and then printed the all-clear: on the rc0545c run
    // `UsesType` went 94 to 0 in 36 minutes under `✓ No issues detected.` This
    // row sits directly beneath the histogram because it is the histogram's
    // own reading, and it renders in every state, including the two where
    // nothing can be compared. A row that fell silent when it had no previous
    // census would be indistinguishable from one reporting a healthy store.
    //
    // The entity count goes in beside the kinds because a relation count alone
    // cannot say whether edges were lost or code was. A store that removed a
    // module holds fewer `Calls` edges and should; a store whose entity count
    // did not move and holds eleven fewer of them lost a derivation, which is
    // what the rc0547b comment-only commit did. This is the same `entity_count`
    // the `Entities:` line above prints, from the same walk.
    let census_comparison = kin_core::relation_census::RelationCensusComparison::build(
        &census.previous,
        &kind_census(&relation_counts),
        census.causes.clone(),
    )
    .with_current_entities(entity_count as u64);
    lines.push(census_comparison.summary_line());

    // Kind distribution
    let mut kind_pairs: Vec<_> = kind_counts.iter().collect();
    kind_pairs.sort_by(|a, b| b.1.cmp(a.1));
    let kind_parts: Vec<String> = kind_pairs
        .iter()
        .take(8)
        .map(|(kind, count)| format!("{:?}: {}", kind, count))
        .collect();
    lines.push(format!("Kinds: {}", kind_parts.join(", ")));

    lines.push(String::new());
    // The counters are true in every state below: with no vector index
    // attached, zero retrievable objects really are indexed in this graph.
    // What the bare counters cannot say is WHY, and a reader who cannot tell a
    // discarded index from a first fill reads every one of them as loss. So the
    // counters always render and the cause is appended when the daemon knows
    // one. Each clause states only a fact the daemon holds; none of them
    // promises the vectors are intact, because nothing on this path can know
    // that. `kin status` reports the same absence as "the live graph carries no
    // vector index" and publishes no coverage at all, which is the wording
    // followed here.
    let mut embeddings_line = format!(
        "Embeddings: {}/{} indexed ({} pending)",
        embed_status.indexed, embed_status.total, embed_status.pending
    );
    let embedding_coverage = kin_core::memory_pressure::EmbeddingCoverage {
        pending: embed_status.pending,
        indexed: embed_status.indexed,
        total: embed_status.total,
    };
    if embedding_persistence_blocks_coverage(
        embedding_runtime.embed_persistence_unavailable,
        embedding_coverage,
    ) {
        // Outranks every clause below, exactly as it does in
        // `semantic_query_health_from_runtime`: this store's graph authority is
        // a remote backend, the embedding worker never starts and `/embed`
        // refuses, so even an empty current queue is not a filling backlog when
        // selected-graph coverage remains short.
        embeddings_line.push_str(
            "; this store's graph authority is a remote storage backend, which carries no \
             durable local vector-sidecar contract, so nothing will embed here",
        );
    } else if embed_status.pending > 0 {
        if let Some(reason) = embedding_runtime.vector_index_discarded.as_ref() {
            // A real gap, reported with its cause. Naming the open-time discard
            // and the automatic recovery is what tells the operator no manual
            // GPU pass is owed. The reason is recorded once at open and never
            // cleared, so it is named only while the gap it explains is still
            // open; a recovered store goes back to the plain line.
            embeddings_line.push_str(&format!(
                "; the persisted vector index was not loaded when this daemon opened ({reason}); \
                 the daemon restores coverage in the background"
            ));
        } else if let Some(salvage) = embedding_runtime.vector_index_salvage {
            // The state FIR-2562 was filed for, and the reason the clause below
            // it could never reach it: a per-key salvage INSTALLS an index, so
            // no discard is recorded and `coverage_is_measured` holds. Before
            // the counts existed on this side of the boundary the line could
            // say only that a fill had finished here once. Now it can name the
            // loss and its size.
            //
            // The cause is stated as what was observed, a sidecar whose stamp
            // no longer matched graph authority, and nothing further is
            // asserted. An ordinary commit between flush and reopen drifts the
            // same stamp with nothing wrong, so naming a fault here would be an
            // exemption doubling as a proof of its own cause.
            embeddings_line.push_str(&format!(
                "; when this daemon opened, the persisted vector index no longer matched this \
                 repository's graph authority, so it was salvaged per key: {} vectors were kept \
                 and {} were retired, and only the retired keys re-embed",
                salvage.kept, salvage.dropped
            ));
        } else if !coverage_is_measured {
            // No index is attached and the daemon recorded no discard at open,
            // so these zeros are structural rather than a measurement of a
            // store that lost ground. That is all this path knows. It does NOT
            // know the vectors are sitting intact somewhere: an index that
            // loaded at open would still be attached, so this branch is reached
            // only when there was no sidecar to load, or when a later reset
            // detached one. Both of those rebuild rather than re-attach, so no
            // clause here may tell the reader to wait instead of embedding.
            embeddings_line.push_str(
                "; the live graph carries no vector index, so nothing in it is indexed yet",
            );
            if embedding_runtime.embedding_coverage_ever_complete {
                embeddings_line.push_str(" and coverage has completed on this store before");
            }
        } else if embedding_runtime.embedding_coverage_ever_complete {
            // An index IS attached, coverage is short, and nothing above
            // applies. Until this arm existed the line fell off the end of the
            // chain and rendered bare, so a store that had lost ground read
            // exactly like a store filling for the first time. The evidence is
            // the rc0545c brown arm, which logged a per-key vector salvage at
            // 00:35:35Z and then published `Embeddings: 1770/2112 indexed (342
            // pending)` at 00:38:19Z with nothing beside it (FIR-2562).
            //
            // The arm above cannot cover this case: it is gated on no index
            // being attached, and a salvage attaches one. The marker this reads
            // is durable rather than latched in memory
            // (`DaemonState::embedding_coverage_ever_complete`), so the daemon
            // that opens after the drift still knows what an earlier daemon on
            // this store finished, which is what makes the arm reachable in the
            // very case it exists for.
            //
            // The claim stops where the evidence does. This says a fill
            // finished here once and this shortfall is measured against it. It
            // does NOT say what caused the shortfall, and it still cannot: a
            // working copy that admitted new files and a sidecar that retired
            // keys at open both land here, and only the second is a loss. The
            // arm above is where a loss gets named, and it is reached only when
            // the daemon actually recorded a salvage. So this remains the
            // honest wording for everything else, and no clause here may imply
            // kin knows a cause it was not told.
            embeddings_line.push_str(
                "; coverage has completed on this store before, so this is a shortfall against a \
                 fill that finished rather than a first fill",
            );
        }
        // Appended after the chain rather than folded into it: every clause
        // above stays true while the model is arriving, and this names the one
        // thing standing in front of all of them right now. Without it the
        // first fill on a fresh machine reports a pending backlog and a worker
        // with nothing to show for several hundred megabytes of egress.
    }
    if embed_status.pending > 0 {
        if let Some(clause) = embedding_runtime.model_fetch.status_clause() {
            embeddings_line.push_str(&clause);
        }
    }
    // Outside the pending gate on purpose, and the only clause here that is.
    //
    // Every clause above explains a shortfall the counters are already showing.
    // This one explains a shortfall they are not: the daemon holds embedded
    // vectors the sidecar does not, so the count beside it is true about this
    // process and would not survive its exit. A drained queue reports zero
    // pending in exactly that state, which is how the regression reached a
    // reader as a complete store one minute and ordinary pending work the next.
    // The clause says what is undurable, and does not promise a number: nothing
    // on this path counts the vectors embedded since the refusal.
    if let Some(reason) = embedding_runtime.deferred_vector_checkpoint.as_ref() {
        embeddings_line.push_str(&format!(
            "; the last vector checkpoint was refused ({reason}), so vectors embedded since then \
             are in this daemon's memory rather than on disk and a restart re-derives them; the \
             daemon retries the checkpoint until it lands"
        ));
    }
    lines.push(embeddings_line);
    // A census, not a queue, and the label has to say so.
    //
    // This counter sat directly beneath the embeddings line above, which IS a
    // fill counter with a real pending count, and read as the same kind of
    // thing. On the 0.5.36 evidence store it showed 305/777 at the start of a
    // session and the identical 305/777 at the end, which a reader took for a
    // stalled worker. Nothing stalled and nothing was scheduled: `doc_summary`
    // is set by the language extractors from the comment preceding a
    // declaration (`extract_preceding_comment`, every adapter in kin-parser)
    // and by nothing else on any live path. So the fraction is a property of
    // the source code, and it moves only when the source gains or loses doc
    // comments. Stating that inline is the fix; there is no queue depth to
    // publish and no stalled flag to raise.
    lines.push(format!(
        "Documented entities: {}/{} ({:.0}%) carry a doc comment extracted from the source at \
         parse time (a census of the code as written, not a job filling in the background)",
        with_docs,
        entity_count,
        if entity_count == 0 {
            0.0
        } else {
            (with_docs as f64 / entity_count as f64) * 100.0
        }
    ));
    lines.push(format!(
        "All graph relations excluding CoChanges: {} ({:.2}/entity)",
        health.semantic_relation_count, health.semantic_relation_density_excluding_cochanges
    ));
    // Named for what it measures. "Supported inputs: 141" beside "Files: 66"
    // reads as a contradiction until the line says the two count different
    // things: what an adapter can parse, and what actually produced an entity.
    lines.push(format!(
        "Supported inputs: {} admitted files a full adapter parses, {} a shallow one (an upper \
         bound on coverage, not a count of files that produced entities)",
        health.supported_entity_source_file_count, health.supported_shallow_source_file_count
    ));
    lines.push(format!(
        "Contaminated paths: {}",
        health.contaminated_path_count
    ));
    if !health.contaminated_paths_sample.is_empty() {
        lines.push(format!(
            "Contamination sample: {}",
            health.contaminated_paths_sample.join(", ")
        ));
    }

    // How much of the parsed reference surface reached the graph. Every counter
    // above describes what the graph HOLDS; none of them could say what it is
    // MISSING, so a graph carrying a fifth of its call edges reported density
    // 0.38 and a clean bill while five shipped tools answered from the absent
    // four fifths.
    lines.push(String::new());
    lines.extend(health.reference_edge_coverage.summary_lines());

    // Warnings
    let mut warnings = health.warnings.clone();
    let criticals = health.critical_issues.clone();
    let all_relation_count = health
        .semantic_relation_count
        .saturating_add(health.cochange_relation_count);
    if entity_count > 0 && all_relation_count == 0 {
        warnings.push("no relations in graph — cross-file linking may have failed".to_string());
    }
    if entity_count > 0 && role_counts.len() == 1 && role_counts.contains_key(&EntityRole::Source) {
        warnings
            .push("all entities are Source — role classification may not be working".to_string());
    }
    let entity_rels_per_ent = if entity_count == 0 {
        0.0
    } else {
        total_relations as f64 / entity_count as f64
    };
    if entity_rels_per_ent < 0.1 && entity_count > 100 {
        warnings.push(format!(
            "very low entity-to-entity relation density ({:.2} rels/entity) — entity linker may be failing",
            entity_rels_per_ent
        ));
    }
    // Reported as warnings rather than as criticals on purpose. A degraded
    // reconcile loop is a live runtime fault and not a defect in the graph this
    // command inspected, and criticals set the response error, which would turn
    // `kin graph status` nonzero for every caller scripting it. Killing the
    // false all-clear is the requirement; changing an exit code is not.
    for reason in reconcile.degraded_reasons() {
        warnings.push(format!("reconcile loop degraded — {reason}"));
    }
    // Warnings rather than criticals, for the reason stated directly above:
    // criticals set the response error and would turn `kin graph status`
    // nonzero for every caller scripting it. A lost relation kind is a real
    // defect in graph truth and it must withhold the all-clear, which a warning
    // does; changing an exit code is a separate decision from killing a false
    // all-clear, and only the second is what this closes.
    warnings.extend(census_comparison.loss_lines());
    // A daemon killed by the memory limit is invisible to every counter above
    // it. The graph it left behind is intact and a replacement is serving, so a
    // store whose daemon has been killed twenty-five times prints a clean
    // report with an all-clear under it. The store's own record is the only
    // thing that remembers, and this is the page a reader is already on.
    // The store's tally OR a death it has not settled yet, for the reason the
    // `kin doctor` row reads both: settlement happens at the next daemon start,
    // and a reader asking this page why the numbers stopped moving may not have
    // started one since the daemon died.
    if let Some(record) = kin_root.and_then(crate::daemon_death::recorded_for_store) {
        warnings.push(record.summary());
    }
    // A suspended sweep is invisible in the same way, and worse: every counter
    // above reads as work still pending, so a store whose enrichment has been
    // switched off looks exactly like one that is converging. The producer that
    // would close the gap is off, and only the store's tally remembers.
    if let Some(suspended) = kin_root.and_then(kin_daemon_spawn::SuspendedSweep::read) {
        warnings.push(suspended.summary());
    }
    // Work the daemon declined for want of memory is invisible in the same way
    // and for the same reason: the counters above report it as pending, and the
    // process that declined it left nothing behind but this record.
    //
    // "The counters above report it as pending" is the condition, not a given,
    // and the counter is right here. A store at `952/952 indexed (0 pending)`
    // printed the embed refusal under its own complete line, so the record is
    // asked whether it still describes work before it is published.
    if let Some(kin_root) = kin_root {
        let refusals = kin_core::memory_pressure::PressureRefusal::read_all(kin_root);
        let coverage = kin_core::memory_pressure::EmbeddingCoverage {
            pending: embed_status.pending,
            indexed: embed_status.indexed,
            total: embed_status.total,
        };
        if let Some(warning) = pressure_refusal_warning(&refusals, coverage) {
            warnings.push(warning);
        }
    }
    if warnings.is_empty() && criticals.is_empty() {
        lines.push(String::new());
        lines.push("✓ No issues detected.".to_string());
    } else {
        lines.push(String::new());
        for issue in &criticals {
            lines.push(format!("✗ {}", issue));
        }
        for w in &warnings {
            lines.push(format!("⚠ {}", w));
        }
    }
    // Printed beside the verdict rather than as part of it. Untracked host
    // content is not a fault, so it withholds no all-clear; it is the answer to
    // the question a reader actually arrives with, which is why a file they can
    // see on disk has no entities in the graph.
    let notices = reconcile.notices();
    if !notices.is_empty() {
        lines.push(String::new());
        for notice in notices {
            lines.push(format!("ℹ {notice}"));
        }
    }
    append_health_notes(&mut lines, &health.notes);

    Ok(GraphCommandResponse {
        lines,
        error: (!criticals.is_empty())
            .then(|| format!("{} critical graph health issue(s) found", criticals.len())),
        source: None,
        reference_edge_coverage: Some(health.reference_edge_coverage.clone()),
        relation_census: Some(census_comparison),
    })
}

/// Render a pressure refusal only while the coverage beside it says its work
/// remains. Kept pure so the response rule can be graded without writing a
/// store record or racing an embedding worker.
fn pressure_refusal_warning(
    refusals: &[kin_core::memory_pressure::PressureRefusal],
    coverage: kin_core::memory_pressure::EmbeddingCoverage,
) -> Option<String> {
    refusals
        .iter()
        .rev()
        .find(|refusal| refusal.describes_outstanding_work(coverage))
        .map(|refusal| format!("{} {}", refusal.cause_sentence(), refusal.remediation()))
}

/// Whether an unavailable vector checkpoint producer is an active blocker for
/// this selected graph. Queue depth alone cannot decide: a refused missing-key
/// backfill may be queue-empty while indexed coverage is still short.
fn embedding_persistence_blocks_coverage(
    unavailable: bool,
    coverage: kin_core::memory_pressure::EmbeddingCoverage,
) -> bool {
    unavailable && !coverage.is_complete()
}

/// Render a health report's notes in the single form every graph reporting
/// surface uses.
///
/// Notes describe expected absences rather than defects, so they follow the
/// verdict instead of suppressing it. `status` and `validate` render them from
/// here so the two cannot drift: a surface that carries the verdict but drops
/// the notes reports a repository whose enrichment is still pending as
/// indistinguishable from a fully enriched one.
fn append_health_notes(lines: &mut Vec<String>, notes: &[String]) {
    for note in notes {
        lines.push(format!("ℹ {}", note));
    }
}

fn build_graph_validate_response(
    authority: &super::repository_authority::RequestRepositoryAuthority,
    graph: &kin_db::InMemoryGraph,
) -> Result<GraphCommandResponse> {
    let health = inspect_graph(authority, graph)?;

    // Validation needs the complete relation table, including corrupt edges
    // whose source and destination are both absent. Entity-rooted traversal
    // cannot discover those edges. A live snapshot is a coherent, graph-owned
    // view of both tables; relation IDs are still deduplicated defensively
    // below before endpoint accounting.
    let snapshot = graph.to_snapshot();
    let entities: Vec<_> = snapshot.entities.into_values().collect();
    let relations = snapshot.relations.into_values();
    let mut issues = Vec::new();

    // Check for duplicate entities (same name + file + kind + byte position).
    // Using byte position distinguishes legitimate overloads (Python @overload,
    // Rust impl From<X>, C++ template specializations) from true duplicates: two
    // entities declared at different positions in one file are never duplicates.
    //
    // An entity with no span has no position to be distinguished by, and
    // collapsing that to byte zero makes the position discriminate nothing. An
    // external reference target is exactly that shape: it stands for a symbol
    // another repository owns, so it carries no file and no span, and its kind
    // is uniform. Name alone would then report two legitimately distinct
    // targets as one duplicated entity, which is what `use log::info` beside
    // `use tracing::info` produces on an ordinary repository. Its fingerprint
    // is derived from the facts that do identify it, the import source and the
    // symbol, so it stands in for the absent position and keeps the check
    // meaningful: two targets naming different import sources stay distinct,
    // while two entities claiming the same import source and symbol are still
    // reported. Entities that do carry a span keep the position key exactly as
    // before, so nothing this check used to catch stops being caught.
    let mut seen: HashMap<
        (String, Option<String>, EntityKind, usize, Option<Hash256>),
        Vec<kin_model::EntityId>,
    > = HashMap::new();
    for e in &entities {
        let start_byte = e.span.as_ref().map(|s| s.start_byte).unwrap_or(0);
        let placeless_identity = e.span.is_none().then_some(e.fingerprint.ast_hash);
        let key = (
            e.name.clone(),
            e.file_origin.as_ref().map(|f| f.0.clone()),
            e.kind,
            start_byte,
            placeless_identity,
        );
        seen.entry(key).or_default().push(e.id);
    }
    let duplicates: Vec<_> = seen.iter().filter(|(_, ids)| ids.len() > 1).collect();
    if !duplicates.is_empty() {
        issues.push(format!(
            "{} true duplicate entities (same name+file+kind, same position or same identity)",
            duplicates.len()
        ));
    }

    // Check for orphaned entities against graph-owned exact tree membership.
    // The working directory is only a projection and cannot invalidate graph
    // authority.
    let resolved_tree = graph.resolved_tree();
    let mut orphaned = 0usize;
    for e in &entities {
        if let Some(ref fo) = e.file_origin {
            let present = kin_model::RepoPath::from_utf8(fo.0.clone())
                .ok()
                .and_then(|path| resolved_tree.artifact_at_path(&path))
                .is_some();
            if !present {
                orphaned += 1;
            }
        }
    }
    if orphaned > 0 {
        issues.push(format!(
            "{} orphaned entities (file is absent from graph-owned exact tree)",
            orphaned
        ));
    }

    // Check relation integrity (src/dst entity IDs exist). Cross-repo Calls and
    // References intentionally point at a deterministic external placeholder
    // that is absent from this repo's entity set. The linker marks that exact
    // contract with a non-empty import source and external_import_reference
    // evidence; every other missing endpoint remains a validation failure.
    let entity_ids: std::collections::HashSet<_> = entities.iter().map(|e| e.id).collect();
    let mut seen_relation_ids = HashSet::new();
    let mut broken_relation_endpoints = 0usize;
    for rel in relations {
        if !seen_relation_ids.insert(rel.id) {
            continue;
        }
        if let kin_model::GraphNodeId::Entity(id) = rel.src {
            if !entity_ids.contains(&id) {
                broken_relation_endpoints += 1;
            }
        }
        if let kin_model::GraphNodeId::Entity(id) = rel.dst {
            if !entity_ids.contains(&id) && !kin_index::is_external_import_placeholder(&rel) {
                broken_relation_endpoints += 1;
            }
        }
    }
    let inspected_relation_count = seen_relation_ids.len();
    if broken_relation_endpoints > 0 {
        let (endpoint_label, verb) = if broken_relation_endpoints == 1 {
            ("relation endpoint", "references")
        } else {
            ("relation endpoints", "reference")
        };
        issues.push(format!(
            "{} {} {} non-existent entities",
            broken_relation_endpoints, endpoint_label, verb
        ));
    }

    issues.extend(health.critical_issues.clone());

    let mut lines = Vec::new();
    lines.push("=== Graph Validation ===".to_string());
    lines.push(String::new());
    let relation_label = if inspected_relation_count == 1 {
        "relation"
    } else {
        "relations"
    };
    lines.push(format!(
        "Checked {} entities, {} {}",
        entities.len(),
        inspected_relation_count,
        relation_label
    ));

    if issues.is_empty() {
        lines.push(String::new());
        lines.push("✓ All integrity checks passed.".to_string());
    } else {
        lines.push(String::new());
        for issue in &issues {
            lines.push(format!("✗ {}", issue));
        }
    }

    // "All checks passed" was read as a clean bill on a graph holding a fifth of
    // its relation edges, and it was defensible only because this command checks
    // integrity: whether the edges present point at entities that exist. It
    // cannot check whether the edges that should exist do. So it says which
    // question it answered and prints the answer to the other one beside it,
    // rather than leaving a reader to assume the two are the same check.
    lines.push(String::new());
    lines.push(
        "Integrity only: these checks say the edges present are coherent, not that the edges a \
         reader expects exist."
            .to_string(),
    );
    lines.extend(health.reference_edge_coverage.summary_lines());
    let unsupportable = health
        .reference_edge_coverage
        .unsupportable_absence_reasons();
    if !unsupportable.is_empty() {
        lines.push(String::new());
        for reason in unsupportable {
            lines.push(format!(
                "⚠ absence is not answerable from this graph: {reason}"
            ));
        }
    }
    append_health_notes(&mut lines, &health.notes);

    Ok(GraphCommandResponse {
        lines,
        error: (!issues.is_empty()).then(|| format!("{} issue(s) found", issues.len())),
        source: None,
        reference_edge_coverage: Some(health.reference_edge_coverage.clone()),
        relation_census: None,
    })
}

fn build_graph_inspect_response(
    graph: &kin_db::InMemoryGraph,
    name: &str,
) -> Result<GraphCommandResponse> {
    let entities = graph.list_all_entities()?;
    let matches: Vec<_> = if let Ok(uuid) = uuid::Uuid::parse_str(name.trim()) {
        graph.get_entity(&EntityId(uuid))?.into_iter().collect()
    } else {
        entities
            .into_iter()
            .filter(|e| e.name == name || e.name.ends_with(&format!(".{}", name)))
            .collect()
    };

    if matches.is_empty() {
        return Ok(GraphCommandResponse {
            lines: graph_entity_not_found_lines(name),
            error: Some(format!("no entity found matching '{}'", name)),
            source: None,
            reference_edge_coverage: None,
            relation_census: None,
        });
    }

    let mut lines = Vec::new();
    for entity in matches {
        lines.push(format!("Entity: {} ({:?})", entity.name, entity.kind));
        lines.push(format!("  ID: {}", entity.id));
        lines.push(format!("  Language: {}", entity.language));
        lines.push(format!("  Role: {:?}", entity.role));
        if let Some(ref fo) = entity.file_origin {
            lines.push(format!("  File: {}", fo.0));
        }
        if let Some(ref span) = entity.span {
            let (start_line, end_line) = presentation_span_lines(span);
            lines.push(format!("  Span: lines {start_line}-{end_line}"));
        }
        lines.push(format!("  Signature: {}", entity.signature));
        if let Some(ref doc) = entity.doc_summary {
            lines.push(format!("  Doc: {}", doc));
        }
        lines.push(format!("  Visibility: {:?}", entity.visibility));

        // Show relations
        let rows = inspect_relation_rows(graph, &entity)?;
        if rows.total > 0 {
            lines.push(format!("  Relations ({}):", rows.total));
            for row in &rows.displayed {
                lines.push(format!(
                    "    {} {:?} {}",
                    row.direction, row.kind, row.peer_label
                ));
            }
            if rows.total > rows.displayed.len() {
                lines.push(format!(
                    "    ... and {} more",
                    rows.total - rows.displayed.len()
                ));
            }
        }
        lines.push(String::new());
    }

    Ok(GraphCommandResponse {
        lines,
        error: None,
        source: None,
        reference_edge_coverage: None,
        relation_census: None,
    })
}

/// Peer rows rendered past this point are summarized as a remainder count.
const INSPECT_RELATION_LIMIT: usize = 20;

/// One peer row of a `kin graph inspect` relation list.
#[derive(Debug)]
struct InspectRelationRow {
    direction: &'static str,
    kind: RelationKind,
    peer_label: String,
}

/// Bounded rendered rows plus the full number of unique peer observations.
#[derive(Debug)]
struct InspectRelationRows {
    total: usize,
    displayed: Vec<InspectRelationRow>,
}

/// Build the deduplicated peer rows for one inspected entity.
///
/// Two rows are the same observation when they share direction marker, kind,
/// and peer node, so only one is rendered. Mixed-domain relations are included,
/// and entity labels carry their stable identity because overloads can share a
/// name, kind, and file. Relation identities determine display order, and peer
/// labels are resolved only for the bounded displayed prefix.
fn inspect_relation_rows(
    graph: &kin_db::InMemoryGraph,
    entity: &Entity,
) -> Result<InspectRelationRows> {
    let mut rows = Vec::new();
    let mut seen = HashSet::new();
    let self_node = kin_model::GraphNodeId::Entity(entity.id);
    let mut relations = graph.get_all_relations_for_node(&self_node)?;
    relations.sort_unstable_by_key(|rel| rel.id.0);

    for rel in relations {
        let src_is_self = matches!(rel.src, kin_model::GraphNodeId::Entity(id) if id == entity.id);
        let dst_is_self = matches!(rel.dst, kin_model::GraphNodeId::Entity(id) if id == entity.id);
        let (direction, peer) = match (src_is_self, dst_is_self) {
            (true, true) => ("<->", rel.src),
            (false, true) => ("<-", rel.src),
            (true, false) => ("->", rel.dst),
            (false, false) => continue,
        };
        if !seen.insert((direction, rel.kind, peer)) {
            continue;
        }
        if rows.len() >= INSPECT_RELATION_LIMIT {
            continue;
        }

        let peer_label = match peer {
            kin_model::GraphNodeId::Entity(peer_id) => graph
                .get_entity(&peer_id)?
                .map(|e| {
                    format!(
                        "{} [{:?}] ({}; entity:{})",
                        e.name,
                        e.kind,
                        e.file_origin.as_ref().map(|f| f.0.as_str()).unwrap_or("?"),
                        e.id
                    )
                })
                .unwrap_or_else(|| format!("{}", peer_id)),
            other => other.to_string(),
        };

        rows.push(InspectRelationRow {
            direction,
            kind: rel.kind,
            peer_label,
        });
    }

    Ok(InspectRelationRows {
        total: seen.len(),
        displayed: rows,
    })
}

/// Actionable lines when a `kin graph inspect|source <name>` lookup misses in
/// this repo's graph. Keeps the not-found signal (callers also set the
/// structured `error` field), then points at discovery commands instead of
/// dead-ending. Honest by construction — no claim the symbol exists elsewhere.
fn graph_entity_not_found_lines(name: &str) -> Vec<String> {
    vec![
        format!("Entity '{name}' not found in this repo's graph."),
        format!(
            "hint: try `kin search {name}` to find the symbol by name, or `kin graph status` to confirm the graph is populated."
        ),
    ]
}

/// Resolve an entity's source into a typed [`EntitySourceOutcome`].
///
/// This is the taxonomy authority for `get_entity_source` / `get_entity_body`:
/// it separates a non-existent/stale ID (`NotFound`, non-retryable) from a real
/// entity that has no source body (`NoSource`) from a genuine read/extraction
/// failure (`Err`, e.g. an out-of-bounds span or an unavailable blob). The
/// daemon MCP path consumes this directly so those cases surface distinctly to
/// agents instead of collapsing into one opaque message.
pub fn build_entity_source_outcome(
    repository_authority: &super::repository_authority::RequestRepositoryAuthority,
    graph: &kin_db::InMemoryGraph,
    entity_query: &str,
) -> Result<EntitySourceOutcome> {
    let entity = match resolve_source_entity(graph, entity_query)? {
        Some(e) => e,
        None => {
            return Ok(EntitySourceOutcome::NotFound(
                entity_source_not_found_message(entity_query),
            ));
        }
    };

    // A structurally sourceless entity (no file origin or no span) is a valid ID
    // with nothing to return — reported as `NoSource`, not as the genuine
    // extraction error below (which signals corrupt spans or unavailable blobs).
    if entity.file_origin.is_none() {
        return Ok(EntitySourceOutcome::NoSource(entity_no_source_message(
            &entity,
            "the entity has no file origin",
        )));
    }
    if entity.span.is_none() {
        return Ok(EntitySourceOutcome::NoSource(entity_no_source_message(
            &entity,
            "the entity has no source span",
        )));
    }

    let record = graph_source_record(repository_authority, graph, &entity)?;
    Ok(EntitySourceOutcome::Found(record))
}

pub fn build_graph_source_response(
    repository_authority: &super::repository_authority::RequestRepositoryAuthority,
    graph: &kin_db::InMemoryGraph,
    entity_query: &str,
) -> Result<GraphCommandResponse> {
    match build_entity_source_outcome(repository_authority, graph, entity_query)? {
        EntitySourceOutcome::Found(record) => {
            let mut lines = vec![
                format!(
                    "Entity source for '{}' -> {} ({})",
                    entity_query, record.name, record.kind
                ),
                format!("ID: {}", record.id),
                format!("File: {}", record.file_path),
                format!("Lines: {}-{}", record.start_line, record.end_line),
            ];
            if !record.signature.is_empty() {
                lines.push(format!("Signature: {}", record.signature));
            }
            lines.push("--- Source ---".to_string());
            lines.push(record.body.clone());

            Ok(GraphCommandResponse {
                lines,
                error: None,
                source: Some(record),
                reference_edge_coverage: None,
                relation_census: None,
            })
        }
        EntitySourceOutcome::NotFound(message) => Ok(GraphCommandResponse {
            lines: graph_entity_not_found_lines(entity_query),
            error: Some(message),
            source: None,
            reference_edge_coverage: None,
            relation_census: None,
        }),
        // A valid entity with no retrievable source is an error for the text/`?`
        // command paths (the CLI `kin graph source` and `trace_data_flow`, which
        // drops the step). The MCP path keeps the two apart via the typed outcome.
        EntitySourceOutcome::NoSource(message) => Err(anyhow::anyhow!(message)),
    }
}

/// Agent-facing message for a `get_entity_source` query that resolved to no
/// entity. When the query is a UUID — the shape MCP agents pass — the wording
/// states plainly that the ID does not exist so the agent stops retrying it and
/// probing adjacent IDs; for a name query it points at the discovery tools.
fn entity_source_not_found_message(entity_query: &str) -> String {
    let trimmed = entity_query.trim();
    if uuid::Uuid::parse_str(trimmed).is_ok() {
        format!(
            "no entity exists with ID '{trimmed}'. This entity ID is invalid or stale — it is \
             not present in the graph, so retrying the same ID will not succeed. Use \
             semantic_locate or semantic_search to obtain a current entity ID."
        )
    } else {
        format!(
            "no entity found matching '{trimmed}'. Use semantic_search or semantic_locate to \
             find the entity, then call get_entity_source with the ID it returns."
        )
    }
}

/// Agent-facing message for a real entity that has no source body to return.
/// Explicitly affirms the ID is valid so the agent does not treat it as a
/// missing/stale ID and retry or probe around it.
fn entity_no_source_message(entity: &Entity, reason: &str) -> String {
    format!(
        "entity '{}' ({}) exists in the graph but has no retrievable source: {reason}. The \
         entity ID is valid — this is not a missing or stale ID — there is simply no source \
         body attached to return.",
        entity.name, entity.id
    )
}

fn resolve_source_entity(
    graph: &kin_db::InMemoryGraph,
    entity_query: &str,
) -> Result<Option<Entity>> {
    let trimmed = entity_query.trim();
    if let Ok(uuid) = uuid::Uuid::parse_str(trimmed) {
        return Ok(graph.get_entity(&EntityId(uuid))?);
    }

    if let Some(entity) = kin_ranking::entity_ranking::select_best_entity(graph, trimmed)? {
        return Ok(Some(entity));
    }

    let matches = kin_core::query_trace_matches(graph, trimmed)?;
    Ok(matches.into_iter().next())
}

fn graph_source_record(
    repository_authority: &super::repository_authority::RequestRepositoryAuthority,
    _graph: &kin_db::InMemoryGraph,
    entity: &Entity,
) -> Result<GraphSourceRecord> {
    let authority = repository_authority.open()?;
    let workspace = authority.workspace()?;
    graph_source_record_from(&authority, &workspace, entity)
}

/// Build an entity's source record through an authority the caller already
/// holds open.
///
/// Opening authority verifies every stored body once, linear in store size, so
/// a caller that needs records for many entities must pay that once for the set
/// rather than once per entity. `graph_source_record` above is the single-record
/// convenience wrapper; batch callers own the open and pass it here.
pub(crate) fn graph_source_record_from(
    authority: &super::repository_authority::ActiveRepositoryAuthority,
    workspace: &kin_model::WorkspaceState,
    entity: &Entity,
) -> Result<GraphSourceRecord> {
    let file_origin = entity
        .file_origin
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("entity '{}' has no file origin", entity.name))?;
    let span = entity
        .span
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("entity '{}' has no source span", entity.name))?;
    let (bytes, blob) = read_entity_file_bytes_with_digest_from(authority, workspace, entity)?;
    // Bind the span to the bytes it is about to cut, through the SAME rule the MCP
    // resolver uses.
    //
    // This arm resolves its own bytes rather than routing through
    // `read_entity_source_excerpt_detailed`, and it is the arm the daemon serves
    // `get_entity_source` and `get_entity_sources` from, so in product mode it is
    // the arm agents actually read through. Leaving the check on the offline
    // resolver only would have protected the path used least. The bounds checks
    // below cannot substitute: a stale span normally still lands inside the file.
    let span_coherence =
        kin_mcp::handlers::common::span_source_coherence(entity, &blob, &file_origin.0)?;
    if span.start_byte >= span.end_byte {
        anyhow::bail!(
            "entity '{}' has an empty or invalid source span ({}..{})",
            entity.name,
            span.start_byte,
            span.end_byte
        );
    }
    if span.end_byte > bytes.len() {
        anyhow::bail!(
            "entity '{}' source span {}..{} is out of bounds for '{}' ({} bytes)",
            entity.name,
            span.start_byte,
            span.end_byte,
            file_origin.0,
            bytes.len()
        );
    }

    let body = std::str::from_utf8(&bytes[span.start_byte..span.end_byte])
        .with_context(|| {
            format!(
                "entity '{}' source span {}..{} in '{}' is not valid UTF-8",
                entity.name, span.start_byte, span.end_byte, file_origin.0
            )
        })?
        .to_string();
    let (start_line, end_line) = presentation_span_lines(span);
    Ok(GraphSourceRecord {
        id: entity.id.to_string(),
        name: entity.name.clone(),
        kind: format!("{:?}", entity.kind),
        language: entity.language.to_string(),
        file_path: file_origin.0.clone(),
        start_line,
        end_line,
        start_byte: span.start_byte,
        end_byte: span.end_byte,
        signature: entity.signature.clone(),
        body,
        span_coherence: span_coherence.label().to_string(),
    })
}

pub(crate) fn read_entity_file_bytes_from_graph(
    binding: &kin_core::LocalRepositoryAuthorityBinding,
    graph: &impl GraphStore,
    entity: &Entity,
) -> Result<Vec<u8>> {
    read_entity_file_bytes_with_digest(binding, graph, entity).map(|(bytes, _)| bytes)
}

/// The bytes at an entity's path in the exact workspace tree, plus the digest
/// they were loaded by.
///
/// Callers that go on to SLICE these bytes with the live entity's span need the
/// digest, because the span and the bytes come from two independently updated
/// stores and the digest is what binds them. Returning it here rather than
/// re-resolving the artifact keeps the pair from being sampled twice.
pub(crate) fn read_entity_file_bytes_with_digest(
    binding: &kin_core::LocalRepositoryAuthorityBinding,
    _graph: &impl GraphStore,
    entity: &Entity,
) -> Result<(Vec<u8>, kin_model::Hash256)> {
    let authority = super::repository_authority::ActiveRepositoryAuthority::open(binding)?;
    let workspace = authority.workspace()?;
    read_entity_file_bytes_with_digest_from(&authority, &workspace, entity)
}

/// The same read against an authority and workspace the caller already holds.
///
/// Split from [`read_entity_file_bytes_with_digest`] so a caller reading many
/// entities pays one authority open for the whole set. The workspace is passed
/// alongside rather than re-derived per entity so every read in a set resolves
/// against one coherent generation: re-deriving it per entity would let a
/// publication landing mid-walk serve some entities from the tree that replaced
/// the one the others came from.
pub(crate) fn read_entity_file_bytes_with_digest_from(
    authority: &super::repository_authority::ActiveRepositoryAuthority,
    workspace: &kin_model::WorkspaceState,
    entity: &Entity,
) -> Result<(Vec<u8>, kin_model::Hash256)> {
    let file_id = entity
        .file_origin
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("entity '{}' has no file origin", entity.name))?;
    let path = kin_model::RepoPath::from_utf8(file_id.0.clone()).with_context(|| {
        format!(
            "entity source path '{}' is not repository-relative",
            file_id.0
        )
    })?;
    let artifact = workspace.tree.artifact_at_path(&path).ok_or_else(|| {
        anyhow::anyhow!(
            "entity source '{}' is not in workspace {} at generation {}",
            file_id.0,
            workspace.workspace_id,
            workspace.generation
        )
    })?;
    let kin_model::TreeEntry::Blob { hash, .. } = artifact.entry else {
        anyhow::bail!(
            "entity source '{}' resolves to non-source entry {:?} for artifact {:?} in repository-v6 workspace {}",
            file_id.0,
            artifact.entry,
            artifact.artifact_id,
            workspace.workspace_id
        );
    };
    let bytes = authority.load_source_blob(hash).with_context(|| {
        format!(
            "repository-v6 source body for artifact {:?} at '{}' is unavailable",
            artifact.artifact_id, file_id.0
        )
    })?;
    Ok((bytes, hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{
        ArtifactId, Entity, EntityMetadata, FilePathId, FingerprintAlgorithm, GraphNodeId, Hash256,
        LanguageId, LocatedEntry, Relation, RelationId, RelationOrigin, RepoPath, ResolvedArtifact,
        ResolvedTree, SemanticFingerprint, SourceSpan, TestCase, TestId, TestKind, TestRunner,
        TransactionDelta, TreeDelta, TreeEntry, VerificationStore, Visibility,
    };

    /// Grade the warning-producing seam, not only the record's predicate: zero
    /// pending embeddings produce zero warning text, while the three
    /// distinguishability controls remain visible.
    #[test]
    fn a_completed_embedding_index_does_not_repeat_an_old_refusal_warning() {
        let refusal = |work: &str| kin_core::memory_pressure::PressureRefusal {
            work: work.to_string(),
            level: "critical".to_string(),
            reason: "background work was refused".to_string(),
            at_unix: 1,
        };
        let complete = kin_core::memory_pressure::EmbeddingCoverage {
            pending: 0,
            indexed: 9,
            total: 9,
        };
        let queue_empty_but_short = kin_core::memory_pressure::EmbeddingCoverage {
            pending: 0,
            indexed: 8,
            total: 9,
        };
        let queued = kin_core::memory_pressure::EmbeddingCoverage {
            pending: 9,
            indexed: 9,
            total: 9,
        };
        assert!(
            pressure_refusal_warning(
                std::slice::from_ref(&refusal(
                    kin_core::memory_pressure::HeavyWork::EmbedBatch.id(),
                )),
                complete,
            )
            .is_none(),
            "an embed refusal cannot describe a whole-coverage store"
        );
        assert!(
            pressure_refusal_warning(
                std::slice::from_ref(&refusal(
                    kin_core::memory_pressure::HeavyWork::EmbedBatch.id(),
                )),
                queue_empty_but_short,
            )
            .is_some(),
            "an empty queue cannot hide refused work while indexed coverage is short"
        );
        assert!(
            !embedding_persistence_blocks_coverage(true, complete),
            "an unavailable future producer is not a blocker once coverage is exact"
        );
        assert!(
            embedding_persistence_blocks_coverage(true, queue_empty_but_short),
            "an empty queue cannot hide short coverage from a producer that will never start"
        );
        assert!(
            embedding_persistence_blocks_coverage(true, queued),
            "a live backlog remains blocked"
        );
        assert!(
            !embedding_persistence_blocks_coverage(false, queue_empty_but_short),
            "short coverage alone does not invent a persistence blocker"
        );
        assert!(
            pressure_refusal_warning(
                std::slice::from_ref(&refusal(
                    kin_core::memory_pressure::HeavyWork::EmbedBatch.id(),
                )),
                queued,
            )
            .is_some(),
            "a live embed backlog keeps the refusal visible"
        );
        assert!(
            pressure_refusal_warning(
                std::slice::from_ref(&refusal(
                    kin_core::memory_pressure::HeavyWork::LspSweep.id(),
                )),
                complete,
            )
            .is_some(),
            "embedding completion cannot clear a refused LSP sweep"
        );
        assert!(
            pressure_refusal_warning(
                std::slice::from_ref(&refusal("future-heavy-work")),
                complete,
            )
            .is_some(),
            "unknown work remains visible until this build can interpret it"
        );

        let embed = refusal(kin_core::memory_pressure::HeavyWork::EmbedBatch.id());
        for independent in [
            refusal(kin_core::memory_pressure::HeavyWork::LspSweep.id()),
            refusal("future-heavy-work"),
        ] {
            for refusals in [
                vec![independent.clone(), embed.clone()],
                vec![embed.clone(), independent.clone()],
            ] {
                let warning = pressure_refusal_warning(&refusals, complete)
                    .expect("independent work remains visible");
                assert!(
                    warning.contains(&independent.reason),
                    "a completed embed entry cannot mask {} in either publication order: \
                     {warning}",
                    independent.work
                );
            }
        }
    }

    /// Admit a test case so a `Test` endpoint names something the store holds.
    ///
    /// These fixtures used to mint a `TestId` and relate it without ever
    /// creating the case, which described coverage by a test the repository
    /// does not have. `create_test_case` with no scopes admits the identity and
    /// writes no relations of its own, so the fixture's own edge stays the only
    /// one it asserts about.
    fn admit_test_case(graph: &kin_db::InMemoryGraph, test_id: TestId) {
        graph
            .create_test_case(&TestCase {
                test_id,
                name: "fixture_case".into(),
                language: "rust".into(),
                kind: TestKind::Unit,
                scopes: Vec::new(),
                runner: TestRunner::Cargo,
                file_origin: Some(FilePathId::new("tests/fixture.rs")),
            })
            .unwrap();
    }

    /// Admit an artifact at `path` so an `Artifact` endpoint names something the
    /// resolved tree carries, through the transaction path the product uses.
    fn admit_artifact(graph: &kin_db::InMemoryGraph, artifact_id: ArtifactId, path: &str) {
        let mut seed = [0u8; 32];
        for (slot, byte) in seed.iter_mut().zip(path.as_bytes()) {
            *slot = *byte;
        }
        graph
            .apply_transaction_delta(&TransactionDelta {
                tree_deltas: vec![TreeDelta::Added {
                    artifact_id,
                    new: LocatedEntry::new(
                        RepoPath::from_utf8(path).unwrap(),
                        TreeEntry::blob(Hash256::from_bytes(seed), false),
                    ),
                }],
                ..TransactionDelta::default()
            })
            .unwrap();
    }
    use std::fs;

    /// The one-shot authority arm, which is what a test with no server around
    /// it has. The shared arm is exercised where a daemon supplies it.
    fn pinned(
        binding: &kin_core::LocalRepositoryAuthorityBinding,
    ) -> super::super::repository_authority::RequestRepositoryAuthority {
        super::super::repository_authority::RequestRepositoryAuthority::pinned(binding.clone())
    }

    mod freshness {
        use super::super::append_freshness_line;
        use chrono::TimeZone;
        use kin_core::last_admission::{LastAdmission, LastAdmissionRead};

        fn at(secs: i64) -> chrono::DateTime<chrono::Utc> {
            chrono::Utc.timestamp_opt(secs, 0).unwrap()
        }

        fn rendered(read: &LastAdmissionRead, now: i64) -> String {
            let mut lines = Vec::new();
            append_freshness_line(&mut lines, read, at(now));
            lines.join("\n")
        }

        /// The Aug-11 store, stated as a test: months behind, and the report has
        /// to say so with an order of magnitude and a coverage count.
        #[test]
        fn a_store_months_behind_reports_its_age_and_coverage() {
            let read = LastAdmissionRead::Recorded(LastAdmission::new(at(0), 31));
            let out = rendered(&read, 86_400 * 70);
            assert!(out.contains("70d"), "expected a day-scale age: {out}");
            assert!(
                out.contains("31 tracked artifact"),
                "expected the coverage count: {out}"
            );
        }

        /// The property that kills the false all-clear: a healthy, current store
        /// still emits the freshness line. If freshness were only reported when
        /// something looked wrong, a reader could never tell silence from health.
        #[test]
        fn a_current_store_still_states_its_freshness() {
            let read = LastAdmissionRead::Recorded(LastAdmission::new(at(1_000), 125));
            let out = rendered(&read, 1_030);
            assert!(
                out.contains("graph truth:"),
                "a current store must still state freshness: {out}"
            );
            assert!(out.contains("30s"), "expected a fresh age: {out}");
        }

        /// Absent and unreadable both have to reach the reader as unknown, never
        /// as silence and never as current.
        #[test]
        fn unknown_freshness_is_stated_rather_than_omitted() {
            for read in [
                LastAdmissionRead::Absent,
                LastAdmissionRead::Unreadable("truncated".to_string()),
            ] {
                let out = rendered(&read, 500);
                assert!(
                    out.contains("unknown"),
                    "unknown freshness must be stated: {out}"
                );
            }
        }
    }

    #[test]
    fn graph_entity_not_found_lines_keep_signal_and_offer_next_steps() {
        let lines = graph_entity_not_found_lines("frobnicate");
        assert!(
            lines[0].contains("not found"),
            "keeps not-found signal: {lines:?}"
        );
        let joined = lines.join("\n");
        assert!(
            joined.contains("kin search frobnicate"),
            "offers search: {joined}"
        );
        assert!(
            joined.contains("kin graph status"),
            "offers graph status: {joined}"
        );
    }

    fn test_entity(name: &str) -> Entity {
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
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

    fn test_relation(kind: RelationKind, src: EntityId, dst: EntityId) -> Relation {
        graph_relation(kind, GraphNodeId::Entity(src), GraphNodeId::Entity(dst))
    }

    fn graph_relation(kind: RelationKind, src: GraphNodeId, dst: GraphNodeId) -> Relation {
        Relation {
            id: RelationId::new(),
            kind,
            src,
            dst,
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: Vec::new(),
        }
    }

    fn external_placeholder_relation(kind: RelationKind) -> (Entity, Relation) {
        let mut caller = test_entity("run_task");
        let file_id = FilePathId::new("src/app.rs");
        caller.file_origin = Some(file_id.clone());
        caller.span = Some(SourceSpan {
            file: file_id,
            start_byte: 0,
            end_byte: 10,
            start_line: 1,
            start_col: 0,
            end_line: 1,
            end_col: 10,
        });
        let files = [kin_index::FileParseData {
            file_path: "src/app.rs".to_string(),
            entities: vec![caller.clone()],
            relations: vec![kin_parser::ExtractedRelation {
                site: None,
                receiver: None,
                call_shape: None,
                kind,
                src_name: caller.name.clone(),
                dst_name: "InMemoryGraph".to_string(),
                import_source: Some("kin_db".to_string()),
            }],
            imports: Vec::new(),
        }];
        let artifact_ids =
            std::collections::HashMap::from([("src/app.rs".to_string(), ArtifactId::new())]);
        let relations = kin_index::link_cross_file(&files, &artifact_ids)
            .expect("test file has an admitted artifact identity");
        assert_eq!(relations.len(), 1);
        let relation = relations.into_iter().next().unwrap();
        assert!(kin_index::is_external_import_placeholder(&relation));
        // The validator fixture has no source file; remove file metadata after
        // the real linker has used it so this test isolates relation integrity
        // rather than also triggering the orphaned-entity check.
        caller.file_origin = None;
        caller.span = None;
        (caller, relation)
    }

    fn graph_validation_fixture() -> (
        tempfile::TempDir,
        kin_core::LocalRepositoryAuthorityBinding,
        kin_db::InMemoryGraph,
    ) {
        let temp = tempfile::tempdir().unwrap();
        let initialized = kin_core::init(temp.path()).unwrap();
        let binding =
            kin_core::LocalRepositoryAuthorityBinding::from_layout(&initialized.layout).unwrap();
        (temp, binding, kin_db::InMemoryGraph::new())
    }

    /// The rc0545c case, driven end to end through the record this store
    /// actually carries.
    ///
    /// A census is taken and written for the store, the graph then loses a
    /// whole relation kind, and status is asked again against the same layout.
    /// The two arms share one fixture and differ only in whether `UsesType`
    /// still has an edge, so a pass in the first arm is the control that makes
    /// the second arm's failure mean something: without it, a build that never
    /// printed the all-clear at all would read as a pass.
    #[test]
    fn a_relation_kind_that_vanished_since_the_recorded_census_refuses_no_issues() {
        let temp = tempfile::tempdir().unwrap();
        let initialized = kin_core::init(temp.path()).unwrap();
        let layout = initialized.layout.clone();
        let binding =
            kin_core::LocalRepositoryAuthorityBinding::from_layout(&initialized.layout).unwrap();

        let enriched = kin_db::InMemoryGraph::new();
        let caller = test_entity("run_task");
        let callee = test_entity("finalize");
        let typed = test_entity("Payload");
        for entity in [&caller, &callee, &typed] {
            enriched.upsert_entity(entity).unwrap();
        }
        enriched
            .upsert_relation(&test_relation(RelationKind::Calls, caller.id, callee.id))
            .unwrap();
        enriched
            .upsert_relation(&test_relation(RelationKind::UsesType, caller.id, typed.id))
            .unwrap();

        // What a completed sweep records. Taken through the same measurement
        // the status row compares against, which is the point of the shared
        // function: a record written by one walk and read by another would
        // report movement no graph ever made.
        let recorded = kin_core::relation_census::RelationCensus::new(
            chrono::Utc::now(),
            kin_core::relation_census::CensusSource::Sweep,
            measure_relation_census(&enriched).unwrap(),
            Vec::new(),
        );
        assert_eq!(
            recorded.kinds.get("UsesType"),
            Some(&1),
            "the recorded census holds the kind that is about to be lost: {:?}",
            recorded.kinds
        );
        kin_core::relation_census::write(&layout, &recorded).unwrap();

        // The control. Nothing has been lost yet, so the census row withholds
        // nothing and the all-clear is reachable.
        let unchanged = build_graph_status_response(
            &pinned(&binding),
            &enriched,
            &Default::default(),
            &Default::default(),
            &kin_core::relation_census::CensusContext::for_layout(
                &layout,
                Vec::<(String, String)>::new(),
            ),
        )
        .unwrap();
        assert!(
            !unchanged
                .lines
                .iter()
                .any(|line| line.contains("relation kind UsesType")),
            "an unchanged census reports no loss: {}",
            unchanged.lines.join("\n")
        );
        assert!(
            unchanged
                .relation_census
                .as_ref()
                .is_some_and(|census| !census.reports_loss()),
            "the control withholds nothing, so the second arm's warning means something: {}",
            unchanged.lines.join("\n")
        );

        // The kind is disabled. This is what `KIN_DAEMON_DISABLE_LSP=1` did to
        // the stranger's store: the edges were re-derived without it.
        let stripped = kin_db::InMemoryGraph::new();
        for entity in [&caller, &callee, &typed] {
            stripped.upsert_entity(entity).unwrap();
        }
        stripped
            .upsert_relation(&test_relation(RelationKind::Calls, caller.id, callee.id))
            .unwrap();

        let lost = build_graph_status_response(
            &pinned(&binding),
            &stripped,
            &Default::default(),
            &Default::default(),
            &kin_core::relation_census::CensusContext::for_layout(
                &layout,
                vec![("KIN_DAEMON_DISABLE_LSP".to_string(), "1".to_string())],
            ),
        )
        .unwrap();
        let rendered = lost.lines.join("\n");
        // The marker prefix is the assertion that matters. A `⚠` line exists
        // only when the warnings vector is non-empty, and the all-clear prints
        // only when that vector is empty, so this proves the loss reached the
        // branch that suppresses "No issues detected". Asserting the absence of
        // the all-clear string directly cannot prove it here: this fixture
        // raises unrelated warnings of its own (pending embeddings, uniform
        // roles), so that line is unreachable in both arms and the assertion
        // would pass whether or not the census did anything.
        assert!(
            rendered.contains("⚠ relation kind UsesType lost every edge it held"),
            "the loss is raised as a warning, which is what withholds the all-clear: {rendered}"
        );
        assert!(
            rendered.contains("UsesType went 1 to 0"),
            "the loss is named with both counts: {rendered}"
        );
        assert!(
            rendered.contains("KIN_DAEMON_DISABLE_LSP"),
            "the recorded cause is named beside the loss: {rendered}"
        );
        assert!(
            lost.relation_census
                .as_ref()
                .is_some_and(|census| census.reports_loss()),
            "doctor reads the same verdict structurally rather than by parsing prose"
        );
    }

    /// Build a graph holding `calls` call edges and `overrides` override edges
    /// over one fixed entity set, so two graphs differing only in edge count
    /// report the same entity count.
    ///
    /// The entity set is fixed on purpose. The rule under test turns on whether
    /// the entity count moved, so a fixture that grew or shrank its entities
    /// between arms would be testing the escape hatch rather than the rule.
    fn graph_with_edges(
        entities: &[Entity],
        calls: usize,
        overrides: usize,
    ) -> kin_db::InMemoryGraph {
        let graph = kin_db::InMemoryGraph::new();
        for entity in entities {
            graph.upsert_entity(entity).unwrap();
        }
        let root = entities[0].id;
        for target in entities.iter().skip(1).take(calls) {
            graph
                .upsert_relation(&test_relation(RelationKind::Calls, root, target.id))
                .unwrap();
        }
        for target in entities.iter().skip(1).take(overrides) {
            graph
                .upsert_relation(&test_relation(RelationKind::Overrides, target.id, root))
                .unwrap();
        }
        graph
    }

    /// The rc0547b case end to end, in the shape the run produced it.
    ///
    /// A comment-only commit on `psf/requests` took `Calls` 1279 to 1268 and
    /// `Overrides` 11 to 10 over an entity count that did not move, and every
    /// surface called the store healthy. Two things had to be true for that:
    /// each drop was far inside the sharp-fall threshold, and the commit wrote
    /// the baseline it was about to be judged against. This drives both.
    #[test]
    fn a_commit_that_loses_edges_without_losing_entities_is_named_and_cannot_reset_its_own_baseline(
    ) {
        let temp = tempfile::tempdir().unwrap();
        let initialized = kin_core::init(temp.path()).unwrap();
        let layout = initialized.layout.clone();
        let binding =
            kin_core::LocalRepositoryAuthorityBinding::from_layout(&initialized.layout).unwrap();

        let entities: Vec<Entity> = (0..10)
            .map(|index| test_entity(&format!("step_{index}")))
            .collect();
        let before = graph_with_edges(&entities, 8, 4);
        let (kinds, entity_count) = measure_relation_census_with_entities(&before).unwrap();
        assert_eq!(kinds.get("Calls"), Some(&8), "{kinds:?}");
        assert_eq!(kinds.get("Overrides"), Some(&4), "{kinds:?}");
        assert_eq!(entity_count, 10);

        let recorded = kin_core::relation_census::RelationCensus::new(
            chrono::Utc::now(),
            kin_core::relation_census::CensusSource::Sweep,
            kinds,
            Vec::new(),
        )
        .with_entities(entity_count);
        assert_eq!(
            kin_core::relation_census::record(&layout, &recorded),
            kin_core::relation_census::CensusRecordOutcome::Advanced,
            "the pre-commit sweep census is the verified-good baseline"
        );

        // The control. Same graph, same entity count, nothing lost.
        let unchanged = build_graph_status_response(
            &pinned(&binding),
            &before,
            &Default::default(),
            &Default::default(),
            &kin_core::relation_census::CensusContext::for_layout(
                &layout,
                Vec::<(String, String)>::new(),
            ),
        )
        .unwrap();
        assert!(
            unchanged
                .relation_census
                .as_ref()
                .is_some_and(|census| !census.reports_loss()),
            "the control withholds nothing: {}",
            unchanged.lines.join("\n")
        );

        // The commit. One call edge and one override edge gone, every entity
        // still there. 12.5% and 25% of a kind, so neither is a whole-kind
        // loss and only one reaches the sharp-fall threshold at all.
        let after = graph_with_edges(&entities, 7, 3);
        let (after_kinds, after_entities) = measure_relation_census_with_entities(&after).unwrap();
        assert_eq!(
            after_entities, entity_count,
            "the entity count did not move"
        );

        // The commit offers its own census. Under the rule this test exists
        // for, it is refused: a losing pass may not become the point the loss
        // is judged against.
        let commit_census = kin_core::relation_census::RelationCensus::new(
            chrono::Utc::now(),
            kin_core::relation_census::CensusSource::Commit,
            after_kinds,
            Vec::new(),
        )
        .with_entities(after_entities);
        assert!(
            matches!(
                kin_core::relation_census::record(&layout, &commit_census),
                kin_core::relation_census::CensusRecordOutcome::Held { .. }
            ),
            "the commit that lost the edges must not become the baseline"
        );
        // And the recovery sweep the stranger ran twice cannot bury it either.
        assert!(
            matches!(
                kin_core::relation_census::record(
                    &layout,
                    &kin_core::relation_census::RelationCensus::new(
                        chrono::Utc::now(),
                        kin_core::relation_census::CensusSource::Sweep,
                        measure_relation_census(&after).unwrap(),
                        Vec::new(),
                    )
                    .with_entities(after_entities),
                ),
                kin_core::relation_census::CensusRecordOutcome::Held { .. }
            ),
            "a sweep that reproduces the loss is not evidence of health"
        );

        let lost = build_graph_status_response(
            &pinned(&binding),
            &after,
            &Default::default(),
            &Default::default(),
            &kin_core::relation_census::CensusContext::for_layout(
                &layout,
                Vec::<(String, String)>::new(),
            ),
        )
        .unwrap();
        let rendered = lost.lines.join("\n");
        assert!(
            rendered.contains("⚠ relation kind Calls lost edges with no entity removed"),
            "the loss is raised as a warning, which is what withholds the all-clear: {rendered}"
        );
        assert!(
            rendered.contains("Calls slipped 8 to 7"),
            "the kind and both counts are named: {rendered}"
        );
        assert!(
            rendered.contains("the entity count held at 10"),
            "the discriminator is named beside the loss: {rendered}"
        );
        assert!(
            lost.relation_census
                .as_ref()
                .is_some_and(|census| census.reports_loss()),
            "doctor reads the same verdict structurally rather than by parsing prose"
        );
    }

    /// The arm that stops the rule above from firing on every deletion. Same
    /// eleven-edge shape, over a store that removed the code holding them.
    #[test]
    fn a_commit_that_removed_entities_reports_no_census_loss() {
        let temp = tempfile::tempdir().unwrap();
        let initialized = kin_core::init(temp.path()).unwrap();
        let layout = initialized.layout.clone();
        let binding =
            kin_core::LocalRepositoryAuthorityBinding::from_layout(&initialized.layout).unwrap();

        let entities: Vec<Entity> = (0..20)
            .map(|index| test_entity(&format!("step_{index}")))
            .collect();
        let before = graph_with_edges(&entities, 16, 8);
        let (kinds, entity_count) = measure_relation_census_with_entities(&before).unwrap();
        kin_core::relation_census::record(
            &layout,
            &kin_core::relation_census::RelationCensus::new(
                chrono::Utc::now(),
                kin_core::relation_census::CensusSource::Sweep,
                kinds,
                Vec::new(),
            )
            .with_entities(entity_count),
        );

        // Two entities deleted, and the edges that hung off them with them.
        // Both kinds fall 12.5%, inside the sharp-fall threshold, so the only
        // thing that could report this is the rule under test.
        let after = graph_with_edges(&entities[..18], 14, 7);
        let (_, after_entities) = measure_relation_census_with_entities(&after).unwrap();
        assert!(after_entities < entity_count, "the store shrank");

        let smaller = build_graph_status_response(
            &pinned(&binding),
            &after,
            &Default::default(),
            &Default::default(),
            &kin_core::relation_census::CensusContext::for_layout(
                &layout,
                Vec::<(String, String)>::new(),
            ),
        )
        .unwrap();
        let rendered = smaller.lines.join("\n");
        assert!(
            !rendered.contains("lost edges with no entity removed"),
            "removing code removes its edges, which is not a regression: {rendered}"
        );
        assert!(
            smaller
                .relation_census
                .as_ref()
                .is_some_and(|census| !census.reports_loss()),
            "and doctor stays green: {rendered}"
        );
    }

    /// The absent arm, so the row above cannot be trivially true. A store with
    /// no recorded census says it cannot compare, and says nothing about health.
    #[test]
    fn a_store_with_no_recorded_census_says_so_and_still_reaches_the_all_clear() {
        let (_temp, binding, graph) = graph_validation_fixture();
        let caller = test_entity("run_task");
        let callee = test_entity("finalize");
        graph.upsert_entity(&caller).unwrap();
        graph.upsert_entity(&callee).unwrap();
        graph
            .upsert_relation(&test_relation(RelationKind::Calls, caller.id, callee.id))
            .unwrap();

        let response = build_graph_status_response(
            &pinned(&binding),
            &graph,
            &Default::default(),
            &Default::default(),
            &Default::default(),
        )
        .unwrap();
        let rendered = response.lines.join("\n");
        assert!(
            rendered.contains("no previous relation census is recorded"),
            "the row states what it cannot do: {rendered}"
        );
        assert!(
            !rendered.contains("⚠ relation kind"),
            "an unrecorded census raises no warning of its own: {rendered}"
        );
        assert!(
            response
                .relation_census
                .as_ref()
                .is_some_and(|census| !census.reports_loss()),
            "and reports no loss to doctor either"
        );
    }

    /// The exact reported failure. `kin graph status` on the umbrella store
    /// printed "No issues detected" while the daemon had failed every
    /// whole-tree admission since Aug 6, because every check this command runs
    /// reads the graph, and the graph a failing loop leaves behind is
    /// internally perfect and merely out of date.
    #[test]
    fn graph_status_refuses_no_issues_while_the_daemon_is_admitting_nothing() {
        let (_temp, binding, graph) = graph_validation_fixture();
        let caller = test_entity("run_task");
        let callee = test_entity("finalize");
        graph.upsert_entity(&caller).unwrap();
        graph.upsert_entity(&callee).unwrap();
        graph
            .upsert_relation(&test_relation(RelationKind::Calls, caller.id, callee.id))
            .unwrap();

        // The control. This fixture's graph raises unrelated warnings of its own
        // (pending embeddings, uniform roles), so the all-clear line is not what
        // separates the two halves here and asserting on it would pass whatever
        // the reconcile term did. What must differ is the reconcile warning
        // itself: absent on a healthy daemon, present on this one.
        let healthy = build_graph_status_response(
            &pinned(&binding),
            &graph,
            &Default::default(),
            &Default::default(),
            &Default::default(),
        )
        .unwrap();
        assert!(
            !healthy
                .lines
                .iter()
                .any(|line| line.contains("reconcile loop degraded")),
            "a healthy daemon must not be reported as degraded: {:?}",
            healthy.lines
        );

        let degraded = build_graph_status_response(
            &pinned(&binding),
            &graph,
            &crate::commands::resources::ReconcileHealth {
                admission_failure_streak: 412,
                admission_failures: 412,
                last_admission_error: Some("scan exceeded its budget".to_string()),
                last_admission_success_age_seconds: Some(172_800),
                ..Default::default()
            },
            &Default::default(),
            &Default::default(),
        )
        .unwrap();
        assert!(
            !degraded
                .lines
                .iter()
                .any(|line| line.contains("No issues detected")),
            "this is the lie the ticket exists to kill: {:?}",
            degraded.lines
        );
        let warning = degraded
            .lines
            .iter()
            .find(|line| line.contains("reconcile loop degraded"))
            .expect("the fault must be named on the surface a user reads");
        assert!(warning.contains("412"), "{warning}");
        assert!(warning.contains("172800"), "{warning}");
        assert!(
            degraded.error.is_none(),
            "a live runtime fault is not a defect in the graph this command \
             inspected, and must not change the exit code"
        );
    }

    /// The command names host content the loop declined to track, and does not
    /// call it a fault.
    ///
    /// This is the untracked-content shape from the reader's side. A file was
    /// written, no entity for it ever appeared, and the only surface that could
    /// have explained why said nothing about it at all. Naming it as a warning
    /// would be the opposite error: a working copy mid-edit holds untracked
    /// files constantly, and a status command that cries fault over every one
    /// of them is one nobody reads.
    #[test]
    fn graph_status_names_untracked_paths_without_calling_them_a_fault() {
        let (_temp, binding, graph) = graph_validation_fixture();
        let entity = test_entity("run_task");
        graph.upsert_entity(&entity).unwrap();

        let response = build_graph_status_response(
            &pinned(&binding),
            &graph,
            &crate::commands::resources::ReconcileHealth {
                untracked_path_count: 1,
                untracked_paths_sample: vec!["fir2152_probe.rs".to_string()],
                ..Default::default()
            },
            &Default::default(),
            &Default::default(),
        )
        .unwrap();
        assert!(
            response
                .lines
                .iter()
                .any(|line| line.contains("fir2152_probe.rs")),
            "the path a reader is looking for must be named: {:?}",
            response.lines
        );
        assert!(
            !response
                .lines
                .iter()
                .any(|line| line.contains("reconcile loop degraded")),
            "untracked content is not a degraded loop: {:?}",
            response.lines
        );
        assert!(
            response.error.is_none(),
            "an ordinary working copy must not turn this command nonzero"
        );
    }

    /// A dropped reconcile event reaches the same verdict: events errored and
    /// were skipped while every surface read clean.
    #[test]
    fn graph_status_names_dropped_reconcile_events() {
        let (_temp, binding, graph) = graph_validation_fixture();
        let entity = test_entity("run_task");
        graph.upsert_entity(&entity).unwrap();

        let response = build_graph_status_response(
            &pinned(&binding),
            &graph,
            &crate::commands::resources::ReconcileHealth {
                skipped_events: 7,
                last_error: Some("src/lib.rs: parser rejected the transaction".to_string()),
                last_error_age_seconds: Some(90),
                ..Default::default()
            },
            &Default::default(),
            &Default::default(),
        )
        .unwrap();
        // The reconcile warning is the assertion that carries this test. The
        // all-clear line is checked below it rather than above it because this
        // fixture's graph raises warnings of its own, so its absence would hold
        // whether or not the reconcile term existed.
        assert!(
            response
                .lines
                .iter()
                .any(|line| line.contains("reconcile loop degraded")),
            "a dropped event must be named on the surface a user reads: {:?}",
            response.lines
        );
        assert!(
            response
                .lines
                .iter()
                .any(|line| line.contains("src/lib.rs: parser rejected the transaction")),
            "the daemon's own error must survive to the surface: {:?}",
            response.lines
        );
        assert!(
            !response
                .lines
                .iter()
                .any(|line| line.contains("No issues detected")),
            "{:?}",
            response.lines
        );
    }

    /// The all-clear line and a degraded reconcile loop are mutually exclusive
    /// by construction, and this is the assertion that proves it.
    ///
    /// No fixture in this module produces a warning-free graph, so a test that
    /// planted a degraded loop and checked the all-clear was gone would hold
    /// with the reconcile term deleted. Reading the suppression rule against the
    /// same reasons the surface renders is what cannot pass by accident: any
    /// non-empty reason set makes the warning list non-empty, and a non-empty
    /// warning list is exactly what withholds the all-clear at the call site.
    #[test]
    fn a_degraded_reconcile_loop_always_withholds_the_all_clear() {
        let degraded = crate::commands::resources::ReconcileHealth {
            admission_failure_streak: 412,
            last_admission_success_age_seconds: Some(172_800),
            ..Default::default()
        };
        assert!(
            !degraded.degraded_reasons().is_empty(),
            "the planted state must be degraded, or this proves nothing"
        );

        let clean = crate::commands::resources::ReconcileHealth::default();
        assert!(
            clean.degraded_reasons().is_empty(),
            "an untouched daemon contributes no warnings, so the all-clear is \
             still reachable for a graph that earns it"
        );
    }

    #[test]
    fn graph_status_labels_each_relation_total_with_its_scope() {
        let (_temp, binding, graph) = graph_validation_fixture();
        let caller = test_entity("run_task");
        let callee = test_entity("finalize");
        graph.upsert_entity(&caller).unwrap();
        graph.upsert_entity(&callee).unwrap();
        graph
            .upsert_relation(&test_relation(RelationKind::Calls, caller.id, callee.id))
            .unwrap();

        let response = build_graph_status_response(
            &pinned(&binding),
            &graph,
            &Default::default(),
            &Default::default(),
            &Default::default(),
        )
        .unwrap();

        // The entity-rooted total and the whole-table total count different
        // scopes, so neither line may carry a bare "Relations" label.
        assert!(response
            .lines
            .iter()
            .any(|line| line.contains("Entity-to-entity relations: 1")));
        assert!(response
            .lines
            .iter()
            .any(|line| line.starts_with("Entity-to-entity rels/entity: ")));
        assert!(response
            .lines
            .iter()
            .any(|line| line.starts_with("Entity-to-entity relation kinds: ")));
        assert!(response
            .lines
            .iter()
            .any(|line| line.starts_with("All graph relations excluding CoChanges: ")));
        assert!(
            !response
                .lines
                .iter()
                .any(|line| line.starts_with("Relations: ") || line.contains("  |  Relations: ")),
            "{:?}",
            response.lines
        );
    }

    /// Two surfaces counting one store must each name the view they show, and
    /// the surface holding the excluded set must publish the arithmetic that
    /// reconciles them.
    ///
    /// `kin graph status` and `kin status` disagreed by 45 entities on one store
    /// at one instant with neither acknowledging a second view existed, so a
    /// reader judging coverage had two denominators and no way to choose. The
    /// gap is not an error: external reference targets are dropped from this
    /// surface's entity total on purpose and counted by durable authority
    /// enrichment. Reverting either half of the disclosure fails this test.
    #[test]
    fn graph_status_names_its_entity_view_and_reconciles_it_with_durable_status() {
        let (_temp, binding, graph) = graph_validation_fixture();
        graph.upsert_entity(&test_entity("run_task")).unwrap();
        // Two nodes this repository references without defining. They are real
        // entities in the graph and are excluded from the entity total below,
        // which is exactly the shape that made the two surfaces disagree.
        graph
            .upsert_entity(&external_target_entity("requests.adapters", 1))
            .unwrap();
        graph
            .upsert_entity(&external_target_entity("urllib3.poolmanager", 2))
            .unwrap();

        let response = build_graph_status_response(
            &pinned(&binding),
            &graph,
            &Default::default(),
            &Default::default(),
            &Default::default(),
        )
        .unwrap();

        let entity_line = response
            .lines
            .iter()
            .find(|line| line.starts_with("Entities: "))
            .unwrap_or_else(|| panic!("no entity line: {:?}", response.lines));
        assert!(
            entity_line.contains("Entities: 1"),
            "the entity total must still exclude external reference targets: {entity_line}"
        );
        assert!(
            entity_line.contains("live query graph"),
            "the entity total must name the view it counts: {entity_line}"
        );

        let external_line = response
            .lines
            .iter()
            .find(|line| line.starts_with("External reference targets: "))
            .unwrap_or_else(|| panic!("no external line: {:?}", response.lines));
        assert!(
            external_line.contains("External reference targets: 2"),
            "the excluded count must be stated: {external_line}"
        );
        assert!(
            external_line.contains("excluded from the entity total"),
            "the excluded set must say it is excluded, or the two totals do not add up for a \
             reader: {external_line}"
        );
        assert!(
            external_line.contains("kin status"),
            "the reconciliation must name the other surface, or a reader still has to guess \
             which denominator is real: {external_line}"
        );
    }

    /// A census must not wear a queue's clothes.
    ///
    /// `doc_summary` is set by the language extractors from the comment
    /// preceding a declaration and by nothing else on any live path: there is no
    /// worker, no queue, and nothing that can stall. The old label read
    /// "Doc summaries: 305/777 (39%)" one line under a genuine embedding fill
    /// counter, and an unchanging fraction across a session was reported as a
    /// silently stalled job. This holds the line that the counter states what it
    /// measures.
    #[test]
    fn documented_entity_census_does_not_read_as_a_pending_queue() {
        let (_temp, binding, graph) = graph_validation_fixture();
        let mut documented = test_entity("send");
        documented.doc_summary = Some("Send the prepared request.".to_string());
        graph.upsert_entity(&documented).unwrap();
        graph.upsert_entity(&test_entity("undocumented")).unwrap();

        let response = build_graph_status_response(
            &pinned(&binding),
            &graph,
            &Default::default(),
            &Default::default(),
            &Default::default(),
        )
        .unwrap();

        let line = response
            .lines
            .iter()
            .find(|line| line.starts_with("Documented entities: "))
            .unwrap_or_else(|| panic!("no documented-entity line: {:?}", response.lines));
        assert!(
            line.contains("1/2"),
            "the census must still count accurately: {line}"
        );
        assert!(
            line.contains("parse time") && line.contains("not a job filling in the background"),
            "the line must say the fraction is extraction-time source truth, or an unchanging \
             value reads as a stalled worker: {line}"
        );
        assert!(
            !response
                .lines
                .iter()
                .any(|line| line.starts_with("Doc summaries: ")),
            "the queue-shaped label must be gone: {:?}",
            response.lines
        );
    }

    fn test_entity_in_file(name: &str, file: &str) -> Entity {
        let mut entity = test_entity(name);
        entity.file_origin = Some(kin_model::FilePathId::new(file));
        entity
    }

    /// A graph whose every edge stays inside one file must say so.
    ///
    /// This is the state the isolation experiment found and the kind histogram
    /// cannot express: `Calls: 8` reads identically whether those calls reach
    /// another module or none of them do.
    #[test]
    fn graph_status_names_a_graph_whose_edges_never_leave_their_file() {
        let (_temp, binding, graph) = graph_validation_fixture();
        let caller = test_entity_in_file("ingest_note", "storage.py");
        let callee = test_entity_in_file("normalize", "storage.py");
        graph.upsert_entity(&caller).unwrap();
        graph.upsert_entity(&callee).unwrap();
        graph
            .upsert_relation(&test_relation(RelationKind::Calls, caller.id, callee.id))
            .unwrap();

        let response = build_graph_status_response(
            &pinned(&binding),
            &graph,
            &Default::default(),
            &Default::default(),
            &Default::default(),
        )
        .unwrap();

        assert!(
            response
                .lines
                .iter()
                .any(|line| line.starts_with("Cross-file entity relations: 0 of 1")),
            "the cross-file count belongs beside the kind breakdown: {:?}",
            response.lines
        );
        assert!(
            response
                .lines
                .iter()
                .any(|line| line.contains("no relation in this graph crosses a file boundary")),
            "a graph that cannot leave a file must state it: {:?}",
            response.lines
        );
    }

    /// The counterpart: one edge across a file boundary withdraws the claim.
    /// Without this, the test above would still pass if the disclosure were
    /// printed unconditionally, which would make it decoration rather than a
    /// measurement.
    #[test]
    fn graph_status_withdraws_the_shortfall_once_an_edge_crosses_files() {
        let (_temp, binding, graph) = graph_validation_fixture();
        let caller = test_entity_in_file("ingest_note", "storage.py");
        let callee = test_entity_in_file("parse_note", "parsing.py");
        graph.upsert_entity(&caller).unwrap();
        graph.upsert_entity(&callee).unwrap();
        graph
            .upsert_relation(&test_relation(RelationKind::Calls, caller.id, callee.id))
            .unwrap();

        let response = build_graph_status_response(
            &pinned(&binding),
            &graph,
            &Default::default(),
            &Default::default(),
            &Default::default(),
        )
        .unwrap();

        assert!(
            response
                .lines
                .iter()
                .any(|line| line.starts_with("Cross-file entity relations: 1 of 1")),
            "{:?}",
            response.lines
        );
        assert!(
            !response
                .lines
                .iter()
                .any(|line| line.contains("no relation in this graph crosses a file boundary")),
            "a graph that does cross files must not be told it cannot: {:?}",
            response.lines
        );
    }

    /// Attach a vector index covering `covered` of this graph's retrievable
    /// keys, so the store reads as measured and short at the same time.
    ///
    /// That pair is what a per-key salvage leaves behind and what no other
    /// fixture here produces: the daemon installed an index, so coverage IS
    /// measured, and it retired the keys current truth could not prove, so
    /// coverage is short. A fixture with no index attached cannot reach the arm
    /// under test, because the arm above it is gated on exactly that.
    #[cfg(feature = "vector")]
    fn attach_partial_vector_index(
        graph: &kin_db::InMemoryGraph,
        dir: &std::path::Path,
        covered: usize,
    ) {
        let index = kin_db::VectorIndex::new(2).unwrap();
        let snapshot = graph.to_snapshot();
        let keys: Vec<kin_model::RetrievalKey> = snapshot
            .entities
            .keys()
            .map(|id| kin_model::RetrievalKey::Entity(*id))
            .chain(
                snapshot
                    .entity_revisions
                    .values()
                    .flat_map(|revisions| revisions.iter())
                    .map(|revision| kin_model::RetrievalKey::EntityRevision(revision.revision_id)),
            )
            .collect();
        assert!(
            keys.len() > covered,
            "the fixture must leave keys uncovered so the store reads short: {} keys, {covered} \
             covered",
            keys.len()
        );
        for key in keys.iter().take(covered) {
            index.upsert_retrievable(*key, &[1.0, 0.0]).unwrap();
        }
        let descriptor = kin_db::IndexDescriptor {
            model_id: Some("salvage-partial-coverage-fixture@v1".to_string()),
            graph_root: Some(hex::encode(graph.compute_root_hash())),
        };
        index.set_descriptor(descriptor.clone());
        let path = dir.join("partial.kvec");
        index.save(&path).unwrap();
        assert!(matches!(
            graph.load_vector_index_compatible(&path, &descriptor),
            kin_db::VectorIndexLoad::Loaded(_)
        ));
    }

    /// A store that had coverage retired at open says so, with both counts.
    ///
    /// This is FIR-2562's first ask, and it could not be answered from kin at
    /// all until kin-db 0.7.47: the counts were computed on the salvage path
    /// and thrown away when `load_vector_index_into_graph_if_valid` collapsed
    /// its outcome into a bare `bool`. With `VectorSidecarLoadOutcome` carrying
    /// them, a coverage LOSS renders as a loss with its size and its cause,
    /// distinct from work not yet done.
    ///
    /// Three arms, because the clause is only worth anything if it separates
    /// the stores it exists to separate: a salvaged store, the same store with
    /// no salvage recorded, and a store that never finished a fill.
    #[cfg(feature = "vector")]
    #[test]
    fn a_store_whose_coverage_was_retired_at_open_names_the_loss_and_its_size() {
        let (temp, binding, graph) = graph_validation_fixture();
        for name in ["alpha_transform", "beta_reduce", "gamma_emit", "delta_fold"] {
            graph.upsert_entity(&test_entity(name)).unwrap();
        }
        attach_partial_vector_index(&graph, temp.path(), 2);
        let status = graph.embedding_status();
        assert!(
            graph.vector_index_stats().is_some() && status.pending > 0,
            "the fixture must read measured and short, which is what a salvage leaves: {status:?}"
        );

        let salvaged = build_graph_status_response(
            &pinned(&binding),
            &graph,
            &Default::default(),
            &crate::commands::resources::EmbedRuntimeState {
                vector_index_salvage: Some(crate::commands::resources::VectorSalvage {
                    kept: 1770,
                    dropped: 342,
                }),
                embedding_coverage_ever_complete: true,
                ..Default::default()
            },
            &Default::default(),
        )
        .unwrap();
        let salvaged_line = salvaged
            .lines
            .iter()
            .find(|line| line.starts_with("Embeddings:"))
            .expect("the embeddings line still renders");
        assert!(
            salvaged_line.contains("1770 vectors were kept")
                && salvaged_line.contains("342 were retired"),
            "both counts have to reach the reader: {salvaged_line}"
        );
        assert!(
            salvaged_line.contains("salvaged per key"),
            "the cause has to be named, not left to be inferred: {salvaged_line}"
        );
        assert!(
            !salvaged_line.contains("shortfall against a fill that finished"),
            "the cause-bearing clause must outrank the one that only knows a fill \
             finished once: {salvaged_line}"
        );

        // Control one: the same store, same marker, no salvage recorded. The
        // counts must vanish rather than persist from somewhere.
        let no_salvage = build_graph_status_response(
            &pinned(&binding),
            &graph,
            &Default::default(),
            &crate::commands::resources::EmbedRuntimeState {
                vector_index_salvage: None,
                embedding_coverage_ever_complete: true,
                ..Default::default()
            },
            &Default::default(),
        )
        .unwrap();
        let no_salvage_line = no_salvage
            .lines
            .iter()
            .find(|line| line.starts_with("Embeddings:"))
            .expect("the embeddings line still renders");
        assert!(
            !no_salvage_line.contains("salvaged per key") && !no_salvage_line.contains("retired"),
            "a store with no salvage recorded must claim none: {no_salvage_line}"
        );
        assert!(
            no_salvage_line.contains("shortfall against a fill that finished"),
            "and it falls back to what it does know: {no_salvage_line}"
        );

        // Control two: a store that never finished a fill gets neither clause.
        let first_fill = build_graph_status_response(
            &pinned(&binding),
            &graph,
            &Default::default(),
            &Default::default(),
            &Default::default(),
        )
        .unwrap();
        let first_fill_line = first_fill
            .lines
            .iter()
            .find(|line| line.starts_with("Embeddings:"))
            .expect("the embeddings line still renders");
        assert!(
            !first_fill_line.contains("salvaged per key")
                && !first_fill_line.contains("a fill that finished"),
            "a first fill claims neither a salvage nor a completed fill: {first_fill_line}"
        );
        assert!(
            first_fill_line.contains(&format!(
                "{}/{} indexed ({} pending)",
                status.indexed, status.total, status.pending
            )),
            "the counters stay disclosed on all three: {first_fill_line}"
        );
    }

    /// A store whose coverage was whole once and is short now says so, and the
    /// clause has to survive an index being attached.
    ///
    /// This is the rendering half of FIR-2562. A per-key vector salvage retires
    /// what current graph truth cannot prove and installs the rest, so the
    /// daemon records no discard and the graph carries a measured, partial
    /// index. Every clause on this line was gated either on a recorded discard
    /// or on NO index being attached, so a salvaged store fell off the end of
    /// the chain and rendered bare: the rc0545c brown arm logged its salvage at
    /// 00:35:35Z and published `Embeddings: 1770/2112 indexed (342 pending)` at
    /// 00:38:19Z with nothing beside it, which is byte-for-byte the shape a
    /// store filling for the first time prints.
    ///
    /// Both directions are driven, because the clause is only worth anything if
    /// it separates the two stores it exists to separate. The store that never
    /// finished a fill must render the same counters and no clause.
    #[cfg(feature = "vector")]
    #[test]
    fn a_measured_store_short_of_a_fill_it_once_finished_says_so() {
        let (temp, binding, graph) = graph_validation_fixture();
        for name in ["alpha_transform", "beta_reduce", "gamma_emit", "delta_fold"] {
            graph.upsert_entity(&test_entity(name)).unwrap();
        }
        attach_partial_vector_index(&graph, temp.path(), 2);

        // The fixture has to hold both properties at once or the arm under test
        // is unreachable and every assertion below passes on the arm above it.
        let status = graph.embedding_status();
        assert!(
            graph.vector_index_stats().is_some(),
            "the fixture must carry an ATTACHED index, which is what a salvage leaves"
        );
        assert!(
            status.pending > 0 && status.indexed > 0,
            "the fixture must read measured and short: {status:?}"
        );

        let ever_complete = build_graph_status_response(
            &pinned(&binding),
            &graph,
            &Default::default(),
            &crate::commands::resources::EmbedRuntimeState {
                vector_index_discarded: None,
                embedding_coverage_ever_complete: true,
                ..Default::default()
            },
            &Default::default(),
        )
        .unwrap();
        let ever_complete_line = ever_complete
            .lines
            .iter()
            .find(|line| line.starts_with("Embeddings:"))
            .expect("the embeddings line still renders");
        assert!(
            ever_complete_line.contains(
                "a shortfall against a fill that finished rather than a \
                 first fill"
            ),
            "a store that lost ground must not render as a first fill: {ever_complete_line}"
        );
        assert!(
            !ever_complete_line.contains("the live graph carries no vector index"),
            "an attached index must not be described as absent: {ever_complete_line}"
        );
        // The cause and its counts live in kin-db and are not plumbed yet, so
        // nothing here may imply this line knows which of them applies.
        for forbidden in ["salvage", "retired", "evicted", "vectors were dropped"] {
            assert!(
                !ever_complete_line.contains(forbidden),
                "this line cannot name a cause kin does not receive ({forbidden}): \
                 {ever_complete_line}"
            );
        }

        let first_fill = build_graph_status_response(
            &pinned(&binding),
            &graph,
            &Default::default(),
            &Default::default(),
            &Default::default(),
        )
        .unwrap();
        let first_fill_line = first_fill
            .lines
            .iter()
            .find(|line| line.starts_with("Embeddings:"))
            .expect("the embeddings line still renders");
        assert!(
            first_fill_line.contains(&format!(
                "{}/{} indexed ({} pending)",
                status.indexed, status.total, status.pending
            )),
            "the counters stay disclosed on both stores: {first_fill_line}"
        );
        assert!(
            !first_fill_line.contains("a fill that finished"),
            "a store that never finished a fill must not claim one: {first_fill_line}"
        );
    }

    /// A graph carrying no attached vector index must never be told its
    /// embeddings are intact.
    ///
    /// `embedding_status` answers zero indexed for every retrievable object
    /// while no index is attached, so the bare counters read as discovered
    /// loss on a store that simply has nothing attached yet. Disclosing that
    /// is the fix. Promising the vectors are sitting somewhere intact is not:
    /// an index that loaded at open would still be attached, so whenever this
    /// state is reached there was no sidecar to load or a later reset detached
    /// one, and both of those rebuild rather than re-attach. The warning is the
    /// reader's only signal that coverage is not there, so it stays.
    #[cfg(feature = "vector")]
    #[test]
    fn a_graph_with_no_attached_index_is_not_told_its_embeddings_are_intact() {
        let (_temp, binding, graph) = graph_validation_fixture();
        graph
            .upsert_entity(&test_entity("alpha_transform"))
            .unwrap();
        let status = graph.embedding_status();
        assert!(
            status.total > 0,
            "the fixture must carry retrievable objects"
        );
        assert!(
            graph.vector_index_stats().is_none(),
            "the fixture graph must carry no attached vector index"
        );

        // The state the daemon can actually produce with no discard recorded:
        // no sidecar was on disk at open, while the persisted marker says this
        // store finished a fill once.
        let no_sidecar = build_graph_status_response(
            &pinned(&binding),
            &graph,
            &Default::default(),
            &crate::commands::resources::EmbedRuntimeState {
                vector_index_discarded: None,
                embedding_coverage_ever_complete: true,
                ..Default::default()
            },
            &Default::default(),
        )
        .unwrap();
        let embeddings_line = no_sidecar
            .lines
            .iter()
            .find(|line| line.starts_with("Embeddings:"))
            .expect("the embeddings line still renders");
        assert!(
            embeddings_line.contains(&format!(
                "{}/{} indexed ({} pending)",
                status.indexed, status.total, status.pending
            )),
            "the counters are true and stay disclosed: {embeddings_line}"
        );
        assert!(
            embeddings_line.contains("the live graph carries no vector index"),
            "the structural zero is named rather than left to read as loss: {embeddings_line}"
        );
        assert!(
            embeddings_line.contains("coverage has completed on this store before"),
            "the marker is disclosed so this is not read as a first fill: {embeddings_line}"
        );
        for forbidden in [
            "await the index",
            "nothing was discarded",
            "startup timing",
            "rather than re-embedding",
        ] {
            assert!(
                !no_sidecar.lines.iter().any(|line| line.contains(forbidden)),
                "no line may claim the vectors are intact ({forbidden}): {:?}",
                no_sidecar.lines
            );
        }
        assert!(
            no_sidecar
                .lines
                .iter()
                .any(|line| line.contains("embeddings are still pending")),
            "the only signal that coverage is absent must survive: {:?}",
            no_sidecar.lines
        );

        // A store that has never finished a fill is in the same structural
        // state and says so, minus the marker clause it has not earned.
        let first_fill = build_graph_status_response(
            &pinned(&binding),
            &graph,
            &Default::default(),
            &Default::default(),
            &Default::default(),
        )
        .unwrap();
        let first_fill_line = first_fill
            .lines
            .iter()
            .find(|line| line.starts_with("Embeddings:"))
            .expect("the embeddings line still renders");
        assert!(
            first_fill_line.contains("the live graph carries no vector index"),
            "a first fill names the same structural absence: {first_fill_line}"
        );
        assert!(
            !first_fill_line.contains("completed on this store before"),
            "a first fill must not claim a completion it never had: {first_fill_line}"
        );
    }

    /// A store whose graph authority is a remote backend has no durable local
    /// vector-sidecar contract: the embedding worker never starts and `/embed`
    /// refuses, so its backlog is not filling and never will. That fact
    /// outranks both the discard reason and the coverage marker here for the
    /// same reason it does in semantic query readiness, because every other
    /// clause implies work that is going to happen.
    #[cfg(feature = "vector")]
    #[test]
    fn a_store_that_can_never_embed_is_not_promised_background_recovery() {
        let (_temp, binding, graph) = graph_validation_fixture();
        graph
            .upsert_entity(&test_entity("gamma_transform"))
            .unwrap();

        let remote = build_graph_status_response(
            &pinned(&binding),
            &graph,
            &Default::default(),
            &crate::commands::resources::EmbedRuntimeState {
                vector_index_discarded: Some(
                    "fixture: metadata no longer matches graph truth".to_string(),
                ),
                embedding_coverage_ever_complete: true,
                embed_persistence_unavailable: true,
                ..Default::default()
            },
            &Default::default(),
        )
        .unwrap();
        let embeddings_line = remote
            .lines
            .iter()
            .find(|line| line.starts_with("Embeddings:"))
            .expect("the embeddings line still renders");
        assert!(
            embeddings_line.contains("remote storage backend")
                && embeddings_line.contains("nothing will embed here"),
            "a store that cannot embed must say so: {embeddings_line}"
        );
        assert!(
            !embeddings_line.contains("restores coverage in the background"),
            "no recovery may be promised where nothing will embed: {embeddings_line}"
        );
        assert!(
            remote
                .lines
                .iter()
                .any(|line| line.contains("embeddings are still pending")),
            "a backlog that will never fill keeps its warning: {:?}",
            remote.lines
        );
    }

    /// A discard at open is a real gap and keeps its accounting, but it names
    /// its cause beside the counters. Bare `0/N (N pending)` after a restart is
    /// what sent operators toward a manual GPU embed pass the daemon's own
    /// recovery made unnecessary.
    #[test]
    fn a_discarded_index_names_its_reason_beside_the_counters() {
        let (_temp, binding, graph) = graph_validation_fixture();
        graph.upsert_entity(&test_entity("beta_transform")).unwrap();
        let status = graph.embedding_status();

        let discarded = build_graph_status_response(
            &pinned(&binding),
            &graph,
            &Default::default(),
            &crate::commands::resources::EmbedRuntimeState {
                vector_index_discarded: Some(
                    "fixture: metadata no longer matches graph truth".to_string(),
                ),
                embedding_coverage_ever_complete: true,
                ..Default::default()
            },
            &Default::default(),
        )
        .unwrap();
        let embeddings_line = discarded
            .lines
            .iter()
            .find(|line| line.starts_with("Embeddings:"))
            .expect("the embeddings line still renders");
        assert!(
            embeddings_line.contains(&format!(
                "{}/{} indexed ({} pending)",
                status.indexed, status.total, status.pending
            )),
            "a real gap keeps its measured counters: {embeddings_line}"
        );
        assert!(
            embeddings_line.contains("fixture: metadata no longer matches graph truth"),
            "the discard reason is named where the counters are read: {embeddings_line}"
        );
        assert!(
            embeddings_line.contains("restores coverage in the background"),
            "the automatic recovery is named so nobody runs a manual pass: {embeddings_line}"
        );
        assert!(
            discarded
                .lines
                .iter()
                .any(|line| line.contains("embeddings are still pending")),
            "a real gap keeps its warning: {:?}",
            discarded.lines
        );

        // The reason is recorded once at open and never cleared, so once the
        // gap it explains is closed the line must not keep naming it. A graph
        // with nothing pending renders the plain measured line.
        let (_temp2, binding2, empty_graph) = graph_validation_fixture();
        let recovered = build_graph_status_response(
            &pinned(&binding2),
            &empty_graph,
            &Default::default(),
            &crate::commands::resources::EmbedRuntimeState {
                vector_index_discarded: Some(
                    "fixture: metadata no longer matches graph truth".to_string(),
                ),
                embedding_coverage_ever_complete: true,
                ..Default::default()
            },
            &Default::default(),
        )
        .unwrap();
        assert!(
            !recovered
                .lines
                .iter()
                .any(|line| line.contains("was not loaded")),
            "a closed gap must not keep naming its discard: {:?}",
            recovered.lines
        );
        assert!(
            recovered
                .lines
                .iter()
                .any(|line| line == "Embeddings: 0/0 indexed (0 pending)"),
            "a store with nothing pending renders the plain measured line: {:?}",
            recovered.lines
        );
    }

    /// A refused vector checkpoint has to reach the reader, and it has to reach
    /// a reader whose counters look complete.
    ///
    /// Every other clause on this line explains a shortfall the counters are
    /// already showing, so every other clause sits behind `pending > 0`. This
    /// one explains a shortfall they are not showing: the daemon holds vectors
    /// the sidecar does not, and a drained queue reports zero pending in
    /// exactly that state. That is how the regression reached a reader as a
    /// complete store at one reading and a store that had lost 342 vectors at
    /// the next. Drive both counter shapes, because a clause that only fires
    /// when something is already pending would miss the case it exists for.
    #[cfg(feature = "vector")]
    #[test]
    fn a_refused_vector_checkpoint_is_named_even_when_nothing_is_pending() {
        const REFUSAL: &str = "refusing vector checkpoint at repository generation 1: live exact \
                               tree does not match workspace authority";

        // A store whose counters read complete: nothing pending, nothing to
        // explain, and the plain line is what the existing tests pin here.
        let (_drained_temp, drained_binding, drained_graph) = graph_validation_fixture();
        let drained_control = build_graph_status_response(
            &pinned(&drained_binding),
            &drained_graph,
            &Default::default(),
            &crate::commands::resources::EmbedRuntimeState::default(),
            &Default::default(),
        )
        .unwrap();
        assert!(
            drained_control
                .lines
                .iter()
                .any(|line| line == "Embeddings: 0/0 indexed (0 pending)"),
            "the control must be the clean-counter case this clause has to survive: {:?}",
            drained_control.lines
        );

        let drained = build_graph_status_response(
            &pinned(&drained_binding),
            &drained_graph,
            &Default::default(),
            &crate::commands::resources::EmbedRuntimeState {
                deferred_vector_checkpoint: Some(REFUSAL.to_string()),
                ..Default::default()
            },
            &Default::default(),
        )
        .unwrap();
        let drained_line = drained
            .lines
            .iter()
            .find(|line| line.starts_with("Embeddings:"))
            .expect("the embeddings line still renders");
        assert!(
            drained_line.contains("the last vector checkpoint was refused"),
            "a store reporting nothing pending must still disclose undurable coverage: \
             {drained_line}"
        );
        assert!(
            drained_line.contains(REFUSAL),
            "the refusal's own cause is what tells a reader this is not ordinary pending work: \
             {drained_line}"
        );
        assert!(
            drained_line.contains("a restart re-derives them"),
            "the consequence a reader acts on is what a restart costs: {drained_line}"
        );

        // And on a store that IS filling, the clause is appended to the existing
        // chain rather than replacing it, so a reader keeps both facts.
        let (_filling_temp, filling_binding, filling_graph) = graph_validation_fixture();
        filling_graph
            .upsert_entity(&test_entity("alpha_transform"))
            .unwrap();
        let filling_status = filling_graph.embedding_status();
        assert!(
            filling_status.pending > 0,
            "the second fixture must actually have a backlog to explain"
        );
        let filling = build_graph_status_response(
            &pinned(&filling_binding),
            &filling_graph,
            &Default::default(),
            &crate::commands::resources::EmbedRuntimeState {
                deferred_vector_checkpoint: Some(REFUSAL.to_string()),
                ..Default::default()
            },
            &Default::default(),
        )
        .unwrap();
        let filling_line = filling
            .lines
            .iter()
            .find(|line| line.starts_with("Embeddings:"))
            .expect("the embeddings line still renders");
        assert!(
            filling_line.contains("the live graph carries no vector index"),
            "the existing pending-gated chain must still run: {filling_line}"
        );
        assert!(
            filling_line.contains("the last vector checkpoint was refused"),
            "and the refusal must be appended beside it, not instead of it: {filling_line}"
        );

        // The no-noise control, and the reason it is an assertion rather than a
        // reading of the code. A clause outside the pending gate runs on every
        // render, including every store that has nothing wrong with it, so the
        // only thing standing between this fix and a permanent new line on
        // every `kin graph status` is that the field is `None`. Pin both lines
        // byte for byte against the same fixture rendered with no refusal.
        let filling_quiet = build_graph_status_response(
            &pinned(&filling_binding),
            &filling_graph,
            &Default::default(),
            &crate::commands::resources::EmbedRuntimeState::default(),
            &Default::default(),
        )
        .unwrap();
        let filling_quiet_line = filling_quiet
            .lines
            .iter()
            .find(|line| line.starts_with("Embeddings:"))
            .expect("the embeddings line still renders");
        assert!(
            !filling_quiet_line.contains("vector checkpoint"),
            "a store with nothing refused must render exactly today's line: {filling_quiet_line}"
        );
        assert_eq!(
            filling_quiet_line.as_str(),
            filling_line
                .split("; the last vector checkpoint was refused")
                .next()
                .expect("the refusal clause must be an append, so the prefix is today's line"),
            "the clause must be a pure append: everything before it has to be byte-identical to \
             what a store with nothing refused renders"
        );
        assert_eq!(
            drained_control
                .lines
                .iter()
                .find(|line| line.starts_with("Embeddings:")),
            Some(&"Embeddings: 0/0 indexed (0 pending)".to_string()),
            "and the drained control's line is today's, unchanged, to the byte"
        );
    }

    /// A first fill that is waiting on the model download says so beside the
    /// counters, and stops saying it once the model is cached.
    ///
    /// The progress is injected rather than fetched, so this asserts what the
    /// status renders rather than what a network does. Without the clause the
    /// line reads as a queue nobody is draining, which is what sent a first
    /// reader looking for a wedged worker.
    #[test]
    fn a_pending_backlog_names_the_model_download_that_is_blocking_it() {
        let (_temp, binding, graph) = graph_validation_fixture();
        graph.upsert_entity(&test_entity("beta_transform")).unwrap();

        let downloading = build_graph_status_response(
            &pinned(&binding),
            &graph,
            &Default::default(),
            &crate::commands::resources::EmbedRuntimeState {
                model_fetch: kin_cli_model_fetch(137 * 1024 * 1024, true),
                ..Default::default()
            },
            &Default::default(),
        )
        .unwrap();
        let embeddings_line = downloading
            .lines
            .iter()
            .find(|line| line.starts_with("Embeddings:"))
            .expect("the embeddings line still renders");
        assert!(
            embeddings_line.contains(
                "embedding model is still downloading (137 of 523 MB from huggingface.co)"
            ),
            "the measured download reaches the counters: {embeddings_line}"
        );
        assert!(
            embeddings_line.contains("nothing can embed until it lands"),
            "the counters are given their cause: {embeddings_line}"
        );

        let cached = build_graph_status_response(
            &pinned(&binding),
            &graph,
            &Default::default(),
            &crate::commands::resources::EmbedRuntimeState {
                model_fetch: kin_cli_model_fetch(0, false),
                ..Default::default()
            },
            &Default::default(),
        )
        .unwrap();
        let cached_line = cached
            .lines
            .iter()
            .find(|line| line.starts_with("Embeddings:"))
            .expect("the embeddings line still renders");
        assert!(
            !cached_line.contains("embedding model"),
            "a model that is not being fetched must not be named as a blocker: {cached_line}"
        );
    }

    /// A model fetch state with everything but the two facts under test held
    /// fixed, so a rendering difference can only come from those two.
    fn kin_cli_model_fetch(
        fetched_bytes: u64,
        fetching: bool,
    ) -> crate::embed_model::EmbedModelFetch {
        crate::embed_model::EmbedModelFetch {
            model_id: crate::embed_model::DEFAULT_EMBED_MODEL_ID.to_string(),
            cache_dir: Some("/home/dev/.cache/huggingface/hub/models--x".to_string()),
            present: !fetching,
            fetched_bytes,
            expected_bytes: Some(crate::embed_model::DEFAULT_EMBED_MODEL_BYTES),
            fetching,
            no_fetch_reason: None,
            relocated_hf_home: None,
        }
    }

    #[test]
    fn graph_status_does_not_call_a_mixed_relation_graph_relationless() {
        let (_temp, binding, graph) = graph_validation_fixture();
        let entity = test_entity("run_task");
        graph.upsert_entity(&entity).unwrap();
        let test_id = kin_model::TestId::new();
        admit_test_case(&graph, test_id);
        graph
            .upsert_relation(&graph_relation(
                RelationKind::Covers,
                GraphNodeId::Test(test_id),
                GraphNodeId::Entity(entity.id),
            ))
            .unwrap();

        let response = build_graph_status_response(
            &pinned(&binding),
            &graph,
            &Default::default(),
            &Default::default(),
            &Default::default(),
        )
        .unwrap();

        assert!(response
            .lines
            .iter()
            .any(|line| line.contains("Entity-to-entity relations: 0")));
        assert!(response
            .lines
            .iter()
            .any(|line| line == "All graph relations excluding CoChanges: 1 (1.00/entity)"));
        assert!(
            !response
                .lines
                .iter()
                .any(|line| line.contains("no relations in graph")),
            "{:?}",
            response.lines
        );
    }

    /// One line states how much of the repository can be queried, and the
    /// counters that are not that answer say what they count instead.
    ///
    /// Four counters on this screen bore on repository coverage and none was
    /// labelled the answer. A stranger reading `Files: 66` beside `Supported
    /// inputs: 141` beside `213 admitted regular files` concluded, correctly,
    /// that the output could not say what fraction of the repository it covered.
    #[test]
    fn graph_status_states_repository_coverage_once_and_labels_it() {
        let (_temp, binding, graph) = graph_validation_fixture();
        let entity = test_entity("run_task");
        graph.upsert_entity(&entity).unwrap();

        let response = build_graph_status_response(
            &pinned(&binding),
            &graph,
            &Default::default(),
            &Default::default(),
            &Default::default(),
        )
        .unwrap();

        let coverage: Vec<&String> = response
            .lines
            .iter()
            .filter(|line| line.starts_with("Repository coverage:"))
            .collect();
        assert_eq!(
            coverage.len(),
            1,
            "exactly one line answers the coverage question: {:?}",
            response.lines
        );
        assert!(
            coverage[0].starts_with("Repository coverage:"),
            "the answer must be labelled: {}",
            coverage[0]
        );

        // The counter that read as a contradiction of it now says it measures
        // something else.
        let supported = response
            .lines
            .iter()
            .find(|line| line.starts_with("Supported inputs:"))
            .unwrap_or_else(|| panic!("supported inputs line: {:?}", response.lines));
        assert!(
            supported.contains("upper bound on coverage"),
            "the upper bound must not read as a second coverage answer: {supported}"
        );
    }

    /// Both arms of the coverage line, stated without a store.
    #[test]
    fn repository_coverage_names_the_fraction_or_says_there_is_none() {
        assert_eq!(
            repository_coverage_line(66, 213),
            "Repository coverage: 66 of 213 admitted files produced entities (31%)"
        );
        // The express numbers the stranger read. A fresh store has no fraction
        // to state, and printing a ratio over zero is the shape being removed.
        assert_eq!(
            repository_coverage_line(0, 0),
            "Repository coverage: no files admitted yet, so there is no coverage fraction to \
             report"
        );
    }

    #[test]
    fn graph_validate_accepts_external_import_placeholder_destination() {
        let (_temp, binding, graph) = graph_validation_fixture();
        let (caller, relation) = external_placeholder_relation(RelationKind::Calls);
        graph.upsert_entity(&caller).unwrap();
        graph.upsert_relation(&relation).unwrap();

        let response = build_graph_validate_response(&pinned(&binding), &graph).unwrap();

        assert!(response.error.is_none(), "{:?}", response.lines);
        assert!(response
            .lines
            .iter()
            .any(|line| line == "✓ All integrity checks passed."));
        // The verdict names the question it answered, and the answer to the
        // other one is printed beside it. A pass here was read as a clean bill
        // on a graph missing most of its relation edges.
        assert!(
            response.lines.iter().any(|line| line
                .starts_with("Integrity only: these checks say the edges present are coherent")),
            "{:?}",
            response.lines
        );
        assert!(
            response
                .lines
                .iter()
                .any(|line| line.starts_with("Reference edge coverage")),
            "{:?}",
            response.lines
        );
    }

    #[test]
    fn graph_validate_rejects_unmarked_dangling_destination() {
        let (_temp, binding, graph) = graph_validation_fixture();
        let caller = test_entity("run_task");
        graph.upsert_entity(&caller).unwrap();
        graph
            .upsert_relation(&test_relation(
                RelationKind::Calls,
                caller.id,
                EntityId::new(),
            ))
            .unwrap();

        let response = build_graph_validate_response(&pinned(&binding), &graph).unwrap();

        assert!(response.error.is_some(), "{:?}", response.lines);
        assert!(response
            .lines
            .iter()
            .any(|line| line == "✗ 1 relation endpoint references non-existent entities"));
    }

    #[test]
    fn graph_validate_rejects_relation_with_both_endpoints_absent() {
        let (_temp, binding, graph) = graph_validation_fixture();
        graph
            .upsert_relation(&test_relation(
                RelationKind::References,
                EntityId::new(),
                EntityId::new(),
            ))
            .unwrap();

        let response = build_graph_validate_response(&pinned(&binding), &graph).unwrap();

        assert!(response.error.is_some(), "{:?}", response.lines);
        assert!(response
            .lines
            .iter()
            .any(|line| line == "Checked 0 entities, 1 relation"));
        assert!(response
            .lines
            .iter()
            .any(|line| line == "✗ 2 relation endpoints reference non-existent entities"));
    }

    #[test]
    fn graph_validate_rejects_missing_source_on_canonical_external_placeholder() {
        let (_temp, binding, graph) = graph_validation_fixture();
        let (_caller, relation) = external_placeholder_relation(RelationKind::References);
        graph.upsert_relation(&relation).unwrap();

        let response = build_graph_validate_response(&pinned(&binding), &graph).unwrap();

        assert!(response.error.is_some(), "{:?}", response.lines);
        assert!(response
            .lines
            .iter()
            .any(|line| line == "✗ 1 relation endpoint references non-existent entities"));
    }

    #[test]
    fn graph_inspect_collapses_repeated_peer_edges() {
        let graph = kin_db::InMemoryGraph::new();
        let mut container = test_entity("Stats");
        container.kind = EntityKind::Class;
        container.file_origin = Some(FilePathId::new("crates/printer/src/stats.rs"));
        let mut member = test_entity("Stats::elapsed");
        member.kind = EntityKind::Method;
        member.file_origin = Some(FilePathId::new("crates/printer/src/stats.rs"));
        graph.upsert_entity(&container).unwrap();
        graph.upsert_entity(&member).unwrap();

        // Two rows for one logical edge: distinct relation IDs, identical
        // (direction, kind, peer).
        for _ in 0..2 {
            graph
                .upsert_relation(&test_relation(
                    RelationKind::Contains,
                    container.id,
                    member.id,
                ))
                .unwrap();
        }

        let response = build_graph_inspect_response(&graph, "Stats::elapsed").unwrap();
        let peer_rows: Vec<_> = response
            .lines
            .iter()
            .filter(|line| line.starts_with("    <- Contains "))
            .collect();

        assert_eq!(peer_rows.len(), 1, "{:?}", response.lines);
        assert_eq!(
            peer_rows[0],
            &format!(
                "    <- Contains Stats [Class] (crates/printer/src/stats.rs; entity:{})",
                container.id
            )
        );
        assert!(response.lines.iter().any(|line| line == "  Relations (1):"));
    }

    #[test]
    fn graph_inspect_keeps_distinct_peers_that_share_a_name_and_file() {
        let graph = kin_db::InMemoryGraph::new();
        let mut member = test_entity("Stats::elapsed");
        member.kind = EntityKind::Method;
        graph.upsert_entity(&member).unwrap();

        let file = FilePathId::new("crates/printer/src/stats.rs");
        let mut declaration = test_entity("Stats");
        declaration.kind = EntityKind::Class;
        declaration.file_origin = Some(file.clone());
        let mut alias = test_entity("Stats");
        alias.kind = EntityKind::TypeAlias;
        alias.file_origin = Some(file);
        graph.upsert_entity(&declaration).unwrap();
        graph.upsert_entity(&alias).unwrap();

        for peer in [&declaration, &alias] {
            graph
                .upsert_relation(&test_relation(RelationKind::Contains, peer.id, member.id))
                .unwrap();
        }

        let response = build_graph_inspect_response(&graph, "Stats::elapsed").unwrap();
        let peer_rows: Vec<_> = response
            .lines
            .iter()
            .filter(|line| line.starts_with("    <- Contains "))
            .collect();

        assert_eq!(peer_rows.len(), 2, "{:?}", response.lines);
        assert!(peer_rows
            .iter()
            .any(|line| line.contains("Stats [Class] (crates/printer/src/stats.rs; entity:")));
        assert!(peer_rows
            .iter()
            .any(|line| line.contains("Stats [TypeAlias] (crates/printer/src/stats.rs; entity:")));
    }

    #[test]
    fn graph_inspect_disambiguates_overloads_with_the_same_name_kind_and_file() {
        let graph = kin_db::InMemoryGraph::new();
        let mut subject = test_entity("dispatch");
        subject.kind = EntityKind::Method;
        graph.upsert_entity(&subject).unwrap();

        let file = FilePathId::new("src/handlers.rs");
        let mut first = test_entity("Handler::run");
        first.kind = EntityKind::Method;
        first.file_origin = Some(file.clone());
        first.span = Some(SourceSpan {
            file: file.clone(),
            start_byte: 10,
            end_byte: 20,
            start_line: 2,
            start_col: 0,
            end_line: 4,
            end_col: 1,
        });
        let mut second = test_entity("Handler::run");
        second.kind = EntityKind::Method;
        second.file_origin = Some(file.clone());
        second.span = Some(SourceSpan {
            file,
            start_byte: 30,
            end_byte: 40,
            start_line: 6,
            start_col: 0,
            end_line: 8,
            end_col: 1,
        });
        graph.upsert_entity(&first).unwrap();
        graph.upsert_entity(&second).unwrap();

        for peer in [&first, &second] {
            graph
                .upsert_relation(&test_relation(RelationKind::Calls, subject.id, peer.id))
                .unwrap();
        }

        let response = build_graph_inspect_response(&graph, "dispatch").unwrap();
        let peer_rows: Vec<_> = response
            .lines
            .iter()
            .filter(|line| line.starts_with("    -> Calls Handler::run "))
            .collect();

        assert_eq!(peer_rows.len(), 2, "{:?}", response.lines);
        assert_ne!(peer_rows[0], peer_rows[1], "{:?}", response.lines);
        assert!(peer_rows
            .iter()
            .any(|line| line.contains(&format!("entity:{}", first.id))));
        assert!(peer_rows
            .iter()
            .any(|line| line.contains(&format!("entity:{}", second.id))));
    }

    #[test]
    fn graph_inspect_includes_mixed_domain_relations() {
        let graph = kin_db::InMemoryGraph::new();
        let subject = test_entity("dispatch");
        graph.upsert_entity(&subject).unwrap();

        let test_id = kin_model::TestId::new();
        let artifact_id = ArtifactId::new();
        admit_test_case(&graph, test_id);
        admit_artifact(&graph, artifact_id, "src/dispatch.rs");
        graph
            .upsert_relation(&graph_relation(
                RelationKind::Covers,
                GraphNodeId::Test(test_id),
                GraphNodeId::Entity(subject.id),
            ))
            .unwrap();
        graph
            .upsert_relation(&graph_relation(
                RelationKind::OwnedByFile,
                GraphNodeId::Entity(subject.id),
                GraphNodeId::Artifact(artifact_id),
            ))
            .unwrap();

        let response = build_graph_inspect_response(&graph, "dispatch").unwrap();

        assert!(response.lines.iter().any(|line| line == "  Relations (2):"));
        assert!(response
            .lines
            .iter()
            .any(|line| line == &format!("    <- Covers test:{test_id}")));
        assert!(response
            .lines
            .iter()
            .any(|line| line == &format!("    -> OwnedByFile artifact:{}", artifact_id.0)));
    }

    #[test]
    fn graph_inspect_bounds_rendered_rows_but_reports_the_full_unique_count() {
        let graph = kin_db::InMemoryGraph::new();
        let subject = test_entity("dispatch");
        graph.upsert_entity(&subject).unwrap();

        for index in 0..=INSPECT_RELATION_LIMIT {
            let peer = test_entity(&format!("peer_{index}"));
            graph.upsert_entity(&peer).unwrap();
            graph
                .upsert_relation(&test_relation(RelationKind::Calls, subject.id, peer.id))
                .unwrap();
        }

        let response = build_graph_inspect_response(&graph, "dispatch").unwrap();
        let peer_rows = response
            .lines
            .iter()
            .filter(|line| line.starts_with("    -> Calls peer_"))
            .count();

        assert_eq!(peer_rows, INSPECT_RELATION_LIMIT, "{:?}", response.lines);
        assert!(response
            .lines
            .iter()
            .any(|line| line == &format!("  Relations ({}):", INSPECT_RELATION_LIMIT + 1)));
        assert!(response
            .lines
            .iter()
            .any(|line| line == "    ... and 1 more"));
    }

    #[test]
    fn graph_inspect_separates_incoming_and_outgoing_edges_of_one_kind() {
        let graph = kin_db::InMemoryGraph::new();
        let subject = test_entity("render");
        let caller = test_entity("main");
        let callee = test_entity("format_row");
        for entity in [&subject, &caller, &callee] {
            graph.upsert_entity(entity).unwrap();
        }
        graph
            .upsert_relation(&test_relation(RelationKind::Calls, caller.id, subject.id))
            .unwrap();
        graph
            .upsert_relation(&test_relation(RelationKind::Calls, subject.id, callee.id))
            .unwrap();

        let response = build_graph_inspect_response(&graph, "render").unwrap();

        assert!(response.lines.iter().any(|line| line == "  Relations (2):"));
        assert!(response
            .lines
            .iter()
            .any(|line| line.starts_with("    <- Calls main ")));
        assert!(response
            .lines
            .iter()
            .any(|line| line.starts_with("    -> Calls format_row ")));
    }

    #[test]
    fn graph_inspect_renders_self_relation_bidirectionally() {
        let graph = kin_db::InMemoryGraph::new();
        let subject = test_entity("render");
        graph.upsert_entity(&subject).unwrap();
        graph
            .upsert_relation(&test_relation(RelationKind::Calls, subject.id, subject.id))
            .unwrap();

        let response = build_graph_inspect_response(&graph, "render").unwrap();

        assert!(response.lines.iter().any(|line| line == "  Relations (1):"));
        assert!(response
            .lines
            .iter()
            .any(|line| line.starts_with("    <-> Calls render ")));
    }

    #[test]
    fn graph_inspect_accepts_entity_uuid() {
        let graph = kin_db::InMemoryGraph::new();
        let entity = test_entity("checkout");
        let id = entity.id;
        graph.upsert_entity(&entity).unwrap();

        let response = build_graph_inspect_response(&graph, &id.to_string()).unwrap();

        assert!(response
            .lines
            .iter()
            .any(|line| line == "Entity: checkout (Function)"));
        assert!(response
            .lines
            .iter()
            .any(|line| line == &format!("  ID: {id}")));
    }

    struct GraphSourceFixture {
        _temp: tempfile::TempDir,
        layout: kin_core::KinLayout,
        binding: kin_core::LocalRepositoryAuthorityBinding,
        graph: kin_db::InMemoryGraph,
        file_id: FilePathId,
    }

    impl GraphSourceFixture {
        /// The pinned arm, which is what a one-shot CLI invocation holds: these
        /// tests measure the source-resolution taxonomy, not authority sharing.
        fn authority(&self) -> super::super::repository_authority::RequestRepositoryAuthority {
            super::super::repository_authority::RequestRepositoryAuthority::pinned(
                self.binding.clone(),
            )
        }
    }

    /// A batch of source resolutions costs ONE authority open, not one each.
    ///
    /// `get_entity_sources` resolves source per entity, and every resolution
    /// used to open authority for itself: a batch of N entities paid N
    /// whole-store verifications. The shared arm makes the batch cost one, which
    /// also makes it coherent, since per-entity opens could straddle a
    /// publication and return rows from two different generations.
    ///
    /// Both arms are measured in one test on purpose. The bound is only evidence
    /// if the counter can tell them apart, and the pinned half is what proves it
    /// can: it still climbs with batch size, which is exactly right for a
    /// one-shot invocation and exactly what the daemon must not do.
    #[test]
    fn a_batch_of_source_resolutions_shares_one_authority_open() {
        const BATCH: usize = 4;
        const SOURCE: &[u8] = b"fn target() {}\n";
        let fixture = graph_source_fixture(Some(SOURCE));
        let entity = source_entity("target", fixture.file_id.clone(), 0, SOURCE.len() - 1);
        let id = entity.id;
        commit_source_entity(&fixture, &entity);
        let opens = super::super::repository_authority::repository_authority_opens_on_this_thread;

        let shared = std::sync::Arc::new(
            super::super::repository_authority::ActiveRepositoryAuthority::open(&fixture.binding)
                .expect("open authority for the batch"),
        );
        let shared_authority =
            super::super::repository_authority::RequestRepositoryAuthority::shared(
                fixture.binding.clone(),
                std::sync::Arc::new(move || Ok(std::sync::Arc::clone(&shared))),
            );

        let before = opens();
        for _ in 0..BATCH {
            let outcome =
                build_entity_source_outcome(&shared_authority, &fixture.graph, &id.to_string())
                    .expect("resolve source through the shared authority");
            assert!(
                matches!(outcome, EntitySourceOutcome::Found(_)),
                "each resolution must actually project a body, or the count proves nothing"
            );
        }
        assert_eq!(
            opens() - before,
            0,
            "a batch reading through one already-open authority must not open again, once per \
             item or at all"
        );

        let pinned = fixture.authority();
        let before = opens();
        for _ in 0..BATCH {
            build_entity_source_outcome(&pinned, &fixture.graph, &id.to_string())
                .expect("resolve source through the pinned authority");
        }
        assert_eq!(
            opens() - before,
            BATCH as u64,
            "the pinned arm opens per resolution, which is what a one-shot CLI invocation wants \
             and what proves this counter can see the difference"
        );
    }

    fn graph_source_fixture(source: Option<&[u8]>) -> GraphSourceFixture {
        // Publication proves the Git source three times and requires all three
        // proofs to agree, and the proof deliberately includes the contents of
        // the user's resolved global excludes file, which is addressed through
        // `HOME`. A neighbouring test that moves `HOME` between two of those
        // proofs therefore fails publication as uncertain. Holding the
        // environment mutation domain, without changing anything in it, is what
        // keeps `HOME` still for the width of the window.
        let _domain = kin_core::test_env::EnvVarGuard::new();
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("repo");
        fs::create_dir(&repo).unwrap();
        let git = |args: &[&str]| {
            let output = crate::commands::test_subprocess::fixture_git(&repo)
                // This fixture consumes the committed repository immediately.
                // Prevent maintenance from detaching work that can leave
                // transient pack locks after `git commit` exits.
                .args(["-c", "maintenance.auto=false", "-c", "gc.auto=0"])
                .args(args)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "git {args:?} failed: stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        };
        git(&["init", "--initial-branch=main"]);
        git(&["config", "user.email", "kin@example.invalid"]);
        git(&["config", "user.name", "Kin"]);
        let file_id = FilePathId::new("src/lib.rs");
        if let Some(source) = source {
            fs::create_dir_all(repo.join("src")).unwrap();
            fs::write(repo.join(&file_id.0), source).unwrap();
        } else {
            fs::write(repo.join("README.md"), b"authority without source\n").unwrap();
        }
        git(&["add", "--all"]);
        git(&["commit", "--signoff", "-m", "seed exact source authority"]);
        let init = kin_core::init_from_git(&repo).unwrap();
        let layout = init.layout;
        let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(&layout).unwrap();
        let authority =
            crate::commands::repository_authority::ActiveRepositoryAuthority::open(&binding)
                .unwrap();
        let mut resolved_tree = authority.workspace().unwrap().tree;
        if source.is_none() {
            let mut artifacts = resolved_tree.into_artifacts().collect::<Vec<_>>();
            artifacts.push(ResolvedArtifact::new(
                ArtifactId::new(),
                RepoPath::from_utf8(file_id.0.clone()).unwrap(),
                TreeEntry::blob(Hash256::from_bytes([0x99; 32]), false),
            ));
            resolved_tree = ResolvedTree::from_artifacts(artifacts).unwrap();
        }
        let mut snapshot = kin_db::GraphSnapshot::empty();
        snapshot.resolved_tree = resolved_tree;
        let graph = kin_db::InMemoryGraph::from_snapshot(snapshot).unwrap();

        GraphSourceFixture {
            _temp: temp,
            layout,
            binding,
            graph,
            file_id,
        }
    }

    fn source_entity(name: &str, file_id: FilePathId, start: usize, end: usize) -> Entity {
        let mut entity = test_entity(name);
        entity.file_origin = Some(file_id);
        entity.span = Some(SourceSpan {
            file: entity.file_origin.clone().unwrap(),
            start_byte: start,
            end_byte: end,
            start_line: 2,
            start_col: 1,
            end_line: 4,
            end_col: 2,
        });
        entity.signature = format!("fn {name}()");
        entity
    }

    fn commit_source_entity(fixture: &GraphSourceFixture, entity: &Entity) {
        fixture.graph.upsert_entity(entity).unwrap();
    }

    #[test]
    fn graph_source_reads_exact_body_from_graph_blob_by_uuid() {
        let source = "fn before() {}\nfn target() {\n    2 + 2\n}\nfn after() {}\n";
        let body = "fn target() {\n    2 + 2\n}";
        let start = source.find(body).unwrap();
        let end = start + body.len();
        let fixture = graph_source_fixture(Some(source.as_bytes()));

        let entity = source_entity("target", fixture.file_id.clone(), start, end);
        let id = entity.id;
        commit_source_entity(&fixture, &entity);

        let response =
            build_graph_source_response(&fixture.authority(), &fixture.graph, &id.to_string())
                .unwrap();
        let source = response.source.unwrap();

        assert_eq!(source.body, body);
        assert_eq!(source.file_path, "src/lib.rs");
        assert_eq!(source.start_byte, start);
        assert_eq!(source.end_byte, end);
    }

    /// This arm enforces the span/bytes coherence rule too.
    ///
    /// It is not reached through `resolve_entity_source_authority`: it resolves its
    /// own bytes, and it is what the daemon serves `get_entity_source` and
    /// `get_entity_sources` from, so in product mode it is the arm agents actually
    /// read through. A rule enforced only on the offline resolver would have
    /// protected the least-used path and left the most-used one open.
    ///
    /// The two bounds checks below it cannot substitute: this fixture's stale span
    /// (0..14 of a 14-byte original) is comfortably inside the longer replacement,
    /// so a length test passes and the read would return a truncated fragment of a
    /// different function as this entity's body.
    #[test]
    fn graph_source_refuses_a_span_derived_from_different_bytes() {
        let original = b"fn target() {}\n";
        let fixture = graph_source_fixture(Some(original));
        let mut entity = source_entity("target", fixture.file_id.clone(), 0, original.len() - 1);
        // Stamp the digest of a DIFFERENT source: the reconciler records the digest
        // each span was derived from, and here it does not describe the tree's bytes.
        entity.metadata.extra.insert(
            "blob_hash".to_string(),
            serde_json::Value::String(Hash256::from_bytes([0x5a; 32]).to_string()),
        );
        let id = entity.id;
        commit_source_entity(&fixture, &entity);

        let error =
            build_graph_source_response(&fixture.authority(), &fixture.graph, &id.to_string())
                .expect_err("a span derived from other bytes must not serve a mis-sliced body");
        let message = format!("{error:#}");
        assert!(
            message.contains("does not describe these bytes"),
            "the refusal must name the incoherence, got: {message}"
        );
    }

    /// An entity whose recorded digest matches the tree is served AND says so, so
    /// a caller preparing an overwrite can tell a verified body from an unverified
    /// one on this arm as well.
    #[test]
    fn graph_source_reports_span_coherence_for_a_verified_read() {
        let original = b"fn target() {}\n";
        let fixture = graph_source_fixture(Some(original));
        let mut entity = source_entity("target", fixture.file_id.clone(), 0, original.len() - 1);

        // The digest the tree actually holds for this path.
        let blob = read_entity_file_bytes_with_digest(&fixture.binding, &fixture.graph, &entity)
            .unwrap()
            .1;
        entity.metadata.extra.insert(
            "blob_hash".to_string(),
            serde_json::Value::String(blob.to_string()),
        );
        let id = entity.id;
        commit_source_entity(&fixture, &entity);

        let response =
            build_graph_source_response(&fixture.authority(), &fixture.graph, &id.to_string())
                .unwrap();
        let record = response.source.unwrap();
        assert_eq!(record.body, "fn target() {}");
        assert_eq!(record.span_coherence, "digest_verified");
    }

    #[test]
    fn graph_source_ignores_checkout_path_reuse() {
        let original = b"fn target() {}\n";
        let fixture = graph_source_fixture(Some(original));
        let entity = source_entity("target", fixture.file_id.clone(), 0, original.len() - 1);
        let id = entity.id;
        commit_source_entity(&fixture, &entity);

        fs::write(
            fixture.layout.working_dir().join(&fixture.file_id.0),
            b"fn replacement() {}\n",
        )
        .unwrap();
        let response =
            build_graph_source_response(&fixture.authority(), &fixture.graph, &id.to_string())
                .unwrap();
        assert_eq!(response.source.unwrap().body, "fn target() {}");
    }

    #[test]
    fn graph_source_returns_error_on_oob_span() {
        let source = "fn target() {}\n";
        let fixture = graph_source_fixture(Some(source.as_bytes()));
        let end = source.len() + 10;
        let entity = source_entity("target", fixture.file_id.clone(), 0, end);
        let id = entity.id;
        commit_source_entity(&fixture, &entity);

        let err =
            build_graph_source_response(&fixture.authority(), &fixture.graph, &id.to_string())
                .unwrap_err()
                .to_string();

        assert!(
            err.contains(&format!("source span 0..{end} is out of bounds")),
            "{err}"
        );
        assert!(err.contains("src/lib.rs"), "{err}");
    }

    #[test]
    fn graph_source_returns_error_when_path_is_absent_from_authority() {
        let fixture = graph_source_fixture(None);
        let entity = source_entity("target", fixture.file_id.clone(), 0, 8);
        let id = entity.id;
        commit_source_entity(&fixture, &entity);

        let err =
            build_graph_source_response(&fixture.authority(), &fixture.graph, &id.to_string())
                .unwrap_err()
                .to_string();

        assert!(
            err.contains("source 'src/lib.rs' is not in workspace"),
            "{err}"
        );
    }

    #[test]
    fn entity_source_outcome_found_returns_record() {
        let source = "fn before() {}\nfn target() {\n    2 + 2\n}\nfn after() {}\n";
        let body = "fn target() {\n    2 + 2\n}";
        let start = source.find(body).unwrap();
        let end = start + body.len();
        let fixture = graph_source_fixture(Some(source.as_bytes()));

        let entity = source_entity("target", fixture.file_id.clone(), start, end);
        let id = entity.id;
        commit_source_entity(&fixture, &entity);

        match build_entity_source_outcome(&fixture.authority(), &fixture.graph, &id.to_string())
            .unwrap()
        {
            EntitySourceOutcome::Found(record) => assert_eq!(record.body, body),
            other => panic!("expected Found, got {other:?}"),
        }
    }

    #[test]
    fn entity_source_outcome_not_found_for_invented_uuid() {
        let fixture = graph_source_fixture(Some(b"fn x() {}\n"));
        let invented = uuid::Uuid::new_v4();

        match build_entity_source_outcome(
            &fixture.authority(),
            &fixture.graph,
            &invented.to_string(),
        )
        .unwrap()
        {
            EntitySourceOutcome::NotFound(message) => {
                assert!(message.contains(&invented.to_string()), "{message}");
                // Non-retryable signal for the agent.
                assert!(message.contains("invalid or stale"), "{message}");
                assert!(message.contains("will not succeed"), "{message}");
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn entity_source_outcome_no_source_for_spanless_entity() {
        let fixture = graph_source_fixture(Some(b"fn x() {}\n"));
        let mut entity = source_entity("target", fixture.file_id.clone(), 0, 8);
        // A valid, resolvable entity that simply carries no source span.
        entity.span = None;
        let id = entity.id;
        fixture.graph.upsert_entity(&entity).unwrap();

        match build_entity_source_outcome(&fixture.authority(), &fixture.graph, &id.to_string())
            .unwrap()
        {
            EntitySourceOutcome::NoSource(message) => {
                assert!(message.contains("target"), "{message}");
                assert!(message.contains("no source span"), "{message}");
                assert!(message.contains("ID is valid"), "{message}");
            }
            other => panic!("expected NoSource, got {other:?}"),
        }
    }

    #[test]
    fn not_found_and_no_source_messages_are_distinguishable() {
        let fixture = graph_source_fixture(Some(b"fn x() {}\n"));

        let invented = uuid::Uuid::new_v4();
        let not_found = build_entity_source_outcome(
            &fixture.authority(),
            &fixture.graph,
            &invented.to_string(),
        )
        .unwrap();

        let mut spanless = source_entity("target", fixture.file_id.clone(), 0, 8);
        spanless.span = None;
        let spanless_id = spanless.id;
        fixture.graph.upsert_entity(&spanless).unwrap();
        let no_source = build_entity_source_outcome(
            &fixture.authority(),
            &fixture.graph,
            &spanless_id.to_string(),
        )
        .unwrap();

        let (nf, ns) = match (not_found, no_source) {
            (EntitySourceOutcome::NotFound(nf), EntitySourceOutcome::NoSource(ns)) => (nf, ns),
            other => panic!("unexpected taxonomy: {other:?}"),
        };
        assert_ne!(nf, ns);
    }

    #[test]
    fn graph_source_response_not_found_sets_error_and_leaves_source_none() {
        // Regression guard for the precedence bug: a not-found query must set the
        // structured `error` field (surfaced ahead of any missing-source text)
        // and leave `source` empty.
        let fixture = graph_source_fixture(Some(b"fn x() {}\n"));
        let invented = uuid::Uuid::new_v4();

        let response = build_graph_source_response(
            &fixture.authority(),
            &fixture.graph,
            &invented.to_string(),
        )
        .unwrap();

        assert!(response.source.is_none());
        let error = response.error.expect("not-found must populate error");
        assert!(error.contains(&invented.to_string()), "{error}");
    }

    /// Build a validate fixture whose graph carries exactly `tree_paths` in its
    /// resolved tree, independent of what the working directory holds.
    fn orphan_fixture(
        tree_paths: &[&str],
    ) -> (
        tempfile::TempDir,
        kin_core::KinLayout,
        kin_core::LocalRepositoryAuthorityBinding,
        kin_db::InMemoryGraph,
    ) {
        let temp = tempfile::tempdir().unwrap();
        let layout = kin_core::init(temp.path()).unwrap().layout;
        let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(&layout).unwrap();
        let artifacts: Vec<_> = tree_paths
            .iter()
            .map(|path| {
                ResolvedArtifact::new(
                    ArtifactId::new(),
                    RepoPath::from_utf8((*path).to_string()).unwrap(),
                    TreeEntry::blob(Hash256::from_bytes([0x99; 32]), false),
                )
            })
            .collect();
        let mut snapshot = kin_db::GraphSnapshot::empty();
        snapshot.resolved_tree = ResolvedTree::from_artifacts(artifacts).unwrap();
        let graph = kin_db::InMemoryGraph::from_snapshot(snapshot).unwrap();
        (temp, layout, binding, graph)
    }

    fn orphan_line(response: &GraphCommandResponse) -> Option<&String> {
        response.lines.iter().find(|line| line.contains("orphaned"))
    }

    /// A file present in the working tree but absent from the graph's exact
    /// tree is still an orphan. Deciding orphan status by probing the working
    /// directory reports zero here, which is what this asserts against: the
    /// projection cannot vouch for an entity the graph does not carry.
    #[test]
    fn graph_validate_counts_orphans_absent_from_the_graph_tree_despite_the_file_on_disk() {
        let (_temp, layout, binding, graph) = orphan_fixture(&[]);
        let on_disk = layout.working_dir().join("src/present.rs");
        fs::create_dir_all(on_disk.parent().unwrap()).unwrap();
        fs::write(&on_disk, b"fn present() {}\n").unwrap();
        assert!(on_disk.exists(), "fixture must put the file on disk");

        let mut entity = test_entity("present");
        entity.file_origin = Some(FilePathId::new("src/present.rs"));
        graph.upsert_entity(&entity).unwrap();

        let response = build_graph_validate_response(&pinned(&binding), &graph).unwrap();

        let line = orphan_line(&response).expect("graph tree lacks the file, so it is orphaned");
        assert!(line.contains('1'), "{line}");
    }

    fn note_lines(response: &GraphCommandResponse) -> Vec<&String> {
        response
            .lines
            .iter()
            .filter(|line| line.starts_with('ℹ'))
            .collect()
    }

    /// The shape admission binds for a symbol another repository owns. Two of
    /// them differ only in the fingerprint derived from their import source and
    /// symbol, which is what makes that fingerprint the identity the duplicate
    /// check has to read.
    fn external_target_entity(name: &str, import_identity: u8) -> Entity {
        let mut entity = test_entity(name);
        entity.kind = EntityKind::Module;
        entity.role = EntityRole::External;
        entity.signature = String::new();
        entity.fingerprint.ast_hash = Hash256::from_bytes([import_identity; 32]);
        entity
    }

    fn duplicate_line(response: &GraphCommandResponse) -> Option<&String> {
        response
            .lines
            .iter()
            .find(|line| line.contains("duplicate"))
    }

    /// Two external targets naming one symbol through different import sources
    /// are two entities, and reporting them as one duplicated entity makes
    /// validate assert corruption against a graph Kin wrote correctly. The
    /// converse still has to hold: two entities that make the same claim about
    /// one external target are a real duplicate, and the check that stops
    /// false-positiving must not stop detecting.
    #[test]
    fn graph_validate_separates_distinct_external_targets_from_duplicated_ones() {
        let (_temp, _layout, binding, graph) = orphan_fixture(&["src/tracked.rs"]);
        graph
            .upsert_entity(&external_target_entity("info", 0x11))
            .unwrap();
        graph
            .upsert_entity(&external_target_entity("info", 0x22))
            .unwrap();

        let distinct = build_graph_validate_response(&pinned(&binding), &graph).unwrap();
        assert!(
            duplicate_line(&distinct).is_none(),
            "distinct import sources are distinct entities: {}",
            distinct.lines.join("\n")
        );

        // A third entity repeating the second one's claim: same name, same
        // import identity, its own entity id.
        graph
            .upsert_entity(&external_target_entity("info", 0x22))
            .unwrap();

        let duplicated = build_graph_validate_response(&pinned(&binding), &graph).unwrap();
        let line = duplicate_line(&duplicated)
            .expect("two entities claiming one external target is a duplicate");
        assert!(line.contains('1'), "{line}");
    }

    /// Notes describe a healthy graph rather than a defect, so a surface that
    /// keeps the verdict but drops them under-reports the repository's real
    /// state. Both graph surfaces read one health report, so both must render
    /// the same notes for the same state, and a reported issue must not
    /// suppress them.
    #[test]
    fn graph_validate_and_status_report_the_same_health_notes() {
        let (_temp, _layout, binding, graph) = orphan_fixture(&["src/tracked.rs"]);
        let mut entity = test_entity("covered");
        entity.role = EntityRole::Test;
        entity.file_origin = Some(FilePathId::new("src/tracked.rs"));
        graph.upsert_entity(&entity).unwrap();

        let validate = build_graph_validate_response(&pinned(&binding), &graph).unwrap();
        let status = build_graph_status_response(
            &pinned(&binding),
            &graph,
            &Default::default(),
            &Default::default(),
            &Default::default(),
        )
        .unwrap();

        let validate_notes = note_lines(&validate);
        assert!(
            !validate_notes.is_empty(),
            "validate must carry the health notes: {:?}",
            validate.lines
        );
        assert_eq!(
            validate_notes,
            note_lines(&status),
            "the two surfaces must not drift on note reporting"
        );
        assert!(
            validate.lines.iter().any(|line| line.starts_with('✗')),
            "this fixture also diverges, so notes are proven to survive a verdict: {:?}",
            validate.lines
        );
    }

    /// The converse: a file the graph's exact tree carries is not an orphan
    /// even though nothing was ever written to the working directory. Together
    /// with the test above this pins the authority — the filesystem is neither
    /// necessary nor sufficient to decide orphan status.
    #[test]
    fn graph_validate_clears_orphans_carried_by_the_graph_tree_with_no_file_on_disk() {
        let (_temp, layout, binding, graph) = orphan_fixture(&["src/tracked.rs"]);
        assert!(
            !layout.working_dir().join("src/tracked.rs").exists(),
            "fixture must leave the working tree empty"
        );

        let mut entity = test_entity("tracked");
        entity.file_origin = Some(FilePathId::new("src/tracked.rs"));
        graph.upsert_entity(&entity).unwrap();

        let response = build_graph_validate_response(&pinned(&binding), &graph).unwrap();

        assert!(
            orphan_line(&response).is_none(),
            "graph tree carries the file: {:?}",
            response.lines
        );
    }
}
