// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};
use kin_index::RelationResolution;
use kin_mcp::handlers::common::ReferenceLinesAbsent;
use kin_model::{Entity, EntityId, EntityStore, GraphNodeId, GraphStore, RelationKind};
use kin_ranking::entity_ranking;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::commands::declaration_neighbors;

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
pub struct RefsRequest {
    pub entity: String,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefsResponse {
    #[serde(default)]
    pub lines: Vec<String>,
    /// The absence verdict for an empty answer, in the fields `find_references`
    /// publishes over MCP.
    ///
    /// Rung three of FIR-2524, carrying the same contract
    /// `ImpactResponse::negative` already carries. The text surface renders this
    /// as a sentence and only when it refuses, because a person reading a
    /// terminal does not need to be told an answer is fine. A machine caller
    /// does: an empty reference list with no verdict beside it is a false clean
    /// at exit 0, and it is the shape a "safe to delete?" sweep acts on. This is
    /// the object the gate returned rather than a second opinion about it, so
    /// the CLI and the MCP tool cannot disagree about one store.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub negative: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkRefsRequest {
    pub entity_ids: Vec<String>,
    #[serde(default = "default_bulk_kind")]
    pub kind: String,
    #[serde(default = "default_bulk_compact")]
    pub compact: bool,
}

fn default_bulk_kind() -> String {
    "Any".to_string()
}

fn default_bulk_compact() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkRefsResponse {
    pub total_checked: usize,
    pub classified_count: usize,
    pub error_count: usize,
    pub incomplete_verdict_count: usize,
    pub with_references: usize,
    pub without_references: usize,
    #[serde(default)]
    pub relation_kinds: Vec<String>,
    pub compact: bool,
    #[serde(default)]
    pub results: Vec<serde_json::Value>,
}

pub async fn run(entity: String, kind: String) -> Result<()> {
    let layout = crate::commands::require_repository_layout()?;
    let _scope = announce_active_scope(&layout, "refs").await?;
    let response = run_daemon_refs(&layout, &RefsRequest { entity, kind }).await?;
    for line in response.lines {
        println!("{}", crate::output_style::paint_refs_line(&line));
    }
    Ok(())
}

pub async fn run_bulk(entities: String, kind: String, compact: bool) -> Result<()> {
    let layout = crate::commands::require_repository_layout()?;
    let _scope = announce_active_scope(&layout, "refs:bulk").await?;
    let entity_ids: Vec<String> = entities
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if entity_ids.is_empty() {
        anyhow::bail!("--entities must be a comma-separated list of one or more entity UUIDs");
    }
    let response = run_daemon_bulk_refs(
        &layout,
        &BulkRefsRequest {
            entity_ids,
            kind,
            compact,
        },
    )
    .await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

async fn run_daemon_refs(
    layout: &kin_core::KinLayout,
    request: &RefsRequest,
) -> Result<RefsResponse> {
    let daemon_url = std::env::var("KIN_DAEMON_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(Some)
        .unwrap_or(crate::daemon_client::resolve_daemon_url(layout).await?);
    let base_url =
        daemon_url.ok_or_else(|| crate::daemon_client::daemon_required_error("refs", layout))?;
    let client = crate::daemon_client::DaemonClient::from_base_url(base_url)?;
    client.refs(request).await.context("daemon refs failed")
}

async fn run_daemon_bulk_refs(
    layout: &kin_core::KinLayout,
    request: &BulkRefsRequest,
) -> Result<BulkRefsResponse> {
    let daemon_url = std::env::var("KIN_DAEMON_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(Some)
        .unwrap_or(crate::daemon_client::resolve_daemon_url(layout).await?);
    let base_url = daemon_url
        .ok_or_else(|| crate::daemon_client::daemon_required_error("bulk refs", layout))?;
    let client = crate::daemon_client::DaemonClient::from_base_url(base_url)?;
    client
        .bulk_refs(request)
        .await
        .context("daemon bulk refs failed")
}

pub fn build_refs_response(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    request: &RefsRequest,
    envelope: &kin_mcp::Envelope,
) -> Result<RefsResponse> {
    let relation_kinds = parse_relation_kinds(&request.kind)?;
    let addressed_by_id = uuid::Uuid::parse_str(request.entity.trim()).ok();
    let target = if let Some(uuid) = addressed_by_id {
        graph.get_entity(&EntityId(uuid))?
    } else {
        entity_ranking::select_best_entity(graph, &request.entity)?
    };
    // `None` means the focal was pinned by id, which is the rule the shared
    // producer switches on. Kept beside the resolution so the two cannot drift.
    let resolved_by_name = if addressed_by_id.is_some() {
        None
    } else {
        Some(request.entity.trim())
    };
    let Some(target) = target else {
        // Not an absence claim about references: the focal never resolved, so
        // nothing was walked and there is no coverage question to answer. A
        // verdict here would qualify a lookup failure as if it were a finding.
        return Ok(RefsResponse {
            lines: refs_not_found_guidance(&request.entity),
            negative: None,
        });
    };
    let target = &target;

    let refs = collect_references(graph, target, &relation_kinds)?;
    let target_path = target
        .file_origin
        .as_ref()
        .map(|f| display_read_path(layout, &f.0))
        .unwrap_or_else(|| "unknown".to_string());

    let mut lines = Vec::new();
    lines.push(format!(
        "References to '{}' -> {} ({:?}) @ {}",
        request.entity, target.name, target.kind, target_path
    ));

    if refs.is_empty() {
        lines.push(format!(
            "No incoming {} relations.",
            relation_kinds_label(&relation_kinds)
        ));
        // How the CALLER addressed the focal decides the ambiguity rule, and
        // taking it against the winner's own name is FIR-2475. `kin refs` takes
        // a uuid or a name, and `resolved_by_name` recorded which.
        let negative = refs_absence_verdict(
            graph,
            target,
            &relation_kinds,
            resolved_by_name,
            envelope,
        );
        lines.extend(refs_absence_qualifier(
            graph,
            target,
            &relation_kinds,
            resolved_by_name,
            envelope,
        ));
        let neighbors = declaration_neighbors::collect(graph, target, &relation_kinds)?;
        lines.extend(empty_result_context(target, &neighbors));
        return Ok(RefsResponse { lines, negative });
    }

    // FIR-1552. A receiver-method call the linker matched on the bare leaf name
    // is a candidate, not a caller: nothing at the reference site says the
    // receiver holds this type. Counting them beside real callers is what let
    // `find_references(HTTPAdapter.send)` answer 33 for a method two lines call.
    // The headline counts callers; the candidates get their own heading and
    // their own count.
    let (resolved, candidates): (Vec<ReferenceEntry>, Vec<ReferenceEntry>) = refs
        .into_iter()
        .partition(|entry| !entry.receiver_name_guess);

    let render = |lines: &mut Vec<String>, entry: &ReferenceEntry| {
        let file_path = entry
            .file_path
            .as_deref()
            .map(|path| display_read_path(layout, path))
            .unwrap_or_else(|| "unknown".to_string());
        let location = match entry.start_line {
            Some(line) => format!("{file_path}:{line}"),
            None => file_path,
        };
        lines.push(format!(
            "  {} @ {} [{}] ({}) {}",
            entry.name,
            location,
            relation_kinds_label(&entry.relation_kinds),
            entry.resolution.as_str(),
            reference_sites_label(&entry),
        ));
    };

    // FIR-2463. The count and the held rows are one reading, so they are printed
    // as one line. A reader who stops at "No resolved incoming calls relations."
    // and never reaches the candidates paragraph below has read a zero the same
    // response is contradicting, which is the shape that made an MCP
    // `total_upstream: 0` deletable while the one real caller sat in the payload
    // beside it.
    let unconfirmed = if candidates.is_empty() {
        String::new()
    } else {
        format!(
            ", plus {} unconfirmed candidate{} not in that count",
            candidates.len(),
            if candidates.len() == 1 { "" } else { "s" }
        )
    };
    if resolved.is_empty() {
        lines.push(format!(
            "No resolved incoming {} relations{unconfirmed}.",
            relation_kinds_label(&relation_kinds)
        ));
    } else {
        lines.push(format!(
            "referenced by {} entities{unconfirmed}:",
            resolved.len()
        ));
        for entry in &resolved {
            render(&mut lines, entry);
        }
    }

    if !candidates.is_empty() {
        lines.push(format!(
            "{} receiver-name candidate{} not counted above; each is a call through a \
             receiver whose type nothing at the reference site settles:",
            candidates.len(),
            if candidates.len() == 1 { "" } else { "s" }
        ));
        for entry in &candidates {
            render(&mut lines, entry);
        }
    }

    // No verdict on this path, and that is decided rather than skipped. The walk
    // returned rows, so there is no absence to qualify. That includes the
    // all-candidates case above: a receiver-name candidate is a reference the
    // graph does hold, disclosed on its own line with its own count (FIR-1552,
    // FIR-2463), so the reader is already being told the answer is not a clean
    // bill. Stamping a coverage verdict on a non-empty answer is the FIR-2404
    // failure in its opposite costume, which this rollout's positive control
    // exists to catch.
    Ok(RefsResponse {
        lines,
        negative: None,
    })
}

/// The reference sites of one entry, or the named reason it has none.
///
/// `start_line` locates the caller's definition and says nothing about where
/// inside it the reference is, which is what sent readers to grep for the line
/// they actually wanted (FIR-1825). These are the sites themselves, 1-based, in
/// the caller's own file.
///
/// An entry with no sites says which absence it is rather than printing an empty
/// list, using the same three names the MCP row carries under
/// `reference_lines_absent_reason`, so the two surfaces can be compared word for
/// word.
/// The machine-readable absence verdict for an empty `kin refs` answer.
///
/// A second call to the same pure gate the rendered sentence goes through, for
/// the reason `impact_absence_verdict` is: sharing an intermediate would put a
/// wording change one edit away from changing what an agent is told.
///
/// Emitted whether or not the verdict refuses, unlike the sentence. Silence is a
/// fine answer for a person and a missing field for a caller, and a missing
/// field is the shape that reads as a clean bill.
fn refs_absence_verdict(
    graph: &kin_db::InMemoryGraph,
    target: &Entity,
    relation_kinds: &[RelationKind],
    addressed_by_name: Option<&str>,
    envelope: &kin_mcp::Envelope,
) -> Option<serde_json::Value> {
    kin_mcp::negative::negative_for(
        "find_references",
        &refs_absence_payload(graph, target, relation_kinds, addressed_by_name),
        envelope,
        &[],
    )
}

/// The absence qualifier for an empty `kin refs` answer.
///
/// Thin on purpose: the observation is this command's own and the rendering is
/// shared, because CLI surfaces answering absence questions differently is the
/// defect rather than the implementation detail. See
/// [`crate::commands::absence_qualifier`].
fn refs_absence_qualifier(
    graph: &kin_db::InMemoryGraph,
    target: &Entity,
    relation_kinds: &[RelationKind],
    addressed_by_name: Option<&str>,
    envelope: &kin_mcp::Envelope,
) -> Vec<String> {
    crate::commands::absence_qualifier::qualify(
        "find_references",
        &refs_absence_payload(graph, target, relation_kinds, addressed_by_name),
        envelope,
        "",
    )
}

/// The observation `find_references`'s gate reads, scoped to the query this
/// command actually ran.
///
/// The scope is the one thing this call site must get right, and it is what
/// makes `find_references` different from the three tools rung one and rung two
/// wired up. Those declare the fixed reference triple; this one is gated on the
/// query's OWN `relation_kinds` (`kin_mcp::negative::absence_cross_file_classes`
/// reads that key and only falls back to the triple when a payload does not
/// report the scope it ran with). So `kin refs --kind calls` must be graded on
/// calls coverage alone. Handing over the default triple instead would refuse on
/// an absent class the query never asked about, and handing over nothing would
/// let a narrow query inherit a verdict only the union earned.
///
/// The coverage observation is taken over the same kinds for the same reason:
/// grading a walk against classes it did not traverse is the mismatch
/// `IMPACT_REFERENCE_KINDS` warns about one level down.
fn refs_absence_payload(
    graph: &kin_db::InMemoryGraph,
    target: &Entity,
    relation_kinds: &[RelationKind],
    addressed_by_name: Option<&str>,
) -> serde_json::Value {
    let coverage = kin_mcp::edge_coverage::observe_cross_file_reference_coverage_for_languages(
        graph,
        &[target.language],
        relation_kinds,
    );
    let mut payload = serde_json::json!({
        "references": [],
        "relation_kinds": relation_kinds
            .iter()
            .map(|kind| relation_kind_label(*kind))
            .collect::<Vec<_>>(),
        // `kin refs` reads one local store and queries no spine, so this is the
        // truthful value rather than a stub. It is also load-bearing: the gate
        // REFUSES a `find_references` absence whose payload reports no
        // cross-repo authority at all, and reporting none is a different claim
        // from reporting that none is configured.
        "cross_repo": { "status": "not_configured" },
        kin_mcp::EDGE_COVERAGE_KEY: coverage,
    });
    // Required, not optional. A payload with no `focal_resolution` is the
    // REFUSING arm of the gate rather than an exemption, so omitting it would
    // make every `kin refs` absence read uncertain for a reason that has nothing
    // to do with this store. Produced by the same function the MCP handler
    // calls, so the two surfaces count ambiguity by one rule (FIR-2475).
    if let Ok(resolution) = kin_mcp::handlers::entities::focal_resolution_for(
        graph,
        target,
        addressed_by_name,
    ) {
        payload["focal_resolution"] = resolution;
    }
    payload
}

fn reference_sites_label(entry: &ReferenceEntry) -> String {
    if entry.reference_lines.is_empty() {
        let reason = entry
            .reference_lines_absent
            .map(ReferenceLinesAbsent::as_str)
            .unwrap_or("unknown");
        return format!("sites none ({reason})");
    }
    let sites = entry
        .reference_lines
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",");
    format!("sites {sites}")
}

/// What the graph still says about a target whose incoming relations are empty.
///
/// An empty answer on a type declaration is true of that entity and misleading
/// about the repository: the references went to entities the declaration's name
/// qualifies, and Kin holds exactly which ones. Naming them turns "no callers"
/// into "these are the callers, one level down", and naming the same-name
/// identities resolution passed over says which node was actually answered for.
///
/// The listing is scoped by name and says so, because the graph ties a
/// declaration only to its same-file members. Claiming ownership instead would
/// tell a same-named declaration that another's members are its own.
///
/// An entity with neither members nor same-name siblings adds nothing here, so
/// it keeps the plain empty answer. That is what stops this note from becoming
/// noise that a reader learns to skip.
fn empty_result_context(
    target: &Entity,
    neighbors: &declaration_neighbors::DeclarationNeighbors,
) -> Vec<String> {
    let mut lines = Vec::new();

    let referenced: Vec<_> = neighbors.referenced_members().collect();
    if let Some(first) = referenced.first() {
        lines.push(format!(
            "{} entit{} named '{}::*' carr{} them:",
            referenced.len(),
            if referenced.len() == 1 { "y" } else { "ies" },
            target.name,
            if referenced.len() == 1 { "ies" } else { "y" },
        ));
        for member in referenced.iter().take(declaration_neighbors::MAX_LISTED) {
            lines.push(format!(
                "  {} @ {} [{} referencing {}]",
                member.name,
                member.location,
                member.referencing_entities,
                if member.referencing_entities == 1 {
                    "entity"
                } else {
                    "entities"
                },
            ));
        }
        if let Some(more) = declaration_neighbors::and_more_suffix(
            declaration_neighbors::MAX_LISTED,
            referenced.len(),
        ) {
            lines.push(format!("  {more}"));
        }
        lines.push(format!("  try: kin refs {}", first.name));
    }

    if !neighbors.siblings.is_empty() {
        lines.push(format!(
            "{} other graph identit{} the name '{}':",
            neighbors.siblings.len(),
            if neighbors.siblings.len() == 1 {
                "y carries"
            } else {
                "ies carry"
            },
            target.name
        ));
        for sibling in neighbors
            .siblings
            .iter()
            .take(declaration_neighbors::MAX_LISTED)
        {
            lines.push(format!(
                "  {} ({}) @ {}",
                sibling.name, sibling.kind, sibling.location
            ));
        }
        if let Some(more) = declaration_neighbors::and_more_suffix(
            declaration_neighbors::MAX_LISTED,
            neighbors.siblings.len(),
        ) {
            lines.push(format!("  {more}"));
        }
    }

    lines
}

/// Distinct entities that reference `entity_id` over the given relation kinds.
///
/// Counted through the same collector the listing is built from, so a count
/// reported beside a suggested `kin refs <member>` is the number that command
/// will print. A source id the graph carries an edge for but no entity record
/// for is still a distinct referencing identity, so it counts here; the ordinary
/// listing path fails loud on that same gap rather than reporting the row.
pub(crate) fn distinct_referencing_entities(
    graph: &impl GraphStore,
    entity_id: &EntityId,
    relation_kinds: &[RelationKind],
) -> Result<usize> {
    let collected = collect_graph_references(graph, entity_id, relation_kinds)?;
    Ok(collected.references.len() + collected.missing_source_ids.len())
}

/// Actionable guidance when `kin refs <symbol>` misses in the current repo's
/// graph.
///
/// `refs` resolves references within the CURRENT repo only. A symbol defined in
/// a sibling/dependency repo (e.g. a `kin-db` symbol queried from the `kin/`
/// graph) legitimately misses here. Rather than dead-ending on a bare
/// "Entity not found", keep the not-found signal but point the agent at the
/// cross-repo surface (`kin xref`) as the concrete next step.
///
/// We do not fabricate a cross-repo *existence* claim: confirming a symbol lives
/// in another repo requires the spine xref query, which is keyed by an entity id
/// we don't have on a local miss. So we hand off to `kin xref` (which performs
/// that lookup) instead of guessing.
fn refs_not_found_guidance(entity: &str) -> Vec<String> {
    let mut lines = vec![format!(
        "Entity '{}' not found in this repo's graph.",
        entity
    )];
    if uuid::Uuid::parse_str(entity.trim()).is_ok() {
        // A UUID miss can't be re-queried by name; xref resolves by symbol name.
        lines.push(
            "hint: `kin refs` resolves references within the current repo only. For a symbol \
             defined in a sibling/dependency repo, look it up cross-repo with `kin xref \
             <symbol-name>` (xref resolves by name)."
                .to_string(),
        );
    } else {
        lines
            .push("hint: `kin refs` resolves references within the current repo only.".to_string());
        lines.push(format!(
            "      If '{entity}' is defined in a sibling/dependency repo, look it up cross-repo:"
        ));
        lines.push(format!("        kin xref {entity}"));
    }
    lines
}

pub fn build_bulk_refs_response(
    graph: &kin_db::InMemoryGraph,
    request: &BulkRefsRequest,
) -> Result<BulkRefsResponse> {
    const MAX_BULK_ENTITIES: usize = 200;

    if request.entity_ids.is_empty() {
        anyhow::bail!("bulk_refs requires at least one entity_id");
    }
    if request.entity_ids.len() > MAX_BULK_ENTITIES {
        anyhow::bail!(
            "bulk_refs accepts at most {} entity_ids (got {})",
            MAX_BULK_ENTITIES,
            request.entity_ids.len()
        );
    }

    let relation_kinds = parse_bulk_relation_kind(&request.kind)?;
    let mut results = Vec::with_capacity(request.entity_ids.len());
    let mut with_references = 0usize;
    let mut without_references = 0usize;
    let mut error_count = 0usize;
    let mut incomplete_verdict_count = 0usize;

    for raw_id in &request.entity_ids {
        let parsed = uuid::Uuid::parse_str(raw_id.trim());
        let Ok(uuid) = parsed else {
            error_count += 1;
            results.push(bulk_refs_error_row(
                raw_id,
                "invalid entity_id (not a UUID)",
                request.compact,
            ));
            continue;
        };
        let entity_id = EntityId(uuid);
        let entity = graph.get_entity(&entity_id)?;
        let Some(entity) = entity else {
            error_count += 1;
            results.push(bulk_refs_error_row(
                raw_id,
                "entity not found",
                request.compact,
            ));
            continue;
        };

        // Bulk mode reports the same unit as the ordinary `kin refs` surface:
        // distinct referencing entities, not raw relation edges. One caller
        // may carry Calls, Imports, and References edges to the same target,
        // and ingestion may retain duplicate observations of an edge. Counting
        // those edges here made the compact answer disagree with the rows the
        // human-readable command could actually enumerate. Keep one grouping
        // authority for both paths so the count cannot drift again.
        let collected = collect_graph_references(graph, &entity_id, &relation_kinds)?;
        let matched_kinds = collected.matched_kinds;
        // Same split the human-readable surface prints, for the same reason
        // (FIR-1552): a bare-leaf receiver-method match is not evidence of use.
        // Reporting the total here while `kin refs` reported the caller count
        // would put two numbers for one target on two surfaces that share a
        // collector precisely so they cannot drift.
        let (resolved, receiver_name): (Vec<_>, Vec<_>) = collected
            .references
            .iter()
            .partition(|entry| !entry.receiver_name_guess);
        let reference_count = resolved.len();
        let receiver_name_candidate_count = receiver_name.len();

        if !collected.missing_source_ids.is_empty() {
            incomplete_verdict_count += 1;
            let missing_source_count = collected.missing_source_ids.len();
            let known_reference_count =
                reference_count + receiver_name_candidate_count + missing_source_count;
            let mut row = serde_json::json!({
                "entity_id": entity_id.to_string(),
                "has_references": null,
                "reference_count": null,
                "known_reference_count": known_reference_count,
                "reference_count_complete": false,
                "verdict_complete": false,
                "verdict_reason": format!(
                    "graph reference authority incomplete: {missing_source_count} incoming source entity record(s) missing"
                ),
                "missing_source_entity_count": missing_source_count,
            });
            if !request.compact {
                row["name"] = serde_json::json!(entity.name);
                row["kind"] = serde_json::json!(format!("{:?}", entity.kind));
                row["file_path"] =
                    serde_json::json!(entity.file_origin.as_ref().map(|p| p.0.clone()));
                row["matched_kinds"] = serde_json::json!(matched_kinds
                    .into_iter()
                    .map(relation_kind_label)
                    .collect::<Vec<_>>());
            }
            results.push(row);
            continue;
        }

        let has_references = reference_count > 0;
        if has_references {
            with_references += 1;
        } else {
            without_references += 1;
        }

        if request.compact {
            results.push(serde_json::json!({
                "entity_id": entity_id.to_string(),
                "has_references": has_references,
                "reference_count": reference_count,
                "receiver_name_candidate_count": receiver_name_candidate_count,
            }));
        } else {
            results.push(serde_json::json!({
                "entity_id": entity_id.to_string(),
                "name": entity.name,
                "kind": format!("{:?}", entity.kind),
                "file_path": entity.file_origin.as_ref().map(|p| p.0.clone()),
                "has_references": has_references,
                "reference_count": reference_count,
                "receiver_name_candidate_count": receiver_name_candidate_count,
                "matched_kinds": matched_kinds
                    .into_iter()
                    .map(relation_kind_label)
                    .collect::<Vec<_>>(),
            }));
        }
    }

    let total_checked = request.entity_ids.len();
    let classified_count = with_references + without_references;
    debug_assert_eq!(
        total_checked,
        classified_count + error_count + incomplete_verdict_count
    );
    Ok(BulkRefsResponse {
        total_checked,
        classified_count,
        error_count,
        incomplete_verdict_count,
        with_references,
        without_references,
        relation_kinds: relation_kinds
            .iter()
            .copied()
            .map(relation_kind_label)
            .collect(),
        compact: request.compact,
        results,
    })
}

fn bulk_refs_error_row(entity_id: &str, error: &str, compact: bool) -> serde_json::Value {
    let mut row = serde_json::json!({
        "entity_id": entity_id,
        "error": error,
        "has_references": null,
        "reference_count": null,
        "known_reference_count": null,
        "reference_count_complete": false,
        "verdict_complete": false,
    });
    if !compact {
        row["name"] = serde_json::Value::Null;
        row["kind"] = serde_json::Value::Null;
        row["file_path"] = serde_json::Value::Null;
        row["matched_kinds"] = serde_json::json!([]);
    }
    row
}

fn parse_bulk_relation_kind(value: &str) -> Result<Vec<RelationKind>> {
    match value.trim().to_ascii_lowercase().as_str() {
        "any" | "all" | "" => Ok(vec![
            RelationKind::Calls,
            RelationKind::Imports,
            RelationKind::References,
        ]),
        "calls" | "call" => Ok(vec![RelationKind::Calls]),
        "imports" | "import" => Ok(vec![RelationKind::Imports]),
        "references" | "reference" | "refs" => Ok(vec![RelationKind::References]),
        other => anyhow::bail!(
            "invalid --kind '{}': use Calls, Imports, References, or Any",
            other
        ),
    }
}

fn relation_kind_label(kind: RelationKind) -> String {
    match kind {
        RelationKind::Calls => "Calls",
        RelationKind::Imports => "Imports",
        RelationKind::References => "References",
        _ => "Other",
    }
    .to_string()
}

#[derive(Debug, Clone)]
pub(crate) struct ReferenceEntry {
    pub(crate) entity_id: EntityId,
    pub(crate) name: String,
    pub(crate) file_path: Option<String>,
    /// 1-based, as every `file:line` an agent pastes into an editor is.
    /// `None` for an entity the graph carries no span for, because reporting a
    /// line for one would be a fabricated position.
    start_line: Option<u32>,
    /// 1-based lines of the reference sites inside this caller, ascending and
    /// deduplicated. Read from the same relation evidence and through the same
    /// helper `find_references` uses, because two surfaces answering "where"
    /// from two rules is how they came to disagree about "how many" (FIR-2398).
    reference_lines: Vec<u32>,
    /// Why this entry has no sites, and `None` when it has some. Same three
    /// conditions the MCP row names, so a reader comparing the surfaces sees
    /// one vocabulary.
    reference_lines_absent: Option<ReferenceLinesAbsent>,
    pub(crate) relation_kinds: Vec<RelationKind>,
    /// Strongest resolution among the edges behind this row. A `name_only` row
    /// is a same-name match with nothing at the reference site proving it, so
    /// dead-code reads this to decide whether the row is evidence of use.
    pub(crate) resolution: RelationResolution,
    /// Whether EVERY edge behind this row is a receiver-method call matched on
    /// the bare leaf name. `resolution` reports the strongest contributing edge
    /// and cannot answer this: `name_only` also covers an exact-name match with
    /// one candidate, which is an ordinary cross-file call. Only the receiver
    /// fan-out is a candidate rather than a reference (FIR-1552).
    pub(crate) receiver_name_guess: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct ReferenceCollection {
    pub(crate) references: Vec<ReferenceEntry>,
    pub(crate) missing_source_ids: Vec<EntityId>,
    pub(crate) matched_kinds: Vec<RelationKind>,
}

/// Collect incoming references to `target` from graph-owned relation edges.
///
/// The graph is the sole authority for what references an entity. There is no
/// raw source-tree scan: a reference the graph does not carry is a
/// graph-completeness gap to close in ingestion, never something reconstructed
/// by walking and grepping the working tree at query time.
fn collect_references(
    graph: &impl GraphStore,
    target: &Entity,
    relation_kinds: &[RelationKind],
) -> Result<Vec<ReferenceEntry>> {
    let collected = collect_graph_references(graph, &target.id, relation_kinds)?;
    if !collected.missing_source_ids.is_empty() {
        let sample = collected
            .missing_source_ids
            .iter()
            .take(3)
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        anyhow::bail!(
            "graph reference authority incomplete for entity {}: {} incoming source entity \
             record(s) missing (sample: {})",
            target.id,
            collected.missing_source_ids.len(),
            sample
        );
    }
    let mut entries = collected.references;
    entries.sort_by(|left, right| {
        left.file_path
            .cmp(&right.file_path)
            .then_with(|| left.name.cmp(&right.name))
            .then_with(|| left.entity_id.cmp(&right.entity_id))
    });
    Ok(entries)
}

/// The one collector every reference-consulting surface reads.
///
/// `kin refs`, `kin refs --bulk-json` and the dead-code scan all answer from
/// this, because two lists of inbound edges are exactly what produced the
/// FIR-2356 contradiction: `find_references` named a caller for four entities
/// that `dead-code`, reading a different rule, called unreferenced at the same
/// graph generation.
pub(crate) fn collect_graph_references(
    graph: &impl GraphStore,
    entity_id: &EntityId,
    relation_kinds: &[RelationKind],
) -> Result<ReferenceCollection> {
    let allowed: std::collections::HashSet<_> = relation_kinds.iter().copied().collect();
    let mut grouped: HashMap<EntityId, Vec<RelationKind>> = HashMap::new();
    let mut resolutions: HashMap<EntityId, RelationResolution> = HashMap::new();
    let mut receiver_name_guesses: HashMap<EntityId, bool> = HashMap::new();
    // Edges kept per caller so the site tally can be taken once the caller's
    // own file is in hand: a span naming another file is not a line under this
    // row's path.
    let mut edges_by_caller: HashMap<EntityId, Vec<kin_model::relation::Relation>> = HashMap::new();
    let mut matched_kinds = Vec::new();

    for rel in graph.get_all_relations_for_entity(entity_id)? {
        if rel.dst != GraphNodeId::Entity(*entity_id) || !allowed.contains(&rel.kind) {
            continue;
        }
        let Some(src_entity_id) = rel.src.as_entity() else {
            continue;
        };
        // A recursive/self relation does not establish reachability from
        // another entity. Bulk refs has always excluded it for dead-code and
        // caller classification; keeping that rule in the shared collector
        // makes the ordinary and bulk surfaces agree without turning a
        // self-recursive orphan into a referenced entity.
        if src_entity_id == *entity_id {
            continue;
        }
        push_relation_kind(grouped.entry(src_entity_id).or_default(), rel.kind);
        push_relation_kind(&mut matched_kinds, rel.kind);
        let resolution = RelationResolution::of(&rel);
        resolutions
            .entry(src_entity_id)
            .and_modify(|current| *current = (*current).max(resolution))
            .or_insert(resolution);
        // Every contributing edge has to be a guess for the row to be one.
        let guess = kin_index::resolution::is_receiver_name_guess(&rel);
        receiver_name_guesses
            .entry(src_entity_id)
            .and_modify(|current| *current &= guess)
            .or_insert(guess);
        edges_by_caller.entry(src_entity_id).or_default().push(rel);
    }

    let mut references = Vec::with_capacity(grouped.len());
    let mut missing_source_ids = Vec::new();
    for (source_id, mut source_kinds) in grouped {
        source_kinds.sort_by_key(relation_kind_rank);
        let Some(entity) = graph.get_entity(&source_id)? else {
            missing_source_ids.push(source_id);
            continue;
        };
        let mut reference_lines = Vec::new();
        let mut spans_outside_caller_file = 0usize;
        for rel in edges_by_caller.get(&source_id).into_iter().flatten() {
            let tally = kin_mcp::handlers::common::relation_reference_lines(
                rel,
                entity.file_origin.as_ref(),
            );
            reference_lines.extend(tally.lines);
            spans_outside_caller_file += tally.outside_caller_file;
        }
        reference_lines.sort_unstable();
        reference_lines.dedup();
        let reference_lines_absent = if !reference_lines.is_empty() {
            None
        } else if spans_outside_caller_file > 0 {
            Some(ReferenceLinesAbsent::SpanOutsideCallerFile)
        } else {
            Some(ReferenceLinesAbsent::NoEvidenceSpan)
        };
        references.push(ReferenceEntry {
            entity_id: source_id,
            name: entity.name.clone(),
            file_path: entity.file_origin.as_ref().map(|f| f.0.clone()),
            start_line: kin_mcp::handlers::common::entity_presentation_start_line(&entity),
            reference_lines,
            reference_lines_absent,
            relation_kinds: source_kinds,
            resolution: resolutions
                .get(&source_id)
                .copied()
                .unwrap_or(RelationResolution::NameOnly),
            receiver_name_guess: receiver_name_guesses
                .get(&source_id)
                .copied()
                .unwrap_or(false),
        });
    }
    missing_source_ids.sort();
    matched_kinds.sort_by_key(relation_kind_rank);
    Ok(ReferenceCollection {
        references,
        missing_source_ids,
        matched_kinds,
    })
}

fn push_relation_kind(kinds: &mut Vec<RelationKind>, kind: RelationKind) {
    if !kinds.contains(&kind) {
        kinds.push(kind);
    }
}

fn parse_relation_kinds(kind: &str) -> Result<Vec<RelationKind>> {
    match kind.to_ascii_lowercase().as_str() {
        "all" => Ok(vec![
            RelationKind::Calls,
            RelationKind::Imports,
            RelationKind::References,
        ]),
        "calls" | "call" => Ok(vec![RelationKind::Calls]),
        "imports" | "import" => Ok(vec![RelationKind::Imports]),
        "references" | "refs" | "reference" => Ok(vec![RelationKind::References]),
        other => anyhow::bail!(
            "invalid --kind '{}': use one of all, calls, imports, references",
            other
        ),
    }
}

fn relation_kinds_label(kinds: &[RelationKind]) -> String {
    kinds
        .iter()
        .map(|kind| match kind {
            RelationKind::Calls => "Calls",
            RelationKind::Imports => "Imports",
            RelationKind::References => "References",
            _ => "Other",
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn relation_kind_rank(kind: &RelationKind) -> usize {
    entity_ranking::relation_kind_rank(kind)
}

fn display_read_path(_layout: &kin_core::KinLayout, rel_path: &str) -> String {
    rel_path.to_string()
}

#[cfg(test)]
mod tests {
    use super::{
        build_bulk_refs_response, build_refs_response, collect_graph_references,
        parse_relation_kinds, refs_not_found_guidance, BulkRefsRequest, BulkRefsResponse,
        ReferenceLinesAbsent, RefsRequest, RelationResolution,
    };


    /// THE SPINE (FIR-2524 rung three). A degraded daemon must make `kin refs`
    /// inherit the MCP verdict for that degradation.
    ///
    /// The same case that made rung one choose the expensive wiring. A thin
    /// envelope built from what the route knows locally carries no degraded
    /// signal, and under it the CLI would say nothing here while
    /// `find_references` refused on the same daemon at the same instant: the
    /// human surface more confident than the agent surface, which is the
    /// divergence this ticket exists to close, reintroduced by its own fix.
    ///
    /// It asserts INHERITANCE rather than wording: the same `negative_for` call
    /// on the same payload must reach the same `safe_to_conclude_absent`, and
    /// the rendered line must name the signal the verdict disclosed rather than
    /// inventing a cause.
    #[test]
    fn a_degraded_daemon_makes_the_refs_cli_inherit_the_mcp_verdict() {
        let (graph, layout, _dir) = orphan_fixture();
        let degraded = kin_mcp::Envelope::daemon().with_health(&serde_json::json!({
            "initialized": true,
            "graph_loaded": true,
            "graph_entity_count": 3,
            "graph_generation": 1,
            "embed_worker_failed": true,
        }));

        let response = build_refs_response(
            &layout,
            &graph,
            &RefsRequest {
                entity: "orphan".to_string(),
                kind: "all".to_string(),
            },
            &degraded,
        )
        .expect("refs response");
        let rendered = response.lines.join("\n");

        let verdict = response
            .negative
            .as_ref()
            .expect("an empty refs answer must carry a verdict");
        assert_eq!(
            verdict["safe_to_conclude_absent"],
            serde_json::json!(false),
            "the verdict must refuse on a degraded daemon, or this test asserts nothing: {verdict}"
        );
        assert!(
            rendered.contains("Kin cannot rule out references it did not see"),
            "the CLI must inherit the refusal and name ITS OWN noun, not impact's: {rendered}"
        );
        assert!(
            rendered.contains("embed_worker_failed") || rendered.contains("holds no cross-file"),
            "the line names what the verdict disclosed rather than inventing a cause: {rendered}"
        );
    }

    /// The machine half, byte for byte (FIR-2478 defect 2, FIR-2524).
    ///
    /// `--json` must carry the object the gate returned rather than a second
    /// opinion about it. A rendered sentence with no field beside it is still a
    /// false clean at exit 0 for anything parsing the payload.
    #[test]
    fn an_empty_refs_answer_carries_the_same_verdict_in_prose_and_in_the_payload() {
        let (graph, layout, _dir) = orphan_fixture();
        let degraded = kin_mcp::Envelope::daemon().with_health(&serde_json::json!({
            "initialized": true,
            "graph_loaded": true,
            "graph_entity_count": 3,
            "graph_generation": 1,
            "embed_worker_failed": true,
        }));
        let response = build_refs_response(
            &layout,
            &graph,
            &RefsRequest {
                entity: "orphan".to_string(),
                kind: "all".to_string(),
            },
            &degraded,
        )
        .expect("refs response");

        let target = kin_model::EntityStore::query_entities(
            &graph,
            &kin_model::graph::EntityFilter {
                name_pattern: Some("orphan".to_string()),
                ..Default::default()
            },
        )
        .unwrap()
        .into_iter()
        .next()
        .expect("focal");
        let kinds = parse_relation_kinds("all").unwrap();
        let mcp = kin_mcp::negative::negative_for(
            "find_references",
            &super::refs_absence_payload(&graph, &target, &kinds, Some("orphan")),
            &degraded,
            &[],
        );
        assert_eq!(
            response.negative, mcp,
            "the CLI field must BE the gate's object, not a recomputation of it"
        );
    }

    /// The noise control, and the arm that would catch this degrading into
    /// stamping every answer uncertain (the FIR-2404 failure in its opposite
    /// costume, which this rollout's own falsification list forbids).
    ///
    /// An answer holding rows is not an absence, so it carries no verdict and no
    /// sentence, even on a daemon degraded exactly as the spine's is.
    #[test]
    fn a_refs_answer_that_finds_rows_stays_unqualified_even_when_degraded() {
        use kin_model::relation::{Relation, RelationOrigin};
        use kin_model::{EntityStore, GraphNodeId};

        let (graph, layout, _dir) = orphan_fixture();
        let target = EntityStore::query_entities(
            &graph,
            &kin_model::graph::EntityFilter {
                name_pattern: Some("orphan".to_string()),
                ..Default::default()
            },
        )
        .unwrap()
        .into_iter()
        .next()
        .expect("focal");
        let caller = EntityStore::query_entities(
            &graph,
            &kin_model::graph::EntityFilter {
                name_pattern: Some("caller".to_string()),
                ..Default::default()
            },
        )
        .unwrap()
        .into_iter()
        .next()
        .expect("caller");
        graph
            .upsert_relation(&Relation {
                id: kin_model::ids::RelationId::new(),
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

        let degraded = kin_mcp::Envelope::daemon().with_health(&serde_json::json!({
            "initialized": true,
            "graph_loaded": true,
            "graph_entity_count": 3,
            "graph_generation": 1,
            "embed_worker_failed": true,
        }));
        let response = build_refs_response(
            &layout,
            &graph,
            &RefsRequest {
                entity: "orphan".to_string(),
                kind: "all".to_string(),
            },
            &degraded,
        )
        .expect("refs response");
        let rendered = response.lines.join("\n");

        assert!(
            response.negative.is_none(),
            "a populated answer is not an absence and carries no verdict: {:?}",
            response.negative
        );
        assert!(
            !rendered.contains("Kin cannot rule out"),
            "a populated answer must stay unqualified, however degraded the daemon: {rendered}"
        );
    }

    /// A focal that never resolved is a lookup failure, not a finding, so it
    /// carries no verdict. Qualifying it would tell a reader their graph lacks
    /// coverage when what it lacks is the name they typed.
    #[test]
    fn an_unresolved_focal_carries_no_absence_verdict() {
        let (graph, layout, _dir) = orphan_fixture();
        let response = build_refs_response(
            &layout,
            &graph,
            &RefsRequest {
                entity: "no_such_symbol_anywhere".to_string(),
                kind: "all".to_string(),
            },
            &refs_test_envelope(),
        )
        .expect("refs response");
        assert!(response.negative.is_none());
        assert!(!response.lines.join("\n").contains("Kin cannot rule out"));
    }

    /// A three-entity fixture whose focal has no incoming edges, with a
    /// same-file neighbour so the coverage observation has something to read.
    fn orphan_fixture() -> (kin_db::InMemoryGraph, kin_core::KinLayout, tempfile::TempDir) {
        use kin_model::{
            Entity, EntityId, EntityKind, EntityMetadata, EntityRole, EntityStore, FilePathId,
            FingerprintAlgorithm, Hash256, LanguageId, SemanticFingerprint, Visibility,
        };

        fn entity(name: &str, rel_path: &str) -> Entity {
            Entity {
                id: EntityId::new(),
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
                file_origin: Some(FilePathId::new(rel_path)),
                span: None,
                signature: name.to_string(),
                visibility: Visibility::Public,
                role: EntityRole::Source,
                doc_summary: None,
                metadata: EntityMetadata::default(),
                lineage_parent: None,
                created_in: None,
                superseded_by: None,
            }
        }

        let graph = kin_db::InMemoryGraph::new();
        for (name, path) in [
            ("orphan", "src/orphan.rs"),
            ("caller", "src/a.rs"),
            ("callee", "src/b.rs"),
        ] {
            let e = entity(name, path);
            EntityStore::upsert_entity(&graph, &e).unwrap();
        }
        let dir = tempfile::tempdir().unwrap();
        let layout = kin_core::KinLayout::new(dir.path().join(".kin"));
        (graph, layout, dir)
    }

    /// A substrate in good health, so a test asserting refs CONTENT is not also
    /// asserting the absence verdict. The refusing direction gets its own tests.
    fn refs_test_envelope() -> kin_mcp::Envelope {
        kin_mcp::Envelope::daemon().with_health(&serde_json::json!({
            "initialized": true,
            "graph_loaded": true,
            "graph_entity_count": 4,
            "graph_generation": 1,
        }))
    }
    use kin_model::RelationKind;

    /// FIR-1552. The bulk row and the printed answer read one collector so their
    /// numbers cannot drift, and a bare-leaf receiver-method match is not
    /// evidence of use on either. Two real callers and three receiver-name
    /// candidates give a row of `reference_count: 2` beside
    /// `receiver_name_candidate_count: 3`, never a single `5`.
    #[test]
    fn bulk_refs_counts_resolved_callers_and_names_the_candidates_apart() {
        use kin_db::InMemoryGraph;
        use kin_model::relation::{Relation, RelationOrigin};
        use kin_model::{
            Entity, EntityId, EntityKind, EntityMetadata, EntityRole, EntityStore, FilePathId,
            FingerprintAlgorithm, GraphNodeId, Hash256, LanguageId, SemanticFingerprint,
            Visibility,
        };

        fn entity(name: &str, rel_path: &str) -> Entity {
            Entity {
                id: EntityId::new(),
                kind: EntityKind::Function,
                name: name.to_string(),
                language: LanguageId::Rust,
                fingerprint: SemanticFingerprint {
                    algorithm: FingerprintAlgorithm::V1TreeSitter,
                    ast_hash: Hash256::from_bytes([0; 32]),
                    signature_hash: Hash256::from_bytes([0; 32]),
                    behavior_hash: Hash256::from_bytes([0; 32]),
                    equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
                    stability_score: 1.0,
                },
                file_origin: Some(FilePathId::new(rel_path)),
                span: None,
                signature: name.to_string(),
                visibility: Visibility::Public,
                role: EntityRole::Source,
                doc_summary: None,
                metadata: EntityMetadata::default(),
                lineage_parent: None,
                created_in: None,
                superseded_by: None,
            }
        }

        let graph = InMemoryGraph::new();
        let target = entity("send", "src/adapters.rs");
        graph.upsert_entity(&target).unwrap();
        // Two parser-certain callers and three receiver-method guesses, so the
        // fixture cannot pass on numbers that happen to coincide.
        for (index, name) in ["proven_a", "proven_b", "guess_a", "guess_b", "guess_c"]
            .iter()
            .enumerate()
        {
            let caller = entity(name, "src/callers.rs");
            graph.upsert_entity(&caller).unwrap();
            graph
                .upsert_relation(&Relation {
                    id: kin_model::ids::RelationId::new(),
                    kind: RelationKind::Calls,
                    src: GraphNodeId::Entity(caller.id),
                    dst: GraphNodeId::Entity(target.id),
                    confidence: if index < 2 {
                        1.0
                    } else {
                        kin_index::resolution::RECEIVER_NAME_FANOUT_CONFIDENCE
                    },
                    origin: RelationOrigin::Parsed,
                    created_in: None,
                    import_source: None,
                    evidence: Vec::new(),
                })
                .unwrap();
        }

        let response = build_bulk_refs_response(
            &graph,
            &BulkRefsRequest {
                entity_ids: vec![target.id.to_string()],
                kind: "calls".to_string(),
                compact: true,
            },
        )
        .unwrap();
        let row = &response.results[0];
        assert_eq!(row["reference_count"], 2, "{row}");
        assert_eq!(row["receiver_name_candidate_count"], 3, "{row}");
        assert_eq!(row["has_references"], true, "{row}");
        assert_eq!(response.with_references, 1);
    }

    /// A language-server edge reaches the reference surface as a RESOLVED
    /// caller, and a same-named bare-name guess beside it does not.
    ///
    /// This is the last hop of FIR-2464. The daemon now wires JavaScript and
    /// TypeScript and starts a server for them, and the enrichment layer is
    /// proved against real servers in
    /// `crates/kin-daemon/tests/lsp_reference_enrichment.rs`. What that proof
    /// does not reach is what `find_references` and `kin refs` DO with the
    /// resulting edge, which is what an agent actually reads. Both rows are
    /// built here from one graph so the difference is the edge rather than the
    /// fixture.
    ///
    /// It also pins a gap rather than papering over it. kin-lsp constructs
    /// every enrichment relation with `evidence: Vec::new()`
    /// (kin-lsp/src/enrichment.rs:218, :320, :426, :503), so an LSP-resolved
    /// caller arrives with no source span and its `reference_lines` come back
    /// empty with `NoEvidenceSpan`. The row is honest about that rather than
    /// silent, and this assertion is what will fail, loudly and in the right
    /// place, on the day kin-lsp starts populating spans.
    #[test]
    fn an_lsp_edge_reaches_the_reference_surface_as_resolved_and_a_name_guess_does_not() {
        use kin_db::InMemoryGraph;
        use kin_model::relation::{Relation, RelationOrigin};
        use kin_model::{
            Entity, EntityId, EntityKind, EntityMetadata, EntityRole, EntityStore, FilePathId,
            FingerprintAlgorithm, GraphNodeId, Hash256, LanguageId, SemanticFingerprint,
            Visibility,
        };

        fn entity(name: &str, rel_path: &str) -> Entity {
            Entity {
                id: EntityId::new(),
                kind: EntityKind::Function,
                name: name.to_string(),
                language: LanguageId::JavaScript,
                fingerprint: SemanticFingerprint {
                    algorithm: FingerprintAlgorithm::V1TreeSitter,
                    ast_hash: Hash256::from_bytes([0; 32]),
                    signature_hash: Hash256::from_bytes([0; 32]),
                    behavior_hash: Hash256::from_bytes([0; 32]),
                    equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
                    stability_score: 1.0,
                },
                file_origin: Some(FilePathId::new(rel_path)),
                span: None,
                signature: name.to_string(),
                visibility: Visibility::Public,
                role: EntityRole::Source,
                doc_summary: None,
                metadata: EntityMetadata::default(),
                lineage_parent: None,
                created_in: None,
                superseded_by: None,
            }
        }

        let graph = InMemoryGraph::new();
        let target = entity("handle", "lib/router.js");
        graph.upsert_entity(&target).unwrap();

        // The caller a language server resolved: origin Lsp.
        let resolved_caller = entity("listen", "lib/app.js");
        graph.upsert_entity(&resolved_caller).unwrap();
        graph
            .upsert_relation(&Relation {
                id: kin_model::ids::RelationId::new(),
                kind: RelationKind::Calls,
                src: GraphNodeId::Entity(resolved_caller.id),
                dst: GraphNodeId::Entity(target.id),
                confidence: 0.95,
                origin: RelationOrigin::Lsp,
                created_in: None,
                import_source: None,
                evidence: Vec::new(),
            })
            .unwrap();

        // The caller the bare-name fallback produced: a receiver-method guess.
        let guessed_caller = entity("dispatch", "lib/other.js");
        graph.upsert_entity(&guessed_caller).unwrap();
        graph
            .upsert_relation(&Relation {
                id: kin_model::ids::RelationId::new(),
                kind: RelationKind::Calls,
                src: GraphNodeId::Entity(guessed_caller.id),
                dst: GraphNodeId::Entity(target.id),
                confidence: kin_index::resolution::RECEIVER_NAME_FANOUT_CONFIDENCE,
                origin: RelationOrigin::Parsed,
                created_in: None,
                import_source: None,
                evidence: Vec::new(),
            })
            .unwrap();

        let collected =
            collect_graph_references(&graph, &target.id, &[RelationKind::Calls]).unwrap();

        let resolved = collected
            .references
            .iter()
            .find(|entry| entry.entity_id == resolved_caller.id)
            .expect("the language-server caller must appear");
        assert_eq!(
            resolved.resolution,
            RelationResolution::TypeResolved,
            "an Lsp-origin edge must reach the reference surface as type_resolved"
        );
        assert!(
            resolved.resolution.is_proven(),
            "a type_resolved caller must be countable as evidence of use"
        );
        assert!(
            !resolved.receiver_name_guess,
            "a language-server edge is not a receiver-name guess"
        );
        // The gap named above, asserted rather than assumed. Delete this pair
        // and assert real line numbers on the day kin-lsp carries spans.
        assert!(
            resolved.reference_lines.is_empty(),
            "kin-lsp emits no evidence span today; if this now has lines, the surrounding \
             doc comment and the FIR-2464 report are out of date"
        );
        assert_eq!(
            resolved.reference_lines_absent,
            Some(ReferenceLinesAbsent::NoEvidenceSpan),
            "an absent line list must say WHY it is absent rather than reading as no evidence"
        );

        let guessed = collected
            .references
            .iter()
            .find(|entry| entry.entity_id == guessed_caller.id)
            .expect("the guessed caller must still appear, marked");
        assert_eq!(
            guessed.resolution,
            RelationResolution::NameOnly,
            "a receiver-name fan-out edge stays a candidate"
        );
        assert!(
            !guessed.resolution.is_proven(),
            "a name-only caller must not be countable as evidence of use"
        );
        assert!(guessed.receiver_name_guess);
    }

    /// `kin refs` must answer only from graph-owned relation edges. A reference
    /// that exists in the working tree but is not linked into the graph must
    /// never be surfaced, because there is no raw source-tree scan fallback: the
    /// retired scan walked the source root and matched import/call lines, which
    /// is exactly the file-first drift the graph-first thesis forbids.
    #[test]
    fn refs_answer_comes_from_graph_relations_not_source_tree_scan() {
        use kin_db::InMemoryGraph;
        use kin_model::relation::{Relation, RelationOrigin};
        use kin_model::{
            Entity, EntityId, EntityKind, EntityMetadata, EntityRole, EntityStore, FilePathId,
            FingerprintAlgorithm, GraphNodeId, Hash256, LanguageId, SemanticFingerprint,
            Visibility,
        };

        fn entity(name: &str, rel_path: &str) -> Entity {
            Entity {
                id: EntityId::new(),
                kind: EntityKind::Function,
                name: name.to_string(),
                language: LanguageId::Rust,
                fingerprint: SemanticFingerprint {
                    algorithm: FingerprintAlgorithm::V1TreeSitter,
                    ast_hash: Hash256::from_bytes([0; 32]),
                    signature_hash: Hash256::from_bytes([0; 32]),
                    behavior_hash: Hash256::from_bytes([0; 32]),
                    equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
                    stability_score: 1.0,
                },
                file_origin: Some(FilePathId::new(rel_path)),
                span: None,
                signature: name.to_string(),
                visibility: Visibility::Public,
                role: EntityRole::Source,
                doc_summary: None,
                metadata: EntityMetadata::default(),
                lineage_parent: None,
                created_in: None,
                superseded_by: None,
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        std::fs::create_dir_all(repo.join(".kin")).unwrap();
        let layout = kin_core::KinLayout::new(repo.join(".kin"));

        // A caller that exists ONLY in the working tree, never linked into the
        // graph. The retired text scan would have surfaced it by matching the
        // `use ...::probe_symbol` import line under the source root.
        std::fs::write(
            repo.join("disk_only_caller.rs"),
            "use crate::target_mod::probe_symbol;\npub fn disk_only() -> i32 { probe_symbol() }\n",
        )
        .unwrap();

        let target = entity("probe_symbol", "target_mod.rs");
        let graph_caller = entity("graph_caller", "graph_caller.rs");

        let graph = InMemoryGraph::new();
        graph.upsert_entity(&target).unwrap();
        graph.upsert_entity(&graph_caller).unwrap();
        graph
            .upsert_relation(&Relation {
                id: kin_model::ids::RelationId::new(),
                kind: RelationKind::References,
                src: GraphNodeId::Entity(graph_caller.id),
                dst: GraphNodeId::Entity(target.id),
                confidence: 1.0,
                origin: RelationOrigin::Parsed,
                created_in: None,
                import_source: None,
                evidence: Vec::new(),
            })
            .unwrap();

        let response = build_refs_response(
            &layout,
            &graph,
            &RefsRequest {
                entity: "probe_symbol".to_string(),
                kind: "all".to_string(),
            },
        &refs_test_envelope(),
        )
        .unwrap();
        let joined = response.lines.join("\n");

        // The graph-linked reference is reported...
        assert!(
            joined.contains("graph_caller"),
            "graph-owned reference must be reported: {joined}"
        );
        // ...and the working-tree-only reference is not, proving refs no longer
        // answers by scanning the raw source tree.
        assert!(
            !joined.contains("disk_only"),
            "refs must not surface a reference that exists only in the working tree: {joined}"
        );
    }

    #[test]
    fn refs_not_found_guidance_keeps_signal_and_points_at_xref() {
        let lines = refs_not_found_guidance("load_vector_index_into_graph_if_valid");
        // Not-found signal preserved (don't silently swallow the miss).
        assert!(
            lines[0].contains("not found"),
            "first line keeps the not-found signal: {:?}",
            lines
        );
        let joined = lines.join("\n");
        // Actionable next step: the cross-repo surface, with a runnable command.
        assert!(
            joined.contains("kin xref"),
            "should point at xref: {joined}"
        );
        assert!(
            joined.contains("kin xref load_vector_index_into_graph_if_valid"),
            "should include a runnable cross-repo command: {joined}"
        );
    }

    #[test]
    fn refs_not_found_guidance_handles_uuid_query() {
        let uuid = "00000000-0000-0000-0000-000000000000";
        let lines = refs_not_found_guidance(uuid);
        let joined = lines.join("\n");
        assert!(lines[0].contains("not found"));
        // A UUID can't be re-queried by name, so guide toward xref by symbol name
        // rather than emitting `kin xref <uuid>`.
        assert!(joined.contains("kin xref"), "should mention xref: {joined}");
        assert!(
            !joined.contains(&format!("kin xref {uuid}")),
            "should not suggest `kin xref <uuid>`: {joined}"
        );
    }

    #[test]
    fn parse_relation_kinds_defaults_to_all_reference_types() {
        let kinds = parse_relation_kinds("all").unwrap();
        assert_eq!(
            kinds,
            vec![
                RelationKind::Calls,
                RelationKind::Imports,
                RelationKind::References
            ]
        );
    }

    /// `kin refs` and MCP `find_references` must return the same number for the
    /// same entity on the same graph.
    ///
    /// They did not. The CLI counts distinct referencing entities; the MCP tool
    /// keyed its rows on the caller's FILE path and so counted distinct files,
    /// which is FIR-2398. Two surfaces answering one question with two numbers
    /// is worse than either being wrong alone, because whichever an agent read
    /// looked internally consistent.
    ///
    /// The fixture is built so the two counts cannot coincide by luck: three
    /// callers share one file, a fourth sits in another, and the target also
    /// calls itself. Under the old rule the MCP tool saw three keys
    /// (two caller files plus the target's own, from the self edge) against the
    /// CLI's four entities, so a regression separates them again.
    #[tokio::test]
    async fn cli_refs_and_mcp_find_references_agree_on_the_caller_count() {
        use kin_db::InMemoryGraph;
        use kin_model::relation::{Relation, RelationOrigin};
        use kin_model::{
            Entity, EntityId, EntityKind, EntityMetadata, EntityRole, EntityStore, FilePathId,
            FingerprintAlgorithm, GraphNodeId, Hash256, LanguageId, SemanticFingerprint,
            Visibility,
        };

        fn entity(name: &str, rel_path: &str) -> Entity {
            Entity {
                id: EntityId::new(),
                kind: EntityKind::Function,
                name: name.to_string(),
                language: LanguageId::Rust,
                fingerprint: SemanticFingerprint {
                    algorithm: FingerprintAlgorithm::V1TreeSitter,
                    ast_hash: Hash256::from_bytes([0; 32]),
                    signature_hash: Hash256::from_bytes([0; 32]),
                    behavior_hash: Hash256::from_bytes([0; 32]),
                    equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
                    stability_score: 1.0,
                },
                file_origin: Some(FilePathId::new(rel_path)),
                span: None,
                signature: name.to_string(),
                visibility: Visibility::Public,
                role: EntityRole::Source,
                doc_summary: None,
                metadata: EntityMetadata::default(),
                lineage_parent: None,
                created_in: None,
                superseded_by: None,
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let layout = kin_core::KinLayout::new(dir.path().join(".kin"));
        let graph = InMemoryGraph::new();

        let target = entity("to_dot", "linkgraph.rs");
        let callers = [
            entity("draws_nodes", "test_linkgraph.rs"),
            entity("draws_edges", "test_linkgraph.rs"),
            entity("draws_dashed", "test_linkgraph.rs"),
            entity("cmd_graph", "cli.rs"),
        ];
        graph.upsert_entity(&target).unwrap();

        let edge = |src: EntityId, dst: EntityId| {
            graph
                .upsert_relation(&Relation {
                    id: kin_model::ids::RelationId::new(),
                    kind: RelationKind::Calls,
                    src: GraphNodeId::Entity(src),
                    dst: GraphNodeId::Entity(dst),
                    confidence: 1.0,
                    origin: RelationOrigin::Parsed,
                    created_in: None,
                    import_source: None,
                    evidence: Vec::new(),
                })
                .unwrap();
        };
        for caller in &callers {
            graph.upsert_entity(caller).unwrap();
            edge(caller.id, target.id);
        }
        // Recursive: an upstream caller on neither surface.
        edge(target.id, target.id);

        let cli = build_refs_response(
            &layout,
            &graph,
            &RefsRequest {
                entity: target.id.to_string(),
                kind: "calls".to_string(),
            },
        &refs_test_envelope(),
        )
        .unwrap();
        let cli_text = cli.lines.join("\n");

        let args = std::collections::HashMap::from([
            (
                "entity_id".to_string(),
                serde_json::json!(target.id.to_string()),
            ),
            ("relation_kinds".to_string(), serde_json::json!(["calls"])),
        ]);
        let mcp = kin_mcp::handlers::entities::handle_find_references(&args, &graph, None)
            .await
            .unwrap();
        let kin_mcp::types::ContentBlock::Text { text } = mcp.content.first().unwrap();
        let mcp_body: serde_json::Value = serde_json::from_str(text).unwrap();
        let mcp_count = mcp_body["total_upstream"].as_u64().unwrap();

        // Absolute value first: two surfaces agreeing on a wrong number is not
        // agreement, and this is the assertion that catches both regressing the
        // same way.
        assert_eq!(
            mcp_count, 4,
            "four callers, whichever files they share: {mcp_body:#}"
        );
        assert!(
            cli_text.contains("referenced by 4 entities:"),
            "the CLI must count the same four: {cli_text}"
        );
        assert_eq!(
            mcp_body["counts"]["counted"], "referencing_entities",
            "the agreed count must name its unit: {mcp_body:#}"
        );
        // Non-vacuity: the file count is genuinely different, so the assertions
        // above are not passing because every number in the fixture is 4.
        assert_eq!(
            mcp_body["counts"]["files"], 2,
            "the fixture must span fewer files than callers: {mcp_body:#}"
        );

        // Row for row, not just in total: every caller the CLI names is a row
        // the MCP tool returned, by entity id.
        let mcp_ids = mcp_body["references"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["entity_id"].as_str().unwrap().to_string())
            .collect::<std::collections::BTreeSet<_>>();
        for caller in &callers {
            assert!(
                mcp_ids.contains(&caller.id.to_string()),
                "MCP dropped caller {}: {mcp_body:#}",
                caller.name
            );
            assert!(
                cli_text.contains(&caller.name),
                "the CLI dropped caller {}: {cli_text}",
                caller.name
            );
        }
        assert!(
            !mcp_ids.contains(&target.id.to_string()),
            "the recursive edge must not be reported as a caller: {mcp_body:#}"
        );
    }

    #[test]
    fn parse_relation_kinds_accepts_import_alias() {
        let kinds = parse_relation_kinds("import").unwrap();
        assert_eq!(kinds, vec![RelationKind::Imports]);
    }

    /// Distinct entity ids are distinct callers even when their display
    /// metadata is identical. Duplicate/multi-kind edges from one caller enrich
    /// that caller's row, and self-edges do not establish external reachability.
    #[test]
    fn refs_and_bulk_count_distinct_external_entities_not_relation_edges_or_self_edges() {
        use kin_db::InMemoryGraph;
        use kin_model::relation::{Relation, RelationOrigin};
        use kin_model::{
            Entity, EntityId, EntityKind, EntityMetadata, EntityRole, EntityStore, FilePathId,
            FingerprintAlgorithm, GraphNodeId, Hash256, LanguageId, SemanticFingerprint,
            Visibility,
        };

        fn entity(name: &str, rel_path: &str) -> Entity {
            Entity {
                id: EntityId::new(),
                kind: EntityKind::Function,
                name: name.to_string(),
                language: LanguageId::Rust,
                fingerprint: SemanticFingerprint {
                    algorithm: FingerprintAlgorithm::V1TreeSitter,
                    ast_hash: Hash256::from_bytes([0; 32]),
                    signature_hash: Hash256::from_bytes([0; 32]),
                    behavior_hash: Hash256::from_bytes([0; 32]),
                    equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
                    stability_score: 1.0,
                },
                file_origin: Some(FilePathId::new(rel_path)),
                span: None,
                signature: name.to_string(),
                visibility: Visibility::Public,
                role: EntityRole::Source,
                doc_summary: None,
                metadata: EntityMetadata::default(),
                lineage_parent: None,
                created_in: None,
                superseded_by: None,
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let layout = kin_core::KinLayout::new(dir.path().join(".kin"));

        let target = entity("probe_symbol", "target_mod.rs");
        // Same file and same name are deliberate: display metadata cannot be
        // the grouping key. These remain two semantic entities by id.
        let caller_a = entity("shared_caller", "callers.rs");
        let caller_b = entity("shared_caller", "callers.rs");

        let graph = InMemoryGraph::new();
        for e in [&target, &caller_a, &caller_b] {
            graph.upsert_entity(e).unwrap();
        }
        for caller in [&caller_a, &caller_b] {
            graph
                .upsert_relation(&Relation {
                    id: kin_model::ids::RelationId::new(),
                    kind: RelationKind::References,
                    src: GraphNodeId::Entity(caller.id),
                    dst: GraphNodeId::Entity(target.id),
                    confidence: 1.0,
                    origin: RelationOrigin::Parsed,
                    created_in: None,
                    import_source: None,
                    evidence: Vec::new(),
                })
                .unwrap();
        }
        // The same caller can carry multiple graph-owned observations of the
        // target. They enrich its row; they do not create more callers.
        for kind in [RelationKind::References, RelationKind::Calls] {
            graph
                .upsert_relation(&Relation {
                    id: kin_model::ids::RelationId::new(),
                    kind,
                    src: GraphNodeId::Entity(caller_a.id),
                    dst: GraphNodeId::Entity(target.id),
                    confidence: 1.0,
                    origin: RelationOrigin::Parsed,
                    created_in: None,
                    import_source: None,
                    evidence: Vec::new(),
                })
                .unwrap();
        }
        // A recursive-only edge does not make the target reachable from some
        // other entity and must not affect either count or matched_kinds.
        for kind in [
            RelationKind::Calls,
            RelationKind::Imports,
            RelationKind::References,
        ] {
            graph
                .upsert_relation(&Relation {
                    id: kin_model::ids::RelationId::new(),
                    kind,
                    src: GraphNodeId::Entity(target.id),
                    dst: GraphNodeId::Entity(target.id),
                    confidence: 1.0,
                    origin: RelationOrigin::Parsed,
                    created_in: None,
                    import_source: None,
                    evidence: Vec::new(),
                })
                .unwrap();
        }

        let response = build_refs_response(
            &layout,
            &graph,
            &RefsRequest {
                entity: "probe_symbol".to_string(),
                kind: "all".to_string(),
            },
        &refs_test_envelope(),
        )
        .unwrap();
        let joined = response.lines.join("\n");

        assert!(
            joined.contains("referenced by 2 entities:"),
            "count line must count entities: {joined}"
        );
        assert!(
            joined.matches("shared_caller @ callers.rs [").count() == 2,
            "both same-metadata entity ids must be listed separately: {joined}"
        );

        let compact = build_bulk_refs_response(
            &graph,
            &BulkRefsRequest {
                entity_ids: vec![target.id.to_string()],
                kind: "Any".to_string(),
                compact: true,
            },
        )
        .unwrap();
        assert_eq!(compact.classified_count, 1);
        assert_eq!(compact.error_count, 0);
        assert_eq!(compact.incomplete_verdict_count, 0);
        assert_eq!(compact.with_references, 1);
        assert_eq!(compact.without_references, 0);
        assert_eq!(compact.results[0]["reference_count"], 2);
        assert_eq!(compact.results[0]["has_references"], true);
        assert_eq!(compact.results[0]["entity_id"], target.id.to_string());
        assert!(compact.results[0].get("matched_kinds").is_none());
        assert!(compact.results[0].get("name").is_none());

        let verbose = build_bulk_refs_response(
            &graph,
            &BulkRefsRequest {
                entity_ids: vec![target.id.to_string()],
                kind: "Any".to_string(),
                compact: false,
            },
        )
        .unwrap();
        assert_eq!(verbose.results[0]["reference_count"], 2);
        assert_eq!(verbose.results[0]["has_references"], true);
        assert_eq!(verbose.results[0]["entity_id"], target.id.to_string());
        assert_eq!(verbose.results[0]["name"], "probe_symbol");
        assert_eq!(verbose.results[0]["kind"], "Function");
        assert_eq!(verbose.results[0]["file_path"], "target_mod.rs");
        assert_eq!(
            verbose.results[0]["matched_kinds"],
            serde_json::json!(["Calls", "References"])
        );

        let self_only_kind = build_bulk_refs_response(
            &graph,
            &BulkRefsRequest {
                entity_ids: vec![target.id.to_string()],
                kind: "Imports".to_string(),
                compact: true,
            },
        )
        .unwrap();
        assert_eq!(self_only_kind.results[0]["has_references"], false);
        assert_eq!(self_only_kind.results[0]["reference_count"], 0);
        assert_eq!(self_only_kind.classified_count, 1);
        assert_eq!(self_only_kind.error_count, 0);
        assert_eq!(self_only_kind.incomplete_verdict_count, 0);
        assert_eq!(self_only_kind.with_references, 0);
        assert_eq!(self_only_kind.without_references, 1);
    }

    #[test]
    fn bulk_invalid_and_missing_targets_are_errors_never_negative_verdicts() {
        let graph = kin_db::InMemoryGraph::new();
        let missing_id = kin_model::EntityId::new().to_string();

        for compact in [true, false] {
            let response = build_bulk_refs_response(
                &graph,
                &BulkRefsRequest {
                    entity_ids: vec!["not-a-uuid".to_string(), missing_id.clone()],
                    kind: "Any".to_string(),
                    compact,
                },
            )
            .unwrap();

            assert_eq!(response.total_checked, 2);
            assert_eq!(response.classified_count, 0);
            assert_eq!(response.error_count, 2);
            assert_eq!(response.incomplete_verdict_count, 0);
            assert_eq!(response.with_references, 0);
            assert_eq!(response.without_references, 0);
            assert_bulk_error_row(
                &response.results[0],
                compact,
                "invalid entity_id (not a UUID)",
            );
            assert_bulk_error_row(&response.results[1], compact, "entity not found");
        }
    }

    #[test]
    fn dangling_reference_source_is_explicitly_incomplete_in_both_modes() {
        use kin_db::InMemoryGraph;
        use kin_model::relation::{Relation, RelationOrigin};
        use kin_model::{
            Entity, EntityId, EntityKind, EntityMetadata, EntityRole, EntityStore, FilePathId,
            FingerprintAlgorithm, GraphNodeId, Hash256, LanguageId, SemanticFingerprint,
            Visibility,
        };

        fn entity(name: &str, rel_path: &str) -> Entity {
            Entity {
                id: EntityId::new(),
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
                file_origin: Some(FilePathId::new(rel_path)),
                span: None,
                signature: name.to_string(),
                visibility: Visibility::Public,
                role: EntityRole::Source,
                doc_summary: None,
                metadata: EntityMetadata::default(),
                lineage_parent: None,
                created_in: None,
                superseded_by: None,
            }
        }

        let target = entity("target", "target.rs");
        let materialized_caller = entity("caller", "caller.rs");
        let missing_source_id = EntityId::new();
        let graph = InMemoryGraph::new();
        graph.upsert_entity(&target).unwrap();
        graph.upsert_entity(&materialized_caller).unwrap();

        for (source_id, kind) in [
            (materialized_caller.id, RelationKind::References),
            (missing_source_id, RelationKind::References),
            // Repeated/multi-kind observations from the missing source remain
            // one known caller identity while preserving the known kind union.
            (missing_source_id, RelationKind::References),
            (missing_source_id, RelationKind::Calls),
        ] {
            graph
                .upsert_relation(&Relation {
                    id: kin_model::ids::RelationId::new(),
                    kind,
                    src: GraphNodeId::Entity(source_id),
                    dst: GraphNodeId::Entity(target.id),
                    confidence: 1.0,
                    origin: RelationOrigin::Parsed,
                    created_in: None,
                    import_source: None,
                    evidence: Vec::new(),
                })
                .unwrap();
        }

        for compact in [true, false] {
            let response = build_bulk_refs_response(
                &graph,
                &BulkRefsRequest {
                    entity_ids: vec![target.id.to_string()],
                    kind: "Any".to_string(),
                    compact,
                },
            )
            .unwrap();

            assert_eq!(response.total_checked, 1);
            assert_eq!(response.classified_count, 0);
            assert_eq!(response.error_count, 0);
            assert_eq!(response.incomplete_verdict_count, 1);
            assert_eq!(response.with_references, 0);
            assert_eq!(response.without_references, 0);

            let row = &response.results[0];
            assert!(row["has_references"].is_null());
            assert!(row["reference_count"].is_null());
            assert_eq!(row["known_reference_count"], 2);
            assert_eq!(row["reference_count_complete"], false);
            assert_eq!(row["verdict_complete"], false);
            assert_eq!(row["missing_source_entity_count"], 1);
            assert!(row["verdict_reason"]
                .as_str()
                .unwrap()
                .contains("graph reference authority incomplete"));
            if compact {
                assert!(row.get("name").is_none());
                assert!(row.get("matched_kinds").is_none());
            } else {
                assert_eq!(row["name"], "target");
                assert_eq!(row["kind"], "Function");
                assert_eq!(row["file_path"], "target.rs");
                assert_eq!(
                    row["matched_kinds"],
                    serde_json::json!(["Calls", "References"])
                );
            }
        }

        let layout = kin_core::KinLayout::new(tempfile::tempdir().unwrap().path().join(".kin"));
        let error = build_refs_response(
            &layout,
            &graph,
            &RefsRequest {
                entity: target.id.to_string(),
                kind: "all".to_string(),
            },
        &refs_test_envelope(),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("graph reference authority incomplete"),
            "ordinary refs must fail loud on the same gap: {error:#}"
        );
    }

    #[test]
    fn request_level_bulk_failures_return_no_classification_response() {
        let graph = kin_db::InMemoryGraph::new();
        assert!(build_bulk_refs_response(
            &graph,
            &BulkRefsRequest {
                entity_ids: Vec::new(),
                kind: "Any".to_string(),
                compact: true,
            },
        )
        .is_err());
        assert!(build_bulk_refs_response(
            &graph,
            &BulkRefsRequest {
                entity_ids: vec![kin_model::EntityId::new().to_string()],
                kind: "unsupported".to_string(),
                compact: false,
            },
        )
        .is_err());
    }

    #[test]
    fn legacy_bulk_response_without_completeness_counts_fails_closed() {
        let legacy = serde_json::json!({
            "total_checked": 1,
            "with_references": 0,
            "without_references": 1,
            "relation_kinds": ["Calls", "Imports", "References"],
            "compact": true,
            "results": [{
                "entity_id": kin_model::EntityId::new().to_string(),
                "has_references": false,
                "reference_count": 0
            }]
        });

        let error = serde_json::from_value::<BulkRefsResponse>(legacy).unwrap_err();
        assert!(
            error.to_string().contains("classified_count"),
            "a version-skewed response must fail instead of recovering unsafe negatives: {error}"
        );
    }

    /// A reference must report the line a human editor shows.
    ///
    /// Graph spans carry tree-sitter rows, which are 0-based, and this listing
    /// emitted them raw. An agent that read `kin refs` and jumped to the
    /// reported `file:line` landed one line above every reference it was given,
    /// on every reference, while `find_references` over MCP answered the same
    /// question one line lower.
    ///
    /// The fixture puts the caller on graph row 41, which is line 42 of the
    /// file, so an off-by-one cannot pass by coincidence.
    #[test]
    fn a_reference_reports_the_line_a_human_editor_shows() {
        use kin_db::InMemoryGraph;
        use kin_model::relation::{Relation, RelationOrigin};
        use kin_model::{
            Entity, EntityId, EntityKind, EntityMetadata, EntityRole, EntityStore, FilePathId,
            FingerprintAlgorithm, GraphNodeId, Hash256, LanguageId, SemanticFingerprint,
            SourceSpan, Visibility,
        };

        fn entity(name: &str, rel_path: &str, graph_row: Option<u32>) -> Entity {
            Entity {
                id: EntityId::new(),
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
                file_origin: Some(FilePathId::new(rel_path)),
                span: graph_row.map(|row| SourceSpan {
                    file: FilePathId::new(rel_path),
                    start_byte: 0,
                    end_byte: 1,
                    start_line: row,
                    start_col: 0,
                    end_line: row + 3,
                    end_col: 0,
                }),
                signature: name.to_string(),
                visibility: Visibility::Public,
                role: EntityRole::Source,
                doc_summary: None,
                metadata: EntityMetadata::default(),
                lineage_parent: None,
                created_in: None,
                superseded_by: None,
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        std::fs::create_dir_all(repo.join(".kin")).unwrap();
        let layout = kin_core::KinLayout::new(repo.join(".kin"));

        let target = entity("probe_symbol", "target_mod.rs", Some(0));
        let spanned_caller = entity("spanned_caller", "spanned.rs", Some(41));
        let spanless_caller = entity("spanless_caller", "spanless.rs", None);

        let graph = InMemoryGraph::new();
        graph.upsert_entity(&target).unwrap();
        for caller in [&spanned_caller, &spanless_caller] {
            graph.upsert_entity(caller).unwrap();
            graph
                .upsert_relation(&Relation {
                    id: kin_model::ids::RelationId::new(),
                    kind: RelationKind::References,
                    src: GraphNodeId::Entity(caller.id),
                    dst: GraphNodeId::Entity(target.id),
                    confidence: 1.0,
                    origin: RelationOrigin::Parsed,
                    created_in: None,
                    import_source: None,
                    evidence: Vec::new(),
                })
                .unwrap();
        }

        let response = build_refs_response(
            &layout,
            &graph,
            &RefsRequest {
                entity: "probe_symbol".to_string(),
                kind: "all".to_string(),
            },
        &refs_test_envelope(),
        )
        .unwrap();
        let joined = response.lines.join("\n");

        assert!(
            joined.contains("spanned.rs:42"),
            "graph row 41 is line 42 to a reader: {joined}"
        );
        assert!(
            !joined.contains("spanned.rs:41"),
            "the raw graph row must never reach the listing: {joined}"
        );
        assert!(
            joined.contains("spanless_caller @ spanless.rs "),
            "an entity with no span reports its path and no fabricated line: {joined}"
        );
        assert!(
            !joined.contains("spanless.rs:0"),
            "line 0 exists in no editor: {joined}"
        );
    }

    fn assert_bulk_error_row(row: &serde_json::Value, compact: bool, expected_error: &str) {
        assert_eq!(row["error"], expected_error);
        assert!(row["has_references"].is_null());
        assert!(row["reference_count"].is_null());
        assert!(row["known_reference_count"].is_null());
        assert_eq!(row["reference_count_complete"], false);
        assert_eq!(row["verdict_complete"], false);
        if compact {
            assert!(row.get("name").is_none());
            assert!(row.get("kind").is_none());
            assert!(row.get("file_path").is_none());
            assert!(row.get("matched_kinds").is_none());
        } else {
            assert!(row["name"].is_null());
            assert!(row["kind"].is_null());
            assert!(row["file_path"].is_null());
            assert_eq!(row["matched_kinds"], serde_json::json!([]));
        }
    }
}
