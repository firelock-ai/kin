// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};
use kin_index::RelationResolution;
use kin_mcp::handlers::common::{ReferenceEdge, ReferenceLinesAbsent};
use kin_mcp::handlers::external_symbols::SiteText;
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

/// How `kin refs` lays an answer out for a person at a terminal: every line
/// fits in `width` columns, and the first `callers` callers are listed with the
/// rest counted and left to `--all`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefsView {
    pub width: usize,
    pub callers: usize,
}

impl RefsView {
    /// The narrowest layout a view is drawn at, whatever the terminal says.
    pub const MIN_WIDTH: usize = 40;
    /// Callers a terminal answer lists before it counts the rest.
    pub const CALLERS: usize = 20;
    /// The width a terminal whose size cannot be read is drawn at.
    pub const FALLBACK_WIDTH: usize = 80;
}

/// What the CLI sends the daemon for `kin refs`: the request, and the view it
/// wants the answer laid out in. With no view the answer is the complete
/// listing, which `--all`, `--json` and a caller that is not a terminal read,
/// and which a daemon that predates views returns for any request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefsCommandRequest {
    #[serde(flatten)]
    pub request: RefsRequest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub view: Option<RefsView>,
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
    /// Set when the query resolved to no entity. Without it a caller reading the
    /// exit code takes the guidance for an answer, which for `kin refs` is an
    /// empty reference list: the exact shape a "safe to delete?" sweep acts on
    /// (FIR-3071). The same text stays in `lines` for an older client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// The call sites of every caller in the files that import the focal's
    /// file, the `call_sites` block `find_references` serves over the same
    /// files, so the two surfaces say the same thing about one store. Absent
    /// when the focal did not resolve or those files could not be
    /// established.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_sites: Option<serde_json::Value>,
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

/// `kin refs`. At a terminal the answer is laid out for a person: sized to the
/// terminal's width and listing the first [`RefsView::CALLERS`] callers.
/// `--all`, `--json` and output that is not a terminal get the complete answer.
pub async fn run(entity: String, kind: String, all: bool, json: bool) -> Result<()> {
    let layout = crate::commands::require_repository_layout()?;
    let _scope = announce_active_scope(&layout, "refs").await?;
    let view = (!all && !json && console::Term::stdout().is_term()).then(|| RefsView {
        width: crate::mark::terminal_columns()
            .unwrap_or(RefsView::FALLBACK_WIDTH)
            .max(RefsView::MIN_WIDTH),
        callers: RefsView::CALLERS,
    });
    let response = run_daemon_refs(
        &layout,
        &RefsCommandRequest {
            request: RefsRequest { entity, kind },
            view,
        },
    )
    .await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&response)?);
        if let Some(error) = response.error {
            anyhow::bail!(error);
        }
        return Ok(());
    }
    // Refuse before printing, so a miss leaves stdout empty.
    if let Some(error) = response.error {
        anyhow::bail!(error);
    }
    for line in response.lines {
        println!("{}", crate::output_style::paint_refs_line(&line));
    }
    Ok(())
}

/// An explicitly bounded JSON view shares MCP's frozen continuation contract.
pub async fn run_page(
    entity: String,
    kind: String,
    cursor: Option<String>,
    max_chars: Option<usize>,
) -> Result<()> {
    let max_chars = max_chars.unwrap_or(12_000);
    if !(kin_mcp::budget::RESPONSE_MIN_MAX_CHARS..=kin_mcp::budget::RESPONSE_MAX_MAX_CHARS)
        .contains(&max_chars)
    {
        anyhow::bail!("--max-chars must be between 2000 and 60000");
    }
    let kinds = parse_relation_kinds(&kind)?
        .into_iter()
        .map(|kind| match kind {
            RelationKind::Calls => "calls",
            RelationKind::Imports => "imports",
            _ => "references",
        })
        .collect::<Vec<_>>();
    let mut arguments = HashMap::from([
        ("query".into(), serde_json::json!(entity)),
        ("relation_kinds".into(), serde_json::json!(kinds)),
        ("max_chars".into(), serde_json::json!(max_chars)),
    ]);
    if let Some(cursor) = cursor {
        arguments.insert("cursor".into(), serde_json::json!(cursor));
    }
    let layout = crate::commands::require_repository_layout()?;
    let url = match std::env::var("KIN_DAEMON_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
    {
        Some(url) => Some(url),
        None => crate::daemon_client::resolve_daemon_url(&layout).await?,
    }
    .ok_or_else(|| crate::daemon_client::daemon_required_error("refs", &layout))?;
    let response = crate::daemon_client::DaemonClient::from_base_url(url)?
        .reference_page(arguments)
        .await?;
    let Some(kin_mcp::ContentBlock::Text { text }) = response.content.first() else {
        anyhow::bail!("reference page contains no semantic payload");
    };
    if response.is_error == Some(true) {
        anyhow::bail!("{text}");
    }
    // Preserve the already measured compact page, including its trust reading.
    println!("{text}");
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
    request: &RefsCommandRequest,
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

/// The daemon's spine as one `kin refs` read found it, and the repository that
/// read answers for.
///
/// Only an empty answer uses it: its absence is graded on the cross-repo
/// authority `find_references` weighs, so a reference from another repository
/// into the focal is not certified away.
#[derive(Clone, Copy)]
pub struct RefsSpine<'a> {
    pub repo_id: &'a str,
    pub spine: ::kin_spine::DaemonSpine<'a>,
    /// The authority and source scope the daemon holds for this read, which
    /// the store-wide reading of the focal's possible callers reads caller text
    /// and takes its escape census through, as `find_references` does. `None`
    /// reads the callers in the files that import the focal's file alone.
    pub call_site_sources: Option<(
        &'a kin_mcp::handlers::RequestRepositoryAuthority,
        kin_mcp::handlers::common::EntitySourceScope,
    )>,
}

impl RefsSpine<'static> {
    /// No spine to consult, which is what a daemon whose spine is switched off
    /// hands over.
    pub fn absent() -> Self {
        Self {
            repo_id: "",
            spine: ::kin_spine::DaemonSpine::Absent,
            call_site_sources: None,
        }
    }
}

/// [`build_refs_response_with_spine`] for a caller that holds no spine read.
pub fn build_refs_response(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    request: &RefsRequest,
    envelope: &kin_mcp::Envelope,
) -> Result<RefsResponse> {
    build_refs_response_with_spine(layout, graph, request, envelope, RefsSpine::absent())
}

/// [`build_refs_response_quoted`] for a caller that holds no body reader:
/// every site keeps its line inside its caller and says its text is
/// unavailable.
pub fn build_refs_response_with_spine(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    request: &RefsRequest,
    envelope: &kin_mcp::Envelope,
    spine: RefsSpine<'_>,
) -> Result<RefsResponse> {
    build_refs_response_quoted(
        layout,
        graph,
        request,
        envelope,
        spine,
        &kin_mcp::handlers::common::NoCallerText,
        None,
    )
}

/// `kin refs`, with the text at each site cut from its caller's own body
/// through `site_text`, the reader `find_references` quotes a site through.
///
/// With a `view` the answer is laid out for a person at a terminal (see
/// [`RefsView`]); without one it is the complete listing.
pub fn build_refs_response_quoted(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    request: &RefsRequest,
    envelope: &kin_mcp::Envelope,
    spine: RefsSpine<'_>,
    site_text: &dyn SiteText,
    view: Option<RefsView>,
) -> Result<RefsResponse> {
    let mut response = build_refs_lines(layout, graph, request, envelope, spine, site_text, view)?;
    if let Some(view) = view {
        response.lines = fit_lines(&response.lines, view.width);
    }
    Ok(response)
}

fn build_refs_lines(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    request: &RefsRequest,
    envelope: &kin_mcp::Envelope,
    spine: RefsSpine<'_>,
    site_text: &dyn SiteText,
    view: Option<RefsView>,
) -> Result<RefsResponse> {
    let relation_kinds = parse_relation_kinds(&request.kind)?;
    let want_dispatch = strip_dispatch_modifier(&request.kind).1;
    // A symbol outside the repository, by the address every surface serves for
    // it or by its bare id: its callers are the entities with an edge into it.
    // Asked before the entity resolver, which would report it absent and send
    // the caller to `kin xref`, a name lookup that cannot find it.
    if let Some(node) = crate::commands::external_symbols::lookup(graph, &request.entity)? {
        return build_external_refs_response(
            layout,
            graph,
            request,
            &node,
            &relation_kinds,
            want_dispatch,
            envelope,
            site_text,
        );
    }
    if crate::commands::external_symbols::is_address(&request.entity) {
        let lines = crate::commands::external_symbols::unknown_address_lines(&request.entity);
        return Ok(RefsResponse {
            error: Some(lines.join("\n")),
            lines,
            negative: None,
            call_sites: None,
        });
    }
    // The one resolver every read command shares (FIR-3505). The ranker this
    // replaced tied every twin on name, kind and callers, so it answered about
    // whichever one the store listed first, and nothing said a choice was made.
    let resolution = crate::entity_identity::resolve_entity(
        graph,
        &request.entity,
        &crate::entity_identity::IdentityQualifiers::default(),
    )?;
    // A name no repository entity carries may name a symbol outside the
    // repository, `Array.map` or its SCIP symbol. It is matched the way
    // `find_references` matches it, so the two surfaces answer one name alike.
    if resolution.name_matches.is_empty() {
        let (named, matched) =
            kin_mcp::handlers::external_symbols::external_symbols_named(graph, &request.entity)
                .map_err(|error| {
                    anyhow::anyhow!(
                        "read the symbols outside the repository named '{}': {error}",
                        request.entity.trim()
                    )
                })?;
        match named.as_slice() {
            [] => {}
            [node] => {
                let mut response = build_external_refs_response(
                    layout,
                    graph,
                    request,
                    node,
                    &relation_kinds,
                    want_dispatch,
                    envelope,
                    site_text,
                )?;
                response.lines.insert(
                    0,
                    crate::commands::external_symbols::named_line(&request.entity, node, matched),
                );
                return Ok(response);
            }
            candidates => {
                let lines = crate::commands::external_symbols::name_candidate_lines(
                    "kin refs",
                    &request.entity,
                    candidates,
                );
                return Ok(RefsResponse {
                    error: Some(lines.join("\n")),
                    lines,
                    negative: None,
                    call_sites: None,
                });
            }
        }
    }
    // A member name several owners share is answered for each of them, the way
    // `find_references` sections the same name under `candidates_by_owner`,
    // rather than refused or answered for one.
    if resolution.shares_member_name() {
        return build_shared_member_refs_response(
            layout,
            graph,
            request,
            &resolution,
            envelope,
            spine,
            site_text,
            view,
        );
    }
    let refusal = if resolution.name_matches.is_empty() {
        // Not an absence claim about references: the focal never resolved, so
        // nothing was walked and there is no coverage question to answer. A
        // verdict here would qualify a lookup failure as if it were a finding.
        Some(refs_not_found_guidance(&resolution.reference.name))
    } else if resolution.pin_excluded_all() {
        // Spelled the way this command takes its pins. `kin refs --kind` filters
        // relation kinds, so a miss telling the caller to narrow with `--kind`
        // would send them to a flag that answers a different question.
        Some(crate::entity_identity::pin_miss_lines(
            graph,
            &resolution,
            crate::entity_identity::PinSpelling::FileEntityKind,
        ))
    } else if resolution.needs_a_pin() {
        Some(crate::entity_identity::pin_request_lines(
            graph,
            &resolution,
        ))
    } else {
        None
    };
    if let Some(lines) = refusal {
        return Ok(RefsResponse {
            error: Some(lines.join("\n")),
            lines,
            negative: None,
            call_sites: None,
        });
    }
    let target = resolution.chosen().cloned().ok_or_else(|| {
        anyhow::anyhow!(
            "resolving '{}' produced no candidate",
            resolution.reference.name
        )
    })?;
    // `None` means the focal was pinned by id, which is the rule the shared
    // producer switches on. Kept beside the resolution so the two cannot drift.
    let resolved_by_name = if resolution.addressed_by_id() {
        None
    } else {
        Some(resolution.reference.name.as_str())
    };
    let target = &target;
    // The call sites of every caller in the files that import the focal's
    // file, tallied as `find_references` tallies them, so both surfaces say
    // the same thing about one store. Absent when those files could not be
    // established, which the arrival reading says on its own.
    // Qualified by the owed callers outside those files, since a caller can
    // reach the focal without importing its file.
    let arrival = match spine.call_site_sources {
        Some((authority, scope)) => kin_mcp::handlers::entities::reference_caller_arrival(
            graph,
            target,
            Some(authority),
            scope,
        ),
        None => kin_mcp::caller_arrival::observe_caller_arrival(graph, target),
    };
    let call_sites = arrival.call_sites_block();
    // Said in plain words for the person at the terminal. The block above is
    // what the daemon's JSON carries, verdict codes included, unchanged.
    let call_site_lines = |lines: &mut Vec<String>| {
        if let Some(tally) = arrival.call_sites.as_ref() {
            lines.extend(call_site_words(
                tally,
                arrival.owed_outside.as_deref(),
                arrival.owed_callers_cannot_name_focal,
                target,
            ));
        }
        if let Some(scan) = arrival.scan.as_deref() {
            lines.extend(kin_mcp::call_sites::candidate_lines(scan, &target.name));
        }
    };

    let refs = collect_references(graph, target, &relation_kinds)?;
    let target_path = entity_address(layout, graph, target);

    let mut lines = Vec::new();
    // First, and on every answer, when a missing language server leaves out
    // references this answer could otherwise have held: the rows below are
    // then a lower bound, and a reader who stops at them must not read them as
    // the whole set.
    lines.extend(language_server_gap_line(target.language));
    lines.push(format!(
        "References to '{}' -> {} ({:?}) {}",
        resolution.reference.name, target.name, target.kind, target_path
    ));
    lines.extend(pinned_note(&resolution, target, &target_path));
    let choice = crate::entity_identity::choice_note(
        graph,
        &resolution,
        crate::entity_identity::PinSpelling::FileEntityKind,
    );
    let listed_candidates = !choice.is_empty();
    lines.extend(choice);

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
            &arrival,
            envelope,
            spine,
        );
        lines.extend(refs_absence_qualifier(
            graph,
            target,
            &relation_kinds,
            resolved_by_name,
            &arrival,
            envelope,
            spine,
        ));
        // What leaves the answer unsettled, and the unproven call sites that
        // could still be calls to the focal, are read right under the verdict,
        // before the listing of what the graph holds nearby, in every layout.
        call_site_lines(&mut lines);
        let neighbors = declaration_neighbors::collect(graph, target, &relation_kinds)?;
        // The candidate note above already named every same-name identity, so
        // the sibling listing would only repeat it.
        lines.extend(empty_result_context(target, &neighbors, !listed_candidates));
        // Additive, and deliberately AFTER the absence verdict rather than
        // instead of it. A Go concrete method reached only through an interface
        // has no direct callers at all, so this is the path the whole class
        // lands on, and a candidate is not evidence that the verdict above was
        // wrong: the verdict answers whether the graph could have held a direct
        // caller, and these rows are not direct callers.
        if want_dispatch {
            lines.extend(dispatch_candidate_lines(layout, graph, target));
        }
        if let Some(note) = crate::entity_identity::stale_span_note(&lines) {
            lines.push(note);
        }
        return Ok(RefsResponse {
            lines,
            negative,
            error: None,
            call_sites,
        });
    }

    // FIR-1552. A receiver-method call the linker matched on the bare leaf name
    // is a candidate, not a caller: nothing at the reference site says the
    // receiver holds this type. Counting them beside real callers is what let
    // `find_references(HTTPAdapter.send)` answer 33 for a method two lines call.
    // The headline counts callers; the candidates get their own heading and
    // their own count.
    //
    // A row that is only a name match is held out for the same reason and gets
    // its own heading too. On cli/cli v2.101.0 the repository holds exactly one
    // `func requestBody`, and `kin refs requestBody` counted seventeen
    // referencing entities: sixteen were local variables of that name in
    // packages that never import the one the function lives in, every one of
    // them a `References` edge at `name_only`, and one was the real caller.
    // A caller with no file-reading tool cannot check sixteen fabricated
    // cross-package references against anything, so they must not be inside the
    // number the answer leads with.
    //
    // A counted caller is cut by its own edges, because one proven edge used to
    // count every site the caller's other edges recorded. Its sites that only
    // a held edge recorded go under the heading that edge earns, as a row that
    // says its caller is counted above.
    let mut resolved: Vec<ReferenceEntry> = Vec::new();
    let mut receiver_candidates: Vec<ReferenceEntry> = Vec::new();
    let mut name_matches: Vec<ReferenceEntry> = Vec::new();
    for entry in refs {
        let (counted, held) = entry.split_held_sites();
        resolved.extend(counted);
        match held {
            Some(held) if held.receiver_name_guess => receiver_candidates.push(held),
            Some(held) => name_matches.push(held),
            None => {}
        }
    }
    let unconfirmed_count = receiver_candidates.len() + name_matches.len();

    // A row names its caller by id, with the file only as the projection it
    // is, and each site inside the caller, never by a file line.
    let render = |lines: &mut Vec<String>, entry: &ReferenceEntry| {
        let caller = graph.get_entity(&entry.entity_id).ok().flatten();
        let address = match caller.as_ref() {
            Some(caller) => entity_address(layout, graph, caller),
            None => format!("[{}]", entry.entity_id),
        };
        let held_note = if entry.held_sites_of_counted_caller {
            " (its proven sites are counted above)"
        } else {
            ""
        };
        lines.push(format!(
            "  {} {} [{}] ({}) {}{held_note}",
            entry.name,
            address,
            relation_kinds_label(&entry.relation_kinds),
            entry.resolution.as_str(),
            reference_sites_label(entry, caller.as_ref(), site_text),
        ));
    };

    // FIR-2463. The count and the held rows are one reading, so they are printed
    // as one line. A reader who stops at "No resolved incoming calls relations."
    // and never reaches the candidates paragraph below has read a zero the same
    // response is contradicting, which is the shape that made an MCP
    // `total_upstream: 0` deletable while the one real caller sat in the payload
    // beside it.
    let unconfirmed = if unconfirmed_count == 0 {
        String::new()
    } else {
        format!(
            ", plus {} unconfirmed candidate{} not in that count",
            unconfirmed_count,
            if unconfirmed_count == 1 { "" } else { "s" }
        )
    };
    let count_line = if resolved.is_empty() {
        format!(
            "No resolved incoming {} relations{unconfirmed}.",
            relation_kinds_label(&relation_kinds)
        )
    } else {
        format!("referenced by {} entities{unconfirmed}:", resolved.len())
    };
    let receiver_heading = (!receiver_candidates.is_empty()).then(|| {
        format!(
            "{} receiver-name candidate{} not counted above; each is a call through a \
             receiver whose type nothing at the reference site settles:",
            receiver_candidates.len(),
            if receiver_candidates.len() == 1 {
                ""
            } else {
                "s"
            }
        )
    });
    let name_heading = (!name_matches.is_empty()).then(|| {
        format!(
            "{} name-only match{} not counted above; each is an identifier that carries this \
             name with nothing at the site proving it is this entity, which is what a local \
             variable or a parameter of the same name looks like:",
            name_matches.len(),
            if name_matches.len() == 1 { "" } else { "es" }
        )
    });
    let sections: [(Option<String>, &[ReferenceEntry]); 3] = [
        (None, &resolved),
        (receiver_heading, &receiver_candidates),
        (name_heading, &name_matches),
    ];
    let weak_tier = sections
        .iter()
        .flat_map(|(_, entries)| entries.iter())
        .any(|entry| !entry.resolution.is_proven());

    // Laid out for a person at a terminal: what qualifies the answer first,
    // then the callers, name first, sized to the terminal.
    if let Some(view) = view {
        let mut notes = Vec::new();
        if weak_tier {
            notes.push(TIER_NOTE.to_string());
        }
        if want_dispatch {
            notes.extend(dispatch_candidate_lines(layout, graph, target));
        }
        let mut call_site_disclosure = Vec::new();
        call_site_lines(&mut call_site_disclosure);
        let lines = compact_refs_lines(
            view,
            CompactListing {
                layout,
                graph,
                site_text,
                lead: lines,
                call_site_lines: call_site_disclosure,
                count_line,
                sections: &sections,
                notes,
            },
        );
        return Ok(RefsResponse {
            lines,
            negative: None,
            error: None,
            call_sites,
        });
    }

    // The complete listing, which `--all`, `--json` and a pipe read, leads
    // with the same disclosure the terminal layout does: what leaves the
    // answer unsettled and the unproven call sites that could still be calls
    // to the focal, before any row.
    call_site_lines(&mut lines);
    lines.push(count_line);
    for (heading, entries) in &sections {
        if let Some(heading) = heading {
            lines.push(heading.clone());
        }
        for entry in entries.iter() {
            render(&mut lines, entry);
        }
    }

    // What the tag after each row means, said once, whenever a row carries a
    // tier weaker than proven. The tags were already printed and nothing said
    // what they meant, and the reader this answer is written for has no grep to
    // check a row against, so the tier is the whole of what it has.
    if weak_tier {
        lines.push(TIER_NOTE.to_string());
    }
    // How a site is addressed, said once, whenever a row printed one.
    if resolved
        .iter()
        .chain(&receiver_candidates)
        .chain(&name_matches)
        .any(|entry| !entry.reference_lines.is_empty())
    {
        lines.push(REFS_SITE_NOTE.to_string());
    }

    if want_dispatch {
        lines.extend(dispatch_candidate_lines(layout, graph, target));
    }

    // No verdict on this path, and that is decided rather than skipped. The walk
    // returned rows, so there is no absence to qualify. That includes the
    // all-candidates case above: a receiver-name candidate is a reference the
    // graph does hold, disclosed on its own line with its own count (FIR-1552,
    // FIR-2463), so the reader is already being told the answer is not a clean
    // bill. Stamping a coverage verdict on a non-empty answer is the FIR-2404
    // failure in its opposite costume, which this rollout's positive control
    // exists to catch.
    if let Some(note) = crate::entity_identity::stale_span_note(&lines) {
        lines.push(note);
    }
    Ok(RefsResponse {
        lines,
        negative: None,
        error: None,
        call_sites,
    })
}

/// Files with callers still being linked outside the importing files that a
/// `kin refs` answer names before it says how many more there are.
const OWED_OUTSIDE_FILES_NAMED: usize = 5;

/// The call sites of the callers in the files that import the focal's file,
/// in plain words for a person reading a terminal.
///
/// It states the facts [`kin_mcp::call_sites::text_lines`] states for the
/// `call_sites` block `find_references` serves over the same files: every
/// count, the files it names, and the command that finishes work still owed.
/// It leaves out the verdict codes, which stay in that block for a program to
/// read. This is a completeness disclosure, so it never says an answer is
/// complete while a count says otherwise: every caller still owed, every
/// caller nothing can link on this machine and every call site whose target
/// is unproven is counted, and each says what it may cost this answer.
fn call_site_words(
    tally: &kin_model::CallSiteTally,
    owed_outside: Option<&[kin_mcp::call_sites::OwedFile]>,
    cannot_name: u64,
    focal: &kin_model::Entity,
) -> Vec<String> {
    use kin_model::call_site_reading::{
        BINDING_UNPROVEN, CALL_SITES_NOT_IN_BUILD, CALL_SITES_SERVER_FAILED, CALL_SITES_UNRESOLVED,
        PROOF_CONTEXT_STALE,
    };

    let file = focal
        .file_origin
        .as_ref()
        .map(|file| {
            std::path::Path::new(&file.0)
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| file.0.clone())
        })
        .unwrap_or_else(|| "its file".to_string());
    let name = focal.name.as_str();
    let callers = tally.callers;
    let sites = tally.sites;
    let mut lines = vec![format!(
        "Call sites in files that import {file}: {sites} across {callers} {}.",
        plural(callers, "caller", "callers")
    )];
    // Left out of the count above, and said so, as the block counts them.
    if cannot_name > 0 {
        lines.push(format!(
            "  {cannot_name} more {} there {} still linking, but never {} {name}, so {} \
             can't call it by name and {} counted.",
            plural(cannot_name, "caller", "callers"),
            plural(cannot_name, "is", "are"),
            plural(cannot_name, "spells", "spell"),
            plural(cannot_name, "it", "they"),
            plural(cannot_name, "isn't", "aren't"),
        ));
    }
    let mut still_linking = false;

    let owed = tally.callers_owed();
    if owed > 0 {
        still_linking = true;
        lines.push(format!(
            "  Still linking {owed} of the {callers} {}, so this answer may be missing calls \
             from {}.",
            plural(callers, "caller", "callers"),
            plural(owed, "it", "them")
        ));
    }

    let unlinkable = tally.callers_unproven_no_resolver;
    if unlinkable > 0 {
        let why: Vec<&str> = tally.no_resolver.keys().map(String::as_str).collect();
        lines.push(format!(
            "  {unlinkable} of the {callers} {} can't be linked on this machine ({}), so this \
             answer may be missing calls from {}, and waiting won't change that.",
            plural(callers, "caller", "callers"),
            why.join("; "),
            plural(unlinkable, "it", "them")
        ));
    }

    // One sentence per reason a call site's target is unproven, in the order
    // the verdict codes sort, as the block lists its clauses.
    let mut unproven: std::collections::BTreeMap<&'static str, u64> =
        std::collections::BTreeMap::new();
    for (kind, count) in &tally.by_state {
        if let Some(code) = kind.verdict_code() {
            *unproven.entry(code).or_insert(0) += count;
        }
    }
    for (code, count) in unproven {
        if count == 0 {
            continue;
        }
        let one = count == 1;
        let what = match code {
            BINDING_UNPROVEN if one => {
                "calls through a variable or other value, which doesn't prove what it calls"
            }
            BINDING_UNPROVEN => {
                "call through a variable or other value, which doesn't prove what they call"
            }
            CALL_SITES_UNRESOLVED if one => "was checked, but its target couldn't be proven",
            CALL_SITES_UNRESOLVED => "were checked, but their targets couldn't be proven",
            CALL_SITES_SERVER_FAILED => {
                "got no answer because the language server timed out, crashed or failed"
            }
            CALL_SITES_NOT_IN_BUILD if one => "is in a file no build of the repository compiles",
            CALL_SITES_NOT_IN_BUILD => "are in files no build of the repository compiles",
            PROOF_CONTEXT_STALE if one => {
                "was linked under a language-server setup that has since changed"
            }
            PROOF_CONTEXT_STALE => {
                "were linked under a language-server setup that has since changed"
            }
            _ if one => "is not settled",
            _ => "are not settled",
        };
        lines.push(format!(
            "  {count} of the {sites} call {} {what}, so {} may call {name}.",
            plural(sites, "site", "sites"),
            if one { "it" } else { "one of them" }
        ));
    }

    match owed_outside {
        None => lines.push(format!(
            "  Kin couldn't read its index of {} code, so callers in files that don't import \
             {file} weren't checked, and one that reaches {name} without importing {file} may \
             be missing from this answer.",
            focal.language
        )),
        Some([]) => {}
        Some(files) => {
            still_linking = true;
            let owed_callers: u64 = files.iter().map(|file| file.callers).sum();
            lines.push(format!(
                "  Still linking {owed_callers} {} in {} {} that {} import {file}. A caller \
                 can reach {name} without importing {file}, so this answer may be missing one \
                 of them.",
                plural(owed_callers, "caller", "callers"),
                files.len(),
                plural(files.len() as u64, "file", "files"),
                plural(files.len() as u64, "doesn't", "don't"),
            ));
            for owed_file in files.iter().take(OWED_OUTSIDE_FILES_NAMED) {
                lines.push(format!(
                    "    {} ({} {})",
                    owed_file.file,
                    owed_file.callers,
                    plural(owed_file.callers, "caller", "callers")
                ));
            }
            let more = files.len().saturating_sub(OWED_OUTSIDE_FILES_NAMED);
            if more > 0 {
                lines.push(format!(
                    "    and {more} more {}",
                    plural(more as u64, "file", "files")
                ));
            }
        }
    }

    if still_linking {
        lines.push("  Run `kin daemon sweep` to finish linking now.".to_string());
    } else if lines.len() == 1 && sites > 0 {
        lines.push("  Every one of them is accounted for.".to_string());
    }
    lines
}

/// `one` for a count of one, `many` for any other.
fn plural(count: u64, one: &'static str, many: &'static str) -> &'static str {
    if count == 1 {
        one
    } else {
        many
    }
}

/// `kin refs` for a member name several owners share: a full answer for each
/// owner's member, each addressed by its id, under one lead that says why.
///
/// The CLI half of `find_references`' sectioned reply. Both surfaces reach the
/// candidates through the one member rule, list them in the same order, and
/// section at most the same number, so `kin refs get` and
/// `find_references(query: "get")` answer about the same entities. Each section
/// is the ordinary answer for one entity, produced by addressing it by id, so
/// it is exactly what `kin refs <id>` prints for it.
fn build_shared_member_refs_response(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    request: &RefsRequest,
    resolution: &crate::entity_identity::EntityResolution,
    envelope: &kin_mcp::Envelope,
    spine: RefsSpine<'_>,
    site_text: &dyn SiteText,
    view: Option<RefsView>,
) -> Result<RefsResponse> {
    let mut candidates = resolution.candidates.clone();
    kin_ranking::entity_ranking::sort_name_candidates(&mut candidates);
    let sectioned = candidates
        .len()
        .min(kin_mcp::handlers::entities::RESOLUTION_CANDIDATES_LISTED_MAX);
    let scope = if sectioned < candidates.len() {
        format!("the first {sectioned} of them, ordered by file and then name,")
    } else {
        "each of them".to_string()
    };
    let mut lines = vec![format!(
        "{}, so this answer covers {scope} rather than choosing one. Name one by its \
         owner-qualified name, or pass its id, to answer about it alone.",
        kin_mcp::handlers::entities::name_candidates_situation(
            &resolution.reference.name,
            kin_ranking::entity_ranking::CandidateReason::SharedMemberName,
            candidates.len(),
        ),
    )];
    for candidate in candidates.iter().take(sectioned) {
        let section = build_refs_response_quoted(
            layout,
            graph,
            &RefsRequest {
                entity: candidate.id.to_string(),
                kind: request.kind.clone(),
            },
            envelope,
            spine,
            site_text,
            view,
        )?;
        lines.push(String::new());
        lines.push(format!(
            "== {} ({})",
            candidate.name,
            kin_review::StableEntityIdentity::from_entity(candidate).kind
        ));
        lines.extend(section.lines);
    }
    // Every candidate past the sections is still named, by id, the way
    // `find_references` lists them under `unsectioned_candidates`.
    let rest = &candidates[sectioned..];
    if !rest.is_empty() {
        let listed = rest
            .len()
            .min(kin_mcp::handlers::entities::NAME_CANDIDATES_LISTED_MAX);
        lines.push(String::new());
        lines.push(format!(
            "Not answered above, {} more by id; pass one to answer about it:",
            rest.len()
        ));
        for candidate in &rest[..listed] {
            lines.push(format!("  {}  {}", candidate.name, candidate.id));
        }
        if listed < rest.len() {
            lines.push(format!(
                "  ... and {} more, not listed; name the owner to narrow",
                rest.len() - listed
            ));
        }
    }
    Ok(RefsResponse {
        lines,
        negative: None,
        error: None,
        call_sites: None,
    })
}

/// `kin refs` for a symbol outside the repository: the symbol, then one row per
/// entity with an edge into it, each with its sites inside that entity and the
/// proof.
///
/// Rendered from the answer `find_references` gives for the same symbol, built
/// by the same function over the same edges, so the two surfaces list the same
/// callers with the same sites and proof. That answer's own floor note is
/// printed as it stands. The text at each site is cut through `site_text`, the
/// body reader the daemon hands this command, and a site keeps its `+N` inside
/// its caller when there is none.
fn build_external_refs_response(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    request: &RefsRequest,
    node: &kin_mcp::handlers::external_symbols::ExternalSymbolNode,
    relation_kinds: &[RelationKind],
    want_dispatch: bool,
    envelope: &kin_mcp::Envelope,
    site_text: &dyn SiteText,
) -> Result<RefsResponse> {
    use crate::commands::external_symbols as external;
    // The floor `find_references` applies by default, so a caller held there
    // is held here, and each site's text is cut through the same reader.
    let payload = kin_mcp::handlers::external_symbols::external_references_reply_quoted(
        graph,
        node,
        relation_kinds,
        false,
        RelationResolution::ImportScoped,
        site_text,
    )
    .map_err(|error| anyhow::anyhow!("read the callers of {}: {error}", node.address()))?;
    let references = payload["references"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let candidates = payload["candidates"]
        .as_array()
        .cloned()
        .unwrap_or_default();

    let render = |row: &serde_json::Value| -> String {
        let location = row["entity_id"]
            .as_str()
            .and_then(|id| uuid::Uuid::parse_str(id).ok())
            .and_then(|uuid| graph.get_entity(&EntityId(uuid)).ok().flatten())
            .map(|caller| entity_address(layout, graph, &caller))
            .unwrap_or_else(|| "unknown".to_string());
        let kinds = row["relation_kinds"]
            .as_array()
            .map(|kinds| {
                kinds
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .map(reference_kind_label)
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();
        format!(
            "  {} {} [{}] ({}) {} {}",
            row["name"].as_str().unwrap_or("?"),
            location,
            kinds,
            row["resolution"].as_str().unwrap_or("unresolved"),
            external::sites_label(&row["sites"]),
            external::proof_label(row),
        )
    };

    let mut lines = vec![format!(
        "References to '{}' -> {}",
        request.entity.trim(),
        external::node_label(node)
    )];
    let unconfirmed = if candidates.is_empty() {
        String::new()
    } else {
        format!(
            ", plus {} unconfirmed candidate{} not in that count",
            candidates.len(),
            if candidates.len() == 1 { "" } else { "s" }
        )
    };
    if references.is_empty() {
        lines.push(format!(
            "No incoming {} relations{unconfirmed}.",
            relation_kinds_label(relation_kinds)
        ));
    } else {
        lines.push(format!(
            "referenced by {} entit{}{unconfirmed}:",
            references.len(),
            if references.len() == 1 { "y" } else { "ies" }
        ));
        lines.extend(references.iter().map(render));
    }
    if !candidates.is_empty() {
        lines.push(format!(
            "{} caller{} below import_scoped not counted above:",
            candidates.len(),
            if candidates.len() == 1 { "" } else { "s" }
        ));
        lines.extend(candidates.iter().map(render));
    }
    if references.iter().chain(&candidates).any(|row| {
        row["sites"]
            .as_array()
            .is_some_and(|sites| !sites.is_empty())
    }) {
        lines.push(external::SITE_OFFSET_NOTE.to_string());
    }
    for degradation in payload["degradations"].as_array().into_iter().flatten() {
        if let Some(detail) = degradation["detail"].as_str() {
            lines.push(format!("note: {detail}"));
        }
    }
    if want_dispatch {
        lines.push(format!(
            "No interface-dispatch candidates: they are computed for Go methods, and '{}' is a \
             symbol outside this repository.",
            node.display_name()
        ));
    }
    // Only an empty answer carries the verdict, as for an entity, and it is
    // the one `find_references` reaches on this same payload.
    let negative = if references.is_empty() {
        kin_mcp::negative::negative_for("find_references", &payload, envelope, &[])
    } else {
        None
    };
    Ok(RefsResponse {
        lines,
        negative,
        error: None,
        call_sites: None,
    })
}

/// A relation kind as `find_references` names it (`calls`), spelled as this
/// command's rows spell it (`Calls`).
fn reference_kind_label(name: &str) -> String {
    match name {
        "calls" => "Calls".to_string(),
        "imports" => "Imports".to_string(),
        "references" => "References".to_string(),
        other => other.to_string(),
    }
}

/// The line a refs answer leads with when a language server this host lacks
/// would have linked references for `language`: what is missing and the
/// command that adds it. The same sentence the MCP answer's `_kin.advice`
/// carries, so the CLI and every MCP profile say it alike.
///
/// Read from the language-server readiness the daemon published, which is the
/// fact the MCP answer's coverage observation is computed from. `None` where
/// nothing was published or nothing is missing.
fn language_server_gap_line(language: kin_model::LanguageId) -> Option<String> {
    let readiness = kin_mcp::edge_coverage::published_language_server_readiness()?;
    let enrichment = kin_core::reference_coverage::reference_enrichment_for(language, &readiness);
    let observation = serde_json::json!({
        "language": format!("{language:?}"),
        "reference_enrichment": enrichment,
    });
    kin_mcp::first_contact::language_server_advice(
        &observation,
        kin_mcp::first_contact::Spelling::Kin,
    )
}

/// What the header adds when the caller pinned which definition it meant.
///
/// Empty when nothing was pinned, so an ordinary answer is unchanged. It exists
/// because the candidate note goes quiet exactly when a pin worked. One
/// candidate survives, so nothing else in the answer records that several
/// same-named entities were narrowed to one, and a reader cannot tell a pinned
/// answer from a name that only ever named one thing.
///
/// The kind is spelled the way `--entity-kind` takes it rather than the
/// header's debug spelling, so the note can be pasted back into the command
/// that produced it.
fn pinned_note(
    resolution: &crate::entity_identity::EntityResolution,
    target: &Entity,
    target_path: &str,
) -> Vec<String> {
    let mut pins = resolution
        .reference
        .qualifiers
        .labels_for(crate::entity_identity::PinSpelling::FileEntityKind);
    if let Some(line) = resolution.reference.line {
        pins.push(format!("line {line}"));
    }
    if pins.is_empty() {
        return Vec::new();
    }
    let reached = resolution.name_matches.len();
    vec![format!(
        "note: pinned by {} to the {} {}, of {} entit{} the name reaches.",
        pins.join(" "),
        kin_review::StableEntityIdentity::from_entity(target).kind,
        target_path,
        reached,
        if reached == 1 { "y" } else { "ies" },
    )]
}

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
    arrival: &kin_mcp::caller_arrival::CallerArrival,
    envelope: &kin_mcp::Envelope,
    spine: RefsSpine<'_>,
) -> Option<serde_json::Value> {
    kin_mcp::negative::negative_for(
        "find_references",
        &refs_absence_payload(
            graph,
            target,
            relation_kinds,
            addressed_by_name,
            arrival,
            spine,
        ),
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
///
/// The one sentence of its own is for references another repository holds
/// into the focal. They make this answer no absence at all, so it says so
/// instead of explaining why an absence cannot be certified.
fn refs_absence_qualifier(
    graph: &kin_db::InMemoryGraph,
    target: &Entity,
    relation_kinds: &[RelationKind],
    addressed_by_name: Option<&str>,
    arrival: &kin_mcp::caller_arrival::CallerArrival,
    envelope: &kin_mcp::Envelope,
    spine: RefsSpine<'_>,
) -> Vec<String> {
    let payload = refs_absence_payload(
        graph,
        target,
        relation_kinds,
        addressed_by_name,
        arrival,
        spine,
    );
    let federated = payload["references"].as_array().map_or(0, Vec::len);
    if federated > 0 {
        return vec![format!(
            "{federated} reference{} from other repositories reach{} '{}', so this is not an \
             absence; `kin xref {}` lists {}.",
            if federated == 1 { "" } else { "s" },
            if federated == 1 { "es" } else { "" },
            target.name,
            target.id,
            if federated == 1 { "it" } else { "them" },
        )];
    }
    crate::commands::absence_qualifier::qualify("find_references", &payload, envelope, "")
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
    arrival: &kin_mcp::caller_arrival::CallerArrival,
    spine: RefsSpine<'_>,
) -> serde_json::Value {
    let coverage = kin_mcp::edge_coverage::observe_cross_file_reference_coverage_for_languages(
        graph,
        &[target.language],
        relation_kinds,
    );
    let (cross_repo, federated) = refs_cross_repo(graph, target, relation_kinds, spine);
    let mut payload = serde_json::json!({
        // No local reference reached this path. What other repositories hold
        // into the focal goes here, the way `find_references` merges its
        // federated rows, so an answer they populate claims no absence.
        "references": federated,
        "relation_kinds": relation_kinds
            .iter()
            .map(|kind| relation_kind_label(*kind))
            .collect::<Vec<_>>(),
        // The cross-repo authority this read had, in the block
        // `find_references` publishes. Load-bearing: the gate REFUSES a
        // `find_references` absence whose payload reports no cross-repo
        // authority at all, and a spine that is switched off still reports
        // `not_configured`.
        "cross_repo": cross_repo,
        // The id alone, which is what the gate binds a spine's authority
        // anchor to.
        "focal_entity": { "id": target.id.to_string() },
        kin_mcp::EDGE_COVERAGE_KEY: coverage,
    });
    // Required, not optional. A payload with no `focal_resolution` is the
    // REFUSING arm of the gate rather than an exemption, so omitting it would
    // make every `kin refs` absence read uncertain for a reason that has nothing
    // to do with this store. Produced by the same function the MCP handler
    // calls, so the two surfaces count ambiguity by one rule (FIR-2475).
    if let Ok(resolution) =
        kin_mcp::handlers::entities::focal_resolution_for(graph, target, addressed_by_name)
    {
        payload["focal_resolution"] = resolution;
    }
    // The two readings `find_references` publishes about the callers that
    // could reach the focal, so the gate reads the same inputs on both
    // surfaces. Without them this command certified an absence the MCP answer
    // refused while it printed, a few lines below, that the call sites in
    // scope were not settled.
    payload[kin_mcp::caller_arrival::CALLER_ARRIVAL_KEY] = arrival.to_json();
    if let Some(block) = arrival.call_sites_block() {
        payload[kin_mcp::call_sites::CALL_SITES_KEY] = block;
    }
    payload
}

/// The `cross_repo` block `find_references` publishes for `target` from this
/// spine read, and the references into it from other repositories that the
/// block counts.
///
/// The spine's state is read through `daemon_spine_xref`, the producer the MCP
/// handler uses, so the two surfaces word a deferred, refused, stale or
/// unregistered spine the same way. A federated reference counts only when the
/// query asked for every relation class, as it does there, because a
/// cross-repo edge does not record which class it was. One that cannot count
/// leaves the relation subtype incomplete, which the gate refuses.
fn refs_cross_repo(
    graph: &kin_db::InMemoryGraph,
    target: &Entity,
    relation_kinds: &[RelationKind],
    spine: RefsSpine<'_>,
) -> (serde_json::Value, Vec<serde_json::Value>) {
    use kin_mcp::handlers::entities::{cross_repo_unavailable_json, daemon_spine_xref};
    if matches!(spine.spine, ::kin_spine::DaemonSpine::Absent) {
        return (
            serde_json::json!({ "status": "not_configured" }),
            Vec::new(),
        );
    }
    let graph_root = hex::encode(graph.compute_root_hash());
    let authority = kin_mcp::handlers::entities::FindReferencesAuthority {
        repo_id: spine.repo_id,
        graph_root: &graph_root,
        spine: spine.spine,
    };
    let (repo_id, body) = match daemon_spine_xref(authority, &target.id) {
        Ok((repo_id, ::kin_spine::SpineQuery::Found(body))) => (repo_id, body),
        Ok((_, ::kin_spine::SpineQuery::Unavailable(reason))) | Err(reason) => {
            return (cross_repo_unavailable_json(&reason), Vec::new())
        }
        Ok((_, ::kin_spine::SpineQuery::NotConfigured)) => {
            return (
                serde_json::json!({ "status": "not_configured" }),
                Vec::new(),
            )
        }
    };
    let federated = body
        .edges
        .iter()
        .filter(|edge| {
            edge.dst_repo == repo_id && edge.dst_entity == target.id && edge.src_repo != repo_id
        })
        .map(|edge| {
            let source = body.entities.iter().find(|entity| {
                entity.repo_id == edge.src_repo && entity.entity_id == edge.src_entity
            });
            serde_json::json!({
                "name": source.map_or_else(|| edge.src_entity.to_string(), |entity| entity.name.clone()),
                "file_path": match source.and_then(|entity| entity.file_path.as_deref()) {
                    Some(path) => format!("[{}] {path}", edge.src_repo),
                    None => format!("[{}] {}", edge.src_repo, edge.src_entity),
                },
                "repo_id": edge.src_repo.as_str(),
            })
        })
        .collect::<Vec<_>>();
    let every_class = kin_mcp::handlers::common::default_reference_kinds();
    let relation_subtype_complete = federated.is_empty()
        || (relation_kinds.len() == every_class.len()
            && every_class.iter().all(|kind| relation_kinds.contains(kind)));
    let counted = if relation_subtype_complete {
        federated
    } else {
        Vec::new()
    };
    let block = serde_json::json!({
        "status": "available",
        "relation_subtype_complete": relation_subtype_complete,
        "authority_complete": body.authority_complete_for(&repo_id, &target.id),
        "authority_anchor": body.authority_anchor,
        "authority_revision": body.authority_revision,
        "authority_roots": body.authority_roots,
    });
    (block, counted)
}

/// How `kin refs` names an entity: its id, which is its address, then the
/// file it is projected into, labelled as the projection it is. A caller
/// whose span the graph can no longer vouch for carries the stale mark.
fn entity_address(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    entity: &Entity,
) -> String {
    let pointer = crate::entity_identity::entity_pointer(graph, entity);
    let mut address = match pointer.path {
        Some(path) => format!(
            "[{}] (projection: {})",
            entity.id,
            display_read_path(layout, &path)
        ),
        None => format!("[{}]", entity.id),
    };
    if pointer.stale {
        address.push(' ');
        address.push_str(crate::entity_identity::STALE_SPAN_MARK);
    }
    address
}

/// What a `kin refs` answer says once about how its rows address a site.
pub const REFS_SITE_NOTE: &str = "note: a site is +N, N lines below the first line of the \
     entity that holds it, the offset a numbered body shows, with the text at it. A row names \
     its entity by id; the path after `projection:` is the file that entity is projected into, \
     not an address.";

/// What the tag after each row means, said once whenever a row carries a tier
/// weaker than proven.
const TIER_NOTE: &str = "note: the tag after each row is its resolution tier. type_resolved \
     means the destination entity itself is proven, import_scoped means an import singled out \
     the scope the name was selected in, and name_only means the name matched and nothing at \
     the site settles the destination.";

/// The site note a terminal answer carries, whose rows name callers without
/// their ids.
const COMPACT_SITE_NOTE: &str = "note: a site is +N, N lines below the first line of the \
     caller that holds it, with the text there. --all adds each caller's id; --json gives \
     the whole answer.";

/// What a terminal answer is drawn from.
struct CompactListing<'a> {
    layout: &'a kin_core::KinLayout,
    graph: &'a kin_db::InMemoryGraph,
    site_text: &'a dyn SiteText,
    /// The header and the notes about how the focal was chosen.
    lead: Vec<String>,
    /// The call-site disclosure in plain words, read before any row.
    call_site_lines: Vec<String>,
    /// How many callers the answer counts, and how many it holds apart.
    count_line: String,
    /// The counted callers, then each held group under its heading.
    sections: &'a [(Option<String>, &'a [ReferenceEntry])],
    /// What follows the rows: the tier note and the dispatch listing.
    notes: Vec<String>,
}

/// A `kin refs` answer laid out for a person at a terminal.
///
/// What qualifies the answer comes first: the header, then the call-site
/// summary and every clause that leaves it unsettled, in the plain words the
/// complete listing uses, so a reader who stops at the first screen has read
/// them. Then the callers, grouped under
/// the file each is projected into, each one row with its name first and its
/// sites inside it, `+N` and the text there. At most `view.callers` callers are
/// listed, and a count of the rest points at `--all` and `--json`. Every line
/// fits in `view.width` columns: a site's text is cut with an ellipsis, and
/// prose wraps between words.
fn compact_refs_lines(view: RefsView, listing: CompactListing<'_>) -> Vec<String> {
    let width = view.width.max(RefsView::MIN_WIDTH);
    let mut lines = fit_lines(&listing.lead, width);
    // Every clause of the disclosure is kept: it is already bounded, naming at
    // most a handful of files, and a clause left to `--all` would be a gap the
    // first screen does not show.
    lines.extend(fit_lines(&listing.call_site_lines, width));
    lines.extend(fit_lines(std::slice::from_ref(&listing.count_line), width));

    // Only the callers listed are read, so a symbol with hundreds of callers
    // costs a screen's worth of bodies, and the rest are counted.
    let entries: Vec<(usize, &ReferenceEntry)> = listing
        .sections
        .iter()
        .enumerate()
        .flat_map(|(section, (_, entries))| entries.iter().map(move |entry| (section, entry)))
        .collect();
    let shown = entries.len().min(view.callers);
    let rows: Vec<(usize, CompactRow)> = entries[..shown]
        .iter()
        .map(|(section, entry)| {
            (
                *section,
                compact_row(listing.layout, listing.graph, listing.site_text, entry),
            )
        })
        .collect();
    let name_width = rows
        .iter()
        .map(|(_, row)| console::measure_text_width(&row.name))
        .max()
        .unwrap_or(0)
        .min(width * 2 / 5);
    let mut section_open = None;
    let mut projection_open: Option<Option<String>> = None;
    for (section, row) in &rows {
        if section_open != Some(*section) {
            section_open = Some(*section);
            projection_open = None;
            if let Some(heading) = &listing.sections[*section].0 {
                lines.extend(fit_lines(std::slice::from_ref(heading), width));
            }
        }
        if projection_open.as_ref() != Some(&row.projection) {
            projection_open = Some(row.projection.clone());
            let heading = match &row.projection {
                Some(path) => {
                    let room = width.saturating_sub("  (projection: )".len());
                    format!("  (projection: {})", truncate_left(path, room))
                }
                None => "  (no projection)".to_string(),
            };
            lines.push(heading);
        }
        lines.extend(row.render(name_width, width));
    }
    let more = entries.len() - shown;
    if more > 0 {
        lines.extend(fit_lines(
            &[format!(
                "  and {more} more; --all or --json for the full list"
            )],
            width,
        ));
    }
    let mut notes = listing.notes;
    if rows.iter().any(|(_, row)| row.has_sites) {
        notes.push(COMPACT_SITE_NOTE.to_string());
    }
    if rows.iter().any(|(_, row)| row.stale) {
        notes.extend(crate::entity_identity::stale_span_note(&[
            crate::entity_identity::STALE_SPAN_MARK.to_string(),
        ]));
    }
    lines.extend(fit_lines(&notes, width));
    lines
}

/// One caller as a terminal answer lists it.
struct CompactRow {
    name: String,
    projection: Option<String>,
    /// Each site, `+N` and the text there, or why the row has none.
    sites: Vec<String>,
    has_sites: bool,
    /// The graph can no longer vouch for the caller's span.
    stale: bool,
    /// What sets the row apart from a proven call: a weaker tier, another
    /// relation kind, a held part of a counted caller, a stale span.
    tags: Vec<String>,
}

impl CompactRow {
    /// The row in lines of at most `width` columns: the name padded to
    /// `name_width`, then the sites, wrapping between sites under the first.
    fn render(&self, name_width: usize, width: usize) -> Vec<String> {
        const INDENT: &str = "    ";
        let name_room = width.saturating_sub(INDENT.len() + 2 + 12).max(8);
        let name = truncate_right(&self.name, name_room);
        let pad = name_width.saturating_sub(console::measure_text_width(&name));
        let head = format!("{INDENT}{name}{}  ", " ".repeat(pad));
        let head_width = console::measure_text_width(&head);
        // One column is kept back for the comma a wrapped site ends on.
        let room = width.saturating_sub(head_width + 1).max(1);
        let continuation = " ".repeat(head_width);
        let mut items: Vec<(String, &str)> = self
            .sites
            .iter()
            .map(|site| (truncate_right(site, room), ", "))
            .collect();
        if !self.tags.is_empty() {
            let tags = format!("({})", self.tags.join(", "));
            items.push((truncate_right(&tags, room), " "));
        }
        let mut lines = Vec::new();
        let mut current = head;
        let mut used = 0usize;
        for (item, separator) in items {
            let item_width = console::measure_text_width(&item);
            if used == 0 {
                current.push_str(&item);
                used = item_width;
            } else if used + separator.len() + item_width <= room {
                current.push_str(separator);
                current.push_str(&item);
                used += separator.len() + item_width;
            } else {
                if separator == ", " {
                    current.push(',');
                }
                lines.push(current);
                current = format!("{continuation}{item}");
                used = item_width;
            }
        }
        lines.push(current);
        lines
    }
}

fn compact_row(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    site_text: &dyn SiteText,
    entry: &ReferenceEntry,
) -> CompactRow {
    let caller = graph.get_entity(&entry.entity_id).ok().flatten();
    let pointer = caller
        .as_ref()
        .map(|caller| crate::entity_identity::entity_pointer(graph, caller));
    let projection = pointer
        .as_ref()
        .and_then(|pointer| pointer.path.as_deref())
        .map(|path| display_read_path(layout, path));
    let sites_json = reference_sites_json(entry, caller.as_ref(), site_text);
    let has_sites = !sites_json.is_empty();
    let sites = if has_sites {
        sites_json.iter().map(compact_site).collect()
    } else {
        vec![format!(
            "no sites ({})",
            entry
                .reference_lines_absent
                .map(ReferenceLinesAbsent::as_str)
                .unwrap_or("unknown")
        )]
    };
    let mut tags = Vec::new();
    if entry.resolution != RelationResolution::TypeResolved {
        tags.push(entry.resolution.as_str().to_string());
    }
    if entry.relation_kinds != [RelationKind::Calls] {
        tags.push(relation_kinds_label(&entry.relation_kinds).to_lowercase());
    }
    if entry.held_sites_of_counted_caller {
        tags.push("also counted above".to_string());
    }
    let stale = pointer.as_ref().is_some_and(|pointer| pointer.stale);
    if stale {
        tags.push("span stale".to_string());
    }
    CompactRow {
        name: entry.name.clone(),
        projection,
        sites,
        has_sites,
        stale,
        tags,
    }
}

/// `+N text`, `+N` when the text cannot be read, or `+?` when the site cannot
/// be placed inside its caller.
fn compact_site(site: &serde_json::Value) -> String {
    let offset = match site["line_in_entity"].as_u64() {
        Some(line) => format!("+{line}"),
        None => "+?".to_string(),
    };
    match site["callee"]
        .as_str()
        .map(crate::commands::external_symbols::callee_text)
    {
        Some(text) if !text.is_empty() => format!("{offset} {text}"),
        _ => offset,
    }
}

/// `text` cut to `width` columns from the right, with an ellipsis for what
/// was cut.
fn truncate_right(text: &str, width: usize) -> String {
    console::truncate_str(text, width, "\u{2026}").into_owned()
}

/// `text` cut to `width` columns from the left, so a path keeps the file it
/// names.
fn truncate_left(text: &str, width: usize) -> String {
    if console::measure_text_width(text) <= width || width == 0 {
        return text.to_string();
    }
    let mut kept: Vec<char> = Vec::new();
    let mut used = 1usize;
    for ch in text.chars().rev() {
        let ch_width = console::measure_text_width(ch.encode_utf8(&mut [0u8; 4]));
        if used + ch_width > width {
            break;
        }
        used += ch_width;
        kept.push(ch);
    }
    kept.reverse();
    format!("\u{2026}{}", kept.into_iter().collect::<String>())
}

/// Every line in at most `width` columns, wrapped between words and never
/// inside one. A continuation keeps the line's indent and adds two spaces, and
/// a single word wider than the room left is cut with an ellipsis.
pub(crate) fn fit_lines(lines: &[String], width: usize) -> Vec<String> {
    let mut fitted = Vec::new();
    for line in lines {
        if console::measure_text_width(line) <= width {
            fitted.push(line.clone());
            continue;
        }
        let indent = (line.len() - line.trim_start_matches(' ').len()).min(width / 2);
        let continuation = (indent + 2).min(width / 2);
        let mut line_indent = indent;
        let mut current = String::new();
        let mut current_width = 0usize;
        for word in line.split(' ').filter(|word| !word.is_empty()) {
            let word_width = console::measure_text_width(word);
            if !current.is_empty() && current_width + 1 + word_width <= width {
                current.push(' ');
                current.push_str(word);
                current_width += 1 + word_width;
                continue;
            }
            if !current.is_empty() {
                fitted.push(std::mem::take(&mut current));
                line_indent = continuation;
            }
            let word = truncate_right(word, width.saturating_sub(line_indent).max(1));
            current = format!("{}{word}", " ".repeat(line_indent));
            current_width = line_indent + console::measure_text_width(&word);
        }
        if !current.is_empty() {
            fitted.push(current);
        }
    }
    fitted
}

/// The reference sites of one entry, each addressed inside its caller, or the
/// named reason it has none.
///
/// A site is `+N` below the caller's first line with the text at it, cut from
/// the caller's own body through `site_text`: the address `find_references`
/// serves under `sites`, rendered by the renderer an external symbol's
/// callers use, so the two surfaces can be compared site for site. Never a
/// file line.
///
/// An entry with no sites says which absence it is rather than printing an
/// empty list, using the names the MCP row carries under
/// `sites_absent_reason`, so the two surfaces can be compared word for word.
fn reference_sites_label(
    entry: &ReferenceEntry,
    caller: Option<&Entity>,
    site_text: &dyn SiteText,
) -> String {
    if entry.reference_lines.is_empty() {
        let reason = entry
            .reference_lines_absent
            .map(ReferenceLinesAbsent::as_str)
            .unwrap_or("unknown");
        return format!("sites none ({reason})");
    }
    let sites = reference_sites_json(entry, caller, site_text);
    crate::commands::external_symbols::sites_label(&serde_json::Value::Array(sites))
}

/// Each site of one entry as `find_references` serves it, addressed inside
/// the caller through `site_text`.
fn reference_sites_json(
    entry: &ReferenceEntry,
    caller: Option<&Entity>,
    site_text: &dyn SiteText,
) -> Vec<serde_json::Value> {
    let spans: Vec<(RelationKind, kin_model::SourceSpan)> = entry
        .edges
        .iter()
        .flat_map(|edge| edge.spans.iter().map(|span| (edge.kind, span.clone())))
        .collect();
    let addresses = match caller {
        Some(caller) => kin_mcp::handlers::common::address_reference_sites(
            caller,
            &entry.reference_lines,
            &spans,
            site_text,
        ),
        None => Default::default(),
    };
    let unaddressed = kin_mcp::handlers::common::ReferenceSite::unaddressed();
    entry
        .reference_lines
        .iter()
        .map(|line| addresses.get(line).unwrap_or(&unaddressed).to_json())
        .collect()
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
    list_siblings: bool,
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

    if list_siblings && !neighbors.siblings.is_empty() {
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
        // Reachability is a question about repository entities. A symbol
        // outside the repository is not one, so its row says what it is and
        // which command answers about it, instead of reading as a miss.
        if let Some(node) = crate::commands::external_symbols::lookup(graph, raw_id)? {
            error_count += 1;
            let mut row = bulk_refs_error_row(
                raw_id,
                kin_mcp::handlers::external_symbols::EXTERNAL_SYMBOL_NOT_SERVED,
                request.compact,
            );
            row["symbol"] =
                kin_mcp::handlers::external_symbols::external_symbol_record_json(graph, &node)
                    .map_err(|error| {
                        anyhow::anyhow!("read external symbol {}: {error}", node.address())
                    })?;
            row["detail"] = serde_json::json!(format!(
                "{} names {}, declared outside this repository; `kin refs {}` lists the \
                 entities that call it.",
                node.address(),
                crate::commands::external_symbols::node_label(&node),
                node.address()
            ));
            results.push(row);
            continue;
        }
        if crate::commands::external_symbols::is_address(raw_id) {
            error_count += 1;
            results.push(bulk_refs_error_row(
                raw_id,
                "external symbol not found",
                request.compact,
            ));
            continue;
        }
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
        // The callers `kin refs` counts, by the same per-edge rule, for the
        // same reason: a bare-leaf receiver-method match is not evidence of
        // use, and neither is a bare name match that is not a call. Counting
        // every caller that was not all guesses put a caller holding one of
        // each in this count while `kin refs` held it, two numbers for one
        // target on two surfaces that share a collector so they cannot drift.
        let reference_count = collected
            .references
            .iter()
            .filter(|entry| entry.counts())
            .count();
        let receiver_name_candidate_count = collected
            .references
            .iter()
            .filter(|entry| entry.receiver_name_guess)
            .count();
        // Every caller `kin refs` holds whole under a candidate heading,
        // receiver-name guesses and bare name matches alike. Any one of them may
        // be a caller, so beside one the count is a floor and a zero is not an
        // absence: the row says so rather than reading as a proved zero.
        let unconfirmed_candidate_count = collected
            .references
            .iter()
            .filter(|entry| !entry.counts())
            .count();

        if !collected.missing_source_ids.is_empty() {
            incomplete_verdict_count += 1;
            let missing_source_count = collected.missing_source_ids.len();
            // The known count is the callers this surface counts and nothing
            // else, as on the complete path. A source whose record is missing
            // and a caller held as a candidate are both stated beside it, apart,
            // because adding them in made a held caller and a dangling source
            // read as two known references where none was counted.
            let mut row = serde_json::json!({
                "entity_id": entity_id.to_string(),
                "has_references": null,
                "reference_count": null,
                "known_reference_count": reference_count,
                "reference_count_complete": false,
                "verdict_complete": false,
                "verdict_reason": format!(
                    "graph reference authority incomplete: {missing_source_count} incoming source entity record(s) missing"
                ),
                "missing_source_entity_count": missing_source_count,
                "receiver_name_candidate_count": receiver_name_candidate_count,
                "unconfirmed_candidate_count": unconfirmed_candidate_count,
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

        let known_positive = reference_count > 0;
        let reference_count_complete = unconfirmed_candidate_count == 0;
        let has_references = if known_positive {
            Some(true)
        } else if reference_count_complete {
            Some(false)
        } else {
            None
        };
        match has_references {
            Some(true) => with_references += 1,
            Some(false) => without_references += 1,
            None => incomplete_verdict_count += 1,
        }

        let mut row = serde_json::json!({
            "entity_id": entity_id.to_string(),
            "has_references": has_references,
            "reference_count": reference_count_complete.then_some(reference_count),
            "receiver_name_candidate_count": receiver_name_candidate_count,
            "unconfirmed_candidate_count": unconfirmed_candidate_count,
        });
        if !reference_count_complete {
            row["known_reference_count"] = serde_json::json!(reference_count);
            row["reference_count_complete"] = serde_json::json!(false);
            row["verdict_complete"] = serde_json::json!(has_references.is_some());
            if !known_positive {
                row["verdict_reason"] =
                    serde_json::json!("unconfirmed candidate references remain");
            }
        }
        if !request.compact {
            row["name"] = serde_json::json!(entity.name);
            row["kind"] = serde_json::json!(format!("{:?}", entity.kind));
            row["file_path"] = serde_json::json!(entity.file_origin.as_ref().map(|p| p.0.clone()));
            row["matched_kinds"] = serde_json::json!(matched_kinds
                .into_iter()
                .map(relation_kind_label)
                .collect::<Vec<_>>());
        }
        results.push(row);
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
    /// The reference sites inside this caller, keyed by their 1-based line in
    /// the caller's file, ascending and deduplicated. Read from the same
    /// relation evidence and through the same helper `find_references` uses,
    /// because two surfaces answering "where" from two rules is how they came
    /// to disagree about "how many". The key is internal: a row prints each
    /// site inside its caller, never this line.
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
    /// Every edge behind this row, each with its own strength and its own
    /// sites: the record `find_references` cuts its rows by, so the two
    /// surfaces hold the same sites back. See [`Self::split_held_sites`].
    pub(crate) edges: Vec<ReferenceEdge>,
    /// Whether this row is the held part of a caller counted above: the sites
    /// only a weaker edge of that caller recorded.
    pub(crate) held_sites_of_counted_caller: bool,
}

impl ReferenceEntry {
    /// Whether one edge is held out of what this surface counts.
    ///
    /// Two grounds. A receiver-method call matched on its bare leaf name is a
    /// candidate, not a caller: nothing at the site says the receiver holds
    /// this type. And a bare name match that is not a call is what a
    /// local variable or a parameter sharing a function's name produces: on
    /// cli/cli v2.101.0 one Go function with one caller came back with
    /// seventeen referencing entities, sixteen of them `References` edges at
    /// `name_only` from locals in packages that never import it.
    ///
    /// A call at `name_only` is deliberately counted. The site is a call, which
    /// is evidence of use even when the destination was chosen by name, and the
    /// same store answers real cross-file calls that way: holding those out
    /// would understate a function that is genuinely called.
    ///
    /// `kin refs` cuts every caller by this and `kin refs --bulk-json` counts
    /// callers by it, through [`Self::counts`], so the two surfaces count the
    /// same callers.
    fn edge_is_held(edge: &ReferenceEdge) -> bool {
        edge.receiver_name_guess
            || (!edge.resolution.is_proven() && edge.kind != RelationKind::Calls)
    }

    /// Whether this caller counts as a reference on this surface: one of the
    /// edges behind it is not held.
    pub(crate) fn counts(&self) -> bool {
        self.edges.iter().any(|edge| !Self::edge_is_held(edge))
    }

    /// Cut a counted row into its proven sites and, when a weaker edge of the
    /// same caller recorded sites no counted edge did, a held row carrying
    /// those. A row none of whose edges this surface counts is held whole: the
    /// row rule counted one whose only call was a receiver-name guess beside a
    /// bare name match.
    ///
    /// A row used to print every site any of its edges recorded under its
    /// strongest resolution, so one proven edge confirmed sites nothing proved.
    /// On the gh CLI, `kin refs` printed `NewCreateContext ... (type_resolved)
    /// sites 649,678,697,723` for `Repository.RepoOwner`, and 649 and 697 are
    /// `RepoOwner()` calls on a `ghrepo.Interface` value that only the parser's
    /// receiver fan-out recorded. The same rule [`split_reference_row`] applies
    /// to `find_references`, under this surface's own grounds for holding a
    /// row.
    ///
    /// [`split_reference_row`]: kin_mcp::handlers::common::split_reference_row
    fn split_held_sites(self) -> (Option<ReferenceEntry>, Option<ReferenceEntry>) {
        let (held, counted): (Vec<ReferenceEdge>, Vec<ReferenceEdge>) =
            self.edges.iter().cloned().partition(Self::edge_is_held);
        if held.is_empty() {
            return (Some(self), None);
        }
        if counted.is_empty() {
            return (None, Some(self));
        }
        let counted_lines: std::collections::HashSet<u32> = counted
            .iter()
            .flat_map(|edge| edge.lines.iter().copied())
            .collect();
        let held: Vec<ReferenceEdge> = held
            .into_iter()
            .filter_map(|mut edge| {
                edge.lines.retain(|line| !counted_lines.contains(line));
                (!edge.lines.is_empty()).then_some(edge)
            })
            .collect();
        let counted_row = self.rebuilt_from(counted);
        if held.is_empty() {
            return (Some(counted_row), None);
        }
        let mut held_row = self.rebuilt_from(held);
        held_row.held_sites_of_counted_caller = true;
        (Some(counted_row), Some(held_row))
    }

    /// This caller's row, summarized again from `edges` alone.
    fn rebuilt_from(&self, edges: Vec<ReferenceEdge>) -> ReferenceEntry {
        let mut reference_lines: Vec<u32> = edges
            .iter()
            .flat_map(|edge| edge.lines.iter().copied())
            .collect();
        reference_lines.sort_unstable();
        reference_lines.dedup();
        let outside_caller_file: usize = edges.iter().map(|edge| edge.outside_caller_file).sum();
        let mut relation_kinds = Vec::new();
        for edge in &edges {
            push_relation_kind(&mut relation_kinds, edge.kind);
        }
        relation_kinds.sort_by_key(relation_kind_rank);
        ReferenceEntry {
            reference_lines_absent: if !reference_lines.is_empty() {
                None
            } else if edges.iter().any(|edge| edge.site_contract_gap == Some(kin_mcp::handlers::common::ReferenceLinesPartial::OccurrenceQualificationUnavailable)) {
                Some(ReferenceLinesAbsent::UnconfirmedSitesWithheld)
            } else if outside_caller_file > 0 {
                Some(ReferenceLinesAbsent::SpanOutsideCallerFile)
            } else {
                Some(ReferenceLinesAbsent::NoEvidenceSpan)
            },
            reference_lines,
            relation_kinds,
            resolution: edges
                .iter()
                .map(|edge| edge.resolution)
                .max()
                .unwrap_or(RelationResolution::NameOnly),
            receiver_name_guess: edges.iter().all(|edge| edge.receiver_name_guess),
            edges,
            held_sites_of_counted_caller: false,
            ..self.clone()
        }
    }
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

    for rel in kin_index::relation_read::relations_for_read(graph, entity_id)? {
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
        let mut edges = Vec::new();
        for rel in edges_by_caller.get(&source_id).into_iter().flatten() {
            for edge in kin_mcp::handlers::common::reference_edges(rel, entity.file_origin.as_ref())
            {
                reference_lines.extend(edge.lines.iter().copied());
                spans_outside_caller_file += edge.outside_caller_file;
                edges.push(edge);
            }
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
            edges,
            held_sites_of_counted_caller: false,
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
    match strip_dispatch_modifier(kind)
        .0
        .to_ascii_lowercase()
        .as_str()
    {
        "all" => Ok(vec![
            RelationKind::Calls,
            RelationKind::Imports,
            RelationKind::References,
        ]),
        "calls" | "call" => Ok(vec![RelationKind::Calls]),
        "imports" | "import" => Ok(vec![RelationKind::Imports]),
        "references" | "refs" | "reference" => Ok(vec![RelationKind::References]),
        other => anyhow::bail!(
            "invalid --kind '{}': use one of all, calls, imports, references, \
             each optionally suffixed with +dispatch",
            other
        ),
    }
}

/// Split a `--kind` value into the relation kinds it names and whether it asked
/// for interface-dispatch candidates beside them.
///
/// Carried on the existing argument rather than as a new request field because
/// `RefsRequest` crosses the daemon boundary and is constructed at a dozen call
/// sites; a suffix costs no wire change and no churn, and `calls+dispatch` reads
/// as what it is. `dispatch` alone means `calls+dispatch`, because a dispatch
/// candidate is only ever a call.
fn strip_dispatch_modifier(kind: &str) -> (&str, bool) {
    let trimmed = kind.trim();
    if trimmed.eq_ignore_ascii_case("dispatch") {
        return ("calls", true);
    }
    match trimmed.rsplit_once('+') {
        Some((head, tail)) if tail.eq_ignore_ascii_case("dispatch") => (head.trim(), true),
        _ => (trimmed, false),
    }
}

/// The interface-dispatch candidates for `target`, rendered.
///
/// Empty unless `target` is a Go method whose receiver type satisfies an
/// interface the graph holds. Every row is labelled a candidate and none is
/// added to the reference count above it, because a Go interface is satisfied
/// structurally: the graph can say a call through `Writer.Write` MAY have
/// reached `Buffer.Write`, and holds nothing that says it did. The heading
/// names the interface method each row came through so a reader can check the
/// claim rather than take it.
fn dispatch_candidate_lines(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    target: &Entity,
) -> Vec<String> {
    // Asked for and answered, at zero as well as above it. A section that
    // appears only when it has rows is one a reader never learns to look for,
    // and the reader who most needs this one is the reader who got an empty
    // reference list and is deciding whether the method is dead.
    if target.kind != kin_model::EntityKind::Method || target.language != kin_model::LanguageId::Go
    {
        return vec![format!(
            "No interface-dispatch candidates: they are computed for Go methods, and '{}' is \
             a {:?} in {}.",
            target.name, target.kind, target.language
        )];
    }
    // The focal IS the contract. Asked which interfaces it may be dispatched
    // through, the honest answer is that a caller here already reaches it
    // directly; what they are almost certainly after is the other direction,
    // which this section answers instead of printing "satisfies no interface"
    // about a thing that is one.
    match kin_index::dispatch::implementations_apply(graph, target) {
        Ok(true) => return implementation_candidate_lines(layout, graph, target),
        Ok(false) => {}
        Err(error) => {
            return vec![format!(
                "Interface-dispatch candidates unavailable: {error}"
            )]
        }
    }
    let targets = match kin_index::dispatch::interface_dispatch_targets(graph, target) {
        Ok(targets) if !targets.is_empty() => targets,
        Ok(_) => {
            return vec![
                "0 interface-dispatch candidates: this method's receiver type satisfies no \
                 interface this graph holds, so no call through an interface can reach it."
                    .to_string(),
            ]
        }
        // A walk that failed is not a candidate-free answer, and saying so is
        // not this command's verdict to change: the reference answer beside it
        // stands on its own edges. Reported rather than swallowed.
        Err(error) => {
            return vec![format!(
                "Interface-dispatch candidates unavailable: {error}"
            )]
        }
    };
    let callers = match kin_index::dispatch::dispatch_candidate_callers(graph, target, &targets) {
        Ok(callers) => callers,
        Err(error) => {
            return vec![format!(
                "Interface-dispatch candidates unavailable: {error}"
            )]
        }
    };
    let contracts: Vec<&str> = targets
        .iter()
        .map(|entry| entry.interface_method_name.as_str())
        .collect();
    if callers.is_empty() {
        return vec![format!(
            "0 interface-dispatch candidates. This method satisfies {}, and nothing calls {} \
             either.",
            contracts.join(", "),
            if contracts.len() == 1 { "it" } else { "them" }
        )];
    }
    let mut lines = vec![format!(
        "{} interface-dispatch candidate{} not counted above; each calls {}, which this \
         method's receiver type satisfies, so dispatch here is possible and unproven:",
        callers.len(),
        if callers.len() == 1 { "" } else { "s" },
        contracts.join(", "),
    )];
    for (caller_id, via) in &callers {
        let Ok(Some(caller)) = graph.get_entity(caller_id) else {
            continue;
        };
        lines.push(format!(
            "  {} {} [Calls] (dispatch_candidate) via {}",
            caller.name,
            entity_address(layout, graph, &caller),
            via.join(", ")
        ));
    }
    lines
}

/// Where a Go interface method is implemented, rendered.
///
/// The mirror of [`dispatch_candidate_lines`], for a focal that is the contract
/// rather than an implementation of one. Every row is labelled a candidate and
/// none is added to the reference count above it, for the reason that direction
/// gives: Go interface satisfaction is structural, so the graph can say this
/// method's receiver type satisfies the contract and holds nothing that says the
/// author wrote it to.
///
/// Each row names the declaration by its entity id. A reader handed only the
/// file still has to search it, and the measurement that found this gap scored
/// a file-granularity answer at zero on the site axis for exactly that reason;
/// the id is the declaration's own address, and the file follows it only as
/// the projection it is, never with a file line.
fn implementation_candidate_lines(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    target: &Entity,
) -> Vec<String> {
    let contract = kin_index::dispatch::split_qualified_method(&target.name)
        .map(|(owner, _)| owner.to_string())
        .unwrap_or_else(|| target.name.clone());
    let candidates = match kin_index::dispatch::interface_implementations(graph, target) {
        Ok(candidates) => candidates,
        // A walk that failed is not an implementation-free answer, and saying so
        // is not this command's verdict to change.
        Err(error) => return vec![format!("Interface implementations unavailable: {error}")],
    };
    if candidates.is_empty() {
        return vec![format!(
            "0 implementation candidates: no type this graph holds offers the whole method set \
             of {contract}, so nothing here implements this method."
        )];
    }
    let mut lines = vec![format!(
        "{} implementation candidate{} not counted above; each is a concrete method whose \
         receiver type satisfies {contract}, so the binding here is possible and unproven:",
        candidates.len(),
        if candidates.len() == 1 { "" } else { "s" },
    )];
    for candidate in &candidates {
        let Ok(Some(method)) = graph.get_entity(&candidate.method_id) else {
            continue;
        };
        lines.push(format!(
            "  {} {} [Implements] (implementation_candidate) on {}",
            candidate.method_name,
            entity_address(layout, graph, &method),
            candidate.receiver_name
        ));
    }
    lines
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
        build_bulk_refs_response, build_refs_response, build_refs_response_quoted, call_site_words,
        collect_graph_references, dispatch_candidate_lines, parse_relation_kinds,
        refs_not_found_guidance, strip_dispatch_modifier, BulkRefsRequest, BulkRefsResponse,
        Entity, EntityId, ReferenceLinesAbsent, RefsRequest, RefsResponse, RefsSpine, RefsView,
        RelationResolution, SiteText,
    };

    /// MEASUREMENT, not an assertion. Prints which of a C prototype and its
    /// definition `kin refs` resolves to, and why.
    ///
    /// `kin refs` ranks through `kin_ranking::entity_ranking::select_best_entity`,
    /// whose key has no definition term and whose earlier terms include incoming
    /// reference counts. Whether those counts separate a prototype from its
    /// definition depends on which one the linker bound the callers to, which is
    /// a fact about the graph rather than about this ranking, so it is measured
    /// before anything here is changed. Run with --nocapture.
    #[test]
    fn measure_which_c_twin_refs_resolves_to_today() {
        use kin_model::{EntityId, EntityStore as _, FilePathId};

        fn twin(
            base: &kin_model::Entity,
            file: &str,
            signature: &str,
            line: u32,
        ) -> kin_model::Entity {
            let file_id = FilePathId::new(file);
            let mut e = base.clone();
            e.id = EntityId::from_content(&file_id.0, &e.name, "Function", line);
            e.signature = signature.to_string();
            e.file_origin = Some(file_id);
            e
        }

        let (graph, _layout, _dir) = orphan_fixture();
        let base = graph
            .query_entities(&kin_model::EntityFilter::default())
            .unwrap()
            .into_iter()
            .next()
            .expect("the fixture holds at least one entity");

        let graph2 = kin_db::InMemoryGraph::new();
        let mut decl = twin(&base, "hiredis.h", "int f(int a);", 338);
        decl.name = "measuredTwin".to_string();
        decl.id = EntityId::from_content("hiredis.h", "measuredTwin", "Function", 338);
        let mut def = twin(&base, "hiredis.c", "int f(int a)", 1052);
        def.name = "measuredTwin".to_string();
        def.id = EntityId::from_content("hiredis.c", "measuredTwin", "Function", 1052);
        graph2.upsert_entity(&decl).unwrap();
        graph2.upsert_entity(&def).unwrap();

        let picked = kin_ranking::entity_ranking::select_best_entity(&graph2, "measuredTwin")
            .unwrap()
            .map(|e| {
                (
                    e.file_origin
                        .as_ref()
                        .map(|f| f.0.clone())
                        .unwrap_or_default(),
                    e.signature.clone(),
                )
            });
        println!("\nrefs select_best_entity picked: {picked:?}");
        println!("  declaration id {} ({})", decl.id, decl.signature);
        println!("  definition  id {} ({})", def.id, def.signature);
        println!(
            "  lower id is the {}",
            if decl.id < def.id {
                "DECLARATION"
            } else {
                "DEFINITION"
            }
        );
    }

    /// A miss has to be readable as a miss by a caller that only checks the exit
    /// code. For `kin refs` the guidance reads as an empty reference list, which
    /// is the shape a "safe to delete?" sweep acts on, so the discriminator
    /// beside the prose is what makes the command refuse (FIR-3071).
    #[test]
    fn refs_miss_carries_the_discriminator_and_not_just_the_prose() {
        let (graph, layout, _dir) = orphan_fixture();
        let healthy = kin_mcp::Envelope::daemon().with_health(&serde_json::json!({
            "initialized": true,
            "graph_loaded": true,
            "graph_entity_count": 3,
            "graph_generation": 1,
        }));

        let response = build_refs_response(
            &layout,
            &graph,
            &RefsRequest {
                entity: "definitelyMissingEntity".to_string(),
                kind: "all".to_string(),
            },
            &healthy,
        )
        .expect("refs response");

        let joined = response.lines.join("\n");
        assert!(joined.contains("not found"), "{joined}");
        assert_eq!(response.error.as_deref(), Some(joined.as_str()));
    }

    /// The other side of the same rule: a resolved answer must not carry the
    /// discriminator, or every `kin refs` would refuse.
    #[test]
    fn a_resolved_refs_answer_carries_no_error_discriminator() {
        let (graph, layout, _dir) = orphan_fixture();
        let healthy = kin_mcp::Envelope::daemon().with_health(&serde_json::json!({
            "initialized": true,
            "graph_loaded": true,
            "graph_entity_count": 3,
            "graph_generation": 1,
        }));

        let response = build_refs_response(
            &layout,
            &graph,
            &RefsRequest {
                entity: "orphan".to_string(),
                kind: "all".to_string(),
            },
            &healthy,
        )
        .expect("refs response");

        assert!(response.error.is_none(), "{:?}", response.error);
    }

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
            &super::refs_absence_payload(
                &graph,
                &target,
                &kinds,
                Some("orphan"),
                &kin_mcp::caller_arrival::observe_caller_arrival(&graph, &target),
                super::RefsSpine::absent(),
            ),
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

    /// THE TICKET'S NEGATIVE CONTROL, taken literally: a genuinely dead entity
    /// on a healthy enriched store must still read plainly, with no qualifier.
    ///
    /// This is the arm that stops the rollout becoming the FIR-2404 failure in
    /// its opposite costume, and it is not hypothetical. The first CI run of
    /// this change went red here, on the sibling e2e fixture, because a
    /// repository with no spine reports `cross_repo: not_configured` and the
    /// `find_references` gate counts that as a gap. Left alone, every empty
    /// `kin refs` on every non-federated repository would carry a warning about
    /// a federation the user never asked for. `only_unconfigured_federation` is
    /// what withholds that sentence, and this test is what proves it fires:
    /// all three reference classes are present here, so the coverage gate is
    /// satisfied and an unconfigured spine is the only thing left to object to.
    #[test]
    fn a_dead_focal_on_a_coverage_complete_store_reads_plainly() {
        // This fixture isolates other verdict inputs on a measured usable host.
        let _readiness = kin_mcp::edge_coverage::test_support::scoped_language_servers(&[
            kin_model::LanguageId::Rust,
        ]);
        use kin_model::relation::{Relation, RelationOrigin};
        use kin_model::{EntityStore, GraphNodeId};

        let (graph, layout, _dir) = orphan_fixture();
        let pick = |name: &str| {
            EntityStore::query_entities(
                &graph,
                &kin_model::graph::EntityFilter {
                    name_pattern: Some(name.to_string()),
                    ..Default::default()
                },
            )
            .unwrap()
            .into_iter()
            .next()
            .expect("fixture entity")
        };
        let caller = pick("caller");
        let callee = pick("callee");
        // Every class the query asks about, cross-file, between two entities
        // that are not the focal. The focal stays genuinely unreferenced.
        for kind in [
            RelationKind::Calls,
            RelationKind::Imports,
            RelationKind::References,
        ] {
            graph
                .upsert_relation(&Relation {
                    id: kin_model::ids::RelationId::new(),
                    kind,
                    src: GraphNodeId::Entity(caller.id),
                    dst: GraphNodeId::Entity(callee.id),
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
                entity: "orphan".to_string(),
                kind: "all".to_string(),
            },
            &refs_test_envelope(),
        )
        .expect("refs response");
        let rendered = response.lines.join("\n");

        assert!(
            rendered.contains("No incoming"),
            "the fixture must reach the empty arm or this test asserts nothing: {rendered}"
        );
        assert!(
            !rendered.contains("Kin cannot rule out"),
            "a dead focal on a coverage-complete store reads plainly; an unconfigured spine is \
             not a gap in this repository: {rendered}"
        );
    }

    #[test]
    fn refs_absence_inherits_local_binding_qualification() {
        // This fixture isolates other verdict inputs on a measured usable host.
        let _readiness = kin_mcp::edge_coverage::test_support::scoped_language_servers(&[
            kin_model::LanguageId::Rust,
        ]);
        use kin_mcp::source_derivation::{SourceDerivationObservation, SourceObservationScope};
        use kin_model::relation::{Relation, RelationOrigin};
        use kin_model::{EntityStore, GraphNodeId};
        use kin_review::source_derivation::{
            PriorLocalBindingStatus, SourceBinding, SourceDerivationReport,
        };

        let (graph, layout, _dir) = orphan_fixture();
        let entities = graph.query_entities(&Default::default()).unwrap();
        let caller = entities
            .iter()
            .find(|entity| entity.name == "caller")
            .unwrap();
        let callee = entities
            .iter()
            .find(|entity| entity.name == "callee")
            .unwrap();
        // Imports establish the language's importer observation too; without
        // one, caller arrival independently refuses before this test can
        // discriminate the local-binding states.
        for kind in [RelationKind::Calls, RelationKind::Imports] {
            graph
                .upsert_relation(&Relation {
                    id: kin_model::RelationId::new(),
                    kind,
                    src: GraphNodeId::Entity(caller.id),
                    dst: GraphNodeId::Entity(callee.id),
                    confidence: 1.0,
                    origin: RelationOrigin::Parsed,
                    created_in: None,
                    import_source: None,
                    evidence: Vec::new(),
                })
                .unwrap();
        }
        for (binding, outstanding, reason) in [
            (PriorLocalBindingStatus::NoRecordedDebt, Some(0), None),
            (
                PriorLocalBindingStatus::Unproven,
                None,
                Some("local_binding_unproven"),
            ),
            (
                PriorLocalBindingStatus::Outstanding,
                Some(1),
                Some("local_binding_outstanding"),
            ),
        ] {
            let mut report = SourceDerivationReport::unproven("fixture");
            report.body_binding = SourceBinding::Current;
            report.prior_local_binding = binding;
            report.outstanding_local_binding_obligations = outstanding;
            let mut envelope = refs_test_envelope();
            envelope.source_derivation = Some(SourceDerivationObservation {
                scope: SourceObservationScope::LiveHead,
                checked_scope: "admitted_inventory".into(),
                sampled: "selected_graph_before_query".into(),
                report: Some(report),
                admission_failure: None,
                local_binding_requirement:
                    kin_mcp::source_derivation::LocalBindingRequirement::Required,
            });
            let response = build_refs_response(
                &layout,
                &graph,
                &RefsRequest {
                    entity: "orphan".into(),
                    kind: "calls".into(),
                },
                &envelope,
            )
            .unwrap();
            let negative = response.negative.expect("empty references carry a verdict");
            assert_eq!(
                negative["safe_to_conclude_absent"],
                reason.is_none(),
                "{negative}"
            );
            assert_eq!(
                response.lines.join("\n").contains("Kin cannot rule out"),
                reason.is_some(),
                "{:?}",
                response.lines
            );
            if let Some(reason) = reason {
                assert!(
                    negative["trust_reason"].as_str().unwrap().contains(reason),
                    "{negative}"
                );
            }
        }
    }

    /// The federation guard must not swallow a REAL gap, and this is the state
    /// where it could.
    ///
    /// Two rounds of falsification to find it. Widening the guard to fire on any
    /// trust reason left every refs test green, including the degraded-daemon
    /// one, because a degraded daemon publishes a `degraded_signals` array and
    /// that arm is matched BEFORE the guard is ever consulted. The guard is only
    /// reachable when there is no absent class AND no degraded signal, so the
    /// only way to catch an over-broad one is a gap that lives in neither.
    ///
    /// `focal_resolution_ambiguous` is exactly that gap and it is not exotic: a
    /// repository holding two entities with one name, queried by that name,
    /// answers for one of them and says so. Coverage is complete here so the
    /// absent-class path cannot fire, and the daemon is sound so no signal is
    /// disclosed, which leaves the ambiguity as the one thing to say.
    #[test]
    fn an_ambiguous_focal_still_speaks_on_a_sound_coverage_complete_store() {
        use kin_model::relation::{Relation, RelationOrigin};
        use kin_model::{EntityStore, GraphNodeId};

        let (graph, layout, _dir) = orphan_fixture();
        let pick = |name: &str| {
            EntityStore::query_entities(
                &graph,
                &kin_model::graph::EntityFilter {
                    name_pattern: Some(name.to_string()),
                    ..Default::default()
                },
            )
            .unwrap()
            .into_iter()
            .next()
            .expect("fixture entity")
        };
        let first = pick("orphan");
        // A second entity carrying the same name, in another file. The query
        // resolves one and the other is what it could not speak for.
        let mut twin = first.clone();
        twin.id = kin_model::EntityId::new();
        twin.file_origin = Some(kin_model::FilePathId::new("src/twin.rs"));
        EntityStore::upsert_entity(&graph, &twin).unwrap();

        let caller = pick("caller");
        let callee = pick("callee");
        for kind in [
            RelationKind::Calls,
            RelationKind::Imports,
            RelationKind::References,
        ] {
            graph
                .upsert_relation(&Relation {
                    id: kin_model::ids::RelationId::new(),
                    kind,
                    src: GraphNodeId::Entity(caller.id),
                    dst: GraphNodeId::Entity(callee.id),
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
                entity: "orphan".to_string(),
                kind: "all".to_string(),
            },
            &refs_test_envelope(),
        )
        .expect("refs response");
        let rendered = response.lines.join("\n");
        let verdict = response
            .negative
            .as_ref()
            .expect("an empty refs answer carries a verdict");
        let reason = verdict["trust_reason"].as_str().unwrap_or_default();

        assert!(
            reason.contains("focal_resolution_ambiguous"),
            "the fixture must reach the ambiguity gap or this test asserts nothing: {reason}"
        );
        assert!(
            !rendered.contains("holds no cross-file"),
            "coverage is complete, so the absent-class path must not fire: {rendered}"
        );
        assert!(
            rendered.contains("Kin cannot rule out references it did not see"),
            "an ambiguous focal is a real gap and must be spoken, or the federation guard has \
             widened into silencing everything it was never meant to touch: {rendered}"
        );
    }

    /// The federation guard must not swallow a REAL gap.
    ///
    /// Written because falsification found the hole rather than because the
    /// design predicted it: making `only_unconfigured_federation` fire on any
    /// trust reason at all left every refs test green. Every one of them runs on
    /// a coverage-poor store, which renders the absent-class sentence and never
    /// consults the guard, so an over-broad guard silencing genuine degradation
    /// was invisible. Coverage is COMPLETE here on purpose, so the absent-class
    /// path cannot fire and the degraded signal is the only thing left to say.
    #[test]
    fn a_degraded_daemon_still_speaks_when_coverage_is_complete() {
        // This fixture isolates other verdict inputs on a measured usable host.
        let _readiness = kin_mcp::edge_coverage::test_support::scoped_language_servers(&[
            kin_model::LanguageId::Rust,
        ]);
        use kin_model::relation::{Relation, RelationOrigin};
        use kin_model::{EntityStore, GraphNodeId};

        let (graph, layout, _dir) = orphan_fixture();
        let pick = |name: &str| {
            EntityStore::query_entities(
                &graph,
                &kin_model::graph::EntityFilter {
                    name_pattern: Some(name.to_string()),
                    ..Default::default()
                },
            )
            .unwrap()
            .into_iter()
            .next()
            .expect("fixture entity")
        };
        let caller = pick("caller");
        let callee = pick("callee");
        for kind in [
            RelationKind::Calls,
            RelationKind::Imports,
            RelationKind::References,
        ] {
            graph
                .upsert_relation(&Relation {
                    id: kin_model::ids::RelationId::new(),
                    kind,
                    src: GraphNodeId::Entity(caller.id),
                    dst: GraphNodeId::Entity(callee.id),
                    confidence: 1.0,
                    origin: RelationOrigin::Parsed,
                    created_in: None,
                    import_source: None,
                    evidence: Vec::new(),
                })
                .unwrap();
        }

        // A held language-server sweep: a flag that describes the relations
        // refs reads, so it still bounds this answer.
        let degraded = kin_mcp::Envelope::daemon()
            .with_health(&serde_json::json!({
                "initialized": true,
                "graph_loaded": true,
                "graph_entity_count": 3,
                "graph_generation": 1,
            }))
            .with_memory_pressure(Some(&kin_core::memory_pressure::PressureRefusal {
                work: "lsp-sweep".to_string(),
                level: "critical".to_string(),
                reason: "host memory pressure is critical".to_string(),
                at_unix: 0,
                from_budget: false,
            }));
        let answer = |envelope: &kin_mcp::Envelope| {
            build_refs_response(
                &layout,
                &graph,
                &RefsRequest {
                    entity: "orphan".to_string(),
                    kind: "all".to_string(),
                },
                envelope,
            )
            .expect("refs response")
            .lines
            .join("\n")
        };
        let rendered = answer(&degraded);

        assert!(
            !rendered.contains("holds no cross-file"),
            "coverage is complete here, so the absent-class path must not fire or this test is \
             exercising the wrong branch: {rendered}"
        );
        assert!(
            rendered.contains("Kin cannot rule out references it did not see"),
            "a degraded daemon is a real gap and must still be spoken: {rendered}"
        );
        assert!(
            rendered.contains("memory_pressure"),
            "and it must name the signal the verdict disclosed: {rendered}"
        );

        // The other direction. A stopped embedding worker describes vectors,
        // which refs never reads, so it no longer puts this answer in doubt.
        let vectors_only = kin_mcp::Envelope::daemon().with_health(&serde_json::json!({
            "initialized": true,
            "graph_loaded": true,
            "graph_entity_count": 3,
            "graph_generation": 1,
            "embed_worker_failed": true,
        }));
        let rendered = answer(&vectors_only);
        assert!(!rendered.contains("holds no cross-file"), "{rendered}");
        assert!(
            !rendered.contains("Kin cannot rule out references it did not see"),
            "a flag that describes vectors must not bound an answer read off relations: {rendered}"
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

    /// A Go contract, one type that satisfies it and one that misses a method,
    /// with the implementation's declaration line set so a printed row can be
    /// checked against one.
    ///
    /// Hand built. The graph SHAPE it assumes is graded in
    /// `kin-index/tests/go_interface_implementations.rs`, which runs the real Go
    /// adapter over source; this test is about what `kin refs --kind dispatch`
    /// PRINTS for that shape.
    fn go_contract_fixture() -> (
        kin_db::InMemoryGraph,
        kin_core::KinLayout,
        tempfile::TempDir,
        kin_model::Entity,
    ) {
        use kin_model::{
            Entity, EntityId, EntityKind, EntityMetadata, EntityRole, EntityStore, FilePathId,
            FingerprintAlgorithm, Hash256, LanguageId, RelationId, RelationOrigin,
            SemanticFingerprint, SourceSpan, Visibility,
        };

        fn go(
            kind: EntityKind,
            name: &str,
            path: &str,
            signature: &str,
            line: Option<u32>,
        ) -> Entity {
            Entity {
                id: EntityId::new(),
                kind,
                name: name.to_string(),
                language: LanguageId::Go,
                fingerprint: SemanticFingerprint {
                    algorithm: FingerprintAlgorithm::V1TreeSitter,
                    ast_hash: Hash256::from_bytes([0; 32]),
                    signature_hash: Hash256::from_bytes([0; 32]),
                    behavior_hash: Hash256::from_bytes([0; 32]),
                    equivalence_hash: Hash256::from_bytes([0; 32]),
                    stability_score: 1.0,
                },
                file_origin: Some(FilePathId::new(path)),
                span: line.map(|line| SourceSpan {
                    file: FilePathId::new(path),
                    start_byte: 0,
                    end_byte: 1,
                    start_line: line,
                    start_col: 0,
                    end_line: line + 2,
                    end_col: 1,
                }),
                signature: signature.to_string(),
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
        let writer = go(
            EntityKind::Interface,
            "Writer",
            "internal/gh/contract.go",
            "type Writer interface",
            None,
        );
        let writer_write = go(
            EntityKind::Method,
            "Writer.Write",
            "internal/gh/contract.go",
            "Write(p []byte) (int, error)",
            None,
        );
        let writer_close = go(
            EntityKind::Method,
            "Writer.Close",
            "internal/gh/contract.go",
            "Close() error",
            None,
        );
        let buffer = go(
            EntityKind::Class,
            "Buffer",
            "internal/buf/buffer.go",
            "type Buffer struct",
            None,
        );
        let buffer_write = go(
            EntityKind::Method,
            "Buffer.Write",
            "internal/buf/buffer.go",
            "func (b *Buffer) Write(p []byte) (int, error)",
            Some(7),
        );
        let buffer_close = go(
            EntityKind::Method,
            "Buffer.Close",
            "internal/buf/buffer.go",
            "func (b *Buffer) Close() error",
            Some(12),
        );
        // The control: a Write and no Close, so it satisfies no Writer.
        let counter = go(
            EntityKind::Class,
            "Counter",
            "internal/count/counter.go",
            "type Counter struct",
            None,
        );
        let counter_write = go(
            EntityKind::Method,
            "Counter.Write",
            "internal/count/counter.go",
            "func (c *Counter) Write(p []byte) (int, error)",
            Some(5),
        );

        for entity in [
            &writer,
            &writer_write,
            &writer_close,
            &buffer,
            &buffer_write,
            &buffer_close,
            &counter,
            &counter_write,
        ] {
            EntityStore::upsert_entity(&graph, entity).unwrap();
        }
        for (owner, member) in [
            (&writer, &writer_write),
            (&writer, &writer_close),
            (&buffer, &buffer_write),
            (&buffer, &buffer_close),
            (&counter, &counter_write),
        ] {
            EntityStore::upsert_relation(
                &graph,
                &kin_model::Relation {
                    id: RelationId::new(),
                    kind: kin_model::RelationKind::Contains,
                    src: kin_model::GraphNodeId::Entity(owner.id),
                    dst: kin_model::GraphNodeId::Entity(member.id),
                    confidence: 1.0,
                    origin: RelationOrigin::Parsed,
                    created_in: None,
                    import_source: None,
                    evidence: Vec::new(),
                },
            )
            .unwrap();
        }
        let dir = tempfile::tempdir().unwrap();
        let layout = kin_core::KinLayout::new(dir.path().join(".kin"));
        (graph, layout, dir, writer_write)
    }

    /// Asked about a Go INTERFACE method, `--kind dispatch` used to say the
    /// focal's receiver type satisfies no interface, which describes a contract
    /// as if it were a failed implementation. It now answers the question a
    /// reader is actually asking there: where is this implemented.
    ///
    /// The declaration's id is the assertion. A compiler-graded measurement on
    /// `cli/cli` at `14d339d9` put Kin at zero correct implementation sites out
    /// of 142 because the file was the most it could name; the id is the
    /// declaration's own address, and its file follows only as the projection
    /// it is, with no file line.
    #[test]
    fn refs_dispatch_on_a_contract_names_where_it_is_implemented() {
        let (graph, layout, _dir, spec) = go_contract_fixture();
        let printed = dispatch_candidate_lines(&layout, &graph, &spec).join("\n");

        assert!(
            printed.contains("1 implementation candidate not counted above"),
            "{printed}"
        );
        let buffer_write =
            kin_model::EntityStore::query_entities(&graph, &kin_model::EntityFilter::default())
                .unwrap()
                .into_iter()
                .find(|entity| entity.name == "Buffer.Write")
                .expect("the fixture holds Buffer.Write");
        assert!(
            printed.contains(&format!(
                "Buffer.Write [{}] (projection: internal/buf/buffer.go) [Implements]",
                buffer_write.id
            )),
            "the row must name the declaration by its id, not only the file: {printed}"
        );
        assert!(
            !printed.contains("buffer.go:"),
            "no file line on a reference answer's row: {printed}"
        );
        assert!(printed.contains("(implementation_candidate)"), "{printed}");
        assert!(
            !printed.contains("Counter.Write"),
            "Counter has no Close, so it implements nothing here: {printed}"
        );
        assert!(
            !printed.contains("satisfies no interface"),
            "that sentence is about an implementation, and the focal is a contract: {printed}"
        );
    }

    /// The other direction is unchanged: a concrete method still gets the
    /// dispatch answer, and the two sections cannot be confused for each other.
    #[test]
    fn refs_dispatch_on_a_concrete_method_still_answers_dispatch() {
        let (graph, layout, _dir, _spec) = go_contract_fixture();
        let concrete = kin_model::EntityStore::query_entities(
            &graph,
            &kin_model::graph::EntityFilter::default(),
        )
        .unwrap()
        .into_iter()
        .find(|entity| entity.name == "Buffer.Write")
        .expect("the fixture holds the implementation");

        let printed = dispatch_candidate_lines(&layout, &graph, &concrete).join("\n");
        assert!(
            printed.contains("interface-dispatch candidate"),
            "a concrete method keeps the dispatch section: {printed}"
        );
        assert!(
            !printed.contains("implementation candidate"),
            "and never the implementations one: {printed}"
        );
    }

    /// A three-entity fixture whose focal has no incoming edges, with a
    /// same-file neighbour so the coverage observation has something to read.
    fn orphan_fixture() -> (
        kin_db::InMemoryGraph,
        kin_core::KinLayout,
        tempfile::TempDir,
    ) {
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

    /// `kin refs` reads the same caller readings `find_references` publishes.
    ///
    /// A Python focal whose importer holds a caller no call-site ledger
    /// describes yet: the MCP gate reads the family's `call_sites` block as
    /// owed and refuses the absence, and the CLI printed that block's
    /// "not settled" line while certifying the absence anyway, because its gate
    /// payload carried neither reading.
    #[test]
    fn an_owed_caller_in_the_family_qualifies_the_refs_absence_on_both_surfaces() {
        use kin_model::{
            Entity, EntityId, EntityKind, EntityMetadata, EntityRole, EntityStore, FilePathId,
            FingerprintAlgorithm, GraphNodeId, Hash256, LanguageId, Relation, RelationId,
            RelationOrigin, SemanticFingerprint, SourceSpan, Visibility,
        };
        fn entity(
            name: &str,
            kind: EntityKind,
            file: &str,
            span: Option<(usize, usize)>,
        ) -> Entity {
            let mut metadata = EntityMetadata::default();
            // The caller's file parses one call, so its callers are owed a
            // ledger rather than read as a file without calls.
            metadata.extra.insert(
                kin_parser::FILE_PARSED_CALL_SITES_KEY.to_string(),
                serde_json::json!(1),
            );
            Entity {
                id: EntityId::new(),
                kind,
                name: name.to_string(),
                language: LanguageId::Python,
                fingerprint: SemanticFingerprint {
                    algorithm: FingerprintAlgorithm::V1TreeSitter,
                    ast_hash: Hash256::from_bytes([0; 32]),
                    signature_hash: Hash256::from_bytes([0; 32]),
                    behavior_hash: Hash256::from_bytes([0; 32]),
                    equivalence_hash: Hash256::from_bytes([0; 32]),
                    stability_score: 1.0,
                },
                file_origin: Some(FilePathId::new(file)),
                span: span.map(|(start, end)| SourceSpan {
                    file: FilePathId::new(file),
                    start_byte: start,
                    end_byte: end,
                    start_line: 0,
                    start_col: 0,
                    end_line: 1,
                    end_col: 0,
                }),
                signature: name.to_string(),
                visibility: Visibility::Public,
                role: EntityRole::Source,
                doc_summary: None,
                metadata,
                lineage_parent: None,
                created_in: None,
                superseded_by: None,
            }
        }
        let graph = kin_db::InMemoryGraph::new();
        let focal = entity("unused_probe", EntityKind::Function, "callee.py", None);
        let caller_module = entity("caller", EntityKind::Module, "caller.py", Some((0, 60)));
        let caller = entity(
            "caller_probe",
            EntityKind::Function,
            "caller.py",
            Some((20, 60)),
        );
        for node in [&focal, &caller_module, &caller] {
            EntityStore::upsert_entity(&graph, node).unwrap();
        }
        EntityStore::upsert_relation(
            &graph,
            &Relation {
                id: RelationId::new(),
                kind: RelationKind::Imports,
                src: GraphNodeId::Entity(caller_module.id),
                dst: GraphNodeId::Entity(focal.id),
                confidence: 1.0,
                origin: RelationOrigin::Parsed,
                created_in: None,
                import_source: None,
                evidence: Vec::new(),
            },
        )
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let layout = kin_core::KinLayout::new(dir.path().join(".kin"));
        let envelope = refs_test_envelope();

        let response = build_refs_response(
            &layout,
            &graph,
            &RefsRequest {
                entity: "unused_probe".to_string(),
                kind: "calls".to_string(),
            },
            &envelope,
        )
        .expect("refs response");
        let arrival = kin_mcp::caller_arrival::observe_caller_arrival(&graph, &focal);
        let block = arrival.call_sites_block().expect("the family is tallied");
        assert_eq!(block["settled"], false, "{block}");
        assert_eq!(block["callers_owed_enrichment"], 2, "{block}");
        let payload = super::refs_absence_payload(
            &graph,
            &focal,
            &[RelationKind::Calls],
            Some("unused_probe"),
            &arrival,
            super::RefsSpine::absent(),
        );
        assert_eq!(
            payload[kin_mcp::call_sites::CALL_SITES_KEY],
            block,
            "the gate reads the block the answer prints"
        );
        assert_eq!(
            payload[kin_mcp::caller_arrival::CALLER_ARRIVAL_KEY],
            arrival.to_json()
        );
        let verdict = response
            .negative
            .as_ref()
            .expect("an empty refs answer carries a verdict");
        assert_eq!(
            verdict["safe_to_conclude_absent"],
            serde_json::json!(false),
            "{verdict}"
        );
        let rendered = response.lines.join("\n");
        assert!(
            rendered.contains("Kin cannot rule out references it did not see"),
            "{rendered}"
        );
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
    /// candidates give a row of `known_reference_count: 2` beside
    /// `receiver_name_candidate_count: 3`, never a single `5`, and the total is
    /// left open beside them.
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
        // Two, apart from the three candidates, and a floor beside them: any
        // candidate may still be a caller, so the total is not claimed.
        assert!(row["reference_count"].is_null(), "{row}");
        assert_eq!(row["known_reference_count"], 2, "{row}");
        assert_eq!(row["reference_count_complete"], false, "{row}");
        assert_eq!(row["receiver_name_candidate_count"], 3, "{row}");
        assert_eq!(row["unconfirmed_candidate_count"], 3, "{row}");
        assert_eq!(row["has_references"], true, "{row}");
        assert_eq!(row["verdict_complete"], true, "{row}");
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

    #[test]
    fn a_dispatch_suffix_keeps_the_relation_kinds_it_was_added_to() {
        assert_eq!(strip_dispatch_modifier("calls+dispatch"), ("calls", true));
        assert_eq!(strip_dispatch_modifier("all+dispatch"), ("all", true));
        assert_eq!(
            parse_relation_kinds("calls+dispatch").unwrap(),
            vec![RelationKind::Calls]
        );
        assert_eq!(
            parse_relation_kinds("all+dispatch").unwrap(),
            vec![
                RelationKind::Calls,
                RelationKind::Imports,
                RelationKind::References
            ]
        );
    }

    /// A dispatch candidate is always a call, so the bare word needs no second
    /// argument to mean something.
    #[test]
    fn bare_dispatch_means_calls_plus_dispatch() {
        assert_eq!(strip_dispatch_modifier("dispatch"), ("calls", true));
        assert_eq!(
            parse_relation_kinds("dispatch").unwrap(),
            vec![RelationKind::Calls]
        );
    }

    /// Every existing spelling must keep meaning exactly what it meant, because
    /// this suffix rides on an argument that crosses the daemon boundary.
    #[test]
    fn a_kind_without_the_suffix_asks_for_no_candidates() {
        for kind in ["all", "calls", "call", "imports", "import", "references"] {
            assert!(
                !strip_dispatch_modifier(kind).1,
                "{kind} must not turn on dispatch candidates"
            );
        }
    }

    #[test]
    fn an_unknown_kind_is_still_refused_with_the_suffix() {
        assert!(parse_relation_kinds("nonsense+dispatch").is_err());
        assert!(parse_relation_kinds("nonsense").is_err());
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
        let shared_rows: Vec<&str> = response
            .lines
            .iter()
            .map(String::as_str)
            .filter(|line| {
                line.starts_with("  shared_caller [") && line.contains("(projection: callers.rs) [")
            })
            .collect();
        assert_eq!(
            shared_rows.len(),
            2,
            "both same-metadata entity ids must be listed separately: {joined}"
        );
        assert_ne!(
            shared_rows[0], shared_rows[1],
            "each row names its own entity id: {joined}"
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
            // The one materialized, parser-certain caller. The missing source is
            // stated beside it rather than counted as a known caller.
            assert_eq!(row["known_reference_count"], 1);
            assert_eq!(row["reference_count_complete"], false);
            assert_eq!(row["verdict_complete"], false);
            assert_eq!(row["missing_source_entity_count"], 1);
            assert_eq!(row["unconfirmed_candidate_count"], 0);
            assert_eq!(row["receiver_name_candidate_count"], 0);
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

    /// `kin refs` prints the call sites of the callers in the files that
    /// import the focal's file, the block `find_references` tallies over the
    /// same files, so the two say the same thing about one store.
    #[test]
    fn refs_prints_the_call_sites_find_references_tallies() {
        use crate::commands::call_site_fixture::{admit, spanned};
        use kin_model::EntityStore as _;
        let graph = kin_db::InMemoryGraph::new();
        let mut target = spanned("find_note", "pkg/storage.py", 200, "def find_note():\n");
        target.file_origin = Some(kin_model::FilePathId::new("pkg/storage.py"));
        target.span = None;
        let mut target_module = spanned("storage", "pkg/storage.py", 0, "import db\n");
        target_module.kind = kin_model::EntityKind::Module;
        target_module.file_origin = Some(kin_model::FilePathId::new("pkg/storage.py"));
        target_module.span = None;
        let caller_body = "def test_it(db):\n    print(db)\n";
        let mut caller = spanned("test_it", "tests/test_storage.py", 20, caller_body);
        caller.file_origin = Some(kin_model::FilePathId::new("tests/test_storage.py"));
        let mut caller_module = spanned(
            "test_storage",
            "tests/test_storage.py",
            0,
            "import storage\n",
        );
        caller_module.kind = kin_model::EntityKind::Module;
        caller_module.file_origin = Some(kin_model::FilePathId::new("tests/test_storage.py"));
        admit(
            &graph,
            &[&target, &target_module, &caller, &caller_module],
            vec![(
                &caller,
                caller_body,
                vec![("print", kin_model::CallSiteState::ProvenOutside)],
            )],
        );
        graph
            .upsert_relation(&kin_model::Relation {
                id: kin_model::RelationId::new(),
                kind: kin_model::RelationKind::Imports,
                src: kin_model::GraphNodeId::Entity(caller_module.id),
                dst: kin_model::GraphNodeId::Entity(target_module.id),
                confidence: 1.0,
                origin: kin_model::relation::RelationOrigin::Parsed,
                created_in: None,
                import_source: None,
                evidence: Vec::new(),
            })
            .unwrap();
        let layout = kin_core::KinLayout::new(tempfile::tempdir().unwrap().path().join(".kin"));
        let response = build_refs_response(
            &layout,
            &graph,
            &RefsRequest {
                entity: target.id.to_string(),
                kind: "all".to_string(),
            },
            &refs_test_envelope(),
        )
        .unwrap();
        let block = response
            .call_sites
            .as_ref()
            .expect("refs carries the block");
        assert_eq!(block["scope"], kin_mcp::call_sites::FAMILY_SCOPE, "{block}");
        assert_eq!(block["callers_owed_enrichment"], 1, "{block}");
        // The block keeps its verdict code for a program to read.
        assert!(
            block["clauses"]
                .as_array()
                .is_some_and(|clauses| clauses.iter().any(|clause| clause
                    .as_str()
                    .is_some_and(|clause| clause.starts_with("call_sites_owed: ")))),
            "{block}"
        );
        // The terminal says the same thing in plain words, naming the file.
        let text = response.lines.join("\n");
        assert!(
            text.contains("Call sites in files that import storage.py: 1 across 2 callers."),
            "{text}"
        );
        assert!(
            text.contains(
                "  Still linking 1 of the 2 callers, so this answer may be missing calls from it."
            ),
            "{text}"
        );
        assert!(
            text.contains("  Run `kin daemon sweep` to finish linking now."),
            "{text}"
        );
        assert!(
            !text.contains("call_sites_owed") && !text.contains("the focal's file"),
            "the codes and the internal wording stay out of the text: {text}"
        );
    }

    fn words_focal() -> kin_model::Entity {
        let mut focal = crate::commands::call_site_fixture::spanned(
            "want_bytes",
            "src/itsdangerous/encoding.py",
            0,
            "def want_bytes():\n",
        );
        focal.file_origin = Some(kin_model::FilePathId::new("src/itsdangerous/encoding.py"));
        focal
    }

    fn words(
        tally: &kin_model::CallSiteTally,
        owed_outside: Option<&[kin_mcp::call_sites::OwedFile]>,
    ) -> Vec<String> {
        call_site_words(tally, owed_outside, 0, &words_focal())
    }

    /// Owed callers that never spell the function's name are left out of the
    /// count, and the answer says how many, as the daemon's block does.
    #[test]
    fn owed_callers_that_cannot_name_the_focal_are_counted_out_loud() {
        let tally = kin_model::CallSiteTally {
            callers: 3,
            sites: 5,
            ..Default::default()
        };
        let lines = call_site_words(&tally, Some(&[]), 2, &words_focal());
        assert_eq!(
            lines[1],
            "  2 more callers there are still linking, but never spell want_bytes, so they \
             can't call it by name and aren't counted."
        );
        let lines = call_site_words(&tally, Some(&[]), 1, &words_focal());
        assert_eq!(
            lines[1],
            "  1 more caller there is still linking, but never spells want_bytes, so it can't \
             call it by name and isn't counted."
        );
        let lines = call_site_words(&tally, Some(&[]), 0, &words_focal());
        assert!(
            !lines.iter().any(|line| line.contains("never spell")),
            "{lines:?}"
        );
    }

    /// A clone whose linking is still owed says so, with every count and the
    /// command that finishes it, in the words a person reads.
    #[test]
    fn owed_callers_are_disclosed_in_plain_words() {
        let tally = kin_model::CallSiteTally {
            callers: 69,
            callers_owed_enrichment: 60,
            callers_owed_derivation: 8,
            ..Default::default()
        };
        assert_eq!(
            words(&tally, Some(&[])),
            vec![
                "Call sites in files that import encoding.py: 0 across 69 callers.",
                "  Still linking 68 of the 69 callers, so this answer may be missing calls from \
                 them.",
                "  Run `kin daemon sweep` to finish linking now.",
            ]
        );
    }

    /// After linking, each unproven kind of call site keeps its own count, and
    /// a single site reads in the singular.
    #[test]
    fn unproven_call_sites_keep_their_counts() {
        let mut tally = kin_model::CallSiteTally {
            callers: 69,
            sites: 155,
            ..Default::default()
        };
        tally
            .by_state
            .insert(kin_model::SiteStateKind::ProvenTarget, 146);
        tally.by_state.insert(kin_model::SiteStateKind::Binding, 1);
        tally
            .by_state
            .insert(kin_model::SiteStateKind::Unresolved, 8);
        assert_eq!(
            words(&tally, Some(&[])),
            vec![
                "Call sites in files that import encoding.py: 155 across 69 callers.",
                "  1 of the 155 call sites calls through a variable or other value, which \
                 doesn't prove what it calls, so it may call want_bytes.",
                "  8 of the 155 call sites were checked, but their targets couldn't be proven, \
                 so one of them may call want_bytes.",
            ]
        );
        // The same counts the verdict clauses carry, so the two cannot drift.
        let clauses = tally.clauses(kin_mcp::call_sites::FAMILY_SCOPE);
        assert!(clauses
            .iter()
            .any(|clause| clause.starts_with("binding_unproven: 1 of the 155")));
        assert!(clauses
            .iter()
            .any(|clause| clause.starts_with("call_sites_unresolved: 8 of the 155")));
    }

    /// Every other unproven kind has its own sentence, and none falls back to
    /// a code.
    #[test]
    fn every_unproven_kind_has_its_own_sentence() {
        for (kind, words_for_it) in [
            (
                kin_model::SiteStateKind::ServerFailed,
                "got no answer because the language server timed out, crashed or failed",
            ),
            (
                kin_model::SiteStateKind::NotInBuild,
                "are in files no build of the repository compiles",
            ),
            (
                kin_model::SiteStateKind::ProofContextStale,
                "were linked under a language-server setup that has since changed",
            ),
        ] {
            let mut tally = kin_model::CallSiteTally {
                callers: 3,
                sites: 10,
                ..Default::default()
            };
            tally.by_state.insert(kind, 2);
            let text = words(&tally, Some(&[])).join("\n");
            assert!(
                text.contains(&format!(
                    "  2 of the 10 call sites {words_for_it}, so one of them may call want_bytes."
                )),
                "{kind:?}: {text}"
            );
            assert!(!text.contains("not settled"), "{kind:?}: {text}");
        }
    }

    /// Callers no resolver can link on this machine are counted, with why,
    /// and the answer does not tell the reader to wait for them.
    #[test]
    fn unlinkable_callers_say_why_and_that_waiting_wont_help() {
        let mut tally = kin_model::CallSiteTally {
            callers: 4,
            sites: 2,
            callers_unproven_no_resolver: 3,
            ..Default::default()
        };
        tally.no_resolver.insert(
            "python: no language server for it is installed or wired".to_string(),
            3,
        );
        tally
            .by_state
            .insert(kin_model::SiteStateKind::ProvenTarget, 2);
        let text = words(&tally, Some(&[]));
        assert_eq!(
            text[1],
            "  3 of the 4 callers can't be linked on this machine (python: no language server \
             for it is installed or wired), so this answer may be missing calls from them, and \
             waiting won't change that."
        );
        assert!(
            !text.iter().any(|line| line.contains("kin daemon sweep")),
            "a sweep does not settle these: {text:?}"
        );
    }

    /// Callers still owed outside the importing files are counted and named,
    /// and the command is said once however much is owed.
    #[test]
    fn owed_callers_outside_the_importing_files_are_named() {
        let tally = kin_model::CallSiteTally {
            callers: 5,
            sites: 9,
            callers_owed_enrichment: 1,
            by_state: [(kin_model::SiteStateKind::ProvenTarget, 9)]
                .into_iter()
                .collect(),
            ..Default::default()
        };
        let outside: Vec<kin_mcp::call_sites::OwedFile> = (0..7)
            .map(|index| kin_mcp::call_sites::OwedFile {
                file: format!("src/app/view_{index}.py"),
                callers: if index == 0 { 1 } else { 2 },
            })
            .collect();
        let text = words(&tally, Some(&outside));
        assert_eq!(
            text,
            vec![
                "Call sites in files that import encoding.py: 9 across 5 callers.",
                "  Still linking 1 of the 5 callers, so this answer may be missing calls from it.",
                "  Still linking 13 callers in 7 files that don't import encoding.py. A caller \
                 can reach want_bytes without importing encoding.py, so this answer may be \
                 missing one of them.",
                "    src/app/view_0.py (1 caller)",
                "    src/app/view_1.py (2 callers)",
                "    src/app/view_2.py (2 callers)",
                "    src/app/view_3.py (2 callers)",
                "    src/app/view_4.py (2 callers)",
                "    and 2 more files",
                "  Run `kin daemon sweep` to finish linking now.",
            ]
        );
    }

    /// An index that could not be read is a gap, said as one, and never
    /// reads as a settled answer.
    #[test]
    fn an_unreadable_index_is_disclosed() {
        let tally = kin_model::CallSiteTally {
            callers: 2,
            sites: 3,
            by_state: [(kin_model::SiteStateKind::ProvenTarget, 3)]
                .into_iter()
                .collect(),
            ..Default::default()
        };
        let text = words(&tally, None);
        assert_eq!(
            text[1],
            "  Kin couldn't read its index of python code, so callers in files that don't \
             import encoding.py weren't checked, and one that reaches want_bytes without \
             importing encoding.py may be missing from this answer."
        );
        assert!(
            !text.iter().any(|line| line.contains("accounted for")),
            "{text:?}"
        );
    }

    /// Only an answer with nothing owed, nothing unlinkable and no unproven
    /// site says it is accounted for.
    #[test]
    fn a_settled_answer_says_so() {
        let tally = kin_model::CallSiteTally {
            callers: 2,
            sites: 3,
            by_state: [(kin_model::SiteStateKind::ProvenTarget, 3)]
                .into_iter()
                .collect(),
            ..Default::default()
        };
        assert!(tally.is_settled());
        assert_eq!(
            words(&tally, Some(&[])),
            vec![
                "Call sites in files that import encoding.py: 3 across 2 callers.",
                "  Every one of them is accounted for.",
            ]
        );
    }

    /// A store where `count` callers in one test file each call `find_note`
    /// once, and that file imports the focal's, so the call-site block is
    /// taken over it and reads as owed. Each caller's call sits two lines
    /// below its first line, and `call` is the text written there.
    fn many_callers_fixture(
        count: usize,
        name: impl Fn(usize) -> String,
        call: &str,
    ) -> (
        kin_db::InMemoryGraph,
        kin_model::Entity,
        std::collections::HashMap<EntityId, String>,
    ) {
        many_callers_fixture_with(count, name, call, false)
    }

    /// [`many_callers_fixture`], and with `stray` one more caller, `reindex`
    /// in a file that imports nothing of the focal's, whose one call no
    /// resolver settled. A store-wide reading that cannot rule out the focal
    /// being held as a value keeps that call as a candidate.
    fn many_callers_fixture_with(
        count: usize,
        name: impl Fn(usize) -> String,
        call: &str,
        stray: bool,
    ) -> (
        kin_db::InMemoryGraph,
        kin_model::Entity,
        std::collections::HashMap<EntityId, String>,
    ) {
        use crate::commands::call_site_fixture::{admit, spanned};
        use kin_model::EntityStore as _;
        let graph = kin_db::InMemoryGraph::new();
        let mut target = spanned("find_note", "pkg/storage.py", 200, "def find_note():\n");
        target.file_origin = Some(kin_model::FilePathId::new("pkg/storage.py"));
        target.span = None;
        let mut target_module = spanned("storage", "pkg/storage.py", 0, "import db\n");
        target_module.kind = kin_model::EntityKind::Module;
        target_module.file_origin = Some(kin_model::FilePathId::new("pkg/storage.py"));
        target_module.span = None;
        let mut caller_module = spanned(
            "test_storage",
            "tests/test_storage.py",
            0,
            "import storage\n",
        );
        caller_module.kind = kin_model::EntityKind::Module;
        caller_module.file_origin = Some(kin_model::FilePathId::new("tests/test_storage.py"));
        caller_module.span = None;
        let mut callers = Vec::new();
        let mut bodies = std::collections::HashMap::new();
        for index in 0..count {
            let name = name(index);
            let body = format!("def {name}(db):\n    db.open()\n    {call}\n");
            let start = 1_000 * (index + 1);
            let mut caller = spanned(&name, "tests/test_storage.py", start, &body);
            caller.file_origin = Some(kin_model::FilePathId::new("tests/test_storage.py"));
            let span = caller.span.as_mut().unwrap();
            span.start_line = 10 * (index as u32 + 1);
            span.end_line = span.start_line + 3;
            let site_start = start + body.find(call).unwrap();
            let site = kin_model::SourceSpan {
                file: kin_model::FilePathId::new("tests/test_storage.py"),
                start_byte: site_start,
                end_byte: site_start + call.len(),
                start_line: span.start_line + 2,
                start_col: 4,
                end_line: span.start_line + 2,
                end_col: 4,
            };
            bodies.insert(caller.id, body);
            callers.push((caller, site));
        }
        let mut entities: Vec<&kin_model::Entity> = vec![&target, &target_module, &caller_module];
        entities.extend(callers.iter().map(|(caller, _)| caller));
        const STRAY_BODY: &str = "def reindex(db):\n    db.rebuild()\n";
        let mut reindex = spanned("reindex", "pkg/maintenance.py", 90_000, STRAY_BODY);
        reindex.file_origin = Some(kin_model::FilePathId::new("pkg/maintenance.py"));
        let mut ledgers = Vec::new();
        if stray {
            entities.push(&reindex);
            ledgers.push((
                &reindex,
                STRAY_BODY,
                vec![(
                    "db.rebuild()",
                    kin_model::CallSiteState::Unresolved {
                        reason: kin_model::UnresolvedReason::NoAnswer,
                    },
                )],
            ));
        }
        admit(&graph, &entities, ledgers);
        let relation = |kind, src: &kin_model::Entity, dst: &kin_model::Entity, evidence| {
            kin_model::Relation {
                id: kin_model::RelationId::new(),
                kind,
                src: kin_model::GraphNodeId::Entity(src.id),
                dst: kin_model::GraphNodeId::Entity(dst.id),
                confidence: 1.0,
                origin: kin_model::relation::RelationOrigin::Parsed,
                created_in: None,
                import_source: None,
                evidence,
            }
        };
        graph
            .upsert_relation(&relation(
                RelationKind::Imports,
                &caller_module,
                &target_module,
                Vec::new(),
            ))
            .unwrap();
        for (caller, site) in &callers {
            graph
                .upsert_relation(&relation(
                    RelationKind::Calls,
                    caller,
                    &target,
                    vec![kin_model::relation::RelationEvidence {
                        source_span: Some(site.clone()),
                        ..Default::default()
                    }],
                ))
                .unwrap();
        }
        (graph, target, bodies)
    }

    /// Each caller's body as the fixture wrote it, starting at its span.
    fn fixture_bodies(
        bodies: std::collections::HashMap<EntityId, String>,
    ) -> crate::commands::external_symbols::BodySiteText<impl FnMut(&Entity) -> Option<String>>
    {
        crate::commands::external_symbols::BodySiteText::new(move |caller: &Entity| {
            bodies.get(&caller.id).cloned()
        })
    }

    fn view_response(
        graph: &kin_db::InMemoryGraph,
        target: &kin_model::Entity,
        site_text: &dyn SiteText,
        view: Option<RefsView>,
    ) -> RefsResponse {
        let layout = kin_core::KinLayout::new(tempfile::tempdir().unwrap().path().join(".kin"));
        build_refs_response_quoted(
            &layout,
            graph,
            &RefsRequest {
                entity: target.id.to_string(),
                kind: "all".to_string(),
            },
            &refs_test_envelope(),
            RefsSpine::absent(),
            site_text,
            view,
        )
        .unwrap()
    }

    /// A terminal answer about a symbol with more callers than a screen holds
    /// leads with what qualifies it, the call-site summary and every clause
    /// that leaves it unsettled, then lists the first twenty callers, name
    /// first with each site inside the caller, then counts the rest and says
    /// where to read them. The complete listing keeps every caller.
    #[test]
    fn a_terminal_answer_lists_twenty_callers_after_what_qualifies_it() {
        let (graph, target, bodies) = many_callers_fixture(
            25,
            |index| format!("test_find_note_case_{index:02}"),
            "find_note(db, 'x')",
        );
        let text = fixture_bodies(bodies);
        let view = RefsView {
            width: 80,
            callers: RefsView::CALLERS,
        };
        let lines = view_response(&graph, &target, &text, Some(view)).lines;
        let joined = lines.join("\n");

        let rows: Vec<usize> = lines
            .iter()
            .enumerate()
            .filter(|(_, line)| line.starts_with("    test_find_note_case_"))
            .map(|(index, _)| index)
            .collect();
        assert_eq!(rows.len(), 20, "the first twenty callers: {joined}");
        for index in &rows {
            let row = &lines[*index];
            assert!(
                row.ends_with("+2 find_note"),
                "name first, then the site inside the caller and its text: {row:?}"
            );
            assert!(!row.contains("test_storage.py:"), "no file line: {row:?}");
        }
        assert!(
            lines.contains(&"  and 5 more; --all or --json for the full list".to_string()),
            "{joined}"
        );
        assert_eq!(
            lines
                .iter()
                .filter(|line| *line == "  (projection: tests/test_storage.py)")
                .count(),
            1,
            "the callers are grouped under the file they are projected into: {joined}"
        );

        // What qualifies the answer is read before any row.
        let count_line = lines
            .iter()
            .position(|line| line.starts_with("referenced by 25 entities"))
            .unwrap_or_else(|| panic!("no count line: {joined}"));
        let summary = lines
            .iter()
            .position(|line| line.starts_with("Call sites in"))
            .unwrap_or_else(|| panic!("no call-site summary: {joined}"));
        // The plain words the complete listing uses, every clause of them: the
        // owed callers, and the command that finishes the linking.
        let unsettled: Vec<usize> = lines
            .iter()
            .enumerate()
            .filter(|(_, line)| {
                line.starts_with("  Still linking") || line.starts_with("  Run `kin daemon sweep`")
            })
            .map(|(index, _)| index)
            .collect();
        assert!(
            unsettled.len() >= 2,
            "the owed callers leave it unsettled, and the answer says how to finish: {joined}"
        );
        let full_disclosure: Vec<String> = view_response(&graph, &target, &text, None)
            .lines
            .into_iter()
            .skip_while(|line| !line.starts_with("Call sites in"))
            .take_while(|line| line.starts_with("Call sites in") || line.starts_with("  "))
            .collect();
        // Width-fitting wraps a long clause between words, so the two are
        // compared word for word.
        let words = |text: &str| text.split_whitespace().collect::<Vec<_>>().join(" ");
        let terminal_words = words(&joined);
        assert!(!full_disclosure.is_empty(), "{joined}");
        for clause in &full_disclosure {
            assert!(
                terminal_words.contains(&words(clause)),
                "the terminal answer drops no clause of the disclosure: {clause:?} \
                 against {joined}"
            );
        }
        assert!(summary < count_line, "{joined}");
        assert!(
            unsettled.iter().all(|index| *index < count_line),
            "{joined}"
        );
        assert!(count_line < rows[0], "{joined}");

        // The complete listing, which `--all`, `--json` and a pipe read, keeps
        // every caller with its id and projection.
        let full = view_response(&graph, &target, &text, None);
        let full_rows = full
            .lines
            .iter()
            .filter(|line| {
                line.starts_with("  test_find_note_case_")
                    && line.contains("(projection: tests/test_storage.py) [Calls]")
            })
            .count();
        assert_eq!(full_rows, 25, "{:#?}", full.lines);
        assert!(!full.lines.iter().any(|line| line.contains("more; --all")));
    }

    /// The call-site disclosure leads every layout, and the unproven call
    /// sites a store-wide reading keeps are part of it: the terminal view and
    /// the complete listing `--all`, `--json` and a pipe read both give the
    /// summary, what leaves it unsettled and the candidate lines before the
    /// count and any row.
    #[test]
    fn the_call_site_disclosure_and_its_candidates_lead_every_layout() {
        let (graph, target, bodies) = many_callers_fixture_with(
            3,
            |index| format!("test_find_note_case_{index:02}"),
            "find_note(db, 'x')",
            true,
        );
        let text = fixture_bodies(bodies);
        let temp = tempfile::tempdir().unwrap();
        let kin_root = temp.path().join(".kin");
        std::fs::create_dir_all(kin_root.join("objects")).unwrap();
        let layout = kin_core::KinLayout::new(kin_root);
        let authority = kin_mcp::handlers::RequestRepositoryAuthority::pinned(
            kin_core::LocalRepositoryAuthorityBinding::from_parts(
                kin_model::RepositoryId::new("refs-disclosure-test").unwrap(),
                kin_model::WorkspaceId::new(),
                std::sync::Arc::new(kin_db::LocalFileBackend::new(layout.kindb_dir())),
            ),
        );
        let spine = RefsSpine {
            repo_id: "",
            spine: ::kin_spine::DaemonSpine::Absent,
            call_site_sources: Some((
                &authority,
                kin_mcp::handlers::common::EntitySourceScope::WorkspaceHead,
            )),
        };
        for view in [
            Some(RefsView {
                width: 100,
                callers: RefsView::CALLERS,
            }),
            None,
        ] {
            let lines = build_refs_response_quoted(
                &layout,
                &graph,
                &RefsRequest {
                    entity: target.id.to_string(),
                    kind: "all".to_string(),
                },
                &refs_test_envelope(),
                spine,
                &text,
                view,
            )
            .unwrap()
            .lines;
            let joined = lines.join("\n");
            let at = |prefix: &str| {
                lines
                    .iter()
                    .position(|line| line.starts_with(prefix))
                    .unwrap_or_else(|| panic!("{view:?}: no line starting {prefix:?}: {joined}"))
            };
            let summary = at("Call sites in");
            let candidates = at("Unproven call sites that could call find_note");
            let count = at("referenced by 3 entities");
            let first_row = lines
                .iter()
                .position(|line| line.contains("test_find_note_case_"))
                .unwrap_or_else(|| panic!("{view:?}: no caller row: {joined}"));
            assert!(
                summary < candidates && candidates < count && count < first_row,
                "{view:?}: the disclosure, candidates included, leads the rows: {joined}"
            );
            // The candidate block is whole before the count: its heading, then
            // the kept call counted by why it is kept, and nothing of it after.
            let kept = at("  1 more are kept because of");
            assert!(candidates < kept && kept < count, "{view:?}: {joined}");
            assert!(
                !lines[count..]
                    .iter()
                    .any(|line| line.contains("Unproven call sites")
                        || line.contains("are kept because of")),
                "{view:?}: no candidate line follows the rows: {joined}"
            );
        }
    }

    /// No line of a terminal answer is wider than the terminal, and none is
    /// broken inside a word: a name or a site's text too long for the room
    /// left is cut with an ellipsis, and prose wraps between words.
    #[test]
    fn no_line_of_a_terminal_answer_is_wider_than_the_terminal() {
        let (graph, target, bodies) = many_callers_fixture(
            23,
            |index| {
                format!(
                    "TestStorageRoundTripsEveryNoteKindThroughTheLongestHelperChain.case_{index}"
                )
            },
            "result = storage_helpers.with_a_rather_long_attribute_chain.find_note(db, 'x')",
        );
        let text = fixture_bodies(bodies);
        let words = |lines: &[String]| -> std::collections::HashSet<String> {
            lines
                .iter()
                .flat_map(|line| line.split(' '))
                .filter(|word| !word.is_empty())
                .map(str::to_string)
                .collect()
        };
        // Every word an unconstrained layout prints, so a word the fitted
        // layout prints must be one of them or be cut with an ellipsis.
        let unconstrained = view_response(
            &graph,
            &target,
            &text,
            Some(RefsView {
                width: 10_000,
                callers: RefsView::CALLERS,
            }),
        );
        let known = words(&unconstrained.lines);
        for width in [40, 57, 80, 120] {
            let lines = view_response(
                &graph,
                &target,
                &text,
                Some(RefsView {
                    width,
                    callers: RefsView::CALLERS,
                }),
            )
            .lines;
            for line in &lines {
                assert!(
                    console::measure_text_width(line) <= width,
                    "{width} columns: {line:?} is {} wide",
                    console::measure_text_width(line)
                );
            }
            for word in words(&lines) {
                assert!(
                    known.contains(&word) || word.ends_with('\u{2026}'),
                    "{width} columns: {word:?} is part of a word: {lines:#?}"
                );
            }
            assert!(
                lines
                    .iter()
                    .any(|line| line.contains("and 3 more; --all or --json")),
                "{width} columns: {lines:#?}"
            );
        }
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

    /// A reference row names its caller by entity id and the file it is
    /// projected into, and carries no file line, whether or not the caller has
    /// a span.
    ///
    /// This listing once printed `file:line` from raw 0-based graph rows, one
    /// line above every reference. It now prints no file line at all, so the
    /// fixture keeps the caller on graph row 41 to show neither row 41 nor line
    /// 42 reaches the listing.
    #[test]
    fn a_reference_row_names_its_caller_by_id_and_projection_and_no_file_line() {
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

        // A row names its caller by id and the file it is projected into,
        // never by a file line, whether or not the caller carries a span.
        for (caller, file) in [
            (&spanned_caller, "spanned.rs"),
            (&spanless_caller, "spanless.rs"),
        ] {
            let address = format!(" [{}] (projection: {file}) [", caller.id);
            assert!(
                joined.contains(&format!("  {}{address}", caller.name)),
                "{} must be addressed by id and projection: {joined}",
                caller.name
            );
            assert!(
                !joined.contains(&format!("{file}:")),
                "no file line may reach the listing: {joined}"
            );
        }
        assert!(
            response.lines[0].ends_with(&format!(
                "-> probe_symbol (Function) [{}] (projection: target_mod.rs)",
                target.id
            )),
            "the header names the focal the same way: {joined}"
        );
    }

    /// `kin refs` answers for a symbol outside the repository by the address
    /// the MCP tools serve for it, and by its bare id: the symbol's name,
    /// package, version and whether it is a standard library, then one row per
    /// caller with its sites addressed inside the caller and the proof. A site
    /// is never a file line, and the answer says its list is a floor.
    #[test]
    fn refs_lists_the_callers_of_an_external_symbol_with_their_sites_and_proof() {
        let store = crate::commands::external_symbols::fixture::external_store(true);
        let dir = tempfile::tempdir().unwrap();
        let layout = kin_core::KinLayout::new(dir.path().join(".kin"));
        for entity in [store.address(), store.node.id.to_string()] {
            let response = build_refs_response(
                &layout,
                &store.graph,
                &RefsRequest {
                    entity: entity.clone(),
                    kind: "all".to_string(),
                },
                &refs_test_envelope(),
            )
            .expect("refs response");
            assert!(response.error.is_none(), "{entity}: {:?}", response.error);
            assert!(
                response.negative.is_none(),
                "an answer with callers claims no absence"
            );
            let text = response.lines.join("\n");
            assert!(
                response.lines[0].contains(
                    "Array.map (external symbol, npm typescript 5.6.3, standard library)"
                ),
                "{text}"
            );
            assert!(text.contains("referenced by 1 entity:"), "{text}");
            let row = response
                .lines
                .iter()
                .find(|line| line.trim_start().starts_with("render ["))
                .unwrap_or_else(|| panic!("no caller row: {text}"));
            assert_eq!(
                row.trim(),
                format!(
                    "render [{}] (projection: src/app.ts) [Calls] (type_resolved) sites +2, +5 \
                     proven_external by lsp:tsserver 5.6.3 (lsp_definition)",
                    store.caller.id
                ),
                "{text}"
            );
            assert!(text.contains("a site is +N"), "{text}");
            assert!(text.contains("this list is a floor"), "{text}");
            assert!(!text.contains("not found"), "{text}");
            assert!(!text.contains("kin xref"), "{text}");
        }
    }

    /// A name no repository entity carries reaches the symbol outside the
    /// repository it names, by each spelling `find_references` accepts, and
    /// the answer is the one its address gets, led by what the name named.
    #[test]
    fn refs_reaches_an_external_symbol_by_its_name() {
        let store = crate::commands::external_symbols::fixture::external_store(true);
        let dir = tempfile::tempdir().unwrap();
        let layout = kin_core::KinLayout::new(dir.path().join(".kin"));
        let refs = |entity: &str| {
            build_refs_response(
                &layout,
                &store.graph,
                &RefsRequest {
                    entity: entity.to_string(),
                    kind: "all".to_string(),
                },
                &refs_test_envelope(),
            )
            .expect("refs response")
        };
        let by_address = refs(&store.address());
        let descriptors = store.node.symbol.clone();
        let whole = format!("{} {}", store.node.canonical_source, store.node.symbol);
        for (name, matched) in [
            ("Array.map", "name"),
            (descriptors.as_str(), "SCIP descriptor chain"),
            (whole.as_str(), "whole SCIP symbol"),
        ] {
            let response = refs(name);
            assert!(response.error.is_none(), "{name}: {:?}", response.error);
            assert_eq!(
                response.lines[0],
                format!(
                    "{name} names no entity in this repository; it names Array.map (external \
                     symbol, npm typescript 5.6.3, standard library), matched by its {matched}."
                )
            );
            // The header quotes what was asked; everything under it is the
            // answer the address gets.
            assert_eq!(
                response.lines[1],
                by_address.lines[0].replace(&store.address(), name),
                "{name}"
            );
            assert_eq!(response.lines[2..], by_address.lines[1..], "{name}");
            assert_eq!(response.negative, by_address.negative, "{name}");
            assert_eq!(response.call_sites, by_address.call_sites, "{name}");
        }
    }

    /// A name several symbols outside the repository share lists each by its
    /// address and answers about none of them, the candidates `find_references`
    /// lists for the same name.
    #[test]
    fn refs_lists_every_external_symbol_a_shared_name_names() {
        use kin_model::{EntityStore as _, ScipDescriptor, ScipPackage};
        let store = crate::commands::external_symbols::fixture::external_store(true);
        let other = kin_model::ExternalSymbol::new(
            ScipPackage::new("npm", "typescript", "5.7.2").unwrap(),
            vec![
                ScipDescriptor::namespace("lib.es5.d.ts"),
                ScipDescriptor::type_("Array"),
                ScipDescriptor::method("map"),
            ],
        )
        .unwrap()
        .to_reference()
        .unwrap();
        store
            .graph
            .apply_transaction_delta(&kin_model::TransactionDelta {
                external_reference_deltas: vec![kin_model::ExternalReferenceDelta::Added {
                    new: other.clone(),
                }],
                ..kin_model::TransactionDelta::default()
            })
            .expect("hold a second Array.map");
        let dir = tempfile::tempdir().unwrap();
        let layout = kin_core::KinLayout::new(dir.path().join(".kin"));
        let response = build_refs_response(
            &layout,
            &store.graph,
            &RefsRequest {
                entity: "Array.map".to_string(),
                kind: "all".to_string(),
            },
            &refs_test_envelope(),
        )
        .expect("refs response");
        let text = response.lines.join("\n");
        assert_eq!(response.error.as_deref(), Some(text.as_str()));
        assert!(
            response.lines[0]
                .starts_with("Array.map names 2 symbols declared outside this repository"),
            "{text}"
        );
        assert!(text.contains(&store.address()), "{text}");
        assert!(
            text.contains(&format!("external_reference:{}", other.id)),
            "{text}"
        );
        assert!(!text.contains("referenced by"), "{text}");
        assert!(response.negative.is_none() && response.call_sites.is_none());

        let (named, matched) =
            kin_mcp::handlers::external_symbols::external_symbols_named(&store.graph, "Array.map")
                .unwrap();
        assert_eq!(
            matched,
            kin_mcp::handlers::external_symbols::MATCHED_DISPLAY_NAME
        );
        let mut addresses: Vec<String> = named.iter().map(|node| node.address()).collect();
        addresses.sort();
        let mut listed: Vec<String> = response.lines[1..]
            .iter()
            .filter_map(|line| line.split_whitespace().next().map(str::to_string))
            .collect();
        listed.sort();
        assert_eq!(
            listed, addresses,
            "the CLI lists what find_references lists"
        );
    }

    /// With no caller of the asked kind, the answer says so about the symbol
    /// and carries the verdict `find_references` reaches on the same payload,
    /// which cannot certify an absence the resolver's proofs only floor.
    #[test]
    fn refs_on_an_external_symbol_with_no_caller_of_the_kind_carries_the_verdict() {
        let store = crate::commands::external_symbols::fixture::external_store(true);
        let dir = tempfile::tempdir().unwrap();
        let layout = kin_core::KinLayout::new(dir.path().join(".kin"));
        let response = build_refs_response(
            &layout,
            &store.graph,
            &RefsRequest {
                entity: store.address(),
                kind: "imports".to_string(),
            },
            &refs_test_envelope(),
        )
        .expect("refs response");
        assert!(response.error.is_none(), "{:?}", response.error);
        let text = response.lines.join("\n");
        assert!(text.contains("No incoming Imports relations"), "{text}");
        assert!(text.contains("this list is a floor"), "{text}");
        let verdict = response
            .negative
            .as_ref()
            .expect("an empty answer's verdict");
        assert_eq!(verdict["safe_to_conclude_absent"], false, "{verdict}");
    }

    /// An address this graph holds no symbol under is refused as that, not as
    /// an entity miss whose `kin xref` hint cannot find a symbol outside every
    /// repository.
    #[test]
    fn refs_refuses_an_unknown_external_address_precisely() {
        let store = crate::commands::external_symbols::fixture::external_store(true);
        let dir = tempfile::tempdir().unwrap();
        let layout = kin_core::KinLayout::new(dir.path().join(".kin"));
        let address = "external_reference:00000000-0000-8000-8000-000000000000";
        let response = build_refs_response(
            &layout,
            &store.graph,
            &RefsRequest {
                entity: address.to_string(),
                kind: "all".to_string(),
            },
            &refs_test_envelope(),
        )
        .expect("refs response");
        let error = response.error.expect("a refusal");
        assert!(
            error.contains("names no symbol outside the repository"),
            "{error}"
        );
        assert!(!error.contains("kin xref"), "{error}");
    }

    /// Bulk mode classifies repository entities by reachability, which says
    /// nothing about a symbol outside the repository, so such a row is an
    /// error row naming what it is and the command that answers about it.
    #[test]
    fn bulk_refs_names_an_external_symbol_row_instead_of_a_miss() {
        let store = crate::commands::external_symbols::fixture::external_store(true);
        let response = build_bulk_refs_response(
            &store.graph,
            &BulkRefsRequest {
                entity_ids: vec![
                    store.address(),
                    store.node.id.to_string(),
                    store.caller.id.to_string(),
                ],
                kind: "Any".to_string(),
                compact: true,
            },
        )
        .expect("bulk refs");
        assert_eq!(response.error_count, 2, "{:?}", response.results);
        for row in &response.results[..2] {
            assert_bulk_error_row(row, true, "external_symbol_not_served");
            assert_eq!(row["symbol"]["name"], "Array.map", "{row}");
            assert_eq!(row["symbol"]["id"], store.address(), "{row}");
            let detail = row["detail"].as_str().unwrap_or_default();
            assert!(
                detail.contains(&format!("kin refs {}", store.address())),
                "{row}"
            );
        }
        assert!(response.results[2].get("error").is_none());
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
