// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};
use kin_model::EntityStore;
use kin_model::{Entity, TokenBudget};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContextRequest {
    /// The first focal, kept as its own field so a client and a daemon that
    /// predate several focals still speak to each other.
    #[serde(default)]
    pub entity: String,
    pub budget: String,
    #[serde(default)]
    pub assistant: Option<String>,
    /// Focal entities beyond the first, each a name, a pinned name or an id in
    /// the syntax [`crate::entity_ref`] parses.
    ///
    /// A daemon predating this field ignores it and answers about `entity`
    /// alone, which is a pack for one end of the question. That is why
    /// [`ContextResponse::multi_focal`] exists and why the CLI refuses a
    /// response missing it: a quietly narrowed answer is worse than an error.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entities: Vec<String>,
    /// A question to resolve the focals from, through the graph's own ranking.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub question: Option<String>,
    /// The most focals a question may resolve to. Defaults to
    /// [`QUESTION_FOCAL_MAX`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_focals: Option<usize>,
}

/// How many focals a question resolves to unless the caller says otherwise.
///
/// The ranking is ordered, so taking more of it costs budget on entities the
/// question named less clearly. Five is what the demo measured a chain question
/// needs: fewer lost an end of the chain, more spent the pack on near misses.
pub const QUESTION_FOCAL_MAX: usize = 5;

impl ContextRequest {
    /// One focal, the way the surface has always taken it.
    pub fn one(entity: impl Into<String>, budget: impl Into<String>) -> Self {
        Self {
            entity: entity.into(),
            budget: budget.into(),
            ..Self::default()
        }
    }

    /// Every focal token the caller gave, in order, first field first.
    pub fn focal_tokens(&self) -> Vec<String> {
        let mut tokens = Vec::new();
        if !self.entity.trim().is_empty() {
            tokens.push(self.entity.trim().to_string());
        }
        for entity in &self.entities {
            if !entity.trim().is_empty() {
                tokens.push(entity.trim().to_string());
            }
        }
        tokens
    }

    /// Whether this request needs the multi-focal assembler.
    ///
    /// One named focal and no question is the surface's original shape and
    /// keeps its original code path, byte for byte, so nothing that depends on
    /// today's rendering moves under it.
    pub fn is_multi_focal(&self) -> bool {
        self.question.is_some() || self.focal_tokens().len() > 1
    }
}

/// Names the structured half of [`ContextResponse`]. A daemon predating it
/// answers with `lines` only and leaves this empty, which is what lets `--json`
/// refuse loudly instead of emitting a document missing everything it promises.
pub const CONTEXT_RESPONSE_SCHEMA_VERSION: &str = "kin-context-response-v1";

/// What the pack was built for. The human rendering opens with the same three
/// facts, so a structured caller is not reading a different resolution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextTarget {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub budget_tokens: usize,
}

/// How the pack's dependency section was filled.
///
/// A pack whose focal has no dependency edge falls back to neighbours from the
/// focal's own file, and the pack carries no field saying so: the tag lives in
/// a comment inside each entry's content. `kin context` and the
/// `get_context_pack` MCP tool report these same facts under these same names,
/// so a reader moving between the two surfaces is not learning two
/// vocabularies for one selection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextDependencySelection {
    /// `dependency_edges` or `same_file_fallback`.
    pub source: String,
    /// Rows in `pack.dependency_signatures` the focal depends on, plus any
    /// same-file fallback rows. This is the count the `Dependencies` line
    /// reports.
    pub returned: usize,
    /// Rows in `pack.dependency_signatures` that depend on the focal instead.
    /// They ride real edges and stay in the pack; they are simply not
    /// dependencies, and counting them as such reported callers as callees.
    #[serde(default)]
    pub dependents_returned: usize,
    /// Same-file neighbours the fallback had to choose from. Zero when the
    /// fallback did not run.
    pub same_file_candidates: usize,
    /// Same-file neighbours the cap or the token budget dropped.
    pub same_file_dropped: usize,
}

/// The context response, structured half added alongside the rendered lines.
///
/// `lines` stays first and required so an older client keeps decoding this, and
/// the structured fields default so this client keeps decoding an older daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextResponse {
    pub lines: Vec<String>,
    #[serde(default)]
    pub schema_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<ContextTarget>,
    /// Absent when the entity did not resolve, which is the one case the human
    /// rendering answers with guidance rather than a pack.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pack: Option<kin_model::context::ContextPack>,
    /// Absent for the same reason as `pack`, and from a daemon that predates
    /// the field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dependency_selection: Option<ContextDependencySelection>,
    /// What the token budget refused, per section, under the same group names
    /// and the same shape the `get_context_pack` MCP tool publishes.
    ///
    /// Empty when the budget refused nothing, so a reader keying on this map
    /// never has to tell "lost nothing" from "does not report losses": the
    /// human rendering says the same thing on the same run.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub budget_elisions: BTreeMap<String, ContextElision>,
    /// Set when the query resolved to no entity, so a caller reading the exit
    /// code is not handed guidance as though it were a pack (FIR-3071). The same
    /// text stays in `lines` for a client that predates this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Every focal this pack was built from, in the order the caller named
    /// them. `target` stays the first of them so a reader written against one
    /// focal keeps working.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub focals: Vec<ContextTarget>,
    /// How a multi-focal pack was assembled: which focals, how each resolved,
    /// what each contributed, the routes between them and what the budget
    /// refused.
    ///
    /// Absent on a single-focal pack, and absent from a daemon that predates
    /// multi-focal packs. The CLI reads the second case as a refusal rather
    /// than as a pack, because a daemon that quietly answered about one focal
    /// has answered a different question.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multi_focal: Option<kin_context::MultiFocalReport>,
    /// What the rendered output actually costs, by the estimator kin builds
    /// packs with (`kin_context::estimate_tokens`, a structure-aware count with
    /// a 15 percent margin).
    ///
    /// Reported on every pack, including the single-focal one, which can exceed
    /// its budget by design: every section there keeps a row whatever the
    /// budget says. A caller subtracting a pack from its own context window
    /// needs the number the bytes cost, not the number it asked for.
    #[serde(default)]
    pub measured_tokens: usize,
    /// Focal tokens that resolved to nothing, in the caller's own spelling.
    ///
    /// A pack built from two of three named focals answers a narrower question
    /// than the one asked, and the difference is invisible in the pack itself.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unresolved: Vec<String>,
}

/// What one pack section lost to the token budget.
///
/// The same four fields the MCP `elisions` map carries, so a reader moving
/// between `kin context --json` and `get_context_pack` is not learning two
/// vocabularies for one fact.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContextElision {
    /// Rows the token budget refused.
    pub elided: usize,
    /// Rows the pack still carries.
    pub kept: usize,
    /// Rows that were candidates, which is `kept + elided`.
    pub total: usize,
    /// What withheld them. `token_budget` here, named rather than assumed so a
    /// cut made later for another reason cannot be read as this one.
    pub reason: String,
}

/// The reason code a row the pack's token budget refused carries. Matches
/// `kin_mcp::budget::ELISION_REASON_TOKEN_BUDGET`, which is the same fact
/// reported on the other surface.
pub const CONTEXT_ELISION_REASON_TOKEN_BUDGET: &str = "token_budget";

pub async fn run(
    entities: Vec<String>,
    question: Option<String>,
    budget: String,
    assistant: Option<String>,
    max_focals: Option<usize>,
    json: bool,
) -> Result<()> {
    let mut entities = entities;
    let question = question.filter(|text| !text.trim().is_empty());
    if entities.is_empty() && question.is_none() {
        anyhow::bail!(
            "kin context needs an entity or a question: `kin context <entity> [<entity>...]` or `kin context --question \"<what you want to know>\"`"
        );
    }
    let entity = if entities.is_empty() {
        String::new()
    } else {
        entities.remove(0)
    };
    let request = ContextRequest {
        entity,
        budget,
        assistant,
        entities,
        question,
        max_focals,
    };

    let layout = crate::commands::require_repository_layout()?;
    let _scope = announce_active_scope(&layout, "context").await?;
    let response = run_daemon_context(&layout, &request).await?;

    if answered_a_narrower_question(&request, &response) {
        anyhow::bail!(
            "the running daemon does not support multi-focal context packs; restart it with the current Kin build"
        );
    }

    if json {
        if response.schema_version.is_empty() {
            anyhow::bail!(
                "the running daemon does not support structured context packs; restart it with the current Kin build"
            );
        }
        if let Some(error) = response.error {
            anyhow::bail!(error);
        }
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        // Refuse before printing, so a miss leaves stdout empty.
        if let Some(error) = response.error {
            anyhow::bail!(error);
        }
        for line in response.lines {
            println!("{line}");
        }
    }
    Ok(())
}

async fn run_daemon_context(
    layout: &kin_core::KinLayout,
    request: &ContextRequest,
) -> Result<ContextResponse> {
    let daemon_url = std::env::var("KIN_DAEMON_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(Some)
        .unwrap_or(crate::daemon_client::resolve_daemon_url(layout).await?);
    let base_url =
        daemon_url.ok_or_else(|| crate::daemon_client::daemon_required_error("context", layout))?;
    let client = crate::daemon_client::DaemonClient::from_base_url(base_url)?;
    client
        .context(request)
        .await
        .context("daemon context failed")
}

pub fn build_context_response(
    graph: &kin_db::InMemoryGraph,
    request: &ContextRequest,
) -> Result<ContextResponse> {
    if request.is_multi_focal() {
        return build_multi_focal_response(graph, request);
    }
    let token_budget = parse_budget(&request.budget)?;

    let assistant_hint = assistant_hint_from(request.assistant.as_deref());

    let Some(target) = resolve_context_target(graph, &request.entity)? else {
        let lines = context_not_found_guidance(&request.entity);
        let measured_tokens = kin_context::estimate_tokens(&lines.join("\n"));
        return Ok(ContextResponse {
            error: Some(lines.join("\n")),
            lines,
            // Stamped even here: an unresolved entity is an answer, and leaving
            // this empty would report it as a daemon too old to answer at all.
            schema_version: CONTEXT_RESPONSE_SCHEMA_VERSION.to_string(),
            target: None,
            pack: None,
            dependency_selection: None,
            budget_elisions: BTreeMap::new(),
            focals: Vec::new(),
            multi_focal: None,
            measured_tokens,
            unresolved: vec![request.entity.clone()],
        });
    };
    let opts = kin_context::ContextOptions {
        budget: token_budget,
        max_depth: 2,
        include_tests: true,
        include_contracts: true,
        include_traffic: false,
        assistant_hint,
    };

    let (pack, selection) =
        kin_context::build_context_pack_with_provenance(graph, &target.id, &opts)?;
    let dependents_returned = count_dependents(&pack, &selection);
    let dependencies_returned = pack.dependency_signatures.len() - dependents_returned;

    let max_tokens = token_budget.max_tokens();
    // What the budget refused, per section. The pack's rows are the whole of
    // what the rendering used to show, and a section trimmed from twelve rows
    // to six printed "Dependencies: 6 entries", which is exactly what a focal
    // with six dependencies prints. Nothing on the surface distinguished them.
    let elisions = budget_elisions(
        &selection,
        &[
            (kin_context::group::DEPENDENCIES, dependencies_returned),
            (kin_context::group::DEPENDENTS, dependents_returned),
            (
                kin_context::group::TRANSITIVE_DEPS,
                pack.transitive_deps.len(),
            ),
            (kin_context::group::TESTS, pack.tests.len()),
            (kin_context::group::CONTRACTS, pack.contracts.len()),
            (kin_context::group::WORK_ITEMS, pack.work_items.len()),
            (kin_context::group::ANNOTATIONS, pack.annotations.len()),
        ],
    );
    let withheld = |group: &str| -> String { budget_note(&elisions, group, max_tokens) };

    let mut lines = vec![
        format!("Context pack for '{}' ({:?}):", target.name, target.kind),
        format!(
            "  Budget: {}/{} tokens{}",
            pack.actual_tokens,
            max_tokens,
            // A pack over its own budget is not a bug and not a rounding
            // error: every section that had a candidate keeps one, so a
            // section can never render as empty when the graph found rows.
            // Saying so is cheaper than leaving a reader to explain a number
            // that looks wrong.
            if pack.actual_tokens > max_tokens {
                " (over budget: every section keeps a row)"
            } else {
                ""
            }
        ),
        format!("  Focal: {} entries", pack.focal_entities.len()),
        format!(
            "  Dependencies: {} entries{}",
            dependencies_returned,
            dependency_selection_note(&selection, dependencies_returned, &elisions, max_tokens)
        ),
        format!(
            "  Dependents: {} entries{}",
            dependents_returned,
            withheld(kin_context::group::DEPENDENTS)
        ),
        format!(
            "  Transitive: {} entries{}",
            pack.transitive_deps.len(),
            withheld(kin_context::group::TRANSITIVE_DEPS)
        ),
        format!(
            "  Contracts: {} entries{}",
            pack.contracts.len(),
            withheld(kin_context::group::CONTRACTS)
        ),
        format!(
            "  Tests: {} entries{}",
            pack.tests.len(),
            withheld(kin_context::group::TESTS)
        ),
    ];
    // Work items and annotations have never had a line of their own, because a
    // pack usually carries none and a row of zeroes is noise. A section the
    // budget took rows from is the case where saying nothing is the defect, so
    // the line appears exactly when there is something to report.
    for (group, label, held) in [
        (
            kin_context::group::WORK_ITEMS,
            "Work items",
            pack.work_items.len(),
        ),
        (
            kin_context::group::ANNOTATIONS,
            "Annotations",
            pack.annotations.len(),
        ),
    ] {
        let note = withheld(group);
        if held == 0 && note.is_empty() {
            continue;
        }
        lines.push(format!("  {label}: {held} entries{note}"));
    }
    // One line naming the lever, because a per-section count says what was lost
    // and not what recovers it. Present only when something was cut, so a whole
    // pack never carries a note about a cut that did not happen.
    let total_elided: usize = elisions.values().map(|elision| elision.elided).sum();
    if total_elided > 0 {
        lines.push(format!(
            "  Raise --budget above {max_tokens} to recover the {total_elided} \
             {} the token budget withheld.",
            if total_elided == 1 {
                "entry"
            } else {
                "entries"
            }
        ));
    }
    // The same sentence the multi-focal method line carries, in the header a
    // person reads first. A pack whose ranking could not see half the store is
    // a different answer from one whose ranking saw all of it, and until now
    // neither pack said which it was.
    lines.push(format!(
        "  Semantic coverage: {}",
        coverage_sentence(&crate::commands::locate::local_semantic_coverage(
            graph,
            Some(graph)
        ))
    ));

    lines.push(String::new());
    lines.push("--- Context Pack ---".to_string());

    for entry in &pack.focal_entities {
        lines.push(entry.content.clone());
    }
    for entry in &pack.dependency_signatures {
        lines.push(entry.content.clone());
    }
    for entry in &pack.transitive_deps {
        lines.push(entry.content.clone());
    }

    let measured_tokens = kin_context::estimate_tokens(&lines.join("\n"));
    let focal_target = ContextTarget {
        id: target.id.to_string(),
        name: target.name.clone(),
        kind: format!("{:?}", target.kind),
        budget_tokens: token_budget.max_tokens(),
    };

    Ok(ContextResponse {
        lines,
        schema_version: CONTEXT_RESPONSE_SCHEMA_VERSION.to_string(),
        target: Some(focal_target.clone()),
        dependency_selection: Some(ContextDependencySelection {
            source: selection.source().as_str().to_string(),
            returned: dependencies_returned,
            dependents_returned,
            same_file_candidates: selection.same_file_candidates(),
            same_file_dropped: selection.same_file_dropped(),
        }),
        budget_elisions: elisions,
        error: None,
        focals: vec![focal_target],
        multi_focal: None,
        measured_tokens,
        unresolved: Vec::new(),
        pack: Some(pack),
    })
}

/// What the token budget refused, per section, keyed by the group names the two
/// surfaces share.
///
/// Sections with nothing refused are absent rather than present with a zero, so
/// the map answers "did this pack lose anything" by being empty or not.
fn budget_elisions(
    selection: &kin_context::DependencySelection,
    sections: &[(&str, usize)],
) -> BTreeMap<String, ContextElision> {
    let mut elisions = BTreeMap::new();
    for (group, kept) in sections {
        let elided = selection.budget_elided(group);
        if elided == 0 {
            continue;
        }
        elisions.insert(
            (*group).to_string(),
            ContextElision {
                elided,
                kept: *kept,
                total: kept.saturating_add(elided),
                reason: CONTEXT_ELISION_REASON_TOKEN_BUDGET.to_string(),
            },
        );
    }
    elisions
}

/// The parenthetical a section line carries when the budget took rows from it.
fn budget_note(
    elisions: &BTreeMap<String, ContextElision>,
    group: &str,
    max_tokens: usize,
) -> String {
    match elisions.get(group) {
        Some(elision) => format!(
            " ({} withheld by the {max_tokens}-token budget)",
            elision.elided
        ),
        None => String::new(),
    }
}

/// Rows in the pack's dependency section that depend on the focal.
///
/// Counted off the rows themselves rather than tracked as a separate total, so
/// the number cannot drift from the list it describes when the token budget
/// drops a row.
fn count_dependents(
    pack: &kin_model::context::ContextPack,
    selection: &kin_context::DependencySelection,
) -> usize {
    pack.dependency_signatures
        .iter()
        .filter(|entry| {
            selection.relation_for(&entry.entity_id)
                == kin_context::DependencyRelation::DependentEdge
        })
        .count()
}

/// The parenthetical after the dependency count in the human rendering.
///
/// Six rows on a class with twenty-four methods and no dependency edges look
/// exactly like six dependencies, so the rendering says which selection ran and
/// what the cap dropped rather than leaving the reader to infer it from a
/// comment buried in each entry.
fn dependency_selection_note(
    selection: &kin_context::DependencySelection,
    returned: usize,
    elisions: &BTreeMap<String, ContextElision>,
    max_tokens: usize,
) -> String {
    let budget = budget_note(elisions, kin_context::group::DEPENDENCIES, max_tokens);
    match selection.source() {
        kin_context::DependencySource::DependencyEdges if returned == 0 => budget,
        kin_context::DependencySource::DependencyEdges => format!(" (dependency edges){budget}"),
        // Both causes, separately, whenever both are real. Nothing recovers the
        // cap and `--budget` recovers the other, so folding them into one
        // shortfall would rebuild the two-causes-one-number reading this
        // disclosure exists to remove. Naming both is what keeps the whole
        // shortfall accountable while the causes stay distinct.
        kin_context::DependencySource::SameFileFallback => {
            let candidates = selection.same_file_candidates();
            let kept = selection.same_file_kept();
            let refused = elisions
                .get(kin_context::group::DEPENDENCIES)
                .map_or(0, |elision| elision.elided);
            let capped = candidates.saturating_sub(kept).saturating_sub(refused);
            let mut note =
                format!(" (same-file neighbors, no dependency edges; kept {kept} of {candidates}");
            if refused > 0 {
                note.push_str(&format!(
                    "; {refused} withheld by the {max_tokens}-token budget"
                ));
            }
            if capped > 0 {
                note.push_str(&format!(
                    "; {capped} past the {}-neighbor cap",
                    kin_context::SAME_FILE_FALLBACK_MAX
                ));
            }
            note.push(')');
            note
        }
    }
}

/// The entity a single-focal `kin context <symbol>` is about.
///
/// Routed through the shared identity resolver, the one `kin trace`, `kin
/// impact` and `kin xref` use, so one name means one entity across every read
/// command. It also accepts the `Name#Kind@path:line` suffix the multi-focal
/// form takes, so the two spellings do not diverge on the same command.
///
/// This replaces a local picker whose final tiebreak was `a.id.cmp(&b.id)`,
/// commented "stable, deterministic final tiebreak". It was deterministic
/// within one store and not across two: entity ids are minted per ingest, so
/// two ingests of one tree resolved one name to different entities. Measured on
/// this module's own fixture, twenty ingests of a header declaration beside a
/// source definition split eleven to nine. That is the defect FIR-3071 named,
/// and `kin context` was the read command it was never fixed on.
fn resolve_context_target(
    graph: &kin_db::InMemoryGraph,
    entity_query: &str,
) -> Result<Option<Entity>> {
    let reference = crate::entity_ref::parse_entity_ref(entity_query);
    let resolved =
        crate::entity_identity::resolve_identity(graph, &reference.name, &reference.qualifiers)?;
    let mut matches = resolved.matches;
    crate::entity_ref::apply_line(&mut matches, reference.line);
    Ok(crate::entity_identity::choose_definition(&matches).cloned())
}

fn parse_budget(s: &str) -> Result<TokenBudget> {
    match s {
        "8k" => Ok(TokenBudget::Small8k),
        "16k" => Ok(TokenBudget::Medium16k),
        "32k" => Ok(TokenBudget::Large32k),
        _ => {
            let n: usize = s.parse().map_err(|_| {
                anyhow::anyhow!("invalid budget: use '8k', '16k', '32k', or a number")
            })?;
            Ok(TokenBudget::Custom(n))
        }
    }
}

/// True when a response came back about a narrower question than the one asked.
///
/// A daemon predating several focals decodes a multi-focal request, ignores the
/// fields it does not know, and answers about `entity` alone. That answer is
/// well formed, and it is about one end of a question that named several
/// things, which is the shape a caller cannot detect from the pack itself.
fn answered_a_narrower_question(request: &ContextRequest, response: &ContextResponse) -> bool {
    request.is_multi_focal() && response.multi_focal.is_none()
}

/// The assistant hint a request's string names, shared by both pack paths so
/// one spelling cannot mean two things.
fn assistant_hint_from(assistant: Option<&str>) -> Option<kin_context::AssistantHint> {
    assistant.and_then(|hint| match hint.to_lowercase().as_str() {
        "claude" | "claude-code" => Some(kin_context::AssistantHint::ClaudeCode),
        "codex" => Some(kin_context::AssistantHint::Codex),
        "gemini" | "gemini-cli" => Some(kin_context::AssistantHint::GeminiCli),
        _ => None,
    })
}

/// One entity a question ranked for, and the score it ranked at.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuestionFocal {
    pub entity_id: String,
    pub score: f32,
}

/// One sentence on what the ranking behind these focals could see.
///
/// Read off the same [`SemanticCoverage`] every locate surface publishes, and
/// deliberately not derived from the embedding fraction alone: a store can have
/// every embedding indexed and still rank on text alone, which is exactly the
/// case a reader needs told.
///
/// [`SemanticCoverage`]: crate::commands::locate::SemanticCoverage
pub fn coverage_sentence(coverage: &crate::commands::locate::SemanticCoverage) -> String {
    if !coverage.supported {
        return "this build carries no vector retrieval, so the ranking ran on lexical and graph \
                signals alone"
            .to_string();
    }
    let mut sentence = format!(
        "{} of {} entities embedded",
        coverage.indexed, coverage.total
    );
    if coverage.pending > 0 {
        sentence.push_str(&format!(", {} pending", coverage.pending));
    }
    if !coverage.complete {
        let cause = if coverage.limited_by.is_empty() {
            "cause not reported".to_string()
        } else {
            coverage.limited_by.join(", ")
        };
        sentence.push_str(&format!(", incomplete: {cause}"));
    }
    sentence
}

/// The focals a question resolves to, through the graph's own ranking.
///
/// This is `kin locate` in process, against the same graph the pack is built
/// from, and the entities it returns are its own ranking rather than anything
/// re-derived here. The snippet options matter: the plain default switches the
/// `entities[]` ranking off entirely and would leave a question resolving to
/// nothing on a healthy store, so the agent projection is asked for with the
/// bodies turned off, which is the ranking without the source it would cost.
pub fn question_focals(
    graph: &kin_db::InMemoryGraph,
    question: &str,
    limit: usize,
) -> Result<(Vec<QuestionFocal>, String)> {
    use crate::commands::locate::{LocateScope, SnippetOptions};

    let result =
        crate::commands::locate::run_with_graph_capture_with_priority_files_and_vector_source(
            graph,
            None,
            question,
            false,
            LOCATE_MAX_FILES,
            false,
            Vec::new(),
            Some(graph),
            SnippetOptions::enabled(None).without_bodies(),
            None,
            kin_mcp::handlers::common::EntitySourceScope::WorkspaceHead,
            LocateScope::SOURCE_ONLY,
        )?;
    let coverage = result
        .semantic_coverage
        .clone()
        .unwrap_or_else(|| crate::commands::locate::local_semantic_coverage(graph, Some(graph)));
    let focals = result
        .entities
        .iter()
        // An artifact hit carries no entity id. It is a real answer to the
        // question and not a focal entity, so it is skipped here rather than
        // turned into one.
        .filter(|hit| !hit.entity_id.is_empty())
        .take(limit)
        .map(|hit| QuestionFocal {
            entity_id: hit.entity_id.clone(),
            score: hit.score,
        })
        .collect();
    Ok((focals, coverage_sentence(&coverage)))
}

/// Files `kin locate` ranks over when a question resolves focals, matching the
/// CLI's own default so the ranking a question sees is the ranking a person
/// would see typing `kin locate`.
const LOCATE_MAX_FILES: usize = 10;

/// One focal, resolved through the shared identity resolver.
struct ResolvedFocal {
    entity: kin_model::Entity,
    resolution: kin_context::FocalResolution,
}

/// Resolve one focal token to an entity, or to the guidance a miss needs.
///
/// The resolution itself is [`crate::entity_identity::resolve_identity`], the
/// one `kin trace`, `kin impact` and `kin xref` use, so a name means the same
/// entity whichever command reads it. This adds only the suffix spelling
/// (`Name#Kind@path:line`), because `kin context A B C` has nowhere to put a
/// per-focal `--file`.
///
/// The two miss shapes come straight off the resolver's own two stages: an
/// empty `name_matches` is a name the graph does not carry, and an empty
/// `matches` beside a non-empty `name_matches` is a pin that excluded
/// everything. They need opposite fixes, so they are never merged into one
/// message.
fn resolve_focal(
    graph: &kin_db::InMemoryGraph,
    token: &str,
) -> Result<std::result::Result<ResolvedFocal, Vec<String>>> {
    let reference = crate::entity_ref::parse_entity_ref(token);
    let resolved =
        crate::entity_identity::resolve_identity(graph, &reference.name, &reference.qualifiers)?;

    if resolved.name_matches.is_empty() {
        return Ok(Err(context_not_found_guidance(&reference.name)));
    }

    let mut matches = resolved.matches.clone();
    crate::entity_ref::apply_line(&mut matches, reference.line);
    let Some(chosen) = crate::entity_identity::choose_definition(&matches) else {
        // The name is in the graph and the pin excluded every entity carrying
        // it. Naming the twins that do exist is what turns this from a dead end
        // into a correctable one.
        let mut lines = vec![format!(
            "Entity '{}' is in the graph, but nothing there matches the pin {}.",
            reference.name,
            reference.pin_note().unwrap_or_default()
        )];
        for candidate in resolved.name_matches.iter().take(8) {
            lines.push(format!(
                "  {} ({})",
                crate::entity_identity::entity_location(candidate),
                kin_review::StableEntityIdentity::from_entity(candidate).kind
            ));
        }
        return Ok(Err(lines));
    };

    let twins = resolved.name_matches.len();
    let resolution = if resolved.addressed_by_id {
        kin_context::FocalResolution::by_id(token.to_string())
    } else {
        kin_context::FocalResolution::by_name(reference.name.clone())
            .with_twins(twins, reference.pin_note())
    };
    Ok(Ok(ResolvedFocal {
        entity: chosen.clone(),
        resolution,
    }))
}

/// One focal, resolved for a caller that speaks JSON rather than Rust.
///
/// The daemon's MCP route is that caller: it holds the resolver and the pack
/// builder in two crates that cannot see each other, so it resolves here and
/// forwards the entity id with the route that found it. Returns `None` for a
/// token the graph cannot resolve, which the daemon leaves in place so the
/// builder refuses over it rather than silently answering a smaller question.
pub fn resolve_focal_for_mcp(
    graph: &kin_db::InMemoryGraph,
    token: &str,
) -> Result<Option<serde_json::Value>> {
    let Ok(focal) = resolve_focal(graph, token)? else {
        return Ok(None);
    };
    Ok(Some(serde_json::json!({
        "entity_id": focal.entity.id.to_string(),
        "route": focal.resolution.route,
        "query": focal.resolution.query,
        "twins": focal.resolution.twins,
        "pin": focal.resolution.pin,
    })))
}

/// The focals a request resolved to, kept together so the three parallel lists
/// cannot drift out of step.
#[derive(Default)]
struct FocalSet {
    ids: Vec<kin_model::EntityId>,
    resolutions: Vec<kin_context::FocalResolution>,
    targets: Vec<ContextTarget>,
}

impl FocalSet {
    fn len(&self) -> usize {
        self.ids.len()
    }

    fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    /// Take one focal, unless this entity is already in the set.
    ///
    /// A question routinely ranks an entity a caller also named, and a name
    /// routinely resolves to an entity another name already reached. Either way
    /// the pack should carry it once, and the caller's own naming wins the
    /// resolution story because it is the more specific claim.
    fn admit(
        &mut self,
        entity: &kin_model::Entity,
        resolution: kin_context::FocalResolution,
        budget_tokens: usize,
    ) {
        if self.ids.contains(&entity.id) {
            return;
        }
        self.ids.push(entity.id);
        self.resolutions.push(resolution);
        self.targets.push(ContextTarget {
            id: entity.id.to_string(),
            name: entity.name.clone(),
            kind: format!("{:?}", entity.kind),
            budget_tokens,
        });
    }
}

/// Build a pack from several focals.
///
/// The focals the caller named are resolved first, in their own order, so a
/// question never displaces something explicitly asked for. Then, when there is
/// a question, the graph's ranking fills the rest of the slots with what it
/// says the question is about.
fn build_multi_focal_response(
    graph: &kin_db::InMemoryGraph,
    request: &ContextRequest,
) -> Result<ContextResponse> {
    let token_budget = parse_budget(&request.budget)?;
    let limit = request
        .max_focals
        .unwrap_or(QUESTION_FOCAL_MAX)
        .clamp(1, 32);

    let mut focals = FocalSet::default();
    let mut unresolved: Vec<String> = Vec::new();
    let mut guidance: Vec<String> = Vec::new();

    for token in request.focal_tokens() {
        match resolve_focal(graph, &token)? {
            Ok(focal) => {
                focals.admit(&focal.entity, focal.resolution, token_budget.max_tokens());
            }
            Err(miss) => {
                unresolved.push(token.clone());
                guidance.extend(miss);
            }
        }
    }

    // Coverage is stated on EVERY route, not only the question one. A store
    // with no embeddings ranks and packs perfectly happily, and the pack it
    // returns looks the same as one from a fully embedded store; the demo's
    // stores had no embeddings tonight and nothing on any surface said so. The
    // question route overwrites this with the coverage its own ranking
    // observed, which is the same reading taken at the same instant.
    let mut coverage = Some(coverage_sentence(
        &crate::commands::locate::local_semantic_coverage(graph, Some(graph)),
    ));
    if let Some(question) = request.question.as_deref() {
        let (hits, coverage_note) = question_focals(graph, question, limit)?;
        coverage = Some(coverage_note);
        for hit in hits {
            if focals.len() >= limit {
                break;
            }
            let Ok(uuid) = uuid::Uuid::parse_str(&hit.entity_id) else {
                continue;
            };
            let Some(entity) = graph.get_entity(&kin_model::EntityId(uuid))? else {
                continue;
            };
            focals.admit(
                &entity,
                kin_context::FocalResolution::from_question(hit.score),
                token_budget.max_tokens(),
            );
        }
    }

    if focals.is_empty() {
        let mut lines = match request.question.as_deref() {
            Some(question) if guidance.is_empty() => vec![
                format!("Nothing in this repo's graph ranks for '{question}'."),
                "hint: `kin graph status` reports whether the store is indexed and embedded."
                    .to_string(),
            ],
            _ => guidance,
        };
        if lines.is_empty() {
            lines = context_not_found_guidance(&request.entity);
        }
        let measured_tokens = kin_context::estimate_tokens(&lines.join("\n"));
        return Ok(ContextResponse {
            // A multi-focal request that resolved nothing is a miss like any
            // other, so it exits the way `kin trace` does rather than handing
            // guidance back as though it were a pack (FIR-3071).
            error: Some(lines.join("\n")),
            lines,
            schema_version: CONTEXT_RESPONSE_SCHEMA_VERSION.to_string(),
            target: None,
            pack: None,
            dependency_selection: None,
            budget_elisions: BTreeMap::new(),
            focals: Vec::new(),
            // Stamped even with no pack: the caller asked a multi-focal
            // question and needs to know the daemon understood it, or it reads
            // an empty answer as an old daemon and retries forever.
            multi_focal: Some(empty_multi_focal_report(
                token_budget.max_tokens(),
                coverage,
            )),
            measured_tokens,
            unresolved,
        });
    }

    let opts = kin_context::MultiFocalOptions {
        budget: token_budget,
        max_depth: 2,
        include_tests: true,
        include_contracts: true,
        assistant_hint: assistant_hint_from(request.assistant.as_deref()),
        resolutions: focals.resolutions,
        coverage,
    };
    let (pack, report) = kin_context::build_multi_focal_pack(graph, &focals.ids, &opts)?;

    let mut lines = kin_context::render_multi_focal_lines(&pack, &report);
    if !guidance.is_empty() {
        // The misses go after the pack, so a reader sees the answer first and
        // then what it does not cover.
        lines.push(String::new());
        lines.extend(guidance);
    }

    let budget_elisions = report
        .elisions
        .iter()
        .map(|(group, elision)| {
            (
                group.clone(),
                ContextElision {
                    elided: elision.elided,
                    kept: elision.kept,
                    total: elision.total,
                    reason: elision.reason.clone(),
                },
            )
        })
        .collect();

    Ok(ContextResponse {
        error: None,
        lines,
        schema_version: CONTEXT_RESPONSE_SCHEMA_VERSION.to_string(),
        target: focals.targets.first().cloned(),
        pack: Some(pack),
        dependency_selection: None,
        budget_elisions,
        focals: focals.targets,
        measured_tokens: report.measured_tokens,
        multi_focal: Some(report),
        unresolved,
    })
}

/// The report a multi-focal request that resolved no focal still carries, so a
/// caller can tell "this daemon understood the question" from "this daemon is
/// too old to have been asked".
fn empty_multi_focal_report(
    budget_tokens: usize,
    coverage: Option<String>,
) -> kin_context::MultiFocalReport {
    kin_context::MultiFocalReport {
        focals: Vec::new(),
        routes: Vec::new(),
        route_search: kin_context::RouteSearch {
            max_hops: kin_context::ROUTE_MAX_HOPS,
            ..Default::default()
        },
        neighborhood_depth: 0,
        budget_tokens,
        measured_tokens: 0,
        elisions: BTreeMap::new(),
        coverage,
        method: "Method: no focal entity resolved, so no pack was built".to_string(),
        method_style: "full".to_string(),
    }
}

/// Actionable guidance when `kin context <symbol>` can't resolve the symbol in
/// this repo's graph. A context pack is built around a local entity, so a name
/// miss dead-ends; keep the not-found signal and point at discovery commands
/// (`kin search` by name, `kin locate` by description) instead of a bare error.
fn context_not_found_guidance(entity: &str) -> Vec<String> {
    vec![
        format!("Entity '{entity}' not found in this repo's graph."),
        format!(
            "hint: try `kin search {entity}` to find the symbol by name, or `kin locate \"<what it does>\"` to find relevant files."
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{
        EntityId, EntityKind, EntityMetadata, EntityRole, FingerprintAlgorithm, Hash256,
        LanguageId, SemanticFingerprint, Visibility,
    };

    #[test]
    fn context_not_found_guidance_keeps_signal_and_offers_discovery() {
        let lines = context_not_found_guidance("frobnicate");
        assert!(
            lines[0].contains("not found"),
            "keeps not-found signal: {lines:?}"
        );
        let joined = lines.join("\n");
        assert!(
            joined.contains("kin search frobnicate"),
            "offers search: {joined}"
        );
        assert!(joined.contains("kin locate"), "offers locate: {joined}");
    }

    /// A miss has to be readable as a miss by a caller that only checks the exit
    /// code. The prose stays in `lines` for an older client; the discriminator
    /// beside it is what makes `kin context` refuse (FIR-3071).
    #[test]
    fn context_miss_carries_the_discriminator_and_not_just_the_prose() {
        let graph = kin_db::InMemoryGraph::new();
        graph.upsert_entity(&test_entity("checkout")).unwrap();

        let response = build_context_response(
            &graph,
            &ContextRequest {
                entity: "definitelyMissingEntity".to_string(),
                budget: "8k".to_string(),
                assistant: None,
                ..ContextRequest::default()
            },
        )
        .unwrap();

        let joined = response.lines.join("\n");
        assert!(joined.contains("not found"), "{joined}");
        assert_eq!(response.error.as_deref(), Some(joined.as_str()));
        assert!(response.pack.is_none());
    }

    /// The other side of the same rule: a resolved context must not carry the
    /// discriminator, or every answer would refuse.
    #[test]
    fn a_resolved_context_carries_no_error_discriminator() {
        let graph = kin_db::InMemoryGraph::new();
        graph.upsert_entity(&test_entity("checkout")).unwrap();

        let response = build_context_response(
            &graph,
            &ContextRequest {
                entity: "checkout".to_string(),
                budget: "8k".to_string(),
                assistant: None,
                ..ContextRequest::default()
            },
        )
        .unwrap();

        assert!(response.error.is_none(), "{:?}", response.error);
    }

    fn test_entity(name: &str) -> Entity {
        test_entity_kind(name, EntityKind::Function)
    }

    fn test_entity_kind(name: &str, kind: EntityKind) -> Entity {
        Entity {
            id: EntityId::new(),
            kind,
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

    /// `--json` is why the structured half exists, and it must carry the pack
    /// rather than the rendered lines. Serializing `lines` alone would be human
    /// text in a JSON envelope, which is what the surface already had.
    #[test]
    fn a_resolved_context_carries_its_pack_and_target_for_machines() {
        let graph = kin_db::InMemoryGraph::new();
        let entity = test_entity("checkout");
        graph.upsert_entity(&entity).unwrap();

        let response = build_context_response(
            &graph,
            &ContextRequest {
                entity: "checkout".to_string(),
                budget: "8k".to_string(),
                assistant: None,
                ..ContextRequest::default()
            },
        )
        .expect("a resolved entity builds a context response");

        assert_eq!(response.schema_version, CONTEXT_RESPONSE_SCHEMA_VERSION);
        let target = response.target.as_ref().expect("a resolved target");
        assert_eq!(target.name, "checkout");
        assert_eq!(target.kind, "Function");
        assert_eq!(target.budget_tokens, 8000);
        let pack = response.pack.as_ref().expect("a resolved pack");
        assert!(!pack.focal_entities.is_empty(), "the pack names its focus");

        // The document a caller receives holds the structure, not just prose.
        let rendered = serde_json::to_string(&response).expect("serialize");
        let value: serde_json::Value = serde_json::from_str(&rendered).expect("parse");
        assert_eq!(value["target"]["name"], "checkout");
        assert!(
            value["pack"]["focal_entities"].is_array(),
            "the pack must survive serialization: {rendered}"
        );
        assert!(value["pack"]["actual_tokens"].is_number());
    }

    /// An unresolved entity is an answer, so it is stamped. Leaving the version
    /// empty there would make `--json` report it as a daemon too old to answer.
    #[test]
    fn an_unresolved_entity_is_stamped_but_carries_no_pack() {
        let graph = kin_db::InMemoryGraph::new();
        let response = build_context_response(
            &graph,
            &ContextRequest {
                entity: "frobnicate".to_string(),
                budget: "8k".to_string(),
                assistant: None,
                ..ContextRequest::default()
            },
        )
        .expect("an unresolved entity still answers");

        assert_eq!(response.schema_version, CONTEXT_RESPONSE_SCHEMA_VERSION);
        assert!(response.pack.is_none());
        assert!(response.target.is_none());
        assert!(!response.lines.is_empty(), "guidance is still rendered");
    }

    /// The version guard has to be able to fire, which means an older daemon's
    /// reply must still decode and must still leave the version empty. If the
    /// field were required, this would be a decode error and `--json` would
    /// report a transport failure for a version skew.
    #[test]
    fn an_older_daemons_reply_still_decodes_and_reports_no_schema() {
        let older: ContextResponse =
            serde_json::from_str(r#"{"lines":["Context pack for 'Foo' (Function):"]}"#)
                .expect("a lines-only reply must still decode");
        assert!(
            older.schema_version.is_empty(),
            "an unstamped reply is what makes `--json` refuse rather than emit an empty document"
        );
        assert!(older.pack.is_none());
        assert_eq!(older.lines.len(), 1);
    }

    fn file_entity(name: &str, kind: EntityKind, file: &str) -> Entity {
        let mut entity = test_entity_kind(name, kind);
        entity.file_origin = Some(kin_model::FilePathId::new(file));
        entity
    }

    /// `kin context` on a class with no dependency edges lists same-file
    /// neighbours under a heading that says "Dependencies", and the only tag
    /// saying otherwise was a comment inside each entry. The rendering and the
    /// structured half both name the selection now, in the same words the MCP
    /// tool uses.
    #[test]
    fn a_same_file_fallback_says_so_in_both_halves_of_the_response() {
        let graph = kin_db::InMemoryGraph::new();
        let class = file_entity("NoteStore", EntityKind::Class, "src/notes.py");
        graph.upsert_entity(&class).unwrap();
        for member in ["NoteStore.open", "NoteStore.close", "NoteStore.stats"] {
            graph
                .upsert_entity(&file_entity(member, EntityKind::Method, "src/notes.py"))
                .unwrap();
        }

        let response = build_context_response(
            &graph,
            &ContextRequest {
                entity: "NoteStore".to_string(),
                budget: "8k".to_string(),
                assistant: None,
                ..ContextRequest::default()
            },
        )
        .expect("a resolved entity builds a context response");

        let rendered = response.lines.join("\n");
        assert!(
            rendered.contains(
                "Dependencies: 3 entries (same-file neighbors, no dependency edges; kept 3 of 3)"
            ),
            "the human rendering must name the fallback: {rendered}"
        );
        let selection = response
            .dependency_selection
            .as_ref()
            .expect("a resolved pack reports how its dependencies were selected");
        assert_eq!(selection.source, "same_file_fallback");
        assert_eq!(selection.returned, 3);
        assert_eq!(selection.same_file_candidates, 3);
        assert_eq!(selection.same_file_dropped, 0);
    }

    /// The control: a focal with a real edge must be reported as edges on this
    /// surface too, or the fallback wording says nothing.
    #[test]
    fn a_pack_built_from_edges_is_not_reported_as_a_fallback() {
        use kin_model::relation::{Relation, RelationKind, RelationOrigin};

        let graph = kin_db::InMemoryGraph::new();
        let caller = file_entity("read_notes", EntityKind::Function, "src/reader.py");
        let callee = file_entity("LinkRecord", EntityKind::Class, "src/records.py");
        graph.upsert_entity(&caller).unwrap();
        graph.upsert_entity(&callee).unwrap();
        graph
            .upsert_relation(&Relation {
                id: kin_model::ids::RelationId::new(),
                kind: RelationKind::Calls,
                src: kin_model::GraphNodeId::Entity(caller.id),
                dst: kin_model::GraphNodeId::Entity(callee.id),
                confidence: 1.0,
                origin: RelationOrigin::Parsed,
                created_in: None,
                import_source: None,
                evidence: Vec::new(),
            })
            .unwrap();

        let response = build_context_response(
            &graph,
            &ContextRequest {
                entity: "read_notes".to_string(),
                budget: "8k".to_string(),
                assistant: None,
                ..ContextRequest::default()
            },
        )
        .expect("a resolved entity builds a context response");

        let rendered = response.lines.join("\n");
        assert!(
            rendered.contains("Dependencies: 1 entries (dependency edges)"),
            "an edge-built pack must say so: {rendered}"
        );
        let selection = response.dependency_selection.as_ref().expect("a selection");
        assert_eq!(selection.source, "dependency_edges");
        assert_eq!(selection.same_file_candidates, 0);
    }

    #[test]
    fn context_target_accepts_entity_uuid() {
        let graph = kin_db::InMemoryGraph::new();
        let entity = test_entity("checkout");
        let id = entity.id;
        graph.upsert_entity(&entity).unwrap();

        let resolved = resolve_context_target(&graph, &id.to_string()).unwrap();

        assert_eq!(resolved.unwrap().id, id);
    }

    #[test]
    fn context_target_prefers_class_over_constructor_member() {
        // Dogfood wart #10: `kin context Foo` must land on the class, not the
        // `Foo.__init__` constructor that also matches the name pattern. The
        // graph returns both (sorted by id), so resolution has to rank by intent.
        let graph = kin_db::InMemoryGraph::new();
        let class = test_entity_kind("Foo", EntityKind::Class);
        let ctor = test_entity_kind("Foo.__init__", EntityKind::Method);
        let class_id = class.id;
        // Insert the member first so a naive "first match" would pick it.
        graph.upsert_entity(&ctor).unwrap();
        graph.upsert_entity(&class).unwrap();

        let resolved = resolve_context_target(&graph, "Foo").unwrap().unwrap();

        assert_eq!(
            resolved.id, class_id,
            "expected the class, got {}",
            resolved.name
        );
        assert_eq!(resolved.kind, EntityKind::Class);
    }

    #[test]
    fn context_target_exact_name_beats_substring_match() {
        // An exact name must win over a longer name that merely contains the
        // query as a token/substring, regardless of kind.
        let graph = kin_db::InMemoryGraph::new();
        let exact = test_entity_kind("parse", EntityKind::Function);
        let longer = test_entity_kind("parse_config", EntityKind::Function);
        let exact_id = exact.id;
        graph.upsert_entity(&longer).unwrap();
        graph.upsert_entity(&exact).unwrap();

        let resolved = resolve_context_target(&graph, "parse").unwrap().unwrap();

        assert_eq!(
            resolved.id, exact_id,
            "expected exact match, got {}",
            resolved.name
        );
    }

    // ── What the token budget refused reaches both renderings (FIR-2482) ──

    /// A focal calling `deps` entities, so a tight budget has rows to refuse.
    fn calling_graph(deps: usize) -> (kin_db::InMemoryGraph, Entity) {
        use kin_model::relation::{Relation, RelationKind, RelationOrigin};
        use kin_model::GraphNodeId;
        let graph = kin_db::InMemoryGraph::new();
        let focal = test_entity("focal");
        graph.upsert_entity(&focal).unwrap();
        for index in 0..deps {
            let dep = test_entity(&format!("dep_{index:04}"));
            graph.upsert_entity(&dep).unwrap();
            graph
                .upsert_relation(&Relation {
                    id: kin_model::ids::RelationId::new(),
                    kind: RelationKind::Calls,
                    src: GraphNodeId::Entity(focal.id),
                    dst: GraphNodeId::Entity(dep.id),
                    confidence: 1.0,
                    origin: RelationOrigin::Parsed,
                    created_in: None,
                    import_source: None,
                    evidence: Vec::new(),
                })
                .unwrap();
        }
        (graph, focal)
    }

    fn context_for(graph: &kin_db::InMemoryGraph, budget: &str) -> ContextResponse {
        build_context_response(
            graph,
            &ContextRequest {
                entity: "focal".to_string(),
                budget: budget.to_string(),
                assistant: None,
                ..ContextRequest::default()
            },
        )
        .unwrap()
    }

    /// Six rows on a focal with sixty dependencies printed "Dependencies: 6
    /// entries", which is what a focal with six dependencies prints. The
    /// rendering is the whole of what a `kin context` reader sees, so a cut it
    /// does not name is a cut that did not happen as far as that reader knows.
    #[test]
    fn a_budget_cut_section_names_its_loss_in_the_lines_and_in_the_json() {
        let (graph, _) = calling_graph(60);
        let whole = context_for(&graph, "32k");
        let full_deps = whole.pack.as_ref().unwrap().dependency_signatures.len();
        assert!(
            whole.budget_elisions.is_empty(),
            "a generous budget refused nothing and must claim nothing: {:?}",
            whole.budget_elisions
        );

        // Sized off the unconstrained pack so the cut lands mid-list however
        // projection costs change later.
        let tight = (whole.pack.as_ref().unwrap().actual_tokens / 2).to_string();
        let cut = context_for(&graph, &tight);
        let kept = cut.pack.as_ref().unwrap().dependency_signatures.len();
        assert!(
            kept > 0 && kept < full_deps,
            "the budget must actually cut for this test to mean anything: kept {kept} of \
             {full_deps}"
        );

        let elision = cut
            .budget_elisions
            .get("dependencies")
            .unwrap_or_else(|| panic!("a cut section must publish an elision: {:?}", cut.lines));
        assert_eq!(elision.kept, kept);
        assert_eq!(elision.kept + elision.elided, elision.total);
        assert_eq!(elision.reason, CONTEXT_ELISION_REASON_TOKEN_BUDGET);

        let rendered = cut.lines.join("\n");
        assert!(
            rendered.contains(&format!(
                "{} withheld by the {tight}-token budget",
                elision.elided
            )),
            "the section line names what the budget took: {rendered}"
        );
        assert!(
            rendered.contains(&format!("Raise --budget above {tight}")),
            "the rendering names the lever that recovers it: {rendered}"
        );
    }

    /// The other direction, and it is the one that gives an absent disclosure
    /// its meaning: a pack that lost nothing says nothing, on both halves.
    #[test]
    fn a_whole_pack_carries_no_budget_note_at_all() {
        let (graph, _) = calling_graph(2);
        let whole = context_for(&graph, "32k");
        assert!(
            whole.budget_elisions.is_empty(),
            "{:?}",
            whole.budget_elisions
        );
        let rendered = whole.lines.join("\n");
        assert!(
            !rendered.contains("withheld by the"),
            "nothing was withheld, so nothing may be claimed: {rendered}"
        );
        assert!(
            !rendered.contains("Raise --budget"),
            "no lever is offered for a cut that did not happen: {rendered}"
        );
        // The other side of the over-budget note. Without this the note could
        // fire on every pack and every test here would still pass, which is a
        // fixture sitting entirely on one side of the branch.
        assert!(
            !rendered.contains("over budget"),
            "a pack inside its budget must not report itself over one: {rendered}"
        );
        assert!(
            whole.pack.as_ref().unwrap().actual_tokens <= 32_000,
            "the fixture must actually fit, or the assertion above proves nothing"
        );
    }

    // ---- several focals, and the question route ------------------------

    fn linked_store() -> (kin_db::InMemoryGraph, Vec<Entity>) {
        use kin_model::relation::{Relation, RelationKind, RelationOrigin};
        let graph = kin_db::InMemoryGraph::new();
        let names = [
            "handleKeyboardInput",
            "applyEdits",
            "pushEditOperations",
            "TextDocument",
        ];
        let mut chain = Vec::new();
        for (index, name) in names.iter().enumerate() {
            let mut entity = test_entity(name);
            entity.file_origin = Some(kin_model::FilePathId::new(format!("src/{name}.ts")));
            entity.doc_summary = Some(format!("{name} in the editor input path"));
            entity.span = Some(kin_model::SourceSpan {
                file: kin_model::FilePathId::new(format!("src/{name}.ts")),
                start_byte: 0,
                end_byte: 64,
                start_line: (index as u32 + 1) * 10,
                start_col: 0,
                end_line: (index as u32 + 1) * 10 + 6,
                end_col: 0,
            });
            graph.upsert_entity(&entity).unwrap();
            chain.push(entity);
        }
        for pair in chain.windows(2) {
            graph
                .upsert_relation(&Relation {
                    id: kin_model::ids::RelationId::new(),
                    kind: RelationKind::Calls,
                    src: kin_model::GraphNodeId::Entity(pair[0].id),
                    dst: kin_model::GraphNodeId::Entity(pair[1].id),
                    confidence: 1.0,
                    origin: RelationOrigin::Parsed,
                    created_in: None,
                    import_source: None,
                    evidence: Vec::new(),
                })
                .unwrap();
        }
        (graph, chain)
    }

    /// The failure this whole path exists for: a question that names two
    /// things used to produce a pack about one of them.
    #[test]
    fn two_named_focals_produce_one_pack_carrying_both() {
        let (graph, chain) = linked_store();
        let response = build_context_response(
            &graph,
            &ContextRequest {
                entity: "handleKeyboardInput".to_string(),
                entities: vec!["TextDocument".to_string()],
                budget: "8k".to_string(),
                ..ContextRequest::default()
            },
        )
        .expect("two focals build a pack");

        let report = response
            .multi_focal
            .as_ref()
            .expect("a multi-focal request carries its report");
        assert_eq!(report.focals.len(), 2);
        assert_eq!(response.focals.len(), 2);
        let pack = response.pack.as_ref().expect("a pack");
        let focal_ids: Vec<String> = pack
            .focal_entities
            .iter()
            .map(|entry| entry.entity_id.to_string())
            .collect();
        assert!(
            focal_ids.contains(&chain[0].id.to_string()),
            "{focal_ids:?}"
        );
        assert!(
            focal_ids.contains(&chain[3].id.to_string()),
            "{focal_ids:?}"
        );
        assert_eq!(report.route_search.pairs_connected, 1);
        assert!(
            report
                .routes
                .iter()
                .any(|route| route.via_names.contains(&"applyEdits".to_string())),
            "the material between the ends is in the pack: {:?}",
            report.routes
        );
    }

    /// One focal and no question keeps the original path, byte for byte, so
    /// nothing already reading `kin context Foo` moves under this change.
    #[test]
    fn one_focal_still_takes_the_single_focal_path() {
        let (graph, _) = linked_store();
        let response = build_context_response(&graph, &ContextRequest::one("applyEdits", "8k"))
            .expect("one focal builds a pack");
        assert!(
            response.multi_focal.is_none(),
            "one focal is not a multi-focal pack"
        );
        assert!(response.dependency_selection.is_some());
        assert!(response.lines[0].starts_with("Context pack for 'applyEdits'"));
    }

    /// The number a caller subtracts from its own window is the number the
    /// bytes cost, on both paths.
    #[test]
    fn every_pack_reports_what_its_rendering_costs() {
        let (graph, _) = linked_store();
        for request in [
            ContextRequest::one("applyEdits", "8k"),
            ContextRequest {
                entity: "handleKeyboardInput".to_string(),
                entities: vec!["TextDocument".to_string()],
                budget: "800".to_string(),
                ..ContextRequest::default()
            },
        ] {
            let response = build_context_response(&graph, &request).expect("a pack");
            assert_eq!(
                response.measured_tokens,
                kin_context::estimate_tokens(&response.lines.join("\n")),
                "the reported size is the size of the lines returned"
            );
        }
    }

    /// The multi-focal pack keeps the promise the single-focal one does not.
    #[test]
    fn a_multi_focal_pack_comes_in_under_its_budget() {
        let (graph, _) = linked_store();
        for budget in ["300", "700", "1500"] {
            let response = build_context_response(
                &graph,
                &ContextRequest {
                    entity: "handleKeyboardInput".to_string(),
                    entities: vec!["TextDocument".to_string(), "applyEdits".to_string()],
                    budget: budget.to_string(),
                    ..ContextRequest::default()
                },
            )
            .expect("a pack");
            let asked: usize = budget.parse().unwrap();
            assert!(
                response.measured_tokens <= asked,
                "asked {asked}, measured {}",
                response.measured_tokens
            );
        }
    }

    #[test]
    fn the_method_line_is_the_second_line_of_the_human_form() {
        let (graph, _) = linked_store();
        let response = build_context_response(
            &graph,
            &ContextRequest {
                entity: "handleKeyboardInput".to_string(),
                entities: vec!["TextDocument".to_string()],
                budget: "8k".to_string(),
                ..ContextRequest::default()
            },
        )
        .expect("a pack");
        let method = &response.lines[1];
        assert!(method.starts_with("Method: 2 focals"), "{method}");
        assert!(method.contains("named as handleKeyboardInput"), "{method}");
        assert!(method.contains("named as TextDocument"), "{method}");
        assert_eq!(
            method,
            &response.multi_focal.as_ref().unwrap().method,
            "the line a person reads and the field a machine reads are one string"
        );
    }

    /// A focal that resolves and one that does not: answer with what there is,
    /// and say what is missing rather than pretending the question was smaller.
    #[test]
    fn an_unresolved_focal_is_named_beside_the_pack_it_is_missing_from() {
        let (graph, _) = linked_store();
        let response = build_context_response(
            &graph,
            &ContextRequest {
                entity: "applyEdits".to_string(),
                entities: vec!["frobnicate".to_string()],
                budget: "8k".to_string(),
                ..ContextRequest::default()
            },
        )
        .expect("one resolved focal still builds a pack");
        assert_eq!(response.unresolved, vec!["frobnicate".to_string()]);
        assert_eq!(response.focals.len(), 1);
        let rendered = response.lines.join("\n");
        assert!(
            rendered.contains("frobnicate"),
            "the miss is in the output a person reads: {rendered}"
        );
    }

    /// A twin is chosen, and the choice is stated. The demo measured this
    /// exact case resolving two ways across ingests of one tree.
    #[test]
    fn a_twin_is_reported_in_the_method_line() {
        let (graph, _) = linked_store();
        let mut twin = test_entity("applyEdits");
        twin.file_origin = Some(kin_model::FilePathId::new("src/applyEdits.h"));
        graph.upsert_entity(&twin).unwrap();

        let response = build_context_response(
            &graph,
            &ContextRequest {
                entity: "applyEdits".to_string(),
                entities: vec!["TextDocument".to_string()],
                budget: "8k".to_string(),
                ..ContextRequest::default()
            },
        )
        .expect("a pack");
        let method = &response.lines[1];
        assert!(
            method.contains("1 of 2 under that name"),
            "the method says a choice was made: {method}"
        );
    }

    /// The pack's focal choice among twins does not move between ingests.
    ///
    /// This is the multi-focal surface's stake in `choose_definition`, which
    /// belongs to the shared identity resolver rather than to this module. A
    /// pack is built for a specific entity, so a resolver that answered
    /// differently per ingest would build a different pack from the same
    /// question, and the count alone cannot see that: a chooser keyed on the
    /// entity id reports "1 of 2" just as truthfully while picking either one.
    /// Twenty independently minted pairs, so a chooser reaching for an id lands
    /// on both twins and fails here.
    #[test]
    fn the_twin_a_pack_is_built_for_does_not_move_between_ingests() {
        let mut chosen = Vec::new();
        for trial in 0..20 {
            let graph = kin_db::InMemoryGraph::new();
            let mut definition = test_entity("applyEdits");
            definition.file_origin = Some(kin_model::FilePathId::new("src/applyEdits.ts"));
            let mut declaration = test_entity("applyEdits");
            declaration.file_origin = Some(kin_model::FilePathId::new("src/applyEdits.h"));
            declaration.signature = "declare function applyEdits();".to_string();

            // Alternate insertion order, so listing order varies alongside ids.
            if trial % 2 == 0 {
                graph.upsert_entity(&definition).unwrap();
                graph.upsert_entity(&declaration).unwrap();
            } else {
                graph.upsert_entity(&declaration).unwrap();
                graph.upsert_entity(&definition).unwrap();
            }

            let response = build_context_response(&graph, &ContextRequest::one("applyEdits", "8k"))
                .expect("a pack");
            let target = response.target.as_ref().expect("a resolved target");
            let file = if target.id == definition.id.to_string() {
                "src/applyEdits.ts"
            } else {
                "src/applyEdits.h"
            };
            chosen.push(file);
        }
        let first = chosen[0];
        assert!(
            chosen.iter().all(|file| *file == first),
            "twenty ingests of one tree must build the pack for one twin, got {chosen:?}"
        );
    }

    /// A pinned twin is the one that lands, and the pin is stated.
    #[test]
    fn a_pinned_twin_is_the_one_the_pack_carries() {
        let (graph, _) = linked_store();
        let mut twin = test_entity("applyEdits");
        twin.file_origin = Some(kin_model::FilePathId::new("src/applyEdits.h"));
        graph.upsert_entity(&twin).unwrap();

        let response = build_context_response(
            &graph,
            &ContextRequest {
                entity: "applyEdits@src/applyEdits.h".to_string(),
                entities: vec!["TextDocument".to_string()],
                budget: "8k".to_string(),
                ..ContextRequest::default()
            },
        )
        .expect("a pack");
        assert_eq!(response.focals[0].id, twin.id.to_string());
        assert!(
            response.lines[1].contains("pinned by src/applyEdits.h"),
            "{}",
            response.lines[1]
        );
    }

    /// The question route, end to end on a fixture store: no entity named, and
    /// the pack still comes back built from what the ranking says the question
    /// is about, with the score and the store's coverage on the record.
    #[test]
    fn a_question_resolves_its_own_focals_through_the_ranking() {
        let (graph, chain) = linked_store();
        let response = build_context_response(
            &graph,
            &ContextRequest {
                budget: "2000".to_string(),
                question: Some("how does handleKeyboardInput reach the TextDocument".to_string()),
                ..ContextRequest::default()
            },
        )
        .expect("a question builds a pack");

        let report = response
            .multi_focal
            .as_ref()
            .expect("the question route reports its method");
        assert!(
            !report.focals.is_empty(),
            "the ranking named the focals: {}",
            report.method
        );
        assert!(
            report
                .focals
                .iter()
                .any(|focal| focal.resolution.route == "question"),
            "and they are on the record as located rather than named: {:?}",
            report.focals
        );
        let known: Vec<String> = chain.iter().map(|entity| entity.id.to_string()).collect();
        assert!(
            report
                .focals
                .iter()
                .all(|focal| known.contains(&focal.entity_id)),
            "every focal is an entity of this store"
        );
        assert!(
            report.coverage.is_some(),
            "the coverage the ranking had is reported: {report:?}"
        );
        assert!(
            report.method.contains("semantic coverage"),
            "and it reaches the line a person reads: {}",
            report.method
        );
    }

    /// Coverage is stated whichever route built the pack. A store with no
    /// embeddings packs exactly like a fully embedded one, which is what left
    /// the demo unable to see that its stores had none.
    #[test]
    fn every_route_states_the_coverage_its_ranking_had() {
        let (graph, _) = linked_store();

        let single = build_context_response(&graph, &ContextRequest::one("applyEdits", "8k"))
            .expect("one focal builds a pack");
        assert!(
            single
                .lines
                .iter()
                .any(|line| line.starts_with("  Semantic coverage: ")),
            "the single-focal header states it: {:?}",
            single.lines
        );

        let named = build_context_response(
            &graph,
            &ContextRequest {
                entity: "applyEdits".to_string(),
                entities: vec!["TextDocument".to_string()],
                budget: "8k".to_string(),
                ..ContextRequest::default()
            },
        )
        .expect("two named focals build a pack");
        let report = named.multi_focal.as_ref().expect("a report");
        assert!(
            report.coverage.is_some(),
            "the named route states it too, with no question anywhere: {report:?}"
        );
        assert!(
            report.method.contains("semantic coverage"),
            "and it reaches the method line: {}",
            report.method
        );
    }

    /// The question route runs the graph's own ranking. A question that ranks
    /// nothing says so, and still carries the report, so a caller can tell a
    /// daemon that understood the question from one too old to have been asked.
    #[test]
    fn a_question_that_ranks_nothing_says_so_and_still_reports_its_method() {
        let graph = kin_db::InMemoryGraph::new();
        let response = build_context_response(
            &graph,
            &ContextRequest {
                budget: "800".to_string(),
                question: Some("how does a character reach the document".to_string()),
                ..ContextRequest::default()
            },
        )
        .expect("an empty graph still answers");
        assert!(response.pack.is_none());
        assert!(
            response.multi_focal.is_some(),
            "the report is stamped even with no pack, so an empty answer is not read as an old daemon"
        );
        let rendered = response.lines.join("\n");
        assert!(rendered.contains("kin graph status"), "{rendered}");
    }

    /// The guard that keeps an old daemon's narrower answer from passing for
    /// the answer that was asked for.
    #[test]
    fn a_response_missing_its_report_is_read_as_a_narrower_answer() {
        let multi = ContextRequest {
            entity: "a".to_string(),
            entities: vec!["b".to_string()],
            budget: "8k".to_string(),
            ..ContextRequest::default()
        };
        let single = ContextRequest::one("a", "8k");
        let old_daemon = ContextResponse {
            error: None,
            lines: vec!["Context pack for 'a' (Function):".to_string()],
            schema_version: CONTEXT_RESPONSE_SCHEMA_VERSION.to_string(),
            target: None,
            pack: None,
            dependency_selection: None,
            budget_elisions: BTreeMap::new(),
            focals: Vec::new(),
            multi_focal: None,
            measured_tokens: 9,
            unresolved: Vec::new(),
        };
        assert!(
            answered_a_narrower_question(&multi, &old_daemon),
            "a multi-focal request answered without a report is a narrower answer"
        );
        assert!(
            !answered_a_narrower_question(&single, &old_daemon),
            "a single-focal request is answered correctly by exactly this response"
        );
    }

    #[test]
    fn a_request_knows_which_path_it_needs() {
        assert!(!ContextRequest::one("a", "8k").is_multi_focal());
        assert!(ContextRequest {
            entity: "a".to_string(),
            entities: vec!["b".to_string()],
            budget: "8k".to_string(),
            ..ContextRequest::default()
        }
        .is_multi_focal());
        assert!(ContextRequest {
            budget: "8k".to_string(),
            question: Some("what happens on save".to_string()),
            ..ContextRequest::default()
        }
        .is_multi_focal());
    }

    #[test]
    fn focal_tokens_drop_blanks_and_keep_the_callers_order() {
        let request = ContextRequest {
            entity: "  first  ".to_string(),
            entities: vec!["".to_string(), "second".to_string(), "   ".to_string()],
            budget: "8k".to_string(),
            ..ContextRequest::default()
        };
        assert_eq!(
            request.focal_tokens(),
            vec!["first".to_string(), "second".to_string()]
        );
    }
}
