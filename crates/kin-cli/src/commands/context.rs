// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};
use kin_model::EntityStore;
use kin_model::{Entity, EntityFilter, EntityId, EntityKind, TokenBudget};
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextRequest {
    pub entity: String,
    pub budget: String,
    #[serde(default)]
    pub assistant: Option<String>,
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
    entity: String,
    budget: String,
    assistant: Option<String>,
    json: bool,
) -> Result<()> {
    let layout = crate::commands::require_repository_layout()?;
    let _scope = announce_active_scope(&layout, "context").await?;
    let response = run_daemon_context(
        &layout,
        &ContextRequest {
            entity,
            budget,
            assistant,
        },
    )
    .await?;
    if json {
        if response.schema_version.is_empty() {
            anyhow::bail!(
                "the running daemon does not support structured context packs; restart it with the current Kin build"
            );
        }
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
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
    let token_budget = parse_budget(&request.budget)?;

    let assistant_hint =
        request
            .assistant
            .as_deref()
            .and_then(|a| match a.to_lowercase().as_str() {
                "claude" | "claude-code" => Some(kin_context::AssistantHint::ClaudeCode),
                "codex" => Some(kin_context::AssistantHint::Codex),
                "gemini" | "gemini-cli" => Some(kin_context::AssistantHint::GeminiCli),
                _ => None,
            });

    let Some(target) = resolve_context_target(graph, &request.entity)? else {
        return Ok(ContextResponse {
            lines: context_not_found_guidance(&request.entity),
            // Stamped even here: an unresolved entity is an answer, and leaving
            // this empty would report it as a daemon too old to answer at all.
            schema_version: CONTEXT_RESPONSE_SCHEMA_VERSION.to_string(),
            target: None,
            pack: None,
            dependency_selection: None,
            budget_elisions: BTreeMap::new(),
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
        format!("  Budget: {}/{} tokens", pack.actual_tokens, max_tokens),
        format!("  Focal: {} entries", pack.focal_entities.len()),
        format!(
            "  Dependencies: {} entries{}",
            dependencies_returned,
            dependency_selection_note(
                &selection,
                dependencies_returned,
                &elisions,
                max_tokens
            )
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
    // One line naming the lever, because a per-section count says what was lost
    // and not what recovers it. Present only when something was cut, so a whole
    // pack never carries a note about a cut that did not happen.
    let total_elided: usize = elisions.values().map(|elision| elision.elided).sum();
    if total_elided > 0 {
        lines.push(format!(
            "  Raise --budget above {max_tokens} to recover the {total_elided} \
             {} the token budget withheld.",
            if total_elided == 1 { "entry" } else { "entries" }
        ));
    }
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

    Ok(ContextResponse {
        lines,
        schema_version: CONTEXT_RESPONSE_SCHEMA_VERSION.to_string(),
        target: Some(ContextTarget {
            id: target.id.to_string(),
            name: target.name.clone(),
            kind: format!("{:?}", target.kind),
            budget_tokens: token_budget.max_tokens(),
        }),
        dependency_selection: Some(ContextDependencySelection {
            source: selection.source().as_str().to_string(),
            returned: dependencies_returned,
            dependents_returned,
            same_file_candidates: selection.same_file_candidates(),
            same_file_dropped: selection.same_file_dropped(),
        }),
        budget_elisions: elisions,
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

fn resolve_context_target(
    graph: &kin_db::InMemoryGraph,
    entity_query: &str,
) -> Result<Option<Entity>> {
    let trimmed = entity_query.trim();
    if let Ok(uuid) = uuid::Uuid::parse_str(trimmed) {
        return Ok(graph.get_entity(&EntityId(uuid))?);
    }

    let filter = EntityFilter {
        name_pattern: Some(trimmed.to_string()),
        ..Default::default()
    };
    // `query_entities` matches names by exact/token/substring and then returns
    // candidates sorted by entity id, so a bare `.next()` would pick an
    // arbitrary match — e.g. `kin context Foo` landing on `Foo.__init__` instead
    // of the class `Foo`. Rank the matches by intent here so the symbol the user
    // typed wins: an exact name beats a partial one, and a type/container
    // declaration beats one of its members.
    Ok(pick_context_target(trimmed, graph.query_entities(&filter)?))
}

/// Choose the entity a `kin context <symbol>` query most likely meant from the
/// name-pattern matches the graph returned.
fn pick_context_target(query: &str, mut candidates: Vec<Entity>) -> Option<Entity> {
    candidates.sort_by(|a, b| {
        name_match_rank(query, a)
            .cmp(&name_match_rank(query, b))
            .then_with(|| kind_rank(a.kind).cmp(&kind_rank(b.kind)))
            // Shorter names are more canonical (`Foo` over `Foo.__init__`).
            .then_with(|| a.name.len().cmp(&b.name.len()))
            // Stable, deterministic final tiebreak.
            .then_with(|| a.id.cmp(&b.id))
    });
    candidates.into_iter().next()
}

/// Lower is a better name match: an exact hit beats a case-insensitive hit,
/// which beats a mere substring/token match.
fn name_match_rank(query: &str, entity: &Entity) -> u8 {
    if entity.name == query {
        0
    } else if entity.name.eq_ignore_ascii_case(query) {
        1
    } else {
        2
    }
}

/// Lower is preferred: a type/container declaration outranks one of its members
/// when both match equally well, so `kin context Foo` resolves to the class
/// rather than `Foo.__init__` or another method.
fn kind_rank(kind: EntityKind) -> u8 {
    match kind {
        EntityKind::Class
        | EntityKind::Interface
        | EntityKind::TraitDef
        | EntityKind::TypeAlias
        | EntityKind::EnumDef
        | EntityKind::Module
        | EntityKind::Package
        | EntityKind::Schema
        | EntityKind::EventContract => 0,
        _ => 1,
    }
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
        EntityKind, EntityMetadata, EntityRole, FingerprintAlgorithm, Hash256, LanguageId,
        SemanticFingerprint, Visibility,
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
}
