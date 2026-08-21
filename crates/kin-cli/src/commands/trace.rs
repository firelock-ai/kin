// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};
use kin_model::{Entity, GraphStore, TokenBudget};
use serde::{Deserialize, Serialize};

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
pub struct TraceRequest {
    pub entity: String,
    #[serde(default)]
    pub json: bool,
    #[serde(default)]
    pub compact: bool,
    pub budget: String,
    #[serde(default)]
    pub assistant: Option<String>,
    pub max_lines: usize,
    pub nearby_limit: usize,
    pub transitive_limit: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceResponse {
    #[serde(default)]
    pub lines: Vec<String>,
    #[serde(default)]
    pub entities: Vec<TraceJsonEntity>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceJsonEntity {
    pub kind: String,
    pub name: String,
    pub file: String,
    pub line: u32,
    pub signature: Option<String>,
}

pub async fn run(
    entity: String,
    compact: bool,
    budget: String,
    assistant: Option<String>,
    max_lines: usize,
    nearby_limit: usize,
    transitive_limit: usize,
) -> Result<()> {
    let layout = crate::commands::require_repository_layout()?;
    let _scope = announce_active_scope(&layout, "trace").await?;
    let response = run_daemon_trace(
        &layout,
        &TraceRequest {
            entity,
            json: false,
            compact,
            budget,
            assistant,
            max_lines,
            nearby_limit,
            transitive_limit,
        },
    )
    .await?;
    for line in response.lines {
        println!("{line}");
    }
    Ok(())
}

async fn run_daemon_trace(
    layout: &kin_core::KinLayout,
    request: &TraceRequest,
) -> Result<TraceResponse> {
    let daemon_url = std::env::var("KIN_DAEMON_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(Some)
        .unwrap_or(crate::daemon_client::resolve_daemon_url(layout).await?);
    let base_url =
        daemon_url.ok_or_else(|| crate::daemon_client::daemon_required_error("trace", layout))?;
    let client = crate::daemon_client::DaemonClient::from_base_url(base_url)?;
    client.trace(request).await.context("daemon trace failed")
}

#[allow(clippy::too_many_arguments)]
pub fn build_trace_response(
    layout: &kin_core::KinLayout,
    binding: &kin_core::LocalRepositoryAuthorityBinding,
    graph: &impl GraphStore,
    request: &TraceRequest,
    envelope: &kin_mcp::Envelope,
) -> Result<TraceResponse> {
    if request.json {
        return build_trace_json_response(layout, graph, &request.entity);
    }

    Ok(TraceResponse {
        lines: build_trace_lines(
            layout,
            binding,
            graph,
            &request.entity,
            request.compact,
            &request.budget,
            request.assistant.as_deref(),
            request.max_lines,
            request.nearby_limit,
            request.transitive_limit,
            envelope,
        )?,
        entities: Vec::new(),
    })
}

/// The absence qualifier for a pack whose dependency walk came back empty.
///
/// Declares `trace_data_flow`, whose spec is `field: "chain"`, `kind: "no_flow"`
/// and subject "no data-flow chain was found from the focal entity". That is the
/// direction this command walked: every group a pack carries
/// (`dependency_signatures`, `transitive_deps`) runs OUTWARD from the focal.
///
/// Deliberately NOT `get_context_pack`, even though `kin_context::build_context_pack`
/// above is what builds the pack. That tool's spec field is `dependents`, the
/// INBOUND direction, and `kin_mcp::negative` chose it over `dependencies` on
/// purpose. A `ContextPack` holds no dependents group at all, so handing that
/// gate a synthetic `"dependents": []` would run a leaf's outbound fact through
/// a gate built for the opposite claim and print a sentence about a set this
/// command never walked. Matching the gate to the BUILDER rather than to the
/// CLAIM is the same mistake as naming the wrong edge class, which is what
/// `IMPACT_REFERENCE_KINDS` warns about one level down.
///
/// The coverage observation is shared with the inbound readers because it is
/// direction-agnostic: it reports whether this graph holds cross-file edges of
/// these classes at all, and a graph holding none can no more show what a focal
/// reaches than what reaches it.
fn trace_absence_qualifier(
    graph: &impl GraphStore,
    target: &Entity,
    envelope: &kin_mcp::Envelope,
) -> Vec<String> {
    let coverage = kin_mcp::edge_coverage::observe_cross_file_reference_coverage_for_languages(
        graph,
        &[target.language],
        &kin_mcp::handlers::review::IMPACT_REFERENCE_KINDS,
    );
    let payload = serde_json::json!({
        "chain": [],
        kin_mcp::EDGE_COVERAGE_KEY: coverage,
    });
    crate::commands::absence_qualifier::qualify("trace_data_flow", &payload, envelope, "")
}

pub fn build_trace_json_response(
    layout: &kin_core::KinLayout,
    graph: &impl GraphStore,
    entity: &str,
) -> Result<TraceResponse> {
    if looks_like_file_path(entity) {
        return Ok(TraceResponse {
            lines: Vec::new(),
            entities: Vec::new(),
        });
    }

    let matches = query_trace_matches(graph, entity)?;
    let mut matches = if matches.is_empty() {
        fallback_leaf_trace_matches(graph, entity)?
    } else {
        matches
    };

    if let Some(best_id) = select_best_match_with_layout(entity, &matches).map(|e| e.id) {
        matches.sort_by_key(|candidate| (candidate.id != best_id, candidate.name.len()));
    }

    let entities = matches
        .iter()
        .map(|candidate| TraceJsonEntity {
            kind: format!("{:?}", candidate.kind),
            name: candidate.name.clone(),
            file: candidate
                .file_origin
                .as_ref()
                .map(|f| display_read_path(layout, &f.0))
                .unwrap_or_default(),
            line: kin_mcp::handlers::common::entity_presentation_start_line(candidate).unwrap_or(1),
            signature: (!candidate.signature.is_empty()).then(|| candidate.signature.clone()),
        })
        .collect::<Vec<_>>();

    Ok(TraceResponse {
        lines: Vec::new(),
        entities,
    })
}

#[allow(clippy::too_many_arguments)]
fn build_trace_lines(
    layout: &kin_core::KinLayout,
    binding: &kin_core::LocalRepositoryAuthorityBinding,
    graph: &impl GraphStore,
    entity: &str,
    compact: bool,
    budget: &str,
    assistant: Option<&str>,
    max_lines: usize,
    nearby_limit: usize,
    transitive_limit: usize,
    envelope: &kin_mcp::Envelope,
) -> Result<Vec<String>> {
    // Agents sometimes pass file paths instead of entity names; resolve those to
    // the graph-owned entities declared in that file rather than a raw file read.
    if looks_like_file_path(entity) {
        return Ok(render_file_path_trace_lines(layout, graph, entity));
    }

    build_trace_lines_with_graph(
        layout,
        binding,
        graph,
        entity,
        compact,
        budget,
        assistant,
        max_lines,
        nearby_limit,
        transitive_limit,
        envelope,
    )
}

pub async fn run_json(
    entity: String,
    _compact: bool,
    _budget: String,
    _assistant: Option<String>,
    _max_lines: usize,
    _nearby_limit: usize,
    _transitive_limit: usize,
) -> Result<()> {
    let layout = crate::commands::require_repository_layout()?;
    let _scope = announce_active_scope(&layout, "trace --json").await?;
    let response = run_daemon_trace(
        &layout,
        &TraceRequest {
            entity,
            json: true,
            compact: _compact,
            budget: _budget,
            assistant: _assistant,
            max_lines: _max_lines,
            nearby_limit: _nearby_limit,
            transitive_limit: _transitive_limit,
        },
    )
    .await?;
    println!("{}", serde_json::to_string(&response.entities)?);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn build_trace_lines_with_graph(
    layout: &kin_core::KinLayout,
    binding: &kin_core::LocalRepositoryAuthorityBinding,
    graph: &impl GraphStore,
    entity: &str,
    compact: bool,
    budget: &str,
    assistant: Option<&str>,
    max_lines: usize,
    nearby_limit: usize,
    transitive_limit: usize,
    envelope: &kin_mcp::Envelope,
) -> Result<Vec<String>> {
    let token_budget = parse_budget(budget)?;
    let focal_max_lines = if compact {
        max_lines.min(12)
    } else {
        max_lines
    };
    let snippet_max_chars = if compact { 800 } else { 2400 };
    let nearby_limit = if compact { 0 } else { nearby_limit };
    let transitive_limit = if compact { 0 } else { transitive_limit };
    let followup_limit = if compact { 0 } else { 4 };
    let mut lines = Vec::new();

    let assistant_hint = assistant.and_then(|a| match a.to_lowercase().as_str() {
        "claude" | "claude-code" => Some(kin_context::AssistantHint::ClaudeCode),
        "codex" => Some(kin_context::AssistantHint::Codex),
        "gemini" | "gemini-cli" => Some(kin_context::AssistantHint::GeminiCli),
        _ => None,
    });

    let matches = query_trace_matches(graph, entity)?;
    let matches = if matches.is_empty() {
        fallback_leaf_trace_matches(graph, entity)?
    } else {
        matches
    };

    if matches.is_empty() {
        return Ok(trace_not_found_guidance(entity));
    }

    let target = match select_best_match_with_layout(entity, &matches) {
        Some(target) => target,
        None => return Ok(trace_not_found_guidance(entity)),
    };

    let opts = kin_context::ContextOptions {
        budget: token_budget,
        max_depth: if compact { 5 } else { 2 },
        include_tests: true,
        include_contracts: true,
        include_traffic: false,
        assistant_hint,
    };
    let pack = kin_context::build_context_pack(graph, &target.id, &opts)?;

    let file_display = target
        .file_origin
        .as_ref()
        .map(|f| display_read_path(layout, &f.0))
        .unwrap_or_else(|| "unknown".to_string());

    if compact {
        lines.push(format!(
            "{} ({:?}) @ {}",
            target.name, target.kind, file_display
        ));
    } else {
        lines.push(format!(
            "Trace for '{}' -> {} ({:?}, {})",
            entity, target.name, target.kind, file_display
        ));
        lines.push(format!(
            "Budget: {}/{} tokens",
            pack.actual_tokens,
            token_budget.max_tokens()
        ));
    }

    if let Some(content) =
        render_entity_source(binding, graph, target, focal_max_lines, snippet_max_chars)?
    {
        if !compact {
            lines.push("\n--- Focal ---".to_string());
        }
        lines.push(content.clone());
        if followup_limit > 0 {
            let followups = extract_textual_followups(&content);
            if !followups.is_empty() {
                lines.push("\n--- Follow-ups ---".to_string());
                for item in followups.iter().take(followup_limit) {
                    lines.push(format!("- {}", item));
                }
            }
        }
    } else if let Some(entry) = pack.focal_entities.first() {
        if !compact {
            lines.push("\n--- Focal ---".to_string());
        }
        let clipped =
            clip_rendered_text_with_cap(&entry.content, focal_max_lines, snippet_max_chars);
        lines.push(clipped.clone());
        if followup_limit > 0 {
            let followups = extract_textual_followups(&clipped);
            if !followups.is_empty() {
                lines.push("\n--- Follow-ups ---".to_string());
                for item in followups.iter().take(followup_limit) {
                    lines.push(format!("- {}", item));
                }
            }
        }
    }

    // Where the silence was. An empty dependency walk printed NOTHING at all,
    // which is quieter than impact's bare line and says even less: a reader saw
    // a pack with no dependency section and had no way to tell a focal that
    // reaches nothing from one whose outbound edges this graph could never have
    // held (FIR-2524).
    //
    // Hoisted above the compact split on purpose. Both renderings key on the
    // same two groups, and leaving this inside the compact arm left the DEFAULT
    // invocation, the one a person types, as the only surface still silent.
    if pack.dependency_signatures.is_empty() && pack.transitive_deps.is_empty() {
        lines.extend(trace_absence_qualifier(graph, target, envelope));
    }

    if compact {
        // Compact deps: one-liner per dependency with file path so agents can Read
        // directly instead of tracing each dependency serially (anti-spiral).
        let all_dep_ids: Vec<_> = pack
            .dependency_signatures
            .iter()
            .chain(pack.transitive_deps.iter())
            .map(|e| &e.entity_id)
            .collect();
        if !all_dep_ids.is_empty() {
            lines.push("\n--- Deps ---".to_string());
            let mut printed = 0usize;
            for eid in &all_dep_ids {
                if printed >= 8 {
                    break;
                }
                if let Some(dep) = graph.get_entity(eid)? {
                    if dep.file_origin == target.file_origin {
                        continue; // skip same-file deps — agent already has the file
                    }
                    let file_loc = dep
                        .file_origin
                        .as_ref()
                        .map(|f| display_read_path(layout, &f.0))
                        .unwrap_or_else(|| "unknown".to_string());
                    let line = kin_mcp::handlers::common::entity_presentation_start_line(&dep)
                        .unwrap_or(0);
                    lines.push(format!("  {} @ {}:{}", dep.name, file_loc, line));
                    printed += 1;
                }
            }
        }
    } else {
        if !pack.dependency_signatures.is_empty() {
            lines.push("\n--- Nearby ---".to_string());
            let mut expanded_same_file = 0usize;
            for entry in pack.dependency_signatures.iter().take(nearby_limit) {
                if let Some(dep) = graph.get_entity(&entry.entity_id)? {
                    let same_file = dep.file_origin == target.file_origin;
                    if same_file && expanded_same_file < 4 {
                        if let Some(content) = render_neighbor_source(
                            binding,
                            graph,
                            &dep,
                            focal_max_lines,
                            snippet_max_chars,
                        )? {
                            lines.push(content);
                            expanded_same_file += 1;
                            continue;
                        }
                    }
                }

                lines.push(clip_rendered_text_with_cap(
                    &entry.content,
                    focal_max_lines,
                    snippet_max_chars,
                ));
            }
        }

        if !pack.transitive_deps.is_empty() {
            lines.push("\n--- Transitive ---".to_string());
            for entry in pack.transitive_deps.iter().take(transitive_limit) {
                lines.push(clip_rendered_text_with_cap(
                    &entry.content,
                    focal_max_lines,
                    snippet_max_chars,
                ));
            }
        }
    }

    if !compact {
        lines.push(format!(
            "\nCounts: contracts={} tests={} work_items={} annotations={}",
            pack.contracts.len(),
            pack.tests.len(),
            pack.work_items.len(),
            pack.annotations.len()
        ));
        let read_path = display_read_path(
            layout,
            target
                .file_origin
                .as_ref()
                .map(|f| f.0.as_str())
                .unwrap_or(""),
        );
        lines.push(focused_trace_tip(&read_path, &target.name));
    }

    Ok(lines)
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

fn query_trace_matches(graph: &impl GraphStore, query: &str) -> Result<Vec<Entity>> {
    Ok(kin_core::query_trace_matches(graph, query)?)
}

fn fallback_leaf_trace_matches(graph: &impl GraphStore, query: &str) -> Result<Vec<Entity>> {
    Ok(kin_core::fallback_leaf_trace_matches(graph, query)?)
}

#[cfg(test)]
fn select_best_match<'a>(query: &str, matches: &'a [Entity]) -> Option<&'a Entity> {
    kin_core::select_best_match(query, matches, |entity, hint| {
        kin_core::normalize_symbol_hint(&entity.name).contains(hint)
    })
}

fn select_best_match_with_layout<'a>(query: &str, matches: &'a [Entity]) -> Option<&'a Entity> {
    kin_core::select_best_match(query, matches, |entity, hint| {
        entity_mentions_qualifier(entity, hint)
    })
}

fn render_file_path_trace_lines(
    layout: &kin_core::KinLayout,
    graph: &impl GraphStore,
    entity: &str,
) -> Vec<String> {
    let read_path = display_read_path(layout, entity);
    let entities = graph_entities_for_file(graph, entity);

    if entities.is_empty() {
        return vec![format!(
            "`kin trace` expects an entity name, not a file path.\n\
             To read this file: Read {}\n\
             To find entities: kin search <EntityName> --show-body",
            read_path
        )];
    }

    let mut lines = vec![format!("--- entities declared in {} ---", read_path)];
    for entity in entities.iter().take(40) {
        let line = kin_mcp::handlers::common::entity_presentation_start_line(entity).unwrap_or(0);
        lines.push(format!(
            "  {} ({:?}) @ {}:{}",
            entity.name, entity.kind, read_path, line
        ));
    }
    lines.push(
        "\nTip: `kin trace <EntityName>` to follow data flow from one of these declarations."
            .to_string(),
    );
    lines
}

fn graph_entities_for_file(graph: &impl GraphStore, path: &str) -> Vec<Entity> {
    let direct = graph
        .query_entities(&kin_model::EntityFilter {
            file_path: Some(kin_model::FilePathId::new(path)),
            ..Default::default()
        })
        .unwrap_or_default();
    if !direct.is_empty() {
        return sort_entities_by_line(direct);
    }

    let suffix = path.trim_start_matches("./");
    let matched = graph
        .query_entities(&kin_model::EntityFilter::default())
        .unwrap_or_default()
        .into_iter()
        .filter(|entity| {
            entity
                .file_origin
                .as_ref()
                .map(|origin| origin.0 == path || origin.0.ends_with(suffix))
                .unwrap_or(false)
        })
        .collect::<Vec<_>>();
    sort_entities_by_line(matched)
}

fn sort_entities_by_line(mut entities: Vec<Entity>) -> Vec<Entity> {
    entities.sort_by_key(|entity| {
        (
            entity
                .span
                .as_ref()
                .map(|span| span.start_line)
                .unwrap_or(0),
            entity.name.clone(),
        )
    });
    entities
}

fn focused_trace_tip(_read_path: &str, target_name: &str) -> String {
    if native_content_restricted() {
        format!(
            "Tip: you have enough context to summarize the flow. If needed, use `kin context {}` for a broader view.",
            target_name
        )
    } else {
        format!(
            "Tip: after 2-3 traces you likely have enough to answer. Use `kin context {}` only if you need a broader view.",
            target_name
        )
    }
}

fn native_content_restricted() -> bool {
    std::env::var("KIN_CONTENT_MODE")
        .map(|mode| mode == "deny")
        .unwrap_or(false)
}

fn looks_like_file_path(s: &str) -> bool {
    let s = s.trim();
    if s.is_empty() {
        return false;
    }
    // Contains path separators → definitely a file path
    if s.contains('/') || s.contains('\\') {
        return true;
    }
    // Ends with a known source file extension (but not dotted entity names like Foo.parse)
    let extensions = [
        ".ts", ".tsx", ".js", ".jsx", ".rs", ".py", ".go", ".java", ".c", ".h", ".cpp", ".hpp",
        ".cc", ".cxx", ".cs", ".rb", ".json", ".yaml", ".yml", ".toml", ".md",
    ];
    extensions.iter().any(|ext| s.ends_with(ext))
}

fn entity_mentions_qualifier(entity: &Entity, qualifier_hint: &str) -> bool {
    if kin_core::normalize_symbol_hint(&entity.name).contains(qualifier_hint) {
        return true;
    }

    if kin_core::normalize_symbol_hint(&entity.signature).contains(qualifier_hint) {
        return true;
    }

    entity
        .doc_summary
        .as_ref()
        .map(|summary| kin_core::normalize_symbol_hint(summary).contains(qualifier_hint))
        .unwrap_or(false)
}

fn render_entity_source(
    binding: &kin_core::LocalRepositoryAuthorityBinding,
    graph: &impl GraphStore,
    entity: &Entity,
    max_lines: usize,
    max_chars: usize,
) -> Result<Option<String>> {
    let Some(span) = entity.span.as_ref() else {
        return Ok(None);
    };
    let Some(file_origin) = entity.file_origin.as_ref() else {
        return Ok(None);
    };
    if span.file != *file_origin {
        anyhow::bail!(
            "entity '{}' has divergent source paths: file_origin '{}' but span file '{}'",
            entity.name,
            file_origin.0,
            span.file.0
        );
    }
    let bytes = crate::commands::graph::read_entity_file_bytes_from_graph(binding, graph, entity)?;
    let start = span.start_byte;
    let end = span.end_byte;
    if start >= end || end > bytes.len() {
        anyhow::bail!(
            "entity '{}' source span {}..{} is invalid for '{}' ({} bytes)",
            entity.name,
            start,
            end,
            file_origin.0,
            bytes.len()
        );
    }

    let source = std::str::from_utf8(&bytes[start..end]).with_context(|| {
        format!(
            "entity '{}' source span {}..{} in '{}' is not valid UTF-8",
            entity.name, start, end, file_origin.0
        )
    })?;
    let snippet = clip_rendered_text_with_cap(source.trim(), max_lines, max_chars);
    if snippet.is_empty() {
        return Ok(None);
    }

    Ok(Some(format!(
        "// {} ({:?}, {})\n{}",
        entity.name, file_origin.0, entity.language, snippet
    )))
}

fn display_read_path(_layout: &kin_core::KinLayout, rel_path: &str) -> String {
    rel_path.to_string()
}

fn render_neighbor_source(
    binding: &kin_core::LocalRepositoryAuthorityBinding,
    graph: &impl GraphStore,
    entity: &Entity,
    max_lines: usize,
    max_chars: usize,
) -> Result<Option<String>> {
    let Some(content) = render_entity_source(binding, graph, entity, max_lines, max_chars)? else {
        return Ok(None);
    };
    Ok(Some(format!("// same-file neighbor\n{}", content)))
}

#[cfg_attr(not(test), allow(dead_code))]
fn clip_rendered_text(text: &str, max_lines: usize) -> String {
    clip_rendered_text_with_cap(text, max_lines, 2400)
}

fn clip_rendered_text_with_cap(text: &str, max_lines: usize, max_chars: usize) -> String {
    let mut clipped_lines = Vec::new();
    let mut truncated = false;

    for (idx, line) in text.lines().enumerate() {
        if idx >= max_lines {
            truncated = true;
            break;
        }
        clipped_lines.push(line);
    }

    let mut out = clipped_lines.join("\n");
    if out.chars().count() > max_chars {
        out = out.chars().take(max_chars).collect::<String>();
        truncated = true;
    }
    if truncated {
        if !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str("... [truncated]");
    }
    out
}

fn extract_textual_followups(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if !(bytes[i].is_ascii_alphabetic() || bytes[i] == b'_' || bytes[i] == b'$') {
            i += 1;
            continue;
        }

        let start = i;
        i += 1;
        while i < bytes.len()
            && (bytes[i].is_ascii_alphanumeric()
                || bytes[i] == b'_'
                || bytes[i] == b'$'
                || bytes[i] == b'.')
        {
            i += 1;
        }

        if i >= bytes.len() || bytes[i] != b'(' {
            continue;
        }

        let candidate = &text[start..i];
        if !candidate.contains('.') {
            continue;
        }

        let mut parts = candidate
            .split('.')
            .filter(|p| !p.is_empty())
            .collect::<Vec<_>>();
        if parts.len() < 2 {
            continue;
        }
        if parts[0].starts_with("console") || parts[0].starts_with("Promise") {
            continue;
        }

        let normalized = if parts.len() >= 2 {
            parts
                .drain(parts.len().saturating_sub(2)..)
                .collect::<Vec<_>>()
                .join(".")
        } else {
            candidate.to_string()
        };

        if !out.contains(&normalized) {
            out.push(normalized);
        }
        if out.len() >= 6 {
            break;
        }
    }
    out
}

/// Actionable guidance when `kin trace <symbol>` resolves nothing — not as a
/// graph entity and not via the source-symbol fallback. Keep the not-found
/// signal, then point at discovery commands rather than dead-ending. Honest by
/// construction — no claim the symbol exists anywhere.
fn trace_not_found_guidance(entity: &str) -> Vec<String> {
    vec![
        format!("Entity '{entity}' not found in this repo's graph (no source-symbol fallback matched either)."),
        format!(
            "hint: try `kin search {entity}` to find the symbol by name, or `kin locate \"<what it does>\"` to find relevant files."
        ),
    ]
}

#[cfg(test)]
mod tests {
    /// A daemon whose substrate is sound, so the FIR-2524 absence qualifier
    /// answers on coverage rather than on the envelope. These cases assert trace
    /// CONTENT and must not start failing for a reason they are not about.
    fn healthy_trace_envelope() -> kin_mcp::Envelope {
        kin_mcp::Envelope::daemon().with_health(&serde_json::json!({
            "initialized": true,
            "graph_loaded": true,
            "graph_entity_count": 2,
            "graph_generation": 1,
        }))
    }

    use super::{
        entity_mentions_qualifier, fallback_leaf_trace_matches, query_trace_matches,
        select_best_match, trace_not_found_guidance,
    };
    use kin_core::normalize_trace_name;
    use kin_db::{InMemoryGraph, LocalFileBackend};
    use kin_model::EntityStore;
    use kin_model::{
        Entity, EntityId, EntityKind, EntityMetadata, EntityRole, FingerprintAlgorithm, Hash256,
        LanguageId, RepositoryId, SemanticFingerprint, Visibility, WorkspaceId,
    };
    use std::sync::Arc;

    fn absent_binding(layout: &kin_core::KinLayout) -> kin_core::LocalRepositoryAuthorityBinding {
        kin_core::LocalRepositoryAuthorityBinding::from_parts(
            RepositoryId::new("trace-test").unwrap(),
            WorkspaceId::new(),
            Arc::new(LocalFileBackend::new(layout.kindb_dir())),
        )
    }

    #[test]
    fn trace_not_found_guidance_keeps_signal_and_offers_discovery() {
        let lines = trace_not_found_guidance("frobnicate");
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

    fn make_entity(name: &str) -> Entity {
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::TypeScript,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_hex(
                    "1111111111111111111111111111111111111111111111111111111111111111",
                )
                .unwrap(),
                signature_hash: Hash256::from_hex(
                    "2222222222222222222222222222222222222222222222222222222222222222",
                )
                .unwrap(),
                behavior_hash: Hash256::from_hex(
                    "3333333333333333333333333333333333333333333333333333333333333333",
                )
                .unwrap(),
                equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: None,
            span: None,
            signature: format!("function {name}()"),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    #[test]
    fn prefers_exact_name_match() {
        let entities = vec![make_entity("Foo.bar"), make_entity("bar")];
        let picked = select_best_match("bar", &entities).unwrap();
        assert_eq!(picked.name, "bar");
    }

    #[test]
    fn falls_back_to_qualified_leaf_match() {
        let entities = vec![make_entity("Foo.parseStrict"), make_entity("Foo.parse")];
        let picked = select_best_match("parseStrict", &entities).unwrap();
        assert_eq!(picked.name, "Foo.parseStrict");
    }

    #[test]
    fn fallback_leaf_trace_matches_supports_dotted_queries() {
        let graph = InMemoryGraph::new();
        let run = make_entity("run");
        graph.upsert_entity(&run).unwrap();

        let matches = fallback_leaf_trace_matches(&graph, "cfg.run").unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].name, "run");
    }

    #[test]
    fn prefers_rust_style_qualified_match_without_generics() {
        let entities = vec![make_entity("Router<S>::route"), make_entity("route")];
        let picked = select_best_match("Router::route", &entities).unwrap();
        assert_eq!(picked.name, "Router<S>::route");
    }

    #[test]
    fn normalize_trace_name_strips_generic_arguments() {
        assert_eq!(normalize_trace_name("Router<S>::route"), "Router::route");
        assert_eq!(normalize_trace_name("Map<K, V>::insert"), "Map::insert");
    }

    #[test]
    fn query_trace_matches_falls_back_to_leaf_for_rust_style_names() {
        let store = InMemoryGraph::new();
        let entity = make_entity("Router<S>::route");
        store.upsert_entity(&entity).unwrap();

        let matches = query_trace_matches(&store, "Router::route").unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].name, "Router<S>::route");
    }

    #[test]
    fn query_trace_matches_rejects_unrelated_leaf_match_for_qualified_name() {
        let store = InMemoryGraph::new();
        store.upsert_entity(&make_entity("run")).unwrap();

        let matches = query_trace_matches(&store, "$Config::run").unwrap();
        assert!(matches.is_empty());
    }

    #[test]
    fn select_best_match_returns_none_when_qualifier_is_unmatched() {
        let entities = vec![make_entity("run"), make_entity("Helper.run")];
        let picked = select_best_match("$Config::run", &entities);
        assert!(picked.is_none());
    }

    #[test]
    fn clip_rendered_text_limits_lines() {
        let text = "a\nb\nc\nd";
        let clipped = super::clip_rendered_text(text, 2);
        assert!(clipped.contains("a\nb"));
        assert!(clipped.contains("[truncated]"));
        assert!(!clipped.contains("c\nd"));
    }

    #[test]
    fn clip_rendered_text_limits_chars() {
        let text = "x".repeat(3000);
        let clipped = super::clip_rendered_text(&text, 100);
        assert!(clipped.contains("[truncated]"));
        assert!(clipped.len() < 2600);
    }

    #[test]
    fn clip_rendered_text_with_cap_uses_custom_char_limit() {
        let text = "x".repeat(3000);
        let clipped = super::clip_rendered_text_with_cap(&text, 100, 1200);
        assert!(clipped.contains("[truncated]"));
        assert!(clipped.len() < 1400);
    }

    #[test]
    fn extract_textual_followups_captures_multi_segment_calls() {
        let text = r#"
const result = schema.engine.run(payload, ctx);
issues.map((iss) => util.finalizeItem(iss, ctx, core.config()));
"#;
        let followups = super::extract_textual_followups(text);
        assert!(followups.iter().any(|s| s == "engine.run"));
        assert!(followups.iter().any(|s| s == "util.finalizeItem"));
        assert!(followups.iter().any(|s| s == "core.config"));
    }

    #[test]
    fn looks_like_file_path_detects_paths() {
        assert!(super::looks_like_file_path("src/parser.ts"));
        assert!(super::looks_like_file_path(
            "packages/app/src/v4/core/parse.ts"
        ));
        assert!(super::looks_like_file_path("index.js"));
        assert!(super::looks_like_file_path("main.rs"));
        assert!(super::looks_like_file_path("lib.py"));
        assert!(super::looks_like_file_path("config.json"));
        assert!(super::looks_like_file_path(
            "src/_kin_probe_deadcheck/probe_group0.ts"
        ));
    }

    #[test]
    fn looks_like_file_path_rejects_entity_names() {
        assert!(!super::looks_like_file_path("parseStrict"));
        assert!(!super::looks_like_file_path("MyString"));
        assert!(!super::looks_like_file_path("$MyType"));
        assert!(!super::looks_like_file_path("Router::route"));
        assert!(!super::looks_like_file_path("Foo.parse"));
        assert!(!super::looks_like_file_path("_ns.run"));
    }

    #[test]
    fn entity_mentions_qualifier_uses_graph_signature_not_disk() {
        let mut entity = make_entity("parse");
        entity.signature = "fn parse(input: &Config) -> Result<()>".to_string();
        assert!(entity_mentions_qualifier(&entity, "config"));

        let unrelated = make_entity("parse");
        assert!(!entity_mentions_qualifier(&unrelated, "config"));
    }

    #[test]
    fn entity_mentions_qualifier_uses_graph_doc_summary() {
        let mut entity = make_entity("run");
        entity.signature = "fn run()".to_string();
        entity.doc_summary = Some("Drives the Scheduler loop".to_string());
        assert!(entity_mentions_qualifier(&entity, "scheduler"));
    }

    #[test]
    fn trace_graph_miss_returns_guidance_without_disk_fallback() {
        let graph = InMemoryGraph::new();
        let layout = kin_core::KinLayout::discover(&std::env::current_dir().unwrap())
            .or_else(|| kin_core::KinLayout::discover(std::path::Path::new(".")));
        let layout = match layout {
            Some(layout) => layout,
            None => return,
        };
        let binding = absent_binding(&layout);
        let response = super::build_trace_response(
            &layout,
            &binding,
            &graph,
            &super::TraceRequest {
                entity: "definitelyMissingEntity".to_string(),
                json: false,
                compact: false,
                budget: "8k".to_string(),
                assistant: None,
                max_lines: 20,
                nearby_limit: 3,
                transitive_limit: 0,
            },
            &healthy_trace_envelope(),
        )
        .unwrap();
        let joined = response.lines.join("\n");
        assert!(
            joined.contains("not found"),
            "graph-miss guidance: {joined}"
        );
        assert!(
            joined.contains("kin search definitelyMissingEntity"),
            "offers search instead of disk fallback: {joined}"
        );
    }
}
