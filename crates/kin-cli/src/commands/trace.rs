// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};
use kin_model::{Entity, GraphStore, TokenBudget};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

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
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
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
    let base_url = daemon_url.ok_or_else(|| {
        anyhow::anyhow!("Kin daemon is required for trace but no daemon endpoint is available")
    })?;
    let client = crate::daemon_client::DaemonClient::from_base_url(base_url)?;
    client.trace(request).await.context("daemon trace failed")
}

#[allow(clippy::too_many_arguments)]
pub fn build_trace_response(
    layout: &kin_core::KinLayout,
    graph: &impl GraphStore,
    request: &TraceRequest,
) -> Result<TraceResponse> {
    if request.json {
        return build_trace_json_response(layout, graph, &request.entity);
    }

    Ok(TraceResponse {
        lines: build_trace_lines(
            layout,
            graph,
            &request.entity,
            request.compact,
            &request.budget,
            request.assistant.as_deref(),
            request.max_lines,
            request.nearby_limit,
            request.transitive_limit,
        )?,
        entities: Vec::new(),
    })
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

    if let Some(best_id) = select_best_match_with_layout(layout, entity, &matches).map(|e| e.id) {
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
            line: candidate
                .span
                .as_ref()
                .map(|span| span.start_line)
                .unwrap_or(1),
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
    graph: &impl GraphStore,
    entity: &str,
    compact: bool,
    budget: &str,
    assistant: Option<&str>,
    max_lines: usize,
    nearby_limit: usize,
    transitive_limit: usize,
) -> Result<Vec<String>> {
    // Detect file path arguments inside the daemon-owned renderer. Agents sometimes
    // pass file paths instead of entity names; the daemon returns the rendered file
    // content without giving the CLI a local source read path.
    if looks_like_file_path(entity) {
        return Ok(render_file_path_trace_lines(layout, entity));
    }

    build_trace_lines_with_graph(
        layout,
        graph,
        entity,
        compact,
        budget,
        assistant,
        max_lines,
        nearby_limit,
        transitive_limit,
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
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
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
    graph: &impl GraphStore,
    entity: &str,
    compact: bool,
    budget: &str,
    assistant: Option<&str>,
    max_lines: usize,
    nearby_limit: usize,
    transitive_limit: usize,
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
        if let Some(fallback) =
            source_symbol_fallback(layout, entity, focal_max_lines, snippet_max_chars)?
        {
            return Ok(render_source_fallback_lines(
                layout,
                entity,
                &fallback,
                followup_limit,
            ));
        }
        return Ok(trace_not_found_guidance(entity));
    }

    let target = match select_best_match_with_layout(layout, entity, &matches) {
        Some(target) => target,
        None => {
            if let Some(fallback) =
                source_symbol_fallback(layout, entity, focal_max_lines, snippet_max_chars)?
            {
                return Ok(render_source_fallback_lines(
                    layout,
                    entity,
                    &fallback,
                    followup_limit,
                ));
            }
            return Ok(trace_not_found_guidance(entity));
        }
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

    if let Some(content) = render_entity_source(layout, target, focal_max_lines, snippet_max_chars)
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
                    let line = dep.span.as_ref().map(|s| s.start_line).unwrap_or(0);
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
                        if let Some(content) =
                            render_neighbor_source(layout, &dep, focal_max_lines, snippet_max_chars)
                        {
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

fn select_best_match_with_layout<'a>(
    layout: &kin_core::KinLayout,
    query: &str,
    matches: &'a [Entity],
) -> Option<&'a Entity> {
    kin_core::select_best_match(query, matches, |entity, hint| {
        entity_or_file_mentions_qualifier(layout, entity, hint)
    })
}

struct SourceSymbolFallback {
    path: PathBuf,
    snippet: String,
}

fn source_symbol_fallback(
    layout: &kin_core::KinLayout,
    query: &str,
    max_lines: usize,
    max_chars: usize,
) -> Result<Option<SourceSymbolFallback>> {
    let source_root = kin_core::source_dir(layout);
    if !source_root.exists() {
        return Ok(None);
    }

    let search_patterns = textual_patterns_for_query(query);
    if search_patterns.is_empty() {
        return Ok(None);
    }

    let mut stack = vec![source_root.clone()];
    let mut best: Option<(i32, PathBuf, String)> = None;

    while let Some(path) = stack.pop() {
        let entries = match std::fs::read_dir(&path) {
            Ok(entries) => entries,
            Err(_) => continue,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(_) => continue,
            };

            if file_type.is_dir() {
                stack.push(path);
                continue;
            }

            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if !matches!(
                ext,
                "ts" | "tsx" | "js" | "jsx" | "rs" | "py" | "go" | "java"
            ) {
                continue;
            }

            let content = match std::fs::read_to_string(&path) {
                Ok(content) => content,
                Err(_) => continue,
            };

            if let Some((score, snippet)) = best_source_snippet_for_patterns(
                &path,
                &content,
                &search_patterns,
                max_lines,
                max_chars,
            ) {
                match &best {
                    Some((best_score, _, _)) if *best_score >= score => {}
                    _ => best = Some((score, path.clone(), snippet)),
                }
            }
        }
    }

    Ok(best.map(|(_, path, snippet)| SourceSymbolFallback { path, snippet }))
}

fn textual_patterns_for_query(query: &str) -> Vec<String> {
    let query = query.trim();
    let mut patterns = Vec::new();

    if !query.is_empty() {
        patterns.push(query.to_string());
    }

    let dotted = query.replace("::", ".");
    if dotted != query {
        patterns.push(dotted.clone());
    }

    let qualifier = kin_core::qualifier_hint_from_query(query)
        .map(|q| q.replace('$', ""))
        .unwrap_or_default();
    let leaf = query
        .rfind("::")
        .map(|idx| &query[idx + 2..])
        .or_else(|| query.rfind('.').map(|idx| &query[idx + 1..]))
        .unwrap_or(query)
        .trim();

    if !qualifier.is_empty() && !leaf.is_empty() {
        patterns.push(leaf.to_string());
        patterns.push(format!("{}.{}", qualifier, leaf));
        patterns.push(format!("{}::{}", qualifier, leaf));
        patterns.push(format!("inst._zod.{}", leaf));
        patterns.push(format!("_zod.{}", leaf));
        patterns.push(format!(".{}", leaf));
    } else if !leaf.is_empty() {
        patterns.push(leaf.to_string());
        patterns.push(format!("_zod.{}", leaf));
        patterns.push(format!(".{}", leaf));
    }

    patterns.sort();
    patterns.dedup();
    patterns
}

fn best_source_snippet_for_patterns(
    path: &std::path::Path,
    content: &str,
    patterns: &[String],
    max_lines: usize,
    max_chars: usize,
) -> Option<(i32, String)> {
    let mut best: Option<(i32, usize)> = None;
    let path_str = path.to_string_lossy();

    for pattern in patterns {
        if pattern.is_empty() {
            continue;
        }
        for (idx, _) in content.match_indices(pattern) {
            let mut score = match pattern.as_str() {
                p if p == patterns[0] => 300,
                p if p.starts_with("inst._zod.") => 260,
                p if p.starts_with("_zod.") => 240,
                p if p.starts_with('.') => 120,
                _ => 180,
            };

            if path_str.contains("/core/") {
                score += 50;
            }
            if path_str.contains("/classic/") {
                score += 35;
            }
            if path_str.contains("/mini/") {
                score -= 90;
            }
            if path_str.contains("/tests/")
                || path_str.contains("/test/")
                || path_str.contains(".test.")
                || path_str.contains(".spec.")
                || path_str.contains("/fixtures/")
                || path_str.contains("/fixture/")
                || path_str.contains("/examples/")
                || path_str.contains("/example/")
            {
                score -= 220;
            }
            if path_str.contains("/bench/") || path_str.contains("/tsc/bench/") {
                score -= 120;
            }
            score += local_symbol_context_bonus(content, idx, pattern);

            match best {
                Some((best_score, _)) if best_score >= score => {}
                _ => best = Some((score, idx)),
            }
        }
    }

    let (score, idx) = best?;
    let snippet = snippet_around_index(content, idx, max_lines, max_chars);
    Some((
        score,
        format!("// source fallback ({})\n{}", path.display(), snippet),
    ))
}

fn local_symbol_context_bonus(content: &str, idx: usize, pattern: &str) -> i32 {
    let window = safe_char_window_around_byte(content, idx, 160, 240);
    let leaf = pattern
        .trim_start_matches('.')
        .rsplit("::")
        .next()
        .and_then(|s| s.rsplit('.').next())
        .unwrap_or(pattern)
        .trim();
    if leaf.is_empty() {
        return 0;
    }

    let mut score = 0;
    for needle in [
        format!("function {}", leaf),
        format!("const {} =", leaf),
        format!("let {} =", leaf),
        format!("var {} =", leaf),
        format!("class {}", leaf),
        format!("{} =", leaf),
        format!("{}(", leaf),
        format!("{}:", leaf),
        format!("inst.{} =", leaf),
        format!("schema.{}(", leaf),
        format!("parse.{}(", leaf),
    ] {
        if window.contains(&needle) {
            score += 35;
        }
    }

    if window.contains("_zod.run") {
        score += 30;
    }

    if window.contains("describe(") || window.contains("it(") || window.contains("test(") {
        score -= 80;
    }

    score
}

fn safe_char_window_around_byte(content: &str, idx: usize, before: usize, after: usize) -> &str {
    let mut start = idx.saturating_sub(before).min(content.len());
    while start > 0 && !content.is_char_boundary(start) {
        start -= 1;
    }

    let mut end = (idx + after).min(content.len());
    while end < content.len() && !content.is_char_boundary(end) {
        end += 1;
    }

    &content[start..end]
}

fn snippet_around_index(content: &str, index: usize, max_lines: usize, max_chars: usize) -> String {
    let mut current = 0usize;
    let mut target_line = 0usize;
    for (line_no, line) in content.lines().enumerate() {
        let next = current + line.len() + 1;
        if index < next {
            target_line = line_no;
            break;
        }
        current = next;
    }

    let start_line = target_line.saturating_sub(max_lines / 2);
    let end_line = start_line + max_lines;
    let snippet = content
        .lines()
        .enumerate()
        .filter(|(i, _)| *i >= start_line && *i < end_line)
        .map(|(_, line)| line)
        .collect::<Vec<_>>()
        .join("\n");

    clip_rendered_text_with_cap(&snippet, max_lines, max_chars)
}

fn render_file_path_trace_lines(layout: &kin_core::KinLayout, entity: &str) -> Vec<String> {
    let source_root = kin_core::source_dir(layout);
    let file_path = source_root.join(entity);
    let read_path = display_read_path(layout, entity);
    if file_path.is_file() {
        let mut lines = vec![format!("--- {} ---", read_path)];
        if let Ok(content) = std::fs::read_to_string(&file_path) {
            // Use generous limits for file auto-reads; these are usually small
            // files and truncation causes agents to re-read redundantly.
            lines.push(clip_rendered_text_with_cap(&content, 40, 2400));
        }
        return lines;
    }

    vec![format!(
        "`kin trace` expects an entity name, not a file path.\n\
         To read this file: Read {}\n\
         To find entities: kin search <EntityName> --show-body",
        read_path
    )]
}

fn render_source_fallback_lines(
    layout: &kin_core::KinLayout,
    query: &str,
    fallback: &SourceSymbolFallback,
    followup_limit: usize,
) -> Vec<String> {
    let display_path = display_source_path(layout, &fallback.path);
    let mut lines = vec![
        format!("Trace for '{}' -> source match ({})", query, display_path),
        "\n--- Focal ---".to_string(),
        fallback.snippet.clone(),
    ];
    let followups = extract_textual_followups(&fallback.snippet);
    if !followups.is_empty() {
        lines.push("\n--- Follow-ups ---".to_string());
        for item in followups.iter().take(followup_limit) {
            lines.push(format!("- {}", item));
        }
    }
    lines.push("\nCounts: contracts=0 tests=0 work_items=0 annotations=0".to_string());
    lines.push(fallback_trace_tip(&display_path));
    lines
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

fn fallback_trace_tip(_display_path: &str) -> String {
    if native_content_restricted() {
        "Tip: you have enough context to summarize the flow. Stop tracing and answer.".to_string()
    } else {
        "Tip: after 2-3 traces you likely have enough to answer. Stop and summarize.".to_string()
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

fn entity_or_file_mentions_qualifier(
    layout: &kin_core::KinLayout,
    entity: &Entity,
    qualifier_hint: &str,
) -> bool {
    if kin_core::normalize_symbol_hint(&entity.name).contains(qualifier_hint) {
        return true;
    }

    let Some(file_origin) = entity.file_origin.as_ref() else {
        return false;
    };

    let path = kin_core::source_dir(layout).join(&file_origin.0);
    let Ok(content) = std::fs::read_to_string(&path) else {
        return false;
    };
    let normalized = kin_core::normalize_symbol_hint(&content);
    normalized.contains(qualifier_hint)
}

fn render_entity_source(
    layout: &kin_core::KinLayout,
    entity: &Entity,
    max_lines: usize,
    max_chars: usize,
) -> Option<String> {
    let span = entity.span.as_ref()?;
    let file_origin = entity.file_origin.as_ref()?;
    let path = kin_core::source_dir(layout).join(&file_origin.0);
    let bytes = std::fs::read(&path).ok()?;
    let start = span.start_byte.min(bytes.len());
    let end = span.end_byte.min(bytes.len());
    if start >= end {
        return None;
    }

    let snippet = clip_rendered_text_with_cap(
        String::from_utf8_lossy(&bytes[start..end]).trim(),
        max_lines,
        max_chars,
    );
    if snippet.is_empty() {
        return None;
    }

    Some(format!(
        "// {} ({:?}, {})\n{}",
        entity.name, file_origin.0, entity.language, snippet
    ))
}

fn display_source_path(layout: &kin_core::KinLayout, path: &std::path::Path) -> String {
    let source_root = kin_core::source_dir(layout);
    if let Ok(rel) = path.strip_prefix(&source_root) {
        return display_read_path(layout, &rel.to_string_lossy());
    }
    path.display().to_string()
}

fn display_read_path(_layout: &kin_core::KinLayout, rel_path: &str) -> String {
    rel_path.to_string()
}

fn render_neighbor_source(
    layout: &kin_core::KinLayout,
    entity: &Entity,
    max_lines: usize,
    max_chars: usize,
) -> Option<String> {
    let content = render_entity_source(layout, entity, max_lines, max_chars)?;
    Some(format!("// same-file neighbor\n{}", content))
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
    use super::{
        best_source_snippet_for_patterns, fallback_leaf_trace_matches, query_trace_matches,
        select_best_match, trace_not_found_guidance,
    };
    use kin_core::normalize_trace_name;
    use kin_db::InMemoryGraph;
    use kin_model::EntityStore;
    use kin_model::{
        Entity, EntityId, EntityKind, EntityMetadata, EntityRole, FingerprintAlgorithm, Hash256,
        LanguageId, SemanticFingerprint, Visibility,
    };

    #[test]
    fn trace_not_found_guidance_keeps_signal_and_offers_discovery() {
        let lines = trace_not_found_guidance("frobnicate");
        assert!(lines[0].contains("not found"), "keeps not-found signal: {lines:?}");
        let joined = lines.join("\n");
        assert!(joined.contains("kin search frobnicate"), "offers search: {joined}");
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
        let entities = vec![make_entity("Foo.safeParse"), make_entity("Foo.parse")];
        let picked = select_best_match("safeParse", &entities).unwrap();
        assert_eq!(picked.name, "Foo.safeParse");
    }

    #[test]
    fn fallback_leaf_trace_matches_supports_dotted_queries() {
        let graph = InMemoryGraph::new();
        let run = make_entity("run");
        graph.upsert_entity(&run).unwrap();

        let matches = fallback_leaf_trace_matches(&graph, "_zod.run").unwrap();
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

        let matches = query_trace_matches(&store, "$ZodType::run").unwrap();
        assert!(matches.is_empty());
    }

    #[test]
    fn select_best_match_returns_none_when_qualifier_is_unmatched() {
        let entities = vec![make_entity("run"), make_entity("Tinybench.run")];
        let picked = select_best_match("$ZodType::run", &entities);
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
const result = schema._zod.run(payload, ctx);
issues.map((iss) => util.finalizeIssue(iss, ctx, core.config()));
"#;
        let followups = super::extract_textual_followups(text);
        assert!(followups.iter().any(|s| s == "_zod.run"));
        assert!(followups.iter().any(|s| s == "util.finalizeIssue"));
        assert!(followups.iter().any(|s| s == "core.config"));
    }

    #[test]
    fn looks_like_file_path_detects_paths() {
        assert!(super::looks_like_file_path("src/parser.ts"));
        assert!(super::looks_like_file_path(
            "packages/zod/src/v4/core/parse.ts"
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
        assert!(!super::looks_like_file_path("safeParse"));
        assert!(!super::looks_like_file_path("ZodString"));
        assert!(!super::looks_like_file_path("$ZodType"));
        assert!(!super::looks_like_file_path("Router::route"));
        assert!(!super::looks_like_file_path("Foo.parse"));
        assert!(!super::looks_like_file_path("_zod.run"));
    }

    #[test]
    fn source_fallback_prefers_implementation_over_test_file() {
        let impl_content = r#"
export const safeParse = <T>(schema: $ZodType<T>, value: unknown) => {
  const result = schema._zod.run({ value, issues: [] }, { async: false });
  return result;
};
"#;
        let test_content = r#"
test("safeParse works", () => {
  expect(schema.safeParse("x").success).toBe(true);
});
"#;

        let impl_score = best_source_snippet_for_patterns(
            std::path::Path::new("/repo/packages/zod/src/v4/core/parse.ts"),
            impl_content,
            &["safeParse".to_string(), ".safeParse".to_string()],
            20,
            2400,
        )
        .unwrap()
        .0;

        let test_score = best_source_snippet_for_patterns(
            std::path::Path::new("/repo/packages/zod/src/v4/core/tests/index.test.ts"),
            test_content,
            &["safeParse".to_string(), ".safeParse".to_string()],
            20,
            2400,
        )
        .unwrap()
        .0;

        assert!(
            impl_score > test_score,
            "{impl_score} should outrank {test_score}"
        );
    }

    #[test]
    fn source_fallback_prefers_classic_core_over_mini_variant() {
        let classic_content = r#"
export interface ZodType {
  safeParse(data: unknown): Result;
}
inst.safeParse = (data, params) => parse.safeParse(inst, data, params);
"#;
        let mini_content = r#"
export interface ZodMiniType {
  safeParse(data: unknown): Result;
}
inst.safeParse = (data, params) => parse.safeParse(inst, data, params);
"#;

        let classic_score = best_source_snippet_for_patterns(
            std::path::Path::new("/repo/packages/zod/src/v4/classic/schemas.ts"),
            classic_content,
            &["safeParse".to_string()],
            20,
            2400,
        )
        .unwrap()
        .0;

        let mini_score = best_source_snippet_for_patterns(
            std::path::Path::new("/repo/packages/zod/src/v4/mini/schemas.ts"),
            mini_content,
            &["safeParse".to_string()],
            20,
            2400,
        )
        .unwrap()
        .0;

        assert!(
            classic_score > mini_score,
            "{classic_score} should outrank {mini_score}"
        );
    }

    #[test]
    fn source_fallback_handles_unicode_without_panicking() {
        let content = r#"
test("Georgian locale uses 'ველი' instead of 'სტრინგი'", () => {
  expect(schema.safeParse("x").success).toBe(true);
});
"#;

        let found = best_source_snippet_for_patterns(
            std::path::Path::new("/repo/packages/zod/src/v4/core/tests/index.test.ts"),
            content,
            &["safeParse".to_string()],
            20,
            2400,
        );

        assert!(found.is_some());
    }
}
