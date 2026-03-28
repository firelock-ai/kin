// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use kin_model::{EntityFilter, EntityKind, EntityStore, RelationKind};
use serde::Serialize;
use std::collections::{HashMap, HashSet};

// ---------------------------------------------------------------------------
// JSON output types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct LocateResult {
    files: Vec<LocateFileEntry>,
}

#[derive(Serialize)]
struct LocateFileEntry {
    path: String,
    score: f32,
    signals: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    spans: Vec<[u32; 2]>,
}

// ---------------------------------------------------------------------------
// Scored file hit with signal provenance
// ---------------------------------------------------------------------------

struct FileHit {
    score: f32,
    spans: Vec<[u32; 2]>,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub async fn run(text: &str, json: bool, max_files: usize) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;

    let snap = crate::backend::open_snapshot_daemon_first(&layout).await?;
    let graph = &*snap.graph();
    run_with_graph(graph, text, json, max_files)
}

fn run_with_graph(
    graph: &kin_db::InMemoryGraph,
    text: &str,
    json: bool,
    max_files: usize,
) -> Result<()> {
    // Strip HTML comments from issue text
    let text = &clean_issue_text(text);

    // Extract priority files (explicit file paths mentioned in the text)
    let priority_files = extract_priority_files(text, graph);

    // Run all signal extractors
    let traceback = extract_traceback_signals(text, graph)?;
    let search = extract_search_signals(text, graph)?;
    let multihop = extract_multihop_signals(&search, graph)?;
    let tests = extract_test_signals(text, graph)?;
    let snippets = extract_snippet_signals(text, graph)?;
    let imports = extract_import_signals(text, graph)?;
    let errors = extract_error_signals(text, graph)?;

    // Collect per-signal ranked lists
    let ranked_lists: Vec<Vec<(String, f32)>> = vec![
        to_ranked(&traceback),
        to_ranked(&search),
        to_ranked(&multihop),
        to_ranked(&tests),
        to_ranked(&snippets),
        to_ranked(&imports),
        to_ranked(&errors),
    ];

    // Reciprocal rank fusion with hybrid scoring
    let mut fused = reciprocal_rank_fusion(&ranked_lists, 60.0);

    // Boost priority files (explicitly mentioned paths)
    boost_priority_in_fused(&mut fused, &priority_files);

    // Adaptive cap
    let results = adaptive_cap(&fused, max_files);

    // Merge signal labels for each file
    let all_hits: Vec<HashMap<String, Vec<FileHit>>> = vec![
        traceback, search, multihop, tests, snippets, imports, errors,
    ];

    if json {
        output_json(&results, &all_hits);
    } else {
        output_text(&results, &all_hits);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Clean issue text (strip HTML comments, etc.)
// ---------------------------------------------------------------------------

fn clean_issue_text(text: &str) -> String {
    // Strip HTML comments (<!-- ... -->)
    let re_html_comment = regex::Regex::new(r"(?s)<!--.*?-->").unwrap();
    re_html_comment.replace_all(text, "").to_string()
}

// ---------------------------------------------------------------------------
// Priority file extraction
// ---------------------------------------------------------------------------

fn extract_priority_files(
    text: &str,
    graph: &kin_db::InMemoryGraph,
) -> Vec<(String, f32)> {
    let mut file_scores: HashMap<String, f32> = HashMap::new();

    // (a) Explicit file paths from text — highest priority
    for file_path in extract_file_paths(text) {
        if let Some(path) = resolve_path_in_graph(graph, &file_path) {
            let entry = file_scores.entry(path).or_insert(0.0);
            *entry = entry.max(200.0);
        }
    }

    // (b) Module path fragments (e.g. astropy.modeling.core -> astropy/modeling/core)
    for fragment in extract_module_path_fragments(text) {
        // Try exact file_path match with .py extension
        let with_py = format!("{}.py", fragment);
        let filter = EntityFilter {
            file_path: Some(kin_model::FilePathId::new(&with_py)),
            ..Default::default()
        };
        if graph
            .query_entities(&filter)
            .ok()
            .is_some_and(|e| !e.is_empty())
        {
            let entry = file_scores.entry(with_py).or_insert(0.0);
            *entry = entry.max(100.0);
        } else {
            // Suffix match: scan entities for file paths containing the fragment
            if let Ok(all) = graph.query_entities(&EntityFilter::default()) {
                let mut seen_paths = HashSet::new();
                for entity in all.iter().take(2000) {
                    if let Some(ref fo) = entity.file_origin {
                        if fo.0.contains(&fragment) && seen_paths.insert(fo.0.clone()) {
                            let entry = file_scores.entry(fo.0.clone()).or_insert(0.0);
                            *entry = entry.max(80.0);
                        }
                    }
                }
            }
        }
    }

    // (c) Backtick-quoted terms and title terms -> entity name resolution
    let re_bt = regex::Regex::new(r"`([^`]+)`").unwrap();
    let mut quoted_terms: Vec<String> = Vec::new();
    for cap in re_bt.captures_iter(text) {
        let raw = cap[1].trim().to_string();
        if raw.len() >= 3 && raw.len() <= 60 && !raw.contains(' ') && !raw.contains('\n') {
            quoted_terms.push(raw);
        }
    }

    let title_line = text.lines().next().unwrap_or("");
    let title_lower = title_line.to_lowercase();
    let re_word = regex::Regex::new(r"\b([a-zA-Z_]\w+)\b").unwrap();
    let title_terms: HashSet<String> = re_word
        .captures_iter(title_line)
        .map(|c| c[1].to_string())
        .collect();

    let mut all_terms: Vec<(String, bool)> = quoted_terms
        .iter()
        .map(|t| {
            let is_title = title_lower.contains(&t.to_lowercase());
            (t.clone(), is_title)
        })
        .collect();
    for tt in &title_terms {
        if !all_terms.iter().any(|(t, _)| t == tt) {
            all_terms.push((tt.clone(), true));
        }
    }

    for (term, is_title) in &all_terms {
        // Strip dotted prefix, take last component
        let leaf = term.rsplit('.').next().unwrap_or(term);
        if leaf.len() <= 2 || is_noise_term(leaf) {
            continue;
        }

        let filter = EntityFilter {
            name_pattern: Some(leaf.to_string()),
            ..Default::default()
        };
        if let Ok(matched) = graph.query_entities(&filter) {
            // Filter to exact name matches (case-insensitive) and definition kinds only
            let leaf_lower = leaf.to_lowercase();
            let exact: Vec<_> = matched
                .iter()
                .filter(|e| e.name.to_lowercase() == leaf_lower)
                .filter(|e| matches!(
                    e.kind,
                    EntityKind::Function
                        | EntityKind::Method
                        | EntityKind::Class
                        | EntityKind::TraitDef
                        | EntityKind::Interface
                        | EntityKind::EnumDef
                        | EntityKind::Module
                ))
                .collect();

            // Collect unique files
            let unique_files: HashSet<String> = exact
                .iter()
                .filter_map(|e| e.file_origin.as_ref().map(|fo| fo.0.clone()))
                .collect();

            // Only use if specific (<=3 unique files)
            if !unique_files.is_empty() && unique_files.len() <= 3 {
                let score = if *is_title { 50.0 } else { 30.0 };
                for path in &unique_files {
                    if !is_test_path(path) {
                        let entry = file_scores.entry(path.clone()).or_insert(0.0);
                        *entry = entry.max(score);
                    }
                }
            }
        }
    }

    // Build result: sorted by score desc, filtered to >=30.0, truncated to 5
    let mut result: Vec<(String, f32)> = file_scores.into_iter().filter(|(_, s)| *s >= 30.0).collect();
    result.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    result.truncate(5);
    result
}

fn boost_priority_in_fused(fused: &mut Vec<(String, f32)>, priority: &[(String, f32)]) {
    if priority.is_empty() {
        return;
    }
    let priority_map: HashMap<String, f32> = priority.iter().cloned().collect();
    let rrf_max = fused.first().map(|(_, s)| *s).unwrap_or(1.0);

    // Boost existing entries
    for (path, score) in fused.iter_mut() {
        if let Some(ps) = priority_map.get(path) {
            let boost = 1.0 + (ps / 100.0).min(3.0);
            *score *= boost;
        }
    }

    // Inject priority files not in fused
    let existing: HashSet<String> = fused.iter().map(|(p, _)| p.clone()).collect();
    for (path, ps) in priority {
        if !existing.contains(path) && *ps >= 50.0 {
            let injected = rrf_max * (ps / 100.0).min(2.0);
            fused.push((path.clone(), injected));
        }
    }

    fused.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
}

// ---------------------------------------------------------------------------
// Module path fragment extraction
// ---------------------------------------------------------------------------

fn extract_module_path_fragments(text: &str) -> Vec<String> {
    let mut fragments = Vec::new();
    let mut seen = HashSet::new();

    // Match dotted module paths like astropy.modeling.core, io.ascii, etc.
    let re_dotted = regex::Regex::new(r"\b([a-zA-Z_]\w*(?:\.\w+){1,})").unwrap();
    for cap in re_dotted.captures_iter(text) {
        let dotted = cap[1].to_string();
        // Convert dots to path separators: astropy.modeling.core -> astropy/modeling/core
        let as_path = dotted.replace('.', "/");
        if seen.insert(as_path.clone()) {
            fragments.push(as_path);
        }
    }

    fragments
}

// ---------------------------------------------------------------------------
// 1. Traceback parser
// ---------------------------------------------------------------------------

fn extract_traceback_signals(
    text: &str,
    graph: &kin_db::InMemoryGraph,
) -> Result<HashMap<String, Vec<FileHit>>> {
    let mut hits: HashMap<String, Vec<FileHit>> = HashMap::new();

    // Match Python traceback lines: File "path", line N, in function_name
    let re_tb = regex::Regex::new(r#"File "([^"]+)", line (\d+)(?:, in (\w+))?"#).unwrap();

    let frames: Vec<_> = re_tb.captures_iter(text).collect();
    let num_frames = frames.len();

    for (i, cap) in frames.iter().enumerate() {
        let file_path = &cap[1];
        let line: u32 = cap[2].parse().unwrap_or(0);
        let rel_path = resolve_path_in_graph(graph, &normalize_traceback_path(file_path));

        // Weight by frame position — last frame is most relevant
        let position_weight = (i + 1) as f32 / num_frames.max(1) as f32;
        let score = 10.0 * position_weight;

        // Keep traceback paths that resolve into this repo even if they came from
        // an installed site-packages path. Skip only when they do not resolve and
        // still look like stdlib/venv noise.
        if let Some(ref path) = rel_path {
            hits.entry(path.clone()).or_default().push(FileHit {
                score,
                spans: vec![[line, line]],
            });
        } else if is_stdlib_path(file_path) {
            continue;
        }

        // Also search for the function name in the graph
        if let Some(func_name) = cap.get(3) {
            let func = func_name.as_str();
            let text_hits = graph.text_search(func, 5)?;
            for (entity_id, _) in &text_hits {
                if let Some(entity) = graph.get_entity(entity_id)? {
                    if let Some(ref fo) = entity.file_origin {
                        let path = fo.0.clone();
                        if !is_test_path(&path) || rel_path.as_ref() == Some(&path) {
                            hits.entry(path).or_default().push(FileHit {
                                score: 5.0 * position_weight,
                                spans: entity_span_pair(&entity),
                            });
                        }
                    }
                }
            }
        }
    }

    Ok(hits)
}

fn is_stdlib_path(path: &str) -> bool {
    let markers = [
        "/lib/python",
        "/venv/",
        "/.venv/",
        "/env/",
        "/Lib/",
        "\\lib\\python",
    ];
    markers.iter().any(|m| path.contains(m))
}

fn normalize_traceback_path(path: &str) -> String {
    // Try to extract relative path from common patterns
    // e.g. /home/user/project/astropy/modeling/core.py -> astropy/modeling/core.py
    let path = path.replace('\\', "/");

    for marker in &["/site-packages/", "/dist-packages/", "\\site-packages\\", "\\dist-packages\\"] {
        if let Some(idx) = path.find(marker) {
            let start = idx + marker.len();
            return path[start..].trim_start_matches('/').trim_start_matches('\\').to_string();
        }
    }

    // If it looks like an absolute path, try to find a recognizable root
    if path.starts_with('/') || path.contains(":/") {
        // Take everything after the last occurrence of common project dirs
        for marker in &["/src/", "/lib/"] {
            if let Some(idx) = path.rfind(marker) {
                return path[idx + 1..].to_string();
            }
        }
        // Otherwise use the last 3+ components
        let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if parts.len() > 2 {
            // Heuristic: keep from the first non-system-looking component
            for (i, part) in parts.iter().enumerate() {
                if !["home", "Users", "usr", "opt", "var", "tmp"]
                    .contains(&part.to_lowercase().as_str())
                    && !part.starts_with('.')
                {
                    return parts[i..].join("/");
                }
            }
        }
    }

    path.to_string()
}

// ---------------------------------------------------------------------------
// 2. Entity search
// ---------------------------------------------------------------------------

fn extract_search_signals(
    text: &str,
    graph: &kin_db::InMemoryGraph,
) -> Result<HashMap<String, Vec<FileHit>>> {
    let mut hits: HashMap<String, Vec<FileHit>> = HashMap::new();

    for file_path in extract_file_paths(text) {
        if let Some(path) = resolve_path_in_graph(graph, &file_path) {
            hits.entry(path).or_default().push(FileHit {
                score: 10.0,
                spans: vec![],
            });
        }
    }

    // Module path fragment matching (e.g. "astropy.modeling.core" -> search for files containing "astropy/modeling/core")
    let module_fragments = extract_module_path_fragments(text);
    for fragment in &module_fragments {
        if let Some(path) = resolve_path_in_graph(graph, fragment) {
            hits.entry(path).or_default().push(FileHit {
                score: 8.0,
                spans: vec![],
            });
        }
        // Also try with common extensions
        for ext in &[".py", ".rs", ".ts", ".js", ".go", ".java"] {
            let with_ext = format!("{}{}", fragment, ext);
            if let Some(path) = resolve_path_in_graph(graph, &with_ext) {
                hits.entry(path).or_default().push(FileHit {
                    score: 8.0,
                    spans: vec![],
                });
            }
        }
    }

    let identifiers = extract_search_terms(text);
    if identifiers.is_empty() {
        return Ok(hits);
    }

    // Determine which terms appear in the issue title (first line) for weighting
    let title_line = text.lines().next().unwrap_or("");
    let title_terms: HashSet<String> = extract_search_terms(title_line)
        .into_iter()
        .map(|s| s.to_lowercase())
        .collect();

    for ident in &identifiers {
        // Title terms get 3x weight
        let is_title_term = title_terms.contains(&ident.to_lowercase());
        let title_mult = if is_title_term { 3.0 } else { 1.0 };

        // Use the SAME search pipeline as `kin search`:
        // 1. Prefix/pattern match via query_entities
        // 2. If <5 results, fall back to text_search
        // This is what made v6 score 0.340 — consistent search quality.

        let mut seen = std::collections::HashSet::new();
        let mut entities_found = Vec::new();

        // Step 1: Pattern match (same as search.rs line 426-436)
        let filter = EntityFilter {
            name_pattern: Some(ident.clone()),
            ..Default::default()
        };
        for entity in graph.query_entities(&filter)? {
            if seen.insert(entity.id) {
                entities_found.push(entity);
            }
        }

        // Step 2: Text search fallback if few results (same as search.rs line 440-459)
        if entities_found.len() < 5 {
            let text_hits = graph.text_search(ident, 20)?;
            for (entity_id, _score) in text_hits {
                if seen.insert(entity_id) {
                    if let Some(entity) = graph.get_entity(&entity_id)? {
                        entities_found.push(entity);
                    }
                }
            }
        }

        // Step 3: File stem matching — if identifier looks like a filename stem
        let ident_lower = ident.to_lowercase();
        {
            let filter_broad = EntityFilter::default();
            // Check if any file paths contain this term
            for entity in graph.query_entities(&filter_broad)?.iter().take(500) {
                if let Some(ref fo) = entity.file_origin {
                    let path_lower = fo.0.to_lowercase();
                    // Check if file stem matches the identifier
                    let stem = std::path::Path::new(&fo.0)
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("");
                    if stem.to_lowercase() == ident_lower {
                        if seen.insert(entity.id) {
                            entities_found.push(entity.clone());
                        }
                    }
                    // Also match path containing the search term
                    else if path_lower.contains(&ident_lower) && ident_lower.len() >= 3 {
                        if seen.insert(entity.id) {
                            entities_found.push(entity.clone());
                        }
                    }
                }
            }
        }

        // Score: definitions get 3x, test files 0.1x, exact name match 5x
        // File path contains search term bonus, conjunctive multi-term bonus
        for entity in &entities_found {
            if let Some(ref fo) = entity.file_origin {
                let path = fo.0.clone();
                let is_test = is_test_path(&path);
                let test_mult = if is_test { 0.1 } else { 1.0 };

                let name_lower = entity.name.to_lowercase();
                let name_mult = if name_lower == ident_lower {
                    5.0  // Exact match
                } else if name_lower.contains(&ident_lower) {
                    2.0  // Substring match
                } else {
                    1.0  // Broad match
                };

                let kind_mult = match entity.kind {
                    EntityKind::Function | EntityKind::Method | EntityKind::Class
                    | EntityKind::TraitDef | EntityKind::Interface | EntityKind::EnumDef
                    | EntityKind::Module => 3.0,
                    _ => 1.0,
                };

                // File path contains search term bonus
                let path_lower = path.to_lowercase();
                let path_mult = if path_lower.contains(&ident_lower) && ident_lower.len() >= 3 {
                    2.0
                } else {
                    1.0
                };

                hits.entry(path).or_default().push(FileHit {
                    score: kind_mult * name_mult * test_mult * title_mult * path_mult,
                    spans: entity_span_pair(entity),
                });
            }
        }
    }

    // Conjunctive multi-term bonus: files matching multiple search terms get a boost
    if identifiers.len() > 1 {
        let mut file_term_matches: HashMap<String, HashSet<String>> = HashMap::new();
        for ident in &identifiers {
            let ident_lower = ident.to_lowercase();
            let mut files_for_term = HashSet::new();
            for (path, _) in hits.iter() {
                let path_lower = path.to_lowercase();
                if path_lower.contains(&ident_lower) {
                    files_for_term.insert(path.clone());
                }
            }
            // Also check entity names in each file
            if let Ok(all_entities) = graph.list_all_entities() {
                for entity in &all_entities {
                    if entity.name.to_lowercase().contains(&ident_lower) {
                        if let Some(ref fo) = entity.file_origin {
                            if hits.contains_key(&fo.0) {
                                files_for_term.insert(fo.0.clone());
                            }
                        }
                    }
                }
            }
            for f in files_for_term {
                file_term_matches.entry(f).or_insert_with(HashSet::new).insert(ident_lower.clone());
            }
        }
        for (path, matched_terms) in &file_term_matches {
            let term_count = matched_terms.len();
            if term_count > 1 {
                let bonus = match term_count {
                    2 => 5.0,
                    3 => 15.0,
                    _ => 30.0, // 4+
                };
                hits.entry(path.clone()).or_default().push(FileHit {
                    score: bonus,
                    spans: vec![],
                });
            }
        }
    }

    // File stem matching
    let all_file_paths: HashSet<String> = if let Ok(entities) = graph.query_entities(&EntityFilter::default()) {
        entities.iter().filter_map(|e| e.file_origin.as_ref().map(|f| f.0.clone())).collect()
    } else {
        HashSet::new()
    };

    let common_stems: HashSet<&str> = [
        "base", "core", "utils", "util", "helpers", "helper", "types",
        "models", "views", "tests", "test", "conf", "config", "settings",
        "urls", "admin", "init", "main", "index", "common", "compat",
        "exceptions", "errors", "constants",
    ].iter().copied().collect();

    for ident in &identifiers {
        let ident_lower = ident.to_lowercase();
        if ident_lower.len() < 4 || common_stems.contains(ident_lower.as_str()) {
            continue;
        }
        let is_title = title_terms.contains(&ident_lower);
        for file_path in &all_file_paths {
            let stem = file_path.rsplit('/').next()
                .and_then(|f| f.rsplit('.').last())
                .unwrap_or("").to_lowercase();
            if stem == ident_lower && !is_test_path(file_path) {
                let score = if is_title { 20.0 } else { 10.0 };
                hits.entry(file_path.clone()).or_default().push(FileHit { score, spans: vec![] });
            }
        }
    }

    Ok(hits)
}

fn extract_file_paths(text: &str) -> Vec<String> {
    let mut paths = Vec::new();
    let mut seen = HashSet::new();

    let re_traceback = regex::Regex::new(r#"File "([^"]+\.[A-Za-z0-9]+)""#).unwrap();
    for cap in re_traceback.captures_iter(text) {
        let path = normalize_traceback_path(&cap[1]);
        if seen.insert(path.clone()) {
            paths.push(path);
        }
    }

    let re_backtick = regex::Regex::new(r"`([a-zA-Z][\w./-]+\.\w{1,6})`").unwrap();
    for cap in re_backtick.captures_iter(text) {
        let path = normalize_traceback_path(&cap[1]);
        if seen.insert(path.clone()) {
            paths.push(path);
        }
    }

    // Fix: use (?:^|[^/\w]) instead of (?<!\w) for lookbehind compatibility
    let re_bare = regex::Regex::new(r"(?:^|[^/\w])([a-zA-Z]\w+(?:/[\w.-]+)+\.\w{1,6})(?:[^\w]|$)").unwrap();
    for cap in re_bare.captures_iter(text) {
        let path = normalize_traceback_path(&cap[1]);
        if seen.insert(path.clone()) {
            paths.push(path);
        }
    }

    paths
}

fn extract_search_terms(text: &str) -> Vec<String> {
    let mut queries = Vec::new();
    let mut seen = HashSet::new();
    let re_call_suffix = regex::Regex::new(r"\(.*\)$").unwrap();

    let re_backtick = regex::Regex::new(r"`([^`]+)`").unwrap();
    for cap in re_backtick.captures_iter(text) {
        let raw = cap[1].trim();
        if raw.len() > 80
            || raw.contains('\n')
            || matches!(raw.chars().next(), Some('$' | '#' | '-' | '/'))
            || (raw.contains('/') && raw.rsplit('/').next().is_some_and(|leaf| leaf.contains('.')))
        {
            continue;
        }

        let normalized = re_call_suffix.replace(raw, "").trim().to_string();
        if normalized.is_empty() || normalized.starts_with('.') {
            continue;
        }

        if normalized.contains('.') {
            let parts: Vec<&str> = normalized.split('.').filter(|part| !part.is_empty()).collect();
            if let Some(last) = parts.last() {
                maybe_add_search_term(last, &mut seen, &mut queries);
            }
            if parts.len() <= 3 {
                maybe_add_search_term(&normalized, &mut seen, &mut queries);
            }
        } else {
            maybe_add_search_term(&normalized, &mut seen, &mut queries);
        }
    }

    let re_camel = regex::Regex::new(r"\b([A-Z][a-z]+(?:[A-Z][a-z]+)+)\b").unwrap();
    for cap in re_camel.captures_iter(text) {
        maybe_add_search_term(&cap[1], &mut seen, &mut queries);
    }

    let re_snake = regex::Regex::new(r"\b([a-z][a-z0-9]*(?:_[a-z0-9]+)+)\b").unwrap();
    for cap in re_snake.captures_iter(text) {
        maybe_add_search_term(&cap[1], &mut seen, &mut queries);
    }

    let re_upper = regex::Regex::new(r"\b([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)\b").unwrap();
    for cap in re_upper.captures_iter(text) {
        maybe_add_search_term(&cap[1], &mut seen, &mut queries);
    }

    if queries.is_empty() {
        if let Some(first_line) = text.lines().next() {
            let re_word = regex::Regex::new(r"\b([a-zA-Z_]\w+)\b").unwrap();
            for cap in re_word.captures_iter(first_line) {
                maybe_add_search_term(&cap[1], &mut seen, &mut queries);
            }
        }
    }

    queries.truncate(10);
    queries
}

fn maybe_add_search_term(term: &str, seen: &mut HashSet<String>, queries: &mut Vec<String>) {
    let trimmed = term.trim();
    if trimmed.is_empty() || trimmed.len() <= 2 || is_noise_term(trimmed) {
        return;
    }
    if seen.insert(trimmed.to_string()) {
        queries.push(trimmed.to_string());
    }
}

fn is_noise_term(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "x86_64"
            | "amd64"
            | "arm64"
            | "linux"
            | "darwin"
            | "windows"
            | "macos"
            | "python"
            | "python3"
            | "pip"
            | "conda"
            | "npm"
            | "cargo"
            | "version"
            | "github"
            | "http"
            | "https"
            | "www"
            | "com"
            | "org"
            | "none"
            | "true"
            | "false"
            | "self"
            | "str"
            | "int"
            | "float"
            | "bool"
            | "list"
            | "dict"
            | "tuple"
            | "set"
            | "bug"
            | "issue"
            | "fix"
            | "patch"
            | "expected"
            | "actual"
            | "example"
            | "sample"
            | "note"
            | "see"
            | "todo"
            | "the"
            | "is"
            | "are"
            | "was"
            | "were"
            | "be"
            | "been"
            | "being"
            | "have"
            | "has"
            | "had"
            | "do"
            | "does"
            | "did"
            | "will"
            | "would"
            | "could"
            | "should"
            | "may"
            | "might"
            | "can"
            | "shall"
            | "not"
            | "no"
            | "and"
            | "or"
            | "but"
            | "if"
            | "then"
            | "else"
            | "when"
            | "while"
            | "for"
            | "to"
            | "from"
            | "in"
            | "on"
            | "at"
            | "by"
            | "with"
            | "of"
            | "about"
            | "this"
            | "that"
            | "it"
            | "its"
            | "my"
            | "your"
            | "our"
            | "their"
            | "which"
            | "what"
            | "how"
            | "why"
            | "where"
            | "there"
            | "here"
            | "all"
            | "any"
            | "each"
            | "every"
            | "some"
            | "new"
            | "old"
    )
}

// ---------------------------------------------------------------------------
// 3. Multi-hop graph walk (restricted: Calls-only, 1-hop)
// ---------------------------------------------------------------------------

fn extract_multihop_signals(
    search_hits: &HashMap<String, Vec<FileHit>>,
    graph: &kin_db::InMemoryGraph,
) -> Result<HashMap<String, Vec<FileHit>>> {
    let mut hits: HashMap<String, Vec<FileHit>> = HashMap::new();

    // Get top files from search results (seed nodes)
    let mut seed_files: Vec<(&String, f32)> = search_hits
        .iter()
        .map(|(path, file_hits)| {
            let max_score = file_hits.iter().map(|h| h.score).fold(0.0f32, f32::max);
            (path, max_score)
        })
        .collect();
    seed_files.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    seed_files.truncate(5);

    // For each seed file, find entities in that file and walk Calls relations only (1 hop)
    for (seed_path, _) in &seed_files {
        let filter = EntityFilter {
            file_path: Some(kin_model::FilePathId::new(seed_path.as_str())),
            ..Default::default()
        };
        let entities = graph.query_entities(&filter)?;

        for entity in entities.iter().take(10) {
            // Restricted: Calls-only, 1-hop (no DependsOn, no Imports, no hop2)
            let rels = graph.get_relations(
                &entity.id,
                &[RelationKind::Calls],
            )?;

            for rel in &rels {
                // Hop 1 only
                if let Some(hop1_entity) = graph.get_entity(&rel.dst)? {
                    if let Some(ref fo) = hop1_entity.file_origin {
                        let path = fo.0.clone();
                        let weight = if is_test_path(&path) { 0.1 } else { 1.0 };
                        hits.entry(path).or_default().push(FileHit {
                            score: 1.5 * weight,
                            spans: entity_span_pair(&hop1_entity),
                        });
                    }
                }
            }
        }
    }

    Ok(hits)
}

// ---------------------------------------------------------------------------
// 4. Failing test extraction
// ---------------------------------------------------------------------------

fn extract_test_signals(
    text: &str,
    graph: &kin_db::InMemoryGraph,
) -> Result<HashMap<String, Vec<FileHit>>> {
    let mut hits: HashMap<String, Vec<FileHit>> = HashMap::new();

    // Extract test names
    let re_test_func = regex::Regex::new(r"\b(test_\w+)\b").unwrap();
    let re_test_class = regex::Regex::new(r"\b(Test\w+)\.(\w+)\b").unwrap();

    let mut test_names: Vec<String> = Vec::new();

    for cap in re_test_func.captures_iter(text) {
        test_names.push(cap[1].to_string());
    }
    for cap in re_test_class.captures_iter(text) {
        test_names.push(format!("{}.{}", &cap[1], &cap[2]));
        test_names.push(cap[2].to_string());
    }

    for test_name in &test_names {
        // Find the test entity
        let filter = EntityFilter {
            name_pattern: Some(test_name.clone()),
            kinds: Some(vec![
                EntityKind::Test,
                EntityKind::Function,
                EntityKind::Method,
            ]),
            ..Default::default()
        };
        let matched = graph.query_entities(&filter)?;

        for test_entity in &matched {
            // The test file itself gets a low score
            if let Some(ref fo) = test_entity.file_origin {
                hits.entry(fo.0.clone()).or_default().push(FileHit {
                    score: 0.5,
                    spans: entity_span_pair(test_entity),
                });
            }

            // Follow imports/calls from test to find source files under test
            let rels = graph.get_relations(
                &test_entity.id,
                &[
                    RelationKind::Calls,
                    RelationKind::Imports,
                    RelationKind::Tests,
                ],
            )?;
            for rel in &rels {
                if let Some(target) = graph.get_entity(&rel.dst)? {
                    if let Some(ref fo) = target.file_origin {
                        let path = fo.0.clone();
                        let score = if is_test_path(&path) { 0.5 } else { 3.0 };
                        hits.entry(path).or_default().push(FileHit {
                            score,

                            spans: entity_span_pair(&target),
                        });
                    }
                }
            }
        }
    }

    Ok(hits)
}

// ---------------------------------------------------------------------------
// 5. Code snippet matching
// ---------------------------------------------------------------------------

fn extract_snippet_signals(
    text: &str,
    graph: &kin_db::InMemoryGraph,
) -> Result<HashMap<String, Vec<FileHit>>> {
    let mut hits: HashMap<String, Vec<FileHit>> = HashMap::new();

    let snippets = extract_code_snippets(text);
    if snippets.is_empty() {
        return Ok(hits);
    }

    for snippet in &snippets {
        // Extract function/class signatures from the snippet
        let re_def = regex::Regex::new(r"(?:def|class|fn|func|function)\s+(\w+)").unwrap();
        for cap in re_def.captures_iter(snippet) {
            let name = &cap[1];
            let filter = EntityFilter {
                name_pattern: Some(name.to_string()),
                ..Default::default()
            };
            let matched = graph.query_entities(&filter)?;
            for entity in &matched {
                // Check if the signature matches
                if !entity.signature.is_empty() && snippet.contains(&entity.name) {
                    if let Some(ref fo) = entity.file_origin {
                        hits.entry(fo.0.clone()).or_default().push(FileHit {
                            score: 2.0,
                            spans: entity_span_pair(entity),
                        });
                    }
                }
            }
        }

        // Also try text search with the whole snippet (first 100 chars)
        let search_text = &snippet[..snippet.len().min(100)];
        let text_hits = graph.text_search(search_text, 5)?;
        for (entity_id, _) in &text_hits {
            if let Some(entity) = graph.get_entity(entity_id)? {
                if let Some(ref fo) = entity.file_origin {
                    hits.entry(fo.0.clone()).or_default().push(FileHit {
                        score: 1.5,
                        spans: entity_span_pair(&entity),
                    });
                }
            }
        }
    }

    Ok(hits)
}

fn extract_code_snippets(text: &str) -> Vec<String> {
    let mut snippets = Vec::new();

    // Extract fenced code blocks (```...```)
    let re_fenced = regex::Regex::new(r"```\w*\n([\s\S]*?)```").unwrap();
    for cap in re_fenced.captures_iter(text) {
        let code = cap[1].trim().to_string();
        if !code.is_empty() {
            snippets.push(code);
        }
    }

    // Extract indented code blocks (4+ spaces or tab at start of line, consecutive)
    let mut current_block = String::new();
    for line in text.lines() {
        if line.starts_with("    ") || line.starts_with('\t') {
            current_block.push_str(line.trim_start());
            current_block.push('\n');
        } else if !current_block.is_empty() {
            let trimmed = current_block.trim().to_string();
            if trimmed.len() > 20 {
                snippets.push(trimmed);
            }
            current_block.clear();
        }
    }
    if !current_block.is_empty() {
        let trimmed = current_block.trim().to_string();
        if trimmed.len() > 20 {
            snippets.push(trimmed);
        }
    }

    snippets
}

// ---------------------------------------------------------------------------
// 6. Import chain tracing
// ---------------------------------------------------------------------------

fn extract_import_signals(
    text: &str,
    graph: &kin_db::InMemoryGraph,
) -> Result<HashMap<String, Vec<FileHit>>> {
    let mut hits: HashMap<String, Vec<FileHit>> = HashMap::new();

    // Match Python imports: from X import Y, import X
    let re_from = regex::Regex::new(r"from\s+([\w.]+)\s+import\s+(\w+)").unwrap();
    // Fix: use (?:^|[^\w]) instead of (?<!\w) for lookbehind compatibility
    let re_import = regex::Regex::new(r"(?:^|[^\w])import\s+([\w.]+)").unwrap();
    let re_backtick = regex::Regex::new(r"`([\w]+(?:\.[\w]+){2,})`").unwrap();

    let mut import_targets: Vec<(String, String)> = Vec::new(); // (module_path, symbol)

    for cap in re_from.captures_iter(text) {
        let module = cap[1].to_string();
        let symbol = cap[2].to_string();
        import_targets.push((module, symbol));
    }
    for cap in re_import.captures_iter(text) {
        let module = cap[1].to_string();
        import_targets.push((module.clone(), module));
    }
    for cap in re_backtick.captures_iter(text) {
        let parts: Vec<&str> = cap[1].split('.').collect();
        if parts.len() >= 2 {
            import_targets.push((parts[..parts.len() - 1].join("."), parts[parts.len() - 1].to_string()));
        }
    }

    for (module, symbol) in &import_targets {
        // Convert module path to file path: astropy.modeling.core -> astropy/modeling/core.py
        let file_path = module.replace('.', "/") + ".py";

        // Search for the file path in the graph
        let filter = EntityFilter {
            file_path: Some(kin_model::FilePathId::new(&file_path)),
            ..Default::default()
        };
        let entities_in_file = graph.query_entities(&filter)?;

        if !entities_in_file.is_empty() {
            hits.entry(file_path.clone()).or_default().push(FileHit {
                score: 5.0,
                spans: vec![],
            });
        }

        // Also search for the symbol
        let text_hits = graph.text_search(symbol, 5)?;
        for (entity_id, _) in &text_hits {
            if let Some(entity) = graph.get_entity(entity_id)? {
                if let Some(ref fo) = entity.file_origin {
                    let path = fo.0.clone();
                    // Direct match in expected file
                    let score = if path == file_path { 5.0 } else { 2.0 };
                    hits.entry(path).or_default().push(FileHit {
                        score,

                        spans: entity_span_pair(&entity),
                    });
                }
            }
        }

        // Follow downstream impact for direct file matches
        if !entities_in_file.is_empty() {
            for entity in entities_in_file.iter().take(3) {
                if entity.name == *symbol {
                    let impacted = graph.get_downstream_impact(&entity.id, 1)?;
                    for dep in &impacted {
                        if let Some(ref fo) = dep.file_origin {
                            let path = fo.0.clone();
                            if path != file_path {
                                hits.entry(path).or_default().push(FileHit {
                                    score: 2.0,
                                    spans: entity_span_pair(dep),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(hits)
}

// ---------------------------------------------------------------------------
// 7. Error type tracing
// ---------------------------------------------------------------------------

fn extract_error_signals(
    text: &str,
    graph: &kin_db::InMemoryGraph,
) -> Result<HashMap<String, Vec<FileHit>>> {
    let mut hits: HashMap<String, Vec<FileHit>> = HashMap::new();

    // Extract exception/error type names
    let re_error = regex::Regex::new(r"\b(\w+(?:Error|Exception|Warning|Fault))\b").unwrap();
    let mut error_names: HashSet<String> = HashSet::new();

    for cap in re_error.captures_iter(text) {
        error_names.insert(cap[1].to_string());
    }

    for error_name in &error_names {
        // Search graph for entities that reference or raise this error
        let text_hits = graph.text_search(error_name, 10)?;
        for (entity_id, _) in &text_hits {
            if let Some(entity) = graph.get_entity(entity_id)? {
                if let Some(ref fo) = entity.file_origin {
                    let path = fo.0.clone();
                    let weight = if is_test_path(&path) { 0.3 } else { 1.0 };
                    hits.entry(path).or_default().push(FileHit {
                        score: 2.5 * weight,
                        spans: entity_span_pair(&entity),
                    });
                }
            }
        }

        // Also try exact entity name match
        let filter = EntityFilter {
            name_pattern: Some(error_name.clone()),
            ..Default::default()
        };
        let matched = graph.query_entities(&filter)?;
        for entity in &matched {
            if let Some(ref fo) = entity.file_origin {
                let path = fo.0.clone();
                hits.entry(path).or_default().push(FileHit {
                    score: 2.5,
                    spans: entity_span_pair(entity),
                });
            }
        }
    }

    Ok(hits)
}

// ---------------------------------------------------------------------------
// 8. Reciprocal Rank Fusion (hybrid: RRF + raw score bonus + cross-signal bonus)
// ---------------------------------------------------------------------------

fn reciprocal_rank_fusion(ranked_lists: &[Vec<(String, f32)>], k: f32) -> Vec<(String, f32)> {
    let mut rrf_scores: HashMap<String, f32> = HashMap::new();
    let mut raw_scores: HashMap<String, f32> = HashMap::new();
    let mut signal_counts: HashMap<String, usize> = HashMap::new();

    for list in ranked_lists {
        // Compute max score in this list for normalization
        let max_score = list.iter().map(|(_, s)| *s).fold(0.0f32, f32::max).max(1.0);

        let mut files_in_list = HashSet::new();
        for (rank, (file, score)) in list.iter().enumerate() {
            // Skip vendored/third-party files entirely
            if is_vendored_path(file) {
                continue;
            }
            *rrf_scores.entry(file.clone()).or_default() += 1.0 / (k + rank as f32 + 1.0);
            // Accumulate normalized raw scores
            *raw_scores.entry(file.clone()).or_default() += score / max_score;
            files_in_list.insert(file.clone());
        }
        // Count how many signal sources contributed to each file
        for file in files_in_list {
            *signal_counts.entry(file).or_default() += 1;
        }
    }

    // Combine: RRF + normalized raw scores + cross-signal bonus
    let mut combined: HashMap<String, f32> = HashMap::new();
    for (file, rrf) in &rrf_scores {
        let raw = raw_scores.get(file).copied().unwrap_or(0.0);
        let signals = signal_counts.get(file).copied().unwrap_or(0) as f32;
        // Cross-signal bonus: files found by multiple extractors are more relevant
        let cross_bonus = if signals > 1.0 { (signals - 1.0) * 0.005 } else { 0.0 };
        combined.insert(file.clone(), rrf + raw * 0.01 + cross_bonus);
    }

    let mut result: Vec<_> = combined.into_iter().collect();
    result.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    result
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn to_ranked(hits: &HashMap<String, Vec<FileHit>>) -> Vec<(String, f32)> {
    let mut ranked: Vec<(String, f32)> = hits
        .iter()
        .map(|(path, file_hits)| {
            // Use top-3 mean score instead of sum to prevent large files with many
            // entities from dominating through sheer entity count
            let mut scores: Vec<f32> = file_hits.iter().map(|h| h.score).collect();
            scores.sort_by(|a, b| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));
            let top_n = scores.iter().take(3).copied().collect::<Vec<_>>();
            let mean = if top_n.is_empty() { 0.0 } else { top_n.iter().sum::<f32>() / top_n.len() as f32 };

            // Source file bonus: non-test source files get a mild boost
            let source_bonus = if !is_test_path(path) { 1.2 } else { 1.0 };

            (path.clone(), mean * source_bonus)
        })
        .collect();
    ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    ranked
}

fn adaptive_cap(fused: &[(String, f32)], max_files: usize) -> Vec<(String, f32)> {
    if fused.is_empty() {
        return vec![];
    }
    if fused.len() <= 1 {
        return fused.to_vec();
    }

    let top = fused[0].1;
    let second = fused[1].1;

    // Elbow detection: find where the score drops significantly
    let mut elbow = fused.len();
    for i in 1..fused.len() {
        let prev = fused[i - 1].1;
        let curr = fused[i].1;
        if prev > 0.0 && curr / prev < 0.5 {
            elbow = i;
            break;
        }
    }

    // Strong confidence: clear winner gets 1-2 files
    let predicted = if second < 0.001 || top > 3.0 * second {
        1
    } else if top > 2.0 * second {
        2
    } else if top > 1.5 * second {
        3
    } else {
        // Tighter default: 3 files max (gold is usually 1-3 files)
        3.min(max_files)
    };

    // Use the smaller of elbow detection and ratio-based prediction
    let cap = predicted.min(elbow).min(max_files);

    fused
        .iter()
        .take(cap)
        .cloned()
        .collect()
}

fn is_vendored_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.contains("/extern/")
        || lower.contains("/vendor/")
        || lower.contains("/third_party/")
        || lower.contains("/thirdparty/")
        || lower.contains("/node_modules/")
        || lower.contains("/_vendor/")
}

fn resolve_path_in_graph(graph: &kin_db::InMemoryGraph, partial_path: &str) -> Option<String> {
    let normalized = partial_path.trim().trim_start_matches("./").replace('\\', "/");
    if normalized.is_empty() {
        return None;
    }

    let parts: Vec<&str> = normalized.split('/').filter(|part| !part.is_empty()).collect();
    for candidate in (0..parts.len()).map(|start| parts[start..].join("/")) {
        let candidate = candidate.trim_start_matches('/');
        if candidate.is_empty() {
            continue;
        }

        let filter = EntityFilter {
            file_path: Some(kin_model::FilePathId::new(candidate)),
            ..Default::default()
        };
        if graph.query_entities(&filter).ok().is_some_and(|entities| !entities.is_empty()) {
            return Some(candidate.to_string());
        }
    }

    None
}

fn is_test_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let markers = [
        "/test/",
        "/tests/",
        "/test_",
        "/_test",
        "/spec/",
        "/specs/",
        "__tests__",
    ];
    markers.iter().any(|m| lower.contains(m))
        || lower.ends_with("_test.py")
        || lower.ends_with("_test.rs")
        || lower.ends_with("_test.go")
        || lower.ends_with(".test.ts")
        || lower.ends_with(".test.js")
        || lower.ends_with(".spec.ts")
        || lower.ends_with(".spec.js")
        || lower.contains("/test_")
}

fn entity_span_pair(entity: &kin_model::Entity) -> Vec<[u32; 2]> {
    entity
        .span
        .as_ref()
        .map(|s| vec![[s.start_line, s.end_line]])
        .unwrap_or_default()
}

fn collect_signals_for_file(file: &str, all_hits: &[HashMap<String, Vec<FileHit>>]) -> Vec<String> {
    let mut signals = Vec::new();
    let signal_names = [
        "traceback",
        "search",
        "multihop",
        "test",
        "snippet",
        "import",
        "error",
    ];
    for (i, hit_map) in all_hits.iter().enumerate() {
        if hit_map.contains_key(file) {
            signals.push(signal_names[i].to_string());
        }
    }
    signals
}

fn collect_spans_for_file(file: &str, all_hits: &[HashMap<String, Vec<FileHit>>]) -> Vec<[u32; 2]> {
    let mut spans = Vec::new();
    let mut seen = HashSet::new();
    for hit_map in all_hits {
        if let Some(file_hits) = hit_map.get(file) {
            for hit in file_hits {
                for span in &hit.spans {
                    if seen.insert(*span) {
                        spans.push(*span);
                    }
                }
            }
        }
    }
    spans.sort_by_key(|s| s[0]);
    spans
}

fn output_json(results: &[(String, f32)], all_hits: &[HashMap<String, Vec<FileHit>>]) {
    let files: Vec<LocateFileEntry> = results
        .iter()
        .map(|(path, score)| LocateFileEntry {
            path: path.clone(),
            score: *score,
            signals: collect_signals_for_file(path, all_hits),
            spans: collect_spans_for_file(path, all_hits),
        })
        .collect();

    let result = LocateResult { files };
    println!(
        "{}",
        serde_json::to_string_pretty(&result).unwrap_or_default()
    );
}

fn output_text(results: &[(String, f32)], all_hits: &[HashMap<String, Vec<FileHit>>]) {
    if results.is_empty() {
        println!("No relevant files found.");
        return;
    }

    for (path, score) in results {
        let signals = collect_signals_for_file(path, all_hits);
        println!(
            "  {:<50} (score: {:.2}, signals: {})",
            path,
            score,
            signals.join(", ")
        );
    }
}
