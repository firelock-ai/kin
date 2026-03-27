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

    // Reciprocal rank fusion
    let fused = reciprocal_rank_fusion(&ranked_lists, 60.0);

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

        // Filter stdlib/venv paths
        if is_stdlib_path(file_path) {
            continue;
        }

        // Weight by frame position — last frame is most relevant
        let position_weight = (i + 1) as f32 / num_frames.max(1) as f32;
        let score = 10.0 * position_weight;

        // Normalize path: strip leading absolute prefix to get relative
        let rel_path = normalize_traceback_path(file_path);

        hits.entry(rel_path.clone()).or_default().push(FileHit {
            score,
            spans: vec![[line, line]],
        });

        // Also search for the function name in the graph
        if let Some(func_name) = cap.get(3) {
            let func = func_name.as_str();
            let text_hits = graph.text_search(func, 5)?;
            for (entity_id, _) in &text_hits {
                if let Some(entity) = graph.get_entity(entity_id)? {
                    if let Some(ref fo) = entity.file_origin {
                        let path = fo.0.clone();
                        if !is_test_path(&path) || path == rel_path {
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
        "/site-packages/",
        "/dist-packages/",
        "/venv/",
        "/.venv/",
        "/env/",
        "/Lib/",
        "\\lib\\python",
        "\\site-packages\\",
    ];
    markers.iter().any(|m| path.contains(m))
}

fn normalize_traceback_path(path: &str) -> String {
    // Try to extract relative path from common patterns
    // e.g. /home/user/project/astropy/modeling/core.py -> astropy/modeling/core.py
    let path = path.replace('\\', "/");

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

    let identifiers = extract_identifiers(text);
    if identifiers.is_empty() {
        return Ok(hits);
    }

    for ident in &identifiers {
        // Text search (BM25)
        let text_hits = graph.text_search(ident, 10)?;
        for (entity_id, bm25_score) in &text_hits {
            if let Some(entity) = graph.get_entity(entity_id)? {
                if let Some(ref fo) = entity.file_origin {
                    let path = fo.0.clone();
                    let score = bm25_score * 2.0;
                    hits.entry(path).or_default().push(FileHit {
                        score,

                        spans: entity_span_pair(&entity),
                    });
                }
            }
        }

        // Also try exact name filter
        let filter = EntityFilter {
            name_pattern: Some(ident.clone()),
            ..Default::default()
        };
        let matched = graph.query_entities(&filter)?;
        for entity in &matched {
            if let Some(ref fo) = entity.file_origin {
                let path = fo.0.clone();
                hits.entry(path).or_default().push(FileHit {
                    score: 3.0,
                    spans: entity_span_pair(entity),
                });
            }
        }
    }

    Ok(hits)
}

fn extract_identifiers(text: &str) -> Vec<String> {
    let mut identifiers = Vec::new();
    let mut seen = HashSet::new();

    // Extract backtick-quoted identifiers
    let re_backtick = regex::Regex::new(r"`([^`]+)`").unwrap();
    for cap in re_backtick.captures_iter(text) {
        let ident = cap[1].trim().to_string();
        if is_plausible_identifier(&ident) && seen.insert(ident.clone()) {
            identifiers.push(ident);
        }
    }

    // Extract CamelCase identifiers
    let re_camel = regex::Regex::new(r"\b([A-Z][a-zA-Z0-9]{2,})\b").unwrap();
    for cap in re_camel.captures_iter(text) {
        let ident = cap[1].to_string();
        if seen.insert(ident.clone()) {
            identifiers.push(ident);
        }
    }

    // Extract snake_case identifiers (at least one underscore, 4+ chars)
    let re_snake = regex::Regex::new(r"\b([a-z][a-z0-9]*(?:_[a-z0-9]+)+)\b").unwrap();
    for cap in re_snake.captures_iter(text) {
        let ident = cap[1].to_string();
        if !is_noise_term(&ident) && seen.insert(ident.clone()) {
            identifiers.push(ident);
        }
    }

    identifiers
}

fn is_plausible_identifier(s: &str) -> bool {
    if s.is_empty() || s.len() < 2 {
        return false;
    }
    // Must contain at least one alphanumeric
    s.chars().any(|c| c.is_alphanumeric()) && !s.contains(' ')
        || s.contains('_')
        || s.contains('.')
        || s.contains("::")
}

fn is_noise_term(s: &str) -> bool {
    let noise = [
        "the", "and", "for", "not", "but", "with", "this", "that", "from", "when", "should",
        "would", "could", "does_not", "is_not", "has_been", "it_is", "to_be", "in_the", "of_the",
        "on_the",
    ];
    noise.contains(&s)
}

// ---------------------------------------------------------------------------
// 3. Multi-hop graph walk
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

    // For each seed file, find entities in that file and walk their relations
    for (seed_path, _) in &seed_files {
        let filter = EntityFilter {
            file_path: Some(kin_model::FilePathId::new(seed_path.as_str())),
            ..Default::default()
        };
        let entities = graph.query_entities(&filter)?;

        for entity in entities.iter().take(10) {
            // Follow Calls and DependsOn relations outward
            let rels = graph.get_relations(
                &entity.id,
                &[
                    RelationKind::Calls,
                    RelationKind::DependsOn,
                    RelationKind::Imports,
                ],
            )?;

            for rel in &rels {
                // Hop 1
                if let Some(hop1_entity) = graph.get_entity(&rel.dst)? {
                    if let Some(ref fo) = hop1_entity.file_origin {
                        let path = fo.0.clone();
                        let weight = if is_test_path(&path) { 0.1 } else { 1.0 };
                        hits.entry(path).or_default().push(FileHit {
                            score: 1.5 * weight,
                            spans: entity_span_pair(&hop1_entity),
                        });
                    }

                    // Hop 2
                    let hop2_rels = graph.get_relations(
                        &hop1_entity.id,
                        &[RelationKind::Calls, RelationKind::DependsOn],
                    )?;
                    for rel2 in hop2_rels.iter().take(5) {
                        if let Some(hop2_entity) = graph.get_entity(&rel2.dst)? {
                            if let Some(ref fo) = hop2_entity.file_origin {
                                let path = fo.0.clone();
                                let weight = if is_test_path(&path) { 0.1 } else { 1.0 };
                                hits.entry(path).or_default().push(FileHit {
                                    score: 0.8 * weight,
                                    spans: entity_span_pair(&hop2_entity),
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
    let re_import = regex::Regex::new(r"^import\s+([\w.]+)").unwrap();

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
// 8. Reciprocal Rank Fusion
// ---------------------------------------------------------------------------

fn reciprocal_rank_fusion(ranked_lists: &[Vec<(String, f32)>], k: f32) -> Vec<(String, f32)> {
    let mut scores: HashMap<String, f32> = HashMap::new();
    for list in ranked_lists {
        for (rank, (file, _)) in list.iter().enumerate() {
            // Skip vendored/third-party files entirely
            if is_vendored_path(file) {
                continue;
            }
            *scores.entry(file.clone()).or_default() += 1.0 / (k + rank as f32 + 1.0);
        }
    }
    let mut result: Vec<_> = scores.into_iter().collect();
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
            let total_score: f32 = file_hits.iter().map(|h| h.score).sum();
            (path.clone(), total_score)
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

    // Strong confidence: clear winner gets 1-2 files
    let predicted = if second < 0.001 || top > 3.0 * second {
        1
    } else if top > 2.0 * second {
        2
    } else if top > 1.5 * second {
        3
    } else {
        // Default tight: 5 files max. Gold is usually 1-3 files.
        5.min(max_files)
    };

    fused
        .iter()
        .take(predicted.min(max_files))
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
