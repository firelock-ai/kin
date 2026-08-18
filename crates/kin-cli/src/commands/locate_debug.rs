// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! `kin locate-debug` — detailed signal breakdown for locate debugging.
//!
//! Three modes:
//! 1. `kin locate-debug "query" --target path/to/file.py` — where did the
//!    target file rank and what helped/hurt it
//! 2. `kin locate-debug "query" --task-file task.json` — load query + gold
//!    files from a benchmark task JSON and diagnose each gold file
//! 3. Either mode with `--json` — machine-readable output for batch processing

use anyhow::Result;
use kin_model::{EntityFilter, EntityStore};
use serde::Serialize;
use std::collections::HashMap;

use crate::commands::locate::LocateResult;

// ---------------------------------------------------------------------------
// Output types for --json
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct DebugReport {
    pub query_preview: String,
    pub total_results: usize,
    pub gold_files: Vec<GoldFileReport>,
    pub top_results: Vec<FileReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub debug_info: Option<DebugInfoReport>,
    pub summary: String,
}

#[derive(Serialize)]
pub struct GoldFileReport {
    pub path: String,
    pub status: String, // "FOUND" or "NOT_FOUND"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rank: Option<usize>, // 1-indexed
    pub score: f32,
    pub top_score: f32,
    pub score_ratio: f32,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub signal_scores: HashMap<String, f32>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub missing_signals_vs_top: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub penalties_detected: Vec<String>,
    // Only populated when NOT_FOUND — did the graph even know about this file?
    #[serde(skip_serializing_if = "Option::is_none")]
    pub graph_entity_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub graph_entity_kinds: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seen_in_stage: Option<String>,
}

#[derive(Serialize)]
pub struct FileReport {
    pub rank: usize,
    pub path: String,
    pub score: f32,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub signal_scores: HashMap<String, f32>,
}

#[derive(Serialize)]
pub struct DebugInfoReport {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scoring_track: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retrieval_profile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fast_path: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub skipped_signals: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub query_terms: Vec<String>,
}

// ---------------------------------------------------------------------------
// Task file parsing
// ---------------------------------------------------------------------------

fn strip_workspace_prefix(path: &str) -> String {
    // Pattern: /workspace/<repo_slug>/rest/of/path -> rest/of/path
    if let Some(after_workspace) = path.strip_prefix("/workspace/") {
        if let Some(idx) = after_workspace.find('/') {
            return after_workspace[idx + 1..].to_string();
        }
    }
    path.to_string()
}

fn parse_task_file(path: &str) -> Result<(String, Vec<String>)> {
    let data: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path)?)?;

    let query = data["problem_statement"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("task file missing problem_statement"))?
        .to_string();

    // gold_context may be a JSON array or a JSON-encoded string of an array
    let gold_context_value = match &data["gold_context"] {
        serde_json::Value::Array(arr) => arr.clone(),
        serde_json::Value::String(s) => {
            serde_json::from_str::<Vec<serde_json::Value>>(s).unwrap_or_default()
        }
        _ => Vec::new(),
    };
    let gold_files: Vec<String> = {
        let mut seen = std::collections::HashSet::new();
        gold_context_value
            .iter()
            .filter_map(|c| c["file"].as_str().map(strip_workspace_prefix))
            .filter(|path| seen.insert(path.clone()))
            .collect()
    };

    Ok((query, gold_files))
}

// ---------------------------------------------------------------------------
// Penalty detection heuristics
// ---------------------------------------------------------------------------

fn detect_penalties(path: &str) -> Vec<String> {
    let mut penalties = Vec::new();
    let basename = path.rsplit('/').next().unwrap_or(path);

    // Module infrastructure penalty
    if matches!(
        basename,
        "mod.rs" | "lib.rs" | "__init__.py" | "index.js" | "index.ts" | "index.tsx"
    ) {
        penalties.push("module_infrastructure".to_string());
    }

    // Vendored/dependency paths
    if path.contains("node_modules/")
        || path.contains("vendor/")
        || path.contains("third_party/")
        || path.contains("/dependencies/")
    {
        penalties.push("vendored_path".to_string());
    }

    // Test file penalties (sometimes tests are gold)
    if path.contains("/test") || path.contains("/tests/") || basename.starts_with("test_") {
        penalties.push("test_file".to_string());
    }

    // Non-source file
    if basename.ends_with(".md")
        || basename.ends_with(".toml")
        || basename.ends_with(".json")
        || basename.ends_with(".yml")
        || basename.ends_with(".yaml")
    {
        penalties.push("non_source".to_string());
    }

    // Header file (C/C++ — sometimes penalized differently)
    if basename.ends_with(".h") || basename.ends_with(".hpp") {
        penalties.push("header_file".to_string());
    }

    penalties
}

// ---------------------------------------------------------------------------
// Analysis
// ---------------------------------------------------------------------------

fn analyze_gold_file(
    gold_path: &str,
    result: &LocateResult,
    top1_signals: &HashMap<String, f32>,
) -> GoldFileReport {
    // Find the gold file in results
    let found = result
        .files
        .iter()
        .enumerate()
        .find(|(_, f)| f.path == gold_path);

    let top_score = result.files.first().map(|f| f.score).unwrap_or(0.0);

    if let Some((idx, entry)) = found {
        let signal_scores = entry.signal_scores.clone().unwrap_or_default();

        // Find signals that top-1 has but this file doesn't
        let missing: Vec<String> = top1_signals
            .keys()
            .filter(|k| {
                signal_scores.get(*k).copied().unwrap_or(0.0) < 0.001
                    && top1_signals.get(*k).copied().unwrap_or(0.0) > 0.001
            })
            .cloned()
            .collect();

        let score_ratio = if top_score > 0.001 {
            entry.score / top_score
        } else {
            0.0
        };

        GoldFileReport {
            path: gold_path.to_string(),
            status: "FOUND".to_string(),
            rank: Some(idx + 1),
            score: entry.score,
            top_score,
            score_ratio,
            signal_scores,
            missing_signals_vs_top: missing,
            penalties_detected: detect_penalties(gold_path),
            graph_entity_count: None,
            graph_entity_kinds: None,
            seen_in_stage: None,
        }
    } else {
        // NOT FOUND — check debug stages
        let mut seen_in_stage = None;
        if let Some(ref debug) = result.debug {
            for stage in &debug.stages {
                if let Some(entry) = stage.files.iter().find(|e| e.path == gold_path) {
                    seen_in_stage = Some(format!("{} (score={:.4})", stage.name, entry.score));
                    break;
                }
            }
            if seen_in_stage.is_none() {
                // Check resolved_files
                if let Some(rf) = debug.resolved_files.iter().find(|r| r.path == gold_path) {
                    seen_in_stage = Some(format!("entity_resolution (score={:.1})", rf.score));
                }
            }
        }

        GoldFileReport {
            path: gold_path.to_string(),
            status: "NOT_FOUND".to_string(),
            rank: None,
            score: 0.0,
            top_score,
            score_ratio: 0.0,
            signal_scores: HashMap::new(),
            missing_signals_vs_top: top1_signals.keys().cloned().collect(),
            penalties_detected: detect_penalties(gold_path),
            graph_entity_count: None, // filled in by caller with graph access
            graph_entity_kinds: None,
            seen_in_stage,
        }
    }
}

fn build_report(query: &str, gold_files: &[String], result: &LocateResult) -> DebugReport {
    let top1_signals = result
        .files
        .first()
        .and_then(|f| f.signal_scores.clone())
        .unwrap_or_default();

    let gold_reports: Vec<GoldFileReport> = gold_files
        .iter()
        .map(|g| analyze_gold_file(g, result, &top1_signals))
        .collect();

    let top_results: Vec<FileReport> = result
        .files
        .iter()
        .enumerate()
        .take(10)
        .map(|(i, f)| FileReport {
            rank: i + 1,
            path: f.path.clone(),
            score: f.score,
            signal_scores: f.signal_scores.clone().unwrap_or_default(),
        })
        .collect();

    let debug_info = result.debug.as_ref().map(|d| DebugInfoReport {
        scoring_track: d.scoring_track.clone(),
        retrieval_profile: d.retrieval_profile.clone(),
        fast_path: d.fast_path.clone(),
        skipped_signals: d.skipped_signals.clone(),
        query_terms: d.query_terms.clone(),
    });

    // Build summary
    let in_top5 = gold_reports
        .iter()
        .filter(|g| g.rank.map(|r| r <= 5).unwrap_or(false))
        .count();
    let in_top10 = gold_reports
        .iter()
        .filter(|g| g.rank.map(|r| r <= 10).unwrap_or(false))
        .count();
    let not_found = gold_reports.iter().filter(|g| g.rank.is_none()).count();

    let summary = format!(
        "{}/{} gold files in top-5, {}/{} in top-10, {} not found",
        in_top5,
        gold_files.len(),
        in_top10,
        gold_files.len(),
        not_found
    );

    DebugReport {
        query_preview: query.chars().take(120).collect(),
        total_results: result.files.len(),
        gold_files: gold_reports,
        top_results,
        debug_info,
        summary,
    }
}

// ---------------------------------------------------------------------------
// Human-readable output
// ---------------------------------------------------------------------------

fn print_human_report(report: &DebugReport) {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║  KIN LOCATE DEBUG                                          ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
    println!("Query: {}...", &report.query_preview);
    println!("Results: {} files returned", report.total_results);
    println!();

    if let Some(ref info) = report.debug_info {
        if let Some(ref track) = info.scoring_track {
            println!("Track:    {}", track);
        }
        if let Some(ref profile) = info.retrieval_profile {
            println!("Profile:  {}", profile);
        }
        if let Some(ref fp) = info.fast_path {
            println!("Fast path: {}", fp);
        }
        if !info.skipped_signals.is_empty() {
            println!("Skipped:  {:?}", info.skipped_signals);
        }
        println!();
    }

    // Top results
    println!("── Top Results ──────────────────────────────────────────────");
    for f in &report.top_results {
        let gold_marker = if report.gold_files.iter().any(|g| g.path == f.path) {
            " ✓ GOLD"
        } else {
            ""
        };
        println!(
            "  #{:<2} {:55} {:.4}{}",
            f.rank, f.path, f.score, gold_marker
        );
        if !f.signal_scores.is_empty() {
            let mut signals: Vec<_> = f.signal_scores.iter().collect();
            signals.sort_by(|a, b| b.1.partial_cmp(a.1).unwrap_or(std::cmp::Ordering::Equal));
            let sig_str: Vec<String> = signals
                .iter()
                .map(|(k, v)| format!("{}={:.2}", k, v))
                .collect();
            println!("       signals: {}", sig_str.join(", "));
        }
    }
    println!();

    // Gold file analysis
    if !report.gold_files.is_empty() {
        println!("── Gold File Analysis ───────────────────────────────────────");
        for g in &report.gold_files {
            let status_icon = if g.rank.is_some() { "✓" } else { "✗" };
            let rank_str = g
                .rank
                .map(|r| format!("rank #{}", r))
                .unwrap_or_else(|| "NOT FOUND".to_string());
            println!("  {} {} — {}", status_icon, g.path, rank_str);

            if g.rank.is_some() {
                println!(
                    "    score={:.4}  top={:.4}  ratio={:.3}",
                    g.score, g.top_score, g.score_ratio
                );
                if !g.signal_scores.is_empty() {
                    let mut signals: Vec<_> = g.signal_scores.iter().collect();
                    signals
                        .sort_by(|a, b| b.1.partial_cmp(a.1).unwrap_or(std::cmp::Ordering::Equal));
                    let sig_str: Vec<String> = signals
                        .iter()
                        .map(|(k, v)| format!("{}={:.2}", k, v))
                        .collect();
                    println!("    signals: {}", sig_str.join(", "));
                }
                if !g.missing_signals_vs_top.is_empty() {
                    println!(
                        "    missing vs top-1: {}",
                        g.missing_signals_vs_top.join(", ")
                    );
                }
            } else {
                if let Some(ref stage) = g.seen_in_stage {
                    println!("    seen in pipeline: {}", stage);
                } else {
                    println!("    never seen in pipeline");
                }
                if let Some(count) = g.graph_entity_count {
                    if count > 0 {
                        println!(
                            "    graph entities: {} ({:?})",
                            count,
                            g.graph_entity_kinds.as_deref().unwrap_or(&[])
                        );
                    } else {
                        println!("    graph entities: NONE (file not in entity graph)");
                    }
                }
            }
            if !g.penalties_detected.is_empty() {
                println!("    penalties: {}", g.penalties_detected.join(", "));
            }
        }
        println!();
        println!("── Summary ─────────────────────────────────────────────────");
        println!("  {}", report.summary);
    }
}

// ---------------------------------------------------------------------------
// Enrich NOT_FOUND gold files with graph entity data
// ---------------------------------------------------------------------------

async fn enrich_not_found_with_graph(report: &mut DebugReport) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?);
    let Some(layout) = layout else {
        return Ok(());
    };
    let snap =
        crate::backend::open_snapshot_explicit_admin_read_only(&layout, "kin locate-debug").await?;
    let graph = &*snap.graph();

    for gold in &mut report.gold_files {
        if gold.status == "NOT_FOUND" && gold.graph_entity_count.is_none() {
            let filter = EntityFilter {
                file_path: Some(kin_model::FilePathId::new(&gold.path)),
                ..Default::default()
            };
            match graph.query_entities(&filter) {
                Ok(entities) => {
                    gold.graph_entity_count = Some(entities.len());
                    if !entities.is_empty() {
                        let kinds: Vec<String> = entities
                            .iter()
                            .map(|e| format!("{:?}", e.kind))
                            .collect::<std::collections::HashSet<_>>()
                            .into_iter()
                            .collect();
                        gold.graph_entity_kinds = Some(kinds);
                    } else {
                        gold.graph_entity_kinds = Some(vec![]);
                    }
                }
                Err(_) => {
                    gold.graph_entity_count = Some(0);
                    gold.graph_entity_kinds = Some(vec![]);
                }
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub async fn run(
    query: String,
    target: Option<String>,
    task_file: Option<String>,
    max_files: usize,
    json_output: bool,
) -> Result<()> {
    // 1. Determine query text and gold files
    let (query_text, gold_files) = if let Some(ref tf) = task_file {
        let (q, gf) = parse_task_file(tf)?;
        // If a query was also provided, prefer the task file's problem_statement
        (q, gf)
    } else {
        let gf = target.map(|t| vec![t]).unwrap_or_default();
        (query, gf)
    };

    if query_text.is_empty() {
        anyhow::bail!("no query text provided (pass inline or use --task-file)");
    }

    // 2. Run locate with explain=true and wider max_files
    let result = crate::commands::locate::capture(
        &query_text,
        Vec::new(),
        true,
        max_files,
        true,
        None,
        false,
        // This report scores files and gold-set overlap, not the entity ranking,
        // so it stays on the coordinates-only projection.
        false,
        crate::commands::locate::LocatePaging::default(),
        crate::commands::locate::LocateScope::SOURCE_ONLY,
    )
    .await?;

    // 3. Build the report
    let mut report = build_report(&query_text, &gold_files, &result);

    // 4. Enrich NOT_FOUND gold files with graph entity data
    let has_not_found = report.gold_files.iter().any(|g| g.status == "NOT_FOUND");
    if has_not_found {
        if let Err(e) = enrich_not_found_with_graph(&mut report).await {
            eprintln!("Warning: could not enrich graph data: {}", e);
        }
    }

    // 5. Output
    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_human_report(&report);
    }

    Ok(())
}
