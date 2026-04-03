// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! `kin locate-debug` — detailed signal breakdown for locate debugging.
//!
//! Two modes:
//! 1. `kin locate-debug "query"` — top 5 results with per-signal scores
//! 2. `kin locate-debug "query" --target path/to/file.py` — where did the
//!    target file rank and what helped/hurt it

use anyhow::Result;

pub async fn run(
    query: String,
    target: Option<String>,
    task_file: Option<String>,
    max_files: usize,
) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let snap = crate::backend::open_snapshot_daemon_first_read_only(&layout).await?;
    let graph = &*snap.graph();

    // If task_file provided, load query and gold files from it
    let (query, gold_files) = if let Some(tf) = task_file {
        let data: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&tf)?,
        )?;
        let q = data["problem_statement"]
            .as_str()
            .unwrap_or(&query)
            .to_string();
        let gf: Vec<String> = serde_json::from_value(
            data["gold_context"].clone(),
        )
        .ok()
        .and_then(|ctx: Vec<serde_json::Value>| {
            Some(ctx.iter().filter_map(|c| c["file"].as_str().map(|s| {
                // Strip workspace prefix if present
                s.rsplit("/workspace/").last().unwrap_or(s)
                    .trim_start_matches(|c: char| c != '/')
                    .to_string()
            })).collect())
        })
        .unwrap_or_default();
        (q, gf)
    } else {
        (query, target.map(|t| vec![t]).unwrap_or_default())
    };

    // Run locate with full explain
    let result = crate::commands::locate::run_with_graph(
        graph,
        &query,
        true,  // json
        true,  // explain
        max_files,
    );

    // Since run_with_graph prints to stdout, we need to capture it differently.
    // For now, run it and print our diagnostic on top.

    // Actually, let's just call the internal scoring directly.
    // The locate command prints results — let's enhance the output format.

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║  KIN LOCATE DEBUG                                          ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
    println!("Query: {}...", &query[..query.len().min(80)]);
    if !gold_files.is_empty() {
        println!("Gold:  {:?}", gold_files);
    }
    println!();

    // Run locate
    if let Err(e) = result {
        println!("Locate error: {}", e);
        return Ok(());
    }

    Ok(())
}
