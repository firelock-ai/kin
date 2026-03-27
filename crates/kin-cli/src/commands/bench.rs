// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use std::path::Path;
use std::time::Duration;

pub async fn run(assistant_run_paths: Vec<String>) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let _snap = kin_db::SnapshotManager::open(crate::backend::kindb_snapshot_path(&layout))?;
    let graph = &*_snap.graph();

    println!("Running Kin benchmarks...");

    // Collect metrics using the MetricCollector
    let dep_cov = kin_bench::MetricCollector::collect_dependency_coverage(&graph)
        .map_err(|e| anyhow::anyhow!("benchmark failed: {}", e))?;
    let dead_code = kin_bench::MetricCollector::collect_dead_code_stats(&graph)
        .map_err(|e| anyhow::anyhow!("benchmark failed: {}", e))?;
    let token_savings = kin_bench::MetricCollector::collect_token_savings(&graph, 500, 50)
        .map_err(|e| anyhow::anyhow!("benchmark failed: {}", e))?;
    let test_cov = kin_bench::MetricCollector::collect_test_coverage(&graph)
        .map_err(|e| anyhow::anyhow!("benchmark failed: {}", e))?;

    // Build report
    let mut report = kin_bench::BenchmarkReport::new("kin bench");
    report.reliability.dependency_coverage = Some(dep_cov);
    report.reliability.dead_code = Some(dead_code);
    report.economic.token_savings = Some(token_savings);
    report.reliability.test_coverage = Some(test_cov);
    report.repo_name = std::env::current_dir()?
        .file_name()
        .map(|name| name.to_string_lossy().to_string());

    if !assistant_run_paths.is_empty() {
        let assistant_runs = load_assistant_runs(&assistant_run_paths)?;
        let run_count = assistant_runs.len();
        report.add_assistant_runs(assistant_runs);
        println!("Loaded {run_count} assistant benchmark run(s).");
    }

    // Print summary
    print!("{}", report.summary());

    // Save report and dashboard to .kin/bench/
    let bench_dir = layout.bench_dir();
    std::fs::create_dir_all(&bench_dir)?;
    let timestamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");
    let report_file = bench_dir.join(format!("bench-{timestamp}.json"));
    let dashboard_file = bench_dir.join(format!("bench-dashboard-{timestamp}.json"));
    let json = report.to_json()?;
    std::fs::write(&report_file, &json)?;
    let dashboard = kin_bench::DashboardData::from_report(&report);
    std::fs::write(&dashboard_file, dashboard.to_json()?)?;
    println!("Report saved to: {}", report_file.display());
    println!("Dashboard saved to: {}", dashboard_file.display());

    Ok(())
}

pub async fn corpus(repos: Vec<String>, github_dir: Option<String>) -> Result<()> {
    let mut repo_paths: Vec<std::path::PathBuf> =
        repos.iter().map(std::path::PathBuf::from).collect();

    if let Some(dir) = github_dir {
        let discovered = kin_bench::corpus::discover_repos(std::path::Path::new(&dir));
        repo_paths.extend(discovered);
    }

    if repo_paths.is_empty() {
        println!("No repositories specified. Use --repo or --github-dir.");
        return Ok(());
    }

    let config = kin_bench::CorpusConfig { repo_paths };
    let runner = kin_bench::CorpusRunner::new();
    let summary = runner.run(&config);

    print!("{}", summary.display());

    // Save results if inside a Kin repo
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?);
    if let Some(layout) = layout {
        let bench_dir = layout.bench_dir();
        std::fs::create_dir_all(&bench_dir)?;
        let timestamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");
        let corpus_file = bench_dir.join(format!("corpus-{timestamp}.json"));
        std::fs::write(&corpus_file, serde_json::to_string_pretty(&summary)?)?;
        println!("\nCorpus results saved to: {}", corpus_file.display());
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn capture(
    assistant: String,
    task: String,
    substrate: String,
    model: Option<String>,
    duration_ms: f64,
    tokens_in: u64,
    tokens_out: u64,
    cost: f64,
    passed: bool,
) -> Result<()> {
    let bench_substrate = match substrate.to_lowercase().as_str() {
        "git" => kin_bench::BenchmarkSubstrate::Git,
        "kin" => kin_bench::BenchmarkSubstrate::Kin,
        other => {
            return Err(anyhow::anyhow!(
                "unknown substrate '{}', expected 'git' or 'kin'",
                other
            ))
        }
    };

    let run = kin_bench::build_run_from_flags(
        &assistant,
        &task,
        bench_substrate,
        model.as_deref(),
        duration_ms,
        tokens_in,
        tokens_out,
        cost,
        passed,
    );

    // Save the run
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let bench_dir = layout.bench_dir();
    std::fs::create_dir_all(&bench_dir)?;

    let timestamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");
    let run_file = bench_dir.join(format!("capture-{}-{timestamp}.json", assistant));
    std::fs::write(&run_file, serde_json::to_string_pretty(&run)?)?;

    println!("Captured benchmark run:");
    println!("  Source: manual CLI capture");
    println!(
        "  Assistant: {} ({})",
        run.assistant_name,
        run.substrate.as_str()
    );
    println!("  Task: {}", run.task_name);
    if let Some(ref m) = run.model_name {
        println!("  Model: {}", m);
    }
    println!("  Duration: {:.0}ms", run.duration_ms.0);
    println!(
        "  Tokens: {} in / {} out / {} total",
        run.input_tokens, run.output_tokens, run.total_tokens
    );
    println!("  Cost: ${:.4}", run.estimated_cost_usd);
    println!("  Passed: {}", run.validation_passed);
    println!("Saved to: {}", run_file.display());
    println!("Note: this path records user-supplied numbers. Use `kin bench capture-artifact` or a live harness for audited comparisons.");

    Ok(())
}

/// Capture a benchmark run from a raw assistant artifact file (Claude JSONL, Codex patch, Gemini JSON).
pub async fn capture_artifact(
    vendor: &str,
    path: String,
    task: Option<String>,
    substrate: Option<String>,
) -> Result<()> {
    let artifact = match vendor {
        "claude" => kin_bench::parse_claude_artifact(std::path::Path::new(&path))
            .map_err(|e| anyhow::anyhow!("failed to parse Claude artifact: {}", e))?,
        "codex" => kin_bench::parse_codex_artifact(std::path::Path::new(&path))
            .map_err(|e| anyhow::anyhow!("failed to parse Codex artifact: {}", e))?,
        "gemini" => kin_bench::parse_gemini_artifact(std::path::Path::new(&path))
            .map_err(|e| anyhow::anyhow!("failed to parse Gemini artifact: {}", e))?,
        other => {
            return Err(anyhow::anyhow!(
                "unknown vendor '{}', expected claude, codex, or gemini",
                other
            ))
        }
    };

    let bench_substrate = match substrate
        .as_deref()
        .unwrap_or("kin")
        .to_lowercase()
        .as_str()
    {
        "git" => kin_bench::BenchmarkSubstrate::Git,
        "kin" => kin_bench::BenchmarkSubstrate::Kin,
        other => {
            return Err(anyhow::anyhow!(
                "unknown substrate '{}', expected 'git' or 'kin'",
                other
            ))
        }
    };

    let task_name = task.unwrap_or_else(|| {
        std::path::Path::new(&path)
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "unnamed".to_string())
    });

    let run = kin_bench::CaptureSession::from_artifact(&artifact, &task_name, bench_substrate);

    // Save the run
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let bench_dir = layout.bench_dir();
    std::fs::create_dir_all(&bench_dir)?;

    let timestamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");
    let run_file = bench_dir.join(format!("capture-{}-{timestamp}.json", vendor));
    std::fs::write(&run_file, serde_json::to_string_pretty(&run)?)?;

    println!("Captured {} artifact:", vendor);
    println!("  Task: {}", run.task_name);
    println!("  Files touched: {}", artifact.files_touched.len());
    for f in &artifact.files_touched {
        println!("    {}", f);
    }
    println!(
        "  Lines: +{} / -{}",
        artifact.lines_added, artifact.lines_removed
    );
    println!("  Tool calls: {}", artifact.tool_calls);
    println!("  Iterations: {}", artifact.iterations);
    if let Some(dur) = artifact.raw_duration_secs {
        println!("  Duration: {:.1}s", dur);
    }
    println!("Saved to: {}", run_file.display());

    Ok(())
}

fn load_assistant_runs(paths: &[String]) -> Result<Vec<kin_bench::AssistantTaskRun>> {
    let mut runs = Vec::new();

    for path in paths {
        let mut parsed = kin_bench::load_assistant_runs_from_path(Path::new(path))
            .map_err(|e| anyhow::anyhow!("failed to load assistant run file {}: {}", path, e))?;
        runs.append(&mut parsed);
    }

    Ok(runs)
}

fn normalize_benchmark_name(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace(['_', ' '], "-")
}

fn parse_arm_filter(value: &str) -> Option<kin_bench::BenchmarkArm> {
    match normalize_benchmark_name(value).as_str() {
        "git" => Some(kin_bench::BenchmarkArm::Git),
        "kin-compat" => Some(kin_bench::BenchmarkArm::KinCompat),
        "kin-native" => Some(kin_bench::BenchmarkArm::KinNative),
        "kin-native-cli" => Some(kin_bench::BenchmarkArm::KinNativeCli),
        "kin-pilot-native" => Some(kin_bench::BenchmarkArm::KinPilotNative),
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn run_live(
    repo: Option<String>,
    task_prompts: Vec<String>,
    task_names: Vec<String>,
    task_set: String,
    assistant_filter: Option<String>,
    exclude: Vec<String>,
    repeat: u32,
    arm_filters: Vec<String>,
    no_monitor: bool,
    keep_workspace: bool,
    native_restrict_discovery: bool,
    native_restrict_filesystem: bool,
    fresh_conversion: bool,
    claude_disable_explore: bool,
    plugin_dir: Option<String>,
    include_kin_pilot_native: bool,
) -> Result<()> {
    use kin_bench::live;

    fn merge_claude_disallowed_tools(env_vars: &mut Vec<(String, String)>, tools: &[&str]) {
        let key = "KIN_CLAUDE_DISALLOWED_TOOLS".to_string();
        let mut merged: Vec<String> = env_vars
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| {
                v.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(ToString::to_string)
                    .collect()
            })
            .unwrap_or_default();

        for tool in tools {
            if !merged.iter().any(|existing| existing == tool) {
                merged.push((*tool).to_string());
            }
        }

        if let Some((_, value)) = env_vars.iter_mut().find(|(k, _)| *k == key) {
            *value = merged.join(",");
        } else if !merged.is_empty() {
            env_vars.push((key, merged.join(",")));
        }
    }

    // 0. Clean up stale benchmark workspaces (older than 24h)
    kin_bench::live::cleanup_stale_workspaces(24);

    // 1. Detect available CLIs
    let all_clis = live::detect_available_clis();
    let mut clis = match assistant_filter {
        Some(ref filter) => live::filter_clis(all_clis, filter),
        None => all_clis,
    };

    // Apply exclusions
    if !exclude.is_empty() {
        let exclude_lower: Vec<String> = exclude.iter().map(|e| e.to_lowercase()).collect();
        clis.retain(|c| {
            !exclude_lower.iter().any(|ex| {
                c.binary.to_lowercase() == *ex || c.name.to_lowercase().contains(ex.as_str())
            })
        });
    }

    if clis.is_empty() {
        println!("No assistant CLIs detected on PATH.");
        println!("Install one or more of: claude, codex, gemini");
        if assistant_filter.is_some() {
            println!("(filtered by --assistant flag)");
        }
        return Ok(());
    }

    println!("Detected assistant CLIs:");
    for cli in &clis {
        print!("  {} ({})", cli.name, cli.binary);
        if let Some(ref v) = cli.version {
            print!(" — {}", v);
        }
        println!();
    }
    println!();

    // 2. Determine repo source
    let repo_source = repo.unwrap_or_else(|| {
        std::env::current_dir()
            .unwrap_or_default()
            .display()
            .to_string()
    });

    // 3. Find kin binary
    let kin_binary = std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("kin"));

    // 4. Set up the benchmark workspace and enabled arms
    println!("Setting up benchmark workspace from: {repo_source}");
    let workspace = kin_bench::BenchWorkspace::setup_with_options(
        &repo_source,
        &kin_binary,
        fresh_conversion,
        include_kin_pilot_native,
    )
    .map_err(|e| anyhow::anyhow!("workspace setup failed: {e}"))?;

    let repo_name = workspace.repo_name.clone();

    println!("Workspace: {}", workspace.root.display());
    println!("  git arm:             {}", workspace.git_dir.display());
    println!(
        "  kin-compat arm:      {}",
        workspace.kin_compat_dir.display()
    );
    println!(
        "  kin-native arm:      {}",
        workspace.kin_native_dir.display()
    );
    if let Some(ref d) = workspace.kin_native_cli_dir {
        println!("  kin-native-cli arm:  {}", d.display());
    }

    // 5. Start report
    let mut report = kin_bench::LiveBenchmarkReport::new(repo_name.clone());
    report.conversions = workspace.conversions.clone();
    report.planted = workspace.planted.clone();

    for conv in &workspace.conversions {
        if report.commit_sha.is_none() {
            report.commit_sha = conv.commit_sha.clone();
        }
        println!();
        println!("--- Kin Conversion ({}) ---", conv.arm);
        println!("  Init:        {:.1}s", conv.init_duration_ms / 1000.0);
        println!("  Commit:      {:.1}s", conv.commit_duration_ms / 1000.0);
        println!("  .kin size:   {} bytes", conv.kin_dir_size_bytes);
        println!("  .git size:   {} bytes", conv.git_dir_size_bytes);
        println!("  Entities:    {}", conv.entity_count);
        println!("  Files:       {}", conv.file_count);
    }

    // System baseline stored in report later after health check runs

    // Determine save directory early so we can use it for transcripts + final report.
    // If the current cwd is not itself a Kin repo, write outside the ephemeral
    // benchmark workspace so cleanup does not delete the collected artifacts.
    let save_dir = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .map(|l| l.bench_dir())
        .unwrap_or_else(|| {
            workspace
                .root
                .parent()
                .unwrap_or(workspace.root.as_path())
                .join("results")
        });

    let run_id = chrono::Utc::now().format("%Y%m%d-%H%M%S").to_string();

    // 6. Build task list
    let mut tasks: Vec<kin_bench::LiveTask> = if task_prompts.is_empty() {
        let set = match task_set.as_str() {
            "discovery" => kin_bench::TaskSet::Discovery,
            "mutation" => kin_bench::TaskSet::Mutation,
            "validated" => kin_bench::TaskSet::Validated,
            _ => kin_bench::TaskSet::All,
        };
        if set == kin_bench::TaskSet::Validated {
            // Validated tasks come from planted artifacts, not built-in prompts
            match &workspace.planted {
                Some(artifacts) => {
                    let validated_tasks = kin_bench::live::validated_tasks(artifacts);
                    eprintln!(
                        "Using validated tasks with planted tag={} ({} tasks)",
                        artifacts.tag,
                        validated_tasks.len()
                    );
                    validated_tasks
                }
                None => {
                    eprintln!("Warning: --task-set validated requires planted artifacts; falling back to discovery");
                    kin_bench::live::live_tasks_for_set(kin_bench::TaskSet::Discovery)
                }
            }
        } else {
            kin_bench::live::live_tasks_for_set(set)
        }
    } else {
        task_prompts
            .iter()
            .enumerate()
            .map(|(i, p)| kin_bench::LiveTask {
                name: format!("custom-{}", i + 1),
                prompt: p.clone(),
                validators: vec![],
            })
            .collect()
    };

    if !task_prompts.is_empty() && !task_names.is_empty() {
        println!("Ignoring --task-name because explicit --task prompts were provided.");
    } else if !task_names.is_empty() {
        let wanted: Vec<String> = task_names
            .iter()
            .map(|name| normalize_benchmark_name(name))
            .collect();
        tasks.retain(|task| wanted.contains(&normalize_benchmark_name(&task.name)));
        if tasks.is_empty() {
            return Err(anyhow::anyhow!(
                "no built-in tasks matched --task-name filters: {}",
                task_names.join(", ")
            ));
        }
    }

    let mut arms = vec![
        kin_bench::BenchmarkArm::Git,
        kin_bench::BenchmarkArm::KinCompat,
        kin_bench::BenchmarkArm::KinNative,
    ];
    if workspace.kin_native_cli_dir.is_some() {
        arms.push(kin_bench::BenchmarkArm::KinNativeCli);
    }
    if include_kin_pilot_native && workspace.kin_pilot_native_dir.is_some() {
        arms.push(kin_bench::BenchmarkArm::KinPilotNative);
    }

    if !arm_filters.is_empty() {
        let requested: Vec<kin_bench::BenchmarkArm> = arm_filters
            .iter()
            .map(|value| {
                parse_arm_filter(value).ok_or_else(|| {
                    anyhow::anyhow!(
                        "unknown --arm '{}'; expected one of git, kin-compat, kin-native, kin-native-cli, kin-pilot-native",
                        value
                    )
                })
            })
            .collect::<Result<Vec<_>>>()?;
        arms.retain(|arm| requested.contains(arm));
        if arms.is_empty() {
            return Err(anyhow::anyhow!(
                "none of the requested --arm filters are available in this workspace"
            ));
        }
    }

    let total_runs = tasks.len() * clis.len() * arms.len() * repeat as usize;
    let mut run_number: usize = 0;

    println!();
    println!(
        "Running {} task(s) x {} CLI(s) x {} arm(s) x {} repeat(s) = {} total runs",
        tasks.len(),
        clis.len(),
        arms.len(),
        repeat,
        total_runs
    );

    // Pre-run system health check
    let baseline = kin_bench::live::capture_system_baseline();
    let pre_health = kin_bench::live::capture_system_health(baseline.cpu_cores, None);
    println!();
    println!("--- System Health ---");
    println!(
        "  CPU: {} cores, {:.0}% busy, load avg {:.1}/{:.1}",
        baseline.cpu_cores, pre_health.cpu_pct, pre_health.load_avg_1m, pre_health.load_avg_5m
    );
    println!(
        "  RAM: {:.0}% used ({:.1} GB / {:.1} GB)",
        pre_health.mem_pressure_pct,
        (baseline.ram_total_bytes as f64
            - (baseline.ram_total_bytes as f64 * (100.0 - pre_health.mem_pressure_pct) / 100.0))
            / 1e9,
        baseline.ram_total_bytes as f64 / 1e9
    );
    if pre_health.swap_total_bytes > 0 {
        println!(
            "  Swap: {:.0} MB used / {:.0} MB total",
            pre_health.swap_used_bytes as f64 / 1e6,
            pre_health.swap_total_bytes as f64 / 1e6
        );
    }
    if pre_health.competing_processes.is_empty() {
        println!("  Competing assistants: none");
    } else {
        println!(
            "  Competing assistants: {} found",
            pre_health.competing_processes.len()
        );
        for p in &pre_health.competing_processes {
            println!(
                "    {} (pid={}, {:.0} MB, {:.1}% CPU)",
                p.name,
                p.pid,
                p.rss_bytes as f64 / 1e6,
                p.cpu_pct
            );
        }
    }
    if pre_health.clean {
        println!("  Status: CLEAN");
    } else {
        println!("  Status: CONTENTION DETECTED");
        for w in &pre_health.warnings {
            println!("    ! {w}");
        }
    }
    if !no_monitor {
        report.system_baseline = Some(baseline.clone());
        report.pre_run_health = Some(pre_health.clone());
    }
    println!();

    // Maximum wall clock per run before flagging as tainted (10 minutes).
    // If a run exceeds this AND the system clock drifted, it was likely
    // interrupted by sleep/network loss.
    let max_run_secs: f64 = 600.0;

    // 7. Execute runs — sequential to avoid contention
    for rep in 0..repeat {
        if repeat > 1 {
            println!("=== Repetition {}/{} ===", rep + 1, repeat);
        }

        for task in &tasks {
            // Rotate arm order per task to reduce systematic bias
            let arm_order: Vec<kin_bench::BenchmarkArm> = if rep % 2 == 0 {
                arms.clone()
            } else {
                let mut reversed = arms.clone();
                reversed.reverse();
                reversed
            };

            for &arm in &arm_order {
                let cwd = workspace.arm_dir(arm);

                for cli in &clis {
                    // Pre-run: detect system sleep by timing a no-op
                    let pre_check_start = std::time::Instant::now();
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    let pre_check_elapsed = pre_check_start.elapsed().as_millis();
                    if pre_check_elapsed > 500 {
                        // System likely just woke from sleep — 10ms took >500ms
                        println!("  WARN: System may have just woken from sleep (10ms sleep took {}ms). Pausing 5s...", pre_check_elapsed);
                        std::thread::sleep(std::time::Duration::from_secs(5));
                    }

                    run_number += 1;
                    eprintln!(
                        "Run [{}/{}] {} | {} | {} (rep {}/{})",
                        run_number,
                        total_runs,
                        arm,
                        cli.name,
                        task.name,
                        rep + 1,
                        repeat
                    );

                    let prompt = kin_bench::live::build_prompt_with_guidance(
                        arm.as_str(),
                        &task.prompt,
                        cwd,
                    );
                    let injected_task = kin_bench::LiveTask {
                        name: task.name.clone(),
                        prompt,
                        validators: task.validators.clone(),
                    };

                    // Create isolated env vars for this arm
                    let env_vars = kin_bench::live::create_isolated_env(
                        cwd,
                        arm,
                        &kin_binary,
                        native_restrict_discovery,
                        native_restrict_filesystem,
                    )
                    .unwrap_or_default();
                    let mut env_vars = env_vars;
                    // Pass plugin dir for Kin arms when running Claude
                    if let Some(ref dir) = plugin_dir {
                        if arm != kin_bench::BenchmarkArm::Git {
                            env_vars.push(("KIN_PLUGIN_DIR".to_string(), dir.clone()));
                        }
                    }
                    if cli.binary.to_lowercase().contains("claude") {
                        let is_native = arm == kin_bench::BenchmarkArm::KinNative
                            || arm == kin_bench::BenchmarkArm::KinPilotNative;
                        let native_strict =
                            is_native && (native_restrict_discovery || native_restrict_filesystem);

                        // In strict native benchmark modes, also disable Claude's Task
                        // subagent tool so filesystem/tool restrictions apply to the
                        // actual work instead of being sidestepped through Explore.
                        if claude_disable_explore || native_strict {
                            merge_claude_disallowed_tools(&mut env_vars, &["Task"]);
                        }
                        if is_native {
                            merge_claude_disallowed_tools(&mut env_vars, &["ToolSearch"]);
                            if native_restrict_filesystem {
                                merge_claude_disallowed_tools(
                                    &mut env_vars,
                                    &["Grep", "Glob", "LS", "Read"],
                                );
                            } else if native_restrict_discovery {
                                merge_claude_disallowed_tools(
                                    &mut env_vars,
                                    &["Grep", "Glob", "LS"],
                                );
                            }
                        }
                    }
                    let env_refs: Vec<(&str, &str)> = env_vars
                        .iter()
                        .map(|(k, v)| (k.as_str(), v.as_str()))
                        .collect();

                    // Start resource monitor if enabled
                    let monitor = if !no_monitor {
                        Some(kin_bench::ResourceMonitor::start(2000))
                    } else {
                        None
                    };

                    let spawned = match arm {
                        kin_bench::BenchmarkArm::Git => {
                            kin_bench::live::spawn_task(&cli.binary, &injected_task, cwd, &env_refs)
                        }
                        kin_bench::BenchmarkArm::KinCompat => {
                            kin_bench::live::spawn_task_via_kin_with(
                                &kin_binary,
                                &cli.binary,
                                &injected_task,
                                cwd,
                                &env_refs,
                                true,
                                false,
                                false,
                            )
                        }
                        kin_bench::BenchmarkArm::KinNative => {
                            // Native arm: .kin/ is relocated to a shadow workspace, so
                            // `kin with` can't discover the repo.  Spawn the assistant
                            // directly — the bench harness already set up CLAUDE.md,
                            // .mcp.json, hooks, and env for the native workspace.
                            kin_bench::live::spawn_task(&cli.binary, &injected_task, cwd, &env_refs)
                        }
                        kin_bench::BenchmarkArm::KinNativeCli => {
                            // Native-CLI arm: .kin/ stays in arm dir for CLI access.
                            // No MCP — Claude uses kin CLI via Bash.
                            kin_bench::live::spawn_task(&cli.binary, &injected_task, cwd, &env_refs)
                        }
                        kin_bench::BenchmarkArm::KinPilotNative => {
                            // kin-pilot has built-in Kin-first instructions — spawn directly
                            kin_bench::live::spawn_task("kin-pilot", &injected_task, cwd, &env_refs)
                        }
                    };

                    match spawned {
                        Ok(spawned) => {
                            if let Some(ref monitor) = monitor {
                                monitor.track_pid(spawned.pid());
                            }
                            let result = spawned.wait_with_timeout(Some(benchmark_timeout(arm)));
                            let resource_report = monitor.map(|m| m.stop());

                            // Post-run: detect system sleep during the run
                            let post_check_start = std::time::Instant::now();
                            std::thread::sleep(std::time::Duration::from_millis(10));
                            let post_check_elapsed = post_check_start.elapsed().as_millis();
                            let system_slept = post_check_elapsed > 500;

                            match result {
                                Ok(ref res) => {
                                    let wall_secs = res.wall_clock_ms / 1000.0;
                                    let tainted = system_slept || wall_secs > max_run_secs;

                                    let validated = res.validate(&task.validators);
                                    let validation_label = if task.validators.is_empty() {
                                        "-".to_string()
                                    } else if validated {
                                        "yes".to_string()
                                    } else {
                                        "NO".to_string()
                                    };

                                    let status = if res.spiral_killed {
                                        "SPIRAL-KILLED"
                                    } else if tainted {
                                        "TAINTED"
                                    } else if res.success {
                                        "OK"
                                    } else {
                                        "FAIL"
                                    };
                                    eprintln!(
                                        "  Done: {:.1}s | {} tokens",
                                        wall_secs, res.total_tokens,
                                    );
                                    println!(
                                        "  {} | {:.1}s | {}in/{}out tokens | ${:.4} | validated: {}",
                                        status,
                                        wall_secs,
                                        res.input_tokens,
                                        res.output_tokens,
                                        res.estimated_cost_usd,
                                        validation_label,
                                    );
                                    if tainted {
                                        println!("  WARN: Result may be unreliable — system sleep or excessive wall clock detected");
                                    }
                                    // Print system health warnings from resource report
                                    if let Some(ref rr) = resource_report {
                                        if let Some(ref health) = rr.pre_run_health {
                                            for w in &health.warnings {
                                                println!("  WARN: {w}");
                                            }
                                        }
                                    }
                                    if let Some(ref err) = res.error {
                                        println!("  Error: {}", err);
                                    }

                                    // Save raw transcript if available
                                    let transcript_path = if !res.raw_stdout.is_empty()
                                        || !res.raw_stderr.is_empty()
                                    {
                                        let transcript_dir = save_dir.join("transcripts");
                                        std::fs::create_dir_all(&transcript_dir).ok();
                                        let cli_slug =
                                            cli.name
                                                .chars()
                                                .map(|ch| {
                                                    if ch.is_ascii_alphanumeric() {
                                                        ch
                                                    } else {
                                                        '-'
                                                    }
                                                })
                                                .collect::<String>()
                                                .to_lowercase();
                                        let filename = format!(
                                            "{}-{}-{}-{}-{}.txt",
                                            run_id, repo_name, arm, cli_slug, task.name
                                        );
                                        let transcript_file = transcript_dir.join(&filename);
                                        let transcript_content = format!(
                                            "=== STDOUT ===\n{}\n\n=== STDERR ===\n{}\n",
                                            res.raw_stdout, res.raw_stderr
                                        );
                                        std::fs::write(&transcript_file, &transcript_content).ok();
                                        Some(transcript_file.display().to_string())
                                    } else {
                                        None
                                    };

                                    let step_trace = if !res.timed_events.is_empty() {
                                        Some(kin_bench::live::extract_step_trace(&res.timed_events))
                                    } else {
                                        None
                                    };

                                    let step_trace_path = if let Some(ref trace) = step_trace {
                                        let trace_dir = save_dir.join("step-traces");
                                        std::fs::create_dir_all(&trace_dir).ok();
                                        let cli_slug =
                                            cli.name
                                                .chars()
                                                .map(|ch| {
                                                    if ch.is_ascii_alphanumeric() {
                                                        ch
                                                    } else {
                                                        '-'
                                                    }
                                                })
                                                .collect::<String>()
                                                .to_lowercase();
                                        let filename = format!(
                                            "{}-{}-{}-{}-{}.json",
                                            run_id, repo_name, arm, cli_slug, task.name
                                        );
                                        let trace_file = trace_dir.join(&filename);
                                        if let Ok(json) = serde_json::to_string_pretty(trace) {
                                            std::fs::write(&trace_file, json).ok();
                                            Some(trace_file.display().to_string())
                                        } else {
                                            None
                                        }
                                    } else {
                                        None
                                    };

                                    // Collect shim log if present (typically kin-native arm)
                                    let raw_shim_log_path = kin_bench::live::shim_log_path(cwd);
                                    let shim_log_path = if raw_shim_log_path.exists() {
                                        let shim_dir = save_dir.join("shim-logs");
                                        std::fs::create_dir_all(&shim_dir).ok();
                                        let cli_slug =
                                            cli.name
                                                .chars()
                                                .map(|ch| {
                                                    if ch.is_ascii_alphanumeric() {
                                                        ch
                                                    } else {
                                                        '-'
                                                    }
                                                })
                                                .collect::<String>()
                                                .to_lowercase();
                                        let filename = format!(
                                            "{}-{}-{}-{}-{}.jsonl",
                                            run_id, repo_name, arm, cli_slug, task.name
                                        );
                                        let shim_file = shim_dir.join(&filename);
                                        if std::fs::copy(&raw_shim_log_path, &shim_file).is_ok() {
                                            Some(shim_file.display().to_string())
                                        } else {
                                            None
                                        }
                                    } else {
                                        None
                                    };
                                    let shim_log_summary = kin_bench::live::collect_shim_log(cwd)
                                        .map(|entries| {
                                            kin_bench::live::summarize_shim_log(&entries)
                                        });

                                    let (step_summary, step_trace_entries, tool_usage) =
                                        match step_trace {
                                            Some(trace) => {
                                                let mut summary = trace.summary;
                                                apply_cost_attribution(
                                                    &mut summary,
                                                    res.total_tokens,
                                                    res.estimated_cost_usd,
                                                );
                                                let entries = trace.entries;
                                                let tool_usage = Some(
                                                    kin_bench::live::extract_tool_usage_from_steps(
                                                        &entries,
                                                        &cli.name,
                                                        arm.as_str(),
                                                        &task.name,
                                                    ),
                                                );
                                                (Some(summary), Some(entries), tool_usage)
                                            }
                                            None => (
                                                None,
                                                None,
                                                Some(kin_bench::live::extract_tool_usage(
                                                    &format!(
                                                        "{}\n{}",
                                                        res.raw_stdout, res.raw_stderr
                                                    ),
                                                    &cli.name,
                                                    arm.as_str(),
                                                    &task.name,
                                                )),
                                            ),
                                        };

                                    // Structured trace is the source of truth when present.
                                    // Raw transcript scanning remains only as a fallback for
                                    // assistants or runs without step-trace extraction.

                                    let mut task_run = res.clone().into_task_run(&task.name, arm);
                                    task_run.validation_passed = validated;
                                    let contention_detected = resource_report
                                        .as_ref()
                                        .and_then(|rr| rr.pre_run_health.as_ref())
                                        .map(|h| !h.clean)
                                        .unwrap_or(false);
                                    report.arms.push(kin_bench::live::ArmResult {
                                        arm,
                                        task_name: task.name.clone(),
                                        cli_name: cli.name.clone(),
                                        run: task_run,
                                        resource_report,
                                        transcript_path,
                                        step_trace_path,
                                        shim_log_path,
                                        step_summary,
                                        tool_usage,
                                        shim_log_summary,
                                        step_trace_entries,
                                        contention_detected,
                                    });
                                }
                                Err(e) => {
                                    println!("  ERROR: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            let _resource_report = monitor.map(|m| m.stop());
                            println!("  ERROR: {}", e);
                        }
                    }
                }
            }
        }
    }

    // 8. Finalize report
    report.finish();

    println!();
    print!("{}", kin_bench::live::format_summary(&report));

    // 9. Save report
    std::fs::create_dir_all(&save_dir)?;
    let report_file = save_dir.join(format!("live-{run_id}.json"));
    std::fs::write(&report_file, report.to_json()?)?;
    println!("Report saved to: {}", report_file.display());

    // 10. Cleanup workspace to free disk space
    if !keep_workspace {
        println!("Cleaning up workspace...");
        if let Err(e) = workspace.cleanup() {
            eprintln!("Warning: workspace cleanup failed: {e}");
        }
    } else {
        println!("Workspace kept at: {}", workspace.root.display());
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Standalone scale benchmarks (no .kin/ required)
// ---------------------------------------------------------------------------

pub async fn graph_scale(entity_count: usize, json: bool) -> Result<()> {
    use std::collections::HashMap;
    use std::time::Instant;
    use kin_model::GraphStore;

    let rels_per_entity = 5;

    if !json {
        println!(
            "Generating synthetic graph: {} entities, {} relations/entity...",
            entity_count, rels_per_entity
        );
    }

    // Generate synthetic graph using snapshot hydration (same approach as kin-db/benches/scale_bench.rs)
    let gen_start = Instant::now();

    let mut entities = HashMap::with_capacity(entity_count);
    let mut entity_ids = Vec::with_capacity(entity_count);

    let fp = kin_model::SemanticFingerprint {
        ast_hash: kin_model::Hash256::from_bytes([0; 32]),
        signature_hash: kin_model::Hash256::from_bytes([0; 32]),
        behavior_hash: kin_model::Hash256::from_bytes([0; 32]),
        algorithm: kin_model::FingerprintAlgorithm::V1TreeSitter,
        stability_score: 1.0,
    };

    for i in 0..entity_count {
        let id = kin_model::EntityId::new();
        entities.insert(
            id,
            kin_model::Entity {
                id,
                kind: match i % 5 {
                    0 => kin_model::EntityKind::Function,
                    1 => kin_model::EntityKind::Class,
                    2 => kin_model::EntityKind::Method,
                    3 => kin_model::EntityKind::Interface,
                    _ => kin_model::EntityKind::Module,
                },
                name: format!("entity_{i}"),
                language: kin_model::LanguageId::Rust,
                fingerprint: fp.clone(),
                file_origin: Some(kin_model::FilePathId::new(format!(
                    "src/mod_{}.rs",
                    i / 50
                ))),
                span: Some(kin_model::SourceSpan {
                    file: kin_model::FilePathId::new(format!("src/mod_{}.rs", i / 50)),
                    start_byte: (i % 50) * 200,
                    end_byte: (i % 50) * 200 + 180,
                    start_line: (i % 50) as u32 * 10,
                    start_col: 0,
                    end_line: (i % 50) as u32 * 10 + 9,
                    end_col: 0,
                }),
                signature: format!("fn entity_{i}() -> Result<()>"),
                visibility: kin_model::Visibility::Public,
                doc_summary: None,
                metadata: kin_model::EntityMetadata::default(),
                lineage_parent: None,
                created_in: None,
                superseded_by: None,
            },
        );
        entity_ids.push(id);
    }

    let mut relations = HashMap::with_capacity(entity_count * rels_per_entity);
    let mut outgoing: HashMap<kin_model::EntityId, Vec<kin_model::RelationId>> =
        HashMap::with_capacity(entity_count);
    let mut incoming: HashMap<kin_model::EntityId, Vec<kin_model::RelationId>> =
        HashMap::with_capacity(entity_count);

    for (i, src_id) in entity_ids.iter().enumerate() {
        for r in 0..rels_per_entity {
            let dst_idx = (i * 7 + r * 13 + 1) % entity_count;
            if dst_idx == i {
                continue;
            }
            let rel_id = kin_model::RelationId::new();
            let dst_id = entity_ids[dst_idx];
            relations.insert(
                rel_id,
                kin_model::Relation {
                    id: rel_id,
                    kind: match r % 3 {
                        0 => kin_model::RelationKind::Calls,
                        1 => kin_model::RelationKind::Imports,
                        _ => kin_model::RelationKind::References,
                    },
                    src: *src_id,
                    dst: dst_id,
                    confidence: 1.0,
                    origin: kin_model::RelationOrigin::Parsed,
                    created_in: None,
                    import_source: None,
                },
            );
            outgoing.entry(*src_id).or_default().push(rel_id);
            incoming.entry(dst_id).or_default().push(rel_id);
        }
    }

    let relation_count = relations.len();

    let snapshot = kin_db::GraphSnapshot {
        version: kin_db::GraphSnapshot::CURRENT_VERSION,
        entities,
        relations,
        outgoing,
        incoming,
        changes: HashMap::new(),
        change_children: HashMap::new(),
        branches: HashMap::new(),
        work_items: HashMap::new(),
        annotations: HashMap::new(),
        work_links: Vec::new(),
        test_cases: HashMap::new(),
        assertions: HashMap::new(),
        verification_runs: HashMap::new(),
        test_covers_entity: Vec::new(),
        test_covers_contract: Vec::new(),
        test_verifies_work: Vec::new(),
        run_proves_entity: Vec::new(),
        run_proves_work: Vec::new(),
        mock_hints: Vec::new(),
        contracts: HashMap::new(),
        actors: HashMap::new(),
        delegations: Vec::new(),
        approvals: Vec::new(),
        audit_events: Vec::new(),
        shallow_files: Vec::new(),
        file_hashes: HashMap::new(),
        sessions: HashMap::new(),
        intents: HashMap::new(),
        downstream_warnings: Vec::new(),
    };

    let graph = kin_db::InMemoryGraph::from_snapshot(snapshot);
    let generation_ms = gen_start.elapsed().as_secs_f64() * 1000.0;

    // entity_lookup: 10,000 iterations
    let iterations = 10_000;
    let start = Instant::now();
    for i in 0..iterations {
        let id = &entity_ids[i % entity_ids.len()];
        let _ = graph.get_entity(id);
    }
    let entity_lookup_ms = start.elapsed().as_secs_f64() * 1000.0;
    let entity_lookup_per_op = entity_lookup_ms * 1000.0 / iterations as f64;

    // query_by_file: 1,000 iterations
    let file_iterations = 1_000;
    let filter = kin_model::graph::EntityFilter {
        file_path: Some(kin_model::FilePathId::new("src/mod_0.rs")),
        ..Default::default()
    };
    let start = Instant::now();
    for _ in 0..file_iterations {
        let _ = graph.query_entities(&filter);
    }
    let query_by_file_ms = start.elapsed().as_secs_f64() * 1000.0;
    let query_by_file_per_op = query_by_file_ms * 1000.0 / file_iterations as f64;

    // bfs_neighborhood (depth 3): 100 iterations
    let bfs_iterations = 100;
    let start = Instant::now();
    for i in 0..bfs_iterations {
        let id = &entity_ids[i % entity_ids.len()];
        let _ = graph.get_dependency_neighborhood(id, 3);
    }
    let bfs_ms = start.elapsed().as_secs_f64() * 1000.0;
    let bfs_per_op = bfs_ms * 1000.0 / bfs_iterations as f64;

    // downstream_impact (depth 5): 100 iterations
    let impact_iterations = 100;
    let start = Instant::now();
    for i in 0..impact_iterations {
        let id = &entity_ids[i % entity_ids.len()];
        let _ = graph.get_downstream_impact(id, 5);
    }
    let impact_ms = start.elapsed().as_secs_f64() * 1000.0;
    let impact_per_op = impact_ms * 1000.0 / impact_iterations as f64;

    // dead_code_detection
    let start = Instant::now();
    let dead = graph.find_dead_code().unwrap_or_default();
    let dead_code_ms = start.elapsed().as_secs_f64() * 1000.0;
    let dead_entities = dead.len();

    // serialization
    let start = Instant::now();
    let snap = graph.to_snapshot();
    let bytes = snap
        .to_bytes()
        .map_err(|e| anyhow::anyhow!("serialization failed: {}", e))?;
    let ser_ms = start.elapsed().as_secs_f64() * 1000.0;
    let ser_bytes = bytes.len();

    // deserialization
    let start = Instant::now();
    let _loaded = kin_db::GraphSnapshot::from_bytes(&bytes)
        .map_err(|e| anyhow::anyhow!("deserialization failed: {}", e))?;
    let deser_ms = start.elapsed().as_secs_f64() * 1000.0;

    if json {
        let result = serde_json::json!({
            "benchmark": "graph-scale",
            "entity_count": entity_count,
            "relation_count": relation_count,
            "results": {
                "generation_ms": (generation_ms * 100.0).round() / 100.0,
                "entity_lookup": {
                    "ops": iterations,
                    "total_ms": (entity_lookup_ms * 100.0).round() / 100.0,
                    "per_op_us": (entity_lookup_per_op * 100.0).round() / 100.0,
                },
                "query_by_file": {
                    "ops": file_iterations,
                    "total_ms": (query_by_file_ms * 100.0).round() / 100.0,
                    "per_op_us": (query_by_file_per_op * 100.0).round() / 100.0,
                },
                "bfs_neighborhood": {
                    "ops": bfs_iterations,
                    "total_ms": (bfs_ms * 100.0).round() / 100.0,
                    "per_op_us": (bfs_per_op * 100.0).round() / 100.0,
                },
                "downstream_impact": {
                    "ops": impact_iterations,
                    "total_ms": (impact_ms * 100.0).round() / 100.0,
                    "per_op_us": (impact_per_op * 100.0).round() / 100.0,
                },
                "dead_code_detection": {
                    "total_ms": (dead_code_ms * 100.0).round() / 100.0,
                    "dead_entities": dead_entities,
                },
                "serialization": {
                    "total_ms": (ser_ms * 100.0).round() / 100.0,
                    "bytes": ser_bytes,
                },
                "deserialization": {
                    "total_ms": (deser_ms * 100.0).round() / 100.0,
                    "bytes": ser_bytes,
                },
            }
        });
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!(
            "\nGraph Scale Benchmark: {} entities, {} relations",
            entity_count, relation_count
        );
        println!("{:-<60}", "");
        println!(
            "  Generation:         {:.1}ms",
            generation_ms
        );
        println!(
            "  Entity lookup:      {:.1}ms total ({} ops, {:.1}us/op)",
            entity_lookup_ms, iterations, entity_lookup_per_op
        );
        println!(
            "  Query by file:      {:.1}ms total ({} ops, {:.1}us/op)",
            query_by_file_ms, file_iterations, query_by_file_per_op
        );
        println!(
            "  BFS neighborhood:   {:.1}ms total ({} ops, {:.1}us/op)",
            bfs_ms, bfs_iterations, bfs_per_op
        );
        println!(
            "  Downstream impact:  {:.1}ms total ({} ops, {:.1}us/op)",
            impact_ms, impact_iterations, impact_per_op
        );
        println!(
            "  Dead code detect:   {:.1}ms ({} dead entities)",
            dead_code_ms, dead_entities
        );
        println!(
            "  Serialization:      {:.1}ms ({:.1} MB)",
            ser_ms,
            ser_bytes as f64 / 1_048_576.0
        );
        println!(
            "  Deserialization:    {:.1}ms ({:.1} MB)",
            deser_ms,
            ser_bytes as f64 / 1_048_576.0
        );
    }

    Ok(())
}

pub async fn spine_scale(repo_count: usize, json: bool) -> Result<()> {
    use kin_bench::spine_throughput::SpineScale;

    let scale = match repo_count {
        0..=25 => SpineScale::Small,
        26..=150 => SpineScale::Medium,
        151..=350 => SpineScale::Large,
        _ => SpineScale::ExtraLarge,
    };

    let entities_per_repo = scale.entities_per_repo();

    if !json {
        println!(
            "Running spine federation benchmark: {} repos, {} entities/repo...",
            scale.repo_count(),
            entities_per_repo
        );
    }

    let iterations = 1000;
    let result = kin_bench::bench_spine_at_scale(scale, iterations);

    if json {
        let memory_bytes = result
            .memory_after_load
            .as_ref()
            .map(|m| m.rss_delta_kb.max(0) as u64 * 1024)
            .unwrap_or(0);

        let mut results = serde_json::Map::new();

        // Helper to convert ThroughputMetric + optional LatencyPercentiles to JSON
        let add_metric = |map: &mut serde_json::Map<String, serde_json::Value>,
                          name: &str,
                          metric: &kin_bench::ThroughputMetric,
                          latency: Option<&kin_bench::LatencyPercentiles>| {
            let mut entry = serde_json::Map::new();
            entry.insert(
                "ops_per_sec".into(),
                serde_json::json!((metric.ops_per_sec * 100.0).round() / 100.0),
            );
            if let Some(lat) = latency {
                entry.insert(
                    "p50_us".into(),
                    serde_json::json!((lat.p50 * 1000.0 * 100.0).round() / 100.0),
                );
                entry.insert(
                    "p90_us".into(),
                    serde_json::json!((lat.p90 * 1000.0 * 100.0).round() / 100.0),
                );
                entry.insert(
                    "p99_us".into(),
                    serde_json::json!((lat.p99 * 1000.0 * 100.0).round() / 100.0),
                );
            }
            map.insert(name.into(), serde_json::Value::Object(entry));
        };

        add_metric(
            &mut results,
            "registration",
            &result.registration,
            result.registration_latency.as_ref(),
        );
        add_metric(
            &mut results,
            "resolve_by_name",
            &result.resolve_by_name,
            result.resolve_latency.as_ref(),
        );
        add_metric(
            &mut results,
            "resolve_with_fingerprint",
            &result.resolve_with_fingerprint,
            None,
        );
        add_metric(&mut results, "edge_lookup", &result.edge_lookup, None);
        add_metric(
            &mut results,
            "federated_bfs",
            &result.federated_bfs,
            result.bfs_latency.as_ref(),
        );
        add_metric(
            &mut results,
            "routing_lookup",
            &result.routing_lookup,
            None,
        );

        let output = serde_json::json!({
            "benchmark": "spine-scale",
            "repo_count": result.repo_count,
            "entities_per_repo": entities_per_repo,
            "total_entities": result.total_entities,
            "results": results,
            "memory_after_load_bytes": memory_bytes,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!(
            "\nSpine Federation Benchmark: {} repos, {} total entities, {} edges",
            result.repo_count, result.total_entities, result.total_edges
        );
        println!("{:-<70}", "");
        println!(
            "  {:30} {:>12} {:>10} {:>10} {:>10}",
            "Operation", "ops/sec", "p50 (us)", "p90 (us)", "p99 (us)"
        );
        println!("{:-<70}", "");

        let print_row = |name: &str,
                         metric: &kin_bench::ThroughputMetric,
                         latency: Option<&kin_bench::LatencyPercentiles>| {
            if let Some(lat) = latency {
                println!(
                    "  {:30} {:>12.0} {:>10.1} {:>10.1} {:>10.1}",
                    name,
                    metric.ops_per_sec,
                    lat.p50 * 1000.0,
                    lat.p90 * 1000.0,
                    lat.p99 * 1000.0,
                );
            } else {
                println!(
                    "  {:30} {:>12.0} {:>10} {:>10} {:>10}",
                    name, metric.ops_per_sec, "-", "-", "-"
                );
            }
        };

        print_row(
            "registration",
            &result.registration,
            result.registration_latency.as_ref(),
        );
        print_row(
            "resolve_by_name",
            &result.resolve_by_name,
            result.resolve_latency.as_ref(),
        );
        print_row(
            "resolve_with_fingerprint",
            &result.resolve_with_fingerprint,
            None,
        );
        print_row("edge_lookup", &result.edge_lookup, None);
        print_row(
            "federated_bfs",
            &result.federated_bfs,
            result.bfs_latency.as_ref(),
        );
        print_row("routing_lookup", &result.routing_lookup, None);

        if let Some(ref mem) = result.memory_after_load {
            println!(
                "\n  Memory delta: {:.1} MB",
                mem.rss_delta_kb.max(0) as f64 / 1024.0
            );
        }
    }

    Ok(())
}

pub async fn parser_throughput(languages: String, path: Option<String>, json: bool) -> Result<()> {
    use std::time::Instant;

    let scan_root = match path {
        Some(ref p) => std::path::PathBuf::from(p),
        None => std::env::current_dir()?,
    };

    let registry = kin_parser::AdapterRegistry::new();

    // Determine which languages to benchmark
    let all_languages = registry.supported_languages();
    let requested: Vec<kin_model::LanguageId> = if languages == "all" {
        all_languages
    } else {
        languages
            .split(',')
            .filter_map(|s| {
                let s = s.trim().to_lowercase();
                all_languages.iter().find(|l| l.to_string() == s).copied()
            })
            .collect()
    };

    if !json {
        println!("Scanning {} for source files...", scan_root.display());
    }

    // Collect files by language
    let mut lang_results: Vec<(String, serde_json::Value)> = Vec::new();
    let mut total_files = 0usize;
    let mut total_lines = 0usize;
    let mut total_time_ms = 0.0f64;
    let mut total_entities = 0usize;

    for lang_id in &requested {
        let adapter = match registry.get_by_language(*lang_id) {
            Some(a) => a,
            None => continue,
        };

        let extensions = adapter.file_extensions();

        // Walk directory and collect matching files
        let mut files: Vec<std::path::PathBuf> = Vec::new();
        collect_source_files(&scan_root, extensions, &mut files);

        if files.is_empty() {
            continue;
        }

        let file_count = files.len();
        let mut line_count = 0usize;
        let mut entity_count = 0usize;

        let start = Instant::now();
        for file_path in &files {
            let source = match std::fs::read(file_path) {
                Ok(s) => s,
                Err(_) => continue,
            };
            line_count += source.iter().filter(|&&b| b == b'\n').count() + 1;

            if let Ok(tree) = adapter.parse(&source) {
                let file_id = kin_model::FilePathId::new(
                    file_path
                        .strip_prefix(&scan_root)
                        .unwrap_or(file_path)
                        .to_string_lossy()
                        .to_string(),
                );
                if let Ok(output) = adapter.extract(&tree, &source, &file_id) {
                    entity_count += output.entities.len();
                }
            }
        }
        let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;

        let lines_per_sec = if elapsed_ms > 0.0 {
            (line_count as f64 / (elapsed_ms / 1000.0)).round() as u64
        } else {
            0
        };
        let entities_per_sec = if elapsed_ms > 0.0 {
            (entity_count as f64 / (elapsed_ms / 1000.0)).round() as u64
        } else {
            0
        };

        lang_results.push((
            lang_id.to_string(),
            serde_json::json!({
                "files": file_count,
                "lines": line_count,
                "time_ms": (elapsed_ms * 100.0).round() / 100.0,
                "lines_per_sec": lines_per_sec,
                "entities": entity_count,
                "entities_per_sec": entities_per_sec,
            }),
        ));

        total_files += file_count;
        total_lines += line_count;
        total_time_ms += elapsed_ms;
        total_entities += entity_count;
    }

    if json {
        let mut languages_map = serde_json::Map::new();
        for (lang, data) in &lang_results {
            languages_map.insert(lang.clone(), data.clone());
        }

        let total_lines_per_sec = if total_time_ms > 0.0 {
            (total_lines as f64 / (total_time_ms / 1000.0)).round() as u64
        } else {
            0
        };

        let output = serde_json::json!({
            "benchmark": "parser-throughput",
            "languages": languages_map,
            "totals": {
                "files": total_files,
                "lines": total_lines,
                "time_ms": (total_time_ms * 100.0).round() / 100.0,
                "lines_per_sec": total_lines_per_sec,
                "entities": total_entities,
            }
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        if lang_results.is_empty() {
            println!("No source files found for the requested languages.");
            return Ok(());
        }

        println!("\nParser Throughput Benchmark");
        println!("{:-<80}", "");
        println!(
            "  {:15} {:>8} {:>10} {:>10} {:>12} {:>10} {:>12}",
            "Language", "Files", "Lines", "Time(ms)", "Lines/sec", "Entities", "Ent/sec"
        );
        println!("{:-<80}", "");

        for (lang, data) in &lang_results {
            println!(
                "  {:15} {:>8} {:>10} {:>10.1} {:>12} {:>10} {:>12}",
                lang,
                data["files"],
                data["lines"],
                data["time_ms"].as_f64().unwrap_or(0.0),
                data["lines_per_sec"],
                data["entities"],
                data["entities_per_sec"],
            );
        }

        let total_lines_per_sec = if total_time_ms > 0.0 {
            (total_lines as f64 / (total_time_ms / 1000.0)).round() as u64
        } else {
            0
        };
        println!("{:-<80}", "");
        println!(
            "  {:15} {:>8} {:>10} {:>10.1} {:>12} {:>10}",
            "TOTAL", total_files, total_lines, total_time_ms, total_lines_per_sec, total_entities
        );
    }

    Ok(())
}

/// Recursively collect source files with matching extensions.
fn collect_source_files(
    dir: &std::path::Path,
    extensions: &[&str],
    files: &mut Vec<std::path::PathBuf>,
) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            // Skip hidden dirs and common non-source dirs
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name.starts_with('.')
                || name == "node_modules"
                || name == "target"
                || name == "vendor"
                || name == "build"
                || name == "__pycache__"
            {
                continue;
            }
            collect_source_files(&path, extensions, files);
        } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if extensions.contains(&ext) {
                files.push(path);
            }
        }
    }
}

#[cfg(test)]
fn repo_display_name(repo_source: &str) -> String {
    let trimmed = repo_source.trim_end_matches('/');
    let candidate = trimmed
        .rsplit(['/', ':'])
        .next()
        .filter(|segment| !segment.is_empty())
        .unwrap_or(trimmed);
    candidate.trim_end_matches(".git").to_string()
}

fn benchmark_timeout(arm: kin_bench::BenchmarkArm) -> Duration {
    match arm {
        // Native-style arms should resolve quickly; anything beyond this is
        // usually an MCP/tool-use spiral rather than legitimate work.
        kin_bench::BenchmarkArm::KinNative
        | kin_bench::BenchmarkArm::KinNativeCli
        | kin_bench::BenchmarkArm::KinPilotNative => Duration::from_secs(180),
        // Git and compat can legitimately take much longer on large repos, but
        // still need a hard stop so one hung CLI doesn't stall the whole suite.
        kin_bench::BenchmarkArm::Git | kin_bench::BenchmarkArm::KinCompat => {
            Duration::from_secs(600)
        }
    }
}

fn apply_cost_attribution(
    summary: &mut kin_bench::live::StepTraceSummary,
    run_total_tokens: u64,
    run_total_cost_usd: f64,
) {
    if run_total_tokens == 0 || run_total_cost_usd <= 0.0 {
        return;
    }

    let grand_total = summary.main_agent_total_tokens + summary.subagent_total_tokens;
    if grand_total == 0 {
        return;
    }

    let scale = run_total_cost_usd / run_total_tokens as f64;
    summary.main_agent_cost_usd = summary.main_agent_total_tokens as f64 * scale;
    summary.subagent_total_cost_usd = summary.subagent_total_tokens as f64 * scale;
    summary.unattributed_total_tokens = run_total_tokens.saturating_sub(grand_total);
    summary.unattributed_cost_usd = summary.unattributed_total_tokens as f64 * scale;
    for subagent in &mut summary.subagents {
        subagent.estimated_cost_usd = subagent.total_tokens as f64 * scale;
    }
}

#[cfg(test)]
mod tests {
    use super::{
        apply_cost_attribution, benchmark_timeout, load_assistant_runs, normalize_benchmark_name,
        parse_arm_filter, repo_display_name,
    };
    use kin_bench::metrics::AssistantRunSource;
    use kin_bench::{AssistantTaskRun, BenchmarkArm, BenchmarkSubstrate, DurationMs};
    use std::time::Duration;

    #[test]
    fn load_assistant_runs_accepts_single_object_and_array() {
        let dir = tempfile::tempdir().unwrap();
        let one = dir.path().join("one.json");
        let many = dir.path().join("many.json");

        let run = AssistantTaskRun {
            task_name: "compare".into(),
            assistant_name: "Claude Code".into(),
            model_name: Some("opus".into()),
            substrate: BenchmarkSubstrate::Kin,
            duration_ms: DurationMs(1200.0),
            input_tokens: 700,
            output_tokens: 300,
            total_tokens: 1000,
            estimated_cost_usd: 0.08,
            first_pass_success: true,
            validation_passed: true,
            run_source: AssistantRunSource::ArtifactImport,
            notes: None,
            recorded_at: chrono::Utc::now(),
        };

        std::fs::write(&one, serde_json::to_string(&run).unwrap()).unwrap();
        std::fs::write(
            &many,
            serde_json::to_string(&vec![run.clone(), run.clone()]).unwrap(),
        )
        .unwrap();

        let loaded =
            load_assistant_runs(&[one.display().to_string(), many.display().to_string()]).unwrap();

        assert_eq!(loaded.len(), 3);
        assert_eq!(loaded[0].assistant_name, "Claude Code");
    }

    #[test]
    fn apply_cost_attribution_scales_to_real_run_cost() {
        let mut summary = kin_bench::live::StepTraceSummary {
            total_steps: 0,
            command_steps: 0,
            mcp_steps: 0,
            subagent_steps: 1,
            agent_message_steps: 0,
            failed_steps: 0,
            total_output_chars: 0,
            total_output_tokens_est: 0,
            has_precise_timing: false,
            top_by_duration: vec![],
            top_by_output: vec![],
            subagents: vec![kin_bench::live::SubagentTraceSummary {
                item_id: Some("agent_1".into()),
                label: "Subagent Explore".into(),
                duration_ms: None,
                child_steps: 0,
                child_command_steps: 0,
                child_mcp_steps: 0,
                child_output_chars: 0,
                child_output_tokens_est: 0,
                input_tokens: 0,
                output_tokens: 0,
                total_tokens: 300,
                estimated_cost_usd: 0.0,
            }],
            main_agent_input_tokens: 0,
            main_agent_output_tokens: 0,
            main_agent_total_tokens: 700,
            main_agent_cost_usd: 0.0,
            subagent_total_input_tokens: 0,
            subagent_total_output_tokens: 0,
            subagent_total_tokens: 300,
            subagent_total_cost_usd: 0.0,
            unattributed_total_tokens: 0,
            unattributed_cost_usd: 0.0,
        };

        apply_cost_attribution(&mut summary, 1000, 0.50);

        assert!((summary.main_agent_cost_usd - 0.35).abs() < 1e-9);
        assert!((summary.subagent_total_cost_usd - 0.15).abs() < 1e-9);
        assert!((summary.subagents[0].estimated_cost_usd - 0.15).abs() < 1e-9);
        assert_eq!(summary.unattributed_total_tokens, 0);
        assert!((summary.unattributed_cost_usd - 0.0).abs() < 1e-9);
    }

    #[test]
    fn repo_display_name_uses_real_repo_basename() {
        assert_eq!(repo_display_name("/tmp/bench-repos/fastapi"), "fastapi");
        assert_eq!(
            repo_display_name("https://github.com/colinhacks/zod.git"),
            "zod"
        );
        assert_eq!(
            repo_display_name("git@github.com:pallets/flask.git"),
            "flask"
        );
    }

    #[test]
    fn normalize_benchmark_name_handles_case_spacing_and_underscores() {
        assert_eq!(normalize_benchmark_name("Find Dead Code"), "find-dead-code");
        assert_eq!(normalize_benchmark_name("kin_native_cli"), "kin-native-cli");
    }

    #[test]
    fn parse_arm_filter_accepts_cli_spellings() {
        assert_eq!(parse_arm_filter("git"), Some(BenchmarkArm::Git));
        assert_eq!(
            parse_arm_filter("kin_native_cli"),
            Some(BenchmarkArm::KinNativeCli)
        );
        assert_eq!(
            parse_arm_filter("Kin Pilot Native"),
            Some(BenchmarkArm::KinPilotNative)
        );
        assert_eq!(parse_arm_filter("unknown"), None);
    }

    #[test]
    fn benchmark_timeout_applies_to_all_arms() {
        assert_eq!(
            benchmark_timeout(BenchmarkArm::Git),
            Duration::from_secs(600)
        );
        assert_eq!(
            benchmark_timeout(BenchmarkArm::KinCompat),
            Duration::from_secs(600)
        );
        assert_eq!(
            benchmark_timeout(BenchmarkArm::KinNative),
            Duration::from_secs(180)
        );
        assert_eq!(
            benchmark_timeout(BenchmarkArm::KinNativeCli),
            Duration::from_secs(180)
        );
        assert_eq!(
            benchmark_timeout(BenchmarkArm::KinPilotNative),
            Duration::from_secs(180)
        );
    }
}
