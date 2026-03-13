use anyhow::Result;
use std::path::Path;

pub async fn run(assistant_run_paths: Vec<String>) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let graph = kin_graph::KuzuGraphStore::open_read_only(&layout.graph_dir())?;

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

pub async fn run_live(
    repo: Option<String>,
    task_prompts: Vec<String>,
    assistant_filter: Option<String>,
    exclude: Vec<String>,
    repeat: u32,
    no_monitor: bool,
    keep_workspace: bool,
    native_restrict_discovery: bool,
    native_restrict_filesystem: bool,
    fresh_conversion: bool,
    claude_disable_explore: bool,
    plugin_dir: Option<String>,
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
    let workspace =
        kin_bench::BenchWorkspace::setup_with_options(&repo_source, &kin_binary, fresh_conversion)
            .map_err(|e| anyhow::anyhow!("workspace setup failed: {e}"))?;

    let repo_name = workspace
        .kin_compat_dir
        .parent()
        .and_then(|p| p.file_name())
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

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
    let tasks: Vec<kin_bench::LiveTask> = if task_prompts.is_empty() {
        kin_bench::live::default_live_tasks()
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

    let mut arms = vec![
        kin_bench::BenchmarkArm::Git,
        kin_bench::BenchmarkArm::KinCompat,
        kin_bench::BenchmarkArm::KinNative,
    ];
    if workspace.kin_native_cli_dir.is_some() {
        arms.push(kin_bench::BenchmarkArm::KinNativeCli);
    }
    if workspace.kin_codex_native_dir.is_some() {
        arms.push(kin_bench::BenchmarkArm::KinCodexNative);
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
                            || arm == kin_bench::BenchmarkArm::KinCodexNative;
                        let native_strict =
                            is_native && (native_restrict_discovery || native_restrict_filesystem);

                        // In strict native benchmark modes, also disable Claude's Task
                        // subagent tool so filesystem/tool restrictions apply to the
                        // actual work instead of being sidestepped through Explore.
                        if claude_disable_explore || native_strict {
                            merge_claude_disallowed_tools(&mut env_vars, &["Task"]);
                        }
                        if is_native {
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
                        kin_bench::BenchmarkArm::KinCodexNative => {
                            // kin-codex has built-in Kin-first instructions — spawn directly
                            kin_bench::live::spawn_task("kin-codex", &injected_task, cwd, &env_refs)
                        }
                    };

                    match spawned {
                        Ok(spawned) => {
                            if let Some(ref monitor) = monitor {
                                monitor.track_pid(spawned.pid());
                            }
                            // Native arms get a hard timeout to prevent spiral runs.
                            // 180s is generous; anything beyond is a spiral.
                            let timeout = if matches!(
                                arm,
                                kin_bench::BenchmarkArm::KinNative
                                    | kin_bench::BenchmarkArm::KinNativeCli
                                    | kin_bench::BenchmarkArm::KinCodexNative
                            ) {
                                Some(std::time::Duration::from_secs(180))
                            } else {
                                None
                            };
                            let result = spawned.wait_with_timeout(timeout);
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
    use super::{apply_cost_attribution, load_assistant_runs};
    use kin_bench::metrics::AssistantRunSource;
    use kin_bench::{AssistantTaskRun, BenchmarkSubstrate, DurationMs};

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
}
