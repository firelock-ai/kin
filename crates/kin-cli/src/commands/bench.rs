use anyhow::Result;
use std::path::Path;

pub async fn run(assistant_run_paths: Vec<String>) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let graph = kin_graph::KuzuGraphStore::open(&layout.graph_dir())?;

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
        other => return Err(anyhow::anyhow!("unknown substrate '{}', expected 'git' or 'kin'", other)),
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
    println!("  Assistant: {} ({})", run.assistant_name, run.substrate.as_str());
    println!("  Task: {}", run.task_name);
    if let Some(ref m) = run.model_name {
        println!("  Model: {}", m);
    }
    println!("  Duration: {:.0}ms", run.duration_ms.0);
    println!("  Tokens: {} in / {} out / {} total", run.input_tokens, run.output_tokens, run.total_tokens);
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
        other => return Err(anyhow::anyhow!("unknown vendor '{}', expected claude, codex, or gemini", other)),
    };

    let bench_substrate = match substrate.as_deref().unwrap_or("kin").to_lowercase().as_str() {
        "git" => kin_bench::BenchmarkSubstrate::Git,
        "kin" => kin_bench::BenchmarkSubstrate::Kin,
        other => return Err(anyhow::anyhow!("unknown substrate '{}', expected 'git' or 'kin'", other)),
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
    println!("  Lines: +{} / -{}", artifact.lines_added, artifact.lines_removed);
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

#[cfg(test)]
mod tests {
    use super::load_assistant_runs;
    use kin_bench::{AssistantTaskRun, BenchmarkSubstrate, DurationMs};
    use kin_bench::metrics::AssistantRunSource;

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
}
