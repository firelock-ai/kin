use anyhow::Result;

pub async fn run() -> Result<()> {
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

    // Print summary
    print!("{}", report.summary());

    // Save report to .kin/bench/
    let bench_dir = layout.bench_dir();
    std::fs::create_dir_all(&bench_dir)?;
    let report_file = bench_dir.join(format!("bench-{}.json", chrono::Utc::now().format("%Y%m%d-%H%M%S")));
    let json = report.to_json()?;
    std::fs::write(&report_file, &json)?;
    println!("Report saved to: {}", report_file.display());

    Ok(())
}
