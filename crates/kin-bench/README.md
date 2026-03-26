# kin-bench

Benchmark engine for Kin.

## Overview

kin-bench is a comprehensive benchmarking framework for measuring Kin's performance across multiple dimensions. It supports live A/B benchmarks (kin-native vs. vanilla workflows), assistant run imports (Claude, GPT/Codex, Gemini), corpus-based evaluation, throughput measurement, regression detection, and dashboard reporting. It captures detailed step traces, resource usage, and per-task comparisons.

## Key Types

- **`BenchmarkRun`** / **`BenchOptions`** -- A benchmark run and its configuration.
- **`BenchmarkReport`** -- Summary report from a benchmark run.
- **`LiveBenchmarkReport`** / **`LiveRunResult`** -- Live A/B comparison results.
- **`BenchmarkArm`** / **`ArmResult`** / **`ArmComparison`** -- Arms of an A/B test with comparison.
- **`CorpusRunner`** / **`CorpusConfig`** / **`CorpusSummary`** -- Corpus-based benchmark runner.
- **`MetricCollector`** -- Collects metrics during a benchmark run.
- **`Metric`** / **`MetricValue`** / **`MetricCategory`** -- Typed metric system with categories.
- **`RegressionReport`** / **`RegressionItem`** -- Regression detection between runs.
- **`StepTrace`** / **`StepHotspot`** -- Per-step performance tracing.
- **`ResourceMonitor`** / **`ResourceReport`** -- System resource monitoring.
- **`BenchmarkProfile`** / **`ProfileConfig`** -- Named benchmark profiles.

## Metric Categories

- Latency, throughput, token savings, cost-per-task
- Context quality, review turnaround, risk detection accuracy
- Dead code accuracy, dependency coverage, CI/CD savings
- Memory usage, impact analysis time

## Usage

```bash
# Run benchmarks via CLI
kin benchmark run --profile default

# Run via MCP tool
# tool: benchmark
```

## Testing

```bash
cargo test -p kin-bench
```

## License

Apache-2.0 -- Copyright 2026 Firelock, LLC
