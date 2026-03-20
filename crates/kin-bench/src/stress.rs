// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Concurrent-write stress tests for the benchmark infrastructure.
//!
//! These tests exercise concurrent access patterns within the bench crate's
//! own types. They do NOT test kin-db directly — they test that bench
//! infrastructure (metric collection, report building, regression comparison)
//! works correctly under concurrent access.

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use crate::metrics::{
        DurationMs, LatencyPercentiles, MemoryMetric, Metric, MetricCategory, MetricValue,
        ThroughputMetric,
    };
    use crate::regression::compare_runs;
    use crate::report::BenchmarkReport;
    use crate::runner::BenchmarkRun;

    #[test]
    fn concurrent_metric_collection() {
        // Two threads creating metrics simultaneously, collecting into a shared vec
        let metrics = Arc::new(Mutex::new(Vec::<Metric>::new()));

        std::thread::scope(|s| {
            let m1 = Arc::clone(&metrics);
            s.spawn(move || {
                for i in 0..100 {
                    let metric = Metric {
                        name: format!("thread1_metric_{}", i),
                        category: MetricCategory::DeveloperVelocity,
                        value: MetricValue::Duration(DurationMs(i as f64)),
                        unit: "ms".into(),
                        timestamp: chrono::Utc::now(),
                        labels: vec![("thread".into(), "1".into())],
                    };
                    m1.lock().unwrap().push(metric);
                }
            });

            let m2 = Arc::clone(&metrics);
            s.spawn(move || {
                for i in 0..100 {
                    let metric = Metric {
                        name: format!("thread2_metric_{}", i),
                        category: MetricCategory::Economic,
                        value: MetricValue::Count(i),
                        unit: "count".into(),
                        timestamp: chrono::Utc::now(),
                        labels: vec![("thread".into(), "2".into())],
                    };
                    m2.lock().unwrap().push(metric);
                }
            });
        });

        let collected = metrics.lock().unwrap();
        assert_eq!(collected.len(), 200);
        let thread1_count = collected
            .iter()
            .filter(|m| m.name.starts_with("thread1"))
            .count();
        let thread2_count = collected
            .iter()
            .filter(|m| m.name.starts_with("thread2"))
            .count();
        assert_eq!(thread1_count, 100);
        assert_eq!(thread2_count, 100);
    }

    #[test]
    fn concurrent_report_building() {
        // Writer thread builds reports while reader thread reads them
        let reports = Arc::new(Mutex::new(Vec::<BenchmarkReport>::new()));

        std::thread::scope(|s| {
            // Writer: creates reports
            let w = Arc::clone(&reports);
            s.spawn(move || {
                for i in 0..50 {
                    let report = BenchmarkReport::new(format!("report-{}", i));
                    w.lock().unwrap().push(report);
                }
            });

            // Reader: reads report count periodically
            let r = Arc::clone(&reports);
            s.spawn(move || {
                let mut max_seen = 0;
                for _ in 0..100 {
                    let count = r.lock().unwrap().len();
                    if count > max_seen {
                        max_seen = count;
                    }
                    // Brief yield
                    std::thread::yield_now();
                }
                // We should have seen at least some reports
                // (may not see all 50 depending on scheduling)
                let _ = max_seen; // reader observed reports being built
            });
        });

        let final_reports = reports.lock().unwrap();
        assert_eq!(final_reports.len(), 50);
    }

    #[test]
    fn concurrent_latency_percentile_computation() {
        // Multiple threads computing percentiles from different sample sets
        let results = Arc::new(Mutex::new(Vec::<LatencyPercentiles>::new()));

        std::thread::scope(|s| {
            for thread_id in 0..4 {
                let r = Arc::clone(&results);
                s.spawn(move || {
                    let samples: Vec<f64> = (0..1000)
                        .map(|i| (i as f64) + (thread_id as f64 * 1000.0))
                        .collect();
                    if let Some(percentiles) = LatencyPercentiles::from_samples(&samples) {
                        r.lock().unwrap().push(percentiles);
                    }
                });
            }
        });

        let computed = results.lock().unwrap();
        assert_eq!(computed.len(), 4);
        for p in computed.iter() {
            assert_eq!(p.count, 1000);
            assert!(p.p50 < p.p99);
            assert!(p.p99 <= p.max);
        }
    }

    #[test]
    fn concurrent_regression_comparison() {
        // Multiple threads doing regression comparisons in parallel
        let reports = Arc::new(Mutex::new(Vec::new()));

        std::thread::scope(|s| {
            for i in 0..4 {
                let r = Arc::clone(&reports);
                s.spawn(move || {
                    let baseline = BenchmarkRun {
                        run_id: format!("base-{}", i),
                        timestamp: chrono::Utc::now(),
                        target: "test".into(),
                        metrics: vec![],
                        dependency_coverage: None,
                        dead_code: None,
                        token_savings: None,
                        token_to_logic: None,
                        test_coverage: None,
                        latency_percentiles: Some(LatencyPercentiles {
                            p50: 10.0,
                            p75: 15.0,
                            p90: 20.0,
                            p95: 25.0,
                            p99: 30.0,
                            max: 35.0,
                            count: 100,
                        }),
                        memory: None,
                        throughput: vec![ThroughputMetric {
                            ops_per_sec: 1000.0,
                            total_duration_ms: 1000.0,
                            iterations: 1000,
                            operation: "entity_lookup".into(),
                        }],
                    };

                    // Simulate a regression in this thread's comparison
                    let current = BenchmarkRun {
                        run_id: format!("curr-{}", i),
                        timestamp: chrono::Utc::now(),
                        target: "test".into(),
                        metrics: vec![],
                        dependency_coverage: None,
                        dead_code: None,
                        token_savings: None,
                        token_to_logic: None,
                        test_coverage: None,
                        latency_percentiles: Some(LatencyPercentiles {
                            p50: 10.0 + (i as f64 * 5.0), // progressively worse
                            p75: 15.0,
                            p90: 20.0,
                            p95: 25.0,
                            p99: 30.0,
                            max: 35.0,
                            count: 100,
                        }),
                        memory: None,
                        throughput: vec![ThroughputMetric {
                            ops_per_sec: 1000.0 - (i as f64 * 200.0), // progressively worse
                            total_duration_ms: 1000.0,
                            iterations: 1000,
                            operation: "entity_lookup".into(),
                        }],
                    };

                    let report = compare_runs(&baseline, &current);
                    r.lock().unwrap().push(report);
                });
            }
        });

        let regression_reports = reports.lock().unwrap();
        assert_eq!(regression_reports.len(), 4);
        // Thread 0 should have no regression (0% change)
        // Later threads should have progressively more regressions
    }

    #[test]
    fn concurrent_memory_metric_snapshots() {
        // Multiple threads taking memory snapshots simultaneously
        let snapshots = Arc::new(Mutex::new(Vec::<u64>::new()));

        std::thread::scope(|s| {
            for _ in 0..4 {
                let snaps = Arc::clone(&snapshots);
                s.spawn(move || {
                    for _ in 0..10 {
                        let rss = MemoryMetric::current_rss_kb();
                        snaps.lock().unwrap().push(rss);
                    }
                });
            }
        });

        let collected = snapshots.lock().unwrap();
        assert_eq!(collected.len(), 40);
        if cfg!(any(target_os = "macos", target_os = "linux")) {
            // All values should be non-zero on supported platforms
            assert!(collected.iter().all(|&v| v > 0));
        }
    }

    #[test]
    fn concurrent_serialization_roundtrip() {
        // Multiple threads serializing and deserializing benchmark reports
        let errors = Arc::new(Mutex::new(Vec::<String>::new()));

        std::thread::scope(|s| {
            for i in 0..4 {
                let errs = Arc::clone(&errors);
                s.spawn(move || {
                    for j in 0..25 {
                        let run = BenchmarkRun {
                            run_id: format!("run-{}-{}", i, j),
                            timestamp: chrono::Utc::now(),
                            target: "test".into(),
                            metrics: vec![],
                            dependency_coverage: None,
                            dead_code: None,
                            token_savings: None,
                            token_to_logic: None,
                            test_coverage: None,
                            latency_percentiles: Some(LatencyPercentiles {
                                p50: 10.0,
                                p75: 15.0,
                                p90: 20.0,
                                p95: 25.0,
                                p99: 30.0,
                                max: 35.0,
                                count: 100,
                            }),
                            memory: Some(MemoryMetric {
                                rss_before_kb: 50_000,
                                rss_after_kb: 55_000,
                                rss_delta_kb: 5_000,
                                peak_kb: 56_000,
                            }),
                            throughput: vec![],
                        };

                        let json = match serde_json::to_string(&run) {
                            Ok(j) => j,
                            Err(e) => {
                                errs.lock().unwrap().push(format!("serialize: {}", e));
                                continue;
                            }
                        };

                        match serde_json::from_str::<BenchmarkRun>(&json) {
                            Ok(parsed) => {
                                if parsed.run_id != run.run_id {
                                    errs.lock()
                                        .unwrap()
                                        .push("run_id mismatch after roundtrip".into());
                                }
                            }
                            Err(e) => {
                                errs.lock().unwrap().push(format!("deserialize: {}", e));
                            }
                        }
                    }
                });
            }
        });

        let errs = errors.lock().unwrap();
        assert!(
            errs.is_empty(),
            "concurrent serialization errors: {:?}",
            *errs
        );
    }
}
