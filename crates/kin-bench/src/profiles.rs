// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Firelock, LLC

//! Benchmark profiles that select different repo subsets and metric levels.

use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::corpus::{CorpusManifest, CorpusTier};

/// Benchmark profile — determines which repos, metrics, and timeout to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BenchmarkProfile {
    /// 3 small repos, basic metrics, <2 min
    Quick,
    /// 10 mixed repos, all metrics, ~10 min
    Standard,
    /// 25+ repos, all metrics + memory, ~30 min
    Full,
    /// XL repos + concurrent operations, ~60 min
    Stress,
}

impl BenchmarkProfile {
    pub fn as_str(&self) -> &'static str {
        match self {
            BenchmarkProfile::Quick => "quick",
            BenchmarkProfile::Standard => "standard",
            BenchmarkProfile::Full => "full",
            BenchmarkProfile::Stress => "stress",
        }
    }

    /// Parse a profile name (case-insensitive).
    pub fn from_str_name(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "quick" => Some(Self::Quick),
            "standard" => Some(Self::Standard),
            "full" => Some(Self::Full),
            "stress" => Some(Self::Stress),
            _ => None,
        }
    }

    /// Maximum time allowed per repo for this profile.
    pub fn timeout_per_repo(&self) -> Duration {
        match self {
            BenchmarkProfile::Quick => Duration::from_secs(30),
            BenchmarkProfile::Standard => Duration::from_secs(60),
            BenchmarkProfile::Full => Duration::from_secs(120),
            BenchmarkProfile::Stress => Duration::from_secs(300),
        }
    }

    /// Whether memory profiling is enabled for this profile.
    pub fn collect_memory(&self) -> bool {
        matches!(self, BenchmarkProfile::Full | BenchmarkProfile::Stress)
    }

    /// Whether throughput benchmarks are enabled for this profile.
    pub fn collect_throughput(&self) -> bool {
        !matches!(self, BenchmarkProfile::Quick)
    }

    /// Whether latency percentiles are collected.
    pub fn collect_latency_percentiles(&self) -> bool {
        true // always collected
    }

    /// Number of throughput iterations per operation.
    pub fn throughput_iterations(&self) -> usize {
        match self {
            BenchmarkProfile::Quick => 100,
            BenchmarkProfile::Standard => 500,
            BenchmarkProfile::Full => 1000,
            BenchmarkProfile::Stress => 5000,
        }
    }

    /// Whether concurrent stress tests are included.
    pub fn run_stress_tests(&self) -> bool {
        matches!(self, BenchmarkProfile::Stress)
    }
}

impl std::fmt::Display for BenchmarkProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Configuration generated from a profile — specifies exactly which repos and
/// metrics to use for a benchmark run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileConfig {
    pub profile: BenchmarkProfile,
    /// Names of repos to include from the corpus manifest.
    pub repo_names: Vec<String>,
    pub collect_memory: bool,
    pub collect_throughput: bool,
    pub collect_latency_percentiles: bool,
    pub throughput_iterations: usize,
    pub run_stress_tests: bool,
    pub timeout_per_repo_secs: u64,
}

impl ProfileConfig {
    /// Build a profile config by selecting repos from the default corpus manifest.
    pub fn from_profile(profile: BenchmarkProfile) -> Self {
        let manifest = CorpusManifest::default_manifest();
        let repo_names = select_repos_for_profile(profile, &manifest);

        Self {
            profile,
            repo_names,
            collect_memory: profile.collect_memory(),
            collect_throughput: profile.collect_throughput(),
            collect_latency_percentiles: profile.collect_latency_percentiles(),
            throughput_iterations: profile.throughput_iterations(),
            run_stress_tests: profile.run_stress_tests(),
            timeout_per_repo_secs: profile.timeout_per_repo().as_secs(),
        }
    }
}

/// Select repo names from the manifest based on the profile.
fn select_repos_for_profile(profile: BenchmarkProfile, manifest: &CorpusManifest) -> Vec<String> {
    match profile {
        BenchmarkProfile::Quick => {
            // 3 small repos
            manifest
                .by_tier(CorpusTier::Small)
                .into_iter()
                .take(3)
                .map(|e| e.name.clone())
                .collect()
        }
        BenchmarkProfile::Standard => {
            // 10 mixed: 3 small + 4 medium + 3 large
            let mut names = Vec::new();
            names.extend(
                manifest
                    .by_tier(CorpusTier::Small)
                    .into_iter()
                    .take(3)
                    .map(|e| e.name.clone()),
            );
            names.extend(
                manifest
                    .by_tier(CorpusTier::Medium)
                    .into_iter()
                    .take(4)
                    .map(|e| e.name.clone()),
            );
            names.extend(
                manifest
                    .by_tier(CorpusTier::Large)
                    .into_iter()
                    .take(3)
                    .map(|e| e.name.clone()),
            );
            names
        }
        BenchmarkProfile::Full => {
            // All repos
            manifest.entries.iter().map(|e| e.name.clone()).collect()
        }
        BenchmarkProfile::Stress => {
            // All repos (XL emphasis — they appear naturally)
            manifest.entries.iter().map(|e| e.name.clone()).collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_display() {
        assert_eq!(BenchmarkProfile::Quick.to_string(), "quick");
        assert_eq!(BenchmarkProfile::Standard.to_string(), "standard");
        assert_eq!(BenchmarkProfile::Full.to_string(), "full");
        assert_eq!(BenchmarkProfile::Stress.to_string(), "stress");
    }

    #[test]
    fn profile_from_str_name() {
        assert_eq!(
            BenchmarkProfile::from_str_name("quick"),
            Some(BenchmarkProfile::Quick)
        );
        assert_eq!(
            BenchmarkProfile::from_str_name("STANDARD"),
            Some(BenchmarkProfile::Standard)
        );
        assert_eq!(
            BenchmarkProfile::from_str_name("Full"),
            Some(BenchmarkProfile::Full)
        );
        assert_eq!(
            BenchmarkProfile::from_str_name("stress"),
            Some(BenchmarkProfile::Stress)
        );
        assert_eq!(BenchmarkProfile::from_str_name("unknown"), None);
    }

    #[test]
    fn quick_profile_selects_3_small_repos() {
        let config = ProfileConfig::from_profile(BenchmarkProfile::Quick);
        assert_eq!(config.repo_names.len(), 3);
        assert!(!config.collect_memory);
        assert!(!config.collect_throughput);
        assert!(config.collect_latency_percentiles);
        assert!(!config.run_stress_tests);
    }

    #[test]
    fn standard_profile_selects_10_repos() {
        let config = ProfileConfig::from_profile(BenchmarkProfile::Standard);
        assert_eq!(config.repo_names.len(), 10);
        assert!(!config.collect_memory);
        assert!(config.collect_throughput);
    }

    #[test]
    fn full_profile_selects_all_repos() {
        let manifest = CorpusManifest::default_manifest();
        let config = ProfileConfig::from_profile(BenchmarkProfile::Full);
        assert_eq!(config.repo_names.len(), manifest.len());
        assert!(config.collect_memory);
        assert!(config.collect_throughput);
        assert!(!config.run_stress_tests);
    }

    #[test]
    fn stress_profile_includes_everything() {
        let config = ProfileConfig::from_profile(BenchmarkProfile::Stress);
        assert!(config.collect_memory);
        assert!(config.collect_throughput);
        assert!(config.run_stress_tests);
        assert_eq!(config.throughput_iterations, 5000);
    }

    #[test]
    fn profile_timeout_increases_with_tier() {
        assert!(
            BenchmarkProfile::Quick.timeout_per_repo()
                < BenchmarkProfile::Standard.timeout_per_repo()
        );
        assert!(
            BenchmarkProfile::Standard.timeout_per_repo()
                < BenchmarkProfile::Full.timeout_per_repo()
        );
        assert!(
            BenchmarkProfile::Full.timeout_per_repo()
                < BenchmarkProfile::Stress.timeout_per_repo()
        );
    }

    #[test]
    fn profile_serialization_roundtrip() {
        for profile in [
            BenchmarkProfile::Quick,
            BenchmarkProfile::Standard,
            BenchmarkProfile::Full,
            BenchmarkProfile::Stress,
        ] {
            let json = serde_json::to_string(&profile).unwrap();
            let parsed: BenchmarkProfile = serde_json::from_str(&json).unwrap();
            assert_eq!(profile, parsed);
        }
    }

    #[test]
    fn profile_config_serialization_roundtrip() {
        let config = ProfileConfig::from_profile(BenchmarkProfile::Standard);
        let json = serde_json::to_string(&config).unwrap();
        let parsed: ProfileConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.profile, BenchmarkProfile::Standard);
        assert_eq!(parsed.repo_names.len(), config.repo_names.len());
    }
}
