// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Machine capability detection for adaptive locate behavior.
//!
//! Determines the [`LocateProfile`] tier from effective CPU cores + available
//! RAM. Lower tiers trade recall for latency on constrained hardware (shallower
//! multihop, no reranker / PRF / LTR), so the tier changes retrieval quality —
//! that downgrade is surfaced, never silent (see [`LocateProfile::name`] /
//! [`LocateProfile::disabled_signals`], reported as a `capability_tier`
//! degradation on every `kin locate` result).
//!
//! Detection is container-aware: cores and RAM are capped by the active cgroup
//! v2 (`cpu.max` / `memory.max`) or v1 (CFS quota / `memory.limit_in_bytes`)
//! budget when one is set, so a `--cpus 2` container is scored as 2 cores rather
//! than reading the host's full topology. A bare-metal host with no cgroup limit
//! is unaffected.
//!
//! Override the auto-detected tier with the `KIN_LOCATE_PROFILE` environment
//! variable, set to `minimal`, `standard`, or `performance` (case-insensitive);
//! any other value falls through to auto-detection.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocateProfile {
    /// ≤2 cores OR ≤4GB RAM
    Minimal,
    /// 4+ cores AND 8GB+ RAM (default)
    Standard,
    /// 8+ cores AND 16GB+ RAM
    Performance,
}

impl LocateProfile {
    pub fn detect() -> Self {
        // Check env override first
        if let Ok(val) = std::env::var("KIN_LOCATE_PROFILE") {
            match val.to_lowercase().as_str() {
                "minimal" => return Self::Minimal,
                "standard" => return Self::Standard,
                "performance" => return Self::Performance,
                _ => {} // fall through to detection
            }
        }

        let cores = num_cpus();
        let ram_gb = available_ram_gb();

        if cores >= 8 && ram_gb >= 16.0 {
            Self::Performance
        } else if cores >= 4 && ram_gb >= 8.0 {
            Self::Standard
        } else {
            Self::Minimal
        }
    }

    pub fn multihop_max_depth(&self) -> usize {
        match self {
            Self::Minimal => 2,
            Self::Standard => 3,
            Self::Performance => 4,
        }
    }

    pub fn multihop_frontier_limit(&self) -> usize {
        match self {
            Self::Minimal => 50,
            Self::Standard => 100,
            Self::Performance => 200,
        }
    }

    pub fn multihop_timeout_ms(&self) -> u64 {
        match self {
            Self::Minimal => 200,
            Self::Standard => 500,
            Self::Performance => 1000,
        }
    }

    pub fn prf_enabled(&self) -> bool {
        matches!(self, Self::Standard | Self::Performance)
    }

    pub fn ltr_enabled(&self) -> bool {
        matches!(self, Self::Performance)
    }

    pub fn reranker_enabled(&self) -> bool {
        matches!(self, Self::Standard | Self::Performance)
    }

    /// Stable lowercase tier name. Also the exact token accepted by the
    /// `KIN_LOCATE_PROFILE` override, so surfaced output names the lever a user
    /// would set to change it.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Minimal => "minimal",
            Self::Standard => "standard",
            Self::Performance => "performance",
        }
    }

    /// Retrieval signals this tier turns off relative to the full `Performance`
    /// pipeline, as stable machine-readable tokens. Empty on `Performance`.
    ///
    /// This is the no-silent-downgrade contract for hardware-adaptive locate: a
    /// smaller machine really does return lower-recall results, and the caller
    /// can see exactly which signals were dropped rather than inferring it from
    /// differing results across machines.
    pub fn disabled_signals(&self) -> Vec<&'static str> {
        let mut off = Vec::new();
        if !self.reranker_enabled() {
            off.push("reranker");
        }
        if !self.prf_enabled() {
            off.push("prf");
        }
        if !self.ltr_enabled() {
            off.push("ltr");
        }
        if self.multihop_max_depth() < Self::Performance.multihop_max_depth() {
            off.push("multihop_depth");
        }
        off
    }
}

/// Effective schedulable core count: host parallelism, capped by a container
/// CPU quota (cgroup v2 `cpu.max` / v1 CFS quota) when one is set. Without a
/// quota this is the raw host count, so bare-metal detection is unchanged.
fn num_cpus() -> usize {
    let host = std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(1);
    match cgroup_cpu_quota() {
        Some(quota) => host.min(quota).max(1),
        None => host,
    }
}

#[cfg(target_os = "macos")]
fn host_ram_gb() -> f64 {
    use std::process::Command;
    Command::new("sysctl")
        .args(["-n", "hw.memsize"])
        .output()
        .ok()
        .and_then(|out| {
            String::from_utf8_lossy(&out.stdout)
                .trim()
                .parse::<u64>()
                .ok()
        })
        .map(|bytes| bytes as f64 / (1024.0 * 1024.0 * 1024.0))
        .unwrap_or(4.0)
}

#[cfg(target_os = "linux")]
fn host_ram_gb() -> f64 {
    std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|contents| {
            for line in contents.lines() {
                if line.starts_with("MemTotal:") {
                    let kb: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
                    return Some(kb as f64 / (1024.0 * 1024.0));
                }
            }
            None
        })
        .unwrap_or(4.0)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn host_ram_gb() -> f64 {
    // Conservative default for unsupported platforms
    4.0
}

/// Effective available RAM in GiB: host physical RAM, capped by a container
/// memory limit (cgroup v2 `memory.max` / v1 `memory.limit_in_bytes`) when one
/// is set. Without a limit this is the host figure, so bare-metal detection is
/// unchanged.
fn available_ram_gb() -> f64 {
    let host = host_ram_gb();
    match cgroup_memory_limit_bytes() {
        Some(limit) => {
            let limit_gb = limit as f64 / (1024.0 * 1024.0 * 1024.0);
            host.min(limit_gb)
        }
        None => host,
    }
}

/// What the host can say about memory pressure, for a command that has to
/// decide whether a failure it just saw was the machine running out of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryEvidence {
    /// The ceiling this process actually runs under: the container limit when
    /// one is set, otherwise the host's physical RAM.
    pub limit_bytes: u64,
    /// Kernel OOM kills accounted to this cgroup. `None` means no accounting
    /// was readable, which is "not observed" and never "did not happen".
    pub cgroup_oom_kills: Option<u64>,
}

/// Read what this host will say about memory pressure right now.
pub fn memory_evidence() -> MemoryEvidence {
    MemoryEvidence {
        limit_bytes: effective_memory_limit_bytes(),
        cgroup_oom_kills: cgroup_oom_kill_count(),
    }
}

/// The memory ceiling a Kin process runs under, in bytes.
fn effective_memory_limit_bytes() -> u64 {
    let host = (host_ram_gb() * 1024.0 * 1024.0 * 1024.0) as u64;
    match cgroup_memory_limit_bytes() {
        Some(limit) => host.min(limit),
        None => host,
    }
}

// ---------------------------------------------------------------------------
// Container (cgroup) quota detection — Linux only
// ---------------------------------------------------------------------------
//
// The tier must reflect the real budget, not the host topology, so a `--cpus 2`
// container is not mis-scored as an 8-core Performance box. The FS-reading
// probes are Linux-only and return `None` when no quota is set (an unlimited
// group, absent files, or off-Linux), keeping bare-metal detection unchanged.
// The parsing is factored into pure helpers so it is unit-tested on any host.

/// Effective CPU count from a container CPU quota, or `None` when unlimited,
/// unset, unparsable, or off Linux.
#[cfg(target_os = "linux")]
fn cgroup_cpu_quota() -> Option<usize> {
    // cgroup v2 unified hierarchy: `cpu.max` is "<quota> <period>" (µs) or
    // "max <period>" when unthrottled.
    if let Ok(contents) = std::fs::read_to_string("/sys/fs/cgroup/cpu.max") {
        if let Some(cores) = parse_v2_cpu_max(&contents) {
            return Some(cores);
        }
        if contents.trim_start().starts_with("max") {
            return None;
        }
    }
    // cgroup v1: cpu.cfs_quota_us / cpu.cfs_period_us.
    let quota: i64 = std::fs::read_to_string("/sys/fs/cgroup/cpu/cpu.cfs_quota_us")
        .ok()?
        .trim()
        .parse()
        .ok()?;
    let period: i64 = std::fs::read_to_string("/sys/fs/cgroup/cpu/cpu.cfs_period_us")
        .ok()?
        .trim()
        .parse()
        .ok()?;
    parse_v1_cpu_quota(quota, period)
}

#[cfg(not(target_os = "linux"))]
fn cgroup_cpu_quota() -> Option<usize> {
    None
}

/// Effective memory limit in bytes from a container memory cap, or `None` when
/// unlimited, unset, unparsable, or off Linux.
#[cfg(target_os = "linux")]
fn cgroup_memory_limit_bytes() -> Option<u64> {
    if let Ok(contents) = std::fs::read_to_string("/sys/fs/cgroup/memory.max") {
        return parse_v2_memory_max(&contents);
    }
    let raw: u64 = std::fs::read_to_string("/sys/fs/cgroup/memory/memory.limit_in_bytes")
        .ok()?
        .trim()
        .parse()
        .ok()?;
    parse_v1_memory_limit(raw)
}

#[cfg(not(target_os = "linux"))]
fn cgroup_memory_limit_bytes() -> Option<u64> {
    None
}

/// How many times the kernel OOM-killed a process accounted to this cgroup, or
/// `None` when no accounting is readable (off Linux, or neither hierarchy's
/// file is present).
///
/// Both hierarchies publish the counter under the same key, in different files:
/// cgroup v2 in `memory.events`, v1 in `memory.oom_control`. The distinction
/// that matters to a caller is `Some(0)` against `None`: the first is the
/// kernel saying nothing was killed, the second is this process being unable
/// to ask.
#[cfg(target_os = "linux")]
fn cgroup_oom_kill_count() -> Option<u64> {
    for path in [
        "/sys/fs/cgroup/memory.events",
        "/sys/fs/cgroup/memory/memory.oom_control",
    ] {
        if let Ok(contents) = std::fs::read_to_string(path) {
            if let Some(count) = parse_oom_kill_count(&contents) {
                return Some(count);
            }
        }
    }
    None
}

#[cfg(not(target_os = "linux"))]
fn cgroup_oom_kill_count() -> Option<u64> {
    None
}

/// The `oom_kill` counter out of a cgroup key/value block, or `None` when the
/// block carries no such key.
#[cfg(any(target_os = "linux", test))]
fn parse_oom_kill_count(contents: &str) -> Option<u64> {
    contents.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        match (fields.next(), fields.next()) {
            (Some("oom_kill"), Some(value)) => value.parse().ok(),
            _ => None,
        }
    })
}

/// Whole-core count for a cgroup v2 `cpu.max` value ("<quota> <period>" in µs,
/// or "max <period>"). Rounds a fractional quota up to one core; `None` when
/// unlimited or unparsable.
#[cfg(any(target_os = "linux", test))]
fn parse_v2_cpu_max(contents: &str) -> Option<usize> {
    let mut fields = contents.split_whitespace();
    let quota = fields.next()?;
    if quota == "max" {
        return None;
    }
    let quota: u64 = quota.parse().ok()?;
    let period: u64 = fields
        .next()
        .and_then(|p| p.parse().ok())
        .unwrap_or(100_000);
    if period == 0 {
        return None;
    }
    Some((quota.div_ceil(period) as usize).max(1))
}

/// Whole-core count for cgroup v1 CFS `quota`/`period` (µs). A non-positive
/// quota/period is "unlimited" → `None`.
#[cfg(any(target_os = "linux", test))]
fn parse_v1_cpu_quota(quota_us: i64, period_us: i64) -> Option<usize> {
    if quota_us <= 0 || period_us <= 0 {
        return None;
    }
    Some(((quota_us as u64).div_ceil(period_us as u64) as usize).max(1))
}

/// Byte limit from a cgroup v2 `memory.max` value, or `None` for "max" /
/// unparsable.
#[cfg(any(target_os = "linux", test))]
fn parse_v2_memory_max(contents: &str) -> Option<u64> {
    let trimmed = contents.trim();
    if trimmed == "max" {
        return None;
    }
    trimmed.parse().ok()
}

/// Byte limit from a cgroup v1 `memory.limit_in_bytes`. An unconstrained group
/// reports a huge page-aligned sentinel near `u64::MAX`; any value ≥ 1 PiB is
/// that sentinel, not a real cap.
#[cfg(any(target_os = "linux", test))]
fn parse_v1_memory_limit(raw: u64) -> Option<u64> {
    const ONE_PIB: u64 = 1 << 50;
    if raw >= ONE_PIB {
        None
    } else {
        Some(raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier_names_match_env_override_tokens() {
        assert_eq!(LocateProfile::Minimal.name(), "minimal");
        assert_eq!(LocateProfile::Standard.name(), "standard");
        assert_eq!(LocateProfile::Performance.name(), "performance");
    }

    #[test]
    fn performance_disables_nothing_lower_tiers_do() {
        assert!(LocateProfile::Performance.disabled_signals().is_empty());
        // Standard keeps reranker + PRF but loses LTR and full multihop depth.
        let standard = LocateProfile::Standard.disabled_signals();
        assert!(standard.contains(&"ltr"));
        assert!(standard.contains(&"multihop_depth"));
        assert!(!standard.contains(&"reranker"));
        // Minimal loses every learned signal.
        let minimal = LocateProfile::Minimal.disabled_signals();
        for sig in ["reranker", "prf", "ltr", "multihop_depth"] {
            assert!(minimal.contains(&sig), "minimal should disable {sig}");
        }
    }

    #[test]
    fn v2_cpu_max_parses_quota_period_and_unlimited() {
        assert_eq!(parse_v2_cpu_max("200000 100000"), Some(2));
        assert_eq!(parse_v2_cpu_max("50000 100000"), Some(1)); // ceil fractional
        assert_eq!(parse_v2_cpu_max("150000 100000"), Some(2));
        assert_eq!(parse_v2_cpu_max("max 100000"), None);
        assert_eq!(parse_v2_cpu_max(""), None);
        assert_eq!(parse_v2_cpu_max("bogus 100000"), None);
    }

    #[test]
    fn v1_cpu_quota_treats_negative_as_unlimited() {
        assert_eq!(parse_v1_cpu_quota(200000, 100000), Some(2));
        assert_eq!(parse_v1_cpu_quota(-1, 100000), None);
        assert_eq!(parse_v1_cpu_quota(0, 100000), None);
    }

    #[test]
    fn v2_memory_max_parses_bytes_and_unlimited() {
        assert_eq!(
            parse_v2_memory_max("4294967296"),
            Some(4 * 1024 * 1024 * 1024)
        );
        assert_eq!(parse_v2_memory_max("max"), None);
    }

    #[test]
    fn oom_kill_count_is_read_from_either_cgroup_hierarchy() {
        // cgroup v2 `memory.events`, which is where the 512 MB constrained
        // profile's evidence came from.
        assert_eq!(
            parse_oom_kill_count("low 0\nhigh 0\nmax 3\noom 1\noom_kill 1\n"),
            Some(1)
        );
        // cgroup v1 `memory.oom_control`, same key, different file.
        assert_eq!(
            parse_oom_kill_count("oom_kill_disable 0\nunder_oom 0\noom_kill 2\n"),
            Some(2)
        );
        // A group that was never killed says so, which is not the same answer
        // as a host that cannot be asked.
        assert_eq!(parse_oom_kill_count("low 0\nhigh 0\nmax 0\noom 0\n"), None);
        assert_eq!(parse_oom_kill_count("oom_kill 0\n"), Some(0));
        assert_eq!(parse_oom_kill_count("oom_kill notanumber\n"), None);
    }

    #[test]
    fn v1_memory_limit_rejects_unlimited_sentinel() {
        assert_eq!(
            parse_v1_memory_limit(4 * 1024 * 1024 * 1024),
            Some(4 * 1024 * 1024 * 1024)
        );
        assert_eq!(parse_v1_memory_limit(0x7FFF_FFFF_FFFF_F000), None);
    }
}
