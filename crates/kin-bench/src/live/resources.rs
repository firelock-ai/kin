// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use serde::{Deserialize, Serialize};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemBaseline {
    pub cpu_cores: u32,
    pub ram_total_bytes: u64,
    pub os_name: String,
    pub arch: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceSample {
    pub offset_ms: u64,
    pub cpu_pct: f64,
    pub mem_used_bytes: u64,
    pub mem_available_bytes: u64,
    #[serde(default)]
    pub swap_used_bytes: u64,
    #[serde(default)]
    pub swap_total_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessMetrics {
    pub peak_rss_bytes: u64,
    pub cpu_user_ms: f64,
    pub cpu_sys_ms: f64,
}

/// A competing assistant CLI process detected on the system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompetingProcess {
    pub pid: u32,
    pub name: String,
    pub rss_bytes: u64,
    pub cpu_pct: f64,
}

/// Pre-run system health snapshot — captures whether the system is "clean"
/// enough for trustworthy benchmark results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemHealth {
    pub load_avg_1m: f64,
    pub load_avg_5m: f64,
    pub cpu_pct: f64,
    pub mem_pressure_pct: f64,
    pub swap_used_bytes: u64,
    pub swap_total_bytes: u64,
    pub competing_processes: Vec<CompetingProcess>,
    /// True if the system looks clean enough for reliable benchmarks.
    pub clean: bool,
    /// Human-readable warnings about contention.
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceReport {
    pub system_baseline: SystemBaseline,
    pub samples: Vec<ResourceSample>,
    pub process_metrics: Option<ProcessMetrics>,
    /// Pre-run system health when the benchmark started.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_run_health: Option<SystemHealth>,
}

// ---------------------------------------------------------------------------
// Standalone capture helpers
// ---------------------------------------------------------------------------

/// Capture a snapshot of the host system's hardware profile.
pub fn capture_system_baseline() -> SystemBaseline {
    let os_name = std::env::consts::OS.to_string();
    let arch = std::env::consts::ARCH.to_string();

    let (cpu_cores, ram_total_bytes) = match os_name.as_str() {
        "macos" => baseline_macos(),
        "linux" => baseline_linux(),
        _ => (0, 0),
    };

    SystemBaseline {
        cpu_cores,
        ram_total_bytes,
        os_name,
        arch,
    }
}

fn baseline_macos() -> (u32, u64) {
    let cores = Command::new("sysctl")
        .args(["-n", "hw.ncpu"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(0);

    let ram = Command::new("sysctl")
        .args(["-n", "hw.memsize"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0);

    (cores, ram)
}

fn baseline_linux() -> (u32, u64) {
    let cores = std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .map(|s| s.lines().filter(|l| l.starts_with("processor")).count() as u32)
        .unwrap_or(0);

    let ram = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("MemTotal:"))
                .and_then(|l| {
                    l.split_whitespace()
                        .nth(1)
                        .and_then(|v| v.parse::<u64>().ok())
                })
                // /proc/meminfo reports in kB
                .map(|kb| kb * 1024)
        })
        .unwrap_or(0);

    (cores, ram)
}

/// Take a single point-in-time sample of system memory (and best-effort CPU).
pub fn sample_system_resources() -> Option<ResourceSample> {
    match std::env::consts::OS {
        "macos" => sample_macos(),
        "linux" => sample_linux(),
        _ => None,
    }
}

fn sample_macos() -> Option<ResourceSample> {
    // Parse `vm_stat` for memory pages.
    let output = Command::new("vm_stat").output().ok()?;
    let text = String::from_utf8(output.stdout).ok()?;

    // First line typically: "Mach Virtual Memory Statistics: (page size of 16384 bytes)"
    let page_size: u64 = text
        .lines()
        .next()
        .and_then(|line| {
            line.split("page size of ")
                .nth(1)
                .and_then(|rest| rest.trim_end_matches(')').trim().parse().ok())
        })
        .unwrap_or(16384);

    let page_val = |key: &str| -> u64 {
        text.lines()
            .find(|l| l.starts_with(key))
            .and_then(|l| {
                l.split(':')
                    .nth(1)
                    .map(|v| v.trim().trim_end_matches('.'))
                    .and_then(|v| v.parse::<u64>().ok())
            })
            .unwrap_or(0)
    };

    let free = page_val("Pages free");
    let active = page_val("Pages active");
    let inactive = page_val("Pages inactive");
    let speculative = page_val("Pages speculative");
    let wired = page_val("Pages wired down");
    let compressed = page_val("Pages occupied by compressor");

    let used_pages = active + wired + compressed;
    let available_pages = free + inactive + speculative;

    let mem_used_bytes = used_pages * page_size;
    let mem_available_bytes = available_pages * page_size;

    // Swap via sysctl
    let (swap_used, swap_total) = swap_macos();

    // CPU: best-effort via `top -l 1 -n 0 -s 0`, parse "CPU usage:" line.
    // If it fails, report 0.0.
    let cpu_pct = Command::new("top")
        .args(["-l", "1", "-n", "0", "-s", "0"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|text| {
            // Line looks like: "CPU usage: 5.26% user, 10.52% sys, 84.21% idle"
            text.lines()
                .find(|l| l.starts_with("CPU usage:"))
                .map(|l| {
                    // Sum user + sys percentages
                    let user = extract_pct(l, "user");
                    let sys = extract_pct(l, "sys");
                    user + sys
                })
        })
        .unwrap_or(0.0);

    Some(ResourceSample {
        offset_ms: 0, // caller fills this in
        cpu_pct,
        mem_used_bytes,
        mem_available_bytes,
        swap_used_bytes: swap_used,
        swap_total_bytes: swap_total,
    })
}

/// Extract a percentage value that appears right before the given label.
/// E.g. for "5.26% user" with label "user", returns 5.26.
fn extract_pct(line: &str, label: &str) -> f64 {
    line.split(label)
        .next()
        .and_then(|before| {
            // Walk backward to find the number before the %
            before
                .trim()
                .trim_end_matches('%')
                .split_whitespace()
                .next_back()
                .and_then(|v| v.parse::<f64>().ok())
        })
        .unwrap_or(0.0)
}

/// Read swap usage on macOS via `sysctl vm.swapusage`.
/// Returns (used_bytes, total_bytes).
fn swap_macos() -> (u64, u64) {
    // Output: "vm.swapusage: total = 6144.00M  used = 2048.00M  free = 4096.00M  ..."
    let output = Command::new("sysctl")
        .args(["-n", "vm.swapusage"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default();

    let parse_mb = |label: &str| -> u64 {
        output
            .split(label)
            .nth(1)
            .and_then(|rest| {
                rest.trim()
                    .trim_start_matches('=')
                    .split_whitespace()
                    .next()
            })
            .and_then(|v| v.trim_end_matches('M').parse::<f64>().ok())
            .map(|mb| (mb * 1024.0 * 1024.0) as u64)
            .unwrap_or(0)
    };

    (parse_mb("used"), parse_mb("total"))
}

fn sample_linux() -> Option<ResourceSample> {
    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;

    let field = |name: &str| -> u64 {
        meminfo
            .lines()
            .find(|l| l.starts_with(name))
            .and_then(|l| {
                l.split_whitespace()
                    .nth(1)
                    .and_then(|v| v.parse::<u64>().ok())
            })
            .unwrap_or(0)
            * 1024 // kB → bytes
    };

    let mem_total = field("MemTotal:");
    let mem_available = field("MemAvailable:");
    let mem_used = mem_total.saturating_sub(mem_available);

    // CPU from /proc/stat — first "cpu " line aggregate.
    // Returns idle ratio; we report (1 - idle_ratio) * 100 as cpu_pct.
    // This is a snapshot, not a delta, so it's a rough lifetime average.
    let cpu_pct = std::fs::read_to_string("/proc/stat")
        .ok()
        .and_then(|text| {
            let line = text.lines().find(|l| l.starts_with("cpu "))?;
            let vals: Vec<u64> = line
                .split_whitespace()
                .skip(1) // skip "cpu"
                .filter_map(|v| v.parse().ok())
                .collect();
            if vals.len() >= 4 {
                let total: u64 = vals.iter().sum();
                let idle = vals[3]; // 4th field is idle
                if total > 0 {
                    Some(((total - idle) as f64 / total as f64) * 100.0)
                } else {
                    Some(0.0)
                }
            } else {
                None
            }
        })
        .unwrap_or(0.0);

    let swap_total = field("SwapTotal:");
    let swap_free = field("SwapFree:");
    let swap_used = swap_total.saturating_sub(swap_free);

    Some(ResourceSample {
        offset_ms: 0,
        cpu_pct,
        mem_used_bytes: mem_used,
        mem_available_bytes: mem_available,
        swap_used_bytes: swap_used,
        swap_total_bytes: swap_total,
    })
}

/// Capture process-level resource metrics for the given PID.
pub fn capture_process_metrics(pid: u32) -> Option<ProcessMetrics> {
    match std::env::consts::OS {
        "macos" => process_metrics_macos(pid),
        "linux" => process_metrics_linux(pid),
        _ => None,
    }
}

fn process_metrics_macos(pid: u32) -> Option<ProcessMetrics> {
    // `ps -o rss=,time= -p <pid>` → "  12345  01:23.45"
    let output = Command::new("ps")
        .args(["-o", "rss=,time=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    let text = String::from_utf8(output.stdout).ok()?;
    let text = text.trim();
    if text.is_empty() {
        return None;
    }

    let parts: Vec<&str> = text.split_whitespace().collect();
    if parts.len() < 2 {
        return None;
    }

    // RSS is in KB
    let rss_kb: u64 = parts[0].parse().ok()?;
    let peak_rss_bytes = rss_kb * 1024;

    // Time is MM:SS.ss — total CPU time (user+sys combined on macOS ps).
    // We report it all as user, sys as 0 since macOS `ps` doesn't split them
    // with these format specifiers.
    let total_ms = parse_ps_time(parts[1]);

    Some(ProcessMetrics {
        peak_rss_bytes,
        cpu_user_ms: total_ms,
        cpu_sys_ms: 0.0,
    })
}

/// Parse a ps time field like "01:23.45" (MM:SS.cc) or "0:02.34" into milliseconds.
fn parse_ps_time(s: &str) -> f64 {
    // Format: [MM:]SS.cc  (centiseconds)
    let (mins, rest) = if let Some(pos) = s.find(':') {
        let m: f64 = s[..pos].parse().unwrap_or(0.0);
        (m, &s[pos + 1..])
    } else {
        (0.0, s)
    };
    let secs: f64 = rest.parse().unwrap_or(0.0);
    (mins * 60.0 + secs) * 1000.0
}

fn process_metrics_linux(pid: u32) -> Option<ProcessMetrics> {
    // VmRSS from /proc/{pid}/status (in kB)
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let rss_kb: u64 = status
        .lines()
        .find(|l| l.starts_with("VmRSS:"))
        .and_then(|l| l.split_whitespace().nth(1).and_then(|v| v.parse().ok()))
        .unwrap_or(0);
    let peak_rss_bytes = rss_kb * 1024;

    // utime and stime from /proc/{pid}/stat — fields 14 and 15 (1-indexed)
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // Fields after the comm (which may contain spaces and is in parens)
    let after_comm = stat.rfind(')')?.checked_add(1)?;
    let fields: Vec<&str> = stat[after_comm..].split_whitespace().collect();
    // After ")", fields[0] is state, fields[11] is utime, fields[12] is stime
    // (0-indexed within this slice)
    let ticks_per_sec: f64 = 100.0; // standard on Linux
    let utime: f64 = fields
        .get(11)
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0) as f64;
    let stime: f64 = fields
        .get(12)
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0) as f64;

    Some(ProcessMetrics {
        peak_rss_bytes,
        cpu_user_ms: (utime / ticks_per_sec) * 1000.0,
        cpu_sys_ms: (stime / ticks_per_sec) * 1000.0,
    })
}

// ---------------------------------------------------------------------------
// Competing process detection & system health
// ---------------------------------------------------------------------------

/// CLI binary names we consider "competing" assistant processes.
const ASSISTANT_BINARIES: &[&str] = &["claude", "codex", "gemini"];

/// Detect running assistant CLI processes, excluding a specific PID (our own benchmark child).
pub fn detect_competing_processes(exclude_pid: Option<u32>) -> Vec<CompetingProcess> {
    match std::env::consts::OS {
        "macos" => competing_macos(exclude_pid),
        "linux" => competing_linux(exclude_pid),
        _ => vec![],
    }
}

fn competing_macos(exclude_pid: Option<u32>) -> Vec<CompetingProcess> {
    // `ps -eo pid,rss,%cpu,comm` — works on macOS
    let output = Command::new("ps")
        .args(["-eo", "pid,rss,%cpu,comm"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default();

    parse_ps_competing(&output, exclude_pid)
}

fn competing_linux(exclude_pid: Option<u32>) -> Vec<CompetingProcess> {
    let output = Command::new("ps")
        .args(["-eo", "pid,rss,%cpu,comm"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default();

    parse_ps_competing(&output, exclude_pid)
}

fn parse_ps_competing(ps_output: &str, exclude_pid: Option<u32>) -> Vec<CompetingProcess> {
    let mut results = Vec::new();
    for line in ps_output.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }
        let pid: u32 = match parts[0].parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        if exclude_pid == Some(pid) {
            continue;
        }
        // The comm field is the last column — extract just the binary name
        let comm = parts[3..].join(" ");
        let binary_name = comm.rsplit('/').next().unwrap_or(&comm);

        if !ASSISTANT_BINARIES
            .iter()
            .any(|b| binary_name.starts_with(b))
        {
            continue;
        }

        let rss_kb: u64 = parts[1].parse().unwrap_or(0);
        let cpu_pct: f64 = parts[2].parse().unwrap_or(0.0);

        results.push(CompetingProcess {
            pid,
            name: binary_name.to_string(),
            rss_bytes: rss_kb * 1024,
            cpu_pct,
        });
    }
    results
}

/// Load average on macOS/Linux.
fn load_averages() -> (f64, f64) {
    match std::env::consts::OS {
        "macos" | "linux" => {
            Command::new("sysctl")
                .args(["-n", "vm.loadavg"])
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .and_then(|s| {
                    // macOS: "{ 2.45 3.12 2.87 }" or Linux: "2.45 3.12 2.87"
                    let cleaned = s.replace(['{', '}'], "");
                    let parts: Vec<f64> = cleaned
                        .split_whitespace()
                        .filter_map(|v| v.parse().ok())
                        .collect();
                    if parts.len() >= 2 {
                        Some((parts[0], parts[1]))
                    } else {
                        None
                    }
                })
                .or_else(|| {
                    // Fallback: read /proc/loadavg on Linux
                    std::fs::read_to_string("/proc/loadavg").ok().and_then(|s| {
                        let parts: Vec<f64> = s
                            .split_whitespace()
                            .take(2)
                            .filter_map(|v| v.parse().ok())
                            .collect();
                        if parts.len() >= 2 {
                            Some((parts[0], parts[1]))
                        } else {
                            None
                        }
                    })
                })
                .unwrap_or((0.0, 0.0))
        }
        _ => (0.0, 0.0),
    }
}

/// Capture a pre-run system health snapshot.
/// `cpu_cores` is used to normalize load averages.
/// `exclude_pid` is our own benchmark child PID (if known).
pub fn capture_system_health(cpu_cores: u32, exclude_pid: Option<u32>) -> SystemHealth {
    let (load_1m, load_5m) = load_averages();
    let sample = sample_system_resources();

    let cpu_pct = sample.as_ref().map(|s| s.cpu_pct).unwrap_or(0.0);
    let mem_used = sample.as_ref().map(|s| s.mem_used_bytes).unwrap_or(0);
    let mem_avail = sample.as_ref().map(|s| s.mem_available_bytes).unwrap_or(1);
    let mem_total = mem_used + mem_avail;
    let mem_pressure_pct = if mem_total > 0 {
        (mem_used as f64 / mem_total as f64) * 100.0
    } else {
        0.0
    };

    let swap_used = sample.as_ref().map(|s| s.swap_used_bytes).unwrap_or(0);
    let swap_total = sample.as_ref().map(|s| s.swap_total_bytes).unwrap_or(0);

    let competing = detect_competing_processes(exclude_pid);

    let mut warnings = Vec::new();

    // Load average > cores means CPU is saturated
    if cpu_cores > 0 && load_1m > cpu_cores as f64 {
        warnings.push(format!(
            "CPU overloaded: 1m load avg {:.1} > {} cores",
            load_1m, cpu_cores
        ));
    }

    // Memory pressure > 85% is concerning
    if mem_pressure_pct > 85.0 {
        warnings.push(format!(
            "High memory pressure: {:.0}% used",
            mem_pressure_pct
        ));
    }

    // Any swap usage is a red flag for benchmarks
    if swap_used > 0 {
        let swap_mb = swap_used as f64 / (1024.0 * 1024.0);
        warnings.push(format!("Swap in use: {:.0} MB", swap_mb));
    }

    // Competing assistant processes
    if !competing.is_empty() {
        let total_rss_mb: f64 =
            competing.iter().map(|p| p.rss_bytes as f64).sum::<f64>() / (1024.0 * 1024.0);
        warnings.push(format!(
            "{} competing assistant process(es) detected ({:.0} MB RSS): {}",
            competing.len(),
            total_rss_mb,
            competing
                .iter()
                .map(|p| format!("{}(pid={})", p.name, p.pid))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    // CPU usage > 50% suggests background work
    if cpu_pct > 50.0 {
        warnings.push(format!("High CPU: {:.0}% in use", cpu_pct));
    }

    let clean = warnings.is_empty();

    SystemHealth {
        load_avg_1m: load_1m,
        load_avg_5m: load_5m,
        cpu_pct,
        mem_pressure_pct,
        swap_used_bytes: swap_used,
        swap_total_bytes: swap_total,
        competing_processes: competing,
        clean,
        warnings,
    }
}

// ---------------------------------------------------------------------------
// ResourceMonitor — background sampling thread
// ---------------------------------------------------------------------------

pub struct ResourceMonitor {
    baseline: SystemBaseline,
    #[allow(dead_code)]
    start: Instant,
    samples: Arc<Mutex<Vec<ResourceSample>>>,
    stop_flag: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
    tracked_pid: Arc<AtomicU32>,
    process_samples: Arc<Mutex<Vec<ProcessMetrics>>>,
    pre_run_health: Option<SystemHealth>,
}

impl std::fmt::Debug for ResourceMonitor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResourceMonitor")
            .field("baseline", &self.baseline)
            .field(
                "sample_count",
                &self.samples.lock().map(|s| s.len()).unwrap_or(0),
            )
            .field("tracked_pid", &self.tracked_pid.load(Ordering::Relaxed))
            .finish()
    }
}

impl ResourceMonitor {
    /// Start background resource monitoring, sampling every `interval_ms` milliseconds.
    /// Captures a pre-run system health snapshot before starting.
    pub fn start(interval_ms: u64) -> Self {
        let baseline = capture_system_baseline();
        let pre_run_health = Some(capture_system_health(baseline.cpu_cores, None));
        let start = Instant::now();
        let samples: Arc<Mutex<Vec<ResourceSample>>> = Arc::new(Mutex::new(Vec::new()));
        let stop_flag = Arc::new(AtomicBool::new(false));
        let tracked_pid = Arc::new(AtomicU32::new(0));
        let process_samples: Arc<Mutex<Vec<ProcessMetrics>>> = Arc::new(Mutex::new(Vec::new()));

        let samples_clone = Arc::clone(&samples);
        let stop_clone = Arc::clone(&stop_flag);
        let tracked_pid_clone = Arc::clone(&tracked_pid);
        let process_samples_clone = Arc::clone(&process_samples);
        let thread_start = start;
        let interval = std::time::Duration::from_millis(interval_ms);

        let handle = std::thread::Builder::new()
            .name("kin-resource-monitor".into())
            .spawn(move || {
                while !stop_clone.load(Ordering::Relaxed) {
                    if let Some(mut sample) = sample_system_resources() {
                        sample.offset_ms = thread_start.elapsed().as_millis() as u64;
                        if let Ok(mut vec) = samples_clone.lock() {
                            vec.push(sample);
                        }
                    }

                    let pid = tracked_pid_clone.load(Ordering::Relaxed);
                    if pid != 0 {
                        if let Some(pm) = capture_process_metrics(pid) {
                            if let Ok(mut vec) = process_samples_clone.lock() {
                                vec.push(pm);
                            }
                        }
                    }

                    std::thread::sleep(interval);
                }
            })
            .expect("failed to spawn resource monitor thread");

        Self {
            baseline,
            start,
            samples,
            stop_flag,
            handle: Some(handle),
            tracked_pid,
            process_samples,
            pre_run_health,
        }
    }

    /// Register a PID to track. The background thread will sample this PID's
    /// metrics alongside system resources until the process exits or monitoring stops.
    pub fn track_pid(&self, pid: u32) {
        self.tracked_pid.store(pid, Ordering::Relaxed);
    }

    /// Stop monitoring and return the collected resource report.
    pub fn stop(self) -> ResourceReport {
        self.finish()
    }

    fn finish(mut self) -> ResourceReport {
        self.stop_flag.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }

        let process_metrics = {
            let samples = self
                .process_samples
                .lock()
                .map(|s| s.clone())
                .unwrap_or_default();
            if samples.is_empty() {
                None
            } else {
                Some(ProcessMetrics {
                    peak_rss_bytes: samples.iter().map(|s| s.peak_rss_bytes).max().unwrap_or(0),
                    cpu_user_ms: samples.last().map(|s| s.cpu_user_ms).unwrap_or(0.0),
                    cpu_sys_ms: samples.last().map(|s| s.cpu_sys_ms).unwrap_or(0.0),
                })
            }
        };

        let samples = self.samples.lock().map(|s| s.clone()).unwrap_or_default();

        ResourceReport {
            system_baseline: self.baseline,
            samples,
            process_metrics,
            pre_run_health: self.pre_run_health,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #[test]
    fn system_baseline_captures_something() {
        let baseline = super::capture_system_baseline();
        assert!(!baseline.os_name.is_empty());
        assert!(!baseline.arch.is_empty());
        assert!(baseline.cpu_cores >= 1);
    }

    #[test]
    fn resource_report_serialization_roundtrip() {
        let report = super::ResourceReport {
            system_baseline: super::SystemBaseline {
                cpu_cores: 8,
                ram_total_bytes: 32_000_000_000,
                os_name: "darwin".into(),
                arch: "aarch64".into(),
            },
            samples: vec![super::ResourceSample {
                offset_ms: 0,
                cpu_pct: 25.0,
                mem_used_bytes: 16_000_000_000,
                mem_available_bytes: 16_000_000_000,
                swap_used_bytes: 0,
                swap_total_bytes: 4_000_000_000,
            }],
            process_metrics: None,
            pre_run_health: None,
        };
        let json = serde_json::to_string(&report).unwrap();
        let parsed: super::ResourceReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.system_baseline.cpu_cores, 8);
        assert_eq!(parsed.samples.len(), 1);
    }

    #[test]
    fn monitor_start_stop_returns_report() {
        let monitor = super::ResourceMonitor::start(100);
        std::thread::sleep(std::time::Duration::from_millis(350));
        let report = monitor.stop();
        assert!(report.system_baseline.cpu_cores >= 1);
        assert!(!report.samples.is_empty());
    }

    #[test]
    fn parse_ps_time_formats() {
        // MM:SS.cc
        let ms = super::parse_ps_time("01:23.45");
        assert!((ms - 83_450.0).abs() < 1.0);
        // 0:02.34
        let ms = super::parse_ps_time("0:02.34");
        assert!((ms - 2_340.0).abs() < 1.0);
    }

    #[test]
    fn monitor_track_pid_stores_value() {
        let monitor = super::ResourceMonitor::start(500);
        monitor.track_pid(12345);
        assert_eq!(
            monitor
                .tracked_pid
                .load(std::sync::atomic::Ordering::Relaxed),
            12345
        );
        let report = monitor.stop();
        assert!(report.system_baseline.cpu_cores >= 1);
    }

    #[test]
    fn extract_pct_parses_cpu_line() {
        let line = "CPU usage: 5.26% user, 10.52% sys, 84.21% idle";
        let user = super::extract_pct(line, "user");
        let sys = super::extract_pct(line, "sys");
        assert!((user - 5.26).abs() < 0.01);
        assert!((sys - 10.52).abs() < 0.01);
    }

    #[test]
    fn parse_ps_competing_finds_claude_processes() {
        let output = "\
  PID   RSS  %CPU COMM\n\
12345 102400  5.2 /usr/local/bin/claude\n\
67890 204800 10.1 /usr/local/bin/node\n\
11111  51200  2.0 /usr/local/bin/codex\n";
        let result = super::parse_ps_competing(output, None);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].name, "claude");
        assert_eq!(result[1].name, "codex");
    }

    #[test]
    fn parse_ps_competing_excludes_own_pid() {
        let output = "\
  PID   RSS  %CPU COMM\n\
12345 102400  5.2 /usr/local/bin/claude\n\
67890  51200  2.0 /usr/local/bin/claude\n";
        let result = super::parse_ps_competing(output, Some(12345));
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].pid, 67890);
    }

    #[test]
    fn system_health_captures_snapshot() {
        let health = super::capture_system_health(8, None);
        // Should at least run without panicking and produce valid data
        assert!(health.mem_pressure_pct >= 0.0);
        assert!(health.mem_pressure_pct <= 100.0);
    }

    #[test]
    fn monitor_includes_pre_run_health() {
        let monitor = super::ResourceMonitor::start(500);
        std::thread::sleep(std::time::Duration::from_millis(100));
        let report = monitor.stop();
        assert!(report.pre_run_health.is_some());
        let health = report.pre_run_health.unwrap();
        assert!(health.mem_pressure_pct >= 0.0);
    }

    #[test]
    fn sample_includes_swap_fields() {
        if let Some(sample) = super::sample_system_resources() {
            // swap_total_bytes might be 0 if no swap is configured, but fields exist
            assert!(
                sample.swap_total_bytes >= sample.swap_used_bytes || sample.swap_total_bytes == 0
            );
        }
    }
}
