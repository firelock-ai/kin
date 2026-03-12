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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessMetrics {
    pub peak_rss_bytes: u64,
    pub cpu_user_ms: f64,
    pub cpu_sys_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceReport {
    pub system_baseline: SystemBaseline,
    pub samples: Vec<ResourceSample>,
    pub process_metrics: Option<ProcessMetrics>,
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
        .map(|s| {
            s.lines()
                .filter(|l| l.starts_with("processor"))
                .count() as u32
        })
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
                .and_then(|l| {
                    // Sum user + sys percentages
                    let user = extract_pct(l, "user");
                    let sys = extract_pct(l, "sys");
                    Some(user + sys)
                })
        })
        .unwrap_or(0.0);

    Some(ResourceSample {
        offset_ms: 0, // caller fills this in
        cpu_pct,
        mem_used_bytes,
        mem_available_bytes,
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

    Some(ResourceSample {
        offset_ms: 0,
        cpu_pct,
        mem_used_bytes: mem_used,
        mem_available_bytes: mem_available,
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
        .and_then(|l| {
            l.split_whitespace()
                .nth(1)
                .and_then(|v| v.parse().ok())
        })
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
}

impl std::fmt::Debug for ResourceMonitor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResourceMonitor")
            .field("baseline", &self.baseline)
            .field("sample_count", &self.samples.lock().map(|s| s.len()).unwrap_or(0))
            .field("tracked_pid", &self.tracked_pid.load(Ordering::Relaxed))
            .finish()
    }
}

impl ResourceMonitor {
    /// Start background resource monitoring, sampling every `interval_ms` milliseconds.
    pub fn start(interval_ms: u64) -> Self {
        let baseline = capture_system_baseline();
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

        let samples = self
            .samples
            .lock()
            .map(|s| s.clone())
            .unwrap_or_default();

        ResourceReport {
            system_baseline: self.baseline,
            samples,
            process_metrics,
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
            }],
            process_metrics: None,
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
        assert!(report.samples.len() >= 1);
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
}
