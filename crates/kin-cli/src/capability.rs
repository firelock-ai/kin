// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

// Machine capability detection for adaptive locate behavior.
// Determines LocateProfile based on CPU cores + available RAM.
// Override with KIN_LOCATE_PROFILE env var.

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
}

fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(1)
}

#[cfg(target_os = "macos")]
fn available_ram_gb() -> f64 {
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
fn available_ram_gb() -> f64 {
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
fn available_ram_gb() -> f64 {
    // Conservative default for unsupported platforms
    4.0
}
