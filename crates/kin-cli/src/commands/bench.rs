// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::env;
use std::path::PathBuf;
use std::process::{exit, Command};

/// Proxy `kin bench` to external benchmark binaries.
///
/// - `kin bench prep ...` → dispatches to `kin-bench-prep`
/// - `kin bench ...`      → dispatches to `kin-bench`
///
/// Each binary is optional. If not found, install instructions are shown.
pub fn bench_proxy(args: &[String]) -> ! {
    match args.first().map(|a| a.as_str()) {
        Some("prep") => dispatch("kin-bench-prep", &args[1..]),
        Some("run") => dispatch("kin-bench-run", &args[1..]),
        Some("eval") => dispatch("kin-bench-eval", &args[1..]),
        Some("autotune") => dispatch("kin-bench-autotune", &args[1..]),
        _ => dispatch("kin-bench", args),
    }
}

fn dispatch(bin_name: &str, args: &[String]) -> ! {
    let bin_path = find_bin(bin_name);

    match bin_path {
        Some(path) => {
            let mut cmd = Command::new(&path);
            cmd.args(args);

            // Clear VFS shim so benchmarks don't crash
            cmd.env_remove("DYLD_INSERT_LIBRARIES");
            cmd.env_remove("LD_PRELOAD");

            // Forward kin binary path for sub-tools
            if env::var_os("KIN_BINARY_PATH").is_none() {
                if let Ok(current_exe) = env::current_exe() {
                    cmd.env("KIN_BINARY_PATH", current_exe);
                }
            }

            match cmd.status() {
                Ok(status) => exit(status.code().unwrap_or(1)),
                Err(e) => {
                    eprintln!("Failed to execute {bin_name}: {e}");
                    exit(1);
                }
            }
        }
        None => {
            eprintln!("{bin_name} is not installed.");
            eprintln!();
            eprintln!("Install it:");
            eprintln!();
            eprintln!("  cd kin-bench && cargo build --release -p {bin_name}");
            eprintln!("  cp target/release/{bin_name} ~/.kin/bin/");
            eprintln!();
            eprintln!("Once installed, `kin bench` will find it automatically.");
            exit(1);
        }
    }
}

fn find_bin(name: &str) -> Option<PathBuf> {
    let home = env::var("HOME").unwrap_or_default();
    // Prefer the -real binary (avoids shell wrapper DYLD issues)
    let real_path = PathBuf::from(&home)
        .join(".kin/bin")
        .join(format!("{name}-real"));
    if real_path.exists() {
        return Some(real_path);
    }
    // Fall back to the wrapper/binary
    let home_path = PathBuf::from(&home).join(".kin/bin").join(name);
    if home_path.exists() {
        return Some(home_path);
    }

    // Check PATH
    Command::new("which")
        .arg(name)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| {
            let p = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if p.is_empty() {
                None
            } else {
                Some(PathBuf::from(p))
            }
        })
}
