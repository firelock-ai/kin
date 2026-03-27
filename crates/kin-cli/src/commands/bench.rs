// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::env;
use std::process::{Command, exit};

/// Proxy `kin bench` to the external `kin-bench` binary.
///
/// The benchmark engine lives in the `kin-bench` repo and is distributed
/// as a separate binary. `kin bench` is a convenience alias that delegates
/// to `kin-bench` with all arguments forwarded.
pub fn bench_proxy(args: &[String]) -> ! {
    // Forward the current kin binary path so kin-bench can re-enter the same
    // build without requiring a separate `kin` install on clean machines.
    let mut cmd = Command::new("kin-bench");
    cmd.args(args);
    if env::var_os("KIN_BINARY_PATH").is_none() {
        if let Ok(current_exe) = env::current_exe() {
            cmd.env("KIN_BINARY_PATH", current_exe);
        }
    }

    // Try to find kin-bench in PATH.
    match cmd.status() {
        Ok(status) => {
            exit(status.code().unwrap_or(1));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("kin-bench is not installed.");
            eprintln!();
            eprintln!("The benchmark engine is distributed separately. Install it with:");
            eprintln!();
            eprintln!("  cargo install --git https://github.com/firelock-ai/kin-bench kin-bench-cli");
            eprintln!();
            eprintln!("Or build from source:");
            eprintln!();
            eprintln!("  git clone https://github.com/firelock-ai/kin-bench");
            eprintln!("  cd kin-bench && cargo install --path crates/kin-bench-cli");
            eprintln!();
            eprintln!("Once installed, `kin bench` will delegate to `kin-bench`.");
            exit(1);
        }
        Err(e) => {
            eprintln!("Failed to execute kin-bench: {e}");
            exit(1);
        }
    }
}
