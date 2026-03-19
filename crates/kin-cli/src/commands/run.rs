// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Firelock, LLC

use anyhow::Result;

/// `kin run <command>` — Execute a validation run and capture evidence.
pub async fn run(command: String) -> Result<()> {
    let _layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;

    let cwd = std::env::current_dir()?;

    println!("Running: {}", command);
    println!();

    let validation = kin_runtime::create_run(kin_runtime::RunOptions {
        label: command.clone(),
        command: command.clone(),
        working_dir: cwd.display().to_string(),
        snapshot_id: None,
    });

    let result = kin_runtime::execute_run(validation)?;

    // Display evidence.
    if let Some(ref evidence) = result.evidence {
        if let Some(ref stdout) = evidence.stdout {
            print!("{}", stdout);
        }
        if let Some(ref stderr) = evidence.stderr {
            eprint!("{}", stderr);
        }
    }

    // Summary.
    println!();
    match result.status {
        kin_runtime::RunStatus::Passed => {
            println!("Run PASSED ({}ms)", result.duration_ms.unwrap_or(0));
        }
        kin_runtime::RunStatus::Failed => {
            println!(
                "Run FAILED (exit code: {}, {}ms)",
                result.exit_code.unwrap_or(-1),
                result.duration_ms.unwrap_or(0)
            );
        }
        other => {
            println!("Run ended with status: {:?}", other);
        }
    }

    // Return error exit code if the run failed.
    if result.status == kin_runtime::RunStatus::Failed {
        std::process::exit(result.exit_code.unwrap_or(1));
    }

    Ok(())
}
