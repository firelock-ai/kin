// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};

use super::locate_telemetry::{consent_marker_path, telemetry_dir};

pub async fn run_status() -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;

    let kin_root = layout.root();
    let consent_path = consent_marker_path(kin_root);
    let spool_dir = telemetry_dir(kin_root);

    let env_val = std::env::var("KIN_LOCATE_TELEMETRY").ok();
    let consent_marker = consent_path.exists();
    let enabled =
        super::locate_telemetry::telemetry_enabled(env_val.as_deref(), consent_marker);

    println!("Telemetry status: {}", if enabled { "ON" } else { "OFF" });
    println!();

    if let Some(ref val) = env_val {
        println!("  KIN_LOCATE_TELEMETRY={val}  (env override — takes precedence)");
    }

    if consent_marker {
        println!("  Consent marker present: {}", consent_path.display());
    } else {
        println!(
            "  No consent marker at {}",
            consent_path.display()
        );
    }

    if spool_dir.is_dir() {
        let (files, bytes) = spool_size(&spool_dir)?;
        println!();
        println!("  Spool directory: {}", spool_dir.display());
        println!("  Spool files:     {files}");
        println!("  Spool size:      {} bytes", bytes);
    } else {
        println!();
        println!("  No spool data ({})", spool_dir.display());
    }

    println!();
    println!("What is collected (locate queries only):");
    println!("  - query text, result ranking, signal scores");
    println!("  - timestamp, max_files requested");
    println!("  - NOT: file contents, entity payloads, diff data");
    println!();
    println!(
        "Run `kin telemetry consent`  to opt in."
    );
    println!("Run `kin telemetry revoke`   to revoke consent.");
    println!("Run `kin telemetry purge`    to delete all spool files.");
    println!("See PRIVACY.md for the full privacy policy.");

    Ok(())
}

pub async fn run_consent() -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;

    let kin_root = layout.root();
    let consent_path = consent_marker_path(kin_root);
    let spool_dir = telemetry_dir(kin_root);

    std::fs::create_dir_all(&spool_dir)
        .with_context(|| format!("could not create telemetry directory {}", spool_dir.display()))?;
    std::fs::write(&consent_path, "")
        .with_context(|| format!("could not write consent marker {}", consent_path.display()))?;

    println!("Telemetry consent recorded at {}.", consent_path.display());
    println!("Locate queries will now be spooled locally.");
    println!("Nothing is uploaded. Run `kin telemetry revoke` to opt out.");

    Ok(())
}

pub async fn run_revoke() -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;

    let kin_root = layout.root();
    let consent_path = consent_marker_path(kin_root);

    if consent_path.exists() {
        std::fs::remove_file(&consent_path).with_context(|| {
            format!("could not remove consent marker {}", consent_path.display())
        })?;
        println!("Telemetry consent revoked. No further queries will be spooled.");
    } else {
        println!("No consent marker found — telemetry was already off.");
    }

    println!(
        "Existing spool data remains at {}. Run `kin telemetry purge` to delete it.",
        telemetry_dir(kin_root).display()
    );

    Ok(())
}

pub async fn run_purge() -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;

    let kin_root = layout.root();
    let spool_dir = telemetry_dir(kin_root);

    if !spool_dir.is_dir() {
        println!("No telemetry spool data found at {}.", spool_dir.display());
        return Ok(());
    }

    let (files, bytes) = spool_size(&spool_dir)?;

    for entry in std::fs::read_dir(&spool_dir)
        .with_context(|| format!("could not read {}", spool_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("jsonl") {
            std::fs::remove_file(&path)
                .with_context(|| format!("could not delete {}", path.display()))?;
        }
    }

    println!(
        "Purged {files} spool file(s) ({bytes} bytes) from {}.",
        spool_dir.display()
    );

    Ok(())
}

fn spool_size(dir: &std::path::Path) -> Result<(usize, u64)> {
    let mut count = 0usize;
    let mut total_bytes = 0u64;
    for entry in std::fs::read_dir(dir)
        .with_context(|| format!("could not read spool directory {}", dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("jsonl") {
            count += 1;
            total_bytes += entry.metadata()?.len();
        }
    }
    Ok((count, total_bytes))
}
