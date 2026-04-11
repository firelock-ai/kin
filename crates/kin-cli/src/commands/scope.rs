// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{bail, Result};

use crate::daemon_client::DaemonClient;

/// Resolve session ID from --session flag or KIN_SESSION_ID env var.
fn resolve_session_id(session: Option<&str>) -> Result<String> {
    if let Some(s) = session {
        return Ok(s.to_string());
    }
    if let Ok(s) = std::env::var("KIN_SESSION_ID") {
        if !s.is_empty() {
            return Ok(s);
        }
    }
    bail!("no session ID provided. Use --session <id> or set KIN_SESSION_ID")
}

pub async fn run(
    ref_string: Option<&str>,
    clear: bool,
    show: bool,
    session: Option<&str>,
) -> Result<()> {
    let session_id = resolve_session_id(session)?;
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let daemon_url = crate::daemon_client::resolve_daemon_url(&layout)
        .await?
        .ok_or_else(|| anyhow::anyhow!("daemon not available"))?;
    let client = DaemonClient::from_base_url(daemon_url)?;

    if clear {
        client.clear_scope(&session_id).await?;
        println!("Scope cleared. Queries now use the live HEAD graph.");
        return Ok(());
    }

    if show || ref_string.is_none() {
        match client.get_scope(&session_id).await? {
            Some(scope) => {
                println!("Active scope:");
                println!("  ref:       {}", scope.ref_string);
                println!("  head:      {}", scope.head);
                println!("  age:       {}s ago", scope.created_at_secs_ago);
                println!("  ttl:       {}s remaining", scope.ttl_remaining_secs);
            }
            None => {
                if show {
                    println!("No active scope. Queries use the live HEAD graph.");
                } else {
                    println!("Usage: kin scope <ref>     Set scope to a historical ref");
                    println!("       kin scope --clear   Clear the current scope");
                    println!("       kin scope --show    Show the current scope");
                }
            }
        }
        return Ok(());
    }

    let ref_str = ref_string.unwrap();
    let scope = client.set_scope(&session_id, ref_str).await?;
    println!(
        "Scope set to {} (head: {})",
        scope.ref_string,
        &scope.head[..12.min(scope.head.len())]
    );
    println!("All subsequent queries will use this historical graph view.");
    println!("Use `kin scope --clear` to return to HEAD.");

    Ok(())
}
