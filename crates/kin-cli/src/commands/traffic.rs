// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};

async fn daemon_base_url() -> Result<String> {
    let layout = crate::commands::require_repository_layout()?;
    crate::daemon_client::resolve_daemon_url(&layout)
        .await?
        .ok_or_else(|| crate::daemon_client::daemon_required_error("traffic commands", &layout))
}

/// `kin traffic show <scope>` — Show active traffic via daemon API.
pub async fn run(scope: String) -> Result<()> {
    let client = reqwest::Client::new();
    let daemon_url = daemon_base_url().await?;

    let resp = client
        .get(format!("{}/traffic/{}", daemon_url, urlencoded(&scope)))
        .send()
        .await
        .context("query daemon traffic endpoint")?;
    if resp.status().is_success() {
        let body: serde_json::Value = resp.json().await?;
        println!("Traffic report for: {}", scope);
        println!();

        let active = body["active_intents"].as_array();
        let downstream = body["downstream_warnings"].as_array();

        let has_active = active.is_some_and(|a| !a.is_empty());
        let has_downstream = downstream.is_some_and(|d| !d.is_empty());

        if !has_active && !has_downstream {
            println!("  No active traffic on this scope.");
            return Ok(());
        }

        if let Some(intents) = active {
            if !intents.is_empty() {
                println!("Direct locks ({}):", intents.len());
                for intent in intents {
                    let lock = intent["lock_type"].as_str().unwrap_or("soft");
                    let lock_label = if lock == "Hard" || lock == "hard" {
                        "HARD"
                    } else {
                        "soft"
                    };
                    let id = intent["intent_id"].as_str().unwrap_or("-");
                    let session = intent["session_id"].as_str().unwrap_or("-");
                    let task = intent["task_description"].as_str().unwrap_or("");
                    println!("  [{lock_label}] {id} (session: {session}, task: \"{task}\")");
                }
                println!();
            }
        }

        if let Some(warnings) = downstream {
            if !warnings.is_empty() {
                println!("Downstream warnings ({}):", warnings.len());
                for w in warnings {
                    let id = w["intent_id"].as_str().unwrap_or("-");
                    let session = w["session_id"].as_str().unwrap_or("-");
                    let task = w["task_description"].as_str().unwrap_or("");
                    println!("  [warn] {id} (session: {session}, task: \"{task}\")");
                }
                println!();
            }
        }

        // Summary
        let hard_count = body["hard_blocks"].as_u64().unwrap_or(0);
        let soft_count = body["soft_locks"].as_u64().unwrap_or(0);
        let downstream_count = body["downstream_count"].as_u64().unwrap_or(0);

        if hard_count > 0 {
            println!(
                "Status: BLOCKED ({} hard lock(s), {} soft lock(s))",
                hard_count, soft_count
            );
        } else if soft_count > 0 || downstream_count > 0 {
            println!(
                "Status: CAUTION ({} soft lock(s), {} downstream warning(s))",
                soft_count, downstream_count
            );
        }

        Ok(())
    } else {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("daemon returned {}: {}", status, body)
    }
}

/// `kin traffic sessions` — List active sessions via daemon API.
pub async fn sessions() -> Result<()> {
    let client = reqwest::Client::new();
    let daemon_url = daemon_base_url().await?;

    let resp = client
        .get(format!("{}/session", daemon_url))
        .send()
        .await
        .context("query daemon sessions endpoint")?;
    if resp.status().is_success() {
        let body: serde_json::Value = resp.json().await?;

        if let Some(sessions) = body.as_array() {
            if sessions.is_empty() {
                println!("No active sessions.");
                return Ok(());
            }

            println!(
                "{:<36}  {:<15}  {:<8}  {:<10}  LAST HEARTBEAT",
                "SESSION", "VENDOR", "TRANSPORT", "PID"
            );
            println!("{}", "-".repeat(110));

            for s in sessions {
                let id = s["session_id"].as_str().unwrap_or("-");
                let vendor = s["vendor"].as_str().unwrap_or("-");
                let transport = s["transport"].as_str().unwrap_or("-");
                let pid = s["pid"].as_u64().map_or("-".to_string(), |p| p.to_string());
                let heartbeat = s["last_heartbeat"].as_str().unwrap_or("-");
                println!(
                    "{:<36}  {:<15}  {:<8}  {:<10}  {}",
                    id, vendor, transport, pid, heartbeat
                );
            }

            println!("\n{} active session(s).", sessions.len());
        }

        Ok(())
    } else {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("daemon returned {}: {}", status, body)
    }
}

fn urlencoded(s: &str) -> String {
    s.replace(':', "%3A").replace('/', "%2F")
}
