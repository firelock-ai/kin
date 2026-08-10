// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};

async fn daemon_base_url() -> Result<String> {
    let layout = crate::commands::require_repository_layout()?;
    crate::daemon_client::resolve_daemon_url(&layout)
        .await?
        .ok_or_else(|| crate::daemon_client::daemon_required_error("intent commands", &layout))
}

/// `kin intent list` — Show all active intents via daemon API.
pub async fn list() -> Result<()> {
    let client = reqwest::Client::new();
    let daemon_url = daemon_base_url().await?;
    let resp = client
        .get(format!("{}/intent", daemon_url))
        .send()
        .await
        .context("query daemon intent endpoint")?;
    if resp.status().is_success() {
        let body: serde_json::Value = resp.json().await?;
        if let Some(intents) = body.as_array() {
            if intents.is_empty() {
                println!("No active intents.");
                return Ok(());
            }
            println!(
                "{:<36}  {:<36}  {:<6}  DESCRIPTION",
                "INTENT", "SESSION", "LOCK"
            );
            println!("{}", "-".repeat(120));
            for intent in intents {
                let intent_id = intent["intent_id"].as_str().unwrap_or("-");
                let session_id = intent["session_id"].as_str().unwrap_or("-");
                let lock = intent["lock_type"].as_str().unwrap_or("soft");
                let task = intent["task_description"].as_str().unwrap_or("");
                println!(
                    "{:<36}  {:<36}  {:<6}  {}",
                    intent_id, session_id, lock, task
                );

                if let Some(scopes) = intent["scopes"].as_array() {
                    for scope in scopes {
                        println!("  scope: {}", scope.as_str().unwrap_or("-"));
                    }
                }
            }
            println!("\n{} active intent(s).", intents.len());
        }
        Ok(())
    } else {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("daemon returned {}: {}", status, body)
    }
}

/// `kin intent register` — Register a new intent via daemon API.
pub async fn register(
    scope: String,
    lock: String,
    task: String,
    session: Option<String>,
) -> Result<()> {
    let client = reqwest::Client::new();
    let daemon_url = daemon_base_url().await?;

    let body = serde_json::json!({
        "scope": scope,
        "lock_type": lock,
        "task_description": task,
        "session_id": session,
    });

    let resp = client
        .post(format!("{}/intent/register", daemon_url))
        .json(&body)
        .send()
        .await
        .context("query daemon intent register endpoint")?;
    if resp.status().is_success() {
        let result: serde_json::Value = resp.json().await?;
        let intent_id = result["intent_id"].as_str().unwrap_or("unknown");
        let status = result["status"].as_str().unwrap_or("registered");

        println!("Intent {}: {}", status, intent_id);

        if let Some(conflicts) = result["conflicts"].as_array() {
            if !conflicts.is_empty() {
                println!("\nCollisions detected:");
                for c in conflicts {
                    let vendor = c["vendor"].as_str().unwrap_or("unknown");
                    let desc = c["task_description"].as_str().unwrap_or("");
                    let cid = c["intent_id"].as_str().unwrap_or("-");
                    println!("  [{vendor}] {cid} — {desc}");
                }
            }
        }

        if let Some(warnings) = result["downstream_warnings"].as_array() {
            if !warnings.is_empty() {
                println!("\nDownstream warnings:");
                for w in warnings {
                    let vendor = w["vendor"].as_str().unwrap_or("unknown");
                    let desc = w["task_description"].as_str().unwrap_or("");
                    println!("  [warn] [{vendor}] {desc}");
                }
            }
        }

        Ok(())
    } else {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("daemon returned {}: {}", status, body)
    }
}

/// `kin intent release <intent-id>` — Release an intent via daemon API.
pub async fn release(intent_id: String) -> Result<()> {
    let client = reqwest::Client::new();
    let daemon_url = daemon_base_url().await?;

    let resp = client
        .delete(format!("{}/intent/{}", daemon_url, intent_id))
        .send()
        .await
        .context("query daemon intent release endpoint")?;
    if resp.status().is_success() {
        println!("Released intent: {}", intent_id);
        Ok(())
    } else {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("daemon returned {}: {}", status, body)
    }
}

/// `kin intent clear <session-id>` — Clear all intents for a session via daemon API.
pub async fn clear(session_id: String) -> Result<()> {
    let client = reqwest::Client::new();
    let daemon_url = daemon_base_url().await?;

    let resp = client
        .delete(format!("{}/session/{}/intents", daemon_url, session_id))
        .send()
        .await
        .context("query daemon intent clear endpoint")?;
    if resp.status().is_success() {
        let result: serde_json::Value = resp.json().await?;
        let count = result["cleared"].as_u64().unwrap_or(0);
        println!("Cleared {} intent(s) for session {}.", count, session_id);
        Ok(())
    } else {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("daemon returned {}: {}", status, body)
    }
}
