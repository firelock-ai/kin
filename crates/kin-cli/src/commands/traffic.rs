use anyhow::Result;

use kin_model::{EntityId, IntentScope, LockType};

/// Default daemon API base URL.
const DAEMON_URL: &str = "http://127.0.0.1:4219";

/// `kin traffic show <scope>` — Show active traffic via daemon API.
pub async fn run(scope: String) -> Result<()> {
    let client = reqwest::Client::new();

    match client
        .get(format!("{}/traffic/{}", DAEMON_URL, urlencoded(&scope)))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
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
        }
        _ => {
            // Fallback to direct graph access when daemon is not running.
            run_direct(scope).await
        }
    }
}

/// `kin traffic sessions` — List active sessions via daemon API.
pub async fn sessions() -> Result<()> {
    let client = reqwest::Client::new();

    match client.get(format!("{}/session", DAEMON_URL)).send().await {
        Ok(resp) if resp.status().is_success() => {
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
        }
        _ => {
            // Fallback to direct graph access when daemon is not running.
            sessions_direct().await
        }
    }
}

// ── Direct graph fallbacks (when daemon is not running) ──────────────

async fn run_direct(scope: String) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let _snap = kin_db::SnapshotManager::open(crate::backend::kindb_snapshot_path(&layout))?;
    let graph = &*_snap.graph();

    let target = parse_scope(&scope)?;

    let all_intents = graph.list_all_intents()?;

    let mut direct_locks = Vec::new();
    let mut downstream = Vec::new();

    for intent in &all_intents {
        let direct_hit = intent.scopes.iter().any(|s| s == &target);
        if direct_hit {
            direct_locks.push(intent);
            continue;
        }

        if let IntentScope::Entity(target_id) = &target {
            let locks_entity = graph.locks_for_entity(target_id)?;
            if locks_entity.iter().any(|l| l.intent_id == intent.intent_id) {
                downstream.push(intent);
            }
        }
    }

    println!("Traffic report for: {}", format_scope(&target));
    println!("  (daemon not running — queried graph directly)");
    println!();

    if direct_locks.is_empty() && downstream.is_empty() {
        println!("  No active traffic on this scope.");
        return Ok(());
    }

    if !direct_locks.is_empty() {
        println!("Direct locks ({}):", direct_locks.len());
        for intent in &direct_locks {
            let lock_label = match intent.lock_type {
                LockType::Hard => "HARD",
                LockType::Soft => "soft",
            };
            println!(
                "  [{lock_label}] {} (session: {}, task: \"{}\")",
                intent.intent_id, intent.session_id, intent.task_description,
            );
        }
        println!();
    }

    if !downstream.is_empty() {
        println!("Downstream warnings ({}):", downstream.len());
        for intent in &downstream {
            println!(
                "  [warn] {} (session: {}, task: \"{}\")",
                intent.intent_id, intent.session_id, intent.task_description,
            );
        }
        println!();
    }

    let hard_count = direct_locks
        .iter()
        .filter(|i| i.lock_type == LockType::Hard)
        .count();
    let soft_count = direct_locks
        .iter()
        .filter(|i| i.lock_type == LockType::Soft)
        .count();

    if hard_count > 0 {
        println!(
            "Status: BLOCKED ({} hard lock(s), {} soft lock(s))",
            hard_count, soft_count
        );
    } else if soft_count > 0 || !downstream.is_empty() {
        println!(
            "Status: CAUTION ({} soft lock(s), {} downstream warning(s))",
            soft_count,
            downstream.len()
        );
    }

    Ok(())
}

async fn sessions_direct() -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let _snap = kin_db::SnapshotManager::open(crate::backend::kindb_snapshot_path(&layout))?;
    let graph = &*_snap.graph();

    let all_sessions = graph.list_sessions()?;

    if all_sessions.is_empty() {
        println!("No active sessions.");
        return Ok(());
    }

    println!(
        "{:<36}  {:<15}  {:<8}  {:<10}  LAST HEARTBEAT",
        "SESSION", "VENDOR", "TRANSPORT", "PID"
    );
    println!("{}", "-".repeat(110));

    for s in &all_sessions {
        let transport = format!("{:?}", s.transport);
        let pid = s.pid.map_or("-".to_string(), |p| p.to_string());
        println!(
            "{:<36}  {:<15}  {:<8}  {:<10}  {}",
            s.session_id, s.vendor, transport, pid, s.last_heartbeat,
        );
    }

    println!("\n{} active session(s).", all_sessions.len());
    println!("  (daemon not running — queried graph directly)");
    Ok(())
}

// ── Helpers ──────────────────────────────────────────────────────────

fn parse_scope(s: &str) -> Result<IntentScope> {
    if let Some(rest) = s.strip_prefix("entity:") {
        let uuid = uuid::Uuid::parse_str(rest)
            .map_err(|_| anyhow::anyhow!("invalid entity UUID: {}", rest))?;
        Ok(IntentScope::Entity(EntityId(uuid)))
    } else if let Some(rest) = s.strip_prefix("file:") {
        Ok(IntentScope::Artifact(kin_model::FilePathId::new(rest)))
    } else if let Ok(uuid) = uuid::Uuid::parse_str(s) {
        Ok(IntentScope::Entity(EntityId(uuid)))
    } else {
        Ok(IntentScope::Artifact(kin_model::FilePathId::new(s)))
    }
}

fn format_scope(scope: &IntentScope) -> String {
    match scope {
        IntentScope::Entity(id) => format!("entity:{}", id),
        IntentScope::Contract(id) => format!("contract:{}", id),
        IntentScope::Artifact(id) => format!("file:{}", id),
    }
}

fn urlencoded(s: &str) -> String {
    s.replace(':', "%3A").replace('/', "%2F")
}
