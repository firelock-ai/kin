// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;

use kin_model::{
    AgentSession, EntityId, FilePathId, IntentScope, LockType, SessionCapabilities,
    SessionTransport,
};

/// Default daemon API base URL.
const DAEMON_URL: &str = "http://127.0.0.1:4219";

/// `kin intent list` — Show all active intents via daemon API.
pub async fn list() -> Result<()> {
    let client = reqwest::Client::new();
    match client.get(format!("{}/intent", DAEMON_URL)).send().await {
        Ok(resp) if resp.status().is_success() => {
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
        }
        _ => {
            // Fallback to direct graph access when daemon is not running.
            list_direct().await
        }
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

    let body = serde_json::json!({
        "scope": scope,
        "lock_type": lock,
        "task_description": task,
        "session_id": session,
    });

    match client
        .post(format!("{}/intent/register", DAEMON_URL))
        .json(&body)
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
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
        }
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("daemon returned {}: {}", status, body)
        }
        Err(_) => {
            // Fallback to direct graph access when daemon is not running.
            register_direct(scope, lock, task, session).await
        }
    }
}

/// `kin intent release <intent-id>` — Release an intent via daemon API.
pub async fn release(intent_id: String) -> Result<()> {
    let client = reqwest::Client::new();

    match client
        .delete(format!("{}/intent/{}", DAEMON_URL, intent_id))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            println!("Released intent: {}", intent_id);
            Ok(())
        }
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("daemon returned {}: {}", status, body)
        }
        Err(_) => release_direct(intent_id).await,
    }
}

/// `kin intent clear <session-id>` — Clear all intents for a session via daemon API.
pub async fn clear(session_id: String) -> Result<()> {
    let client = reqwest::Client::new();

    match client
        .delete(format!("{}/session/{}/intents", DAEMON_URL, session_id))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            let result: serde_json::Value = resp.json().await?;
            let count = result["cleared"].as_u64().unwrap_or(0);
            println!("Cleared {} intent(s) for session {}.", count, session_id);
            Ok(())
        }
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("daemon returned {}: {}", status, body)
        }
        Err(_) => clear_direct(session_id).await,
    }
}

// ── Direct graph fallbacks (when daemon is not running) ──────────────

fn open_snapshot() -> Result<(kin_core::KinLayout, kin_db::SnapshotManager)> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let snapshot = kin_db::SnapshotManager::open(crate::backend::kindb_snapshot_path(&layout))?;
    Ok((layout, snapshot))
}

fn ensure_cli_session(
    graph: &kin_db::InMemoryGraph,
    session_id: kin_model::SessionId,
    cwd: std::path::PathBuf,
) -> Result<()> {
    if graph.get_session(&session_id)?.is_some() {
        return Ok(());
    }

    let now = kin_model::Timestamp::now();
    graph.upsert_session(&AgentSession {
        session_id,
        vendor: "kin-cli".to_string(),
        client_name: "kin intent".to_string(),
        transport: SessionTransport::Cli,
        pid: Some(std::process::id()),
        cwd,
        started_at: now.clone(),
        last_heartbeat: now,
        capabilities: SessionCapabilities {
            can_read: true,
            can_write: true,
            can_execute: false,
            can_branch: true,
            can_commit: true,
            max_concurrent_intents: 1,
        },
    })?;
    Ok(())
}

async fn list_direct() -> Result<()> {
    let (_layout, snapshot) = open_snapshot()?;
    let graph = snapshot.graph();
    let graph = &*graph;

    let intents = graph.list_all_intents()?;

    if intents.is_empty() {
        println!("No active intents.");
        return Ok(());
    }

    println!(
        "{:<36}  {:<36}  {:<6}  DESCRIPTION",
        "INTENT", "SESSION", "LOCK"
    );
    println!("{}", "-".repeat(120));

    for intent in &intents {
        let lock_label = match intent.lock_type {
            LockType::Hard => "hard",
            LockType::Soft => "soft",
        };
        println!(
            "{:<36}  {:<36}  {:<6}  {}",
            intent.intent_id, intent.session_id, lock_label, intent.task_description,
        );

        for scope in &intent.scopes {
            let scope_str = format_scope(scope);
            println!("  scope: {}", scope_str);
        }
    }

    println!("\n{} active intent(s).", intents.len());
    Ok(())
}

async fn register_direct(
    scope: String,
    lock: String,
    task: String,
    session: Option<String>,
) -> Result<()> {
    use kin_model::{Intent, IntentId, SessionId, Timestamp};

    let (layout, snapshot) = open_snapshot()?;
    let graph = snapshot.graph();
    let graph = &*graph;

    let lock_type = parse_lock_type(&lock)?;
    let intent_scope = parse_scope(&scope)?;

    let session_id = match session {
        Some(s) => {
            let uuid = uuid::Uuid::parse_str(&s)
                .map_err(|_| anyhow::anyhow!("invalid session UUID: {}", s))?;
            SessionId(uuid)
        }
        None => SessionId::new(),
    };
    ensure_cli_session(graph, session_id, layout.working_dir().to_path_buf())?;

    let intent = Intent {
        intent_id: IntentId::new(),
        session_id,
        scopes: vec![intent_scope],
        lock_type,
        task_description: task,
        registered_at: Timestamp::now(),
        expires_at: None,
    };

    graph.register_intent(&intent)?;
    snapshot.save()?;

    println!("Registered intent: {}", intent.intent_id);
    println!("  session: {}", intent.session_id);
    println!("  lock: {:?}", intent.lock_type);
    println!("  scope: {}", format_scope(&intent.scopes[0]));
    println!("  task: {}", intent.task_description);
    println!("  (daemon not running — registered directly in graph)");

    Ok(())
}

async fn release_direct(intent_id: String) -> Result<()> {
    use kin_model::IntentId;

    let (_layout, snapshot) = open_snapshot()?;
    let graph = snapshot.graph();
    let graph = &*graph;

    let uuid = uuid::Uuid::parse_str(&intent_id)
        .map_err(|_| anyhow::anyhow!("invalid intent UUID: {}", intent_id))?;
    let id = IntentId(uuid);

    let existing = graph.get_intent(&id)?;
    if existing.is_none() {
        anyhow::bail!("intent not found: {}", intent_id);
    }

    graph.delete_intent(&id)?;
    snapshot.save()?;
    println!("Released intent: {}", intent_id);
    println!("  (daemon not running — released directly in graph)");

    Ok(())
}

async fn clear_direct(session_id: String) -> Result<()> {
    use kin_model::SessionId;

    let (_layout, snapshot) = open_snapshot()?;
    let graph = snapshot.graph();
    let graph = &*graph;

    let uuid = uuid::Uuid::parse_str(&session_id)
        .map_err(|_| anyhow::anyhow!("invalid session UUID: {}", session_id))?;
    let sid = SessionId(uuid);

    let intents = graph.list_intents_for_session(&sid)?;

    if intents.is_empty() {
        println!("No active intents for session {}.", session_id);
        return Ok(());
    }

    for intent in &intents {
        graph.delete_intent(&intent.intent_id)?;
    }
    snapshot.save()?;

    println!(
        "Cleared {} intent(s) for session {}.",
        intents.len(),
        session_id
    );
    println!("  (daemon not running — cleared directly in graph)");

    Ok(())
}

// ── Helpers ──────────────────────────────────────────────────────────

fn parse_lock_type(s: &str) -> Result<LockType> {
    match s.to_lowercase().as_str() {
        "hard" => Ok(LockType::Hard),
        "soft" => Ok(LockType::Soft),
        _ => anyhow::bail!("invalid lock type '{}': expected 'hard' or 'soft'", s),
    }
}

fn parse_scope(s: &str) -> Result<IntentScope> {
    if let Some(rest) = s.strip_prefix("entity:") {
        let uuid = uuid::Uuid::parse_str(rest)
            .map_err(|_| anyhow::anyhow!("invalid entity UUID: {}", rest))?;
        Ok(IntentScope::Entity(EntityId(uuid)))
    } else if let Some(rest) = s.strip_prefix("file:") {
        Ok(IntentScope::Artifact(FilePathId::new(rest)))
    } else if let Ok(uuid) = uuid::Uuid::parse_str(s) {
        Ok(IntentScope::Entity(EntityId(uuid)))
    } else {
        Ok(IntentScope::Artifact(FilePathId::new(s)))
    }
}

fn format_scope(scope: &IntentScope) -> String {
    match scope {
        IntentScope::Entity(id) => format!("entity:{}", id),
        IntentScope::Contract(id) => format!("contract:{}", id),
        IntentScope::Artifact(id) => format!("file:{}", id),
    }
}
