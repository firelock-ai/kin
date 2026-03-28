// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{bail, Context, Result};

use super::remote;

fn base_url() -> String {
    std::env::var("KIN_API_URL")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "https://kinlab.ai".to_string())
        .trim_end_matches('/')
        .to_string()
}

fn resolve_org_id() -> Result<String> {
    std::env::var("KIN_ORG_ID")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("KIN_ORG_ID not set — set it or configure a native remote"))
}

fn resolve_repo_id() -> Result<String> {
    if let Ok(val) = std::env::var("KIN_REPO_ID") {
        let trimmed = val.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    layout
        .working_dir()
        .file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow::anyhow!("could not determine repo ID from workspace path"))
}

fn client_with_auth(base: &str) -> Result<(reqwest::Client, reqwest::header::HeaderMap)> {
    let client = reqwest::Client::new();
    let mut headers = reqwest::header::HeaderMap::new();
    if let Some(token) = remote::native_remote_bearer_token(base) {
        headers.insert(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", token)
                .parse()
                .context("invalid auth token")?,
        );
    } else {
        bail!(
            "No auth token found. Run `kin auth login` or set KIN_REMOTE_BEARER_TOKEN / KINLAB_TOKEN."
        );
    }
    Ok((client, headers))
}

/// List pipelines for the current repo.
pub async fn list() -> Result<()> {
    let base = base_url();
    let org = resolve_org_id()?;
    let repo = resolve_repo_id()?;
    let (client, headers) = client_with_auth(&base)?;
    let url = format!("{}/api/orgs/{}/repos/{}/pipelines", base, org, repo);

    let resp = client
        .get(&url)
        .headers(headers)
        .send()
        .await
        .context("failed to reach KinLab API")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("failed to list pipelines ({}): {}", status, body);
    }

    let json: serde_json::Value = resp.json().await.context("invalid JSON response")?;
    let pipelines = json
        .get("pipelines")
        .and_then(|p| p.as_array())
        .cloned()
        .unwrap_or_default();

    if pipelines.is_empty() {
        println!("No pipelines configured.");
        return Ok(());
    }

    println!("Pipelines:");
    for pipeline in &pipelines {
        let name = pipeline.get("name").and_then(|n| n.as_str()).unwrap_or("?");
        let status = pipeline
            .get("status")
            .and_then(|s| s.as_str())
            .unwrap_or("unknown");
        let last_run = pipeline
            .get("lastRunAt")
            .and_then(|l| l.as_str())
            .unwrap_or("never");
        println!("  {} [{}] (last run: {})", name, status, last_run);
    }

    Ok(())
}

/// Manually trigger a pipeline run.
pub async fn run_pipeline(name: String) -> Result<()> {
    let base = base_url();
    let org = resolve_org_id()?;
    let repo = resolve_repo_id()?;
    let (client, headers) = client_with_auth(&base)?;
    let url = format!("{}/api/orgs/{}/repos/{}/pipelines/run", base, org, repo);

    let resp = client
        .post(&url)
        .headers(headers)
        .json(&serde_json::json!({ "name": name }))
        .send()
        .await
        .context("failed to reach KinLab API")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!(
            "failed to trigger pipeline '{}' ({}): {}",
            name,
            status,
            body
        );
    }

    let json: serde_json::Value = resp.json().await.context("invalid JSON response")?;
    let run_id = json
        .get("runId")
        .and_then(|r| r.as_str())
        .unwrap_or("unknown");
    println!("Pipeline '{}' triggered. Run ID: {}", name, run_id);

    Ok(())
}

/// Fetch logs for a pipeline run.
pub async fn logs(run_id: String) -> Result<()> {
    let base = base_url();
    let org = resolve_org_id()?;
    let repo = resolve_repo_id()?;
    let (client, headers) = client_with_auth(&base)?;
    let url = format!(
        "{}/api/orgs/{}/repos/{}/pipelines/{}/logs",
        base, org, repo, run_id
    );

    let resp = client
        .get(&url)
        .headers(headers)
        .send()
        .await
        .context("failed to reach KinLab API")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!(
            "failed to get logs for run '{}' ({}): {}",
            run_id,
            status,
            body
        );
    }

    let json: serde_json::Value = resp.json().await.context("invalid JSON response")?;
    let lines = json
        .get("lines")
        .and_then(|l| l.as_array())
        .cloned()
        .unwrap_or_default();

    if lines.is_empty() {
        println!("No log output for run '{}'.", run_id);
        return Ok(());
    }

    for line in &lines {
        let text = line.as_str().unwrap_or("");
        println!("{}", text);
    }

    Ok(())
}

/// Cancel a running pipeline.
pub async fn cancel(run_id: String) -> Result<()> {
    let base = base_url();
    let org = resolve_org_id()?;
    let repo = resolve_repo_id()?;
    let (client, headers) = client_with_auth(&base)?;
    let url = format!(
        "{}/api/orgs/{}/repos/{}/pipelines/{}/cancel",
        base, org, repo, run_id
    );

    let resp = client
        .post(&url)
        .headers(headers)
        .send()
        .await
        .context("failed to reach KinLab API")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("failed to cancel run '{}' ({}): {}", run_id, status, body);
    }

    println!("Pipeline run '{}' cancelled.", run_id);
    Ok(())
}
