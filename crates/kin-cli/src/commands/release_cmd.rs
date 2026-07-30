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
    let layout = crate::commands::require_repository_layout()?;
    remote::resolve_repo_id(&layout)
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

/// Create a hosted release.
pub async fn create(tag: String, name: Option<String>, notes: Option<String>) -> Result<()> {
    let base = base_url();
    let org = resolve_org_id()?;
    let repo = resolve_repo_id()?;
    let (client, headers) = client_with_auth(&base)?;
    let url = format!("{}/api/orgs/{}/repos/{}/releases", base, org, repo);

    let mut body = serde_json::json!({ "tag": tag });
    if let Some(n) = &name {
        body["name"] = serde_json::json!(n);
    }
    if let Some(n) = &notes {
        body["notes"] = serde_json::json!(n);
    }

    let resp = client
        .post(&url)
        .headers(headers)
        .json(&body)
        .send()
        .await
        .context("failed to reach KinLab API")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let err = resp.text().await.unwrap_or_default();
        bail!("failed to create release '{}' ({}): {}", tag, status, err);
    }

    let json: serde_json::Value = resp.json().await.context("invalid JSON response")?;
    let release_id = json
        .get("releaseId")
        .and_then(|r| r.as_str())
        .unwrap_or("unknown");
    println!(
        "Release '{}' created (tag: {}, id: {}).",
        name.as_deref().unwrap_or(&tag),
        tag,
        release_id
    );

    Ok(())
}

/// List hosted releases.
pub async fn list() -> Result<()> {
    let base = base_url();
    let org = resolve_org_id()?;
    let repo = resolve_repo_id()?;
    let (client, headers) = client_with_auth(&base)?;
    let url = format!("{}/api/orgs/{}/repos/{}/releases", base, org, repo);

    let resp = client
        .get(&url)
        .headers(headers)
        .send()
        .await
        .context("failed to reach KinLab API")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("failed to list releases ({}): {}", status, body);
    }

    let json: serde_json::Value = resp.json().await.context("invalid JSON response")?;
    let releases = json
        .get("releases")
        .and_then(|r| r.as_array())
        .cloned()
        .unwrap_or_default();

    if releases.is_empty() {
        println!("No releases found.");
        return Ok(());
    }

    println!("Releases:");
    for rel in &releases {
        let tag = rel.get("tag").and_then(|t| t.as_str()).unwrap_or("?");
        let name = rel.get("name").and_then(|n| n.as_str()).unwrap_or(tag);
        let created = rel.get("createdAt").and_then(|c| c.as_str()).unwrap_or("");
        let id = rel.get("id").and_then(|i| i.as_str()).unwrap_or("");
        println!("  {} ({}) [{}] — {}", name, tag, id, created);
    }

    Ok(())
}

/// Upload an artifact to an existing release.
pub async fn upload(release_id: String, file: String) -> Result<()> {
    let path = std::path::Path::new(&file);
    if !path.exists() {
        bail!("file not found: {}", file);
    }

    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("artifact")
        .to_string();
    let file_bytes =
        std::fs::read(path).with_context(|| format!("failed to read file: {}", file))?;

    let base = base_url();
    let org = resolve_org_id()?;
    let repo = resolve_repo_id()?;
    let (client, headers) = client_with_auth(&base)?;
    let url = format!(
        "{}/api/orgs/{}/repos/{}/releases/{}/artifacts",
        base, org, repo, release_id
    );

    let resp = client
        .post(&url)
        .headers(headers)
        .header("content-type", "application/octet-stream")
        .header("x-artifact-name", &file_name)
        .body(file_bytes)
        .send()
        .await
        .context("failed to reach KinLab API")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!(
            "failed to upload '{}' to release '{}' ({}): {}",
            file_name,
            release_id,
            status,
            body
        );
    }

    println!("Uploaded '{}' to release '{}'.", file_name, release_id);
    Ok(())
}
