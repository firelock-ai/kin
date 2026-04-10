// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{bail, Context, Result};
use std::io::Read;

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
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
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

/// Set an org-level secret (value read from stdin).
pub async fn set(name: String) -> Result<()> {
    let mut value = String::new();
    std::io::stdin()
        .read_to_string(&mut value)
        .context("failed to read secret value from stdin")?;
    let value = value.trim().to_string();
    if value.is_empty() {
        bail!("secret value cannot be empty");
    }

    let base = base_url();
    let org = resolve_org_id()?;
    let (client, headers) = client_with_auth(&base)?;
    let url = format!("{}/api/orgs/{}/secrets", base, org);

    let resp = client
        .post(&url)
        .headers(headers)
        .json(&serde_json::json!({ "name": name, "value": value }))
        .send()
        .await
        .context("failed to reach KinLab API")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("failed to set secret '{}' ({}): {}", name, status, body);
    }

    println!("Secret '{}' set.", name);
    Ok(())
}

/// List org-level secrets.
pub async fn list() -> Result<()> {
    let base = base_url();
    let org = resolve_org_id()?;
    let (client, headers) = client_with_auth(&base)?;
    let url = format!("{}/api/orgs/{}/secrets", base, org);

    let resp = client
        .get(&url)
        .headers(headers)
        .send()
        .await
        .context("failed to reach KinLab API")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("failed to list secrets ({}): {}", status, body);
    }

    let json: serde_json::Value = resp.json().await.context("invalid JSON response")?;
    let secrets = json
        .get("secrets")
        .and_then(|s| s.as_array())
        .cloned()
        .unwrap_or_default();

    if secrets.is_empty() {
        println!("No secrets configured.");
        return Ok(());
    }

    println!("Org secrets:");
    for secret in &secrets {
        let name = secret.get("name").and_then(|n| n.as_str()).unwrap_or("?");
        let updated = secret
            .get("updatedAt")
            .and_then(|u| u.as_str())
            .unwrap_or("");
        println!("  {} (updated: {})", name, updated);
    }

    Ok(())
}

/// Delete an org-level secret.
pub async fn delete(name: String) -> Result<()> {
    let base = base_url();
    let org = resolve_org_id()?;
    let (client, headers) = client_with_auth(&base)?;
    let url = format!("{}/api/orgs/{}/secrets", base, org);

    let resp = client
        .post(&url)
        .headers(headers)
        .json(&serde_json::json!({ "name": name, "action": "delete" }))
        .send()
        .await
        .context("failed to reach KinLab API")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("failed to delete secret '{}' ({}): {}", name, status, body);
    }

    println!("Secret '{}' deleted.", name);
    Ok(())
}

/// Set a repo-level secret (value read from stdin).
pub async fn set_repo(name: String) -> Result<()> {
    let mut value = String::new();
    std::io::stdin()
        .read_to_string(&mut value)
        .context("failed to read secret value from stdin")?;
    let value = value.trim().to_string();
    if value.is_empty() {
        bail!("secret value cannot be empty");
    }

    let base = base_url();
    let org = resolve_org_id()?;
    let repo = resolve_repo_id()?;
    let (client, headers) = client_with_auth(&base)?;
    let url = format!("{}/api/orgs/{}/repos/{}/secrets", base, org, repo);

    let resp = client
        .post(&url)
        .headers(headers)
        .json(&serde_json::json!({ "name": name, "value": value }))
        .send()
        .await
        .context("failed to reach KinLab API")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!(
            "failed to set repo secret '{}' ({}): {}",
            name,
            status,
            body
        );
    }

    println!("Repo secret '{}' set.", name);
    Ok(())
}

/// List repo-level secrets.
pub async fn list_repo() -> Result<()> {
    let base = base_url();
    let org = resolve_org_id()?;
    let repo = resolve_repo_id()?;
    let (client, headers) = client_with_auth(&base)?;
    let url = format!("{}/api/orgs/{}/repos/{}/secrets", base, org, repo);

    let resp = client
        .get(&url)
        .headers(headers)
        .send()
        .await
        .context("failed to reach KinLab API")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("failed to list repo secrets ({}): {}", status, body);
    }

    let json: serde_json::Value = resp.json().await.context("invalid JSON response")?;
    let secrets = json
        .get("secrets")
        .and_then(|s| s.as_array())
        .cloned()
        .unwrap_or_default();

    if secrets.is_empty() {
        println!("No repo secrets configured.");
        return Ok(());
    }

    println!("Repo secrets:");
    for secret in &secrets {
        let name = secret.get("name").and_then(|n| n.as_str()).unwrap_or("?");
        let updated = secret
            .get("updatedAt")
            .and_then(|u| u.as_str())
            .unwrap_or("");
        println!("  {} (updated: {})", name, updated);
    }

    Ok(())
}
