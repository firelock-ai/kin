// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! HTTP client for the kin daemon (`:4219`).
//!
//! Used by CLI commands to query the daemon's live graph instead of
//! opening a snapshot directly. Falls back silently when the daemon
//! is unavailable.

use serde::Deserialize;
use std::time::Duration;

/// Response from `GET /health`.
#[derive(Debug, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub uptime_seconds: u64,
    pub graph_entity_count: Option<usize>,
    pub graph_loaded: bool,
    pub reconciliation_status: String,
}

/// A single entity entry from the daemon's entity search.
#[derive(Debug, Deserialize)]
pub struct DaemonEntityEntry {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub file_path: Option<String>,
}

/// Response from `GET /repos/{repo_id}/entities`.
#[derive(Debug, Deserialize)]
pub struct DaemonEntitiesResponse {
    pub repo_id: String,
    pub entities: Vec<DaemonEntityEntry>,
}

/// Response from `GET /status`.
#[derive(Debug, Deserialize)]
pub struct DaemonStatusResponse {
    pub base_change: String,
    pub entity_adds: usize,
    pub entity_mods: usize,
    pub entity_removes: usize,
    pub relation_adds: usize,
    pub relation_removes: usize,
}

/// Client for the kin daemon HTTP API.
pub struct DaemonClient {
    base_url: String,
    client: reqwest::Client,
}

impl DaemonClient {
    /// Try to connect to the daemon. Returns `None` if the daemon is
    /// unreachable or unhealthy.
    pub async fn try_connect() -> Option<Self> {
        let base = std::env::var("KIN_DAEMON_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:4219".to_string());

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .connect_timeout(Duration::from_millis(500))
            .build()
            .ok()?;

        // Probe health endpoint
        let resp = client
            .get(format!("{}/health", base))
            .send()
            .await
            .ok()?;

        if resp.status().is_success() {
            Some(Self { base_url: base, client })
        } else {
            None
        }
    }

    /// Get the daemon's health response (includes entity count, uptime, etc.).
    pub async fn health(&self) -> anyhow::Result<HealthResponse> {
        let resp = self
            .client
            .get(format!("{}/health", self.base_url))
            .send()
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("daemon error (HTTP {}): {}", status, body);
        }
        Ok(resp.json().await?)
    }

    /// Get the working copy status from the daemon.
    pub async fn status(&self) -> anyhow::Result<DaemonStatusResponse> {
        let resp = self
            .client
            .get(format!("{}/status", self.base_url))
            .send()
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("daemon error (HTTP {}): {}", status, body);
        }
        Ok(resp.json().await?)
    }

    /// Search entities via the multi-repo API.
    ///
    /// Uses `GET /repos/{repo_id}/entities?query=<pattern>`.
    /// The `repo_id` is derived from the `.kin/` directory name.
    pub async fn search_entities(
        &self,
        repo_id: &str,
        query: Option<&str>,
    ) -> anyhow::Result<Vec<DaemonEntityEntry>> {
        let mut url = format!("{}/repos/{}/entities", self.base_url, repo_id);
        if let Some(q) = query {
            url = format!("{}?query={}", url, urlencoding::encode(q));
        }
        let resp = self.client.get(&url).send().await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("daemon error (HTTP {}): {}", status, body);
        }
        let body: DaemonEntitiesResponse = resp.json().await?;
        Ok(body.entities)
    }

    /// Get the entity count from the daemon health endpoint.
    pub async fn entity_count(&self) -> anyhow::Result<usize> {
        let health = self.health().await?;
        Ok(health.graph_entity_count.unwrap_or(0))
    }

    /// Return the base URL of the connected daemon.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }
}

/// Simple percent-encoding for query parameters.
mod urlencoding {
    pub fn encode(s: &str) -> String {
        let mut result = String::with_capacity(s.len());
        for byte in s.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    result.push(byte as char);
                }
                _ => {
                    result.push('%');
                    result.push_str(&format!("{:02X}", byte));
                }
            }
        }
        result
    }
}
