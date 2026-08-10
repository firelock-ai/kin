// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};
use kin_model::EntityStore;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityRequest {
    #[serde(default)]
    pub propagate: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityResponse {
    #[serde(default)]
    pub lines: Vec<String>,
}

/// Scan the entity graph for known vulnerability patterns.
///
/// `kin security` analyzes the semantic graph locally for:
///   - Exposed API endpoints without tests
///   - Public entities with no callers (orphaned surface area)
///   - Deep dependency chains (transitive risk)
///   - Event contracts without consumers (dead events)
///   - Public entities calling private internals (encapsulation leaks)
///
/// When `--propagate` is set, additionally traces transitive dependency
/// chains for each finding to surface downstream vulnerability propagation.
pub async fn run_with_options(propagate: bool) -> Result<()> {
    let layout = crate::commands::require_repository_layout()?;
    let response = run_daemon_security(&layout, &SecurityRequest { propagate }).await?;
    for line in response.lines {
        println!("{line}");
    }
    Ok(())
}

async fn run_daemon_security(
    layout: &kin_core::KinLayout,
    request: &SecurityRequest,
) -> Result<SecurityResponse> {
    let daemon_url = std::env::var("KIN_DAEMON_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(Some)
        .unwrap_or(crate::daemon_client::resolve_daemon_url(layout).await?);
    let base_url = daemon_url
        .ok_or_else(|| crate::daemon_client::daemon_required_error("security", layout))?;
    let client = crate::daemon_client::DaemonClient::from_base_url(base_url)?;
    client
        .security(request)
        .await
        .context("daemon security scan failed")
}

pub fn build_security_response(
    graph: &kin_db::InMemoryGraph,
    request: &SecurityRequest,
) -> Result<SecurityResponse> {
    let entity_count = graph.list_all_entities()?.len();

    if entity_count == 0 {
        return Ok(SecurityResponse {
            lines: vec!["No entities in graph. Run `kin commit` first.".to_string()],
        });
    }

    let findings = kin_review::security_findings(graph, request.propagate)?;
    let counts = kin_review::SecurityFindingCounts::of(&findings);

    let mut lines = vec![format!("Security scan: {} entities analyzed", entity_count)];
    if request.propagate {
        lines.push("  (transitive propagation enabled)".to_string());
    }
    lines.push(String::new());

    if findings.is_empty() {
        lines.push("  No security findings detected.".to_string());
        return Ok(SecurityResponse { lines });
    }

    lines.push(format!(
        "  Findings: {} total ({} high, {} medium, {} low, {} info)",
        findings.len(),
        counts.high,
        counts.medium,
        counts.low,
        counts.info
    ));
    lines.push(String::new());

    for finding in &findings {
        lines.push(format!(
            "  [{}] {} ({})",
            finding.severity, finding.entity_name, finding.category
        ));
        lines.push(format!("    {}", finding.message));
    }

    if counts.high > 0 {
        lines.push(String::new());
        lines.push(format!(
            "  {} high-severity finding(s) require attention.",
            counts.high
        ));
    }

    Ok(SecurityResponse { lines })
}

#[cfg(test)]
mod tests {
    use kin_review::SecuritySeverity;

    #[test]
    fn severity_ordering() {
        assert!(SecuritySeverity::Info < SecuritySeverity::Low);
        assert!(SecuritySeverity::Low < SecuritySeverity::Medium);
        assert!(SecuritySeverity::Medium < SecuritySeverity::High);
    }

    #[test]
    fn severity_display() {
        assert_eq!(format!("{}", SecuritySeverity::High), "HIGH");
        assert_eq!(format!("{}", SecuritySeverity::Medium), "MEDIUM");
        assert_eq!(format!("{}", SecuritySeverity::Low), "LOW");
        assert_eq!(format!("{}", SecuritySeverity::Info), "INFO");
    }
}
