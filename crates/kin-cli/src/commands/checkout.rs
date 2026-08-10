// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Wire types and CLI transport for daemon-owned exact checkout.

use anyhow::{bail, Context, Result};
use kin_model::{AuthorId, OperationId, RepoPath, SemanticChangeId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckoutRequest {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub path_hex: Option<String>,
    #[serde(default)]
    pub change_id: Option<String>,
    pub operation_id: OperationId,
    pub actor: AuthorId,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CheckoutReport {
    pub authority: String,
    pub operation_id: OperationId,
    pub selected: RepoPath,
    pub target_change_id: SemanticChangeId,
    pub authority_generation: u64,
    pub workspace_generation: u64,
    pub projected_entries: usize,
    pub projection_only: bool,
    pub idempotent: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckoutResponse {
    #[serde(default)]
    pub lines: Vec<String>,
    #[serde(default)]
    pub mutated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<CheckoutReport>,
}

pub async fn run(
    path: Option<String>,
    path_hex: Option<String>,
    change_id: Option<String>,
) -> Result<()> {
    let layout = crate::commands::require_repository_layout()?;
    let daemon_url = crate::daemon_client::resolve_daemon_url(&layout)
        .await?
        .ok_or_else(|| crate::daemon_client::daemon_required_error("checkout", &layout))?;
    let request = CheckoutRequest {
        path,
        path_hex,
        change_id,
        operation_id: OperationId::new(),
        actor: AuthorId::new(kin_core::whoami()),
    };
    let daemon = crate::daemon_client::DaemonClient::from_base_url_for_layout(daemon_url, &layout)?;
    let response = daemon.checkout(&request).await?;
    for line in response.lines {
        println!("{line}");
    }
    Ok(())
}

pub fn parse_checkout_path(path: Option<&str>, path_hex: Option<&str>) -> Result<RepoPath> {
    let selected = match (path, path_hex) {
        (Some(path), None) => RepoPath::from_utf8(path)
            .map_err(|error| anyhow::anyhow!("invalid checkout path: {error}"))?,
        (None, Some(encoded)) => {
            let bytes = hex::decode(encoded)
                .with_context(|| format!("invalid repository path hex '{encoded}'"))?;
            if hex::encode(&bytes) != encoded {
                bail!("repository path hex must use canonical lowercase hexadecimal encoding");
            }
            RepoPath::from_bytes(bytes)
                .map_err(|error| anyhow::anyhow!("invalid byte-exact checkout path: {error}"))?
        }
        (Some(_), Some(_)) => bail!("provide either a UTF-8 path or --path-hex, not both"),
        (None, None) => bail!("provide a UTF-8 path or --path-hex"),
    };
    let first = selected
        .as_bytes()
        .split(|byte| *byte == b'/')
        .next()
        .expect("validated repository paths have one component");
    if matches!(first, b".kin" | b".kin-session" | b".git") {
        bail!(
            "checkout path {} names reserved repository control state",
            selected
        );
    }
    Ok(selected)
}

#[cfg(test)]
mod tests {
    use super::parse_checkout_path;

    #[test]
    fn parser_is_byte_safe_component_aware_and_control_safe() {
        assert_eq!(
            parse_checkout_path(Some("src"), None).unwrap().as_bytes(),
            b"src"
        );
        assert_eq!(
            parse_checkout_path(None, Some("7372632fff"))
                .unwrap()
                .as_bytes(),
            b"src/\xff"
        );
        for (path, encoded, message) in [
            (None, None, "provide"),
            (Some("src"), Some("737263"), "either"),
            (Some(""), None, "must not be empty"),
            (Some("../src"), None, "must not contain"),
            (Some("/src"), None, "must be relative"),
            (Some(".kin/config"), None, "reserved"),
            (Some(".git/config"), None, "reserved"),
        ] {
            let error = parse_checkout_path(path, encoded).expect_err("path must fail");
            assert!(error.to_string().contains(message), "{error}");
        }
        assert!(parse_checkout_path(None, Some("7372632FFF"))
            .unwrap_err()
            .to_string()
            .contains("canonical lowercase"));
        assert!(parse_checkout_path(None, Some("zz"))
            .unwrap_err()
            .to_string()
            .contains("invalid repository path hex"));
    }
}
