// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Wire types and CLI transport for daemon-owned repository-v6 stashes.
//!
//! A stash is exact graph-owned workspace state sealed as an immutable change
//! under `refs/kin/stash/`, bound to the authority target it was taken against.
//! No branch marker, sidecar file, or working-tree re-read participates.
//!
//! The transport stays fail-closed at the capability gate. The daemon-owned
//! path below it is implemented and covered, but a seal against a live daemon
//! can still leave the daemon query graph disagreeing with workspace authority,
//! and no command may ship while it can wedge the next one.

use anyhow::{bail, Result};
use kin_model::{
    AuthorId, Hash256, OperationId, RefName, RefTarget, RepositoryId, SemanticChangeId, Timestamp,
    WorkspaceId,
};
use serde::{Deserialize, Serialize};

pub const STASH_LIST_SCHEMA: &str = "kin.stash-list.v1";

/// Repository ref namespace that holds sealed workspace states.
pub const STASH_REF_PREFIX: &[u8] = b"refs/kin/stash/";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum StashRequest {
    List,
    Push {
        message: Option<String>,
        operation_id: OperationId,
        timestamp: Timestamp,
        actor: AuthorId,
    },
    Pop {
        operation_id: OperationId,
        actor: AuthorId,
    },
}

impl StashRequest {
    pub fn is_mutation(&self) -> bool {
        !matches!(self, Self::List)
    }
}

/// One sealed workspace state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StashEntryReport {
    pub name: RefName,
    pub ordinal: u64,
    pub change_id: SemanticChangeId,
    pub message: String,
    pub timestamp: Timestamp,
    /// Authority target the sealed state was taken against, or `None` when it
    /// was sealed on an unborn workspace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_target: Option<RefTarget>,
    pub tree_hash: Hash256,
    pub file_count: usize,
    pub entity_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StashListReport {
    pub schema: String,
    pub authority: String,
    pub repository_id: RepositoryId,
    pub authority_generation: u64,
    pub workspace_id: WorkspaceId,
    pub workspace_generation: u64,
    pub workspace_dirty: bool,
    pub entries: Vec<StashEntryReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StashResponse {
    #[serde(default)]
    pub lines: Vec<String>,
    #[serde(default)]
    pub mutated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<StashListReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<StashEntryReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<OperationId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_generation: Option<u64>,
    #[serde(default)]
    pub idempotent: bool,
}

/// Build the exact ref that holds stash `ordinal`.
pub fn stash_ref_name(ordinal: u64) -> Result<RefName> {
    let mut bytes = STASH_REF_PREFIX.to_vec();
    bytes.extend_from_slice(ordinal.to_string().as_bytes());
    RefName::from_bytes(bytes)
        .map_err(|error| anyhow::anyhow!("invalid repository stash ref: {error}"))
}

/// Read the ordinal out of a stash ref, rejecting any non-canonical spelling.
///
/// Anything else under the namespace is not a stash this build wrote, and is
/// never silently reinterpreted as one.
pub fn stash_ref_ordinal(name: &RefName) -> Option<u64> {
    let suffix = name.as_bytes().strip_prefix(STASH_REF_PREFIX)?;
    let text = std::str::from_utf8(suffix).ok()?;
    let ordinal: u64 = text.parse().ok()?;
    if ordinal.to_string() != text {
        return None;
    }
    Some(ordinal)
}

pub async fn list(json: bool) -> Result<()> {
    super::capabilities::require_ready("stash")?;
    let response = execute(StashRequest::List).await?;
    if json {
        let report = response
            .report
            .ok_or_else(|| anyhow::anyhow!("daemon stash list response omitted its report"))?;
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_lines(response);
    }
    Ok(())
}

pub async fn push(message: Option<String>, yes: bool) -> Result<()> {
    super::capabilities::require_ready("stash")?;
    // Discover before asking for consent. Outside a repository there is nothing
    // to seal and nothing to discard, so the confirmation named a cause that
    // was not the cause: a caller who supplied --yes learned the real problem
    // on the second try. `stash list` and `stash pop` already fail on
    // discovery here, and this is what puts `push` back beside them.
    let _ = crate::commands::require_repository_layout()?;
    if !yes {
        confirm_workspace_reset()?;
    }
    let response = execute(StashRequest::Push {
        message,
        operation_id: OperationId::new(),
        timestamp: Timestamp::now(),
        actor: AuthorId::new(kin_core::whoami()),
    })
    .await?;
    print_lines(response);
    Ok(())
}

pub async fn pop() -> Result<()> {
    super::capabilities::require_ready("stash")?;
    let response = execute(StashRequest::Pop {
        operation_id: OperationId::new(),
        actor: AuthorId::new(kin_core::whoami()),
    })
    .await?;
    print_lines(response);
    Ok(())
}

/// Require a typed confirmation before the workspace returns to its base.
///
/// Sealing is durable before anything is discarded, so the working files stay
/// recoverable through `kin stash pop`. The confirmation still exists because
/// the projected files do disappear, and that must never happen silently from
/// an unattended stdin that happens to be closed.
fn confirm_workspace_reset() -> Result<()> {
    use std::io::{BufRead, IsTerminal, Write};

    let stdin = std::io::stdin();
    if !stdin.is_terminal() {
        bail!(
            "returning the workspace to its base after sealing discards the projected working \
             files; pass --yes to confirm non-interactively"
        );
    }
    print!("Return the workspace to its base after sealing? Type \"remove\" to confirm: ");
    std::io::stdout().flush()?;
    let mut answer = String::new();
    stdin.lock().read_line(&mut answer)?;
    if answer.trim() != "remove" {
        bail!("workspace reset not confirmed; nothing was sealed or changed");
    }
    Ok(())
}

async fn execute(request: StashRequest) -> Result<StashResponse> {
    let layout = crate::commands::require_repository_layout()?;
    let daemon_url = crate::daemon_client::resolve_daemon_url(&layout)
        .await?
        .ok_or_else(|| crate::daemon_client::daemon_required_error("stash operations", &layout))?;
    let daemon = crate::daemon_client::DaemonClient::from_base_url_for_layout(daemon_url, &layout)?;
    daemon.stash(&request).await
}

fn print_lines(response: StashResponse) {
    for line in response.lines {
        println!("{line}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stash_ref_names_round_trip_only_through_canonical_ordinals() {
        for ordinal in [0_u64, 1, 9, 10, u64::MAX] {
            let name = stash_ref_name(ordinal).unwrap();
            assert_eq!(stash_ref_ordinal(&name), Some(ordinal));
        }
        assert_eq!(
            stash_ref_name(3).unwrap().as_bytes(),
            b"refs/kin/stash/3".as_slice()
        );
        for foreign in [
            "refs/kin/stash/03",
            "refs/kin/stash/+1",
            "refs/kin/stash/1/2",
            "refs/kin/stash/latest",
            "refs/heads/main",
            "refs/kin/stashes/1",
        ] {
            let name = RefName::from_utf8(foreign).unwrap();
            assert_eq!(stash_ref_ordinal(&name), None, "{foreign}");
        }
    }
}
