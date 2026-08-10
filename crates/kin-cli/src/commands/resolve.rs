// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Wire types and CLI transport for settling and terminating a durable merge.
//!
//! Settling entries and publishing the merge are deliberately separate
//! transactions: a record commits the resolutions it already carries, so the
//! transaction that publishes cannot also be the one that decides. Each request
//! may carry the record identity the caller was looking at, which the daemon
//! requires to still be current, so a session resolving against a view another
//! session has already advanced is refused rather than silently rebased.

use anyhow::{bail, Result};
use kin_model::{
    AuthorId, Hash256, MergeSide, MergeTransactionRecord, OperationId, RepositoryId, RootBundle,
    SemanticChangeId, WorkspaceId,
};
use serde::{Deserialize, Serialize};

pub const RESOLVE_REPORT_SCHEMA: &str = "kin.resolve.v1";

/// How one named conflict is settled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "choice", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResolveChoice {
    /// Bind one of the three inputs by its exact recorded value.
    Side { side: MergeSide },
    /// The identity does not survive the merge. This is the only settlement a
    /// dangling endpoint has when neither side's relation should be kept.
    Remove,
    /// One claimant keeps a contested path. A path has no side to take, so it
    /// is settled by naming an owner among its claimants.
    PathOwner { artifact: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolveDirective {
    /// Names one conflicting identity: its id, its label, or a contested path.
    pub selector: String,
    pub choice: ResolveChoice,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResolveAction {
    /// Settle named entries, and optionally every entry still unresolved that
    /// one side can settle.
    Settle {
        #[serde(default)]
        directives: Vec<ResolveDirective>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        all: Option<MergeSide>,
    },
    /// Publish the merge from the resolutions already recorded.
    Continue,
    /// Abandon the merge and prove the workspace equals its restore point.
    Abort,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolveRequest {
    pub operation_id: OperationId,
    pub actor: AuthorId,
    pub action: ResolveAction,
    /// Identity of the record the caller decided against. When present the
    /// daemon requires it to still be the workspace's current record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_record: Option<Hash256>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolveReport {
    pub schema: String,
    pub authority: String,
    pub repository_id: RepositoryId,
    pub workspace_id: WorkspaceId,
    pub authority_generation: u64,
    pub roots: RootBundle,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record: Option<MergeTransactionRecord>,
    /// The published merge change, present only when this request completed the
    /// merge.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merge_change: Option<SemanticChangeId>,
    pub resolved_count: usize,
    pub unresolved_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolveResponse {
    #[serde(default)]
    pub lines: Vec<String>,
    #[serde(default)]
    pub mutated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<ResolveReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<OperationId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_generation: Option<u64>,
    #[serde(default)]
    pub idempotent: bool,
}

#[allow(clippy::too_many_arguments)]
pub async fn run(
    ours: Vec<String>,
    theirs: Vec<String>,
    base: Vec<String>,
    remove: Vec<String>,
    keep_path: Vec<String>,
    all_ours: bool,
    all_theirs: bool,
    do_continue: bool,
    abort: bool,
    expect: Option<String>,
    json: bool,
) -> Result<()> {
    let action = plan_action(
        ours,
        theirs,
        base,
        remove,
        keep_path,
        all_ours,
        all_theirs,
        do_continue,
        abort,
    )?;
    let expected_record = match expect {
        Some(value) => Some(parse_record_hash(&value)?),
        None => None,
    };
    let response = execute(ResolveRequest {
        operation_id: OperationId::new(),
        actor: AuthorId::new(kin_core::whoami()),
        action,
        expected_record,
    })
    .await?;
    if json {
        let report = response
            .report
            .ok_or_else(|| anyhow::anyhow!("daemon resolve response omitted its report"))?;
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        for line in response.lines {
            println!("{line}");
        }
    }
    Ok(())
}

/// Turn the flag surface into exactly one action, refusing combinations that
/// would need more than one transaction to mean anything.
#[allow(clippy::too_many_arguments)]
fn plan_action(
    ours: Vec<String>,
    theirs: Vec<String>,
    base: Vec<String>,
    remove: Vec<String>,
    keep_path: Vec<String>,
    all_ours: bool,
    all_theirs: bool,
    do_continue: bool,
    abort: bool,
) -> Result<ResolveAction> {
    if do_continue && abort {
        bail!("a merge either completes or is abandoned; --continue and --abort are exclusive");
    }
    let mut directives = Vec::new();
    for selector in ours {
        directives.push(ResolveDirective {
            selector,
            choice: ResolveChoice::Side {
                side: MergeSide::Ours,
            },
        });
    }
    for selector in theirs {
        directives.push(ResolveDirective {
            selector,
            choice: ResolveChoice::Side {
                side: MergeSide::Theirs,
            },
        });
    }
    for selector in base {
        directives.push(ResolveDirective {
            selector,
            choice: ResolveChoice::Side {
                side: MergeSide::Base,
            },
        });
    }
    for selector in remove {
        directives.push(ResolveDirective {
            selector,
            choice: ResolveChoice::Remove,
        });
    }
    for binding in keep_path {
        // Split on the last `=`, not the first: an artifact identity never
        // contains one, but a contested path may, and the listing emits this
        // binding with the path interpolated raw.
        let (path, artifact) = binding.rsplit_once('=').ok_or_else(|| {
            anyhow::anyhow!(
                "--keep-path expects <PATH>=<ARTIFACT>, naming which claimant keeps the contested \
                 path, found {binding}"
            )
        })?;
        directives.push(ResolveDirective {
            selector: path.to_string(),
            choice: ResolveChoice::PathOwner {
                artifact: artifact.to_string(),
            },
        });
    }
    let all = match (all_ours, all_theirs) {
        (true, true) => bail!("--all-ours and --all-theirs choose different sides for one merge"),
        (true, false) => Some(MergeSide::Ours),
        (false, true) => Some(MergeSide::Theirs),
        (false, false) => None,
    };
    let settling = !directives.is_empty() || all.is_some();
    if settling && (do_continue || abort) {
        bail!(
            "a merge transaction publishes the resolutions it already recorded; settle conflicts \
             first, then run `kin resolve --continue`"
        );
    }
    if do_continue {
        return Ok(ResolveAction::Continue);
    }
    if abort {
        return Ok(ResolveAction::Abort);
    }
    // Clap's `resolution` group refuses this before dispatch, so a caller gets
    // a usage block and exit 2. This stays as the backstop for any other caller
    // of this function, and because it names the full remedy set inline.
    if !settling {
        bail!(
            "nothing to resolve; name a conflict with --ours/--theirs/--base/--remove/--keep-path, \
             settle the rest with --all-ours or --all-theirs, or finish with --continue or --abort"
        );
    }
    Ok(ResolveAction::Settle { directives, all })
}

fn parse_record_hash(value: &str) -> Result<Hash256> {
    let bytes = hex::decode(value.trim()).map_err(|error| {
        anyhow::anyhow!("--expect must be a hex merge record identity: {error}")
    })?;
    let bytes: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
        anyhow::anyhow!(
            "--expect must be a 32-byte merge record identity, found {} byte(s)",
            bytes.len()
        )
    })?;
    Ok(Hash256::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keep_path_directives(binding: &str) -> Vec<ResolveDirective> {
        let action = plan_action(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![binding.to_string()],
            false,
            false,
            false,
            false,
        )
        .expect("a keep-path binding plans an action");
        match action {
            ResolveAction::Settle { directives, all } => {
                assert_eq!(all, None, "naming a claimant takes no side");
                directives
            }
            other => panic!("a keep-path binding settles a conflict, got {other:?}"),
        }
    }

    /// The contested-path listing emits `--keep-path <PATH>=<ARTIFACT>` with the
    /// path interpolated raw, so a path holding an `=` reaches this parser with
    /// two of them. Splitting on the first would name the path `docs/a` and
    /// refuse it, leaving the contested path unsettleable from the command the
    /// product just printed. An artifact identity holds no `=`, which is what
    /// makes the last one the unambiguous separator.
    #[test]
    fn a_contested_path_holding_an_equals_sign_still_names_its_claimant() {
        let artifact = "0b9bdc92-369a-51e9-a45d-3cbbb304dd0a";
        assert_eq!(
            keep_path_directives(&format!("docs/a=b.md={artifact}")),
            vec![ResolveDirective {
                selector: "docs/a=b.md".to_string(),
                choice: ResolveChoice::PathOwner {
                    artifact: artifact.to_string(),
                },
            }]
        );
        // The ordinary binding keeps its existing reading.
        assert_eq!(
            keep_path_directives(&format!("docs/notes.md={artifact}")),
            vec![ResolveDirective {
                selector: "docs/notes.md".to_string(),
                choice: ResolveChoice::PathOwner {
                    artifact: artifact.to_string(),
                },
            }]
        );
    }
}

async fn execute(request: ResolveRequest) -> Result<ResolveResponse> {
    let layout = super::merge::require_repository_layout()?;
    let daemon_url = crate::daemon_client::resolve_daemon_url(&layout)
        .await?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Kin daemon is required to resolve a merge but no daemon endpoint is available"
            )
        })?;
    let daemon = crate::daemon_client::DaemonClient::from_base_url_for_layout(daemon_url, &layout)?;
    daemon.resolve(&request).await
}
