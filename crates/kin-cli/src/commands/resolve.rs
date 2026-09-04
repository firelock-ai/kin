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

use anyhow::{bail, Context, Result};
use kin_model::{
    AuthorId, Hash256, MergeSide, MergeTransactionRecord, OperationId, RepositoryId, RootBundle,
    SemanticChangeId, WorkspaceId,
};
use serde::{Deserialize, Serialize};
use std::io::Read;

pub const RESOLVE_REPORT_SCHEMA: &str = "kin.resolve.v1";
/// Custom input is bounded before it is admitted to repository authority.
pub const MAX_RESOLVE_FILE_BYTES: usize = 8 * 1024 * 1024;
/// JSON encodes each byte using at most four bytes, including its separator.
pub const MAX_RESOLVE_REQUEST_BYTES: usize = 4 * MAX_RESOLVE_FILE_BYTES + 1024 * 1024;

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
    /// Replace a conflicting artifact with explicit input bytes and derive its
    /// merged entities and relationships from that body.
    File { body: Vec<u8> },
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
    file: Vec<String>,
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
        file,
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
        actor: crate::commands::require_commit_author()?,
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
    file: Vec<String>,
    all_ours: bool,
    all_theirs: bool,
    do_continue: bool,
    abort: bool,
) -> Result<ResolveAction> {
    if do_continue && abort {
        bail!("a merge either completes or is abandoned; --continue and --abort are exclusive");
    }
    if !file.is_empty() && (do_continue || abort) {
        bail!(
            "settle file conflicts first, then run `kin resolve --continue` or `kin resolve --abort`"
        );
    }
    if file.len() % 2 != 0 {
        bail!("--file expects two arguments: <PATH> <FILE>");
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
    let mut remaining_file_bytes = MAX_RESOLVE_FILE_BYTES;
    for pair in file.chunks_exact(2) {
        let selector = &pair[0];
        let source = &pair[1];
        if selector.trim().is_empty() {
            bail!("--file requires the conflicted repository path or artifact identity");
        }
        if directives.iter().any(|entry| entry.selector == *selector) {
            bail!("conflict {selector} has more than one resolution in this request");
        }
        let body = read_resolution_body(source, remaining_file_bytes)?;
        remaining_file_bytes -= body.len();
        directives.push(ResolveDirective {
            selector: selector.clone(),
            choice: ResolveChoice::File { body },
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
            "nothing to resolve; name a conflict with --ours/--theirs/--base/--remove/--keep-path/--file, \
             settle the rest with --all-ours or --all-theirs, or finish with --continue or --abort"
        );
    }
    Ok(ResolveAction::Settle { directives, all })
}

fn read_resolution_body(source: &str, remaining_bytes: usize) -> Result<Vec<u8>> {
    let input = std::fs::File::open(source)
        .with_context(|| format!("could not read resolution body from {source}"))?;
    let mut body = Vec::new();
    input
        .take(remaining_bytes as u64 + 1)
        .read_to_end(&mut body)
        .with_context(|| format!("could not read resolution body from {source}"))?;
    if body.len() > remaining_bytes {
        bail!(
            "custom resolution bodies exceed the {MAX_RESOLVE_FILE_BYTES}-byte input limit per \
             request; resolve multiple files in separate requests"
        );
    }
    Ok(body)
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

    fn file_action(
        file: Vec<String>,
        ours: Vec<String>,
        do_continue: bool,
    ) -> Result<ResolveAction> {
        plan_action(
            ours,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            file,
            false,
            false,
            do_continue,
            false,
        )
    }

    #[test]
    fn file_resolution_captures_exact_input_bytes_independent_of_the_input_path() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("combined=body.bin");
        let body = b"ours\r\ntheirs\0\xff";
        std::fs::write(&source, body).unwrap();
        let action = file_action(
            vec!["src/a=b.bin".to_string(), source.display().to_string()],
            Vec::new(),
            false,
        )
        .unwrap();
        std::fs::write(&source, b"changed after capture").unwrap();
        assert_eq!(
            action,
            ResolveAction::Settle {
                directives: vec![ResolveDirective {
                    selector: "src/a=b.bin".to_string(),
                    choice: ResolveChoice::File {
                        body: body.to_vec(),
                    },
                }],
                all: None,
            }
        );
        let encoded = serde_json::to_vec(&action).unwrap();
        assert_eq!(
            serde_json::from_slice::<ResolveAction>(&encoded).unwrap(),
            action
        );
        assert!(!String::from_utf8(encoded)
            .unwrap()
            .contains("combined=body.bin"));
    }

    #[test]
    fn file_resolution_refuses_missing_input_and_contradictory_intent() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing").display().to_string();
        let binding = vec!["src/code.rs".to_string(), missing];
        assert!(file_action(binding.clone(), Vec::new(), false)
            .unwrap_err()
            .to_string()
            .contains("could not read resolution body"));
        assert!(file_action(binding.clone(), Vec::new(), true)
            .unwrap_err()
            .to_string()
            .contains("settle file conflicts first"));
        assert!(file_action(binding, vec!["src/code.rs".to_string()], false)
            .unwrap_err()
            .to_string()
            .contains("more than one resolution"));
        assert!(
            file_action(vec!["src/code.rs".to_string()], Vec::new(), false)
                .unwrap_err()
                .to_string()
                .contains("two arguments")
        );
    }

    #[test]
    fn file_resolution_input_limit_refuses_truncation_and_accepts_exact_boundary() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("body.bin");
        std::fs::write(&source, [0xff; 5]).unwrap();
        let source = source.to_str().unwrap();
        assert_eq!(read_resolution_body(source, 5).unwrap(), [0xff; 5]);
        assert!(read_resolution_body(source, 4)
            .unwrap_err()
            .to_string()
            .contains("input limit"));
    }

    fn keep_path_directives(binding: &str) -> Vec<ResolveDirective> {
        let action = plan_action(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![binding.to_string()],
            Vec::new(),
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
    if serde_json::to_vec(&request)?.len() > MAX_RESOLVE_REQUEST_BYTES {
        bail!("resolution request exceeds the {MAX_RESOLVE_REQUEST_BYTES}-byte transport limit");
    }
    let layout = super::merge::require_repository_layout()?;
    let daemon_url = crate::daemon_client::resolve_daemon_url(&layout)
        .await?
        .ok_or_else(|| crate::daemon_client::daemon_required_error("resolve", &layout))?;
    let daemon = crate::daemon_client::DaemonClient::from_base_url_for_layout(daemon_url, &layout)?;
    daemon.resolve(&request).await
}
