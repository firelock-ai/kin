// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Wire types and CLI transport for daemon-owned repository-v6 tags.
//!
//! A tag is a ref, not a side channel: it is published as a `refs/tags/`
//! compare-and-swap inside one repository transaction against the exact roots
//! the proof policy was evaluated over. If authority moves between the policy
//! decision and publication, the transaction's expected-roots compare-and-swap
//! refuses it rather than tagging a source nobody checked.

use anyhow::{Context, Result};
use kin_model::{
    AuthorId, EntityId, OperationId, RefName, RefTarget, RepositoryId, RootBundle, SemanticChangeId,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::repository_authority::parse_ref_name;

pub const TAG_SCHEMA: &str = "kin.tag.v1";

/// Baseline source-bound proof coverage a release tag is expected to clear
/// without an explicit acknowledgment.
pub const BASELINE_COVERAGE_RATIO: f64 = 0.5;

pub const RELEASE_SNAPSHOT_SCHEMA: &str = "kin.release-snapshot.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TagRequest {
    pub name: RefName,
    #[serde(default)]
    pub require_proof: bool,
    #[serde(default)]
    pub require_approval: bool,
    #[serde(default)]
    pub force: bool,
    /// Bind and return the full release snapshot alongside the tag ref.
    #[serde(default)]
    pub snapshot: bool,
    pub operation_id: OperationId,
    pub actor: AuthorId,
}

/// The exact state a release names.
///
/// Every field is the identity of something immutable: the repository roots the
/// tag transaction moved between, the change it points at, the content hash of
/// the complete artifact tree, and the policy decision that admitted it. The
/// digest binds them together, so a snapshot that claims a different tree,
/// source, or policy outcome is a different snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReleaseSnapshot {
    pub schema: String,
    pub repository_id: RepositoryId,
    pub tag: RefName,
    /// Canonical lowercase hexadecimal identity of the released change.
    pub change_id: String,
    pub roots_before: RootBundle,
    pub roots_after: RootBundle,
    /// Canonical lowercase hexadecimal content identity of the released tree.
    pub tree_hash: String,
    pub artifact_count: usize,
    pub blob_artifacts: usize,
    pub symlink_artifacts: usize,
    pub gitlink_artifacts: usize,
    pub entity_count: usize,
    pub relation_count: usize,
    pub proof: TagProofDecision,
    pub snapshot_digest: String,
}

/// Fields the snapshot digest covers, in a fixed order.
#[derive(Serialize)]
struct SnapshotDigestInput<'a> {
    schema: &'a str,
    repository_id: &'a RepositoryId,
    tag: &'a RefName,
    change_id: &'a str,
    roots_before: &'a RootBundle,
    roots_after: &'a RootBundle,
    tree_hash: &'a str,
    artifact_count: usize,
    blob_artifacts: usize,
    symlink_artifacts: usize,
    gitlink_artifacts: usize,
    entity_count: usize,
    relation_count: usize,
    proof: &'a TagProofDecision,
}

impl ReleaseSnapshot {
    /// Compute the digest that binds this snapshot's components together.
    #[allow(clippy::too_many_arguments)]
    pub fn seal(mut self) -> Result<Self> {
        self.snapshot_digest = String::new();
        let payload = serde_json::to_vec(&SnapshotDigestInput {
            schema: &self.schema,
            repository_id: &self.repository_id,
            tag: &self.tag,
            change_id: &self.change_id,
            roots_before: &self.roots_before,
            roots_after: &self.roots_after,
            tree_hash: &self.tree_hash,
            artifact_count: self.artifact_count,
            blob_artifacts: self.blob_artifacts,
            symlink_artifacts: self.symlink_artifacts,
            gitlink_artifacts: self.gitlink_artifacts,
            entity_count: self.entity_count,
            relation_count: self.relation_count,
            proof: &self.proof,
        })
        .context("serialize the release snapshot binding")?;
        let mut hasher = <Sha256 as Digest>::new();
        hasher.update(RELEASE_SNAPSHOT_DIGEST_DOMAIN);
        hasher.update((payload.len() as u64).to_le_bytes());
        hasher.update(&payload);
        self.snapshot_digest = hex::encode(hasher.finalize());
        Ok(self)
    }
}

const RELEASE_SNAPSHOT_DIGEST_DOMAIN: &[u8] = b"kin-release-snapshot-v1\0";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TagProofDecision {
    /// Source-bound proof coverage over the exact tagged change.
    pub source_entities: usize,
    pub entities_with_source_bound_proof: usize,
    pub coverage_percent_hundredths: u32,
    pub baseline_acknowledged: bool,
    pub require_proof: bool,
    pub require_approval: bool,
    pub unapproved_changes: Vec<SemanticChangeId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entities_missing_proof: Vec<EntityId>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TagReport {
    pub schema: String,
    pub authority: String,
    pub repository_id: RepositoryId,
    pub name: RefName,
    pub target: RefTarget,
    pub change_id: SemanticChangeId,
    pub authority_generation: u64,
    pub proof: TagProofDecision,
    pub idempotent: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<ReleaseSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagResponse {
    #[serde(default)]
    pub lines: Vec<String>,
    #[serde(default)]
    pub mutated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<TagReport>,
}

pub async fn run(
    tag: String,
    require_proof: bool,
    require_approval: bool,
    force: bool,
) -> Result<()> {
    publish(tag, require_proof, require_approval, force, false).await
}

/// `kin release snapshot <tag>` — publish the tag and return the exact release
/// snapshot bound to it.
pub async fn snapshot(
    tag: String,
    require_proof: bool,
    require_approval: bool,
    force: bool,
) -> Result<()> {
    publish(tag, require_proof, require_approval, force, true).await
}

async fn publish(
    tag: String,
    require_proof: bool,
    require_approval: bool,
    force: bool,
    snapshot: bool,
) -> Result<()> {
    let name = parse_tag_ref(&tag)?;
    let layout = crate::commands::require_repository_layout()?;
    let daemon_url = crate::daemon_client::resolve_daemon_url(&layout)
        .await?
        .ok_or_else(|| crate::daemon_client::daemon_required_error("tags", &layout))?;
    let daemon = crate::daemon_client::DaemonClient::from_base_url_for_layout(daemon_url, &layout)?;
    let response = daemon
        .tag(&TagRequest {
            name,
            require_proof,
            require_approval,
            force,
            snapshot,
            operation_id: OperationId::new(),
            actor: AuthorId::new(kin_core::whoami()),
        })
        .await?;
    if snapshot {
        let report = validate_response(&response)?;
        let snapshot = report.snapshot.as_ref().context(
            "daemon tag response omitted the release snapshot this publication was bound to",
        )?;
        println!("{}", serde_json::to_string_pretty(snapshot)?);
        return Ok(());
    }
    for line in response.lines {
        println!("{line}");
    }
    Ok(())
}

/// Accept either a bare tag name or an already-qualified `refs/tags/` ref.
pub fn parse_tag_ref(value: &str) -> Result<RefName> {
    let name = if value.starts_with("refs/") {
        parse_ref_name(value)?
    } else {
        RefName::tag(value.as_bytes())
            .map_err(|error| anyhow::anyhow!("invalid tag '{value}': {error}"))?
    };
    if !name.is_tag() {
        anyhow::bail!("tag command requires a ref below refs/tags/, found {name}");
    }
    Ok(name)
}

pub fn coverage_percent(decision: &TagProofDecision) -> f64 {
    f64::from(decision.coverage_percent_hundredths) / 100.0
}

/// Encode a ratio without losing the exact value across the wire in a way that
/// would make two reports of the same decision compare unequal.
pub fn encode_coverage(ratio: f64) -> u32 {
    let clamped = ratio.clamp(0.0, 1.0);
    (clamped * 10_000.0).round() as u32
}

pub fn render_lines(report: &TagReport) -> Vec<String> {
    let mut lines = vec![if report.idempotent {
        format!(
            "Tagged {} at change {} (authority generation {}, idempotent replay)",
            report.name, report.change_id, report.authority_generation
        )
    } else {
        format!(
            "Tagged {} at change {} (authority generation {})",
            report.name, report.change_id, report.authority_generation
        )
    }];
    lines.push(format!(
        "Source-bound proof coverage: {:.2}% of {} entities{}",
        coverage_percent(&report.proof),
        report.proof.source_entities,
        if report.proof.baseline_acknowledged {
            " (baseline acknowledged with --force)"
        } else {
            ""
        }
    ));
    if report.proof.require_approval {
        lines.push("Approval policy: every reachable non-root change is approved".to_string());
    }
    lines
}

/// Render the exact policy refusal so the caller sees which check failed and
/// against which source, rather than a generic conflict.
pub fn render_blocked(name: &RefName, change_id: &SemanticChangeId, blockers: &[String]) -> String {
    format!(
        "refusing to publish {name} at change {change_id}: release policy is not satisfied\n  - {}",
        blockers.join("\n  - ")
    )
}

pub fn context_for(name: &RefName) -> String {
    format!("publish repository-v6 tag {name}")
}

pub fn validate_response(response: &TagResponse) -> Result<&TagReport> {
    response
        .report
        .as_ref()
        .context("daemon tag response omitted its report")
}
