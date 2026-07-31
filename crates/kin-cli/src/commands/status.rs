// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Coherent repository-v6 status.
//!
//! Status reads one immutable authority lease. It never inspects checkout
//! contents, legacy branch sidecars, Git, or a separately opened graph
//! snapshot. Opening the authority also revalidates every referenced source
//! body in the repository-owned CAS.
//!
//! Semantic counts are resolved from the workspace's durable first-parent
//! history and cumulative semantic overlay inside that lease. They deliberately
//! do not describe the daemon's mutable live graph: runtime reconcile and LSP
//! work may advance that derived view without changing repository authority.

use std::path::PathBuf;

use anyhow::{Context, Result};
use kin_model::{
    Hash256, RefName, RefTarget, RepositoryId, RootBundle, WorkspaceHead, WorkspaceId,
};
use serde::{Deserialize, Deserializer, Serialize};

use super::repository_authority::ActiveRepositoryAuthority;

/// First status contract whose enrichment counts name their durable view and
/// exact authority/workspace generations. The earlier, unreleased v1 shape
/// carried counts with different semantics and cannot be inferred truthfully.
pub const STATUS_SCHEMA: &str = "kin.status.v2";

fn deserialize_status_schema<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let schema = String::deserialize(deserializer)?;
    if schema != STATUS_SCHEMA {
        return Err(serde::de::Error::custom(format!(
            "unsupported status schema '{schema}', expected '{STATUS_SCHEMA}'"
        )));
    }
    Ok(schema)
}

fn deserialize_status_authority<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let authority = String::deserialize(deserializer)?;
    if authority != "repository-v6" {
        return Err(serde::de::Error::custom(format!(
            "unsupported status authority '{authority}', expected 'repository-v6'"
        )));
    }
    Ok(authority)
}

fn deserialize_status_unattested<'de, D>(deserializer: D) -> std::result::Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    let completion_attested = bool::deserialize(deserializer)?;
    if completion_attested {
        return Err(serde::de::Error::custom(
            "kin.status.v2 does not carry a semantic-enrichment completion attestation",
        ));
    }
    Ok(false)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SemanticEnrichmentPresence {
    Absent,
    Present,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SemanticEnrichmentView {
    DurableRepositoryAuthority,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SemanticEnrichmentStatus {
    /// This is durable repository/workspace authority, not the daemon's live
    /// query graph. `kin graph status` reports the latter.
    pub view: SemanticEnrichmentView,
    pub authority_generation: u64,
    pub workspace_generation: u64,
    pub presence: SemanticEnrichmentPresence,
    pub entity_count: usize,
    pub relation_count: usize,
    pub semantic_change_count: usize,
    /// There is no repository-v6 completion attestation yet. Counts are exact;
    /// completeness is deliberately not inferred from them.
    pub completion_attested: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SemanticEnrichmentStatusWire {
    view: SemanticEnrichmentView,
    authority_generation: u64,
    workspace_generation: u64,
    presence: SemanticEnrichmentPresence,
    entity_count: usize,
    relation_count: usize,
    semantic_change_count: usize,
    #[serde(deserialize_with = "deserialize_status_unattested")]
    completion_attested: bool,
}

impl<'de> Deserialize<'de> for SemanticEnrichmentStatus {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = SemanticEnrichmentStatusWire::deserialize(deserializer)?;
        let enrichment = Self {
            view: wire.view,
            authority_generation: wire.authority_generation,
            workspace_generation: wire.workspace_generation,
            presence: wire.presence,
            entity_count: wire.entity_count,
            relation_count: wire.relation_count,
            semantic_change_count: wire.semantic_change_count,
            completion_attested: wire.completion_attested,
        };
        enrichment.validate().map_err(serde::de::Error::custom)?;
        Ok(enrichment)
    }
}

impl SemanticEnrichmentStatus {
    pub(crate) fn from_durable_summary(
        summary: &kin_core::DurableSemanticEnrichmentSummary,
    ) -> Self {
        Self {
            view: SemanticEnrichmentView::DurableRepositoryAuthority,
            authority_generation: summary.authority_generation,
            workspace_generation: summary.workspace_generation,
            presence: if summary.entity_count == 0 && summary.relation_count == 0 {
                SemanticEnrichmentPresence::Absent
            } else {
                SemanticEnrichmentPresence::Present
            },
            entity_count: summary.entity_count,
            relation_count: summary.relation_count,
            semantic_change_count: summary.semantic_change_count,
            completion_attested: false,
        }
    }

    fn validate(&self) -> std::result::Result<(), String> {
        let has_graph_semantics = self.entity_count > 0 || self.relation_count > 0;
        match (&self.presence, has_graph_semantics) {
            (SemanticEnrichmentPresence::Absent, true) => Err(
                "semantic_enrichment.presence is absent despite nonzero entity/relation counts"
                    .to_string(),
            ),
            (SemanticEnrichmentPresence::Present, false) => Err(
                "semantic_enrichment.presence is present despite zero entity/relation counts"
                    .to_string(),
            ),
            _ => Ok(()),
        }
    }
}

/// Read the durable enrichment this exact authority lease carries.
///
/// The authority snapshot's own entity and relation tables are not this
/// answer. Exact admission binds entity and relation deltas onto the changes it
/// admits, and the entities a workspace resolves to come from replaying those
/// deltas to its base change and applying its semantic overlay.
/// A surface that counted the raw tables instead would report zero enrichment
/// on a fully enriched repository.
///
/// This accessor intentionally does not materialize the complete workspace
/// graph. Kin core replays only semantic identities and never reconstructs the
/// exact tree, reads source CAS bodies, or builds query indices. The result is
/// generation-bound durable truth. The daemon's live graph is a distinct view
/// and may carry additional derived enrichment.
pub fn semantic_enrichment_from_authority(
    authority: &kin_db::RepositoryAuthorityState,
    workspace_id: &WorkspaceId,
) -> Result<SemanticEnrichmentStatus> {
    let summary = kin_core::durable_semantic_enrichment_summary(authority, workspace_id)
        .with_context(|| {
            format!("summarize durable repository-v6 semantics for workspace {workspace_id}")
        })?;
    Ok(SemanticEnrichmentStatus::from_durable_summary(&summary))
}

/// Exact serialized payload one authority open recovered.
///
/// KinDB mints this receipt inside the same coherent recovery that produced the
/// manager, so the counts name the bytes status actually read. They are not a
/// measurement of the storage directory, which also holds retired journal
/// entries, source bodies, indexes, and allocation overhead that no authority
/// open admitted. The receipt is fixed at open and does not follow later
/// commits.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub struct AuthorityPayloadReceipt {
    pub snapshot_generation: u64,
    pub head_generation: u64,
    pub snapshot_bytes: u64,
    pub acknowledged_delta_count: u64,
    pub acknowledged_delta_bytes: u64,
    pub total_payload_bytes: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityPayloadReceiptWire {
    snapshot_generation: u64,
    head_generation: u64,
    snapshot_bytes: u64,
    acknowledged_delta_count: u64,
    acknowledged_delta_bytes: u64,
    total_payload_bytes: u64,
}

impl<'de> Deserialize<'de> for AuthorityPayloadReceipt {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AuthorityPayloadReceiptWire::deserialize(deserializer)?;
        let receipt = Self {
            snapshot_generation: wire.snapshot_generation,
            head_generation: wire.head_generation,
            snapshot_bytes: wire.snapshot_bytes,
            acknowledged_delta_count: wire.acknowledged_delta_count,
            acknowledged_delta_bytes: wire.acknowledged_delta_bytes,
            total_payload_bytes: wire.total_payload_bytes,
        };
        receipt.validate().map_err(serde::de::Error::custom)?;
        Ok(receipt)
    }
}

impl AuthorityPayloadReceipt {
    /// Carry KinDB's receipt across the wire without restating it.
    ///
    /// Every field is the accessor's own value. Recomputing a total here would
    /// report this process's arithmetic as the payload KinDB admitted.
    fn from_payload_stats(stats: &kin_db::AuthorityPayloadStats) -> Self {
        Self {
            snapshot_generation: stats.snapshot_generation(),
            head_generation: stats.head_generation(),
            snapshot_bytes: stats.snapshot_bytes(),
            acknowledged_delta_count: stats.acknowledged_delta_count(),
            acknowledged_delta_bytes: stats.acknowledged_delta_bytes(),
            total_payload_bytes: stats.total_payload_bytes(),
        }
    }

    fn validate(&self) -> std::result::Result<(), String> {
        let span = self
            .head_generation
            .checked_sub(self.snapshot_generation)
            .ok_or_else(|| {
                format!(
                    "authority_payload.snapshot_generation ({}) exceeds head_generation ({})",
                    self.snapshot_generation, self.head_generation
                )
            })?;
        if self.acknowledged_delta_count != span {
            return Err(format!(
                "authority_payload.acknowledged_delta_count ({}) does not account for the \
                 generations between snapshot ({}) and head ({})",
                self.acknowledged_delta_count, self.snapshot_generation, self.head_generation
            ));
        }
        let total = self
            .snapshot_bytes
            .checked_add(self.acknowledged_delta_bytes)
            .ok_or_else(|| "authority_payload byte counts overflow u64".to_string())?;
        if self.total_payload_bytes != total {
            return Err(format!(
                "authority_payload.total_payload_bytes ({}) is not the snapshot ({}) plus \
                 acknowledged delta ({}) bytes it names",
                self.total_payload_bytes, self.snapshot_bytes, self.acknowledged_delta_bytes
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RepositoryStatus {
    pub repository_id: RepositoryId,
    pub generation: u64,
    pub roots: RootBundle,
    pub ref_count: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_ref: Option<RefName>,
    /// `RepositoryAuthorityManager::open` verifies every authority-referenced
    /// source body before this report can be produced.
    pub source_cas_verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceStatus {
    pub workspace_id: WorkspaceId,
    pub generation: u64,
    pub head: WorkspaceHead,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_target: Option<RefTarget>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_tree_hash: Option<Hash256>,
    pub tree_hash: Hash256,
    pub dirty: bool,
    pub artifact_count: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StatusReport {
    pub schema: String,
    pub authority: String,
    pub repo_root: PathBuf,
    pub repository: RepositoryStatus,
    pub workspace: WorkspaceStatus,
    pub semantic_enrichment: SemanticEnrichmentStatus,
    /// Absent only where authority was never persisted and generation zero was
    /// built in memory. A persisted repository always reports the payload its
    /// open recovered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_payload: Option<AuthorityPayloadReceipt>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusReportWire {
    #[serde(deserialize_with = "deserialize_status_schema")]
    schema: String,
    #[serde(deserialize_with = "deserialize_status_authority")]
    authority: String,
    repo_root: PathBuf,
    repository: RepositoryStatus,
    workspace: WorkspaceStatus,
    semantic_enrichment: SemanticEnrichmentStatus,
    #[serde(default)]
    authority_payload: Option<AuthorityPayloadReceipt>,
}

impl<'de> Deserialize<'de> for StatusReport {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = StatusReportWire::deserialize(deserializer)?;
        let report = Self {
            schema: wire.schema,
            authority: wire.authority,
            repo_root: wire.repo_root,
            repository: wire.repository,
            workspace: wire.workspace,
            semantic_enrichment: wire.semantic_enrichment,
            authority_payload: wire.authority_payload,
        };
        report.validate().map_err(serde::de::Error::custom)?;
        Ok(report)
    }
}

impl StatusReport {
    fn validate(&self) -> std::result::Result<(), String> {
        if self.repository.generation != self.repository.roots.generation {
            return Err(format!(
                "repository.generation ({}) does not match repository.roots.generation ({})",
                self.repository.generation, self.repository.roots.generation
            ));
        }
        self.repository
            .roots
            .validate()
            .map_err(|error| format!("repository.roots is invalid: {error}"))?;
        if self.semantic_enrichment.authority_generation != self.repository.generation {
            return Err(format!(
                "semantic_enrichment.authority_generation ({}) does not match \
                 repository.generation ({})",
                self.semantic_enrichment.authority_generation, self.repository.generation
            ));
        }
        if self.semantic_enrichment.workspace_generation != self.workspace.generation {
            return Err(format!(
                "semantic_enrichment.workspace_generation ({}) does not match \
                 workspace.generation ({})",
                self.semantic_enrichment.workspace_generation, self.workspace.generation
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandStatusRequest {
    #[serde(default)]
    pub json: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cli_sha: Option<String>,
    #[serde(default)]
    pub cli_dirty: bool,
    #[serde(default)]
    pub cli_source_known: bool,
    #[serde(default)]
    pub cli_dependency_provenance: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BuildStatus {
    pub cli_sha: String,
    pub cli_dirty: bool,
    #[serde(default)]
    pub cli_source_known: bool,
    #[serde(default)]
    pub cli_dependency_provenance: String,
    pub daemon_sha: String,
    pub daemon_dirty: bool,
    #[serde(default)]
    pub daemon_source_known: bool,
    #[serde(default)]
    pub daemon_dependency_provenance: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandStatusResponse {
    pub report: StatusReport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build: Option<BuildStatus>,
    #[serde(default)]
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub json: Option<String>,
}

impl CommandStatusRequest {
    pub fn new(json: bool) -> Self {
        let build = kin_buildinfo::get();
        Self {
            json,
            cli_sha: Some(build.sha.to_string()),
            cli_dirty: build.dirty,
            cli_source_known: build.source_known,
            cli_dependency_provenance: build.dependency_provenance.to_string(),
        }
    }
}

pub fn inspect(
    layout: &kin_core::KinLayout,
    binding: &kin_core::LocalRepositoryAuthorityBinding,
) -> Result<StatusReport> {
    let authority = ActiveRepositoryAuthority::open(binding)?;
    let lease = authority.manager().read_authority();
    let metadata = lease.metadata();
    let workspace = metadata
        .workspaces
        .iter()
        .find(|workspace| workspace.workspace_id == authority.workspace_id)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "repository {} has no workspace {} in repository-v6 authority",
                authority.repository_id,
                authority.workspace_id
            )
        })?;
    let roots = lease.roots().clone();
    if roots.generation != metadata.roots.generation {
        anyhow::bail!("repository-v6 lease exposed inconsistent root generations");
    }

    let artifact_count = workspace.tree.artifacts().len();
    let semantic_enrichment = semantic_enrichment_from_authority(&lease, &authority.workspace_id)?;
    let authority_payload = authority
        .payload_stats()
        .as_ref()
        .map(AuthorityPayloadReceipt::from_payload_stats);

    Ok(StatusReport {
        schema: STATUS_SCHEMA.to_string(),
        authority: "repository-v6".to_string(),
        repo_root: layout.working_dir().to_path_buf(),
        repository: RepositoryStatus {
            repository_id: authority.repository_id.clone(),
            generation: roots.generation,
            roots,
            ref_count: metadata.ref_state.refs.len(),
            default_ref: metadata.ref_state.default_ref.clone(),
            source_cas_verified: true,
        },
        workspace: WorkspaceStatus {
            workspace_id: workspace.workspace_id,
            generation: workspace.generation,
            head: workspace.head.clone(),
            base_target: workspace.base_target.clone(),
            base_tree_hash: workspace.base_tree_hash,
            tree_hash: workspace.tree_hash,
            dirty: workspace.is_dirty(),
            artifact_count,
        },
        semantic_enrichment,
        authority_payload,
    })
}

pub fn run(json: bool) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?).ok_or_else(|| {
        anyhow::anyhow!(
            "not a Kin repository (no .kin/ found)\nhint: run `kin init .` to initialize one"
        )
    })?;
    let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(&layout)?;
    let report = inspect(&layout, &binding)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print!("{}", render_text(&report, None));
    }
    Ok(())
}

pub fn build_command_status_response(
    report: StatusReport,
    json: bool,
    build: Option<BuildStatus>,
) -> Result<CommandStatusResponse> {
    let text = render_text(&report, build.as_ref());
    let json = json
        .then(|| serde_json::to_string(&report))
        .transpose()
        .context("serialize repository-v6 status")?;
    Ok(CommandStatusResponse {
        report,
        build,
        text,
        json,
    })
}

fn render_text(report: &StatusReport, build: Option<&BuildStatus>) -> String {
    let workspace_state = if report.workspace.dirty {
        "dirty"
    } else {
        "clean"
    };
    let enrichment = match report.semantic_enrichment.presence {
        SemanticEnrichmentPresence::Absent => "absent",
        SemanticEnrichmentPresence::Present => "present",
    };
    let mut lines = vec![
        "Kin repository-v6 status".to_string(),
        format!("Repository: {}", report.repository.repository_id),
        format!("Authority generation: {}", report.repository.generation),
        format!("Workspace: {}", report.workspace.workspace_id),
        format!(
            "Workspace generation: {}",
            report.workspace.generation
        ),
        format!("Head: {}", render_head(&report.workspace.head)),
        format!(
            "Tree: {} ({} artifacts, {workspace_state})",
            report.workspace.tree_hash, report.workspace.artifact_count
        ),
        format!(
            "Refs: {}{}",
            report.repository.ref_count,
            report
                .repository
                .default_ref
                .as_ref()
                .map(|name| format!(", default {name}"))
                .unwrap_or_default()
        ),
        format!(
            "Durable semantic enrichment: {enrichment} ({} entities, {} relations, {} changes at authority generation {}, workspace generation {}; completion not attested)",
            report.semantic_enrichment.entity_count,
            report.semantic_enrichment.relation_count,
            report.semantic_enrichment.semantic_change_count,
            report.semantic_enrichment.authority_generation,
            report.semantic_enrichment.workspace_generation
        ),
        "Live graph enrichment: see `kin graph status`".to_string(),
        "Source CAS: verified".to_string(),
        match report.authority_payload.as_ref() {
            Some(payload) => format!(
                "Authority payload read: {} bytes ({} snapshot bytes at generation {}, {} acknowledged deltas totalling {} bytes to generation {})",
                payload.total_payload_bytes,
                payload.snapshot_bytes,
                payload.snapshot_generation,
                payload.acknowledged_delta_count,
                payload.acknowledged_delta_bytes,
                payload.head_generation
            ),
            None => "Authority payload read: none (generation zero built in memory)".to_string(),
        },
    ];
    if let Some(build) = build {
        lines.push(format!(
            "Build: CLI {} / daemon {}",
            build_id(&build.cli_sha, build.cli_dirty),
            build_id(&build.daemon_sha, build.daemon_dirty)
        ));
    }
    lines.into_iter().map(|line| format!("{line}\n")).collect()
}

fn render_head(head: &WorkspaceHead) -> String {
    match head {
        WorkspaceHead::Symbolic { target } => format!("symbolic {target}"),
        WorkspaceHead::Detached { target } => format!("detached {}", render_target(target)),
    }
}

fn render_target(target: &RefTarget) -> String {
    match target {
        RefTarget::Change { change_id } => format!("change {change_id}"),
        RefTarget::ExternalObject { object } => {
            format!("{:?} {}", object.kind, object.oid)
        }
        RefTarget::Symbolic { target } => format!("symbolic {target}"),
    }
}

fn build_id(sha: &str, dirty: bool) -> String {
    if dirty && sha != "unknown" {
        format!("{sha}-dirty")
    } else {
        sha.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unreleased_v1_enrichment_is_not_silently_reinterpreted_as_v2() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(&init.layout).unwrap();
        let report = inspect(&init.layout, &binding).unwrap();
        let mut legacy = serde_json::to_value(report).unwrap();
        legacy["schema"] = serde_json::Value::String("kin.status.v1".to_string());

        let error = serde_json::from_value::<StatusReport>(legacy)
            .expect_err("a complete late-v1 daemon response must be rejected by schema");

        assert_eq!(STATUS_SCHEMA, "kin.status.v2");
        assert!(
            error
                .to_string()
                .contains("unsupported status schema 'kin.status.v1'"),
            "v1 must fail explicitly even when every v2 payload field is present: {error}"
        );
    }

    #[test]
    fn status_receipts_the_authority_payload_a_persisted_reopen_read() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        // A binding rebuilt from the layout reopens the persisted bytes rather
        // than reusing the in-memory authority that init constructed.
        let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(&init.layout).unwrap();

        let report = inspect(&init.layout, &binding).unwrap();

        // `None` is legal only where authority was never persisted. Accepting it
        // here would let status report a read whose payload was never measured.
        let payload = report.authority_payload.expect(
            "status on a persisted repository must receipt the payload its authority open read",
        );
        assert!(
            payload.snapshot_bytes > 0,
            "a recovered snapshot cannot occupy zero serialized bytes"
        );
        assert_eq!(
            payload.total_payload_bytes,
            payload.snapshot_bytes + payload.acknowledged_delta_bytes
        );
        assert!(
            render_text(&report, None).contains("Authority payload read: "),
            "text status must state the payload the open read"
        );

        let encoded = serde_json::to_value(&report).unwrap();
        assert_eq!(
            encoded["authority_payload"]["total_payload_bytes"],
            serde_json::json!(payload.total_payload_bytes)
        );
        assert_eq!(
            serde_json::from_value::<StatusReport>(encoded)
                .unwrap()
                .authority_payload,
            Some(payload)
        );
    }

    #[test]
    fn v2_accepts_a_report_without_a_payload_receipt_but_rejects_an_incoherent_one() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(&init.layout).unwrap();
        let valid = serde_json::to_value(inspect(&init.layout, &binding).unwrap()).unwrap();

        let mut without_receipt = valid.clone();
        without_receipt
            .as_object_mut()
            .unwrap()
            .remove("authority_payload");
        assert_eq!(
            serde_json::from_value::<StatusReport>(without_receipt)
                .expect("the receipt is additive over the released v2 shape")
                .authority_payload,
            None
        );

        let mut inflated_total = valid.clone();
        let claimed = inflated_total["authority_payload"]["total_payload_bytes"]
            .as_u64()
            .unwrap()
            + 1;
        inflated_total["authority_payload"]["total_payload_bytes"] = serde_json::json!(claimed);
        let error = serde_json::from_value::<StatusReport>(inflated_total)
            .expect_err("a total that exceeds the bytes it names must be refused");
        assert!(
            error.to_string().contains("total_payload_bytes"),
            "unexpected payload-receipt error: {error}"
        );

        let mut unaccounted_deltas = valid;
        unaccounted_deltas["authority_payload"]["head_generation"] = serde_json::json!(
            unaccounted_deltas["authority_payload"]["head_generation"]
                .as_u64()
                .unwrap()
                + 1
        );
        let error = serde_json::from_value::<StatusReport>(unaccounted_deltas)
            .expect_err("a generation span with no acknowledged deltas must be refused");
        assert!(
            error.to_string().contains("acknowledged_delta_count"),
            "unexpected payload-receipt error: {error}"
        );
    }

    #[test]
    fn v2_enrichment_round_trip_preserves_view_and_generations() {
        let enrichment = SemanticEnrichmentStatus {
            view: SemanticEnrichmentView::DurableRepositoryAuthority,
            authority_generation: 9,
            workspace_generation: 3,
            presence: SemanticEnrichmentPresence::Present,
            entity_count: 7,
            relation_count: 4,
            semantic_change_count: 2,
            completion_attested: false,
        };

        let encoded = serde_json::to_value(&enrichment).unwrap();
        assert_eq!(encoded["view"], "durable_repository_authority");
        assert_eq!(encoded["authority_generation"], 9);
        assert_eq!(encoded["workspace_generation"], 3);
        assert_eq!(
            serde_json::from_value::<SemanticEnrichmentStatus>(encoded).unwrap(),
            enrichment
        );
    }

    #[test]
    fn v2_rejects_false_authority_completion_and_generation_claims() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(&init.layout).unwrap();
        let valid = serde_json::to_value(inspect(&init.layout, &binding).unwrap()).unwrap();

        let mut wrong_authority = valid.clone();
        wrong_authority["authority"] = serde_json::json!("live-daemon-graph");
        let mut false_completion = valid.clone();
        false_completion["semantic_enrichment"]["completion_attested"] = serde_json::json!(true);
        let mut wrong_authority_generation = valid.clone();
        wrong_authority_generation["semantic_enrichment"]["authority_generation"] =
            serde_json::json!(99);
        let mut wrong_workspace_generation = valid.clone();
        wrong_workspace_generation["semantic_enrichment"]["workspace_generation"] =
            serde_json::json!(99);
        let mut wrong_root_generation = valid.clone();
        wrong_root_generation["repository"]["roots"]["generation"] = serde_json::json!(99);
        let mut wrong_root_version = valid.clone();
        wrong_root_version["repository"]["roots"]["version"] = serde_json::json!(99);
        let mut contradictory_presence = valid.clone();
        contradictory_presence["semantic_enrichment"]["presence"] = serde_json::json!("present");
        contradictory_presence["semantic_enrichment"]["entity_count"] = serde_json::json!(0);
        contradictory_presence["semantic_enrichment"]["relation_count"] = serde_json::json!(0);
        let mut unknown_report_field = valid.clone();
        unknown_report_field["unversioned_extension"] = serde_json::json!(true);
        let mut unknown_enrichment_field = valid;
        unknown_enrichment_field["semantic_enrichment"]["unversioned_extension"] =
            serde_json::json!(true);

        for (payload, expected) in [
            (wrong_authority, "unsupported status authority"),
            (
                false_completion,
                "does not carry a semantic-enrichment completion attestation",
            ),
            (
                wrong_authority_generation,
                "does not match repository.generation",
            ),
            (
                wrong_workspace_generation,
                "does not match workspace.generation",
            ),
            (
                wrong_root_generation,
                "does not match repository.roots.generation",
            ),
            (wrong_root_version, "repository.roots is invalid"),
            (
                contradictory_presence,
                "presence is present despite zero entity/relation counts",
            ),
            (
                unknown_report_field,
                "unknown field `unversioned_extension`",
            ),
            (
                unknown_enrichment_field,
                "unknown field `unversioned_extension`",
            ),
        ] {
            let error = serde_json::from_value::<StatusReport>(payload)
                .expect_err("a contradictory v2 status claim must fail deserialization");
            assert!(error.to_string().contains(expected), "{error}");
        }
    }

    #[test]
    fn non_utf8_symbolic_head_is_rendered_without_loss() {
        let target = RefName::from_bytes([
            b'r', b'e', b'f', b's', b'/', b'h', b'e', b'a', b'd', b's', b'/', 0xff,
        ])
        .unwrap();
        assert_eq!(
            render_head(&WorkspaceHead::Symbolic { target }),
            "symbolic refs/heads/\\xff"
        );
    }
}
