// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Coherent repository-v6 status.
//!
//! Every count below the enrichment line comes from one immutable authority
//! lease. Nothing here inspects checkout contents, legacy branch sidecars, Git,
//! or a separately opened graph snapshot. Opening the authority also
//! revalidates every referenced source body in the repository-owned CAS.
//!
//! The lease may be read in this process or, when a daemon already holds this
//! repository, by that daemon on this command's behalf. Both read the same
//! durable authority; only the daemon can additionally observe the live query
//! graph, which is why the report can come from there.
//!
//! Semantic counts are resolved from the workspace's durable first-parent
//! history and cumulative semantic overlay inside that lease. They deliberately
//! do not describe the daemon's mutable live graph: runtime reconcile and LSP
//! work may advance that derived view without changing repository authority.
//!
//! Embedding coverage is the one figure here that authority does not carry.
//! A repository-v6 lease records semantic identities, not which of them a
//! vector index holds, so coverage is reported as its own object naming the
//! live view it was sampled from. When no such view is available the object
//! says so; it never reports the zero that an unindexed graph would produce.
//!
//! Some of those absences are a window rather than a condition: an embedding
//! pass holds the work lock, or a mutation batch spans the sample, and the next
//! read observes coverage with nothing else having changed. Naming them is what
//! lets a caller tell "not measurable right now" from "measured and
//! incomplete", and `--wait-quiesce` lets it act on that instead of only
//! reading it, by bounding a re-read of exactly those states. Completeness is
//! never what the settle inspects, so an observed shortfall is published on the
//! first read and cannot be waited into looking whole.

use std::path::PathBuf;

use anyhow::{Context, Result};
use kin_model::{
    Hash256, RefName, RefTarget, RepositoryId, RootBundle, WorkspaceHead, WorkspaceId,
};
use serde::{Deserialize, Deserializer, Serialize};

use super::repository_authority::ActiveRepositoryAuthority;
use super::store_footprint::StoreFootprint;

/// First status contract carrying embedding coverage alongside enrichment
/// counts that name their durable view and exact authority/workspace
/// generations.
///
/// v2 carried no embedding, index, or vector state anywhere in the payload, so
/// a v2 reader cannot be handed a v3 one: absence of coverage was not a legal
/// v2 encoding of "coverage unknown", it was the whole shape. The version moves
/// rather than the field being defaulted, so a version-skewed pair fails naming
/// the schema instead of silently agreeing on a number neither of them meant.
/// The earlier, unreleased v1 shape carried counts with different semantics and
/// cannot be inferred truthfully either.
pub const STATUS_SCHEMA: &str = "kin.status.v3";

/// How long `kin status` will wait on a live daemon read before falling back to
/// its own authority read and reporting coverage as unobserved.
///
/// Status always has a complete local answer, so this bounds an optional
/// enrichment rather than the command itself. It is deliberately not shorter:
/// the daemon performs the same authority open the fallback would, and a budget
/// tight enough to protect against a stuck handler would also abandon a
/// legitimate read on a large store.
const LIVE_STATUS_READ_BUDGET: std::time::Duration = std::time::Duration::from_secs(30);

/// First and longest gap between re-reads inside a `--wait-quiesce` settle.
///
/// The settle sleeps between attempts rather than retrying immediately. What it
/// waits for is another task finishing: a spin would take the same round trip
/// over and over and compete for the runtime with the work whose completion is
/// the only thing that can change the answer.
const QUIESCE_BACKOFF_FLOOR: std::time::Duration = std::time::Duration::from_millis(50);
const QUIESCE_BACKOFF_CEILING: std::time::Duration = std::time::Duration::from_millis(500);

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
            "kin.status.v3 does not carry a semantic-enrichment completion attestation",
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

/// The live view one coverage observation was sampled from.
///
/// Coverage is only meaningful against the graph a query would actually search,
/// so the reader is told which graph answered rather than being left to assume
/// the durable authority did.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EmbeddingCoverageSource {
    /// A live query graph with a validated vector index installed. This is the
    /// same view `kin graph status` and `kin_graph_status` report.
    LiveQueryGraph,
}

/// Why coverage could not be observed.
///
/// Each variant is a distinct, actionable state. Collapsing any of them into
/// `indexed = 0` would publish a number that a fully embedded repository is
/// indistinguishable from.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EmbeddingCoverageUnobserved {
    /// No daemon holds this repository's live query graph. Status does not
    /// start one: it is a read, and opening a store with pending embeddings
    /// begins inference.
    NoRunningDaemon,
    /// A daemon was reachable but its status response could not be used, which
    /// includes a daemon built against a different status schema.
    DaemonStatusUnavailable,
    /// The live graph carries no vector index, so nothing in it can answer how
    /// many objects are indexed. `embedding_status` reports zero indexed for
    /// every retrievable object in this state, which is exactly the reading a
    /// never-embedded repository produces.
    NoVectorIndexAttached,
    /// This build ships no vector backend, so no index can be attached at all.
    VectorSupportDisabled,
    /// An embedding pass held the work lock, so no counter set could be sampled
    /// at one instant. Transient: the next read observes coverage once the pass
    /// releases.
    SamplingContended,
    /// The embedding work lock is poisoned, so an embedding pass panicked while
    /// holding it and no later pass can take it. This is permanent for the
    /// daemon's lifetime and means the embedding loop is dead, which is why it
    /// is not reported as contention: an operator told to retry a contended
    /// sample would wait for a pass that will never run.
    EmbeddingWorkLockPoisoned,
    /// A graph mutation batch was in flight across every sampling attempt, so
    /// no counter set could be paired with a stable graph authority. Transient,
    /// and distinct from a held embedding lock because the work that has to
    /// finish first is a different one.
    GraphMutationInFlight,
    /// The sampling task did not complete, so nothing was measured. Distinct
    /// from every state above, all of which are answers about a graph that was
    /// reachable.
    SamplingFailed,
}

impl EmbeddingCoverageUnobserved {
    /// Whether re-reading alone can turn this absence into an observation.
    ///
    /// Two of these states end on their own with nobody intervening: an
    /// embedding pass releases the work lock, and a mutation batch closes its
    /// authority epoch. A read that arrives afterwards measures the same graph
    /// the earlier one could not pair a stable epoch with, so waiting is
    /// waiting for a window to shut.
    ///
    /// Every other absence needs a different actor to change something first. A
    /// daemon has to be started, a vector index has to be attached, a build has
    /// to ship a backend, a poisoned lock needs a restart because no later pass
    /// can ever take it. Spending a settle budget on those would report the same
    /// absence later and call the delay progress.
    ///
    /// Exhaustive on purpose: a new absence has to state which side it is on
    /// rather than inheriting a wildcard that would silently make it waitable.
    pub fn settles_on_its_own(self) -> bool {
        match self {
            Self::SamplingContended | Self::GraphMutationInFlight => true,
            Self::NoRunningDaemon
            | Self::DaemonStatusUnavailable
            | Self::NoVectorIndexAttached
            | Self::VectorSupportDisabled
            | Self::EmbeddingWorkLockPoisoned
            | Self::SamplingFailed => false,
        }
    }
}

/// Embedding coverage of the live view that answers semantic queries.
///
/// Reported as a sum type because "nothing is indexed" and "nobody could say"
/// are different facts and every consumer that gates on progress needs to tell
/// them apart.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum EmbeddingCoverage {
    Observed {
        source: EmbeddingCoverageSource,
        indexed: usize,
        pending: usize,
        total: usize,
    },
    Unobserved {
        reason: EmbeddingCoverageUnobserved,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum EmbeddingCoverageState {
    Observed,
    Unobserved,
}

/// Deserialized as a flat wire shape rather than a tagged enum so that a
/// payload carrying the counts of one state under the tag of another is
/// refused instead of having its extra members dropped.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmbeddingCoverageWire {
    state: EmbeddingCoverageState,
    #[serde(default)]
    source: Option<EmbeddingCoverageSource>,
    #[serde(default)]
    reason: Option<EmbeddingCoverageUnobserved>,
    #[serde(default)]
    indexed: Option<usize>,
    #[serde(default)]
    pending: Option<usize>,
    #[serde(default)]
    total: Option<usize>,
}

impl<'de> Deserialize<'de> for EmbeddingCoverage {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = EmbeddingCoverageWire::deserialize(deserializer)?;
        let coverage = match wire.state {
            EmbeddingCoverageState::Observed => {
                if wire.reason.is_some() {
                    return Err(serde::de::Error::custom(
                        "embedding_coverage is observed but carries an unobserved reason",
                    ));
                }
                let missing = |field: &str| {
                    serde::de::Error::custom(format!(
                        "embedding_coverage is observed but carries no {field}"
                    ))
                };
                Self::Observed {
                    source: wire.source.ok_or_else(|| missing("source"))?,
                    indexed: wire.indexed.ok_or_else(|| missing("indexed"))?,
                    pending: wire.pending.ok_or_else(|| missing("pending"))?,
                    total: wire.total.ok_or_else(|| missing("total"))?,
                }
            }
            EmbeddingCoverageState::Unobserved => {
                if wire.source.is_some()
                    || wire.indexed.is_some()
                    || wire.pending.is_some()
                    || wire.total.is_some()
                {
                    return Err(serde::de::Error::custom(
                        "embedding_coverage is unobserved but carries coverage counts",
                    ));
                }
                Self::Unobserved {
                    reason: wire.reason.ok_or_else(|| {
                        serde::de::Error::custom(
                            "embedding_coverage is unobserved but carries no reason",
                        )
                    })?,
                }
            }
        };
        coverage.validate().map_err(serde::de::Error::custom)?;
        Ok(coverage)
    }
}

impl EmbeddingCoverage {
    pub fn unobserved(reason: EmbeddingCoverageUnobserved) -> Self {
        Self::Unobserved { reason }
    }

    /// The same triple invariants `kin.graph-status.v1` enforces.
    ///
    /// Two surfaces reporting one repository's coverage must not disagree about
    /// which triples are legal, or a consumer that validates against one of
    /// them accepts a payload the other calls impossible.
    fn validate(&self) -> std::result::Result<(), String> {
        let Self::Observed {
            indexed,
            pending,
            total,
            ..
        } = self
        else {
            return Ok(());
        };
        if indexed > total {
            return Err(format!(
                "embedding_coverage.indexed ({indexed}) exceeds embedding_coverage.total ({total})"
            ));
        }
        let uncovered = total.saturating_sub(*indexed);
        if *pending < uncovered {
            return Err(format!(
                "embedding_coverage.pending ({pending}) does not account for the {uncovered} \
                 retrievable objects that are not indexed"
            ));
        }
        Ok(())
    }
}

/// Sample coverage from a live query graph.
///
/// `embedding_status` derives `indexed` by testing every retrievable key
/// against the graph's vector index and answers zero for all of them when no
/// index is installed. A graph reconstructed from a snapshot never has one, so
/// counting it there would report zero coverage on a fully embedded repository
/// in a well-formed payload. Coverage is therefore published only once an index
/// is proven attached, and the absence is named otherwise.
#[cfg(feature = "vector")]
pub fn observe_embedding_coverage(graph: &kin_db::InMemoryGraph) -> EmbeddingCoverage {
    if graph.vector_index_stats().is_none() {
        return EmbeddingCoverage::unobserved(EmbeddingCoverageUnobserved::NoVectorIndexAttached);
    }
    let status = graph.embedding_status();
    EmbeddingCoverage::Observed {
        source: EmbeddingCoverageSource::LiveQueryGraph,
        indexed: status.indexed,
        pending: status.pending,
        total: status.total,
    }
}

/// Feature-disabled counterpart: with no vector backend there is no index to
/// attach and no coverage to observe.
#[cfg(not(feature = "vector"))]
pub fn observe_embedding_coverage(_graph: &kin_db::InMemoryGraph) -> EmbeddingCoverage {
    EmbeddingCoverage::unobserved(EmbeddingCoverageUnobserved::VectorSupportDisabled)
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
    /// Coverage of the live query graph, not of the authority lease above.
    /// Required in v3: a report that omitted it would be one whose reader could
    /// not tell an unobservable repository from an unembedded one.
    pub embedding_coverage: EmbeddingCoverage,
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
    embedding_coverage: EmbeddingCoverage,
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
            embedding_coverage: wire.embedding_coverage,
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
        self.embedding_coverage
            .validate()
            .map_err(|error| format!("embedding_coverage is invalid: {error}"))?;
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

/// Build one status report from an authority lease plus a stated coverage
/// observation.
///
/// Coverage is a parameter rather than something this function derives, because
/// nothing reachable from an authority lease can answer it. Making the caller
/// supply it means every path has to name where its coverage came from, and no
/// path can reach a default that reads as measured.
pub fn inspect(
    layout: &kin_core::KinLayout,
    binding: &kin_core::LocalRepositoryAuthorityBinding,
    embedding_coverage: EmbeddingCoverage,
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
                "repository {} has no workspace {} in its authority",
                authority.repository_id,
                authority.workspace_id
            )
        })?;
    let roots = lease.roots().clone();
    if roots.generation != metadata.roots.generation {
        anyhow::bail!(
            "this repository's store reported two different root generations for one lease, which \
             means another process wrote it while this command was reading; re-run `kin status`, \
             and run `kin health` if it repeats"
        );
    }

    let artifact_count = workspace.tree.artifacts().len();
    let semantic_enrichment = semantic_enrichment_from_authority(&lease, &authority.workspace_id)?;
    let authority_payload = authority
        .payload_stats()
        .as_ref()
        .map(AuthorityPayloadReceipt::from_payload_stats);

    let report = StatusReport {
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
        embedding_coverage,
        authority_payload,
    };
    // Validate on the way out, not only on the way in. The reader already
    // refuses an illegal report; running the same check here means a future
    // coverage source that publishes an impossible triple fails in the process
    // that built it rather than in every consumer that parses it.
    report.validate().map_err(|error| {
        anyhow::anyhow!(
            "kin built a status report this build considers invalid ({error}), so it refused \
                 to print it; run `kin health`, and `kin --version` against `kin daemon status` if \
                 the two are on different builds"
        )
    })?;
    Ok(report)
}

/// Read status from the daemon that already holds this repository's live query
/// graph, so the report carries coverage sampled from a real vector index.
///
/// This never starts a daemon. Status is a read, and opening a store whose
/// embeddings are pending starts inference on its own, which is not something a
/// status command may do as a side effect. The error is the reason the local
/// fallback will publish, so an unreachable daemon is reported as an
/// unobserved coverage rather than inferred as an unembedded repository.
///
/// A daemon that answers is not automatically believed. A status response this
/// binary cannot parse, which includes one carrying a status schema it does not
/// know, surfaces here as an unavailable daemon, so schema skew degrades to a
/// named absence instead of failing the command. A build mismatch alone does
/// not reach that gate: `check_response_build_match` refuses a mismatched
/// daemon build only under `KIN_STRICT_BUILD_MATCH` and otherwise warns once
/// and hands back the response. What protects this read from a skewed daemon is
/// the schema, not the build check.
async fn live_status_from_running_daemon(
    layout: &kin_core::KinLayout,
) -> std::result::Result<StatusReport, EmbeddingCoverageUnobserved> {
    let base_url = crate::daemon_client::resolve_daemon_url_if_running_async(layout)
        .await
        .ok_or(EmbeddingCoverageUnobserved::NoRunningDaemon)?;
    let unavailable = |error: anyhow::Error| {
        tracing::debug!(%error, "live status unavailable; reporting coverage as unobserved");
        EmbeddingCoverageUnobserved::DaemonStatusUnavailable
    };
    // The token is resolved from the repository this command resolved, not from
    // the process directory, so running status from a subdirectory does not
    // authenticate against a different repository's daemon.
    let client = crate::daemon_client::DaemonClient::from_base_url_for_layout(base_url, layout)
        .map_err(unavailable)?;
    // The client's default request budget is minutes long, which is right for a
    // mutation and wrong for a read that already has a complete local answer.
    // Supervisor-derived route resolution above returns only an endpoint that
    // answered `/health`; an explicit `KIN_DAEMON_URL` is trusted as supplied.
    // The budget therefore covers both an explicit unreachable route and the
    // narrower case of a healthy daemon stuck inside this handler. It still has
    // to allow a real authority open on a large store, which is the same work
    // the fallback would do.
    match tokio::time::timeout(
        LIVE_STATUS_READ_BUDGET,
        client.command_status(&CommandStatusRequest::new(false)),
    )
    .await
    {
        Ok(response) => response
            .map(|response| response.report)
            .map_err(unavailable),
        Err(_elapsed) => {
            tracing::debug!(
                budget_secs = LIVE_STATUS_READ_BUDGET.as_secs(),
                "live status read exceeded its budget; reporting coverage as unobserved"
            );
            Err(EmbeddingCoverageUnobserved::DaemonStatusUnavailable)
        }
    }
}

/// One complete status reading: the live daemon's when it answers, and this
/// process's own authority read naming why it did not otherwise.
async fn read_status_once(layout: &kin_core::KinLayout) -> Result<StatusReport> {
    match live_status_from_running_daemon(layout).await {
        Ok(report) => Ok(report),
        Err(reason) => {
            let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(layout)?;
            inspect(layout, &binding, EmbeddingCoverage::unobserved(reason))
        }
    }
}

/// Re-read until embedding coverage stops being momentarily unobservable, or
/// until `budget` is spent.
///
/// This waits on one thing only: an absence the state machine documents as
/// self-clearing. Three consequences, and they are the whole contract.
///
/// An observed coverage returns from the first read whatever it counts. A
/// half-embedded repository is not retried, not held back, and cannot be waited
/// into looking complete, because completeness is never what this inspects.
///
/// An absence that needs another actor to move returns immediately too, so a
/// missing daemon or a poisoned embedding lock is reported at once instead of
/// after a budget spent proving it will not change.
///
/// When the budget runs out the last real reading is returned unchanged. The
/// caller publishes what was actually seen, with its reason intact, rather than
/// a timeout standing in for an observation.
///
/// A zero budget reads exactly once, which is what every caller that did not
/// ask to wait gets.
async fn settle_embedding_coverage<Read, Reading>(
    budget: std::time::Duration,
    mut read: Read,
) -> Result<StatusReport>
where
    Read: FnMut() -> Reading,
    Reading: std::future::Future<Output = Result<StatusReport>>,
{
    let deadline = tokio::time::Instant::now() + budget;
    let mut backoff = QUIESCE_BACKOFF_FLOOR;
    loop {
        let report = read().await?;
        let EmbeddingCoverage::Unobserved { reason } = report.embedding_coverage else {
            return Ok(report);
        };
        if !reason.settles_on_its_own() {
            return Ok(report);
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Ok(report);
        }
        // Never overshoot the budget the caller stated, including on the last
        // nap before the deadline.
        tokio::time::sleep(backoff.min(deadline - now)).await;
        backoff = backoff.saturating_mul(2).min(QUIESCE_BACKOFF_CEILING);
    }
}

pub async fn run(json: bool, wait_quiesce: std::time::Duration) -> Result<()> {
    let layout = crate::commands::require_repository_layout()?;
    let report = settle_embedding_coverage(wait_quiesce, || read_status_once(&layout)).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        let footprint = StoreFootprint::measure(&layout);
        print!("{}", render_text(&report, None, Some(&footprint)));
    }
    Ok(())
}

pub fn build_command_status_response(
    report: StatusReport,
    json: bool,
    build: Option<BuildStatus>,
    footprint: Option<&StoreFootprint>,
) -> Result<CommandStatusResponse> {
    let text = render_text(&report, build.as_ref(), footprint);
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

/// Render the report, plus the two observations that are deliberately NOT in it.
///
/// `build` and `footprint` are separate arguments for the same reason. A
/// [`StatusReport`] is derived from one immutable authority lease and must be
/// byte-identical across any amount of checkout or Git drift, which is a
/// property this repository tests directly. Store size is the opposite kind of
/// fact: it is a measurement of the disk this command is standing on, and it
/// moves whenever the working tree does. Carrying it inside the report would
/// have made authority status vary with the filesystem, so it rides alongside
/// the report on the text surface instead, exactly as the build stamp does.
fn render_text(
    report: &StatusReport,
    build: Option<&BuildStatus>,
    footprint: Option<&StoreFootprint>,
) -> String {
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
        format!(
            "Live embedding coverage: {}",
            render_embedding_coverage(&report.embedding_coverage)
        ),
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
    if let Some(footprint) = footprint {
        lines.push(format!("Store size: {}", footprint.render()));
    }
    if let Some(build) = build {
        lines.push(format!(
            "Build: CLI {} / daemon {}",
            build_id(&build.cli_sha, build.cli_dirty),
            build_id(&build.daemon_sha, build.daemon_dirty)
        ));
    }
    lines.into_iter().map(|line| format!("{line}\n")).collect()
}

/// Render coverage so the text surface states the same distinction the payload
/// does. An unobserved coverage prints why, never a count.
fn render_embedding_coverage(coverage: &EmbeddingCoverage) -> String {
    match coverage {
        EmbeddingCoverage::Observed {
            source,
            indexed,
            pending,
            total,
        } => {
            let view = match source {
                EmbeddingCoverageSource::LiveQueryGraph => "live query graph",
            };
            format!("{indexed}/{total} indexed, {pending} pending ({view})")
        }
        EmbeddingCoverage::Unobserved { reason } => {
            let explanation = match reason {
                EmbeddingCoverageUnobserved::NoRunningDaemon => {
                    "no daemon holds this repository's live graph"
                }
                EmbeddingCoverageUnobserved::DaemonStatusUnavailable => {
                    "the daemon's status response could not be used"
                }
                EmbeddingCoverageUnobserved::NoVectorIndexAttached => {
                    "the live graph carries no vector index"
                }
                EmbeddingCoverageUnobserved::VectorSupportDisabled => {
                    "this build ships no vector backend"
                }
                EmbeddingCoverageUnobserved::SamplingContended => "an embedding pass was in flight",
                EmbeddingCoverageUnobserved::EmbeddingWorkLockPoisoned => {
                    "the embedding work lock is poisoned; this daemon's embedding loop is dead \
                     and will not resume without a restart"
                }
                EmbeddingCoverageUnobserved::GraphMutationInFlight => {
                    "a graph mutation was in flight across every sampling attempt"
                }
                EmbeddingCoverageUnobserved::SamplingFailed => {
                    "the coverage sample did not complete"
                }
            };
            format!("not observed ({explanation})")
        }
    }
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

    /// The coverage a bare authority read publishes. These cases exercise the
    /// durable half of the report, where no live graph was consulted, so this
    /// is the honest observation for them rather than a stand-in for one.
    fn unobserved_fixture() -> EmbeddingCoverage {
        EmbeddingCoverage::unobserved(EmbeddingCoverageUnobserved::NoRunningDaemon)
    }

    #[test]
    fn unreleased_v1_enrichment_is_not_silently_reinterpreted_as_v3() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(&init.layout).unwrap();
        let report = inspect(&init.layout, &binding, unobserved_fixture()).unwrap();
        let mut legacy = serde_json::to_value(report).unwrap();
        legacy["schema"] = serde_json::Value::String("kin.status.v1".to_string());

        let error = serde_json::from_value::<StatusReport>(legacy)
            .expect_err("a complete late-v1 daemon response must be rejected by schema");

        assert_eq!(STATUS_SCHEMA, "kin.status.v3");
        assert!(
            error
                .to_string()
                .contains("unsupported status schema 'kin.status.v1'"),
            "v1 must fail explicitly even when every v3 payload field is present: {error}"
        );
    }

    #[test]
    fn status_receipts_the_authority_payload_a_persisted_reopen_read() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        // A binding rebuilt from the layout reopens the persisted bytes rather
        // than reusing the in-memory authority that init constructed.
        let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(&init.layout).unwrap();

        let report = inspect(&init.layout, &binding, unobserved_fixture()).unwrap();

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
            render_text(&report, None, None).contains("Authority payload read: "),
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
    fn v3_accepts_a_report_without_a_payload_receipt_but_rejects_an_incoherent_one() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(&init.layout).unwrap();
        let valid =
            serde_json::to_value(inspect(&init.layout, &binding, unobserved_fixture()).unwrap())
                .unwrap();

        let mut without_receipt = valid.clone();
        without_receipt
            .as_object_mut()
            .unwrap()
            .remove("authority_payload");
        assert_eq!(
            serde_json::from_value::<StatusReport>(without_receipt)
                .expect("the receipt is additive over the released report shape")
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
    fn v3_enrichment_round_trip_preserves_view_and_generations() {
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
    fn v3_rejects_false_authority_completion_and_generation_claims() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(&init.layout).unwrap();
        let valid =
            serde_json::to_value(inspect(&init.layout, &binding, unobserved_fixture()).unwrap())
                .unwrap();

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
                .expect_err("a contradictory v3 status claim must fail deserialization");
            assert!(error.to_string().contains(expected), "{error}");
        }
    }

    #[test]
    fn a_v2_payload_is_refused_by_schema_and_a_v3_one_may_not_omit_coverage() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(&init.layout).unwrap();
        let valid =
            serde_json::to_value(inspect(&init.layout, &binding, unobserved_fixture()).unwrap())
                .unwrap();

        // A v2 payload is exactly a v3 one without coverage. It must fail
        // naming the version, not the field: the field's absence is not a v2
        // statement that coverage was unknown, it is a different contract.
        let mut released_v2 = valid.clone();
        let object = released_v2.as_object_mut().unwrap();
        object.remove("embedding_coverage");
        object.insert(
            "schema".to_string(),
            serde_json::Value::String("kin.status.v2".to_string()),
        );
        let error = serde_json::from_value::<StatusReport>(released_v2)
            .expect_err("a released v2 payload is not a v3 report");
        assert!(
            error
                .to_string()
                .contains("unsupported status schema 'kin.status.v2'"),
            "version skew must be reported as a schema mismatch: {error}"
        );

        // Within v3 the field is required, so a truncated payload cannot be
        // read as a repository whose coverage happened to be absent.
        let mut without_coverage = valid;
        without_coverage
            .as_object_mut()
            .unwrap()
            .remove("embedding_coverage");
        let error = serde_json::from_value::<StatusReport>(without_coverage)
            .expect_err("v3 coverage is required, not defaulted");
        assert!(
            error.to_string().contains("embedding_coverage"),
            "unexpected missing-coverage error: {error}"
        );
    }

    #[test]
    fn coverage_states_may_not_borrow_each_other_s_members() {
        let observed = serde_json::to_value(EmbeddingCoverage::Observed {
            source: EmbeddingCoverageSource::LiveQueryGraph,
            indexed: 5,
            pending: 2,
            total: 7,
        })
        .unwrap();
        assert_eq!(observed["state"], "observed");
        assert_eq!(observed["source"], "live_query_graph");
        assert_eq!(
            serde_json::from_value::<EmbeddingCoverage>(observed.clone()).unwrap(),
            EmbeddingCoverage::Observed {
                source: EmbeddingCoverageSource::LiveQueryGraph,
                indexed: 5,
                pending: 2,
                total: 7,
            }
        );

        let unobserved = serde_json::to_value(EmbeddingCoverage::unobserved(
            EmbeddingCoverageUnobserved::NoVectorIndexAttached,
        ))
        .unwrap();
        assert_eq!(unobserved["state"], "unobserved");
        assert_eq!(unobserved["reason"], "no_vector_index_attached");
        assert!(
            unobserved.get("indexed").is_none(),
            "an unobserved coverage must not serialize a count: {unobserved}"
        );

        // A count smuggled under the unobserved tag would let a consumer read
        // zero coverage from a payload that declared it had none to report.
        let mut counted_absence = unobserved.clone();
        counted_absence["indexed"] = serde_json::json!(0);
        let error = serde_json::from_value::<EmbeddingCoverage>(counted_absence)
            .expect_err("an unobserved coverage carrying counts must be refused");
        assert!(
            error.to_string().contains("carries coverage counts"),
            "{error}"
        );

        let mut reasoned_observation = observed;
        reasoned_observation["reason"] = serde_json::json!("no_running_daemon");
        let error = serde_json::from_value::<EmbeddingCoverage>(reasoned_observation)
            .expect_err("an observed coverage carrying an absence reason must be refused");
        assert!(error.to_string().contains("unobserved reason"), "{error}");

        let mut reasonless_absence = unobserved;
        reasonless_absence.as_object_mut().unwrap().remove("reason");
        let error = serde_json::from_value::<EmbeddingCoverage>(reasonless_absence)
            .expect_err("an unobserved coverage must say why");
        assert!(error.to_string().contains("carries no reason"), "{error}");
    }

    #[test]
    fn coverage_rejects_the_triples_graph_status_v1_rejects() {
        let over_indexed = serde_json::json!({
            "state": "observed",
            "source": "live_query_graph",
            "indexed": 8,
            "pending": 0,
            "total": 7,
        });
        let error = serde_json::from_value::<EmbeddingCoverage>(over_indexed)
            .expect_err("more indexed than retrievable is impossible");
        assert!(error.to_string().contains("exceeds"), "{error}");

        // graph-status.v1 refuses this triple, so status must too: it asserts
        // that nothing is indexed and nothing is outstanding at once.
        let unaccounted = serde_json::json!({
            "state": "observed",
            "source": "live_query_graph",
            "indexed": 0,
            "pending": 0,
            "total": 7,
        });
        let error = serde_json::from_value::<EmbeddingCoverage>(unaccounted)
            .expect_err("uncovered objects with nothing pending is impossible");
        assert!(
            error.to_string().contains("does not account for"),
            "{error}"
        );
    }

    #[test]
    fn text_status_states_an_absent_coverage_rather_than_printing_zero() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(&init.layout).unwrap();

        let unobserved = inspect(
            &init.layout,
            &binding,
            EmbeddingCoverage::unobserved(EmbeddingCoverageUnobserved::NoVectorIndexAttached),
        )
        .unwrap();
        let rendered = render_text(&unobserved, None, None);
        assert!(
            rendered.contains(
                "Live embedding coverage: not observed (the live graph carries no vector index)"
            ),
            "{rendered}"
        );
        assert!(
            !rendered.contains("0/0 indexed"),
            "an unobservable coverage must never render as a measured zero: {rendered}"
        );

        let observed = inspect(
            &init.layout,
            &binding,
            EmbeddingCoverage::Observed {
                source: EmbeddingCoverageSource::LiveQueryGraph,
                indexed: 41,
                pending: 16,
                total: 57,
            },
        )
        .unwrap();
        assert!(
            render_text(&observed, None, None)
                .contains("Live embedding coverage: 41/57 indexed, 16 pending (live query graph)"),
            "{}",
            render_text(&observed, None, None)
        );
    }

    /// Store size rides alongside the report, never inside it.
    ///
    /// Both halves matter. A caller that measured the disk must see the line,
    /// or `kin status` stops disclosing the number this exists to disclose. A
    /// caller that did not must see NO line, because the alternative is a
    /// fabricated zero or a "not measured" that nobody asked for. The report
    /// itself carries no store size in either case, which is what keeps
    /// authority status byte-identical across checkout drift.
    #[test]
    fn store_size_renders_from_the_measurement_and_not_from_the_report() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(&init.layout).unwrap();
        let report = inspect(&init.layout, &binding, unobserved_fixture()).unwrap();

        let without = render_text(&report, None, None);
        assert!(
            !without.contains("Store size"),
            "an unmeasured status must print no store line at all: {without}"
        );

        let footprint = StoreFootprint::measure(&init.layout);
        let with = render_text(&report, None, Some(&footprint));
        assert!(
            with.contains("Store size: ") && with.contains("under .kin/"),
            "a measured status must print the store line: {with}"
        );

        let encoded = serde_json::to_value(&report).unwrap();
        assert!(
            encoded.get("store_footprint").is_none(),
            "the authority report must carry no filesystem measurement: {encoded}"
        );
    }

    /// A permanent condition must not read as the transient one. Once the
    /// embedding work lock is poisoned no later pass can take it, so the text
    /// has to stop telling the reader an embedding pass is in flight.
    #[test]
    fn a_poisoned_embedding_lock_renders_apart_from_a_pass_in_flight() {
        let contended = render_embedding_coverage(&EmbeddingCoverage::unobserved(
            EmbeddingCoverageUnobserved::SamplingContended,
        ));
        let poisoned = render_embedding_coverage(&EmbeddingCoverage::unobserved(
            EmbeddingCoverageUnobserved::EmbeddingWorkLockPoisoned,
        ));

        assert_ne!(
            contended, poisoned,
            "a dead embedding loop and a pass in flight must not render alike"
        );
        assert!(poisoned.contains("poisoned"), "{poisoned}");
        assert!(
            !poisoned.contains("in flight"),
            "a poisoned lock has no pass in flight to wait for: {poisoned}"
        );
    }

    /// The reader already refuses an impossible triple. The writer has to as
    /// well, or a future coverage source publishes one and only its consumers
    /// find out.
    #[test]
    fn building_a_report_refuses_an_impossible_coverage_triple() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(&init.layout).unwrap();

        let error = inspect(
            &init.layout,
            &binding,
            EmbeddingCoverage::Observed {
                source: EmbeddingCoverageSource::LiveQueryGraph,
                indexed: 9,
                pending: 0,
                total: 3,
            },
        )
        .expect_err("a report indexing more objects than it holds must not be built");
        assert!(
            error.to_string().contains("embedding_coverage is invalid"),
            "{error}"
        );
    }

    /// One real report to drive the settle with, so it is exercised against the
    /// shape production hands it rather than a hand-built stand-in.
    fn settle_base_report() -> StatusReport {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(&init.layout).unwrap();
        inspect(&init.layout, &binding, unobserved_fixture()).unwrap()
    }

    fn carrying(base: &StatusReport, coverage: EmbeddingCoverage) -> StatusReport {
        let mut report = base.clone();
        report.embedding_coverage = coverage;
        report
    }

    /// Slack allowed above a settle budget on a loaded machine. Wide on
    /// purpose: these bounds exist to catch a settle that never stops, not to
    /// measure scheduler latency, and a tight bound here would fail on load
    /// rather than on a defect.
    const SETTLE_SLACK: std::time::Duration = std::time::Duration::from_secs(5);

    /// Budget handed to a case that must not wait at all. Generous enough that
    /// spending any of it is unambiguous, short enough that a settle which
    /// wrongly waits fails the suite quickly instead of hanging it.
    const IMMEDIATE_BUDGET: std::time::Duration = std::time::Duration::from_secs(2);

    /// Drive the settle with a scripted sequence of readings, returning the
    /// final report, how many readings were consumed, and how much of the
    /// budget was spent. The last entry repeats once the script runs out, which
    /// is how a never-clearing condition is expressed.
    async fn drive_settle(
        budget: std::time::Duration,
        script: Vec<StatusReport>,
    ) -> (StatusReport, usize, std::time::Duration) {
        let reads = std::cell::Cell::new(0usize);
        let started = tokio::time::Instant::now();
        let report = settle_embedding_coverage(budget, || {
            let attempt = reads.get();
            reads.set(attempt + 1);
            let reading = script[attempt.min(script.len() - 1)].clone();
            async move { Ok(reading) }
        })
        .await
        .unwrap();
        (report, reads.get(), tokio::time::Instant::now() - started)
    }

    /// The FIR-1877 race itself: the daemon could not pair a stable authority
    /// epoch with a sample, and the coverage it was hiding is observable a
    /// moment later. A single-sample caller failed here.
    #[tokio::test]
    async fn a_mutation_in_flight_settles_into_the_observation_it_was_hiding() {
        let base = settle_base_report();
        let stalled = carrying(
            &base,
            EmbeddingCoverage::unobserved(EmbeddingCoverageUnobserved::GraphMutationInFlight),
        );
        let settled = carrying(
            &base,
            EmbeddingCoverage::Observed {
                source: EmbeddingCoverageSource::LiveQueryGraph,
                indexed: 57,
                pending: 0,
                total: 57,
            },
        );

        let (report, reads, elapsed) = drive_settle(
            std::time::Duration::from_secs(30),
            vec![stalled.clone(), stalled, settled.clone()],
        )
        .await;

        assert_eq!(
            report, settled,
            "the settle must publish the reading it waited for"
        );
        assert_eq!(reads, 3, "the settle must re-read until the window shut");
        assert!(
            elapsed < std::time::Duration::from_secs(30),
            "the settle must return when coverage is observable, not at its deadline: {elapsed:?}"
        );
    }

    /// A held embedding lock is the sibling transient state and settles the
    /// same way.
    #[tokio::test]
    async fn a_contended_sample_settles_the_same_way() {
        let base = settle_base_report();
        let contended = carrying(
            &base,
            EmbeddingCoverage::unobserved(EmbeddingCoverageUnobserved::SamplingContended),
        );
        let settled = carrying(
            &base,
            EmbeddingCoverage::Observed {
                source: EmbeddingCoverageSource::LiveQueryGraph,
                indexed: 4,
                pending: 0,
                total: 4,
            },
        );

        let (report, reads, _) = drive_settle(
            std::time::Duration::from_secs(30),
            vec![contended, settled.clone()],
        )
        .await;

        assert_eq!(report, settled);
        assert_eq!(reads, 2);
    }

    /// A window that never shuts must expire truthfully. The caller receives
    /// the last real reading, still unobserved and still naming its reason, so
    /// its own assertion fails on what was actually seen.
    #[tokio::test]
    async fn a_window_that_never_shuts_expires_reporting_the_last_state_seen() {
        let base = settle_base_report();
        let budget = std::time::Duration::from_millis(250);
        let stalled = carrying(
            &base,
            EmbeddingCoverage::unobserved(EmbeddingCoverageUnobserved::GraphMutationInFlight),
        );

        let (report, reads, elapsed) = drive_settle(budget, vec![stalled.clone()]).await;

        assert_eq!(
            report, stalled,
            "an expired settle must publish the reading it last took, not a synthesized one"
        );
        assert!(
            elapsed >= budget,
            "the settle must spend the budget it was given: {elapsed:?} < {budget:?}"
        );
        assert!(
            elapsed < budget + SETTLE_SLACK,
            "the settle must stop at its deadline rather than wait on: {elapsed:?}"
        );
        assert!(
            reads > 1,
            "an expired settle must have actually re-read, not slept once: {reads}"
        );
        // A spin would take far more readings than a backoff floored at 50ms
        // can fit into the budget.
        assert!(
            reads <= 1 + (budget.as_millis() / QUIESCE_BACKOFF_FLOOR.as_millis()) as usize,
            "the settle must back off between readings rather than spin: {reads}"
        );
    }

    /// The falsification that matters most. A store whose coverage is genuinely
    /// incomplete is observed, not unobservable, so the settle returns it
    /// untouched on the first reading. Nothing here can wait a shortfall into
    /// looking whole, and a caller asserting indexed == total still fails.
    #[tokio::test]
    async fn genuine_incompleteness_is_returned_at_once_and_never_masked() {
        let base = settle_base_report();
        let incomplete = carrying(
            &base,
            EmbeddingCoverage::Observed {
                source: EmbeddingCoverageSource::LiveQueryGraph,
                indexed: 11,
                pending: 46,
                total: 57,
            },
        );

        let (report, reads, elapsed) =
            drive_settle(IMMEDIATE_BUDGET, vec![incomplete.clone()]).await;

        assert_eq!(
            report, incomplete,
            "an observed shortfall must pass through unchanged"
        );
        assert_eq!(reads, 1, "an observed coverage must never be re-read");
        assert!(
            elapsed < IMMEDIATE_BUDGET,
            "an observed coverage must not consume the settle budget: {elapsed:?}"
        );
        let EmbeddingCoverage::Observed { indexed, total, .. } = report.embedding_coverage else {
            panic!("coverage must remain observed");
        };
        assert_ne!(
            indexed, total,
            "the shortfall a proof asserts on must survive the settle"
        );
    }

    /// An empty store reads as observed zero, not as unobservable, so a
    /// never-embedded repository fails a completeness assertion immediately
    /// instead of being waited on.
    #[tokio::test]
    async fn an_unembedded_store_is_not_waited_on() {
        let base = settle_base_report();
        let empty = carrying(
            &base,
            EmbeddingCoverage::Observed {
                source: EmbeddingCoverageSource::LiveQueryGraph,
                indexed: 0,
                pending: 0,
                total: 0,
            },
        );

        let (report, reads, elapsed) = drive_settle(IMMEDIATE_BUDGET, vec![empty.clone()]).await;

        assert_eq!(report, empty);
        assert_eq!(reads, 1);
        assert!(elapsed < IMMEDIATE_BUDGET, "{elapsed:?}");
    }

    /// An absence a re-read cannot clear must not consume the budget. Waiting
    /// on a poisoned embedding lock would delay the report and end at the same
    /// answer, having told the operator to keep waiting for a pass that can
    /// never run.
    #[tokio::test]
    async fn an_absence_that_needs_another_actor_returns_immediately() {
        let base = settle_base_report();
        for reason in [
            EmbeddingCoverageUnobserved::EmbeddingWorkLockPoisoned,
            EmbeddingCoverageUnobserved::NoRunningDaemon,
            EmbeddingCoverageUnobserved::NoVectorIndexAttached,
            EmbeddingCoverageUnobserved::VectorSupportDisabled,
            EmbeddingCoverageUnobserved::DaemonStatusUnavailable,
            EmbeddingCoverageUnobserved::SamplingFailed,
        ] {
            let stuck = carrying(&base, EmbeddingCoverage::unobserved(reason));
            let (report, reads, elapsed) =
                drive_settle(IMMEDIATE_BUDGET, vec![stuck.clone()]).await;

            assert_eq!(report, stuck, "{reason:?} must be published as read");
            assert_eq!(reads, 1, "{reason:?} must not be re-read");
            assert!(
                elapsed < IMMEDIATE_BUDGET,
                "{reason:?} must not consume the settle budget: {elapsed:?}"
            );
        }
    }

    /// The default every caller that did not ask to wait receives: exactly the
    /// single sample the command took before this flag existed.
    #[tokio::test]
    async fn a_zero_budget_reads_exactly_once_even_on_a_transient_absence() {
        let base = settle_base_report();
        let stalled = carrying(
            &base,
            EmbeddingCoverage::unobserved(EmbeddingCoverageUnobserved::GraphMutationInFlight),
        );

        let (report, reads, elapsed) =
            drive_settle(std::time::Duration::ZERO, vec![stalled.clone()]).await;

        assert_eq!(report, stalled);
        assert_eq!(reads, 1);
        assert!(elapsed < IMMEDIATE_BUDGET, "{elapsed:?}");
    }

    /// The classification is the whole safety argument, so assert it directly
    /// rather than only through the loop that consults it.
    #[test]
    fn only_the_documented_transient_absences_are_waited_on() {
        assert!(EmbeddingCoverageUnobserved::SamplingContended.settles_on_its_own());
        assert!(EmbeddingCoverageUnobserved::GraphMutationInFlight.settles_on_its_own());
        for permanent in [
            EmbeddingCoverageUnobserved::NoRunningDaemon,
            EmbeddingCoverageUnobserved::DaemonStatusUnavailable,
            EmbeddingCoverageUnobserved::NoVectorIndexAttached,
            EmbeddingCoverageUnobserved::VectorSupportDisabled,
            EmbeddingCoverageUnobserved::EmbeddingWorkLockPoisoned,
            EmbeddingCoverageUnobserved::SamplingFailed,
        ] {
            assert!(
                !permanent.settles_on_its_own(),
                "{permanent:?} does not clear by re-reading and must not be waited on"
            );
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
