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
use chrono::Utc;
use kin_core::last_admission::LastAdmissionRead;
use kin_model::{
    Hash256, MergeTransactionRecord, RefName, RefTarget, RepositoryId, RootBundle, WorkspaceHead,
    WorkspaceId,
};
use serde::{Deserialize, Deserializer, Serialize};

use super::repository_authority::{ActiveRepositoryAuthority, AuthoritySource};
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
    /// Whether the workspace tree sits ahead of `base_target`, or carries
    /// uncommitted semantics.
    ///
    /// This answers "does my workspace differ from the change it is based on",
    /// and it is the only question it answers. It is emphatically not "is
    /// everything on disk in the graph": a file the graph has never admitted
    /// contributes nothing to this flag, so a workspace can be dirty with no
    /// untracked file in sight and can match its base while non-ignored host
    /// paths sit outside graph truth. `kin graph status` is what reports the
    /// second question, and the rendered wording here avoids the bare words
    /// clean and dirty so the two cannot be read as one.
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
    /// A merge this workspace is holding open, read off the same authority the
    /// report came from.
    ///
    /// Carried on the ENVELOPE and not in `report`. `StatusReportWire` denies
    /// unknown fields, so a key added there makes an older CLI reject a newer
    /// daemon's report outright and is a v4 decision to take deliberately. This
    /// struct has never denied them and every field beside `report` already
    /// defaults, so an older peer on either side of the wire ignores this and
    /// keeps working.
    ///
    /// The point of carrying it at all is that the caller stops opening the
    /// whole store a second time to read it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merge: Option<MergeInProgress>,
    /// Where this workspace sits relative to the branch its head names, from
    /// that same authority and for that same reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_tip: Option<crate::commands::workspace_tip::WorkspaceTip>,
    /// Whether this responder took the two readings above off its own authority.
    ///
    /// A flag rather than a `None` test on `merge`, because "this build did not
    /// read a merge" and "this workspace is holding no merge open" are different
    /// facts and only the first is a reason for the caller to open the store
    /// itself. Without it a new CLI against an older daemon would print a clean
    /// status over a workspace with seventy-six conflicts parked in it, which is
    /// FIR-2961 reintroduced through the wire rather than through the code.
    ///
    /// `#[serde(default)]` makes an older peer's silence read as "did not", so
    /// the caller falls back to one local open and answers exactly as it did.
    #[serde(default)]
    pub authority_readings_taken: bool,
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
    inspect_at(layout, &authority, embedding_coverage)
}

/// The same report, from an authority the caller already opened.
///
/// The open is the expensive half of this command by orders of magnitude: it
/// re-verifies every persisted body, so it costs whatever the whole store is
/// worth. A caller that needs more than one reading from repository authority
/// takes ONE open and asks for each of them here, rather than reaching for the
/// binding-taking wrapper once per reading, which is how one `kin status`
/// invocation came to open the whole store twice in the CLI and twice more
/// inside the daemon serving it.
pub fn inspect_at(
    layout: &kin_core::KinLayout,
    authority: &ActiveRepositoryAuthority,
    embedding_coverage: EmbeddingCoverage,
) -> Result<StatusReport> {
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
             and run `kin doctor` if it repeats"
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
                 to print it; run `kin doctor`, and `kin --version` against `kin daemon status` if \
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
) -> std::result::Result<CommandStatusResponse, EmbeddingCoverageUnobserved> {
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
        Ok(response) => response.map_err(unavailable),
        Err(_elapsed) => {
            tracing::debug!(
                budget_secs = LIVE_STATUS_READ_BUDGET.as_secs(),
                "live status read exceeded its budget; reporting coverage as unobserved"
            );
            Err(EmbeddingCoverageUnobserved::DaemonStatusUnavailable)
        }
    }
}

/// One complete status reading, and everything the caller would otherwise open
/// the store again to learn.
///
/// The merge and workspace-tip readings ride here rather than being fetched by
/// their own helpers, and that IS the fix: each of those helpers takes a
/// binding and opens the whole store for itself, which is how one `kin status`
/// came to pay for three whole-store opens on a 470 MiB repository.
pub struct StatusReading {
    pub report: StatusReport,
    pub merge: Option<MergeInProgress>,
    pub workspace_tip: crate::commands::workspace_tip::WorkspaceTip,
    pub source: AuthoritySource,
}

/// One complete status reading: the live daemon's when it answers, and this
/// process's own authority read naming why it did not otherwise.
///
/// Exactly zero authority opens in this process on the daemon arm, and exactly
/// one on the fallback arm. The fallback opens once and asks that one open for
/// all three readings.
async fn read_status_once(layout: &kin_core::KinLayout) -> Result<StatusReading> {
    match live_status_from_running_daemon(layout).await {
        // A daemon that answered but did not take the merge and tip readings is
        // an older build. Believing its silence would print a clean status over
        // a workspace holding a merge open, so this pays for exactly one local
        // open to read them, which is what this command did before the readings
        // moved onto the response.
        Ok(response) if !response.authority_readings_taken => {
            let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(layout)?;
            let authority = ActiveRepositoryAuthority::open(&binding)?;
            Ok(StatusReading {
                report: response.report,
                merge: merge_in_progress_at(&authority),
                workspace_tip: workspace_tip_at(&authority),
                source: AuthoritySource::RunningDaemonAndOwnOpen,
            })
        }
        Ok(response) => Ok(StatusReading {
            report: response.report,
            merge: response.merge,
            // A responder that says it took the readings and then carries no tip
            // is a build defect, not a current workspace, and rendering nothing
            // would say exactly that. Name the gap instead.
            workspace_tip: response.workspace_tip.unwrap_or(
                crate::commands::workspace_tip::WorkspaceTip::Unknown {
                    reason: "the daemon that answered this status reported taking the reading \
                             and then carried none"
                        .to_string(),
                },
            ),
            source: AuthoritySource::RunningDaemon,
        }),
        Err(reason) => {
            let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(layout)?;
            let authority = ActiveRepositoryAuthority::open(&binding)?;
            let report = inspect_at(layout, &authority, EmbeddingCoverage::unobserved(reason))?;
            Ok(StatusReading {
                merge: merge_in_progress_at(&authority),
                workspace_tip: workspace_tip_at(&authority),
                report,
                source: AuthoritySource::OwnAuthorityOpen,
            })
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
) -> Result<StatusReading>
where
    Read: FnMut() -> Reading,
    Reading: std::future::Future<Output = Result<StatusReading>>,
{
    let deadline = tokio::time::Instant::now() + budget;
    let mut backoff = QUIESCE_BACKOFF_FLOOR;
    loop {
        let reading = read().await?;
        let EmbeddingCoverage::Unobserved { reason } = reading.report.embedding_coverage else {
            return Ok(reading);
        };
        if !reason.settles_on_its_own() {
            return Ok(reading);
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Ok(reading);
        }
        // Never overshoot the budget the caller stated, including on the last
        // nap before the deadline.
        tokio::time::sleep(backoff.min(deadline - now)).await;
        backoff = backoff.saturating_mul(2).min(QUIESCE_BACKOFF_CEILING);
    }
}

pub async fn run(json: bool, wait_quiesce: std::time::Duration) -> Result<()> {
    let layout = crate::commands::require_repository_layout()?;
    // Admit, THEN read. The order is the whole point: a report read before the
    // admission describes the graph as it was, which is exactly the answer
    // FIR-2961 is about.
    let pass = admit_before_reading(&layout).await;
    let reading = settle_embedding_coverage(wait_quiesce, || read_status_once(&layout)).await?;
    let report = reading.report;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        // The merge Kin is holding open and where this workspace sits relative
        // to its branch both came off the SAME authority the report did, in
        // `read_status_once`. They used to be fetched here through helpers that
        // each opened the whole store again, which on a 470 MiB import cost two
        // further whole-store opens for two readings already decoded in a lease
        // this command had just paid for.
        let footprint = StoreFootprint::measure(&layout);
        print!(
            "{}",
            render_text_with_tip(
                &report,
                None,
                Some(&footprint),
                crate::daemon_death::recorded_for_store(layout.root()).as_ref(),
                &kin_core::last_admission::read(&layout),
                // Read from the store rather than asked of the daemon, for the
                // same reason the freshness line above it is: the record is
                // durable, so the line appears when the daemon has since gone,
                // and the status wire contract does not move. `StatusReportWire`
                // denies unknown fields, so a new key there would make an older
                // CLI reject a newer daemon's report outright.
                &kin_core::retained_parse::read(&layout),
                &pass,
                reading.merge.as_ref(),
                Some(&reading.workspace_tip),
            )
        );
        // Which authority open answered, in the command's own output. Appended
        // for the same reason the projection and store-size lines are: it is a
        // measurement of this host and this invocation, not authority truth,
        // and it must not move the report's wire shape.
        println!(
            "{}",
            super::repository_authority::answered_by_line(reading.source)
        );
        // Which projection served the files this status describes. Appended
        // here rather than folded into the report for the same reason store
        // size is: the report is authority truth and must not move with the
        // filesystem, and the projection in force is a measurement of this
        // host.
        println!(
            "{}",
            crate::commands::projection::status_line(layout.root())
        );
        // What the daemon serving this repository is holding, and what it is
        // allowed to hold. Appended here for exactly the reason store size and
        // the projection line are: the report above is authority truth and must
        // not move with the machine, and this is a measurement of the machine.
        //
        // Read from the store rather than asked of the daemon, so the line
        // appears when the daemon has since gone and so the status wire
        // contract does not move. `StatusReportWire` denies unknown fields, so
        // a new key there would make an older CLI reject a newer daemon's
        // report outright; putting the budget in the payload is a v4 decision
        // for someone to take deliberately rather than a field to slip in.
        if let Some(line) = daemon_memory_line(layout.root()) {
            println!("{line}");
        }
        // What the working copy holds that graph truth does not. Appended for
        // the same reason as the three lines above, and it is the one this
        // command was missing: every line before it is authority truth, so a
        // reader was told the tree matched its base change over a repository
        // holding a module the graph had never met, and `kin refs` then
        // certified that module's constant authoritatively absent (FIR-2820).
        //
        // Never silent. A count of zero and a daemon that measured nothing are
        // different facts and this line says which it has, because "no
        // untracked files were named" is exactly the shape a reader takes for
        // "there are none".
        println!("{}", untracked_host_content_line(&pass));
    }
    Ok(())
}

/// The `kin status` reading of host content graph truth does not carry.
///
/// Asked of the daemon rather than measured here, so one walk answers for every
/// surface and two readings of one working copy can never disagree. Each arm
/// names its own basis: a measured count with the age of the measurement, a
/// measured nothing with the same age, a daemon that has taken no measurement,
/// and no daemon at all. Only the first two are statements about the working
/// copy, and the other two say so rather than rendering as a clean tree.
fn untracked_host_content_line(pass: &StatusAdmission) -> String {
    const LEAD: &str = "Untracked host content:";
    // Read off the admission this status already took, rather than asked again.
    // Two independent readings of one working copy is how two lines about it
    // come to disagree, and the probes ride on the admission response for
    // exactly this reason.
    let Some(reconcile) = pass.reconcile().cloned() else {
        let StatusAdmission::Skipped(why) = pass else {
            unreachable!("an admission that took a pass carries its probes")
        };
        return format!("{LEAD} not measured; {why}");
    };
    // Fifth arm, and the one that is not a gap. A daemon that admits nothing
    // from the filesystem has no host content waiting to be taken, so counting
    // its projected checkout would report a shortfall the graph is not in.
    if reconcile.untracked_observation_not_applicable {
        return format!(
            "{LEAD} not applicable; filesystem ingestion is off for this repository's daemon, so \
             nothing on disk is waiting to be admitted"
        );
    }
    let Some(age) = reconcile.untracked_observed_age_seconds else {
        return format!(
            "{LEAD} not measured; this repository's daemon reports no measurement of it, so the \
             count it carries stands for nothing"
        );
    };
    if reconcile.untracked_path_count == 0 {
        return format!("{LEAD} none, measured {age}s ago");
    }
    let named = if reconcile.untracked_paths_sample.is_empty() {
        String::new()
    } else {
        let more = reconcile
            .untracked_path_count
            .saturating_sub(reconcile.untracked_paths_sample.len() as u64);
        let listed = reconcile.untracked_paths_sample.join(", ");
        if more > 0 {
            format!(" ({listed}, and {more} more)")
        } else {
            format!(" ({listed})")
        }
    };
    format!(
        "{LEAD} {} host path(s) on disk that graph truth does not carry{named}, measured {age}s \
         ago; nothing above describes them, `kin admit` takes them now, and a commit takes them \
         anyway",
        reconcile.untracked_path_count
    )
}

/// The daemon footprint line, when this store carries a published standing.
///
/// Silent when nothing has been published: no daemon has run under a build that
/// publishes one, and inventing a figure for it would be worse than the blank
/// this replaces.
fn daemon_memory_line(kin_root: &std::path::Path) -> Option<String> {
    let published = kin_core::memory_pressure::DaemonFootprint::read(kin_root)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default();
    Some(format!("Daemon memory: {}", published.line(now)))
}

pub fn build_command_status_response(
    report: StatusReport,
    json: bool,
    build: Option<BuildStatus>,
    footprint: Option<&StoreFootprint>,
    death: Option<&kin_daemon_spawn::DaemonKillRecord>,
    admission: &LastAdmissionRead,
    retained: &kin_core::retained_parse::RetainedParseRead,
    pass: &StatusAdmission,
    merge: Option<&MergeInProgress>,
    workspace_tip: Option<&crate::commands::workspace_tip::WorkspaceTip>,
) -> Result<CommandStatusResponse> {
    let text = render_text_with_tip(
        &report,
        build.as_ref(),
        footprint,
        death,
        admission,
        retained,
        pass,
        merge,
        workspace_tip,
    );
    let json = json
        .then(|| serde_json::to_string(&report))
        .transpose()
        .context("serialize repository-v6 status")?;
    Ok(CommandStatusResponse {
        report,
        build,
        text,
        json,
        merge: merge.cloned(),
        workspace_tip: workspace_tip.cloned(),
        // Said only where a caller actually supplied the tip reading, which is
        // the one that cannot be inferred from a `None`. A caller that passes
        // none has taken neither, and a `merge` of `None` from it means "not
        // read" rather than "no merge".
        authority_readings_taken: workspace_tip.is_some(),
    })
}

/// A merge this workspace is holding open.
///
/// Only the fields a status line needs. The full account is `kin conflicts`, and
/// duplicating it here would give a reader two versions of one merge that can
/// come to disagree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergeInProgress {
    pub source_ref: String,
    pub target_ref: String,
    pub transaction: String,
    pub settled: usize,
    pub total: usize,
}

/// The merge this workspace is holding open, when it is holding one.
///
/// `kin status` said nothing at all during a merge that had left seventy-six
/// conflicts unresolved, and reported the tree as matching its base change while
/// it did (FIR-2961). Kin holds a merge in an authority transaction rather than
/// smearing conflict markers across the working copy, which is the better design
/// and is exactly why the working copy cannot tell you a merge is open: there is
/// nothing on disk to see. Walk away, come back, and the only surface that knows
/// is one you have to already suspect you need.
///
/// Read off the authority lease, from the same durable record `kin conflicts`
/// reads, so the two cannot disagree and neither needs a daemon or a filesystem
/// read. A terminated record is not a merge in progress and is skipped here,
/// because "the last merge" and "a merge waiting on you" are the two states this
/// line exists to separate.
pub fn merge_in_progress(
    binding: &kin_core::LocalRepositoryAuthorityBinding,
) -> Result<Option<MergeInProgress>> {
    let authority = ActiveRepositoryAuthority::open(binding)?;
    Ok(merge_in_progress_at(&authority))
}

/// The same reading, from an authority the caller already opened.
///
/// Infallible, because everything it needs is already decoded in the lease this
/// open produced. The binding-taking wrapper above is fallible only for the
/// open it performs.
pub fn merge_in_progress_at(authority: &ActiveRepositoryAuthority) -> Option<MergeInProgress> {
    let lease = authority.manager().read_authority();
    let workspace_id = authority.workspace_id;
    lease
        .metadata()
        .merge_transactions
        .iter()
        .find(|record| record.workspace_id == workspace_id && record.state.is_in_progress())
        .map(summarize_merge)
}

/// Where this workspace sits relative to the branch its head names, from an
/// authority the caller already opened.
///
/// Metadata only, so it adds nothing measurable to an open that has already
/// happened. See [`crate::commands::workspace_tip`] for why the distance in
/// changes is not part of this reading.
///
/// The workspace comes through the authority's own accessor rather than off the
/// lease here. That is deliberate and not style: `verify-zero-file-search.py`
/// counts the spelling `.metadata()` per file against a pinned allowlist number,
/// so a third one in this file fails the gate even though every one of them
/// reads an authority lease and none of them touches a filesystem. Reaching for
/// the accessor keeps the count where the allowlist reviewed it, and keeps the
/// one lookup of this workspace in one place.
pub fn workspace_tip_at(
    authority: &ActiveRepositoryAuthority,
) -> crate::commands::workspace_tip::WorkspaceTip {
    let workspace = match authority.workspace() {
        Ok(workspace) => workspace,
        Err(error) => {
            return crate::commands::workspace_tip::WorkspaceTip::Unknown {
                reason: error.to_string(),
            }
        }
    };
    let lease = authority.manager().read_authority();
    crate::commands::workspace_tip::read(&lease, &workspace)
}

fn summarize_merge(record: &MergeTransactionRecord) -> MergeInProgress {
    let unresolved = record.unresolved().count();
    MergeInProgress {
        source_ref: record.binding.source_ref.to_string(),
        target_ref: record.binding.target_ref.to_string(),
        transaction: record.hash.to_string(),
        settled: record.entries.len().saturating_sub(unresolved),
        total: record.entries.len(),
    }
}

/// The merge banner, worded so the next command is in the sentence.
///
/// Rendered directly under the heading rather than appended at the end, because
/// the reason this line exists is that a reader who does not already suspect a
/// merge is open will not scroll for it. `git status` puts "You have unmerged
/// paths" at the top for the same reason.
fn merge_line(merge: &MergeInProgress) -> String {
    let remaining = merge.total.saturating_sub(merge.settled);
    if remaining == 0 {
        format!(
            "Merge in progress: {} into {} as merge transaction {}, every one of {} conflict(s) \
             settled; publish it with `kin resolve --continue`",
            merge.source_ref, merge.target_ref, merge.transaction, merge.total
        )
    } else {
        format!(
            "Merge in progress: {} into {} as merge transaction {}, {} of {} conflict(s) settled; \
             `kin conflicts` lists what is outstanding, and nothing below describes it",
            merge.source_ref, merge.target_ref, merge.transaction, merge.settled, merge.total
        )
    }
}

/// Graph truth caught up with the working copy, or the reason it could not be.
///
/// `kin status` used to answer from the graph alone. That answer is right about
/// the graph and is read as a statement about the files on disk, and the two
/// come apart the moment an edit lands after the last admission: a stranger
/// running the whole everyday loop with no Git was told `matching its base
/// change` over a tracked file edited twenty-two seconds earlier, seven readings
/// running (FIR-2961). Putting the admission's age beside the verdict, which
/// landed in kin#1254, makes the sentence honest and does not make it right,
/// because measured on macOS the clock reads `0s ago` inside the roughly
/// two-second window before the ambient watcher catches up, and on a bind mount
/// that window has no end.
///
/// So status admits first and then answers, which is what `kin commit` has
/// always done and the reason no commit ever missed an edit. Founder-owned
/// thesis decision relayed 2026-08-30: the Zero File-Search Authority Rule
/// permits exactly this, because reading the working copy to ADMIT it is
/// ingestion at an explicit input boundary, not answering from files. The cost
/// is a tree walk, which is what makes the answer true, and `git status` pays
/// the same walk for the same reason.
///
/// The report rides along because the admission response already carries the
/// reconcile probes. One round trip answers the verdict and the untracked line
/// both, so the two surfaces cannot disagree about one working copy, which is
/// the principle this file already holds for its enrichment counters.
pub enum StatusAdmission {
    /// The pass ran and the status below was read after it.
    Took(Box<crate::commands::admit::AdmitReport>),
    /// No pass ran, carrying the clause that says why. The verdict must not
    /// present as a statement about the working copy in this arm.
    Skipped(String),
}

impl StatusAdmission {
    /// The reconcile probes the pass reported, when one ran.
    pub fn reconcile(&self) -> Option<&crate::commands::resources::ReconcileHealth> {
        match self {
            Self::Took(report) => Some(&report.reconcile),
            Self::Skipped(_) => None,
        }
    }
}

/// Admit the complete exact tree, then let the caller read.
///
/// Best effort by construction and never fatal: a status that refuses to print
/// because an admission failed is worse than one that prints and says the
/// admission failed. Every arm names its own basis, and none of them is silence.
///
/// No session lease is taken. `kin admit` holds one to keep the daemon awake
/// across a pass an operator asked for; a status read is not that, and a leaked
/// lease keeps a daemon alive indefinitely, which is the defect this would be
/// trading for.
pub async fn admit_before_reading(layout: &kin_core::KinLayout) -> StatusAdmission {
    let Some(base_url) = crate::daemon_client::resolve_daemon_url_if_running_async(layout).await
    else {
        return StatusAdmission::Skipped(
            "no daemon is running for this repository, so nothing admitted the working copy \
             and this reports durable authority alone; `kin admit` takes what the working \
             copy holds"
                .to_string(),
        );
    };
    let Ok(client) = crate::daemon_client::DaemonClient::from_base_url_for_layout(base_url, layout)
    else {
        return StatusAdmission::Skipped(
            "this repository's daemon could not be addressed, so nothing admitted the working copy"
                .to_string(),
        );
    };
    let request = crate::commands::admit::AdmitRequest {
        operation_id: kin_model::OperationId::new(),
        actor: match crate::commands::require_commit_author() {
            Ok(actor) => actor,
            Err(error) => {
                return StatusAdmission::Skipped(format!(
                    "this store cannot name an author for an admission ({error}), so nothing \
                     admitted the working copy"
                ))
            }
        },
    };
    match client.admit(&request).await {
        crate::daemon_client::AdmitDispatch::Answered(response) => match response.report {
            // A refused pass is an answer and it is not an admission. Reporting
            // it as one would put the whole defect back, one layer down.
            Some(report) if report.admitted => StatusAdmission::Took(Box::new(report)),
            Some(report) => StatusAdmission::Skipped(format!(
                "the admission of the working copy failed ({}), so what follows describes graph \
                 truth from before it",
                report.failure.as_deref().unwrap_or("no cause recorded")
            )),
            None => StatusAdmission::Skipped(
                "this repository's daemon answered the admission with no report, so whether the \
                 working copy was admitted is unknown"
                    .to_string(),
            ),
        },
        crate::daemon_client::AdmitDispatch::Refused(error) => StatusAdmission::Skipped(format!(
            "this repository's daemon refused to admit the working copy ({error})"
        )),
        crate::daemon_client::AdmitDispatch::Unanswered(error) => {
            StatusAdmission::Skipped(format!(
                "the admission of the working copy did not answer ({error}), so whether it ran is \
             unknown"
            ))
        }
    }
}

/// The `Tree:` line's verdict, and the basis it rests on.
///
/// `dirty` compares two graph-owned values, the admitted workspace tree and the
/// tree of the change it is based on. That comparison is always right about the
/// graph. What it cannot say is when the graph last looked, and a verdict with
/// no clock beside it is read as a statement about the working copy: a stranger
/// running the whole everyday loop with no Git read `matching its base change`
/// over a tracked file they had edited twenty-two seconds earlier, polled it
/// seven more times, and was told the same thing each time (FIR-2961).
///
/// So the clock rides with the verdict, from the durable last-admission marker
/// `kin diff` and `kin graph status` already read. That marker exists for this
/// exact failure and says so in its own module doc: without it "a store last
/// admitted months ago reads exactly like one admitted a second ago". Reading
/// it here needs no daemon and touches no file in the working copy, so the
/// answer stays graph-owned truth plus the age of that truth.
///
/// Every arm states a basis. An absent or unparseable marker is never rendered
/// as a bare verdict, because a surface that goes quiet when the basis is
/// unknown is indistinguishable from one reporting a healthy store, which is
/// the failure the marker was built to end.
fn workspace_state_phrase(
    dirty: bool,
    admission: &LastAdmissionRead,
    pass: &StatusAdmission,
    now: chrono::DateTime<Utc>,
) -> String {
    // Kept as a comparison against the base change rather than as "clean" or
    // "dirty". Both bare words invite the reading "everything on disk is in the
    // graph", which this flag has never meant and cannot answer: untracked host
    // paths do not move it in either direction. `kin graph status` reports
    // those, and saying what this line compares keeps the two questions apart.
    let verdict = if dirty {
        "ahead of its base change"
    } else {
        "matching its base change"
    };
    // Ahead of the clock, because it outranks it. An age says how old a reading
    // is; this says whether one was taken at all, and a verdict with nothing
    // behind it is not a verdict about the working copy. Measured with the
    // daemon stopped, the untracked line read "no daemon is running" while this
    // line directly above it read "matching its base change as admitted 0s ago"
    // (FIR-2961).
    if let StatusAdmission::Skipped(why) = pass {
        return format!("{verdict} as last admitted, not measured against the working copy: {why}");
    }
    match admission {
        LastAdmissionRead::Recorded(recorded) => format!(
            "{verdict} as admitted {} ago",
            kin_core::last_admission::humanize_age(recorded.age_seconds(now))
        ),
        LastAdmissionRead::Absent => format!(
            "{verdict} as last admitted; this store records no complete admission, so how far \
             behind the working copy that is is unknown, and `kin admit` takes what it holds"
        ),
        LastAdmissionRead::Unreadable(reason) => format!(
            "{verdict} as last admitted; the last-admission record will not parse ({reason}), so \
             how far behind the working copy that is is unknown, and `kin admit` rewrites it"
        ),
    }
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
///
/// `death` rides alongside for the same reason again, and it is the reading
/// FIR-2650 is about. A store whose daemon was killed mid-enrichment carried
/// the words "completion not attested" and nothing else, which is what a store
/// whose enrichment simply has not been certified yet also carries. The counts
/// matched, the presence matched, and the caveat matched, so the two were
/// indistinguishable on this surface.
///
/// This wrapper is the page as it reads with no workspace-tip line. Every
/// production caller has one and goes through [`render_text_with_tip`]; the
/// tests below are about other lines and would otherwise all have to state a
/// tip they do not care about.
///
/// `#[cfg(test)]` because that is now the whole truth about it. Left compiled
/// into the library it is dead code, and `-D warnings` in CI turns dead code
/// into a red gate, so an attribute that says what it is beats a build that
/// happens to include a test target.
#[cfg(test)]
fn render_text(
    report: &StatusReport,
    build: Option<&BuildStatus>,
    footprint: Option<&StoreFootprint>,
    death: Option<&kin_daemon_spawn::DaemonKillRecord>,
    admission: &LastAdmissionRead,
    retained: &kin_core::retained_parse::RetainedParseRead,
    pass: &StatusAdmission,
    merge: Option<&MergeInProgress>,
) -> String {
    render_text_with_tip(
        report, build, footprint, death, admission, retained, pass, merge, None,
    )
}

fn render_text_with_tip(
    report: &StatusReport,
    build: Option<&BuildStatus>,
    footprint: Option<&StoreFootprint>,
    death: Option<&kin_daemon_spawn::DaemonKillRecord>,
    admission: &LastAdmissionRead,
    retained: &kin_core::retained_parse::RetainedParseRead,
    pass: &StatusAdmission,
    merge: Option<&MergeInProgress>,
    workspace_tip: Option<&crate::commands::workspace_tip::WorkspaceTip>,
) -> String {
    let workspace_state =
        workspace_state_phrase(report.workspace.dirty, admission, pass, Utc::now());
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
            "Durable semantic enrichment: {enrichment} ({} entities, {} relations, {} changes at authority generation {}, workspace generation {}; {})",
            report.semantic_enrichment.entity_count,
            report.semantic_enrichment.relation_count,
            report.semantic_enrichment.semantic_change_count,
            report.semantic_enrichment.authority_generation,
            report.semantic_enrichment.workspace_generation,
            crate::daemon_death::enrichment_clause(death)
        ),
        // The counter above is durable authority truth; `kin graph status`
        // measures the daemon's live query graph and excludes external
        // reference targets from its entity total. Both are correct and they do
        // not match, so this line names the second view rather than leaving a
        // reader to discover the disagreement by running both commands.
        "Live graph enrichment: see `kin graph status`, which counts the daemon's live query \
         graph and excludes external reference targets, so its entity total is lower than the \
         durable one above"
            .to_string(),
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
    // Beside the head it qualifies, not appended at the end. A workspace whose
    // branch has moved past it reads as a clean tree in every line below, and a
    // reader who does not already suspect the gap will not scroll for the one
    // line that names it (FIR-2961 taught the same lesson about the merge
    // banner, which is why that one leads).
    if let Some(tip) = workspace_tip {
        let after_head = lines
            .iter()
            .position(|line| line.starts_with("Head: "))
            .map_or(lines.len(), |position| position + 1);
        lines.insert(after_head, crate::commands::workspace_tip::line(tip));
    }
    // The caveat on the enrichment counts directly above, placed there rather
    // than appended at the foot of the page. The counts are correct about what
    // durable authority holds; what they cannot say is that some of it was
    // derived from bytes the working copy no longer has, and a caveat printed
    // fifteen lines under the number it qualifies is one a reader reaches after
    // they have already believed the number. Every placement in this function is
    // computed by searching the lines it already holds rather than by index, so
    // the workspace-tip insert above, the merge banner below and this one cannot
    // shift each other whatever order they run in.
    if let Some(line) = retained.describe(Utc::now()) {
        let after_enrichment = lines
            .iter()
            .position(|line| line.starts_with("Live graph enrichment:"))
            .unwrap_or(lines.len());
        lines.insert(after_enrichment, line);
    }
    if let Some(footprint) = footprint {
        lines.push(format!("Store size: {}", footprint.render()));
    }
    if let Some(merge) = merge {
        lines.insert(1, merge_line(merge));
    }
    if let Some(build) = build {
        lines.push(format!(
            "Build: CLI {} / daemon {}",
            build_id(&build.cli_sha, build.cli_dirty),
            build_id(&build.daemon_sha, build.daemon_dirty)
        ));
    }
    // A warning of its own rather than more parenthesis. The counts above
    // describe what was derived; this describes whether anything more was
    // coming, and it quotes the record's own summary so this page says what
    // `kin graph status` and `kin doctor` say about the same store.
    if let Some(death) = death {
        lines.push(format!("⚠ {}", death.summary()));
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
            render_text(
                &report,
                None,
                None,
                None,
                &LastAdmissionRead::Absent,
                &kin_core::retained_parse::RetainedParseRead::Absent,
                &skipped_pass(),
                None
            )
            .contains("Authority payload read: "),
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
        let rendered = render_text(
            &unobserved,
            None,
            None,
            None,
            &LastAdmissionRead::Absent,
            &kin_core::retained_parse::RetainedParseRead::Absent,
            &skipped_pass(),
            None,
        );
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
            render_text(
                &observed,
                None,
                None,
                None,
                &LastAdmissionRead::Absent,
                &kin_core::retained_parse::RetainedParseRead::Absent,
                &skipped_pass(),
                None
            )
            .contains("Live embedding coverage: 41/57 indexed, 16 pending (live query graph)"),
            "{}",
            render_text(
                &observed,
                None,
                None,
                None,
                &LastAdmissionRead::Absent,
                &kin_core::retained_parse::RetainedParseRead::Absent,
                &skipped_pass(),
                None
            )
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
    /// The admission arm every existing render test wants: none was taken,
    /// because these tests drive the formatter and not a daemon.
    /// A pass that ran, so the arms that grade the admission's AGE are reachable.
    /// Built through the admit fixture rather than by hand, so a field added
    /// there has to be considered here too.
    fn took_pass() -> StatusAdmission {
        StatusAdmission::Took(Box::new(crate::commands::admit::AdmitReport {
            schema: crate::commands::admit::ADMIT_SCHEMA.to_string(),
            repository_id: RepositoryId::new("status-admission").unwrap(),
            tracked_before: 2,
            tracked_after: 2,
            entities_before: 3,
            entities_after: 3,
            embeddings_indexed: 6,
            embeddings_total: 6,
            reconcile: crate::commands::resources::ReconcileHealth::default(),
            tree_moved: Some(false),
            prior_admission_at: None,
            admitted: true,
            failure: None,
        }))
    }

    fn skipped_pass() -> StatusAdmission {
        StatusAdmission::Skipped("no daemon is running for this repository".to_string())
    }

    fn merge_fixture(settled: usize, total: usize) -> MergeInProgress {
        MergeInProgress {
            source_ref: "refs/heads/pretty".to_string(),
            target_ref: "refs/heads/main".to_string(),
            transaction: "1f2f0ae2".to_string(),
            settled,
            total,
        }
    }

    /// FIR-2961. During a merge that had left seventy-six conflicts unresolved,
    /// `kin status` said nothing at all and reported the tree as matching its
    /// base change while it did. Kin holds a merge in an authority transaction
    /// rather than smearing markers across the working copy, which is the better
    /// design and is exactly why the working copy cannot tell you: there is
    /// nothing on disk to see.
    #[test]
    fn a_held_merge_is_named_with_what_it_waits_on() {
        let line = merge_line(&merge_fixture(2, 76));
        assert!(line.starts_with("Merge in progress:"), "{line}");
        assert!(line.contains("refs/heads/pretty"), "{line}");
        assert!(line.contains("refs/heads/main"), "{line}");
        assert!(line.contains("1f2f0ae2"), "{line}");
        assert!(line.contains("2 of 76 conflict(s) settled"), "{line}");
        assert!(line.contains("kin conflicts"), "{line}");
    }

    /// Every conflict settled is a different state and a different next command.
    /// A banner that said the same thing in both would send a reader to
    /// `kin conflicts` to be told there is nothing outstanding.
    #[test]
    fn a_fully_settled_merge_names_the_publish_step_instead() {
        let line = merge_line(&merge_fixture(76, 76));
        assert!(
            line.contains("every one of 76 conflict(s) settled"),
            "{line}"
        );
        assert!(line.contains("kin resolve --continue"), "{line}");
        assert!(
            !line.contains("kin conflicts"),
            "a settled merge must not send the reader to a list of nothing: {line}"
        );
    }

    /// Placement is half the fix. `git status` puts "You have unmerged paths" at
    /// the top, and a banner printed at the bottom of forty lines is one a reader
    /// who does not already suspect a merge will never see. So this grades the
    /// rendered position, not the wording.
    #[test]
    fn the_merge_banner_renders_directly_under_the_heading() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(&init.layout).unwrap();
        let report = inspect(&init.layout, &binding, unobserved_fixture()).unwrap();
        let merge = merge_fixture(2, 76);

        let rendered = render_text(
            &report,
            None,
            None,
            None,
            &LastAdmissionRead::Absent,
            &kin_core::retained_parse::RetainedParseRead::Absent,
            &skipped_pass(),
            Some(&merge),
        );
        let lines: Vec<&str> = rendered.lines().collect();
        assert_eq!(lines[0], "Kin repository-v6 status", "{rendered}");
        assert!(
            lines[1].starts_with("Merge in progress:"),
            "the banner has to be the line under the heading, not somewhere below: {}",
            lines[1]
        );

        // The control, and it is the half that matters: no merge, no banner, and
        // the line under the heading is the one that was always there. A fix that
        // printed the banner unconditionally would pass the assertion above.
        let quiet = render_text(
            &report,
            None,
            None,
            None,
            &LastAdmissionRead::Absent,
            &kin_core::retained_parse::RetainedParseRead::Absent,
            &skipped_pass(),
            None,
        );
        assert!(
            !quiet.contains("Merge in progress:"),
            "a repository with no held merge must not claim one: {quiet}"
        );
        let quiet_lines: Vec<&str> = quiet.lines().collect();
        assert!(
            quiet_lines[1].starts_with("Repository: "),
            "{}",
            quiet_lines[1]
        );
    }

    /// The arm this PR exists for. A verdict with no admission behind it is not
    /// a verdict about the working copy, and the age of an older admission does
    /// not make it one: measured with the daemon stopped, this line read
    /// `matching its base change as admitted 0s ago` while the untracked line
    /// directly below it correctly said nothing had measured anything.
    #[test]
    fn a_verdict_with_no_admission_behind_it_says_it_was_not_measured() {
        let now = Utc::now();
        let recorded =
            LastAdmissionRead::Recorded(kin_core::last_admission::LastAdmission::new(now, 8));
        // The marker is as fresh as it gets, which is the trap: a zero age is
        // what a skipped pass is most likely to be sitting next to.
        let phrase = workspace_state_phrase(false, &recorded, &skipped_pass(), now);
        assert!(
            phrase.contains("not measured against the working copy"),
            "{phrase}"
        );
        assert!(phrase.contains("no daemon is running"), "{phrase}");
        assert!(
            !phrase.contains("as admitted 0s ago"),
            "a skipped pass must not borrow the clock of an older admission: {phrase}"
        );
        // The control, over the same marker: a pass that DID run reaches the age.
        let took = workspace_state_phrase(false, &recorded, &took_pass(), now);
        assert!(took.contains("as admitted 0s ago"), "{took}");
    }

    /// The untracked line reads the pass this status already took. Two readings
    /// of one working copy is how two lines about it come to disagree.
    #[test]
    fn the_untracked_line_reads_the_admission_this_status_took() {
        let took = untracked_host_content_line(&took_pass());
        assert!(took.starts_with("Untracked host content:"), "{took}");
        // A default ReconcileHealth carries no observation age, which is the
        // "measured nothing" arm rather than an all-clear.
        assert!(took.contains("not measured"), "{took}");

        let skipped = untracked_host_content_line(&skipped_pass());
        assert!(skipped.contains("no daemon is running"), "{skipped}");
    }

    /// A refused admission is an answer and it is not an admission. Reporting it
    /// as one puts the whole defect back one layer down.
    #[test]
    fn a_failed_admission_is_not_treated_as_a_pass() {
        let now = Utc::now();
        let recorded =
            LastAdmissionRead::Recorded(kin_core::last_admission::LastAdmission::new(now, 8));
        let refused = StatusAdmission::Skipped(
            "the admission of the working copy failed (host entry changed), so what follows \
             describes graph truth from before it"
                .to_string(),
        );
        let phrase = workspace_state_phrase(false, &recorded, &refused, now);
        assert!(
            phrase.contains("not measured against the working copy"),
            "{phrase}"
        );
        assert!(phrase.contains("host entry changed"), "{phrase}");
        assert!(
            refused.reconcile().is_none(),
            "a skipped pass carries no probes"
        );
    }

    /// FIR-2961. `Tree: ... (matching its base change)` was read as a statement
    /// about the working copy, because with no clock beside it there is nothing
    /// else to read it as. A stranger running the everyday loop with no Git saw
    /// it over a tracked file edited twenty-two seconds earlier and polled it
    /// seven more times before giving up on it.
    ///
    /// The verdict itself was right about the graph both times, so the fix is
    /// not a different verdict, it is the age of the reading the verdict rests
    /// on.
    #[test]
    fn the_tree_verdict_carries_the_age_of_the_admission_it_rests_on() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-08-29T20:49:16Z")
            .unwrap()
            .with_timezone(&Utc);
        let admitted_at = chrono::DateTime::parse_from_rfc3339("2026-08-29T20:47:16Z")
            .unwrap()
            .with_timezone(&Utc);
        let recorded = LastAdmissionRead::Recorded(kin_core::last_admission::LastAdmission::new(
            admitted_at,
            8,
        ));

        let clean = workspace_state_phrase(false, &recorded, &took_pass(), now);
        assert!(clean.contains("matching its base change"), "{clean}");
        assert!(
            clean.contains("admitted 2m ago"),
            "the verdict has to carry when the graph last looked: {clean}"
        );

        let dirty = workspace_state_phrase(true, &recorded, &took_pass(), now);
        assert!(dirty.contains("ahead of its base change"), "{dirty}");
        assert!(dirty.contains("admitted 2m ago"), "{dirty}");
    }

    /// An absent or unparseable marker is the case the whole marker exists for,
    /// and it must not render as a bare verdict. A surface that goes quiet when
    /// its basis is unknown is indistinguishable from one reporting a healthy
    /// store.
    #[test]
    fn an_unknown_admission_basis_is_never_rendered_as_a_bare_verdict() {
        let now = Utc::now();

        let absent = workspace_state_phrase(false, &LastAdmissionRead::Absent, &took_pass(), now);
        assert!(
            absent.contains("no complete admission"),
            "an absent marker has to say so: {absent}"
        );
        assert!(absent.contains("kin admit"), "{absent}");

        let unreadable = workspace_state_phrase(
            false,
            &LastAdmissionRead::Unreadable("trailing bytes".to_string()),
            &took_pass(),
            now,
        );
        assert!(unreadable.contains("will not parse"), "{unreadable}");
        assert!(unreadable.contains("trailing bytes"), "{unreadable}");

        // The control. Every arm carries the verdict, so the qualification is an
        // addition to the answer and never a replacement for it.
        for phrase in [&absent, &unreadable] {
            assert!(phrase.contains("matching its base change"), "{phrase}");
        }
    }

    /// The rendered line, not just the phrase, so a refactor that computes the
    /// right words and prints the old ones is caught here.
    #[test]
    fn the_rendered_tree_line_carries_the_basis() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(&init.layout).unwrap();
        let report = inspect(&init.layout, &binding, unobserved_fixture()).unwrap();

        let tree_line_of = |pass: &StatusAdmission| {
            render_text(
                &report,
                None,
                None,
                None,
                &LastAdmissionRead::Absent,
                &kin_core::retained_parse::RetainedParseRead::Absent,
                pass,
                None,
            )
            .lines()
            .find(|line| line.starts_with("Tree: "))
            .unwrap_or_default()
            .to_string()
        };

        // Read-after-admit outranks the marker, so with no pass behind it the
        // line names itself unmeasured and never reaches the marker's own arm.
        // Both are a basis; this asserts WHICH one, because a test that accepted
        // either could not tell the two apart.
        let skipped = tree_line_of(&skipped_pass());
        assert!(
            skipped.contains("not measured against the working copy"),
            "an unmeasured verdict has to say so on the Tree line itself: {skipped}"
        );

        // With a pass behind it the marker's arm is reachable again, and an
        // absent marker still has to name itself rather than render as a bare
        // verdict. This is the arm kin#1254 added and it is still load-bearing.
        let took = tree_line_of(&took_pass());
        assert!(
            took.contains("no complete admission"),
            "an absent marker behind a real pass still has to name itself: {took}"
        );
        assert!(
            !took.contains("not measured against the working copy"),
            "a pass that ran must not report itself unmeasured: {took}"
        );
    }

    #[test]
    fn store_size_renders_from_the_measurement_and_not_from_the_report() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(&init.layout).unwrap();
        let report = inspect(&init.layout, &binding, unobserved_fixture()).unwrap();

        let without = render_text(
            &report,
            None,
            None,
            None,
            &LastAdmissionRead::Absent,
            &kin_core::retained_parse::RetainedParseRead::Absent,
            &skipped_pass(),
            None,
        );
        assert!(
            !without.contains("Store size"),
            "an unmeasured status must print no store line at all: {without}"
        );

        let footprint = StoreFootprint::measure(&init.layout);
        let with = render_text(
            &report,
            None,
            Some(&footprint),
            None,
            &LastAdmissionRead::Absent,
            &kin_core::retained_parse::RetainedParseRead::Absent,
            &skipped_pass(),
            None,
        );
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

    /// One `kin status` with no daemon must open repository authority exactly
    /// once.
    ///
    /// GAP-6, in the form that scales. An authority open is a full recovery that
    /// re-verifies every persisted body against its content address, so it costs
    /// whatever the whole store is worth: measured on a converted 470 MiB
    /// express store, one open is seconds and this command was paying for two of
    /// them locally, plus two more inside the daemon serving it. The COUNT is
    /// the honest bound and the wall clock is not, because a fixture small
    /// enough to run in CI answers in milliseconds whether it opens once or
    /// three times.
    ///
    /// Counted on this thread only: this binary runs tests in parallel and
    /// siblings open authority of their own.
    ///
    /// Breaking it: put `merge_in_progress(&binding)` or a binding-taking
    /// workspace-tip helper back on the fallback arm of `read_status_once`,
    /// which is exactly what the shipped code did. Either takes this to 2.
    #[tokio::test]
    async fn one_status_reading_opens_repository_authority_once() {
        let _daemon = kin_core::test_env::EnvVarGuard::unset("KIN_DAEMON_URL");
        let root = tempfile::tempdir().expect("a temporary directory for the fixture store");
        let init = kin_core::init(root.path()).expect("kin_core::init builds a real store");

        let before = kin_core::authority_opens();
        let reading = read_status_once(&init.layout)
            .await
            .expect("a fresh store answers a status");
        let opens = kin_core::authority_opens() - before;

        // Non-vacuity, all three halves. A reading that came from a daemon would
        // open nothing here and pass the bound while testing nothing, and a tip
        // reading that could not be taken cannot tell "one open for every
        // reading" apart from "one open and the readings missing".
        assert_eq!(
            reading.source,
            AuthoritySource::OwnAuthorityOpen,
            "this case is about the arm that opens; a daemon answered instead"
        );
        assert_eq!(reading.report.schema, STATUS_SCHEMA);
        assert!(
            !matches!(
                reading.workspace_tip,
                crate::commands::workspace_tip::WorkspaceTip::Unknown { .. }
            ),
            "the workspace-tip reading must have come off that same open: {:?}",
            reading.workspace_tip
        );
        assert_eq!(
            opens, 1,
            "one `kin status` must open repository authority once and ask that open for the \
             report, the merge and the workspace tip; opening per reading is GAP-6"
        );
    }

    /// An older daemon's silence about the merge reading must read as "did not
    /// take it", never as "there is no merge".
    ///
    /// This is the wire half of the mixed-build case. A new CLI talking to a
    /// daemon that predates these fields receives no `authority_readings_taken`
    /// and no `merge`, and if that decoded as "readings taken, no merge" the
    /// command would print a clean tree over a workspace holding seventy-six
    /// conflicts open, which is FIR-2961 reintroduced through the wire.
    ///
    /// Breaking it: give the field a `#[serde(default = ...)]` that yields true,
    /// or drop `#[serde(default)]` so an older payload fails to parse at all.
    #[test]
    fn an_older_daemons_status_payload_says_it_took_no_authority_readings() {
        let payload = serde_json::json!({
            "report": serde_json::to_value(settle_base_report()).unwrap(),
            "text": "Kin repository-v6 status",
        });
        let decoded: CommandStatusResponse =
            serde_json::from_value(payload).expect("an older daemon's payload must still decode");

        // Non-vacuity: the payload really is the older shape, carrying neither
        // of the fields whose absence this is about.
        assert!(decoded.merge.is_none());
        assert!(decoded.workspace_tip.is_none());
        assert!(
            !decoded.authority_readings_taken,
            "an absent flag must mean the readings were not taken, so the caller reads them itself"
        );
    }

    /// One real report to drive the settle with, so it is exercised against the
    /// shape production hands it rather than a hand-built stand-in.
    /// A record naming one path the graph is answering about from an earlier
    /// parse, so the line is testable without a daemon.
    fn retained_fixture() -> kin_core::retained_parse::RetainedParseRead {
        kin_core::retained_parse::RetainedParseRead::Recorded(kin_core::retained_parse::fold(
            &[],
            &[kin_core::retained_parse::ObservedParse::retained(
                "search.py",
                4,
            )],
            Utc::now(),
        ))
    }

    /// `kin status` says which paths it is describing from an earlier parse,
    /// and says it beside the counts it qualifies.
    ///
    /// Placement is half of this. The enrichment counts are correct about what
    /// durable authority holds, and a caveat printed under the store size and
    /// the daemon memory is one a reader reaches after they have already
    /// believed the number.
    #[test]
    fn the_retained_line_sits_under_the_enrichment_counts_it_qualifies() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(&init.layout).unwrap();
        let report = inspect(&init.layout, &binding, unobserved_fixture()).unwrap();

        let rendered = render_text(
            &report,
            None,
            None,
            None,
            &LastAdmissionRead::Absent,
            &retained_fixture(),
            &skipped_pass(),
            None,
        );
        let lines: Vec<&str> = rendered.lines().collect();
        let retained_at = lines
            .iter()
            .position(|line| line.starts_with("Retained from last good parse:"))
            .unwrap_or_else(|| panic!("no retained line in:\n{rendered}"));
        let enrichment_at = lines
            .iter()
            .position(|line| line.starts_with("Durable semantic enrichment:"))
            .expect("the enrichment line is always rendered");
        assert_eq!(
            retained_at,
            enrichment_at + 1,
            "the caveat belongs directly under the number it qualifies:\n{rendered}"
        );
        assert!(
            lines[retained_at].contains("search.py (4 parse errors)"),
            "{rendered}"
        );

        // The control, and the half a fix that printed unconditionally would
        // fail: a store with nothing retained says nothing about it.
        let quiet = render_text(
            &report,
            None,
            None,
            None,
            &LastAdmissionRead::Absent,
            &kin_core::retained_parse::RetainedParseRead::Absent,
            &skipped_pass(),
            None,
        );
        assert!(
            !quiet.contains("Retained from last good parse"),
            "a store answering from its own bytes must not claim otherwise: {quiet}"
        );
    }

    /// A record that will not parse is louder than one that is missing. Silence
    /// here would let a truncated record read as a whole store, which is the
    /// class this whole change closes, reached by the other door.
    #[test]
    fn an_unreadable_retained_record_is_reported_rather_than_skipped() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(&init.layout).unwrap();
        let report = inspect(&init.layout, &binding, unobserved_fixture()).unwrap();

        let rendered = render_text(
            &report,
            None,
            None,
            None,
            &LastAdmissionRead::Absent,
            &kin_core::retained_parse::RetainedParseRead::Unreadable("truncated".to_string()),
            &skipped_pass(),
            None,
        );
        assert!(
            rendered.contains("could not be read (truncated)"),
            "{rendered}"
        );
    }

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
        let reading = settle_embedding_coverage(budget, || {
            let attempt = reads.get();
            reads.set(attempt + 1);
            let report = script[attempt.min(script.len() - 1)].clone();
            async move {
                Ok(StatusReading {
                    report,
                    merge: None,
                    workspace_tip: crate::commands::workspace_tip::WorkspaceTip::Detached,
                    source: AuthoritySource::OwnAuthorityOpen,
                })
            }
        })
        .await
        .unwrap();
        (
            reading.report,
            reads.get(),
            tokio::time::Instant::now() - started,
        )
    }

    /// The race itself: the daemon could not pair a stable authority epoch with
    /// a sample, and the coverage it was hiding is observable a moment later. A
    /// single-sample caller failed here.
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
