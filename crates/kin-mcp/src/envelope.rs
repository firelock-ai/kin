// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Versioned MCP response envelope (D.8).
//!
//! Every MCP tool response is annotated with one additive, versioned metadata
//! object under the reserved top-level key [`ENVELOPE_KEY`] (`_kin`). One
//! envelope shape is shared by all tool families so an agent reads trust
//! metadata the same way regardless of which tool answered. The envelope
//! carries:
//!
//! - the envelope schema version,
//! - the runtime that answered (daemon-owned graph vs explicit offline path),
//! - `semantic_coverage` in the same shape `kin locate --json` / `kin status`
//!   report, lifted from the tool payload when the daemon already included it,
//! - graph freshness (`graph_as_of` plus honest `/health`-derived state),
//! - degraded flags: daemon-unreachable, `embed_worker_failed` (#11),
//!   `embed_persistence_unavailable`,
//!   `mass_deletion_blocked`, offline-fallback, and workspace-mismatch.
//!
//! Honesty contract (CLAUDE.md): the envelope NEVER fabricates coverage or
//! freshness. Anything it cannot observe is `null`/absent, not a default `false`
//! or a zeroed count. Degraded flags are `Some(bool)` only when actually
//! observed (e.g. parsed from the daemon `/health` body); otherwise they are
//! omitted rather than asserted `false`.
//!
//! ## Back-compat
//!
//! The envelope is purely additive. For the common case — a tool whose payload
//! is a JSON object — the original payload keys are left exactly where agents
//! expect them and `_kin` is added alongside. Payloads that are not JSON objects
//! (arrays, scalars, or human-readable error text) are wrapped so the envelope
//! still rides along without losing the original content.

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::budget::ResponseBudget;
use crate::types::{ContentBlock, ToolCallResult};

/// Current envelope schema version. Bump on any breaking field change so
/// Kin-aware consumers can detect and adapt to envelope evolution.
pub const ENVELOPE_VERSION: u32 = 1;

/// Reserved top-level key the envelope is attached under. Distinctive and
/// namespaced so it never collides with a tool payload's own fields.
pub const ENVELOPE_KEY: &str = "_kin";

/// The `semantic_coverage.limited_by` label a producing surface records when the
/// role filter narrowed the population its counters were taken over.
///
/// Spelled here as a literal rather than imported: this crate mirrors the
/// coverage shape kin-cli publishes and does not depend on it. The producer is
/// `kin_cli::commands::locate::COVERAGE_LIMIT_GRAPH_ROLE_FILTER`, and the two
/// have to stay spelled the same.
const SCOPE_LIMIT_ROLE_FILTER: &str = "graph_role_filter";

/// The `semantic_coverage.limited_by` label for missing graph-owned source
/// bodies. Producer:
/// `kin_cli::commands::locate::COVERAGE_LIMIT_GRAPH_BODY_GAP`.
const SCOPE_LIMIT_BODY_GAP: &str = "graph_body_gap";

/// Which runtime produced a tool response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Runtime {
    /// Product path: forwarded to the repo daemon's live, graph-owned truth.
    RepoDaemon,
    /// Explicit offline/test path: an in-process graph store, no daemon. Per the
    /// graph-first thesis this is a fallback surface, not steady-state.
    OfflineInProcess,
}

/// Embedding (semantic signal) coverage, mirroring the `SemanticCoverage` shape
/// kin-cli's locate/status surfaces report (`indexed`/`total`/`pending`/
/// `complete`/`note`) so an agent reads readiness identically from MCP or CLI.
///
/// Only populated when the tool payload carried it (the daemon already computes
/// it for locate/search from its live graph). Never fabricated here.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SemanticCoverage {
    /// Entities with an embedding indexed in the vector store.
    pub indexed: u64,
    /// Total entities eligible for embedding.
    pub total: u64,
    /// Entities still queued for embedding.
    pub pending: u64,
    /// True when the semantic signal was complete (`total == 0`, or every entity
    /// indexed with nothing pending).
    ///
    /// A CONJUNCTION over several independent causes, so it cannot be read as a
    /// statement about embeddings. Read [`Self::embedding_state`] for that, and
    /// [`Self::limited_by`] for which cause cleared this flag.
    pub complete: bool,
    /// What the embedding substrate itself was observed to be, as the producing
    /// surface decided it: `present`, `partial`, `absent` or `unknown`.
    ///
    /// This is the one embedding verdict, computed once where the counters were
    /// taken and carried on the wire rather than re-derived here. Deriving one
    /// from [`Self::complete`] is the FIR-2543 defect: a `semantic_locate`
    /// envelope carried `indexed 2112, pending 0` beside
    /// `completeness.classes.embeddings: absent`, because fifteen test-role
    /// paths withheld from ranking had cleared `complete` and a consumer read
    /// that as an embedding shortfall.
    ///
    /// Absent on payloads minted before the field existed.
    /// [`Self::embedding_state`] narrows those from the counters and answers
    /// `unknown` wherever the counters alone cannot tell a detached index from
    /// an unembedded store.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embedding_state_reported: Option<String>,
    /// Every machine-stable reason [`Self::complete`] is false, as the producing
    /// surface recorded them. Empty or absent when nothing was recorded.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub limited_by: Vec<String>,
    /// When the counters above were sampled, RFC 3339 in UTC, when the payload
    /// carried it.
    ///
    /// Two surfaces reporting different counts for one store in the same minute
    /// is the ordinary state of a store with a backfill running. Without a read
    /// time it is indistinguishable from one of them being wrong, which is half
    /// of what FIR-2543 reported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_at: Option<String>,
    /// Human-readable note describing the degraded state, present only when the
    /// semantic signal was partial.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Graph-owned source paths carrying no body, when the payload reported it.
    ///
    /// `complete` above is a conjunction of the embedding count and this number,
    /// so the flag alone cannot say which of the two limited the answer. A
    /// caller reading `complete: false` beside `indexed == total` is looking at
    /// a body gap, and the remediation is a reconcile rather than an embed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub graph_body_gap_paths: Option<u64>,
}

/// What the embedding substrate was observed to be, as every consumer in this
/// crate reads it.
///
/// Deliberately four states where [`Completeness::classes`] carries three. The
/// class vocabulary answers "was the substrate whole", so `Partial` and `Absent`
/// both render there as `absent`; the finer reading is kept here and named in
/// `limits`, because "some of it is indexed" and "none of it is" have different
/// remediations and only one of them is what a first query on a fresh
/// conversion sees.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmbeddingState {
    /// Every eligible entity is indexed and nothing is queued.
    Present,
    /// Some eligible entities are indexed and some are not.
    Partial,
    /// An attached index holds no embedding for any eligible entity.
    Absent,
    /// Nobody could say.
    Unknown,
}

impl EmbeddingState {
    /// The class word this state contributes to [`Completeness::classes`].
    fn class_state(self) -> &'static str {
        match self {
            Self::Present => STATE_PRESENT,
            Self::Partial | Self::Absent => STATE_ABSENT,
            Self::Unknown => STATE_UNKNOWN,
        }
    }

    /// The machine-stable label this state contributes to
    /// [`Completeness::limits`], or `None` when there is no shortfall to name.
    fn limit_label(self) -> Option<&'static str> {
        match self {
            Self::Present => None,
            Self::Partial => Some("embeddings_partial"),
            Self::Absent => Some("embeddings_absent"),
            Self::Unknown => Some("embeddings_unknown"),
        }
    }
}

impl SemanticCoverage {
    /// Whether this observation leaves no embedding work for a disabled
    /// producer to perform.
    fn embedding_work_complete(&self) -> bool {
        self.pending == 0 && self.indexed == self.total
    }

    /// The one embedding verdict every surface in this crate reads.
    ///
    /// Prefers the observation the producing surface published, because that is
    /// the only reader that knew whether a vector index was attached when the
    /// counters were taken. Falls back to the counters for a payload minted
    /// before the field existed, and that fallback answers `Unknown` for every
    /// reading the counters cannot decide on their own:
    /// `kin_db::InMemoryGraph::embedding_status` reports zero indexed for every
    /// retrievable object when no index is attached, so `indexed: 0` is a
    /// fully embedded store whose index did not load and an unembedded store at
    /// the same time. A count nobody can read is unknown, never zero and never
    /// absent.
    pub fn embedding_state(&self) -> EmbeddingState {
        match self.embedding_state_reported.as_deref() {
            Some("present") => return EmbeddingState::Present,
            Some("partial") => return EmbeddingState::Partial,
            Some("absent") => return EmbeddingState::Absent,
            Some("unknown") => return EmbeddingState::Unknown,
            // An unrecognized word is a producer this build does not understand.
            // Reading it as healthy would let a future state certify answers
            // nobody has decided are certifiable.
            Some(_) => return EmbeddingState::Unknown,
            None => {}
        }
        if self.total > 0 && self.indexed >= self.total && self.pending == 0 {
            EmbeddingState::Present
        } else if self.total == 0 || self.indexed == 0 {
            EmbeddingState::Unknown
        } else {
            EmbeddingState::Partial
        }
    }

    /// Every reason `complete` is false that is NOT a statement about
    /// embeddings, as machine-stable labels.
    ///
    /// These are disclosure. A withheld test path was never ranked and a
    /// body-less path cannot be ranked, and both hold on stores whose every
    /// eligible entity carries a vector, so neither may decide the embedding
    /// class. They still narrow what an empty answer proves, which is why
    /// [`Envelope::negative_trust`] reads them.
    pub fn scope_limits(&self) -> Vec<String> {
        let mut limits = Vec::new();
        if self
            .limited_by
            .iter()
            .any(|limit| limit == SCOPE_LIMIT_ROLE_FILTER)
        {
            limits.push("graph_role_filter_withheld".to_string());
        }
        if self.graph_body_gap_paths.is_some_and(|gaps| gaps > 0)
            || self
                .limited_by
                .iter()
                .any(|limit| limit == SCOPE_LIMIT_BODY_GAP)
        {
            limits.push("graph_body_gap".to_string());
        }
        limits
    }

    /// Lift a `semantic_coverage` object out of a tool payload, validating the
    /// shape. Returns `None` when the payload has no such field or it is not the
    /// expected object — we surface `unknown` rather than guessing.
    fn from_payload_field(value: &Value) -> Option<Self> {
        let obj = value.as_object()?;
        Some(SemanticCoverage {
            indexed: obj.get("indexed").and_then(Value::as_u64)?,
            total: obj.get("total").and_then(Value::as_u64)?,
            pending: obj.get("pending").and_then(Value::as_u64)?,
            complete: obj.get("complete").and_then(Value::as_bool)?,
            embedding_state_reported: obj
                .get("embedding_state")
                .and_then(Value::as_str)
                .map(str::to_string),
            limited_by: {
                let mut limited_by: Vec<String> = obj
                    .get("limited_by")
                    .and_then(Value::as_array)
                    .map(|limits| {
                        limits
                            .iter()
                            .filter_map(Value::as_str)
                            .map(str::to_string)
                            .collect()
                    })
                    .unwrap_or_default();
                // A payload that carries the body-coverage object but not the
                // reason list still stated the role filter, in the one field
                // that has always disclosed it. Reading it here is what keeps a
                // producer one version behind from having its narrowed
                // population read as an embedding shortfall.
                let withheld = obj
                    .get("graph_bodies")
                    .and_then(Value::as_object)
                    .and_then(|bodies| bodies.get("withheld_test_paths"))
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                if withheld > 0 && !limited_by.iter().any(|it| it == SCOPE_LIMIT_ROLE_FILTER) {
                    limited_by.push(SCOPE_LIMIT_ROLE_FILTER.to_string());
                }
                limited_by
            },
            read_at: obj
                .get("read_at")
                .and_then(Value::as_str)
                .map(str::to_string),
            note: obj.get("note").and_then(Value::as_str).map(str::to_string),
            // Optional: payloads from surfaces that ran no retrieval, and every
            // payload minted before graph-body coverage existed, carry no such
            // object. Absent stays absent rather than becoming a fabricated zero.
            graph_body_gap_paths: obj
                .get("graph_bodies")
                .and_then(Value::as_object)
                .and_then(|bodies| bodies.get("gap_paths"))
                .and_then(Value::as_u64),
        })
    }
}

/// Honest degraded-state flags. Each is `Some(bool)` only when observed and
/// `None` (serialized absent) when the envelope could not determine it — never a
/// fabricated `false`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Degraded {
    /// The daemon was required but unreachable; the result is a transport error
    /// rather than graph-owned truth.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub daemon_unreachable: Option<bool>,
    /// Daemon `/health`: the background embedding worker has permanently stopped
    /// (#11). The graph still serves; the vector index is frozen until restart.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embed_worker_failed: Option<bool>,
    /// Daemon `/health`: this graph authority has no durable local vector
    /// sidecar contract, so the embedding worker is intentionally unavailable.
    /// This is not a memory refusal and cannot be cleared by freeing memory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embed_persistence_unavailable: Option<bool>,
    /// Daemon `/health`: a suspected mass-deletion wipe is being withheld pending
    /// operator confirmation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mass_deletion_blocked: Option<bool>,
    /// The response came from the explicit offline/in-process path rather than
    /// daemon-owned truth (graph-first: a fallback surface).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offline_fallback: Option<bool>,
    /// The MCP client's workspace roots name a repository this server does not
    /// serve, so the call was refused rather than answered from the repository
    /// the client left. The daemon is reachable; the disagreement is about which
    /// repository the answer would be about.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_mismatch: Option<bool>,
    /// A daemon serving this store was killed by the memory limit, and this
    /// store's own record says so. Set only from the kernel's own accounting,
    /// never from an inference about how much memory was in use, and never on a
    /// host that publishes no accounting: on those the cause is reported in the
    /// message and no flag claims it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub daemon_killed_by_memory: Option<bool>,
    /// This store's language-server enrichment has been switched off by the
    /// sweep circuit, so the producer that would fill missing cross-file
    /// relations is not running. Set from the store's own tally, which the
    /// daemon resets when a sweep completes, so it clears itself rather than
    /// needing a second event to retract it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sweep_suspended: Option<bool>,
    /// This store's daemon declined heavy work because the machine had no room
    /// for it, and this store's own record says so. The work is owed rather
    /// than lost and Kin resumes it once there is room, but until then the
    /// producer behind some part of this answer is not running, which is the
    /// same reading a suspended sweep changes and for the same reason. Set from
    /// the record the daemon writes and the pass that runs next retires, so it
    /// clears itself rather than needing a second event to retract it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_pressure: Option<bool>,
    /// This store's graph currently holds fewer relations than its own last
    /// verified-good census did, over an entity count that did not fall. The
    /// relation census is the only surface that could see it, and on the rc0550
    /// run it was the only surface that did: a comment-only commit deleted
    /// twelve edges and `find_references` answered from the damaged graph with
    /// an empty degraded list and `edge_coverage.calls: "present"` (FIR-2644).
    /// Set from the record the census pass writes and the next advancing census
    /// retires, so it clears itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relation_census_loss: Option<bool>,
    /// This store's last language-server enrichment sweep offered relations the
    /// graph does not hold, or published some without invalidating their
    /// endpoints' embeddings. Either way a producer that was supposed to fill
    /// cross-file relations did not finish the job, so an absence measured here
    /// may be a gap nothing is working on rather than a gap that is not there.
    /// Set from the record the sweep writes and the next clean sweep retires,
    /// so it clears itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrichment_shortfall: Option<bool>,
}

impl Degraded {
    /// True when any degraded condition is affirmatively set.
    pub fn any(&self) -> bool {
        [
            self.daemon_unreachable,
            self.embed_worker_failed,
            self.embed_persistence_unavailable,
            self.mass_deletion_blocked,
            self.offline_fallback,
            self.workspace_mismatch,
            self.daemon_killed_by_memory,
            self.sweep_suspended,
            self.memory_pressure,
            self.relation_census_loss,
            self.enrichment_shortfall,
        ]
        .into_iter()
        .any(|flag| flag == Some(true))
    }

    /// The names of the degraded signals that are affirmatively set, in a stable
    /// order. Used to spell out "degraded signals Z" in a confidence-qualified
    /// negative without fabricating flags that were never observed.
    pub fn active_labels(&self) -> Vec<&'static str> {
        let mut labels = Vec::new();
        if self.daemon_unreachable == Some(true) {
            labels.push("daemon_unreachable");
        }
        if self.embed_worker_failed == Some(true) {
            labels.push("embed_worker_failed");
        }
        if self.embed_persistence_unavailable == Some(true) {
            labels.push("embed_persistence_unavailable");
        }
        if self.mass_deletion_blocked == Some(true) {
            labels.push("mass_deletion_blocked");
        }
        if self.offline_fallback == Some(true) {
            labels.push("offline_fallback");
        }
        if self.workspace_mismatch == Some(true) {
            labels.push("workspace_mismatch");
        }
        if self.daemon_killed_by_memory == Some(true) {
            labels.push("daemon_killed_by_memory");
        }
        if self.sweep_suspended == Some(true) {
            labels.push("sweep_suspended");
        }
        if self.memory_pressure == Some(true) {
            labels.push("memory_pressure");
        }
        if self.relation_census_loss == Some(true) {
            labels.push("relation_census_loss");
        }
        if self.enrichment_shortfall == Some(true) {
            labels.push("enrichment_shortfall");
        }
        labels
    }
}

/// What the daemon's entity count includes, in one sentence a reader can act on.
pub const ENTITY_COUNT_SCOPE: &str =
    "every entity node the daemon holds, including external reference targets this repository \
     does not define; `kin graph status` prints the smaller count of definitions this \
     repository owns and names the excluded targets on its own line";

/// Graph freshness context — what graph state answered the query. `as_of` is a
/// precise version marker only when the payload/daemon provides one; the rest
/// are honest `/health`-derived signals (never fabricated).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct GraphState {
    /// Daemon `/health` reconciliation status (e.g. `"clean"`, `"reconciling"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reconciliation_status: Option<String>,
    /// Daemon-reported entity count at answer time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entity_count: Option<u64>,
    /// What `entity_count` counts, carried so an agent can reconcile it against
    /// the smaller total the CLI prints without doing arithmetic.
    ///
    /// The two disagree on purpose and by a knowable amount: this one counts
    /// every node the daemon holds, `kin graph status` counts only definitions
    /// the repository owns, and the difference is the external reference
    /// targets that surface names and excludes. A stranger on psf/requests read
    /// 837 here against 777 there, worked the 60 out by subtraction, and had no
    /// way to confirm the subtraction was the right operation. `kin status`
    /// carries the reconciling sentence already; the surface agents actually
    /// read carried nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entity_count_scope: Option<String>,
    /// Whether the daemon has a graph loaded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loaded: Option<bool>,
    /// Whether the daemon has completed first reconciliation / snapshot load.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initialized: Option<bool>,
}

impl GraphState {
    fn is_empty(&self) -> bool {
        self.reconciliation_status.is_none()
            && self.entity_count.is_none()
            && self.entity_count_scope.is_none()
            && self.loaded.is_none()
            && self.initialized.is_none()
    }
}

/// A durability state's wire word. Three states, and `unknown` is a real
/// answer rather than a placeholder for one of the other two.
const DURABILITY_RECORDED: &str = "recorded";
const DURABILITY_LIVE_UNCOMMITTED: &str = "live_uncommitted";
const DURABILITY_UNKNOWN: &str = "unknown";

/// Whether the graph that answered this call is recorded by durable repository
/// authority, or lives only in the daemon's query layer (FIR-2421).
///
/// `completeness` says how much of the substrate the answer could see.
/// This says whether the substrate survives the process serving it. They are
/// independent: a graph can be complete, fully embedded, and gone the moment
/// the daemon exits, which is exactly the state that produced this object.
///
/// A daemon admits host content into its live query graph continuously, so an
/// agent that writes a file and locates it a second later gets a real entity id
/// back. Nothing in that exchange said the entity was uncommitted, and an agent
/// reading a populated `entity_count` beside a successful locate concluded its
/// work was in the graph and never committed. The entities went with the
/// daemon; the payloads it read were all true and all silent about it.
///
/// Nothing here is fabricated. `live_only_entities` is a difference between two
/// counts the daemon observed, and when the two cannot be reconciled the state
/// is `unknown` with no count rather than a number the reader would act on.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Durability {
    /// `recorded` when durable authority carries every entity the selected
    /// graph holds, `live_uncommitted` when it carries fewer, `unknown` when
    /// the daemon reported no durable observation or the two counts cannot be
    /// reconciled.
    pub state: String,
    /// Entities in the live query graph that answered this call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub live_entities: Option<u64>,
    /// Entities durable repository authority carried when this daemon last
    /// levelled its query graph with authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub durable_entities: Option<u64>,
    /// How many of `live_entities` no committed change carries. Absent
    /// whenever `state` is `unknown`, because the whole point of that state is
    /// that this number could not be derived.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub live_only_entities: Option<u64>,
    /// One line an agent can act on without reading the counts.
    pub note: String,
}

/// How far graph truth is behind the working copy this daemon watches.
///
/// Two facts a reader has to have together. `unadmitted_paths` is how many host
/// paths the daemon's most recent complete walk observed that repository
/// authority does not carry and no observation covered; `since` is when a
/// complete admission last succeeded. Either alone misleads. A count with no
/// clock cannot say whether the store fell behind a second ago or a month ago,
/// and a clock with no count cannot say whether anything is actually missing.
///
/// Present when there is something to say, which is two cases and not one:
/// the store is behind by a measured count, or NOTHING MEASURED the working
/// copy, so whether it is behind is unknown. An absent object is a measured
/// all-clear and only that. The second case exists because the first version of
/// this object gated on the count alone, so a zero nobody had measured read
/// exactly like a zero somebody had, and reporting a zero it never verified is
/// the shape of wrong answer this object exists to stop (FIR-2820).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GraphBehind {
    /// Host paths on disk that no admission has taken.
    pub unadmitted_paths: u64,
    /// When a complete admission last succeeded, as the daemon reported it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,
    /// A bounded sample of the unadmitted paths, enough to recognize the file
    /// you just wrote.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sample: Vec<String>,
    /// Seconds since the walk that produced `unadmitted_paths` ran.
    ///
    /// `None` is the whole reason this object can be present with a count of
    /// zero: it means no walk has stamped a reading, so the count above is a
    /// default rather than an observation and nothing here is a statement about
    /// the working copy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub measured_age_seconds: Option<u64>,
    /// One line an agent can act on without reading the counts.
    pub note: String,
}

impl GraphBehind {
    /// Read the reading, and the basis for it, out of a daemon `/health` body.
    ///
    /// `None` when the body carries no reconcile block at all, because there is
    /// then nothing to read rather than something to report.
    ///
    /// Otherwise the count alone does not decide this, and that is the fix. A
    /// zero has three producers and only one of them is an all-clear: a walk
    /// measured it, this daemon admits nothing from the filesystem so the
    /// question does not apply, or a walk should have measured it and none has.
    /// The first two are silence. The third is a disclosure, because a zero
    /// nobody measured is not a zero, and gating on the count alone published it
    /// as one on every surface built from this object while `kin status` on the
    /// same daemon at the same instant correctly answered "not measured"
    /// (FIR-2820).
    pub fn from_health(health: &Value) -> Option<Self> {
        let reconcile = health.get("reconcile")?;
        let unadmitted_paths = reconcile.get("untracked_path_count")?.as_u64()?;
        let measured_age_seconds = reconcile
            .get("untracked_observed_age_seconds")
            .and_then(Value::as_u64);
        // Named by the daemon, not inferred here. A projected checkout on a
        // daemon whose graph is its own write authority holds no content
        // anything failed to admit, so an unstamped zero there is the question
        // not applying rather than a walk that went missing.
        let observation_not_applicable = reconcile
            .get("untracked_observation_not_applicable")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if unadmitted_paths == 0
            && (measured_age_seconds.is_some() || observation_not_applicable)
        {
            return None;
        }
        let since = reconcile
            .get("last_admission_success_at")
            .and_then(Value::as_str)
            .map(str::to_string);
        let sample = reconcile
            .get("untracked_paths_sample")
            .and_then(Value::as_array)
            .map(|paths| {
                paths
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let note = Self::describe(unadmitted_paths, since.as_deref(), measured_age_seconds);
        Some(Self {
            unadmitted_paths,
            since,
            sample,
            measured_age_seconds,
            note,
        })
    }

    /// Whether this object is the no-measurement disclosure rather than a count.
    ///
    /// The count is the discriminator, and there is no third shape:
    /// [`Self::from_health`] emits a zero only when nothing measured the working
    /// copy, and returns `None` for every zero that something did. A consumer
    /// asks this before sending a reader to `kin admit`, because there is no
    /// path to admit.
    pub fn unmeasured(&self) -> bool {
        self.unadmitted_paths == 0
    }

    fn describe(
        unadmitted_paths: u64,
        since: Option<&str>,
        measured_age_seconds: Option<u64>,
    ) -> String {
        let clock = match since {
            Some(since) => format!("the last complete admission was at {since}"),
            None => {
                "this daemon has not reported when a complete admission last succeeded".to_string()
            }
        };
        if unadmitted_paths == 0 {
            return format!(
                "nothing has measured this working copy, so whether graph truth is level with it \
                 is unknown, and {clock}. Answers here cover admitted content only. `kin status` \
                 reports the same, and a commit takes any unadmitted path anyway."
            );
        }
        // The age rides in the sentence as well as the field, because a count
        // with no clock cannot say whether the store fell behind a second ago
        // or a month ago, and a reader of the note gets only the sentence.
        let measured = match measured_age_seconds {
            Some(age) => format!(", measured {age}s ago,"),
            None => String::new(),
        };
        format!(
            "{unadmitted_paths} host path(s) are on disk that graph truth does not carry\
             {measured} and {clock}. Answers here cover admitted content only. `kin admit` takes \
             those paths now, and a commit takes them anyway."
        )
    }

    /// The machine-stable reason an absence claim cannot be certified over this
    /// store.
    ///
    /// A symbol defined only inside an unadmitted path is absent from every
    /// index the query reads, so the answer is right about the graph and wrong
    /// about the repository. That is the difference between "not there" and "not
    /// admitted yet", and it is the whole of what this factor names.
    pub fn limiting_factor(&self) -> String {
        let clock = match self.since.as_deref() {
            Some(since) => format!("the last complete admission was at {since}"),
            None => "no complete admission has been reported".to_string(),
        };
        // Two readings, two reasons, and the reader is sent to a different
        // lever by each. One says the graph is behind by a known amount; the
        // other says nobody knows, which is not the same news and must not
        // borrow the first one's words.
        if self.unmeasured() {
            return format!(
                "working_copy_unmeasured: nothing has measured this working copy, so whether \
                 graph truth is level with it is unknown and {clock}; an absence here cannot be \
                 told apart from content the graph has not taken yet"
            );
        }
        format!(
            "graph_behind_working_tree: {} host path(s) on disk have never been admitted and \
             {clock}, so an absence here cannot be told apart from content the graph has not \
             taken yet",
            self.unadmitted_paths
        )
    }
}

/// Whether the daemon can name a complete admission at all, read on its own
/// rather than through the unadmitted-path count.
///
/// [`GraphBehind`] answers "is there content on disk the graph never took", and
/// it correctly says nothing when the working copy holds no new files. That made
/// it the wrong carrier for a second, independent fact: whether graph truth was
/// ever brought level with the repository in the first place. A store whose
/// working copy is clean and whose graph was built long ago has nothing
/// unadmitted and is still not current, so the clock was discarded by
/// `GraphBehind::from_health`'s zero-count gate before anything could read it,
/// and the answer certified (FIR-2226).
///
/// Read from the daemon's reconcile block, which is the same reading
/// `GraphBehind` uses and carries the clock whether or not the count is zero.
/// Note WHICH clock: it is the daemon's in-memory record of this process's own
/// admissions, so a restart resets it. That is not a flaw in the reading, it is
/// the condition the ticket is about, and it is exactly what makes
/// [`Self::NoAdmissionRecorded`] worth reporting.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum GraphFreshness {
    /// The daemon named a complete admission.
    ///
    /// This says an admission succeeded in this daemon's life and when. It does
    /// NOT say the graph is current, because nothing on this surface measures
    /// distance between graph truth and the repository, and a wall-clock
    /// threshold would age against whatever repository the next user brings.
    Recorded {
        at: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        age_seconds: Option<u64>,
    },
    /// The daemon reported a reconcile reading and no complete admission inside
    /// it, which is the restart case: the record lives in daemon memory, so a
    /// restart erases it and every surface then reports that none has ever
    /// succeeded in this daemon's life. An answer taken over that store is
    /// answering from a graph nothing in this process ever brought level.
    NoAdmissionRecorded,
}

impl GraphFreshness {
    /// Read the clock out of a daemon `/health` body, independently of the
    /// unadmitted-path count.
    ///
    /// `None` when the body carries no reconcile reading at all: a runtime that
    /// reported nothing has nothing to say here, and inventing `current` for it
    /// is the shape of wrong answer this type exists to stop. The two fields are
    /// `skip_serializing_if = "Option::is_none"` at their producer, so their
    /// absence from a reconcile block that IS present is itself the reading,
    /// not a parse failure.
    pub fn from_health(health: &Value) -> Option<Self> {
        let reconcile = health.get("reconcile")?;
        let Some(at) = reconcile
            .get("last_admission_success_at")
            .and_then(Value::as_str)
        else {
            return Some(Self::NoAdmissionRecorded);
        };
        Some(Self::Recorded {
            at: at.to_string(),
            age_seconds: reconcile
                .get("last_admission_success_age_seconds")
                .and_then(Value::as_u64),
        })
    }

    /// The factor a store with no recorded admission carries into the verdict.
    ///
    /// `None` for a store that named one, because this surface has no basis to
    /// refuse an answer over a clock it cannot compare to anything.
    pub fn limiting_factor(&self) -> Option<String> {
        match self {
            Self::Recorded { .. } => None,
            Self::NoAdmissionRecorded => Some(
                "graph_admission_unrecorded: this daemon reports no complete admission of the \
                 repository into graph truth, so how far the graph is behind the working tree is \
                 unmeasured and an answer here cannot be read as covering current code"
                    .to_string(),
            ),
        }
    }
}

impl Durability {
    /// Derive the durability state from the two counts the daemon observed.
    ///
    /// `durable` is `None` when the daemon has never levelled its query graph
    /// with durable authority and therefore has nothing to report; that is
    /// `unknown`, not zero. A durable count ABOVE the live count is also
    /// `unknown`: the live graph has dropped entities authority still carries,
    /// so the difference is not a count of uncommitted work and reporting
    /// `recorded` there would be the false all-clear this object exists to
    /// prevent.
    pub fn observe(live: u64, durable: Option<u64>) -> Self {
        let Some(durable) = durable else {
            return Self {
                state: DURABILITY_UNKNOWN.to_string(),
                live_entities: Some(live),
                durable_entities: None,
                live_only_entities: None,
                note: "This daemon has not levelled its query graph with durable repository \
                       authority, so whether these entities are recorded is unknown. Run `kin \
                       status` to read durable authority directly."
                    .to_string(),
            };
        };
        if durable > live {
            return Self {
                state: DURABILITY_UNKNOWN.to_string(),
                live_entities: Some(live),
                durable_entities: Some(durable),
                live_only_entities: None,
                note: format!(
                    "The live query graph holds {live} entities and durable authority carries \
                     {durable}, so this answer cannot say how much of it is recorded. Run `kin \
                     status` to read durable authority directly."
                ),
            };
        }
        let live_only = live - durable;
        if live_only == 0 {
            return Self {
                state: DURABILITY_RECORDED.to_string(),
                live_entities: Some(live),
                durable_entities: Some(durable),
                live_only_entities: Some(0),
                note: format!(
                    "{live} entities, 0 uncommitted; durable repository authority records \
                     everything answering here."
                ),
            };
        }
        Self {
            state: DURABILITY_LIVE_UNCOMMITTED.to_string(),
            live_entities: Some(live),
            durable_entities: Some(durable),
            live_only_entities: Some(live_only),
            note: format!(
                "{live} entities, {live_only} uncommitted; {} is recorded yet, and the \
                 uncommitted work is lost when this daemon exits. Commit to record it.",
                if durable == 0 {
                    "nothing you wrote"
                } else {
                    "not all of what you wrote"
                }
            ),
        }
    }

    /// Restate this reading over a store the working copy has outrun.
    ///
    /// [`Self::observe`] compares two ENTITY counts, so it answers a question
    /// about what a commit carries and is structurally unable to see a file no
    /// admission has taken. A store holding unadmitted host paths therefore
    /// reached `recorded` and said "durable repository authority records
    /// everything answering here" over a repository holding a 140-line module
    /// the graph had never met (FIR-2499). The counts are left exactly as
    /// observed, because they were never the wrong part; what changes is the
    /// claim made from them.
    ///
    /// The claim is three things and only the prose was withdrawn. `state` kept
    /// reading `recorded` and `live_only_entities` kept reading zero beside a
    /// note explaining that neither could be relied on, so a caller keying on
    /// the fields, which is what fields are for, was told the all-clear the
    /// sentence had just taken back (FIR-2820). Both move here. The derived
    /// number goes rather than growing: how many entities an unadmitted file
    /// holds is not knowable from a graph that never parsed it, and inventing a
    /// figure is the one thing this object promises never to do.
    ///
    /// So the sentence does not state one either. The first version of this
    /// composed its lead from `live_only_entities` and then withdrew the field,
    /// which is the FIR-2499 failure with the halves swapped: a reader grepping
    /// the payload for "0 uncommitted" over an unadmitted module still found it,
    /// one clause before the note explained that no such number was derivable.
    /// The lead now states the live count, which is a fact, and nothing else.
    pub fn qualified_by(mut self, behind: &GraphBehind) -> Self {
        let counts = match self.live_entities {
            Some(live) => format!("{live} entities answered here"),
            None => "this graph answered".to_string(),
        };
        // Two readings and two sentences, for the same reason the limiting
        // factor carries two: a measured count and no measurement at all send a
        // reader to different levers, and one of them is `kin admit`.
        self.note = if behind.unmeasured() {
            format!(
                "{counts}, and nothing has measured this working copy, so how much of it is \
                 recorded is unknown; this reading covers admitted content only. `kin status` \
                 reports the same, and a commit takes any unadmitted path anyway."
            )
        } else {
            format!(
                "{counts}, and {} host path(s) on disk that no admission has taken, so how much \
                 of this working copy is recorded is unknown; this reading covers admitted \
                 content only. `kin admit` takes those paths now, and a commit takes them \
                 anyway.",
                behind.unadmitted_paths
            )
        };
        self.state = DURABILITY_UNKNOWN.to_string();
        self.live_only_entities = None;
        self
    }

    /// True when durable authority does not carry everything the answer read.
    pub fn is_live_uncommitted(&self) -> bool {
        self.state == DURABILITY_LIVE_UNCOMMITTED
    }
}

/// Which completeness gate governs whether an *absent* result can be trusted as
/// a definitive negative. Different retrieval families depend on different
/// substrates, so "is the index complete enough to trust an empty answer?" has
/// two different answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NegativeClass {
    /// Embedding-backed retrieval (`semantic_locate`). An empty result is only
    /// authoritative when *embedding* coverage is complete — a half-embedded
    /// graph can hide a match that exists.
    Semantic,
    /// Graph-structure-backed retrieval (`semantic_search`, `find_references`,
    /// `graph_neighborhood`, `trace_data_flow`, `dead_code`,
    /// `find_dead_code_seeded`, `entity_history`, `bulk_check_references`). These
    /// read typed graph relations or the entity index, not embeddings, so their
    /// absence-trust depends on the *graph* being initialized and loaded, not on
    /// embedding coverage.
    Structural,
}

/// Which substrate an answer was drawn from, and therefore what "complete"
/// means for it.
///
/// Derived from the two registries that already exist rather than declared in a
/// third: a tool that names cross-file edge classes in
/// [`crate::negative::absence_cross_file_classes`] answers from edges, a tool
/// whose [`NegativeClass`] is `Semantic` answers from embeddings, and every
/// other retrieval tool answers from the entity/relation index. A third list
/// would drift from the two, which is the failure the per-tool maps in
/// [`crate::negative`] were written to avoid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CoverageSubstrate {
    Edges,
    Embeddings,
    Graph,
}

impl CoverageSubstrate {
    fn as_str(self) -> &'static str {
        match self {
            CoverageSubstrate::Edges => "edges",
            CoverageSubstrate::Embeddings => "embeddings",
            CoverageSubstrate::Graph => "graph",
        }
    }

    /// The substrate as it reads inside a sentence, which is not the same word
    /// as the wire value: "the edges classes" is not English, and the note is
    /// read by whoever has to act on a partial answer.
    fn noun(self) -> &'static str {
        match self {
            CoverageSubstrate::Edges => "edge",
            CoverageSubstrate::Embeddings => "embedding",
            CoverageSubstrate::Graph => "graph",
        }
    }
}

/// A coverage class's observed state, spelled the same way
/// [`crate::edge_coverage`] spells it so a reader never has to reconcile two
/// vocabularies for one fact.
const STATE_PRESENT: &str = "present";
const STATE_ABSENT: &str = "absent";
const STATE_UNKNOWN: &str = "unknown";
/// A class the scan completed empty on while the parse side shows the linker
/// had sites of it to resolve: a gap in the build, not the code (FIR-2672).
const STATE_UNPRODUCED: &str = "unproduced";

/// The completeness signal every retrieval response carries, empty or not
/// (FIR-2357 item 1).
///
/// The `negative` object guards the LOUD failure: an empty answer, which makes a
/// careful agent suspicious on its own. This guards the quiet one. A partial
/// answer looks exactly like a complete one, so `find_references` returned a
/// single caller for a symbol five call sites reached and carried nothing at all
/// saying the answer was a floor. An agent that reads one file back and
/// concludes the function is local is reasoning correctly from what it was
/// given, which is what makes the missing signal the defect rather than the
/// agent.
///
/// One shape across every retrieval tool. What varies between them is which
/// substrate they read, named in `substrate`, and which classes of it their
/// answer depended on, named in `classes`. Nothing here is fabricated: a class
/// nothing was observed about is `unknown`, and `unknown` is not `absent`.
///
/// ## What decides `status`
///
/// `decided_by` is a subset of `classes`, and the gap between them is
/// deliberate. `classes` DISCLOSES every class the query read; `decided_by`
/// carries only the ones whose absence would actually have hidden an answer.
/// Kin mints no entity-level `Imports` edge at all, so requiring every requested
/// class to be present would report every answer on every healthy graph as
/// partial, which is the "mark everything uncertain" regression FIR-2357 item 4
/// bars by test. [`crate::negative::load_bearing_classes`] is the same narrowing
/// the absence verdict already uses, and it is reused here rather than
/// re-derived.
///
/// ## What decides `bound`
///
/// `status` is about the substrate; `bound` is about the numbers the answer
/// printed. They come apart in both directions: a complete substrate still
/// yields a floor when the response budget dropped rows, and a partial substrate
/// still counts exactly what it holds. `at_least` is the field that kills the
/// unqualified count the ticket names, so it is set whenever the answer cannot
/// be shown to be whole.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Completeness {
    /// `complete` when every deciding class was observed present, `partial` when
    /// one was observed absent, `unknown` when the observation could not say.
    pub status: String,
    /// `exact` when the counts in this answer are the whole set, `at_least` when
    /// they are a floor. Never omitted: a caller reading a bare number is the
    /// failure this object exists to prevent.
    pub bound: String,
    /// Which substrate this answer was drawn from: `edges`, `embeddings`, or
    /// `graph`.
    pub substrate: String,
    /// Every coverage class the answer depended on, each `present`, `absent`, or
    /// `unknown`.
    pub classes: Map<String, Value>,
    /// The subset of `classes` whose state decided `status`.
    pub decided_by: Vec<String>,
    /// What the answer counted and whether that count is the whole set, lifted
    /// from the payload's own accounting rather than recomputed here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counted: Option<Value>,
    /// Parsed call sites against resolved reference edges for the focal's
    /// language, when the graph carries a parse-side count to compare against
    /// (FIR-2357 item 2). This is the reading that makes "1 of 5" sayable;
    /// absent when nothing measured it, never a fabricated ratio.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference_resolution: Option<Value>,
    /// Machine-stable labels for every shortfall this answer's own observation
    /// names, including ones that did not decide `status`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub limits: Vec<String>,
    /// One line an agent can act on without knowing the ground truth.
    pub note: String,
}

impl Completeness {
    /// Build the signal for `tool` from its payload and the envelope beside it,
    /// or `None` for a tool that is not retrieval.
    ///
    /// Retrieval membership is derived, not listed: a tool qualifies when it has
    /// a negative spec or when it declares cross-file edge classes. Both
    /// registries live in [`crate::negative`], so a new retrieval tool earns a
    /// completeness signal by declaring what it reads, exactly as it earns an
    /// absence verdict.
    fn for_tool(tool: &str, payload: &Value, envelope: &Envelope) -> Option<Self> {
        let edge_classes = crate::negative::absence_cross_file_classes(tool, payload);
        let substrate = if !edge_classes.is_empty() {
            CoverageSubstrate::Edges
        } else {
            match crate::negative::negative_class_for(tool)? {
                NegativeClass::Semantic => CoverageSubstrate::Embeddings,
                NegativeClass::Structural => CoverageSubstrate::Graph,
            }
        };

        let (mut classes, mut decided_by, mut limits) = match substrate {
            CoverageSubstrate::Edges => edge_class_states(tool, payload, &edge_classes),
            CoverageSubstrate::Embeddings => embedding_class_states(envelope),
            CoverageSubstrate::Graph => graph_class_states(envelope),
        };

        // A file enumeration is decided by that file's own parse state, which
        // no store-level class can see. A completely loaded, fully embedded,
        // undegraded graph holds no entities for a file no adapter parsed, so
        // the `graph` class above reads `present` while the answer is empty for
        // a reason that has nothing to do with the code.
        if tool == crate::handlers::file_entities::TOOL_NAME {
            merge_file_coverage_classes(
                payload,
                envelope,
                &mut classes,
                &mut decided_by,
                &mut limits,
            );
        }

        // A walk that refused a type-annotation hop withheld something the
        // caller could have asked for, so it is named here. It is disclosure
        // only: `limits` does not decide `status`, and it must not, because a
        // data-flow chain that declines to hop through a type name is more
        // correct rather than less complete. An `external_reference` terminal
        // gets no label at all, since no parameter would produce more of a
        // symbol this repository does not define.
        if payload
            .get("terminal_annotation_steps")
            .and_then(Value::as_u64)
            .is_some_and(|steps| steps > 0)
        {
            limits.push("type_annotation_edges_not_walked".to_string());
        }

        // Runtime facts are disclosed and never decide. The question this object
        // answers is whether the substrate was whole, and `_kin.runtime` plus
        // `_kin.degraded` already answer the separate question of who served it.
        // Folding them in would make every offline answer uncertain regardless
        // of its coverage, which is the barred regression wearing a different
        // costume.
        for label in envelope.degraded.active_labels() {
            limits.push(format!("degraded:{label}"));
        }

        let deciding_states: Vec<&str> = decided_by
            .iter()
            .map(|class| {
                classes
                    .get(class)
                    .and_then(Value::as_str)
                    .unwrap_or(STATE_UNKNOWN)
            })
            .collect();
        let status = if deciding_states.is_empty() {
            STATE_UNKNOWN
        } else if deciding_states
            .iter()
            .any(|state| *state == STATE_ABSENT || *state == STATE_UNPRODUCED)
        {
            "partial"
        } else if deciding_states.iter().any(|state| *state != STATE_PRESENT) {
            STATE_UNKNOWN
        } else {
            "complete"
        };

        let mut counted = counted_for(tool, payload);
        // A payload that says it stopped early is a floor whatever its substrate
        // looked like, so its own truncation flag can veto a complete verdict.
        let walk_truncated = counted
            .as_ref()
            .and_then(|counted| counted.get("floor_reason"))
            .is_some();
        let bound = if status == "complete" && !walk_truncated {
            "exact"
        } else {
            "at_least"
        };
        // One authority for one fact. `bound` decides, and the count restates it
        // where a reader looking at the number will actually see it, because a
        // `counted` reading `exact: true` beside a `bound` of `at_least` is the
        // same contradiction inside one object that this object exists to end
        // between two.
        if let Some(counted) = counted.as_mut().and_then(Value::as_object_mut) {
            counted.insert("exact".to_string(), json!(bound == "exact"));
        }

        let reference_resolution = payload
            .get(crate::edge_coverage::EDGE_COVERAGE_KEY)
            .and_then(|coverage| coverage.get(crate::edge_coverage::REFERENCE_RESOLUTION_KEY))
            .cloned();

        Some(Completeness {
            note: completeness_note(status, bound, substrate, &decided_by, &limits),
            status: status.to_string(),
            bound: bound.to_string(),
            substrate: substrate.as_str().to_string(),
            classes,
            decided_by,
            counted,
            reference_resolution,
            limits,
        })
    }

    /// Downgrade the signal to a floor because the response budget removed rows.
    ///
    /// The budget runs after this object is serialized, so the cut cannot be
    /// known when the verdict is built. A response shortened by the budget is
    /// partial by exactly the definition this object uses, and letting it keep
    /// `exact` would reintroduce the unqualified count through the one path that
    /// removes answers on purpose.
    fn mark_response_bounded(value: &mut Value) {
        let Some(object) = value.as_object_mut() else {
            return;
        };
        object.insert("bound".to_string(), json!("at_least"));
        if let Some(counted) = object.get_mut("counted").and_then(Value::as_object_mut) {
            counted.insert("exact".to_string(), json!(false));
        }
        let limits = object
            .entry("limits".to_string())
            .or_insert_with(|| json!([]));
        if let Some(limits) = limits.as_array_mut() {
            let label = json!("response_bounded");
            if !limits.contains(&label) {
                limits.push(label);
            }
        }
        object.insert(
            "note".to_string(),
            json!(
                "The response budget withheld part of this answer, so its counts are a lower \
                 bound. `_kin.response` names what was cut and how to ask for the rest."
            ),
        );
    }
}

/// The edge-class states this answer depended on, read off the observation the
/// payload carries.
///
/// A payload with no observation leaves every class `unknown` rather than
/// healthy. That is the same reading [`crate::negative::edge_coverage_gap`]
/// takes, and it is what makes a tool publish the observation before it can
/// report itself complete.
fn edge_class_states(
    tool: &str,
    payload: &Value,
    requested: &[String],
) -> (Map<String, Value>, Vec<String>, Vec<String>) {
    let observation = payload
        .get(crate::edge_coverage::EDGE_COVERAGE_KEY)
        .and_then(Value::as_object);
    let states = observation.and_then(|observation| {
        observation
            .get("classes")
            .and_then(Value::as_object)
            .cloned()
    });
    let mut classes = Map::new();
    for class in requested {
        let state = states
            .as_ref()
            .and_then(|states| states.get(class))
            .and_then(Value::as_str)
            .unwrap_or(STATE_UNKNOWN);
        classes.insert(class.clone(), json!(state));
    }
    // The same deciding set the absence gate and the language scan read, so this
    // block cannot say "the counts here are the whole set" about a graph the
    // verdict beside it has just called inconclusive. Shipped v0.5.43 published
    // exactly that pair on expressjs/express (FIR-2505, FIR-2492).
    let decided_by = crate::negative::deciding_classes(
        requested,
        crate::negative::references_producible(payload),
    );
    let limits = crate::negative::edge_coverage_degradation_labels(tool, payload);
    (classes, decided_by, limits)
}

/// The embedding class state, from the one embedding verdict the coverage
/// object carries.
///
/// Reads [`SemanticCoverage::embedding_state`] and never
/// [`SemanticCoverage::complete`]. That flag is a conjunction over the substrate
/// AND the population a query ranked over, so deriving the embedding class from
/// it published `classes.embeddings: absent` beside `indexed 2112, pending 0` in
/// one shipped `semantic_locate` envelope: the role filter had withheld fifteen
/// test-role paths, which clears `complete` and says nothing about embeddings
/// (FIR-2543).
///
/// Every other reason `complete` is false is still reported, in `limits`, where
/// it is disclosure rather than a verdict about a substrate it never measured.
fn embedding_class_states(envelope: &Envelope) -> (Map<String, Value>, Vec<String>, Vec<String>) {
    let mut limits = Vec::new();
    let state = match &envelope.semantic_coverage {
        None => EmbeddingState::Unknown,
        Some(coverage) => {
            limits.extend(coverage.scope_limits());
            coverage.embedding_state()
        }
    };
    let mut classes = Map::new();
    classes.insert("embeddings".to_string(), json!(state.class_state()));
    if let Some(label) = state.limit_label() {
        limits.push(label.to_string());
    }
    (classes, vec!["embeddings".to_string()], limits)
}

/// The graph class state, from the freshness signals the envelope observed.
///
/// Both halves have to be affirmatively true. `initialized` says first
/// reconciliation finished and `loaded` says a graph is actually mounted; either
/// one false means the index a structural answer read is not the whole one.
fn graph_class_states(envelope: &Envelope) -> (Map<String, Value>, Vec<String>, Vec<String>) {
    let state = match (
        envelope.graph_state.initialized,
        envelope.graph_state.loaded,
    ) {
        (Some(true), Some(true)) => STATE_PRESENT,
        (Some(false), _) | (_, Some(false)) => STATE_ABSENT,
        _ => STATE_UNKNOWN,
    };
    let mut classes = Map::new();
    classes.insert("graph".to_string(), json!(state));
    let limits = if state == STATE_PRESENT {
        Vec::new()
    } else {
        vec![format!("graph_{state}")]
    };
    (classes, vec!["graph".to_string()], limits)
}

/// The file's own coverage classes, folded in beside the store's.
///
/// `file_parsed` decides, and it is the only one that does. `file_enriched` and
/// `embeddings` are disclosed because a reader asks about them, but neither can
/// make an enumeration short: enrichment adds edges between entities and
/// embeddings add ranking, while the entity set of a file is fixed by what the
/// adapter extracted. Naming a class that cannot have limited the answer as one
/// that did is how a correct answer comes to read as uncertain.
///
/// `embeddings` is the store-grain reading on purpose and says so in its own
/// name rather than pretending to a per-file number nothing measures. A complete
/// store is a sound superset claim about this file; an incomplete one says
/// nothing about it, which is `unknown` rather than `absent`.
fn merge_file_coverage_classes(
    payload: &Value,
    envelope: &Envelope,
    classes: &mut Map<String, Value>,
    decided_by: &mut Vec<String>,
    limits: &mut Vec<String>,
) {
    let coverage = payload
        .get(crate::handlers::file_entities::FILE_COVERAGE_KEY)
        .and_then(Value::as_object);

    let parsed = match coverage
        .and_then(|coverage| coverage.get("parsed"))
        .and_then(Value::as_str)
    {
        Some("full") => STATE_PRESENT,
        Some("absent") | Some("partial") | Some("failed") => STATE_ABSENT,
        _ => STATE_UNKNOWN,
    };
    classes.insert("file_parsed".to_string(), json!(parsed));
    decided_by.push("file_parsed".to_string());
    if parsed != STATE_PRESENT {
        // Name the cause when the answer carries one. `file_parsed_absent` is
        // true and says nothing: a file no adapter claims and a file whose
        // adapter fell over earn the same word, and only the second is evidence
        // about the code, so a reader acting on the limit cannot tell which they
        // have. `content_opaque` is computed from the adapter registry one file
        // over, so this reads a cause rather than inferring one.
        limits.push(
            match coverage
                .and_then(|coverage| coverage.get("opaque_reason"))
                .and_then(Value::as_str)
            {
                Some(reason) => format!("file_content_opaque_{reason}"),
                None => format!("file_parsed_{parsed}"),
            },
        );
    }

    let enriched = match coverage
        .and_then(|coverage| coverage.get("enriched"))
        .and_then(Value::as_str)
    {
        Some("present") => STATE_PRESENT,
        Some("absent") => STATE_ABSENT,
        _ => STATE_UNKNOWN,
    };
    classes.insert("file_enriched".to_string(), json!(enriched));

    let embedded = match &envelope.semantic_coverage {
        Some(coverage) if coverage.complete => STATE_PRESENT,
        _ => STATE_UNKNOWN,
    };
    classes.insert("embeddings_store_wide".to_string(), json!(embedded));
}

/// A file enumeration's accounting: how many entities the file holds, and
/// whether this response holds all of them.
///
/// `reported` is the whole-file total rather than the page length, because that
/// is the number a caller asks the tool for. `exact` is false the moment the
/// response is one page of several, so the total can be read as the file's count
/// without the page being read as the file.
fn file_entities_counted(payload: &Value) -> Option<Value> {
    let reported = payload.get("total_in_file").and_then(Value::as_u64)?;
    let coverage = payload
        .get(crate::handlers::file_entities::FILE_COVERAGE_KEY)
        .and_then(Value::as_object);
    let certified = coverage
        .and_then(|coverage| coverage.get("certifies_enumeration"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let whole_file = coverage
        .and_then(|coverage| coverage.get("whole_file_in_response"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let shifted = payload
        .get("enumeration_shifted")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let parsed = coverage
        .and_then(|coverage| coverage.get("parsed"))
        .and_then(Value::as_str)
        .unwrap_or("unknown");

    let mut counted = json!({
        "unit": "entities_in_file",
        "reported": reported,
        "returned": payload.get("returned").and_then(Value::as_u64).unwrap_or(0),
        "exact": certified,
    });
    // Named in the order a reader acts on. A file the adapter never parsed is
    // the limiting factor whatever the paging did, because following every
    // cursor to the end still assembles a set the extractor never produced.
    if parsed != "full" {
        counted["floor_reason"] = json!(format!("file_parsed_{parsed}"));
    } else if shifted {
        counted["floor_reason"] = json!("enumeration_shifted");
    } else if !whole_file {
        counted["floor_reason"] = json!("page_bounded");
    }
    Some(counted)
}

/// What this answer counted and whether the count is the whole set, lifted from
/// the payload's own accounting.
///
/// Nothing is recounted here. The handlers already publish what their number
/// means (`counts.counted` names the unit, `counts.reference_sites_complete`
/// says whether the finer number is whole), and recomputing it in the envelope
/// is how two counters come to disagree about one answer.
fn counted_for(tool: &str, payload: &Value) -> Option<Value> {
    if tool == crate::handlers::file_entities::TOOL_NAME {
        return file_entities_counted(payload);
    }
    let (unit, reported) = match tool {
        "find_references" => (
            payload
                .get("counts")
                .and_then(|counts| counts.get("counted"))
                .and_then(Value::as_str)
                .unwrap_or("referencing_entities"),
            payload.get("total_upstream").and_then(Value::as_u64)?,
        ),
        "trace_data_flow" => ("steps", payload.get("total_steps").and_then(Value::as_u64)?),
        "bulk_check_references" => (
            "entities",
            payload
                .get("results")
                .and_then(Value::as_array)
                .map(|rows| rows.len() as u64)?,
        ),
        _ => return None,
    };

    // A response that says it stopped early is a floor whatever its substrate
    // looked like, so the payload's own truncation flag outranks the class
    // verdict for this field.
    let truncated = payload.get("truncated").and_then(Value::as_bool) == Some(true);
    // FIR-1552: same rule, other cause. An answer that held same-name candidates
    // out of its headline reports a number some of those candidates may belong
    // in, so the number is a floor and this object has to say so with the count
    // beside it. Truncation is named first where both hold, because a walk that
    // stopped early did not even see every candidate.
    let withheld = payload
        .get("counts")
        .and_then(|counts| counts.get("receiver_name_candidates"))
        .and_then(Value::as_u64)
        .filter(|withheld| *withheld > 0);
    let mut counted = json!({
        "unit": unit,
        "reported": reported,
        "exact": !truncated && withheld.is_none(),
    });
    if let Some(withheld) = withheld {
        counted["withheld_candidates"] = json!(withheld);
    }
    if truncated {
        counted["floor_reason"] = json!("walk_truncated");
    } else if withheld.is_some() {
        counted["floor_reason"] = json!("receiver_name_candidates_withheld");
    }
    // The site numbers FIR-2398 added answer a narrower question than this
    // object does: whether every RETURNED row could be located at a line, not
    // whether the row set is whole. They are carried verbatim rather than folded
    // into `exact`, because collapsing the two is how a complete row set with one
    // unlocatable site would come to read as an incomplete answer.
    if let Some(sites) = payload.get("counts").and_then(|counts| {
        let object = counts.as_object()?;
        let mut sites = Map::new();
        for key in [
            "reference_sites",
            "known_reference_sites",
            "reference_sites_complete",
        ] {
            if let Some(value) = object.get(key) {
                sites.insert(key.to_string(), value.clone());
            }
        }
        (!sites.is_empty()).then_some(Value::Object(sites))
    }) {
        counted["sites"] = sites;
    }
    Some(counted)
}

/// One line an agent can act on. Says what the answer is worth and, when it is
/// worth less than it looks, what limited it.
///
/// The deciding classes are NAMED rather than described as "every class this
/// answer depended on". That phrasing was accurate about `decided_by` and read
/// as a claim about `classes`, which sat directly below it in the same object
/// with two of three entries marked `absent`. A reader cannot be expected to
/// know which subset a sentence means when the superset is printed beside it.
fn completeness_note(
    status: &str,
    bound: &str,
    substrate: CoverageSubstrate,
    decided_by: &[String],
    limits: &[String],
) -> String {
    let named = if limits.is_empty() {
        String::new()
    } else {
        format!(" Limited by: {}.", limits.join(", "))
    };
    let deciding = if decided_by.is_empty() {
        format!("no {} class", substrate.noun())
    } else {
        format!(
            "the {} {} class(es)",
            decided_by.join(", "),
            substrate.noun()
        )
    };
    match (status, bound) {
        ("complete", "exact") => {
            format!("This answer rested on {deciding}, and each was observed present, so the counts here are the whole set.")
        }
        ("complete", _) => format!(
            "This answer rested on {deciding}, and each was observed present, but the counts are \
             a lower bound.{named}"
        ),
        ("partial", _) => format!(
            "One of the {} classes this answer depended on was observed absent, so what came back \
             is a lower bound and its absence proves nothing about the code.{named}",
            substrate.noun()
        ),
        _ => format!(
            "Whether the {} classes this answer depended on were available could not be \
             established, so treat the counts as a lower bound.{named}",
            substrate.noun()
        ),
    }
}

/// The versioned MCP response envelope shared by every tool family.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Envelope {
    /// Schema version of this envelope ([`ENVELOPE_VERSION`]).
    pub envelope_version: u32,
    /// Runtime that produced the response.
    pub runtime: Runtime,
    /// Embedding coverage when known; `null`/absent when unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantic_coverage: Option<SemanticCoverage>,
    /// Precise graph version marker when known; `null`/absent otherwise. Populated
    /// from the daemon `/health` `graph_generation` marker (the monotonic snapshot
    /// generation, bumped per committed snapshot) via [`Envelope::with_health`], or
    /// from a tool payload's own `graph_as_of`/`as_of` marker when one is carried.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub graph_as_of: Option<Value>,
    /// Whether the graph that answered survives the daemon serving it, beside
    /// the freshness marker rather than inside it: `graph_as_of` names WHICH
    /// graph state answered, and this names whether that state is recorded
    /// anywhere. Absent when the runtime reported no durable observation at
    /// all, which is the one case where saying nothing is more honest than
    /// saying `unknown` for a runtime that has no durable layer to compare to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub durability: Option<Durability>,
    /// How far graph truth is behind the working copy, when the runtime
    /// reported that it is behind at all.
    ///
    /// Beside `durability` rather than inside it because the two count
    /// different things and can disagree. `durability` compares entity counts
    /// and answers "is what answered here recorded"; this compares the graph to
    /// the host and answers "is there content that never reached the graph at
    /// all". A store can be perfectly durable and still be missing the file you
    /// wrote a minute ago, which is exactly the pair FIR-2499 caught reporting
    /// an all-clear.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub behind: Option<GraphBehind>,
    /// Whether graph truth was ever brought level with the repository at all,
    /// beside `behind` rather than inside it because the two count different
    /// things and can disagree. `behind` answers "is there content on disk the
    /// graph never took" and goes quiet on a clean working copy; this answers
    /// "was the graph ever admitted", which a clean working copy says nothing
    /// about. A store can hold zero unadmitted paths and still have been built
    /// against content that has since moved, which is the pair FIR-2226 caught
    /// certifying an all-clear.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub freshness: Option<GraphFreshness>,
    /// Honest graph freshness context; omitted entirely when nothing is known.
    #[serde(default, skip_serializing_if = "GraphState::is_empty")]
    pub graph_state: GraphState,
    /// Degraded-state flags (always present; individual flags omitted when not
    /// observed).
    pub degraded: Degraded,
    /// The completeness signal (FIR-2357): what this answer's substrate could
    /// have found, present on every retrieval response whether it came back
    /// empty or full. `negative` guards only the empty case; this guards the
    /// partial one, which is the case an agent cannot see.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completeness: Option<Completeness>,
    /// The response's one verdict (FIR-2463): the single field a reader acts on,
    /// computed from every block that would otherwise publish a verdict-shaped
    /// claim of its own, with the most pessimistic input winning.
    ///
    /// `negative` and `completeness` beside it are inputs to this and are
    /// projections of it, never independent answers. Present on every retrieval
    /// response at least one input spoke about, absent on everything else.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict: Option<Value>,
    /// What the response budget did to this payload: the budget applied and what
    /// the response measured before it. Present only on the retrieval tools the
    /// budget governs, and written by [`finalize_bounded`] AFTER this struct is
    /// serialized, because the number it reports is a property of the bytes the
    /// envelope itself rides in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response: Option<crate::budget::BudgetAccounting>,
}

impl Envelope {
    /// Envelope for the explicit offline/in-process runtime. Flags
    /// `offline_fallback` honestly — this is not daemon-owned truth.
    pub fn offline() -> Self {
        Self {
            envelope_version: ENVELOPE_VERSION,
            runtime: Runtime::OfflineInProcess,
            semantic_coverage: None,
            graph_as_of: None,
            durability: None,
            behind: None,
            freshness: None,
            graph_state: GraphState::default(),
            degraded: Degraded {
                offline_fallback: Some(true),
                ..Degraded::default()
            },
            completeness: None,
            verdict: None,
            response: None,
        }
    }

    /// Envelope for a daemon-answered response. Degraded flags start empty and
    /// are filled in honestly from the daemon `/health` body via
    /// [`Envelope::with_health`].
    pub fn daemon() -> Self {
        Self {
            envelope_version: ENVELOPE_VERSION,
            runtime: Runtime::RepoDaemon,
            semantic_coverage: None,
            graph_as_of: None,
            durability: None,
            behind: None,
            freshness: None,
            graph_state: GraphState::default(),
            degraded: Degraded::default(),
            completeness: None,
            verdict: None,
            response: None,
        }
    }

    /// Bind the stdio response envelope to the same selected-graph observation
    /// carried by `kin.graph-status.v1`.
    ///
    /// Generic daemon responses enrich their envelope from `/health`. That
    /// endpoint is HEAD-scoped, so using it for a temporal-session graph status
    /// would mix two graph views in one payload. Graph status instead supplies
    /// its own entity and embedding observations here. Fields that only
    /// `/health` knows stay absent rather than being borrowed from HEAD.
    ///
    /// `durable_entity_count` is the one durable reading graph status carries
    /// itself, because the question it answers is about the selected graph and
    /// not about HEAD. `None` reaches [`Durability::observe`] as `unknown`.
    pub fn with_selected_graph_observation(
        mut self,
        entity_count: u64,
        embeddings_indexed: u64,
        embeddings_pending: u64,
        embeddings_total: u64,
        durable_entity_count: Option<u64>,
    ) -> Self {
        let complete = embeddings_pending == 0 && embeddings_indexed == embeddings_total;
        self.runtime = Runtime::RepoDaemon;
        self.semantic_coverage = Some(SemanticCoverage {
            indexed: embeddings_indexed,
            total: embeddings_total,
            pending: embeddings_pending,
            complete,
            // Graph status hands over counters and no index observation, so the
            // verdict is left to the one fallback in
            // [`SemanticCoverage::embedding_state`] rather than decided a second
            // way here. Naming a state this path cannot observe is how a second
            // authority for one fact gets created.
            embedding_state_reported: None,
            limited_by: Vec::new(),
            read_at: None,
            note: (!complete).then(|| {
                "Selected-graph embedding coverage is incomplete at this point-in-time observation."
                    .to_string()
            }),
            // Graph status observes embeddings, not the source-text phase's body
            // resolution, so it has no reading to report here.
            graph_body_gap_paths: None,
        });
        self.graph_as_of = None;
        let durability = Durability::observe(entity_count, durable_entity_count);
        // Requalified rather than replaced. This runs on the graph-status path,
        // which may set durability after `with_health` has already read the
        // reconcile block, and a plain assignment there would restore the
        // all-clear note that block exists to withdraw.
        self.durability = Some(match self.behind.as_ref() {
            Some(behind) => durability.qualified_by(behind),
            None => durability,
        });
        self.graph_state = GraphState {
            entity_count: Some(entity_count),
            ..GraphState::default()
        };
        // The selected report replaces HEAD-scoped health observations, but it
        // must not erase store-scoped records the stdio boundary already read
        // for this response. In production these four are stamped before graph
        // status is finalized. Resetting the whole object here made a refused
        // producer disappear only on `kin_graph_status`, while the same record
        // remained visible on every other tool.
        self.degraded = Degraded {
            embed_persistence_unavailable: if complete {
                None
            } else {
                self.degraded.embed_persistence_unavailable
            },
            sweep_suspended: self.degraded.sweep_suspended,
            memory_pressure: self.degraded.memory_pressure,
            relation_census_loss: self.degraded.relation_census_loss,
            enrichment_shortfall: self.degraded.enrichment_shortfall,
            ..Degraded::default()
        };
        self
    }

    /// Stamp what this store recorded about daemons of its own that were
    /// killed.
    ///
    /// Only the memory attribution becomes a flag, and only when the kernel's
    /// own counter made it. A kill this host could not attribute is reported in
    /// the message the caller reads and claims nothing structurally, because a
    /// client keying on a flag would read "killed by memory" out of a host that
    /// never said so.
    pub fn with_recorded_daemon_kill(
        mut self,
        record: Option<&kin_daemon_spawn::DaemonKillRecord>,
    ) -> Self {
        if record.is_some_and(|record| record.attributed_to_memory()) {
            self.degraded.daemon_killed_by_memory = Some(true);
        }
        self
    }

    /// Stamp that this store's enrichment sweeps have been suspended.
    ///
    /// A flag rather than prose because the caller acting on it is an agent
    /// deciding whether an absence it just measured is authoritative. A missing
    /// cross-file relation on a suspended store is a gap nothing is working on,
    /// which is a different answer from a gap a running sweep is about to fill,
    /// and only a structural signal separates them without parsing a sentence.
    ///
    /// Absent rather than `false` when the circuit is closed, for the reason
    /// every flag here is: `None` says this envelope makes no claim, and a
    /// fabricated `false` would say the store was checked and found healthy on
    /// a call that never looked.
    pub fn with_suspended_sweep(
        mut self,
        suspended: Option<&kin_daemon_spawn::SuspendedSweep>,
    ) -> Self {
        if suspended.is_some() {
            self.degraded.sweep_suspended = Some(true);
        }
        self
    }

    /// Stamp that this store's daemon has held heavy work back for want of
    /// memory.
    ///
    /// A flag rather than prose for the reason [`Self::with_suspended_sweep`]
    /// is one: the caller acting on it is an agent deciding whether an absence
    /// it just measured is authoritative, and a gap nothing is working on is a
    /// different answer from a gap a running pass is about to fill. Only a
    /// structural signal separates them without parsing a sentence.
    ///
    /// Absent rather than `false` when nothing was held back, because `None`
    /// says this envelope makes no claim and a fabricated `false` would say the
    /// store was checked and found clear on a call that never looked.
    pub fn with_memory_pressure(
        mut self,
        refusal: Option<&kin_core::memory_pressure::PressureRefusal>,
    ) -> Self {
        if refusal.is_some() {
            self.degraded.memory_pressure = Some(true);
        }
        self
    }

    /// Stamp that this store's graph is below its own last verified-good
    /// relation census.
    ///
    /// The reading it changes is the one that came back looking complete. A
    /// caller set that lost a member, or a call site that lost its edge, is
    /// indistinguishable from a correct answer at the response level: the rows
    /// that survive are true, the counts agree with themselves, and
    /// `reference_sites_complete` is about the rows that came back rather than
    /// about the ones that should have. The census is the only thing that knows
    /// the graph is short, so an answer taken while it is short says so instead
    /// of presenting as clean (FIR-2644).
    ///
    /// Absent rather than `false` when the store records no hold, for the reason
    /// every flag here is absent: `None` says this envelope makes no claim, and
    /// a fabricated `false` would say the store was checked and found whole on a
    /// call that never looked.
    pub fn with_relation_census_loss(
        mut self,
        hold: Option<&kin_core::relation_census::CensusHold>,
    ) -> Self {
        if hold.is_some() {
            self.degraded.relation_census_loss = Some(true);
        }
        self
    }

    /// Stamp that this store's last enrichment sweep did not publish everything
    /// it offered.
    ///
    /// A flag rather than prose for the reason the two above are: the caller
    /// acting on it is an agent deciding whether an absence it just measured is
    /// authoritative, and a missing cross-file relation on a store whose sweep
    /// fell short is a gap nothing is working on, which is a different answer
    /// from a gap a running sweep is about to fill.
    ///
    /// Absent rather than `false` when the last sweep came out clean, because
    /// `None` says this envelope makes no claim and a fabricated `false` would
    /// say the store was checked and found whole on a call that never looked.
    pub fn with_enrichment_shortfall(
        mut self,
        shortfall: Option<&kin_daemon_spawn::RefusedEnrichment>,
    ) -> Self {
        if shortfall.is_some() {
            self.degraded.enrichment_shortfall = Some(true);
        }
        self
    }

    /// Envelope for the case where the daemon was required but unreachable. The
    /// accompanying tool result is a transport error; this flags it structurally.
    pub fn daemon_unreachable() -> Self {
        Self {
            envelope_version: ENVELOPE_VERSION,
            runtime: Runtime::RepoDaemon,
            semantic_coverage: None,
            graph_as_of: None,
            durability: None,
            behind: None,
            freshness: None,
            graph_state: GraphState::default(),
            degraded: Degraded {
                daemon_unreachable: Some(true),
                ..Degraded::default()
            },
            completeness: None,
            verdict: None,
            response: None,
        }
    }

    /// Envelope for a call refused because the MCP client's workspace roots and
    /// this server's repository binding disagree.
    ///
    /// Deliberately not [`Envelope::daemon_unreachable`]: the daemon this server
    /// is bound to is reachable and healthy, and reporting a transport problem
    /// sends the reader to check the daemon, restart it, or reinstall, none of
    /// which touches the actual disagreement about which repository the answer
    /// would be about.
    pub fn workspace_mismatch() -> Self {
        Self {
            envelope_version: ENVELOPE_VERSION,
            runtime: Runtime::RepoDaemon,
            semantic_coverage: None,
            graph_as_of: None,
            durability: None,
            behind: None,
            freshness: None,
            graph_state: GraphState::default(),
            degraded: Degraded {
                workspace_mismatch: Some(true),
                ..Degraded::default()
            },
            completeness: None,
            verdict: None,
            response: None,
        }
    }

    /// Fold honest signals from a daemon `/health` JSON body into the envelope:
    /// the embedding-worker / persistence / mass-deletion degraded flags and
    /// the graph freshness state. Missing fields stay unknown (absent), never
    /// fabricated.
    pub fn with_health(mut self, health: &Value) -> Self {
        if let Some(value) = health.get("embed_worker_failed").and_then(Value::as_bool) {
            self.degraded.embed_worker_failed = Some(value);
        }
        if let Some(value) = health
            .get("embed_persistence_unavailable")
            .and_then(Value::as_bool)
        {
            self.degraded.embed_persistence_unavailable = Some(value);
        }
        if let Some(value) = health.get("mass_deletion_blocked").and_then(Value::as_bool) {
            self.degraded.mass_deletion_blocked = Some(value);
        }
        if let Some(value) = health.get("reconciliation_status").and_then(Value::as_str) {
            self.graph_state.reconciliation_status = Some(value.to_string());
        }
        if let Some(value) = health.get("graph_entity_count").and_then(Value::as_u64) {
            self.graph_state.entity_count = Some(value);
            self.graph_state.entity_count_scope = Some(ENTITY_COUNT_SCOPE.to_string());
        }
        if let Some(value) = health.get("graph_loaded").and_then(Value::as_bool) {
            self.graph_state.loaded = Some(value);
        }
        if let Some(value) = health.get("initialized").and_then(Value::as_bool) {
            self.graph_state.initialized = Some(value);
        }
        // Derived from the pair rather than reported by the daemon, because the
        // live count is the one this envelope already carries and deriving it
        // here keeps the two numbers from describing different instants. A
        // daemon that reports no live count has nothing to compare against, so
        // the object stays absent instead of asserting `unknown` about a graph
        // it never measured.
        if let Some(live) = self.graph_state.entity_count {
            self.durability = Some(Durability::observe(
                live,
                health.get("durable_entity_count").and_then(Value::as_u64),
            ));
        }
        // Read after the counts, and applied to them. The reconcile block is
        // the only place a response can learn that the host holds content the
        // graph never met, and without it every surface built from the counts
        // above states an all-clear it did not verify.
        self.behind = GraphBehind::from_health(health);
        // Read from the same reconcile block and deliberately NOT through
        // `behind`: the count gates that object off on a clean working copy, and
        // the clock is a fact about the graph rather than about the disk.
        self.freshness = GraphFreshness::from_health(health);
        if let Some(behind) = self.behind.as_ref() {
            self.durability = self
                .durability
                .take()
                .map(|durability| durability.qualified_by(behind));
        }
        // The daemon `/health` `graph_generation` marker (monotonic snapshot
        // generation, bumped per committed snapshot) is a precise freshness
        // marker: lift it into `graph_as_of` so a negative can say *which* graph
        // answered. A tool payload's own marker, if one is later carried, still
        // wins (the `is_none` guard leaves a payload-lifted value untouched).
        if self.graph_as_of.is_none() {
            if let Some(generation) = health.get("graph_generation").and_then(Value::as_u64) {
                self.graph_as_of = Some(json!({ "generation": generation }));
            }
        }
        self
    }

    /// Read only what the daemon's health body says about the WORKING COPY,
    /// leaving every count it carries alone.
    ///
    /// For the one answer that may not take the rest. `kin_graph_status` reports
    /// the exact graph view the daemon selected, so borrowing `/health`'s entity
    /// count or generation would put two authorities for one number in one
    /// response, and the stdio path therefore skipped the health lift outright.
    /// It skipped the reconcile block with it, so a graph-status answer could
    /// never learn that the host holds content the graph has never met, and it
    /// published "0 uncommitted" over exactly that working copy (FIR-2820).
    ///
    /// There is no second authority for these two. Neither describes the
    /// selected graph: one counts host paths outside it and the other is a clock
    /// about admissions. Durability is requalified if it is already set, and
    /// [`Self::with_selected_graph_observation`] requalifies from `behind` when
    /// it runs after this, so either order reaches the same reading.
    pub fn with_working_copy_health(mut self, health: &Value) -> Self {
        self.behind = GraphBehind::from_health(health);
        self.freshness = GraphFreshness::from_health(health);
        if let Some(behind) = self.behind.as_ref() {
            self.durability = self
                .durability
                .take()
                .map(|durability| durability.qualified_by(behind));
        }
        self
    }

    /// Stamp the daemon storage capability without importing HEAD-scoped
    /// graph observations from `/health`.
    ///
    /// Temporal graph status uses this narrow seam because vector persistence
    /// is a property of the serving daemon's backend, while health's entity
    /// count, generation, freshness and reconcile state describe HEAD.
    pub fn with_embed_persistence_unavailable(mut self, unavailable: bool) -> Self {
        self.degraded.embed_persistence_unavailable = Some(unavailable);
        self
    }

    /// Lift `semantic_coverage` and `graph_as_of` out of a tool payload when the
    /// daemon already computed them, so they live in one predictable place on the
    /// envelope. Absent fields stay unknown.
    ///
    /// One name is emitted and two are read. Every current retrieval payload
    /// publishes coverage as the counter object under `semantic_coverage`, on
    /// both `semantic_locate` arms, which is the same name and type this envelope
    /// carries. `semantic_coverage_detail` is read only as a compatibility path
    /// for a payload minted before that settle, when the cosine arm published a
    /// bare `indexed / total` float under the shared name and the counters under
    /// this second one. A stdio shim can be newer than the daemon it forwards to,
    /// so the older shape still lifts rather than reporting coverage unknown next
    /// to a coverage figure the same response had just printed.
    pub fn with_payload_metadata(mut self, payload: &Value) -> Self {
        if self.semantic_coverage.is_none() {
            if let Some(coverage) = ["semantic_coverage", "semantic_coverage_detail"]
                .into_iter()
                .filter_map(|key| payload.get(key))
                .find_map(SemanticCoverage::from_payload_field)
            {
                self.semantic_coverage = Some(coverage);
            }
        }
        if self
            .semantic_coverage
            .as_ref()
            .is_some_and(SemanticCoverage::embedding_work_complete)
        {
            // A backend capability is actionable only while this selected
            // graph still owes embeddings. This is the same precedence as CLI
            // semantic readiness: exact complete coverage is healthy even when
            // no future local vector checkpoint could be written.
            self.degraded.embed_persistence_unavailable = None;
        }
        if self.graph_as_of.is_none() {
            for key in ["graph_as_of", "as_of"] {
                if let Some(marker) = payload.get(key) {
                    if !marker.is_null() {
                        self.graph_as_of = Some(marker.clone());
                        break;
                    }
                }
            }
        }
        self
    }

    /// Whether an "absent" answer from a tool of the given [`NegativeClass`] can
    /// be trusted as a definitive negative, with the machine-stable reason naming
    /// *which gate ruled*.
    ///
    /// This is the epistemic core of the confidence-qualified-negative contract:
    /// a "not found" is only distinguishable from "not indexed" when the answer
    /// came from daemon-owned truth (`RepoDaemon`) with no degraded signals **and**
    /// the substrate the tool actually reads is complete. The two runtime/degraded
    /// gates are shared; the completeness gate is class-specific:
    ///
    /// - [`NegativeClass::Semantic`] tools read embeddings, so absence is
    ///   authoritative only with **complete embedding coverage**.
    /// - [`NegativeClass::Structural`] tools read typed graph relations, so absence
    ///   is authoritative when the daemon **graph is initialized and loaded** —
    ///   embedding coverage is irrelevant to them.
    ///
    /// The reason is honest about which gate held and never claims authority the
    /// envelope did not actually observe.
    /// The reason names only what THIS function checked: the daemon's own
    /// flags, which are the sole degraded set an envelope can see. It
    /// deliberately makes no claim about degraded signals in general, because
    /// [`crate::negative`] publishes a wider set beside it (the payload's own
    /// `degradations[]` and the coverage shortfalls its `edge_coverage` names)
    /// and finishes the sentence there. Claiming the wider silence from here
    /// shipped in v0.5.43 as `trust_reason` ending "with no degraded signals"
    /// one field away from a two-element `degraded_signals` array (FIR-2505).
    pub fn negative_trust(&self, class: NegativeClass) -> (bool, &'static str) {
        if self.runtime != Runtime::RepoDaemon {
            return (
                false,
                "offline_fallback: answered by the in-process graph, a fallback surface — not authoritative graph truth",
            );
        }
        if self.degraded.any() {
            return (
                false,
                "degraded: the daemon reported a degraded signal, so the index may not reflect current truth",
            );
        }
        match class {
            // Every reason this gate refuses is read off the same object the
            // completeness class reads, and each one names the cause it actually
            // observed. Three causes clear `coverage.complete` and they have
            // three different remediations, so a gate that reported all of them
            // as "the semantic index is incomplete" sent a caller to `kin embed`
            // on a store whose embeddings were already whole (FIR-2543).
            NegativeClass::Semantic => match &self.semantic_coverage {
                None => (
                    false,
                    "coverage_unknown: embedding coverage was not reported, so an empty result may mean 'not indexed' rather than 'not present'",
                ),
                Some(coverage) => match coverage.embedding_state() {
                    EmbeddingState::Unknown => (
                        false,
                        "coverage_unknown: no vector index was attached to read coverage from, so an empty result may mean 'not indexed' rather than 'not present'",
                    ),
                    EmbeddingState::Absent => (
                        false,
                        "coverage_absent: no entity in this store carries an embedding, so an empty result means 'nothing was ranked' rather than 'not present'",
                    ),
                    EmbeddingState::Partial => (
                        false,
                        "coverage_partial: the semantic index is incomplete, so an empty result may mean 'not indexed' rather than 'not present'",
                    ),
                    // Embeddings are whole. What is left can only narrow the
                    // POPULATION that was ranked, and an absence over a narrowed
                    // population is not an absence over the repository, so the
                    // gate still refuses and says which narrowing it saw.
                    EmbeddingState::Present => {
                        let scope = coverage.scope_limits();
                        if scope.iter().any(|limit| limit == "graph_body_gap") {
                            (
                                false,
                                "coverage_graph_body_gap: graph-owned source bodies are missing for some paths, so entities in them rank on text fallback and an empty result may mean 'no body to rank' rather than 'not present'",
                            )
                        } else if scope
                            .iter()
                            .any(|limit| limit == "graph_role_filter_withheld")
                        {
                            (
                                false,
                                "coverage_role_filter_withheld: test-role source paths were withheld from ranking, so an empty result may mean 'not ranked' rather than 'not present'; pass include_tests to rank them",
                            )
                        } else {
                            (
                                true,
                                "semantic_authoritative: daemon-owned truth with complete embedding coverage",
                            )
                        }
                    }
                },
            },
            NegativeClass::Structural => {
                if self.graph_state.initialized != Some(true) {
                    (
                        false,
                        "graph_uninitialized: the daemon has not confirmed first reconciliation/snapshot load, so an empty structural result may mean the graph is not yet complete",
                    )
                } else if self.graph_state.loaded != Some(true) {
                    (
                        false,
                        "graph_not_loaded: the daemon reports no graph loaded, so an empty structural result is not authoritative",
                    )
                } else {
                    (
                        true,
                        "structural_authoritative: daemon graph initialized and loaded",
                    )
                }
            }
        }
    }

    /// Serialize the envelope to a JSON value for embedding under [`ENVELOPE_KEY`].
    fn to_value(&self) -> Value {
        serde_json::to_value(self).unwrap_or(Value::Null)
    }
}

/// Annotate a tool result with the envelope under [`ENVELOPE_KEY`].
///
/// - Object payloads keep every existing key in place; `_kin` is added alongside
///   (the back-compat common case). An existing `_kin` is never clobbered.
/// - Non-object JSON payloads (arrays/scalars) are wrapped as
///   `{ "_kin": <envelope>, "result": <payload> }`.
/// - Human-readable text (e.g. error messages that are not JSON) is wrapped as
///   `{ "_kin": <envelope>, "message": <text> }`, preserving the message, plus
///   `negative` when one was synthesized for it, since a resolution miss is
///   reported as text and still has to be calibratable.
///
/// `is_error` and any non-text content blocks are preserved unchanged.
pub fn annotate(result: ToolCallResult, envelope: &Envelope) -> ToolCallResult {
    annotate_inner(result, envelope, None, "", &ResponseBudget::default(), &[])
}

/// Like [`annotate`], but also attaches a confidence-qualified `negative` object
/// alongside `_kin` when one was synthesized for the tool. The negative rides
/// the same content block as the envelope so an agent reads both from one place.
/// A pre-existing `negative` key is never clobbered.
fn annotate_inner(
    result: ToolCallResult,
    envelope: &Envelope,
    negative: Option<&Value>,
    tool_name: &str,
    budget: &ResponseBudget,
    edge_coverage_limits: &[String],
) -> ToolCallResult {
    let envelope_value = envelope.to_value();
    let content = result
        .content
        .into_iter()
        .map(|block| {
            annotate_block(
                block,
                &envelope_value,
                negative,
                tool_name,
                budget,
                edge_coverage_limits,
            )
        })
        .collect();
    ToolCallResult {
        content,
        is_error: result.is_error,
    }
}

/// Extract the first text content block's payload as JSON, when it parses.
fn first_payload_value(result: &ToolCallResult) -> Option<Value> {
    result.content.iter().find_map(|block| {
        let ContentBlock::Text { text } = block;
        serde_json::from_str::<Value>(text).ok()
    })
}

/// The first text content block verbatim. This is what a failed call carries
/// instead of a payload: human-readable text that [`annotate_block`] preserves
/// under `message`.
fn first_message_text(result: &ToolCallResult) -> Option<&str> {
    result.content.first().map(|block| {
        let ContentBlock::Text { text } = block;
        text.as_str()
    })
}

/// The single call sites use to attach the envelope: lift any metadata the tool
/// payload already carries (`semantic_coverage`, `graph_as_of`) into `base`,
/// synthesize a confidence-qualified `negative` for retrieval tools that came
/// back empty, then annotate the result under [`ENVELOPE_KEY`]. Keeping
/// lift + qualify + annotate together in one chokepoint means every dispatch
/// path (offline and daemon) produces a consistently-enriched envelope and an
/// identical negative contract regardless of which runtime answered.
///
/// A retrieval tool has two ways of reporting "nothing", and only one of them
/// carries a payload. When the name a caller passed resolves to no entity the
/// answer is a human message with no collection to count, which used to reach
/// the agent as a bare `{"message": ...}` beside the envelope while every
/// resolved answer from the same tool carried a full negative. That asymmetry
/// is the one an agent cannot see, so the miss is qualified here too.
pub fn finalize(result: ToolCallResult, base: Envelope, tool_name: &str) -> ToolCallResult {
    finalize_bounded(result, base, tool_name, &ResponseBudget::default())
}

/// [`finalize`] under the size contract the CALL asked for.
///
/// This is the last point at which the bytes a client receives are known, so it
/// is where the budget has to hold. The envelope and the `negative` object are
/// part of those bytes and are attached here, which is why the payload cannot
/// bound itself alone: a handler that cut to exactly its ceiling would go back
/// over it the moment this function wrapped the result.
///
/// The budget never touches `_kin` or `negative`. Those are the fields that say
/// how far the answer can be trusted, and an answer that was shortened is
/// exactly when a caller needs them most.
pub fn finalize_bounded(
    result: ToolCallResult,
    base: Envelope,
    tool_name: &str,
    budget: &ResponseBudget,
) -> ToolCallResult {
    let payload = first_payload_value(&result);
    let mut envelope = match &payload {
        Some(payload) => base.with_payload_metadata(payload),
        None => base,
    };
    // Built for every retrieval answer that carried a payload at all, empty or
    // full. A call that failed before producing one has no substrate to report
    // on, and the `negative` synthesized for it below is the signal that case
    // needs.
    if let Some(payload) = &payload {
        envelope.completeness = Completeness::for_tool(tool_name, payload, &envelope);
    }
    let negative = match &payload {
        Some(payload) => crate::negative::negative_for(
            tool_name,
            payload,
            &envelope,
            &crate::verdict::Verdict::pre_negative_gaps(payload),
        ),
        None if result.is_error == Some(true) => first_message_text(&result).and_then(|message| {
            crate::negative::resolution_miss_for(tool_name, message, &envelope)
        }),
        None => None,
    };
    // The one verdict is computed last, because every block it reads has to
    // exist first, and then projected back over the blocks that would otherwise
    // answer the same question differently. Projection only ever downgrades: the
    // completeness signal is itself an input, so a certified verdict is one it
    // already agreed with.
    let mut edge_coverage_limits: Vec<String> = Vec::new();
    if let Some(payload) = &payload {
        if let Some(verdict) =
            crate::verdict::Verdict::compute(tool_name, payload, &envelope, negative.as_ref())
        {
            verdict.project_onto_completeness(&mut envelope.completeness);
            edge_coverage_limits = verdict.edge_coverage_limits();
            envelope.verdict = Some(verdict.to_value());
        }
    }
    annotate_inner(
        result,
        &envelope,
        negative.as_ref(),
        tool_name,
        budget,
        &edge_coverage_limits,
    )
}

/// Write the verdict's qualifiers onto the `edge_coverage` block.
///
/// The block reports what a coverage scan observed. It cannot report whether
/// the answer around it is trustworthy, and a reader holding only the block
/// cannot tell those two apart: "every requested class is present" and "this
/// answer's completeness is unknown" are both true at once, and the block
/// renders only the first. That is how one response came to carry two verdicts,
/// with `edge_coverage` reading as a certification beside a completeness that
/// refused.
///
/// `limits` is the same vocabulary `completeness.limits` already uses in the
/// other direction, so a reader grades both blocks by one rule instead of a
/// special case. An empty list is omitted: a block that licenses on its own
/// says nothing, rather than saying so with an empty array.
///
/// The list is computed by the one verdict and only copied here. Nothing in
/// this function reads another block's state, because two places deriving one
/// answer is how they come to disagree.
fn stamp_edge_coverage_limits(map: &mut serde_json::Map<String, Value>, limits: &[String]) {
    if limits.is_empty() {
        return;
    }
    let Some(coverage) = map
        .get_mut(crate::edge_coverage::EDGE_COVERAGE_KEY)
        .and_then(Value::as_object_mut)
    else {
        return;
    };
    coverage.insert(
        "limits".to_string(),
        Value::Array(limits.iter().map(|l| Value::String(l.clone())).collect()),
    );
}

fn annotate_block(
    block: ContentBlock,
    envelope_value: &Value,
    negative: Option<&Value>,
    tool_name: &str,
    budget: &ResponseBudget,
    edge_coverage_limits: &[String],
) -> ContentBlock {
    let ContentBlock::Text { text } = block;
    let annotated = match serde_json::from_str::<Value>(&text) {
        Ok(Value::Object(mut map)) => {
            stamp_edge_coverage_limits(&mut map, edge_coverage_limits);
            map.entry(ENVELOPE_KEY.to_string())
                .or_insert_with(|| envelope_value.clone());
            if let Some(negative) = negative {
                map.entry(crate::negative::NEGATIVE_KEY.to_string())
                    .or_insert_with(|| negative.clone());
            }
            Value::Object(map)
        }
        Ok(other) => {
            let mut map = Map::new();
            map.insert(ENVELOPE_KEY.to_string(), envelope_value.clone());
            if let Some(negative) = negative {
                map.insert(crate::negative::NEGATIVE_KEY.to_string(), negative.clone());
            }
            map.insert("result".to_string(), other);
            Value::Object(map)
        }
        Err(_) => {
            let mut map = Map::new();
            map.insert(ENVELOPE_KEY.to_string(), envelope_value.clone());
            if let Some(negative) = negative {
                map.insert(crate::negative::NEGATIVE_KEY.to_string(), negative.clone());
            }
            map.insert("message".to_string(), Value::String(text));
            Value::Object(map)
        }
    };
    let mut annotated = annotated;
    apply_response_budget(&mut annotated, tool_name, budget);
    let rendered =
        serde_json::to_string_pretty(&annotated).unwrap_or_else(|_| annotated.to_string());
    ContentBlock::Text { text: rendered }
}

/// Run the contradiction checker against what a client will actually read, and
/// publish what it finds.
///
/// It used to be reached only from a `debug_assert!`, which a release build
/// compiles out, so no shipped envelope was ever checked (FIR-2697). The v0.5.52
/// response that certified an answer over an edge class its own completeness
/// recorded as absent shipped with this checker present and inert, and the lane
/// that found the hole found it because a falsification arm which DELETED the
/// checker came back green under a release build: a removed detector and a
/// silent one are the same run in that profile.
///
/// It discloses rather than panics. A contradiction is a defect in Kin, not in
/// the caller's repository, and killing the response denies the caller both the
/// answer and the warning. `_kin.self_check` names each disagreement in the
/// words the checker uses, so a client, an acceptance run and a bug report all
/// read the same sentence.
///
/// It does NOT feed the verdict. By this point the verdict is computed and the
/// budget has been applied, so a refusing input arriving here would be a second
/// verdict rather than an input to the one. The block says the response
/// disagrees with itself and leaves the verdict as the thing it disagrees with.
///
/// The debug assertion it replaced is GONE rather than kept underneath, and that
/// is deliberate. A panic in debug makes the disclosure untestable, because
/// every test that constructs a contradiction dies before reaching the block it
/// is meant to read, and tests are debug builds. A payload a test can assert on
/// is the stronger guard anyway: `self_check` absent is a positive statement
/// that nothing disagreed, where a panic that did not fire says only that
/// nothing reached it.
///
/// **This does not close the certified-over-nothing hole (FIR-2723).** A checker
/// catches a response that contradicts itself. A verdict that certifies over one
/// input while five are silent contradicts nothing, so no arm here can see it.
fn disclose_self_contradictions(annotated: &mut Value, tool_name: &str) {
    let found = crate::verdict::disagreements(annotated);
    if found.is_empty() {
        if let Some(envelope) = annotated
            .get_mut(ENVELOPE_KEY)
            .and_then(Value::as_object_mut)
        {
            envelope.remove("self_check");
        }
        return;
    }
    tracing::warn!(
        tool = tool_name,
        disagreements = ?found,
        "response contradicts its own verdict"
    );
    let Some(envelope) = annotated
        .get_mut(ENVELOPE_KEY)
        .and_then(Value::as_object_mut)
    else {
        // No envelope to disclose into. `disagreements` reads the verdict out of
        // that same envelope, so it cannot have found anything without one, and
        // this arm is unreachable rather than a silent drop.
        return;
    };
    envelope.insert(
        "self_check".to_string(),
        json!({
            "status": "contradicted",
            "disagreements": found,
            "note": "This response contradicts its own verdict, which is a defect in Kin rather \
                     than a fact about the repository. Trust the most pessimistic reading of the \
                     blocks named here, and report this.",
        }),
    );
}

/// Bound the fully annotated payload and record its exact final size under
/// `_kin.response`.
///
/// The accounting stanza is written BEFORE the cut as well as after it. The
/// number it carries is a property of the object it sits inside, so a stanza
/// added afterwards would push a response that had just been cut to fit back
/// over its ceiling by its own length. The budget downgrade and contradiction
/// check can also grow the envelope after the first cut, so the ladder is rerun
/// to a stable value and the accounting number is solved to a fixed point. A
/// final response is therefore either inside the ceiling or carries the
/// residual-over-budget disclosure, and `chars_after_budget` equals the bytes
/// that actually ship.
fn apply_response_budget(annotated: &mut Value, tool_name: &str, budget: &ResponseBudget) {
    if !crate::budget::is_budgeted(tool_name) {
        disclose_self_contradictions(annotated, tool_name);
        return;
    }
    let chars_before = crate::budget::measure(annotated);
    let mut accounting = crate::budget::BudgetAccounting {
        max_chars: budget.max_chars,
        chars_before,
        // The placeholder carries a number of the same magnitude as the one that
        // replaces it, so the stanza written first is the width of the stanza
        // that ships and the ladder charges the budget for the right bytes.
        chars_after: chars_before,
        bounded: false,
        compact: budget.compact,
    };
    write_response_accounting(annotated, &accounting);
    let mut bounded = false;
    let mut largest_before = chars_before;

    // A pass can add its own disclosure; the epistemic downgrade and self-check
    // can then add more. Re-run until one whole pass leaves the response
    // unchanged. Every removable field or row is finite, and the downgrade is
    // idempotent, so this converges after a handful of passes while preserving
    // the rule that verdict inputs themselves are never trimmed.
    for _ in 0..16 {
        let before = annotated.clone();
        if let Some(applied) = crate::budget::enforce(annotated, tool_name, budget) {
            bounded |= applied.bounded;
            largest_before = largest_before.max(applied.chars_before);
            accounting = applied;
        }
        accounting.bounded = bounded;
        accounting.chars_before = largest_before;

        if bounded {
            if let Some(completeness) = annotated
                .get_mut(ENVELOPE_KEY)
                .and_then(Value::as_object_mut)
                .and_then(|envelope| envelope.get_mut("completeness"))
            {
                Completeness::mark_response_bounded(completeness);
            }
            // The verdict and the absence object are downgraded with it. A
            // budget that removed rows on purpose is the one cut that cannot
            // leave a response certifying what it no longer carries.
            crate::verdict::mark_response_bounded(annotated);
        }
        disclose_self_contradictions(annotated, tool_name);
        settle_response_accounting(annotated, &mut accounting);

        if *annotated == before {
            break;
        }
    }

    // The last accounting rewrite is itself part of the response. Reconcile
    // the residual marker against that exact shape, then settle its size once
    // more because adding or removing the marker changes the measured bytes.
    crate::budget::reconcile_residual(annotated, budget);
    settle_response_accounting(annotated, &mut accounting);
}

/// Write `_kin.response` until its `chars_after_budget` field equals the exact
/// pretty-serialized size of the object that contains it.
fn settle_response_accounting(
    annotated: &mut Value,
    accounting: &mut crate::budget::BudgetAccounting,
) {
    write_response_accounting(annotated, accounting);
    loop {
        let measured = crate::budget::measure(annotated);
        if accounting.chars_after == measured {
            break;
        }
        accounting.chars_after = measured;
        write_response_accounting(annotated, accounting);
    }
}

fn write_response_accounting(annotated: &mut Value, accounting: &crate::budget::BudgetAccounting) {
    if let Some(envelope) = annotated
        .get_mut(ENVELOPE_KEY)
        .and_then(Value::as_object_mut)
    {
        envelope.insert("response".to_string(), accounting.to_value());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope_of(result: &ToolCallResult) -> Value {
        let ContentBlock::Text { text } = result.content.first().expect("one content block");
        let value: Value = serde_json::from_str(text).expect("annotated payload is JSON");
        value
            .get(ENVELOPE_KEY)
            .cloned()
            .expect("annotated payload carries _kin envelope")
    }

    #[test]
    fn offline_envelope_flags_fallback_and_version() {
        let env = Envelope::offline();
        assert_eq!(env.envelope_version, ENVELOPE_VERSION);
        assert_eq!(env.runtime, Runtime::OfflineInProcess);
        assert_eq!(env.degraded.offline_fallback, Some(true));
        // Honesty: nothing observed about coverage/freshness offline.
        assert!(env.semantic_coverage.is_none());
        assert!(env.graph_state.is_empty());
    }

    #[test]
    fn daemon_unreachable_envelope_sets_flag() {
        let env = Envelope::daemon_unreachable();
        assert_eq!(env.runtime, Runtime::RepoDaemon);
        assert_eq!(env.degraded.daemon_unreachable, Some(true));
        assert!(env.degraded.any());
    }

    /// A workspace disagreement is not a reachability failure, and the two must
    /// not be spelled the same way: an agent that reads `daemon_unreachable`
    /// goes and checks a daemon that is answering perfectly well.
    #[test]
    fn workspace_mismatch_envelope_is_not_a_reachability_failure() {
        let env = Envelope::workspace_mismatch();
        assert_eq!(env.runtime, Runtime::RepoDaemon);
        assert_eq!(env.degraded.workspace_mismatch, Some(true));
        assert!(env.degraded.daemon_unreachable.is_none());
        assert!(env.degraded.any());
        assert_eq!(env.degraded.active_labels(), vec!["workspace_mismatch"]);

        // Falsification: the reachability envelope keeps its own flag and never
        // claims a workspace mismatch, so the two verdicts stay distinguishable
        // in both directions.
        let unreachable = Envelope::daemon_unreachable();
        assert!(unreachable.degraded.workspace_mismatch.is_none());
        assert_eq!(
            unreachable.degraded.active_labels(),
            vec!["daemon_unreachable"]
        );
    }

    #[test]
    fn with_health_folds_degraded_and_state_honestly() {
        let health = serde_json::json!({
            "status": "attention",
            "embed_worker_failed": true,
            "embed_persistence_unavailable": true,
            "mass_deletion_blocked": false,
            "reconciliation_status": "clean",
            "graph_entity_count": 1234,
            "graph_loaded": true,
            "initialized": true,
        });
        let env = Envelope::daemon().with_health(&health);
        assert_eq!(env.degraded.embed_worker_failed, Some(true));
        assert_eq!(env.degraded.embed_persistence_unavailable, Some(true));
        assert_eq!(env.degraded.mass_deletion_blocked, Some(false));
        assert_eq!(
            env.graph_state.reconciliation_status.as_deref(),
            Some("clean")
        );
        assert_eq!(env.graph_state.entity_count, Some(1234));
        assert_eq!(env.graph_state.loaded, Some(true));
        assert_eq!(env.graph_state.initialized, Some(true));
        assert!(env.degraded.any());
        assert!(env
            .degraded
            .active_labels()
            .contains(&"embed_persistence_unavailable"));
    }

    #[test]
    fn unavailable_embed_persistence_qualifies_only_outstanding_embedding_work() {
        let observed = |pending, indexed, total, complete| {
            Envelope::daemon()
                .with_health(&serde_json::json!({
                    "embed_persistence_unavailable": true,
                }))
                .with_payload_metadata(&serde_json::json!({
                    "semantic_coverage": {
                        "pending": pending,
                        "indexed": indexed,
                        "total": total,
                        "complete": complete,
                    }
                }))
        };

        let exact = observed(0, 9, 9, false);
        assert!(
            exact.degraded.embed_persistence_unavailable.is_none(),
            "exact embedding completion outranks an unavailable future producer even when scope makes the overall coverage incomplete"
        );

        for (name, env) in [
            ("queue-empty short coverage", observed(0, 8, 9, false)),
            ("live backlog", observed(1, 8, 9, false)),
            ("over-indexed observation", observed(0, 10, 9, false)),
        ] {
            assert_eq!(
                env.degraded.embed_persistence_unavailable,
                Some(true),
                "{name} cannot dismiss the producer blocker"
            );
            assert!(env.degraded.any());
            assert!(env
                .degraded
                .active_labels()
                .contains(&"embed_persistence_unavailable"));
        }
    }

    /// The four states a durability observation can be in, including the two
    /// that must refuse to name a number.
    ///
    /// `durable > live` is the one worth writing down. The live graph has
    /// dropped entities authority still carries, so the difference is not a
    /// count of uncommitted work, and a `recorded` verdict there would be the
    /// false all-clear this object exists to prevent. It is reachable: an
    /// admission that evicts a removed path's entities shrinks the live graph
    /// while authority still holds them.
    #[test]
    fn durability_names_a_count_only_when_the_two_counts_can_be_reconciled() {
        let uncommitted = Durability::observe(14, Some(0));
        assert_eq!(uncommitted.state, "live_uncommitted");
        assert_eq!(uncommitted.live_only_entities, Some(14));
        assert!(
            uncommitted.note.contains("14 entities, 14 uncommitted")
                && uncommitted.note.contains("nothing you wrote"),
            "an empty durable authority means none of it is recorded: {}",
            uncommitted.note
        );

        let partly = Durability::observe(14, Some(9));
        assert_eq!(partly.state, "live_uncommitted");
        assert_eq!(partly.live_only_entities, Some(5));
        assert!(
            partly.note.contains("not all of what you wrote"),
            "a nonempty durable authority records some of it: {}",
            partly.note
        );

        let recorded = Durability::observe(14, Some(14));
        assert_eq!(recorded.state, "recorded");
        assert_eq!(recorded.live_only_entities, Some(0));

        let unmeasured = Durability::observe(14, None);
        assert_eq!(unmeasured.state, "unknown");
        assert_eq!(
            unmeasured.live_only_entities, None,
            "an unlevelled daemon must not report 14 uncommitted entities it cannot see"
        );

        let shrunk = Durability::observe(9, Some(14));
        assert_eq!(
            shrunk.state, "unknown",
            "a live graph below durable authority cannot be read as recorded"
        );
        assert_eq!(shrunk.live_only_entities, None);
    }

    /// The generic tool path takes its envelope from `/health`, so the fold
    /// there is what decides whether a locate carries the disclosure at all.
    #[test]
    fn with_health_derives_durability_from_the_live_and_durable_counts() {
        let env = Envelope::daemon().with_health(&serde_json::json!({
            "graph_entity_count": 22,
            "durable_entity_count": 0,
        }));
        let durability = env
            .durability
            .expect("a measured live count carries durability");
        assert_eq!(durability.state, "live_uncommitted");
        assert_eq!(durability.live_only_entities, Some(22));

        // A daemon that reports no durable reading is unknown, not recorded.
        let unlevelled = Envelope::daemon()
            .with_health(&serde_json::json!({ "graph_entity_count": 22 }))
            .durability
            .expect("a measured live count carries durability");
        assert_eq!(unlevelled.state, "unknown");

        // And a runtime that measured no live count has nothing to compare, so
        // the object stays absent rather than asserting anything.
        assert!(Envelope::daemon()
            .with_health(&serde_json::json!({ "graph_loaded": true }))
            .durability
            .is_none());
    }

    /// FIR-2499. The pair that was wrong together: a store holding an
    /// unadmitted module reported "0 uncommitted; durable repository authority
    /// records everything answering here".
    #[test]
    fn a_store_holding_unadmitted_host_paths_never_reports_an_all_clear() {
        let env = Envelope::daemon().with_health(&serde_json::json!({
            "graph_entity_count": 51,
            "durable_entity_count": 51,
            "reconcile": {
                "untracked_path_count": 1,
                "untracked_paths_sample": ["notekeeper/search.py"],
                "last_admission_success_at": "2026-08-20T13:00:00Z",
            },
        }));

        let behind = env
            .behind
            .as_ref()
            .expect("a reported untracked path is the store being behind");
        assert_eq!(behind.unadmitted_paths, 1);
        assert_eq!(behind.since.as_deref(), Some("2026-08-20T13:00:00Z"));
        assert_eq!(behind.sample, vec!["notekeeper/search.py".to_string()]);

        let durability = env.durability.expect("the counts still answer");
        assert_eq!(
            durability.live_entities,
            Some(51),
            "the counts were never the wrong part and are left exactly as observed"
        );
        assert!(
            !durability
                .note
                .contains("records everything answering here"),
            "the all-clear this reading cannot make: {}",
            durability.note
        );
        assert!(
            durability
                .note
                .contains("host path(s) on disk that no admission has taken"),
            "the note has to name what it does not cover: {}",
            durability.note
        );
        // FIR-2820. The half a caller keys on. Withdrawing the sentence and
        // leaving `recorded` and a zero standing is telling a reader of the
        // prose one thing and a reader of the fields the opposite, and the
        // fields are what an agent branches on.
        assert_eq!(
            durability.state, DURABILITY_UNKNOWN,
            "a store the working copy has outrun cannot report its work recorded"
        );
        assert_eq!(
            durability.live_only_entities, None,
            "how much of an unadmitted file is uncommitted is not derivable from a graph that \
             never parsed it, so the number goes rather than growing"
        );
    }

    /// FIR-2499. The graph-status path sets durability after `with_health` has
    /// already read the reconcile block, so it has to requalify rather than
    /// assign.
    ///
    /// This is the sibling of the case above and it needed its own: a plain
    /// assignment here restores the all-clear the reconcile block exists to
    /// withdraw, and every assertion on the `with_health` path stays green
    /// while it does, because that path is not the one this call rewrites.
    #[test]
    fn a_graph_status_reading_over_a_behind_store_does_not_restore_the_all_clear() {
        let env = Envelope::daemon()
            .with_health(&serde_json::json!({
                "graph_entity_count": 51,
                "durable_entity_count": 51,
                "reconcile": {
                    "untracked_path_count": 2,
                    "untracked_paths_sample": ["notekeeper/search.py"],
                    "last_admission_success_at": "2026-08-20T13:00:00Z",
                },
            }))
            .with_selected_graph_observation(51, 51, 0, 51, Some(51));

        let durability = env.durability.expect("graph status reports the counts");
        assert!(
            !durability
                .note
                .contains("records everything answering here"),
            "the graph-status reading restored an all-clear over a behind store: {}",
            durability.note
        );
        assert!(
            durability
                .note
                .contains("host path(s) on disk that no admission has taken"),
            "the note has to keep naming what it does not cover: {}",
            durability.note
        );
        // FIR-2820, on the second path for the same reason it is asserted on
        // the first: this call requalifies rather than assigns, so a state that
        // moved on one path and not the other is exactly the shape that stays
        // green while shipping the defect.
        assert_eq!(durability.state, DURABILITY_UNKNOWN, "{}", durability.note);
        assert_eq!(durability.live_only_entities, None, "{}", durability.note);
    }

    /// FIR-2820. The one answer that may not take the counts still has to take
    /// the working copy.
    ///
    /// `kin_graph_status` reports the graph view the daemon selected, so
    /// borrowing `/health`'s entity count would put two authorities for one
    /// number in one response, and the stdio path skipped the health lift
    /// outright rather than pick. It skipped the reconcile block with it, and
    /// published "0 uncommitted" over a working copy holding a module the graph
    /// had never met.
    #[test]
    fn the_working_copy_lift_takes_the_reconcile_block_and_none_of_the_counts() {
        let health = serde_json::json!({
            "graph_entity_count": 900,
            "durable_entity_count": 900,
            "graph_generation": 77,
            "reconcile": {
                "untracked_path_count": 1,
                "untracked_paths_sample": ["linkgraph/predicates.py"],
                "last_admission_success_at": "2026-08-27T09:00:00Z",
            },
        });
        let env = Envelope::daemon()
            .with_working_copy_health(&health)
            .with_selected_graph_observation(6, 6, 0, 6, Some(6));

        assert_eq!(
            env.graph_state.entity_count,
            Some(6),
            "the selected graph's own count answers, never the health body's 900"
        );
        let behind = env.behind.as_ref().expect("the working copy was read");
        assert_eq!(behind.unadmitted_paths, 1);
        let durability = env.durability.expect("graph status reports the counts");
        assert_eq!(
            durability.state, DURABILITY_UNKNOWN,
            "the reading has to move, or this lift changed nothing: {}",
            durability.note
        );
        assert_eq!(durability.live_only_entities, None);
        assert!(
            durability
                .note
                .contains("host path(s) on disk that no admission has taken"),
            "{}",
            durability.note
        );

        // The order the stdio path does not use, asserted because either order
        // has to reach the same reading or the fix depends on a call sequence
        // nobody is holding still.
        let reversed = Envelope::daemon()
            .with_selected_graph_observation(6, 6, 0, 6, Some(6))
            .with_working_copy_health(&health)
            .durability
            .expect("graph status reports the counts");
        assert_eq!(reversed.state, DURABILITY_UNKNOWN);
        assert_eq!(reversed.live_only_entities, None);
    }

    /// The control for the lift above: a store with nothing unadmitted keeps the
    /// clean graph-status reading, so this cannot qualify every answer.
    #[test]
    fn the_working_copy_lift_leaves_a_level_store_alone() {
        let env = Envelope::daemon()
            .with_working_copy_health(&serde_json::json!({
                // Stamped, which is what makes the zero an all-clear rather
                // than a default nothing measured.
                "reconcile": {
                    "untracked_path_count": 0,
                    "untracked_observed_age_seconds": 0,
                },
            }))
            .with_selected_graph_observation(6, 6, 0, 6, Some(6));

        assert!(env.behind.is_none(), "nothing unadmitted is nothing to say");
        let durability = env.durability.expect("graph status reports the counts");
        assert_eq!(durability.state, DURABILITY_RECORDED);
        assert_eq!(durability.live_only_entities, Some(0));
    }

    /// FIR-2820, the review's second finding. A zero nobody measured is not a
    /// zero, and the first version of this gated on the count alone.
    ///
    /// Two routes reach an unstamped zero on a daemon that should have measured:
    /// a walk that errored, which is logged and swallowed so the previous
    /// reading stands, and a daemon that has not walked yet. On both,
    /// `kin status` correctly answered "not measured" while durability, behind
    /// and negative on the same daemon at the same instant answered
    /// "0 uncommitted", `recorded` and `authoritative`. That is the ticket's own
    /// two-readers-disagreeing shape, inverted: the field existed and three of
    /// its four readers ignored it.
    #[test]
    fn an_unmeasured_working_copy_is_a_disclosure_rather_than_a_zero() {
        let env = Envelope::daemon().with_health(&serde_json::json!({
            "graph_entity_count": 51,
            "durable_entity_count": 51,
            "reconcile": { "untracked_path_count": 0 },
        }));

        let behind = env
            .behind
            .as_ref()
            .expect("a zero with no measurement behind it is a disclosure");
        assert!(behind.unmeasured());
        assert_eq!(behind.measured_age_seconds, None);
        assert!(
            behind.limiting_factor().contains("working_copy_unmeasured"),
            "an unmeasured reading must not borrow the behind-by-a-count words, which send a \
             reader to `kin admit` for a path that does not exist: {}",
            behind.limiting_factor()
        );

        let durability = env.durability.expect("the counts still answer");
        assert_eq!(
            durability.state, DURABILITY_UNKNOWN,
            "a working copy nobody measured cannot report its work recorded: {}",
            durability.note
        );
        assert_eq!(durability.live_only_entities, None);
        assert!(
            durability.note.contains("nothing has measured this working copy"),
            "{}",
            durability.note
        );
    }

    /// The control that keeps the gate above from firing on every daemon whose
    /// graph is its own write authority.
    ///
    /// Filesystem ingestion off means nothing on disk is ever admitted, so host
    /// content is not a gap the graph failed to close and there is no walk to
    /// miss. Gating on the stamp alone would turn every such daemon into a
    /// permanent disclosure, which is why the daemon names this case rather than
    /// leaving the envelope to infer it.
    #[test]
    fn a_daemon_that_admits_nothing_from_the_filesystem_stays_silent() {
        let env = Envelope::daemon().with_health(&serde_json::json!({
            "graph_entity_count": 51,
            "durable_entity_count": 51,
            "reconcile": {
                "untracked_path_count": 0,
                "untracked_observation_not_applicable": true,
            },
        }));

        assert!(
            env.behind.is_none(),
            "a projected checkout is not evidence about what the graph failed to admit: {:?}",
            env.behind
        );
        let durability = env.durability.expect("the counts still answer");
        assert_eq!(durability.state, DURABILITY_RECORDED);
        assert_eq!(durability.live_only_entities, Some(0));
    }

    /// The note the fields withdrew must not survive in the sentence.
    ///
    /// FIR-2499 withdrew the prose and left the fields; the first version of
    /// this fix withdrew the fields and left the prose, composing its own lead
    /// out of `live_only_entities` one statement before setting it to `None`. A
    /// stranger grepping the payload for "0 uncommitted" over an unadmitted
    /// module still found it.
    #[test]
    fn a_qualified_durability_note_states_no_uncommitted_count() {
        let env = Envelope::daemon().with_health(&serde_json::json!({
            "graph_entity_count": 6,
            "durable_entity_count": 6,
            "reconcile": {
                "untracked_path_count": 1,
                "untracked_paths_sample": ["linkgraph/predicates.py"],
                "untracked_observed_age_seconds": 0,
            },
        }));
        let durability = env.durability.expect("the counts still answer");
        assert!(
            !durability.note.contains("uncommitted"),
            "the field is gone and the sentence has to go with it: {}",
            durability.note
        );
        assert!(
            durability.note.contains("6 entities answered here"),
            "the live count is a fact and stays: {}",
            durability.note
        );
    }

    /// The control for the case above, and the one that keeps this from
    /// qualifying every answer: a store with nothing unadmitted says so exactly
    /// as before.
    #[test]
    fn a_store_with_nothing_unadmitted_keeps_its_recorded_reading() {
        let env = Envelope::daemon().with_health(&serde_json::json!({
            "graph_entity_count": 51,
            "durable_entity_count": 51,
            // Stamped: a measured zero is the all-clear, an unstamped one is the
            // disclosure the test below this asserts.
            "reconcile": {
                "untracked_path_count": 0,
                "untracked_observed_age_seconds": 3,
            },
        }));

        assert!(env.behind.is_none(), "nothing unadmitted is nothing to say");
        let durability = env.durability.expect("the counts still answer");
        assert_eq!(durability.state, "recorded");
        assert!(
            durability
                .note
                .contains("records everything answering here"),
            "{}",
            durability.note
        );
    }

    /// A body carrying no reconcile reading at all says nothing here. Silence
    /// is the absence of a reading, never a zero this envelope did not verify.
    #[test]
    fn a_health_body_with_no_reconcile_reading_makes_no_behind_claim() {
        let env = Envelope::daemon().with_health(&serde_json::json!({
            "graph_entity_count": 51,
            "durable_entity_count": 51,
        }));
        assert!(env.behind.is_none());

        // And a reconcile block that omits the count is the same answer, which
        // is the arm that would otherwise read as zero.
        let partial = Envelope::daemon().with_health(&serde_json::json!({
            "graph_entity_count": 51,
            "reconcile": { "skipped_events": 3 },
        }));
        assert!(partial.behind.is_none());
    }

    #[test]
    fn with_health_missing_fields_stay_unknown() {
        // An empty/partial health body must not fabricate `false`/`0` values.
        let env = Envelope::daemon().with_health(&serde_json::json!({}));
        assert!(env.degraded.embed_worker_failed.is_none());
        assert!(env.degraded.mass_deletion_blocked.is_none());
        assert!(env.graph_state.is_empty());
        assert!(!env.degraded.any());
    }

    #[test]
    fn with_health_lifts_graph_generation_into_graph_as_of() {
        // 621af29 added `graph_generation` to /health; the envelope lifts that
        // monotonic snapshot marker into `graph_as_of` so a negative can name
        // which graph snapshot answered.
        let env = Envelope::daemon().with_health(&serde_json::json!({
            "graph_loaded": true,
            "initialized": true,
            "graph_generation": 7,
        }));
        assert_eq!(
            env.graph_as_of,
            Some(serde_json::json!({ "generation": 7 }))
        );
    }

    #[test]
    fn with_health_without_generation_leaves_graph_as_of_unknown() {
        // Honesty: no marker reported => graph_as_of stays absent, never fabricated.
        let env = Envelope::daemon().with_health(&serde_json::json!({ "graph_loaded": true }));
        assert!(env.graph_as_of.is_none());
    }

    #[test]
    fn with_payload_metadata_lifts_coverage_and_as_of() {
        let payload = serde_json::json!({
            "results": [],
            "semantic_coverage": {
                "indexed": 10, "total": 20, "pending": 5, "complete": false,
                "note": "partial",
            },
            "as_of": "change:abcdef",
        });
        let env = Envelope::daemon().with_payload_metadata(&payload);
        let coverage = env.semantic_coverage.expect("coverage lifted");
        assert_eq!(coverage.indexed, 10);
        assert_eq!(coverage.total, 20);
        assert_eq!(coverage.pending, 5);
        assert!(!coverage.complete);
        assert_eq!(coverage.note.as_deref(), Some("partial"));
        assert_eq!(env.graph_as_of, Some(serde_json::json!("change:abcdef")));
    }

    #[test]
    fn with_payload_metadata_lifts_counters_beside_a_bare_coverage_float() {
        // The compatibility path, for a payload minted before FIR-2415 settled
        // coverage on one name and one type. The cosine `semantic_locate` arm
        // used to publish a bare `indexed / total` float under the shared name,
        // which carries no counts to build an envelope field from, so the lift
        // skipped it and the negative reported coverage unknown next to a
        // coverage figure the same payload printed; the counters rode alongside
        // under a second name. A stdio shim can be newer than the daemon it
        // forwards to, so that older shape must still lift.
        let payload = serde_json::json!({
            "results": [],
            "semantic_coverage": 1.0,
            "semantic_coverage_detail": {
                "indexed": 49, "total": 49, "pending": 0, "complete": true,
            },
        });
        let env = Envelope::daemon().with_payload_metadata(&payload);
        let coverage = env.semantic_coverage.expect("counters lifted");
        assert_eq!(coverage.indexed, 49);
        assert_eq!(coverage.total, 49);
        assert!(coverage.complete);
    }

    #[test]
    fn with_payload_metadata_prefers_the_coverage_object_over_the_detail_key() {
        // Both arms now publish the counters under `semantic_coverage` itself.
        // That is the tool's own field and stays authoritative; the legacy
        // detail key is only consulted when it is not an object.
        let payload = serde_json::json!({
            "semantic_coverage": {
                "indexed": 10, "total": 20, "pending": 10, "complete": false,
            },
            "semantic_coverage_detail": {
                "indexed": 99, "total": 99, "pending": 0, "complete": true,
            },
        });
        let env = Envelope::daemon().with_payload_metadata(&payload);
        let coverage = env.semantic_coverage.expect("coverage lifted");
        assert_eq!(coverage.indexed, 10);
        assert!(!coverage.complete);
    }

    #[test]
    fn with_payload_metadata_ignores_malformed_coverage() {
        // A coverage field that is not the expected object shape is treated as
        // unknown, not partially fabricated.
        let payload = serde_json::json!({ "semantic_coverage": "n/a" });
        let env = Envelope::daemon().with_payload_metadata(&payload);
        assert!(env.semantic_coverage.is_none());
    }

    #[test]
    fn annotate_object_payload_adds_kin_in_place() {
        let result = ToolCallResult::text(
            serde_json::to_string(&serde_json::json!({ "results": [1, 2, 3] })).unwrap(),
        );
        let annotated = annotate(result, &Envelope::offline());
        let ContentBlock::Text { text } = annotated.content.first().unwrap();
        let value: Value = serde_json::from_str(text).unwrap();
        // Original key stays exactly where agents expect it.
        assert_eq!(value["results"], serde_json::json!([1, 2, 3]));
        // Envelope rides alongside.
        assert_eq!(value[ENVELOPE_KEY]["envelope_version"], ENVELOPE_VERSION);
        assert_eq!(value[ENVELOPE_KEY]["runtime"], "offline-in-process");
    }

    #[test]
    fn annotate_does_not_clobber_existing_kin() {
        let result = ToolCallResult::text(
            serde_json::to_string(&serde_json::json!({ "_kin": "preexisting" })).unwrap(),
        );
        let annotated = annotate(result, &Envelope::offline());
        let ContentBlock::Text { text } = annotated.content.first().unwrap();
        let value: Value = serde_json::from_str(text).unwrap();
        assert_eq!(value[ENVELOPE_KEY], serde_json::json!("preexisting"));
    }

    #[test]
    fn annotate_array_payload_wraps_under_result() {
        let result =
            ToolCallResult::text(serde_json::to_string(&serde_json::json!([1, 2])).unwrap());
        let annotated = annotate(result, &Envelope::offline());
        let value = envelope_of(&annotated);
        assert_eq!(value["envelope_version"], ENVELOPE_VERSION);
        let ContentBlock::Text { text } = annotated.content.first().unwrap();
        let whole: Value = serde_json::from_str(text).unwrap();
        assert_eq!(whole["result"], serde_json::json!([1, 2]));
    }

    #[test]
    fn annotate_plain_text_error_wraps_under_message_and_preserves_is_error() {
        let result = ToolCallResult::error("daemon is unreachable");
        assert_eq!(result.is_error, Some(true));
        let annotated = annotate(result, &Envelope::daemon_unreachable());
        // Error flag survives annotation.
        assert_eq!(annotated.is_error, Some(true));
        let ContentBlock::Text { text } = annotated.content.first().unwrap();
        let whole: Value = serde_json::from_str(text).unwrap();
        assert_eq!(whole["message"], serde_json::json!("daemon is unreachable"));
        assert_eq!(whole[ENVELOPE_KEY]["degraded"]["daemon_unreachable"], true);
        // Human substring is still findable inside the wrapped JSON.
        assert!(text.contains("daemon is unreachable"));
    }

    /// A daemon envelope over a graph that reports itself ready, which is the
    /// state every one of these fixtures answers from.
    fn ready_daemon_envelope() -> Envelope {
        Envelope::daemon().with_health(&json!({
            "initialized": true,
            "graph_loaded": true,
            "reconciliation_status": "clean",
        }))
    }

    fn completeness_of(result: &ToolCallResult) -> Value {
        envelope_of(result)
            .get("completeness")
            .cloned()
            .expect("every retrieval response carries a completeness signal")
    }

    fn annotated_value(result: &ToolCallResult) -> Value {
        let ContentBlock::Text { text } = result.content.first().expect("one content block");
        serde_json::from_str(text).expect("annotated payload is JSON")
    }

    /// One reference answer, parameterised by what the graph could see.
    fn reference_payload(returned: u64, calls_state: &str) -> ToolCallResult {
        ToolCallResult::text(
            json!({
                "total_upstream": returned,
                "counts": {
                    "counted": "referencing_entities",
                    "referencing_entities": returned,
                    "reference_sites": returned,
                    "known_reference_sites": returned,
                    "reference_sites_complete": true,
                },
                "references": vec![json!({"name": "extract_links"}); returned as usize],
                "relation_kinds": ["calls", "imports", "references"],
                // Complete on purpose. Since FIR-2463 a populated answer carries
                // the response verdict too, and a fixture that reports no
                // cross-repo authority is not the fully-resolved answer these
                // cases are about: it would read as a floor for a reason the
                // test never meant to exercise.
                "focal_entity": { "id": "0195f2a1-0000-7000-8000-00000000f0ca" },
                "cross_repo": {
                    "status": "available",
                    "authority_complete": true,
                    "authority_revision": "sha256:complete",
                    "authority_roots": { "local": "local-root" },
                    "authority_anchor": {
                        "repo_id": "local",
                        "entity_id": "0195f2a1-0000-7000-8000-00000000f0ca",
                    },
                },
                // Every class but the one the case varies is present, and the
                // host can produce reference edges. Since FIR-2672 every
                // requested class decides, so a "fully resolved" fixture has
                // to be one.
                "edge_coverage": {
                    "scope": "language",
                    "language": "Python",
                    "classes": {
                        "calls": calls_state,
                        "imports": "present",
                        "references": "present",
                    },
                    "reference_enrichment": "available",
                    "budget_exhausted": false,
                },
                // Unambiguous on purpose, and present on purpose. The handler
                // publishes this block on every answer, and since FIR-2475 the
                // verdict reads it: an answer that does not say how its focal
                // was resolved cannot be certified, because it may describe a
                // same-named sibling. A fixture omitting it is not a smaller
                // response, it is one the handler cannot produce.
                "focal_resolution": {
                    "addressed_by": "entity_id",
                    "same_name_candidates": 1,
                    "matched": "exact_focal_name",
                    "other_candidates": [],
                },
            })
            .to_string(),
        )
    }

    /// The FIR-2672 shape at the envelope layer: the populated answer the
    /// rc0552s stranger received on 0.5.52, `calls` and `references` present,
    /// `imports` short, with a language server available and nothing else
    /// wrong. Every field a reader acts on must follow the one verdict, and the
    /// `disagreements` scanner is the invariant that says they do.
    fn stranger_reference_payload(imports: &str) -> ToolCallResult {
        ToolCallResult::text(
            json!({
                "total_upstream": 5,
                "counts": {
                    "counted": "referencing_entities",
                    "referencing_entities": 5,
                    "reference_sites": 5,
                    "known_reference_sites": 5,
                    "reference_sites_complete": true,
                    "receiver_name_candidates": 0,
                },
                "references": vec![json!({"name": "extract_tags"}); 5],
                "relation_kinds": ["calls", "imports", "references"],
                "degradations": [],
                "focal_entity": { "id": "0195f2a1-0000-7000-8000-00000000f0ca" },
                "cross_repo": {
                    "status": "available",
                    "authority_complete": true,
                    "authority_revision": "sha256:complete",
                    "authority_roots": { "local": "local-root" },
                    "authority_anchor": {
                        "repo_id": "local",
                        "entity_id": "0195f2a1-0000-7000-8000-00000000f0ca",
                    },
                },
                "edge_coverage": {
                    "scope": "language",
                    "language": "Python",
                    "requested_classes": ["calls", "imports", "references"],
                    "classes": {
                        "calls": "present",
                        "imports": imports,
                        "references": "present",
                    },
                    "reference_enrichment": "available",
                    "budget_exhausted": false,
                },
                "focal_resolution": {
                    "addressed_by": "entity_id",
                    "same_name_candidates": 1,
                    "matched": "exact_focal_name",
                    "other_candidates": [],
                },
            })
            .to_string(),
        )
    }

    /// FIR-2672. A populated answer over a requested class it could not read
    /// does not certify, every acted-on field follows, the class is named in
    /// `limits` and in the limiting factor, and the response carries no
    /// disagreement. With the one class present the same answer certifies.
    #[test]
    fn a_populated_answer_over_an_unread_class_does_not_certify_and_stays_consistent() {
        for (state, label) in [
            ("absent", "edge_coverage:imports_absent"),
            ("unproduced", "edge_coverage:imports_unproduced"),
        ] {
            let annotated = finalize(
                stranger_reference_payload(state),
                ready_daemon_envelope(),
                "find_references",
            );
            let value = annotated_value(&annotated);
            let verdict = &value[ENVELOPE_KEY]["verdict"];
            let completeness = &value[ENVELOPE_KEY]["completeness"];
            assert_eq!(verdict["state"], "inconclusive", "{state}: {value}");
            assert!(
                verdict["limiting_factor"]
                    .as_str()
                    .is_some_and(|factor| factor.contains("imports")),
                "{state}: the factor names the class: {verdict}"
            );
            assert_eq!(
                verdict["inputs"]["edge_coverage"], "inconclusive",
                "{state}"
            );
            assert_eq!(completeness["status"], "partial", "{state}: {completeness}");
            assert_eq!(completeness["bound"], "at_least", "{state}: {completeness}");
            assert_eq!(
                completeness["counted"]["exact"], false,
                "{state}: {completeness}"
            );
            assert_eq!(completeness["classes"]["imports"], state, "{completeness}");
            assert!(
                completeness["limits"]
                    .as_array()
                    .is_some_and(|limits| limits.iter().any(|limit| limit == label)),
                "{state}: limits name the class: {completeness}"
            );
            assert!(
                completeness["decided_by"]
                    .as_array()
                    .is_some_and(|decided| decided.iter().any(|class| class == "imports")),
                "{state}: the class that refused is on the record of what decided: \
                 {completeness}"
            );
            let found = crate::verdict::disagreements(&value);
            assert!(found.is_empty(), "{state}: {found:?}");
        }

        let annotated = finalize(
            stranger_reference_payload("present"),
            ready_daemon_envelope(),
            "find_references",
        );
        let value = annotated_value(&annotated);
        assert_eq!(
            value[ENVELOPE_KEY]["verdict"]["state"], "certified",
            "{value}"
        );
        assert_eq!(value[ENVELOPE_KEY]["completeness"]["status"], "complete");
        assert_eq!(value[ENVELOPE_KEY]["completeness"]["bound"], "exact");
        assert!(crate::verdict::disagreements(&value).is_empty());
    }

    /// The FIR-2357 headline at the envelope layer. A NON-empty answer over a
    /// graph holding no cross-file call edges is 20% complete and used to ship
    /// with nothing at all saying so: no negative, no trust field, no caveat.
    /// The signal has to be there, and it has to say the count is a floor.
    #[test]
    fn a_partial_non_empty_answer_carries_a_completeness_signal() {
        let annotated = finalize(
            reference_payload(1, "absent"),
            ready_daemon_envelope(),
            "find_references",
        );
        let completeness = completeness_of(&annotated);

        assert_eq!(
            completeness["status"], "partial",
            "a graph holding no cross-file calls cannot have found the other callers: \
             {completeness}"
        );
        assert_eq!(
            completeness["bound"], "at_least",
            "and the count it did return is a floor, not a fact: {completeness}"
        );
        assert_eq!(completeness["substrate"], "edges");
        assert_eq!(completeness["counted"]["reported"], 1);
        assert_eq!(completeness["counted"]["unit"], "referencing_entities");
        assert!(
            completeness["limits"]
                .as_array()
                .unwrap()
                .contains(&json!("edge_coverage:calls_absent")),
            "the limiting class is named rather than left to be inferred: {completeness}"
        );

        // The payload is not empty, and since FIR-2463 it still carries the
        // response's verdict. What it must never carry is an absence claim, so
        // the qualifier is present and says so.
        let negative = &annotated_value(&annotated)[crate::negative::NEGATIVE_KEY];
        assert_eq!(
            negative["safe_to_conclude_absent"],
            json!(false),
            "a populated answer claims no absence: {negative}"
        );
        assert_eq!(negative["interpretation"], json!("qualified_answer"));
    }

    /// The regression FIR-2357 item 4 bars, held in the opposite direction. A
    /// graph that demonstrably links calls across files answers completely, and
    /// a fix that marked everything uncertain would fail here while passing the
    /// test above.
    #[test]
    fn a_fully_resolved_answer_reports_complete_and_exact() {
        let annotated = finalize(
            reference_payload(5, "present"),
            ready_daemon_envelope(),
            "find_references",
        );
        let completeness = completeness_of(&annotated);

        assert_eq!(completeness["status"], "complete", "{completeness}");
        assert_eq!(completeness["bound"], "exact", "{completeness}");
        assert_eq!(completeness["counted"]["reported"], 5);
        assert_eq!(completeness["counted"]["exact"], true);
        // Every requested class decides and every one is present (FIR-2672).
        // This used to pin `imports: absent` beside `decided_by: ["calls"]`,
        // the shipped 0.5.52 shape, as the fully resolved case.
        assert_eq!(completeness["classes"]["imports"], "present");
        assert_eq!(
            completeness["decided_by"],
            json!(["calls", "imports", "references"])
        );
        assert!(
            completeness["limits"].is_null() || completeness["limits"] == json!([]),
            "nothing was short, so nothing is named as a limit: {completeness}"
        );
    }

    /// FIR-2505 and FIR-2492, on the block that carried the sentence. Shipped
    /// v0.5.43 answered `status: "complete"`, `bound: "exact"`, `decided_by:
    /// ["calls"]` and "so the counts here are the whole set" on expressjs/express,
    /// over a graph holding no cross-file reference edge at all, while listing
    /// that very absence one field away under `limits`.
    ///
    /// A verdict and a completeness block disagreeing inside one object is the
    /// defect FIR-2463 named, so the deciding set is shared and this flips with
    /// the gate rather than beside it.
    #[test]
    fn a_producible_reference_class_that_produced_nothing_makes_the_counts_a_floor() {
        let payload = ToolCallResult::text(
            json!({
                "total_upstream": 0,
                "references": [],
                "relation_kinds": ["calls", "imports", "references"],
                "edge_coverage": {
                    "scope": "language",
                    "language": "JavaScript",
                    "classes": {
                        "calls": "present",
                        "imports": "absent",
                        "references": "absent",
                    },
                    "reference_enrichment": "available",
                    "budget_exhausted": false,
                },
                "focal_resolution": {
                    "addressed_by": "entity_id",
                    "same_name_candidates": 1,
                    "matched": "exact_focal_name",
                    "other_candidates": [],
                },
            })
            .to_string(),
        );
        let annotated = finalize(payload, ready_daemon_envelope(), "find_references");
        let completeness = completeness_of(&annotated);

        assert_eq!(
            completeness["decided_by"],
            json!(["calls", "imports", "references"]),
            "every requested class is one the verdict rests on: {completeness}"
        );
        assert_eq!(completeness["status"], "partial", "{completeness}");
        assert_eq!(completeness["bound"], "at_least", "{completeness}");
        let note = completeness["note"].as_str().unwrap();
        assert!(
            !note.contains("the whole set"),
            "a graph missing the class the question needed does not hold the whole set: {note}"
        );
        assert!(
            note.contains("lower bound"),
            "the note says what the counts actually are: {note}"
        );
    }

    /// Unobserved is not healthy. A payload carrying no observation leaves every
    /// class unknown and the answer a floor, so a tool cannot earn a complete
    /// verdict by declining to measure.
    #[test]
    fn an_unobserved_answer_is_unknown_rather_than_complete() {
        let payload = ToolCallResult::text(
            json!({
                "total_upstream": 3,
                "references": [{"name": "a"}, {"name": "b"}, {"name": "c"}],
                "relation_kinds": ["calls"],
            })
            .to_string(),
        );
        let completeness = completeness_of(&finalize(
            payload,
            ready_daemon_envelope(),
            "find_references",
        ));

        assert_eq!(completeness["status"], "unknown", "{completeness}");
        assert_eq!(completeness["bound"], "at_least", "{completeness}");
        assert_eq!(completeness["classes"]["calls"], "unknown");
        assert!(completeness["limits"]
            .as_array()
            .unwrap()
            .contains(&json!("edge_coverage:unreported")));
    }

    /// The budget removes rows on purpose, and a response it shortened is
    /// partial by exactly the definition this object uses. The cut happens after
    /// the verdict is built, so the downgrade has to be applied to the
    /// serialized signal or the one path that removes answers deliberately would
    /// be the one path that reports them as whole.
    #[test]
    fn a_budget_shortened_answer_reports_a_floor() {
        let rows: Vec<Value> = (0..400)
            .map(|index| {
                json!({
                    "name": format!("caller_{index}"),
                    "body": "x".repeat(200),
                })
            })
            .collect();
        let payload = ToolCallResult::text(
            json!({
                "total_upstream": rows.len(),
                "counts": {
                    "counted": "referencing_entities",
                    "reference_sites_complete": true,
                },
                "references": rows,
                "relation_kinds": ["calls"],
                "edge_coverage": {
                    "language": "Python",
                    "classes": { "calls": "present" },
                    "reference_enrichment": "unknown",
                    "budget_exhausted": false,
                },
            })
            .to_string(),
        );
        let budget = ResponseBudget {
            max_chars: 4_000,
            ..ResponseBudget::default()
        };
        let annotated =
            finalize_bounded(payload, ready_daemon_envelope(), "find_references", &budget);
        let envelope = envelope_of(&annotated);
        assert_eq!(
            envelope["response"]["bounded"], true,
            "the fixture has to actually trip the budget: {}",
            envelope["response"]
        );

        let completeness = &envelope["completeness"];
        assert_eq!(
            completeness["bound"], "at_least",
            "a response the budget cut is a floor however healthy its graph was: {completeness}"
        );
        assert_eq!(completeness["counted"]["exact"], false);
        assert!(completeness["limits"]
            .as_array()
            .unwrap()
            .contains(&json!("response_bounded")));

        let ContentBlock::Text { text } = annotated.content.first().unwrap();
        let final_payload: Value = serde_json::from_str(text).unwrap();
        let final_chars = crate::budget::measure(&final_payload);
        assert_eq!(
            envelope["response"]["chars_after_budget"],
            json!(final_chars),
            "accounting is measured after the downgrade and every disclosure: {final_payload}"
        );
        let residual = final_payload
            .get("degradations")
            .and_then(Value::as_array)
            .is_some_and(|entries| {
                entries.iter().any(|entry| {
                    entry.get("reason").and_then(Value::as_str)
                        == Some(crate::budget::OVER_BUDGET_REASON)
                })
            });
        assert!(
            final_chars <= budget.max_chars || residual,
            "a response over the caller ceiling must disclose the residual: {final_payload}"
        );
        assert_eq!(
            final_payload[ENVELOPE_KEY]["verdict"]["limiting_factor"]
                .as_str()
                .unwrap()
                .matches("response_bounded:")
                .count(),
            1,
            "reconciliation must not repeat the verdict factor"
        );
        assert_eq!(
            final_payload[crate::negative::NEGATIVE_KEY]["trust_reason"]
                .as_str()
                .unwrap()
                .matches("response_bounded:")
                .count(),
            1,
            "reconciliation must not repeat the negative reason"
        );
    }

    /// One shape, but not one substrate. A ranked answer depends on embeddings
    /// and never traverses an edge, so its classes name embeddings and an
    /// incomplete index makes it partial.
    #[test]
    fn a_ranked_answer_reports_the_embedding_substrate() {
        let payload = ToolCallResult::text(
            json!({
                "results": [{"name": "normalize_title"}],
                "semantic_coverage": {
                    "indexed": 40,
                    "total": 100,
                    "pending": 60,
                    "complete": false,
                },
            })
            .to_string(),
        );
        let completeness = completeness_of(&finalize(
            payload,
            ready_daemon_envelope(),
            "semantic_locate",
        ));

        assert_eq!(completeness["substrate"], "embeddings");
        assert_eq!(completeness["classes"]["embeddings"], "absent");
        assert_eq!(completeness["status"], "partial", "{completeness}");
        assert_eq!(completeness["bound"], "at_least");
    }

    /// Build one `semantic_locate` response over a store with the given
    /// coverage, exactly as the serving path assembles it.
    fn locate_response_with_coverage(coverage: Value) -> Value {
        let payload = ToolCallResult::text(
            json!({
                "results": [{"name": "normalize_title"}],
                "semantic_coverage": coverage,
            })
            .to_string(),
        );
        envelope_of(&finalize(
            payload,
            ready_daemon_envelope(),
            "semantic_locate",
        ))
    }

    /// The counters and the class verdict in one envelope are one fact, so a
    /// reader acting on either reaches the same decision.
    ///
    /// FIR-2543 is the case this drives with. A shipped v0.5.45 `semantic_locate`
    /// envelope carried `semantic_coverage: {indexed: 2112, total: 2112,
    /// pending: 0}` and `completeness.classes.embeddings: "absent"` in one
    /// response, because fifteen test-role paths withheld from ranking had
    /// cleared `complete` and the class was derived from that flag. An agent
    /// reading the counters proceeded and an agent reading the class backed off,
    /// both from the same object.
    ///
    /// Every case below carries real counters. There is no empty-input arm,
    /// because a store with no eligible entity makes the agreement trivially
    /// true and could not fail if the rule were removed.
    #[test]
    fn the_coverage_counters_and_the_embedding_class_never_disagree() {
        // (case name, coverage payload, expected class, expected limit label)
        let cases: Vec<(&str, Value, &str, Option<&str>)> = vec![
            (
                "n_of_n_with_a_role_filter_withholding_paths",
                json!({
                    "indexed": 2112, "total": 2112, "pending": 0,
                    "complete": false,
                    "embedding_state": "present",
                    "limited_by": ["graph_role_filter"],
                    "graph_bodies": {
                        "source_paths": 275, "with_body": 275, "gap_paths": 0,
                        "withheld_test_paths": 15,
                    },
                }),
                "present",
                None,
            ),
            (
                "n_of_n_with_nothing_pending",
                json!({
                    "indexed": 2112, "total": 2112, "pending": 0,
                    "complete": true,
                    "embedding_state": "present",
                }),
                "present",
                None,
            ),
            (
                "zero_of_n_against_an_attached_index",
                json!({
                    "indexed": 0, "total": 2112, "pending": 2112,
                    "complete": false,
                    "embedding_state": "absent",
                    "limited_by": ["embeddings_incomplete"],
                }),
                "absent",
                Some("embeddings_absent"),
            ),
            (
                "some_indexed_with_work_still_pending",
                json!({
                    "indexed": 1536, "total": 2112, "pending": 576,
                    "complete": false,
                    "embedding_state": "partial",
                    "limited_by": ["embeddings_incomplete"],
                }),
                "absent",
                Some("embeddings_partial"),
            ),
            (
                "counters_taken_with_no_index_attached_to_read_them",
                json!({
                    "indexed": 0, "total": 2112, "pending": 2112,
                    "complete": false,
                    "embedding_state": "unknown",
                    "limited_by": ["vector_index_absent"],
                }),
                "unknown",
                Some("embeddings_unknown"),
            ),
        ];

        for (case, coverage, expected_class, expected_limit) in cases {
            let envelope = locate_response_with_coverage(coverage);
            let completeness = &envelope["completeness"];
            let counters = &envelope["semantic_coverage"];
            assert_eq!(
                completeness["classes"]["embeddings"],
                json!(expected_class),
                "case {case}: the class must follow the counters beside it: {envelope}"
            );
            // The counters have to survive intact, because the whole defect was
            // two readings of one store in one object.
            assert_eq!(
                counters["indexed"], envelope["semantic_coverage"]["indexed"],
                "case {case}: counters are republished verbatim"
            );
            let limits = completeness["limits"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            match expected_limit {
                Some(label) => assert!(
                    limits.contains(&json!(label)),
                    "case {case}: the finer reading must be named in limits: {completeness}"
                ),
                None => assert!(
                    !limits.iter().any(|limit| limit
                        .as_str()
                        .is_some_and(|limit| limit.starts_with("embeddings_"))),
                    "case {case}: a whole index names no embedding shortfall: {completeness}"
                ),
            }
        }
    }

    /// The FIR-2543 envelope, asserted as the one thing a reader cannot be asked
    /// to reconcile: `pending: 0` over a full index beside a class saying the
    /// embeddings are gone.
    ///
    /// The role filter is still disclosed, because it narrowed the population
    /// that was ranked. It is disclosed as what it is.
    #[test]
    fn a_role_filter_is_disclosed_without_being_reported_as_a_missing_index() {
        let envelope = locate_response_with_coverage(json!({
            "indexed": 2112, "total": 2112, "pending": 0,
            "complete": false,
            "embedding_state": "present",
            "limited_by": ["graph_role_filter"],
            "graph_bodies": {
                "source_paths": 275, "with_body": 275, "gap_paths": 0,
                "withheld_test_paths": 15,
            },
        }));
        let completeness = &envelope["completeness"];
        assert_eq!(
            completeness["classes"]["embeddings"],
            json!("present"),
            "2112 of 2112 indexed with nothing pending is a present index: {completeness}"
        );
        let limits = completeness["limits"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert!(
            limits.contains(&json!("graph_role_filter_withheld")),
            "the narrowed population is still disclosed: {completeness}"
        );
        assert!(
            !limits.contains(&json!("embeddings_absent")),
            "a whole index is never an absent one: {completeness}"
        );
    }

    /// A producer one version behind carries the body-coverage object and no
    /// reason list, and its role filter still must not be read as an embedding
    /// shortfall.
    #[test]
    fn a_role_filter_declared_only_by_the_body_coverage_object_is_still_read() {
        let envelope = locate_response_with_coverage(json!({
            "indexed": 800, "total": 800, "pending": 0,
            "complete": false,
            "embedding_state": "present",
            "graph_bodies": {
                "source_paths": 40, "with_body": 40, "gap_paths": 0,
                "withheld_test_paths": 6,
            },
        }));
        let limits = envelope["completeness"]["limits"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert!(
            limits.contains(&json!("graph_role_filter_withheld")),
            "the filter is disclosed from the only field that carried it: {}",
            envelope["completeness"]
        );
    }

    /// A payload minted before the verdict existed gets the honest reading of
    /// its own counters, and `indexed: 0` is not one of the readings the
    /// counters can decide.
    ///
    /// `embedding_status` reports zero indexed for every retrievable object when
    /// no vector index is attached, so a bare `0 of 2112` is a fully embedded
    /// store whose index did not load and a store nobody embedded, at once.
    #[test]
    fn a_legacy_payload_reporting_zero_indexed_is_unknown_rather_than_absent() {
        let envelope = locate_response_with_coverage(json!({
            "indexed": 0, "total": 2112, "pending": 2112,
            "complete": false,
        }));
        let completeness = &envelope["completeness"];
        assert_eq!(
            completeness["classes"]["embeddings"],
            json!("unknown"),
            "a count nobody could read is unknown, never zero: {completeness}"
        );
        assert_eq!(
            completeness["status"],
            json!("unknown"),
            "and the status it decides follows it: {completeness}"
        );

        // The control that makes the arm above capable of failing: the same
        // legacy shape with counters that DO decide reads partial, not unknown.
        let decidable = locate_response_with_coverage(json!({
            "indexed": 1536, "total": 2112, "pending": 576,
            "complete": false,
        }));
        assert_eq!(
            decidable["completeness"]["classes"]["embeddings"],
            json!("absent"),
            "counters that decide are still read: {}",
            decidable["completeness"]
        );
    }

    /// A wire word this build does not know is not a healthy one. A future
    /// producer must not be able to certify an answer by naming a state nobody
    /// here has agreed is certifiable.
    #[test]
    fn an_unrecognized_embedding_state_reads_as_unknown() {
        let envelope = locate_response_with_coverage(json!({
            "indexed": 2112, "total": 2112, "pending": 0,
            "complete": true,
            "embedding_state": "mostly_fine",
        }));
        assert_eq!(
            envelope["completeness"]["classes"]["embeddings"],
            json!("unknown"),
            "{}",
            envelope["completeness"]
        );
    }

    /// A mutation is not retrieval and carries no completeness object, so the
    /// signal means something where it appears rather than becoming a field
    /// every response has to carry an answer for.
    #[test]
    fn a_non_retrieval_tool_carries_no_completeness_signal() {
        let annotated = finalize(
            ToolCallResult::text(json!({"committed": true}).to_string()),
            ready_daemon_envelope(),
            "kin_transaction_commit",
        );
        assert!(
            envelope_of(&annotated).get("completeness").is_none(),
            "{}",
            envelope_of(&annotated)
        );
    }

    #[test]
    fn envelope_omits_unknown_fields_when_serialized() {
        // The offline envelope should not serialize null coverage / empty state.
        let value = Envelope::offline().to_value();
        let obj = value.as_object().unwrap();
        assert!(!obj.contains_key("semantic_coverage"));
        assert!(!obj.contains_key("graph_as_of"));
        assert!(!obj.contains_key("graph_state"));
        // degraded is always present.
        assert!(obj.contains_key("degraded"));
    }

    fn kill_record(memory_kills: u64) -> kin_daemon_spawn::DaemonKillRecord {
        kin_daemon_spawn::DaemonKillRecord {
            kills: 4,
            memory_kills,
            first_unix: 4_320,
            last_unix: 4_800,
            last_pid: Some(41),
            last_cause: if memory_kills > 0 {
                kin_daemon_spawn::DaemonKillCause::MemoryLimit {
                    kernel_oom_kills: 1,
                }
            } else {
                kin_daemon_spawn::DaemonKillCause::Unattributed { signal: 9 }
            },
            limit_bytes: Some(12 * 1024 * 1024 * 1024),
            last_rss_bytes: None,
        }
    }

    /// The flag is what separates a gap something is working on from a gap
    /// nothing is, and an agent certifying an absence reads the flag rather
    /// than the prose. A closed circuit must claim nothing at all, because a
    /// fabricated `false` says this store was checked and found sweeping on a
    /// call that never looked.
    /// A store whose last enrichment sweep fell short is flagged, and a store
    /// whose sweep came out clean makes no claim at all.
    ///
    /// The absent case is the half that matters. `None` says this envelope did
    /// not look; a fabricated `false` would say it looked and found the graph
    /// whole, which is a claim no call that never read the record can make.
    #[test]
    fn an_enrichment_shortfall_is_flagged_and_labelled_and_absent_when_clean() {
        let clean = Envelope::daemon().with_enrichment_shortfall(None);
        assert_eq!(
            clean.degraded.enrichment_shortfall, None,
            "a sweep that lost nothing must leave this absent, never false"
        );
        assert!(!clean
            .degraded
            .active_labels()
            .contains(&"enrichment_shortfall"));
        assert!(!clean.degraded.any());

        let record = kin_daemon_spawn::RefusedEnrichment {
            lost: 12,
            offered: 600,
            vector_stale: 0,
            at_unix: 0,
        };
        let short = Envelope::daemon().with_enrichment_shortfall(Some(&record));
        assert_eq!(short.degraded.enrichment_shortfall, Some(true));
        assert!(
            short
                .degraded
                .active_labels()
                .contains(&"enrichment_shortfall"),
            "a flag that is set and not listed is a degradation nothing can observe: {:?}",
            short.degraded.active_labels()
        );
        assert!(
            short.degraded.any(),
            "any() enumerates its fields by hand, so a new flag missing from it reports healthy"
        );
    }

    #[test]
    fn a_suspended_sweep_is_stamped_and_a_running_one_claims_nothing() {
        let running = Envelope::daemon().with_suspended_sweep(None);
        assert_eq!(running.degraded.sweep_suspended, None);
        assert!(!running.degraded.any());
        assert!(!running
            .degraded
            .active_labels()
            .contains(&"sweep_suspended"));

        let suspended = Envelope::daemon()
            .with_suspended_sweep(Some(&kin_daemon_spawn::SuspendedSweep { interruptions: 3 }));
        assert_eq!(suspended.degraded.sweep_suspended, Some(true));
        assert!(suspended.degraded.any());
        assert!(suspended
            .degraded
            .active_labels()
            .contains(&"sweep_suspended"));
    }

    /// An agent certifying an absence has to be able to tell a gap nothing is
    /// working on from a gap a running pass is about to fill, and work Kin
    /// declined for want of memory is the first kind.
    #[test]
    fn held_back_work_is_stamped_and_a_machine_with_room_claims_nothing() {
        let clear = Envelope::daemon().with_memory_pressure(None);
        assert_eq!(clear.degraded.memory_pressure, None);
        assert!(!clear.degraded.any());
        assert!(!clear.degraded.active_labels().contains(&"memory_pressure"));
        let json = serde_json::to_string(&clear.degraded).expect("serialize degraded");
        assert!(
            !json.contains("memory_pressure"),
            "an unobserved flag is absent, never false: {json}"
        );

        let refusal = kin_core::memory_pressure::PressureRefusal {
            work: "lsp-sweep".to_string(),
            level: "critical".to_string(),
            reason: "host memory pressure is critical".to_string(),
            at_unix: 4_800,
        };
        let held = Envelope::daemon().with_memory_pressure(Some(&refusal));
        assert_eq!(held.degraded.memory_pressure, Some(true));
        assert!(held.degraded.any());
        assert!(held.degraded.active_labels().contains(&"memory_pressure"));
        let json = serde_json::to_string(&held.degraded).expect("serialize degraded");
        assert!(
            json.contains("\"memory_pressure\":true"),
            "a refusal an agent has to reason about is structural: {json}"
        );
    }

    /// Absent rather than `false` on the wire, for the reason every flag in
    /// this struct is absent when unobserved: a client cannot tell a
    /// serialized `false` from an answer that looked and found nothing wrong.
    #[test]
    fn a_running_sweep_puts_no_key_on_the_wire() {
        let running = Envelope::daemon().with_suspended_sweep(None);
        let json = serde_json::to_string(&running.degraded).expect("serialize degraded");
        assert!(
            !json.contains("sweep_suspended"),
            "an unobserved flag is absent, never false: {json}"
        );
        let suspended = Envelope::daemon()
            .with_suspended_sweep(Some(&kin_daemon_spawn::SuspendedSweep { interruptions: 4 }));
        let json = serde_json::to_string(&suspended.degraded).expect("serialize degraded");
        assert!(
            json.contains("\"sweep_suspended\":true"),
            "an observed suspension is structural: {json}"
        );
    }

    /// Only the kernel's own attribution becomes a flag. A client keying on
    /// `daemon_killed_by_memory` must never read it out of a host that
    /// publishes no accounting and therefore never said memory at all.
    #[test]
    fn only_a_kernel_attributed_kill_is_stamped_on_the_envelope() {
        let stamped =
            Envelope::daemon_unreachable().with_recorded_daemon_kill(Some(&kill_record(4)));
        assert_eq!(stamped.degraded.daemon_killed_by_memory, Some(true));
        assert!(stamped
            .degraded
            .active_labels()
            .contains(&"daemon_killed_by_memory"));

        let unattributed =
            Envelope::daemon_unreachable().with_recorded_daemon_kill(Some(&kill_record(0)));
        assert_eq!(
            unattributed.degraded.daemon_killed_by_memory, None,
            "a kill nothing attributed to memory claims nothing structurally"
        );

        let never_killed = Envelope::daemon_unreachable().with_recorded_daemon_kill(None);
        assert_eq!(never_killed.degraded.daemon_killed_by_memory, None);
        assert_eq!(
            serde_json::to_value(&never_killed.degraded).unwrap(),
            serde_json::json!({"daemon_unreachable": true}),
            "a store with no record serializes exactly as it did"
        );
    }

    /// FIR-2644: a graph short of its own relation census must say so, and a
    /// whole one must not.
    ///
    /// Both halves matter. The signal exists because the rows that come back
    /// from a damaged graph are all true, so nothing in the payload separates a
    /// halved caller set from a complete one; and a flag that fires on every
    /// store separates nothing either.
    #[test]
    fn a_census_hold_becomes_a_degraded_signal_and_its_absence_does_not() {
        // Built from the wire shape the census pass writes, so the test also
        // pins the record this envelope reads to the one that is published.
        let hold: kin_core::relation_census::CensusHold = serde_json::from_str(
            r#"{"held_at":"2026-08-22T22:35:16Z","held_source":"enrichment sweep",
                "losses":["Calls slipped 1279 to 1269, while the entity count held at 783"]}"#,
        )
        .expect("the published hold shape parses");
        let flagged = Envelope::daemon().with_relation_census_loss(Some(&hold));
        assert_eq!(flagged.degraded.relation_census_loss, Some(true));
        assert!(flagged.degraded.any());
        assert!(flagged
            .degraded
            .active_labels()
            .contains(&"relation_census_loss"));

        let whole = Envelope::daemon().with_relation_census_loss(None);
        assert_eq!(
            whole.degraded.relation_census_loss, None,
            "a store recording no hold makes no claim rather than claiming health"
        );
        assert!(!whole
            .degraded
            .active_labels()
            .contains(&"relation_census_loss"));
        let json = serde_json::to_string(&whole.degraded).expect("degraded serializes");
        assert!(
            !json.contains("relation_census_loss"),
            "an unobserved flag is absent from the wire, not false: {json}"
        );
    }
}

#[cfg(test)]
mod self_check_tests {
    use super::*;
    use serde_json::json;

    /// A response whose blocks all agree, so nothing may be disclosed.
    fn agreeing() -> Value {
        json!({
            "_kin": {
                "verdict": {
                    "state": "certified",
                    "absence_claim": "authoritative",
                    "safe_to_conclude_absent": true,
                    "limiting_factor": Value::Null,
                },
                "completeness": {
                    "status": "complete",
                    "bound": "exact",
                    "counted": {"reported": 2, "exact": true},
                    "note": "the counts here are the whole set.",
                },
            },
            "negative": {
                "safe_to_conclude_absent": true,
                "trust": "authoritative",
            },
        })
    }

    /// FIR-2697. The checker was reached only from a `debug_assert!`, so a
    /// release binary never ran it and the v0.5.52 envelope that certified over
    /// an absent edge class shipped with it present and inert.
    ///
    /// It runs unconditionally now and publishes what it finds, so this asserts
    /// on the block a client reads rather than on a panic a release build
    /// deletes.
    #[test]
    fn a_response_that_contradicts_itself_says_so_where_a_client_reads_it() {
        let mut value = agreeing();
        // The completeness refuses while the verdict certifies: the exact shape
        // that shipped, and the one the certified-direction arms were added for.
        value["_kin"]["completeness"]["status"] = json!("unknown");
        value["_kin"]["completeness"]["bound"] = json!("at_least");

        disclose_self_contradictions(&mut value, "find_references");

        let check = &value["_kin"]["self_check"];
        assert_eq!(check["status"], json!("contradicted"), "{value}");
        let found = check["disagreements"]
            .as_array()
            .expect("the disagreements are named");
        assert!(
            found.iter().any(|line| line
                .as_str()
                .is_some_and(|line| line.contains("bound reads at_least under a certified"))),
            "the disclosure names what disagreed: {found:?}"
        );
        assert!(
            check["note"]
                .as_str()
                .is_some_and(|note| note.contains("defect in Kin")),
            "and says whose fault it is, since a caller cannot fix it: {check}"
        );
    }

    /// The control, and the half that stops the fix being "disclose always".
    /// A response whose blocks agree must carry no `self_check` at all, so its
    /// absence is a positive statement rather than a field nobody set.
    #[test]
    fn an_agreeing_response_carries_no_self_check() {
        let mut value = agreeing();
        disclose_self_contradictions(&mut value, "find_references");
        assert!(
            value["_kin"].get("self_check").is_none(),
            "an agreeing response disclosed a contradiction: {value}"
        );
    }

    #[test]
    fn response_accounting_includes_the_final_self_check_and_residual_state() {
        let mut value = agreeing();
        value["references"] = json!([{"name": "one surviving answer"}]);
        value["_kin"]["completeness"]["status"] = json!("unknown");
        value["_kin"]["completeness"]["bound"] = json!("at_least");
        let budget = ResponseBudget {
            max_chars: crate::budget::measure(&value) + 100,
            compact: false,
            ..ResponseBudget::default()
        };

        apply_response_budget(&mut value, "find_references", &budget);

        assert_eq!(value["_kin"]["self_check"]["status"], "contradicted");
        let final_chars = crate::budget::measure(&value);
        assert_eq!(
            value["_kin"]["response"]["chars_after_budget"],
            json!(final_chars),
            "the self-check is part of the bytes the accounting reports: {value}"
        );
        let residual = value
            .get("degradations")
            .and_then(Value::as_array)
            .is_some_and(|entries| {
                entries.iter().any(|entry| {
                    entry.get("reason").and_then(Value::as_str)
                        == Some(crate::budget::OVER_BUDGET_REASON)
                })
            });
        assert!(
            final_chars <= budget.max_chars || residual,
            "post-budget self-check growth must fit or disclose: {value}"
        );
    }
}
