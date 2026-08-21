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
}

impl Degraded {
    /// True when any degraded condition is affirmatively set.
    pub fn any(&self) -> bool {
        [
            self.daemon_unreachable,
            self.embed_worker_failed,
            self.mass_deletion_blocked,
            self.offline_fallback,
            self.workspace_mismatch,
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
        if self.mass_deletion_blocked == Some(true) {
            labels.push("mass_deletion_blocked");
        }
        if self.offline_fallback == Some(true) {
            labels.push("offline_fallback");
        }
        if self.workspace_mismatch == Some(true) {
            labels.push("workspace_mismatch");
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
/// Present only when the store IS behind. An absent object is not a claim that
/// it is current: a runtime that reported no reconcile reading has nothing to
/// say here, and reporting a zero it never verified is the shape of wrong
/// answer this object exists to stop.
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
    /// One line an agent can act on without reading the counts.
    pub note: String,
}

impl GraphBehind {
    /// Read the two halves out of a daemon `/health` body.
    ///
    /// `None` when the body carries no reconcile reading at all, and `None`
    /// again when it reports nothing unadmitted. The two are different facts and
    /// both are correctly silent here: this object speaks only when the store is
    /// behind, and the gates that consume it treat its silence as no reading
    /// rather than as an all-clear.
    pub fn from_health(health: &Value) -> Option<Self> {
        let reconcile = health.get("reconcile")?;
        let unadmitted_paths = reconcile.get("untracked_path_count")?.as_u64()?;
        if unadmitted_paths == 0 {
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
        let note = Self::describe(unadmitted_paths, since.as_deref());
        Some(Self {
            unadmitted_paths,
            since,
            sample,
            note,
        })
    }

    fn describe(unadmitted_paths: u64, since: Option<&str>) -> String {
        let clock = match since {
            Some(since) => format!("the last complete admission was at {since}"),
            None => "this daemon has not reported when a complete admission last succeeded"
                .to_string(),
        };
        format!(
            "{unadmitted_paths} host path(s) are on disk that graph truth does not carry, and \
             {clock}. Answers here cover admitted content only. `kin admit` takes those paths \
             now, and a commit takes them anyway."
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
        format!(
            "graph_behind_working_tree: {} host path(s) on disk have never been admitted and \
             {clock}, so an absence here cannot be told apart from content the graph has not \
             taken yet",
            self.unadmitted_paths
        )
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
    pub fn qualified_by(mut self, behind: &GraphBehind) -> Self {
        let counts = match (self.live_entities, self.live_only_entities) {
            (Some(live), Some(live_only)) => format!("{live} entities, {live_only} uncommitted"),
            (Some(live), None) => format!("{live} entities"),
            _ => "this graph".to_string(),
        };
        self.note = format!(
            "{counts}, and {} host path(s) on disk that no admission has taken; this reading \
             covers admitted content only. `kin admit` takes those paths now, and a commit takes \
             them anyway.",
            behind.unadmitted_paths
        );
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
        } else if deciding_states.iter().any(|state| *state == STATE_ABSENT) {
            "partial"
        } else if deciding_states.iter().any(|state| *state == STATE_UNKNOWN) {
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
        limits.push(format!("file_parsed_{parsed}"));
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
        self.degraded = Degraded::default();
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
    /// the `embed_worker_failed` / `mass_deletion_blocked` degraded flags and the
    /// graph freshness state. Missing fields stay unknown (absent), never
    /// fabricated.
    pub fn with_health(mut self, health: &Value) -> Self {
        if let Some(value) = health.get("embed_worker_failed").and_then(Value::as_bool) {
            self.degraded.embed_worker_failed = Some(value);
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
    annotate_inner(result, envelope, None, "", &ResponseBudget::default())
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
) -> ToolCallResult {
    let envelope_value = envelope.to_value();
    let content = result
        .content
        .into_iter()
        .map(|block| annotate_block(block, &envelope_value, negative, tool_name, budget))
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
    if let Some(payload) = &payload {
        if let Some(verdict) =
            crate::verdict::Verdict::compute(tool_name, payload, &envelope, negative.as_ref())
        {
            verdict.project_onto_completeness(&mut envelope.completeness);
            envelope.verdict = Some(verdict.to_value());
        }
    }
    annotate_inner(result, &envelope, negative.as_ref(), tool_name, budget)
}

fn annotate_block(
    block: ContentBlock,
    envelope_value: &Value,
    negative: Option<&Value>,
    tool_name: &str,
    budget: &ResponseBudget,
) -> ContentBlock {
    let ContentBlock::Text { text } = block;
    let annotated = match serde_json::from_str::<Value>(&text) {
        Ok(Value::Object(mut map)) => {
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
    // The invariant that keeps the collapse from being undone one block at a
    // time. It reads what a client will read, after the budget has had its say,
    // so a block added later cannot reintroduce a second verdict without this
    // firing in every debug build and every test.
    debug_assert!(
        crate::verdict::disagreements(&annotated).is_empty(),
        "response for {tool_name} contradicts its own verdict: {:?}",
        crate::verdict::disagreements(&annotated)
    );
    let rendered =
        serde_json::to_string_pretty(&annotated).unwrap_or_else(|_| annotated.to_string());
    ContentBlock::Text { text: rendered }
}

/// Bound the fully annotated payload and record what that cost under
/// `_kin.response`.
///
/// The accounting stanza is written BEFORE the cut as well as after it. The
/// number it carries is a property of the object it sits inside, so a stanza
/// added afterwards would push a response that had just been cut to fit back
/// over its ceiling by its own length. Writing it first means the ladder
/// measures the bytes that actually ship. `chars_before` is then restored to the
/// first measurement, which is the one taken before anything was removed.
fn apply_response_budget(annotated: &mut Value, tool_name: &str, budget: &ResponseBudget) {
    if !crate::budget::is_budgeted(tool_name) {
        return;
    }
    let chars_before = crate::budget::measure(annotated);
    let mut accounting = crate::budget::BudgetAccounting {
        max_chars: budget.max_chars,
        chars_before,
        bounded: false,
        compact: budget.compact,
    };
    write_response_accounting(annotated, &accounting);
    if let Some(applied) = crate::budget::enforce(annotated, tool_name, budget) {
        accounting = applied;
        accounting.chars_before = chars_before;
    }
    write_response_accounting(annotated, &accounting);
    if accounting.bounded {
        if let Some(completeness) = annotated
            .get_mut(ENVELOPE_KEY)
            .and_then(Value::as_object_mut)
            .and_then(|envelope| envelope.get_mut("completeness"))
        {
            Completeness::mark_response_bounded(completeness);
        }
        // The verdict and the absence object are downgraded with it. A budget
        // that removed rows on purpose is the one cut that cannot leave a
        // response certifying what it no longer carries.
        crate::verdict::mark_response_bounded(annotated);
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
            "mass_deletion_blocked": false,
            "reconciliation_status": "clean",
            "graph_entity_count": 1234,
            "graph_loaded": true,
            "initialized": true,
        });
        let env = Envelope::daemon().with_health(&health);
        assert_eq!(env.degraded.embed_worker_failed, Some(true));
        assert_eq!(env.degraded.mass_deletion_blocked, Some(false));
        assert_eq!(
            env.graph_state.reconciliation_status.as_deref(),
            Some("clean")
        );
        assert_eq!(env.graph_state.entity_count, Some(1234));
        assert_eq!(env.graph_state.loaded, Some(true));
        assert_eq!(env.graph_state.initialized, Some(true));
        assert!(env.degraded.any());
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
            !durability.note.contains("records everything answering here"),
            "the all-clear this reading cannot make: {}",
            durability.note
        );
        assert!(
            durability.note.contains("host path(s) on disk that no admission has taken"),
            "the note has to name what it does not cover: {}",
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
            "reconcile": { "untracked_path_count": 0 },
        }));

        assert!(env.behind.is_none(), "nothing unadmitted is nothing to say");
        let durability = env.durability.expect("the counts still answer");
        assert_eq!(durability.state, "recorded");
        assert!(
            durability.note.contains("records everything answering here"),
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
                "cross_repo": {
                    "status": "available",
                    "authority_complete": true,
                    "authority_revision": "sha256:complete",
                    "authority_roots": { "local": "local-root" },
                },
                "edge_coverage": {
                    "scope": "language",
                    "language": "Python",
                    "classes": {
                        "calls": calls_state,
                        "imports": "absent",
                        "references": "absent",
                    },
                    "reference_enrichment": "unknown",
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
        // `imports` is absent here and on every real graph, since Kin mints no
        // entity-level import edge, so it is disclosed and does not decide.
        // `references` is absent here too, and does not decide because this
        // fixture's `reference_enrichment` reads `unknown`: nothing established
        // that this host could produce the class. Where a host CAN produce it,
        // `references` does decide (FIR-2505), which is the case the test below
        // pins. Both directions of this contract hold only because the deciding
        // set is computed from that fact rather than fixed.
        assert_eq!(completeness["classes"]["imports"], "absent");
        assert_eq!(completeness["decided_by"], json!(["calls"]));
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
            json!(["calls", "references"]),
            "a class this host could produce is one the verdict rests on: {completeness}"
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
}
