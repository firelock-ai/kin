// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use kin_model::ids::{EntityId, IntentId, SessionId};
use kin_model::session::{
    AgentSession, Intent, IntentScope, IntentSummary, LockType, SessionCapabilities,
    SessionTransport, TrafficReport,
};
use kin_model::timestamp::Timestamp;
use serde::{Deserialize, Serialize};

/// Registered assistant session (legacy compat for simple register_session tool).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssistantSession {
    pub session_id: String,
    pub assistant_name: String,
    pub registered_at: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum McpMutationPayload {
    Entity(kin_model::Entity),
    Relation {
        from: kin_model::ids::EntityId,
        to: kin_model::ids::EntityId,
        kind: kin_model::relation::RelationKind,
    },
    Blob(Vec<u8>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpMutationOperation {
    pub verb: String,
    /// Exact repository entity ID for entity payloads; empty for relation
    /// payloads, which identify themselves by endpoint and kind.
    pub target: String,
    pub payload: Option<McpMutationPayload>,
    /// New full UTF-8 source text for an entity body edit. The product daemon
    /// splices this body into exact repository-CAS bytes in memory, reparses the
    /// resulting complete file, and publishes semantic change + exact tree +
    /// workspace/ref authority through one repository transaction. It is
    /// absent for relation operations; source-bound metadata-only edits fail
    /// closed because they cannot produce exact source truth.
    #[serde(default)]
    pub body: Option<String>,
    pub description: String,
}

/// A payload-less operation that expresses "this entity's new source is
/// `body`": verb update/modify, `target` naming the entity (name or id), and a
/// non-empty `body`. This is the minimal write surface for agents, which know
/// names and source text but not Kin's entity structs.
///
/// Only the daemon commit path can honor it: the daemon resolves the target
/// fail-closed against repository authority, plans the exact span edit, and
/// projects the new source into the entity's working-directory file. The
/// in-process commit path has no projection and refuses the shape rather than
/// committing a same-entity no-op that would discard the body.
pub fn is_target_body_update(op: &McpMutationOperation) -> bool {
    op.payload.is_none()
        && matches!(op.verb.trim().to_lowercase().as_str(), "update" | "modify")
        && !op.target.trim().is_empty()
        && op
            .body
            .as_deref()
            .is_some_and(|body| !body.trim().is_empty())
}

/// A payload-less operation that expresses "the complete source of the new
/// repository file at `target` is `body`": verb create/add/insert, `target`
/// naming a repository-relative path, and a non-empty `body`.
///
/// This is the admission surface for source the graph has never seen.
/// [`is_target_body_update`] covers the case where an entity already exists to
/// edit, and it cannot reach a new file: it resolves `target` against
/// repository authority and splices into an existing span, so a path with no
/// entity and no span has nothing for it to resolve. An agent that has just
/// authored a module holds neither an entity id nor a span, so `target` names
/// the path and the daemon derives every entity in the file from `body`
/// through the same extractor the ingest path runs.
///
/// The body travels in the call rather than the daemon reading the path off
/// disk. Graph truth is then written from bytes the caller supplied, and the
/// working file is a projection of what was committed, which is the direction
/// the graph-first thesis requires. It also keeps admission off the filesystem
/// entirely: no walk, no scan, and no race against the caller's own writes.
///
/// `upsert` is deliberately not one of the verbs. It would have to mean
/// "create if absent, edit if present", and a create that silently becomes an
/// edit of somebody else's file is the failure this shape exists to make
/// impossible. A path that is already tracked is refused by name.
pub fn is_new_source_file(op: &McpMutationOperation) -> bool {
    op.payload.is_none()
        && matches!(
            op.verb.trim().to_lowercase().as_str(),
            "create" | "add" | "insert"
        )
        && !op.target.trim().is_empty()
        && op
            .body
            .as_deref()
            .is_some_and(|body| !body.trim().is_empty())
}

/// An operation that carries new source text for a file.
///
/// Source text can only become truth by being spliced into exact repository
/// bytes and projected into the working file, which lives in the daemon commit
/// path. Any other path must refuse an operation shaped like this rather than
/// commit whatever else the operation carries, because a commit that keeps the
/// metadata and drops the source reports an agent's edit as durable while the
/// file it named is unchanged.
///
/// Deliberately wider than [`is_target_body_update`]: that names the one shape
/// the daemon can honor without a payload, while this names every shape whose
/// substance is the body, including an entity payload sent alongside one.
pub fn carries_source_body(op: &McpMutationOperation) -> bool {
    op.body
        .as_deref()
        .is_some_and(|body| !body.trim().is_empty())
}

/// Why a commit was refused before anything was applied, in a form a caller can
/// branch on without reading prose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitRefusalCode {
    /// The operations cannot be turned into a committed delta on any path.
    NotCommittable,
    /// The operations carry new source text and this path has no projection to
    /// write it with. The daemon commit path honors the identical operations.
    SourceBodyRequiresDaemonCommit,
}

impl CommitRefusalCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotCommittable => "not_committable",
            Self::SourceBodyRequiresDaemonCommit => "source_body_requires_daemon_commit",
        }
    }

    fn remedy(self) -> &'static str {
        match self {
            Self::NotCommittable => {
                "Fix or remove the named operations and commit again; the transaction is left \
                 active and nothing was applied."
            }
            Self::SourceBodyRequiresDaemonCommit => {
                "These operations require the daemon commit path, which splices the body into \
                 exact repository bytes and projects the result into the working file. Commit \
                 through a running Kin daemon; the transaction is left active and nothing was \
                 applied."
            }
        }
    }
}

/// One refusal, naming its code, the operations that caused it, and the state
/// the transaction is left in.
///
/// Rendered as a sentence followed by the same refusal as JSON: an agent reads
/// the code and the operation list, a human reads the sentence, and neither has
/// to reconstruct the other from the other's format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitRefusal {
    pub schema: String,
    pub code: CommitRefusalCode,
    pub transaction_id: String,
    pub transaction_state: String,
    pub applied: bool,
    pub operations: Vec<String>,
    pub remedy: String,
}

impl CommitRefusal {
    pub const SCHEMA: &'static str = "kin.mcp.commit_refusal.v1";

    pub fn new(code: CommitRefusalCode, transaction_id: &str, operations: Vec<String>) -> Self {
        Self {
            schema: Self::SCHEMA.to_string(),
            code,
            transaction_id: transaction_id.to_string(),
            transaction_state: "active".to_string(),
            applied: false,
            operations,
            remedy: code.remedy().to_string(),
        }
    }

    pub fn render(&self) -> String {
        let listed = self
            .operations
            .iter()
            .map(|reason| format!("  - {reason}"))
            .collect::<Vec<_>>()
            .join("\n");
        let evidence = serde_json::to_string(self)
            .unwrap_or_else(|error| format!("{{\"serialize_error\":\"{error}\"}}"));
        format!(
            "Cannot commit transaction {}: {} staged operation(s) were refused ({}):\n{listed}\n{}\n{evidence}",
            self.transaction_id,
            self.operations.len(),
            self.code.as_str(),
            self.remedy,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpTransaction {
    pub transaction_id: String,
    pub session_id: String,
    pub scope: String,
    pub state: String,
    pub staged_operations: Vec<McpMutationOperation>,
    /// Canonical digest of the exact staged operation set being committed.
    ///
    /// Daemon-owned repository commits persist `state = "committing"` and
    /// this digest before moving repository authority. A restart can then
    /// distinguish an idempotent receipt recovery from a transaction whose
    /// payload was changed after publication began. Unfenced active
    /// transactions carry no digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit_payload_hash: Option<String>,
}

/// Linearized outcome of an in-process intent registration attempt.
#[derive(Debug, Clone)]
pub enum IntentRegistrationAttempt {
    Registered {
        intent: Intent,
        policy_warnings: Vec<String>,
    },
    Blocked {
        intent_id: IntentId,
        conflicts: Vec<IntentSummary>,
    },
    LimitExceeded {
        intent_id: IntentId,
        active: usize,
        limit: usize,
    },
    CapabilityDenied {
        intent_id: IntentId,
        capability: &'static str,
    },
    SessionNotFound,
}

/// Effective coordination enforcement mode shared by transaction preflight
/// and proof/build attestation. Warn remains the default; only explicit
/// `enforce` may reject a write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoordinationEnforcementMode {
    Off,
    Warn,
    Enforce,
}

impl CoordinationEnforcementMode {
    pub fn from_env() -> Self {
        Self::parse(std::env::var("KIN_WRITE_VETO").ok().as_deref())
    }

    pub fn parse(raw: Option<&str>) -> Self {
        match raw.map(str::trim) {
            Some(value) if value.eq_ignore_ascii_case("enforce") => Self::Enforce,
            Some(value) if value.eq_ignore_ascii_case("off") => Self::Off,
            _ => Self::Warn,
        }
    }

    pub fn is_enforcing(self) -> bool {
        matches!(self, Self::Enforce)
    }

    pub fn evaluates(self) -> bool {
        !matches!(self, Self::Off)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Warn => "warn",
            Self::Enforce => "enforce",
        }
    }
}

/// Honest surface attestation for MCP transaction coordination. Contract
/// scopes stay explicitly ineligible until a transaction can derive a touched
/// contract from the actual semantic delta.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoordinationSurfaceCoverage {
    pub entity_scopes: bool,
    pub artifact_scopes_from_entity_origin: bool,
    pub relation_endpoint_entities: bool,
    pub contract_scopes: bool,
    pub direct_filesystem_writes: bool,
}

impl Default for CoordinationSurfaceCoverage {
    fn default() -> Self {
        Self {
            entity_scopes: true,
            artifact_scopes_from_entity_origin: true,
            relation_endpoint_entities: true,
            contract_scopes: false,
            direct_filesystem_writes: false,
        }
    }
}

/// Result of checking a transaction immediately before graph application.
#[derive(Debug, Clone, Serialize)]
pub struct CoordinationWritePreflight {
    pub schema: &'static str,
    pub mode: CoordinationEnforcementMode,
    pub evaluated: bool,
    pub allowed: bool,
    pub session_id: String,
    pub touched_scopes: Vec<IntentScope>,
    pub blocking_intents: Vec<IntentSummary>,
    pub capability_violations: Vec<String>,
    pub coverage: CoordinationSurfaceCoverage,
}

/// The mutation verbs the transaction commit path understands, listed for
/// actionable error messages.
const KNOWN_MUTATION_VERBS: &str = "create/add/upsert/insert, update/modify, or delete/remove";

fn is_known_mutation_verb(verb: &str) -> bool {
    matches!(
        verb,
        "create" | "add" | "upsert" | "insert" | "update" | "modify" | "delete" | "remove"
    )
}

/// Validate staged mutation operations at stage time so malformed payloads fail
/// loud with an actionable message instead of being silently dropped at commit.
///
/// These checks are intrinsic to the payload (no graph access required) and are
/// safe in every runtime, so they run identically for the in-process handler and
/// the product daemon-forward path. Stage-time rejection is a superset of what
/// the commit path (`uncommittable_operations`) rejects: every operation the
/// commit `match` would fall through and silently drop — an absent or unknown
/// verb, a missing payload, a relation `update`/`modify`, or a `Blob` payload —
/// fails loud here, plus the intrinsic empty-entity-name case. This guarantees
/// anything that stages clean will not surprise-drop at commit. Deeper,
/// graph-dependent validation (does the target entity exist, contract/schema
/// conformance) stays with the daemon, which owns graph truth.
pub fn validate_staged_operations(
    operations: &[McpMutationOperation],
) -> std::result::Result<(), String> {
    for (idx, op) in operations.iter().enumerate() {
        let verb = op.verb.trim().to_lowercase();
        if verb.is_empty() {
            return Err(format!(
                "operation #{idx}: missing verb; expected one of {KNOWN_MUTATION_VERBS}"
            ));
        }
        if !is_known_mutation_verb(&verb) {
            return Err(format!(
                "operation #{idx}: unknown verb '{}'; expected one of {KNOWN_MUTATION_VERBS}",
                op.verb
            ));
        }
        let Some(payload) = op.payload.as_ref() else {
            if is_target_body_update(op) {
                continue;
            }
            if is_new_source_file(op) {
                validate_new_source_path(idx, op)?;
                continue;
            }
            return Err(format!(
                "operation #{idx} ('{}'): missing payload; provide an entity, relation, or blob \
                 payload, express an edit to an existing entity as verb 'update' with `target` \
                 (entity name or id) and `body` (the entity's full new source text), or admit a \
                 source file the graph has never seen as verb 'create' with `target` (its \
                 repository-relative path) and `body` (the file's complete text)",
                op.verb
            ));
        };
        if let McpMutationPayload::Entity(entity) = payload {
            if entity.name.trim().is_empty() {
                return Err(format!(
                    "operation #{idx}: entity payload has an empty name; an entity must be named"
                ));
            }
        }
        // Reject the remaining commit-silent-drop cases (relation update/modify,
        // blob payloads) so stage-time rejection is a strict superset of what the
        // commit path drops. Verb and payload are already validated above, so
        // this only fires for these payload/verb combinations.
        if let Some(reason) = uncommittable_reason(op) {
            return Err(format!("operation #{idx} ('{}'): {reason}", op.verb));
        }
    }
    Ok(())
}

/// Validate the repository-relative path a new-source-file operation names.
///
/// Runs the same path rule the projection applies
/// ([`kin_core::validate_source_paths`]), so a path that stages clean is a path
/// the commit can materialize. Doing it here rather than only in the daemon is
/// what keeps stage-time rejection a superset of commit-time rejection: an
/// absolute path, a `..` escape, or a name reserved for Kin or Git control
/// metadata is refused at the call that introduced it, with the path quoted,
/// instead of at a commit that has already accepted several other operations.
///
/// Intrinsic to the payload and free of graph access, like every other check in
/// [`validate_staged_operations`], so it behaves identically in-process and
/// through the daemon.
fn validate_new_source_path(idx: usize, op: &McpMutationOperation) -> Result<(), String> {
    let target = op.target.trim();
    let path = kin_model::RepoPath::from_utf8(target.to_string()).map_err(|error| {
        format!(
            "operation #{idx} ('{}'): {target:?} is not a usable repository path: {error}",
            op.verb
        )
    })?;
    kin_core::validate_source_paths([&path]).map_err(|error| {
        format!(
            "operation #{idx} ('{}'): {target:?} is not an admissible repository source path: \
             {error}. Name a repository-relative path such as \"src/parser.py\", with no leading \
             slash, no \"..\", and no Kin or Git control component",
            op.verb
        )
    })
}

/// Why a single staged operation cannot be turned into a committed delta, or
/// `None` when it is committable.
///
/// This mirrors exactly what the commit path (`handle_transaction_commit`) can
/// turn into an `EntityDelta`/`RelationDelta`. The cases it flags are the ones
/// the commit `match` would otherwise fall through and silently drop:
/// relation `update`/`modify` (relations are identity-less edges — only
/// add/remove are committable) and `Blob` payloads (no transactional blob path
/// yet), plus the intrinsic problems stage-time validation already guards.
/// No graph access is required, so it is safe to run in any runtime; existence
/// checks (does the relation/entity actually exist) stay graph-side.
///
/// Runtime-independent by design, so a payload-less source update and a
/// payload-less new source file are both `None` here: the daemon commits them.
/// The in-process commit path layers its own offline-only refusal on top of
/// this check, and [`carries_source_body`] already covers both shapes because
/// each is a body; see `handlers::sessions::handle_transaction_commit`.
pub fn uncommittable_reason(op: &McpMutationOperation) -> Option<String> {
    let verb = op.verb.trim().to_lowercase();
    if verb.is_empty() {
        return Some(format!(
            "missing verb; expected one of {KNOWN_MUTATION_VERBS}"
        ));
    }
    if !is_known_mutation_verb(&verb) {
        return Some(format!(
            "unknown verb '{}'; expected one of {KNOWN_MUTATION_VERBS}",
            op.verb
        ));
    }
    let Some(payload) = op.payload.as_ref() else {
        if is_target_body_update(op) || is_new_source_file(op) {
            return None;
        }
        return Some("missing payload".to_string());
    };
    match payload {
        // Every known verb maps to an entity delta (add/modify/remove).
        McpMutationPayload::Entity(_) => None,
        McpMutationPayload::Relation { .. } => {
            if matches!(verb.as_str(), "update" | "modify") {
                Some(format!(
                    "verb '{}' is not committable for relation payloads; relations support only \
                     create/add/upsert/insert or delete/remove",
                    op.verb
                ))
            } else {
                None
            }
        }
        McpMutationPayload::Blob(_) => {
            Some("blob payloads are not yet committable through transactions".to_string())
        }
    }
}

/// The complete `operations` element schema, spelled out for a caller that has
/// to construct them without reading Kin's Rust types.
///
/// Every refusal from [`parse_staged_operations`] carries this whole text
/// rather than the single field serde stopped on. A caller improvising the
/// shape learns one missing field per attempt from a raw decode error, so it
/// discovers the contract by looping on retries; naming the full schema once
/// ends the loop on the first refusal.
pub const ACCEPTED_OPERATION_SHAPES: &str = "each element of `operations` is one of:\n  \
     - an entity source edit: {\"verb\": \"update\", \"target\": \"<entity uuid or exact name>\", \
     \"body\": \"<the entity's full new source text>\", \"description\": \"<why>\"}\n  \
     - an entity payload edit: {\"verb\": \"update\", \"target\": \"<entity uuid>\", \
     \"payload\": {\"Entity\": {<the entity object>}}, \"body\": \"<full new source text>\", \
     \"description\": \"<why>\"}\n  \
     - a relation edit: {\"verb\": \"create\"|\"delete\", \"target\": \"\", \
     \"payload\": {\"Relation\": {\"from\": \"<uuid>\", \"to\": \"<uuid>\", \"kind\": \"<relation kind>\"}}, \
     \"description\": \"<why>\"}\n\
     Prefer the first shape: it needs only a target and the new source text.\n\
     Every field of an operation, and nothing else is accepted:\n  \
     - `verb` (string, REQUIRED): one of create/add/upsert/insert, update/modify, or \
     delete/remove. Compared case-insensitively after trimming.\n  \
     - `target` (string, REQUIRED): the entity this operation acts on, as either its uuid or \
     its exact name. Empty string for relation payloads, which identify themselves by their \
     endpoints and kind.\n  \
     - `description` (string, REQUIRED): why this operation is being made.\n  \
     - `body` (string, optional): the entity's complete new source text, never a fragment or a \
     diff. New source text is carried by this field and no other; a key like `content`, \
     `source`, or `new_body` is refused rather than accepted with the source dropped.\n  \
     - `payload` (object, optional): omit it for a source edit. Otherwise exactly one of \
     {\"Entity\": {<entity object>}}, {\"Relation\": {\"from\": \"<uuid>\", \"to\": \"<uuid>\", \
     \"kind\": \"<relation kind>\"}}, or {\"Blob\": [<bytes>]}. Relation payloads accept only \
     create/add/upsert/insert or delete/remove, and blob payloads are not committable through \
     transactions yet";

/// Every field an operation is allowed to carry.
///
/// Serde drops keys it does not model, so an operation naming its source text
/// anything other than `body` decodes cleanly with `body: None` and is planned
/// as if no source had been sent. Checking the key set first is what turns that
/// into a refusal the caller can act on.
const OPERATION_FIELDS: [&str; 5] = ["verb", "target", "payload", "body", "description"];

/// Decode an `operations` argument into staged operations.
///
/// A raw serde failure here names an internal field of whichever payload
/// variant it got furthest into (`missing field 'kind'`), which tells a caller
/// improvising the shape nothing it can act on. Every decode failure is
/// rewritten to name the accepted shapes, so a caller that guessed wrong learns
/// the contract from the refusal instead of looping on retries.
///
/// Unknown keys are refused rather than ignored. A caller writing the shape by
/// hand reaches for `content`, `source`, or `new_body` before it reaches for
/// `body`, and silently discarding that key is indistinguishable from a commit
/// that dropped the change: the operation stages, commits, and reports success
/// having carried no source at all.
pub fn parse_staged_operations(
    operations: &serde_json::Value,
) -> std::result::Result<Vec<McpMutationOperation>, String> {
    let serde_json::Value::Array(elements) = operations else {
        return Err(format!(
            "invalid operations: expected a JSON array, got {}; {ACCEPTED_OPERATION_SHAPES}",
            json_type_name(operations)
        ));
    };
    for (idx, element) in elements.iter().enumerate() {
        let Some(fields) = element.as_object() else {
            return Err(format!(
                "invalid operations: element #{idx} is {}, expected an object; \
                 {ACCEPTED_OPERATION_SHAPES}",
                json_type_name(element)
            ));
        };
        let unknown = fields
            .keys()
            .filter(|key| !OPERATION_FIELDS.contains(&key.as_str()))
            .map(|key| format!("'{key}'"))
            .collect::<Vec<_>>();
        if !unknown.is_empty() {
            return Err(format!(
                "invalid operations: element #{idx} carries unknown field(s) {}; an operation is \
                 described only by {}. New source text goes in `body`, and nowhere else, or it is \
                 not committed; {ACCEPTED_OPERATION_SHAPES}",
                unknown.join(", "),
                OPERATION_FIELDS.join(", ")
            ));
        }
    }
    serde_json::from_value(operations.clone())
        .map_err(|error| format!("invalid operations array: {error}; {ACCEPTED_OPERATION_SHAPES}"))
}

/// Whether two staged operation sets describe exactly the same work.
///
/// Used to tell a resume of a fenced commit apart from an attempt to change
/// what that commit publishes. Compared through their serialized form because
/// an operation carries payload types that model no equality of their own.
pub fn staged_operations_match(
    left: &[McpMutationOperation],
    right: &[McpMutationOperation],
) -> bool {
    match (serde_json::to_value(left), serde_json::to_value(right)) {
        (Ok(left), Ok(right)) => left == right,
        // A set that cannot be serialized cannot be proven identical, and a
        // resume that guesses wrong would append to a fenced payload.
        _ => false,
    }
}

fn json_type_name(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "a boolean",
        serde_json::Value::Number(_) => "a number",
        serde_json::Value::String(_) => "a string",
        serde_json::Value::Array(_) => "an array",
        serde_json::Value::Object(_) => "an object",
    }
}

/// Indexed, human-readable reasons for every staged operation that cannot be
/// committed. Empty when the whole batch is committable. The commit and
/// validate handlers use this to fail loud instead of silently dropping
/// un-committable operations at commit.
pub fn uncommittable_operations(operations: &[McpMutationOperation]) -> Vec<String> {
    operations
        .iter()
        .enumerate()
        .filter_map(|(idx, op)| {
            uncommittable_reason(op)
                .map(|reason| format!("operation #{idx} ('{}'): {reason}", op.verb))
        })
        .collect()
}

/// Thread-safe registry for agent sessions and intents.
///
/// This is the in-process coordination hub. The daemon would host this
/// and expose it over HTTP; the MCP server holds a local instance for
/// direct MCP-connected agents.
pub struct SessionRegistry {
    /// Legacy simple sessions (from `register_session` tool).
    sessions: Mutex<HashMap<String, AssistantSession>>,
    /// Rich agent sessions (from `kin_session_start` tool).
    agent_sessions: Mutex<HashMap<SessionId, AgentSession>>,
    /// Active intents keyed by IntentId.
    intents: Mutex<HashMap<IntentId, Intent>>,
    /// Active transactions keyed by TransactionId.
    transactions: Mutex<HashMap<String, McpTransaction>>,
    /// Linearization point for rich-session and intent lifecycle mutations.
    /// The maps stay separate for low-impact compatibility, but registration's
    /// session lookup + concurrency check + conflict check + insert is one
    /// indivisible coordinator operation under this gate.
    intent_registration_gate: Mutex<()>,
    /// Daemon-owned mode snapshot. `None` keeps standalone/offline MCP behavior
    /// environment-driven; the daemon sets this explicitly so a request cannot
    /// observe a process-global env change mid-run.
    coordination_mode: Mutex<Option<CoordinationEnforcementMode>>,
}

impl SessionRegistry {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            agent_sessions: Mutex::new(HashMap::new()),
            intents: Mutex::new(HashMap::new()),
            transactions: Mutex::new(HashMap::new()),
            intent_registration_gate: Mutex::new(()),
            coordination_mode: Mutex::new(None),
        }
    }

    // ── Legacy session API (backward compat) ──

    /// Register a simple session. Returns the session ID.
    pub fn register(&self, session_id: &str, assistant_name: &str) -> String {
        let session = AssistantSession {
            session_id: session_id.to_string(),
            assistant_name: assistant_name.to_string(),
            registered_at: Timestamp::now(),
        };
        let id = session.session_id.clone();
        self.sessions
            .lock()
            .expect("session lock poisoned")
            .insert(id.clone(), session);
        id
    }

    /// Get a simple session by ID.
    pub fn get(&self, session_id: &str) -> Option<AssistantSession> {
        self.sessions
            .lock()
            .expect("session lock poisoned")
            .get(session_id)
            .cloned()
    }

    /// Remove a simple session.
    pub fn remove(&self, session_id: &str) -> Option<AssistantSession> {
        self.sessions
            .lock()
            .expect("session lock poisoned")
            .remove(session_id)
    }

    /// List all simple sessions.
    pub fn list(&self) -> Vec<AssistantSession> {
        self.sessions
            .lock()
            .expect("session lock poisoned")
            .values()
            .cloned()
            .collect()
    }

    /// Number of simple sessions.
    pub fn count(&self) -> usize {
        self.sessions.lock().expect("session lock poisoned").len()
    }

    // ── Rich agent session API (Phase 7) ──

    /// Start a new agent session.
    pub fn start_agent_session(
        &self,
        vendor: &str,
        client_name: &str,
        transport: SessionTransport,
        pid: Option<u32>,
        cwd: PathBuf,
        capabilities: SessionCapabilities,
    ) -> AgentSession {
        let _gate = self
            .intent_registration_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = Timestamp::now();
        let session = AgentSession {
            session_id: SessionId::new(),
            vendor: vendor.to_string(),
            client_name: client_name.to_string(),
            transport,
            pid,
            cwd,
            started_at: now.clone(),
            last_heartbeat: now,
            capabilities,
        };
        let id = session.session_id;
        self.agent_sessions
            .lock()
            .expect("agent_sessions lock poisoned")
            .insert(id, session.clone());
        session
    }

    /// Record a heartbeat for an agent session. Returns true if session exists.
    pub fn heartbeat(&self, session_id: &SessionId) -> bool {
        let mut map = self
            .agent_sessions
            .lock()
            .expect("agent_sessions lock poisoned");
        if let Some(session) = map.get_mut(session_id) {
            session.last_heartbeat = Timestamp::now();
            true
        } else {
            false
        }
    }

    /// End an agent session and release all its intents.
    pub fn end_agent_session(&self, session_id: &SessionId) -> Option<AgentSession> {
        let _gate = self
            .intent_registration_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let session = self
            .agent_sessions
            .lock()
            .expect("agent_sessions lock poisoned")
            .remove(session_id);

        if session.is_some() {
            // Release all intents owned by this session.
            let mut intents = self.intents.lock().expect("intents lock poisoned");
            intents.retain(|_, intent| intent.session_id != *session_id);
        }

        session
    }

    /// Get an agent session by ID.
    pub fn get_agent_session(&self, session_id: &SessionId) -> Option<AgentSession> {
        self.agent_sessions
            .lock()
            .expect("agent_sessions lock poisoned")
            .get(session_id)
            .cloned()
    }

    /// List all agent sessions.
    pub fn list_agent_sessions(&self) -> Vec<AgentSession> {
        self.agent_sessions
            .lock()
            .expect("agent_sessions lock poisoned")
            .values()
            .cloned()
            .collect()
    }

    /// Replace the rich session and intent maps from daemon-owned state.
    ///
    /// Product MCP stdio does not own sessions. The repo daemon uses this to
    /// build a per-request read snapshot for tool handlers that enrich graph
    /// answers with active traffic.
    pub fn replace_agent_sessions_and_intents(
        &self,
        agent_sessions: Vec<AgentSession>,
        intents: Vec<Intent>,
    ) {
        let _gate = self
            .intent_registration_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut sessions_map = self
            .agent_sessions
            .lock()
            .expect("agent_sessions lock poisoned");
        sessions_map.clear();
        for session in agent_sessions {
            sessions_map.insert(session.session_id, session);
        }
        drop(sessions_map);

        let mut intents_map = self.intents.lock().expect("intents lock poisoned");
        intents_map.clear();
        for intent in intents {
            intents_map.insert(intent.intent_id, intent);
        }
    }

    // ── Intent API ──

    pub fn set_coordination_mode(&self, mode: CoordinationEnforcementMode) {
        *self
            .coordination_mode
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(mode);
    }

    pub(crate) fn lock_coordination_apply(&self) -> std::sync::MutexGuard<'_, ()> {
        self.intent_registration_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Backward-compatible registration API. Callers that need to distinguish
    /// conflict, capability, and concurrency-limit rejection should use
    /// [`Self::register_intent_checked`].
    pub fn register_intent(
        &self,
        session_id: SessionId,
        scopes: Vec<IntentScope>,
        lock_type: LockType,
        task_description: String,
        expires_at: Option<Timestamp>,
    ) -> Option<Intent> {
        match self.register_intent_checked(
            session_id,
            scopes,
            lock_type,
            task_description,
            expires_at,
        ) {
            IntentRegistrationAttempt::Registered { intent, .. } => Some(intent),
            _ => None,
        }
    }

    /// Register a new intent as one linearized arbitration operation and
    /// preserve the exact rejection reason.
    pub fn register_intent_checked(
        &self,
        session_id: SessionId,
        scopes: Vec<IntentScope>,
        lock_type: LockType,
        task_description: String,
        expires_at: Option<Timestamp>,
    ) -> IntentRegistrationAttempt {
        let _gate = self
            .intent_registration_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let session = self
            .agent_sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&session_id)
            .cloned();
        let Some(session) = session else {
            return IntentRegistrationAttempt::SessionNotFound;
        };

        let now = Timestamp::now();
        let intent = Intent {
            intent_id: IntentId::new(),
            session_id,
            scopes,
            lock_type,
            task_description,
            registered_at: now,
            expires_at,
        };
        let id = intent.intent_id;
        let mut intents = self
            .intents
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let mode = self
            .coordination_mode
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .unwrap_or_else(CoordinationEnforcementMode::from_env);
        let mut policy_warnings = Vec::new();

        if lock_type == LockType::Hard && !session.capabilities.can_write {
            if mode.is_enforcing() {
                return IntentRegistrationAttempt::CapabilityDenied {
                    intent_id: id,
                    capability: "can_write",
                };
            }
            if mode.evaluates() {
                policy_warnings.push(
                    "hard intent requires can_write=true; registration would be denied in enforce mode"
                        .to_string(),
                );
            }
        }

        let now = Timestamp::now();
        let active = intents
            .values()
            .filter(|active| {
                active.session_id == session_id
                    && active
                        .expires_at
                        .as_ref()
                        .is_none_or(|expires_at| expires_at >= &now)
            })
            .count();
        let limit = session.capabilities.max_concurrent_intents;
        if active >= limit {
            if mode.is_enforcing() {
                return IntentRegistrationAttempt::LimitExceeded {
                    intent_id: id,
                    active,
                    limit,
                };
            }
            if mode.evaluates() {
                policy_warnings.push(format!(
                    "active intent count {active} reached max_concurrent_intents={limit}; registration would be denied in enforce mode"
                ));
            }
        }

        if lock_type == LockType::Hard {
            let sessions = self
                .agent_sessions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut conflicts: Vec<IntentSummary> = intents
                .values()
                .filter(|active| {
                    active
                        .expires_at
                        .as_ref()
                        .is_none_or(|expires_at| expires_at >= &now)
                        && active.session_id != session_id
                        && active.lock_type == LockType::Hard
                        && active
                            .scopes
                            .iter()
                            .any(|scope| intent.scopes.contains(scope))
                })
                .map(|active| IntentSummary {
                    intent_id: active.intent_id,
                    session_id: active.session_id,
                    vendor: sessions
                        .get(&active.session_id)
                        .map(|owner| owner.vendor.clone())
                        .unwrap_or_else(|| "unknown".to_string()),
                    task_description: active.task_description.clone(),
                    lock_type: active.lock_type,
                    registered_at: active.registered_at.clone(),
                })
                .collect();
            conflicts.sort_by_key(|conflict| conflict.intent_id.to_string());
            if !conflicts.is_empty() {
                return IntentRegistrationAttempt::Blocked {
                    intent_id: id,
                    conflicts,
                };
            }
        }

        intents.insert(id, intent.clone());
        IntentRegistrationAttempt::Registered {
            intent,
            policy_warnings,
        }
    }

    /// Release a specific intent. Returns it if it existed.
    pub fn release_intent(&self, session_id: &SessionId, intent_id: &IntentId) -> Option<Intent> {
        let _gate = self
            .intent_registration_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut intents = self.intents.lock().expect("intents lock poisoned");
        if let Some(intent) = intents.get(intent_id) {
            if intent.session_id == *session_id {
                return intents.remove(intent_id);
            }
        }
        None
    }

    /// List all intents for a given session in deterministic ID order.
    pub fn list_intents_for_session(&self, session_id: &SessionId) -> Vec<Intent> {
        let mut intents: Vec<_> = self
            .intents
            .lock()
            .expect("intents lock poisoned")
            .values()
            .filter(|i| i.session_id == *session_id)
            .cloned()
            .collect();
        intents.sort_by_key(|intent| intent.intent_id.to_string());
        intents
    }

    /// Evaluate exact-scope intent conflicts and declared write capabilities
    /// immediately before a transaction delta is applied. In enforce mode an
    /// unknown/non-rich session fails closed; warn mode records the same
    /// violations while preserving the historical proceed behavior.
    pub fn evaluate_transaction_write(
        &self,
        session_id: &str,
        touched_scopes: Vec<IntentScope>,
    ) -> CoordinationWritePreflight {
        let mode = self
            .coordination_mode
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .unwrap_or_else(CoordinationEnforcementMode::from_env);
        self.evaluate_transaction_write_with_mode(session_id, touched_scopes, mode)
    }

    pub fn evaluate_transaction_write_with_mode(
        &self,
        session_id: &str,
        touched_scopes: Vec<IntentScope>,
        mode: CoordinationEnforcementMode,
    ) -> CoordinationWritePreflight {
        if !mode.evaluates() {
            return CoordinationWritePreflight {
                schema: "kin.coordination-preflight.v1",
                mode,
                evaluated: false,
                allowed: true,
                session_id: session_id.to_string(),
                touched_scopes,
                blocking_intents: Vec::new(),
                capability_violations: Vec::new(),
                coverage: CoordinationSurfaceCoverage::default(),
            };
        }

        let parsed_session = uuid::Uuid::parse_str(session_id).ok().map(SessionId);
        let session = parsed_session.and_then(|id| self.get_agent_session(&id));
        let mut capability_violations = Vec::new();

        match session.as_ref() {
            Some(session) => {
                if !session.capabilities.can_write {
                    capability_violations.push("can_write=false".to_string());
                }
                if !session.capabilities.can_commit {
                    capability_violations.push("can_commit=false".to_string());
                }
            }
            None => capability_violations
                .push("transaction session is not an active rich agent session".to_string()),
        }

        let intents = self
            .intents
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let sessions = self
            .agent_sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = Timestamp::now();
        let mut blocking_intents: Vec<IntentSummary> = intents
            .values()
            .filter(|intent| {
                intent
                    .expires_at
                    .as_ref()
                    .is_none_or(|expires_at| expires_at >= &now)
                    && Some(intent.session_id) != parsed_session
                    && intent.lock_type == LockType::Hard
                    && intent
                        .scopes
                        .iter()
                        .any(|scope| touched_scopes.contains(scope))
            })
            .map(|intent| IntentSummary {
                intent_id: intent.intent_id,
                session_id: intent.session_id,
                vendor: sessions
                    .get(&intent.session_id)
                    .map(|owner| owner.vendor.clone())
                    .unwrap_or_else(|| "unknown".to_string()),
                task_description: intent.task_description.clone(),
                lock_type: intent.lock_type,
                registered_at: intent.registered_at.clone(),
            })
            .collect();
        blocking_intents.sort_by_key(|intent| intent.intent_id.to_string());

        let violates_policy = !blocking_intents.is_empty() || !capability_violations.is_empty();
        CoordinationWritePreflight {
            schema: "kin.coordination-preflight.v1",
            mode,
            evaluated: true,
            allowed: !mode.is_enforcing() || !violates_policy,
            session_id: session_id.to_string(),
            touched_scopes,
            blocking_intents,
            capability_violations,
            coverage: CoordinationSurfaceCoverage::default(),
        }
    }

    /// Check traffic for the given scopes. Returns a TrafficReport per scope.
    pub fn check_traffic(&self, scopes: &[IntentScope]) -> Vec<TrafficReport> {
        let intents = self.intents.lock().expect("intents lock poisoned");
        let sessions = self
            .agent_sessions
            .lock()
            .expect("agent_sessions lock poisoned");

        scopes
            .iter()
            .map(|target| {
                let active: Vec<IntentSummary> = intents
                    .values()
                    .filter(|i| i.scopes.contains(target))
                    .map(|i| {
                        let vendor = sessions
                            .get(&i.session_id)
                            .map(|s| s.vendor.clone())
                            .unwrap_or_else(|| "unknown".into());
                        IntentSummary {
                            intent_id: i.intent_id,
                            session_id: i.session_id,
                            vendor,
                            task_description: i.task_description.clone(),
                            lock_type: i.lock_type,
                            registered_at: i.registered_at.clone(),
                        }
                    })
                    .collect();

                TrafficReport {
                    target: target.clone(),
                    active_intents: active,
                    // Downstream warnings require graph traversal; the MCP
                    // handler can populate this when a store is available.
                    downstream_warnings: vec![],
                }
            })
            .collect()
    }

    /// Get active traffic summaries near a given entity (for include_traffic flag).
    pub fn get_traffic_near_entity(&self, entity_id: &EntityId) -> Vec<IntentSummary> {
        let target = IntentScope::Entity(*entity_id);
        let intents = self.intents.lock().expect("intents lock poisoned");
        let sessions = self
            .agent_sessions
            .lock()
            .expect("agent_sessions lock poisoned");

        intents
            .values()
            .filter(|i| i.scopes.contains(&target))
            .map(|i| {
                let vendor = sessions
                    .get(&i.session_id)
                    .map(|s| s.vendor.clone())
                    .unwrap_or_else(|| "unknown".into());
                IntentSummary {
                    intent_id: i.intent_id,
                    session_id: i.session_id,
                    vendor,
                    task_description: i.task_description.clone(),
                    lock_type: i.lock_type,
                    registered_at: i.registered_at.clone(),
                }
            })
            .collect()
    }

    // ── Transaction API ──

    /// Whether `session_id` names a live session in either registry: a rich
    /// agent session or a legacy registered assistant session. Transactions
    /// must belong to a real session so commits attribute to a real actor.
    pub fn has_session(&self, session_id: &str) -> bool {
        if uuid::Uuid::parse_str(session_id)
            .ok()
            .map(SessionId)
            .and_then(|id| self.get_agent_session(&id))
            .is_some()
        {
            return true;
        }
        self.sessions
            .lock()
            .expect("sessions lock poisoned")
            .contains_key(session_id)
    }

    pub fn begin_transaction(
        &self,
        session_id: &str,
        scope: &str,
    ) -> std::result::Result<McpTransaction, String> {
        if !self.has_session(session_id) {
            // A well-formed id that names nothing is an ended or idle-reaped
            // session, not a typo. Saying only "not found" sends an agent
            // hunting for a bad argument; naming expiry sends it to the one
            // call that recovers.
            return Err(format!(
                "Session not found: {session_id}. It was ended or expired after its idle \
                 timeout. Call kin_session_start for a new session id and begin the \
                 transaction on that one; kin_session_heartbeat keeps a session alive \
                 through a long read phase."
            ));
        }
        let transaction_id = EntityId::new().to_string();
        let transaction = McpTransaction {
            transaction_id: transaction_id.clone(),
            session_id: session_id.to_string(),
            scope: scope.to_string(),
            state: "active".to_string(),
            staged_operations: Vec::new(),
            commit_payload_hash: None,
        };

        self.transactions
            .lock()
            .expect("transactions lock poisoned")
            .insert(transaction_id, transaction.clone());

        Ok(transaction)
    }

    pub fn stage_transaction(
        &self,
        transaction_id: &str,
        operations: Vec<McpMutationOperation>,
    ) -> std::result::Result<McpTransaction, String> {
        let mut map = self
            .transactions
            .lock()
            .expect("transactions lock poisoned");
        if let Some(tx) = map.get_mut(transaction_id) {
            if tx.state != "active" {
                return Err(format!(
                    "Cannot stage operations on transaction {} in state: {}",
                    transaction_id, tx.state
                ));
            }
            tx.staged_operations.extend(operations);
            Ok(tx.clone())
        } else {
            Err(format!("Transaction not found: {}", transaction_id))
        }
    }

    pub fn validate_transaction(
        &self,
        transaction_id: &str,
    ) -> std::result::Result<McpTransaction, String> {
        let mut map = self
            .transactions
            .lock()
            .expect("transactions lock poisoned");
        if let Some(tx) = map.get_mut(transaction_id) {
            if tx.state != "active" {
                return Err(format!(
                    "Cannot validate transaction {} in state: {}",
                    transaction_id, tx.state
                ));
            }
            tx.state = "validated".to_string();
            Ok(tx.clone())
        } else {
            Err(format!("Transaction not found: {}", transaction_id))
        }
    }

    pub fn commit_transaction(
        &self,
        transaction_id: &str,
    ) -> std::result::Result<McpTransaction, String> {
        let mut map = self
            .transactions
            .lock()
            .expect("transactions lock poisoned");
        if let Some(tx) = map.get_mut(transaction_id) {
            if tx.state != "active" && tx.state != "validated" && tx.state != "committing" {
                return Err(format!(
                    "Cannot commit transaction {} in state: {}",
                    transaction_id, tx.state
                ));
            }
            tx.state = "committed".to_string();
            Ok(tx.clone())
        } else {
            Err(format!("Transaction not found: {}", transaction_id))
        }
    }

    /// Return an editable transaction to an empty staged set after an attempt
    /// that provably did not move repository authority.
    ///
    /// A commit that fails while planning leaves the operations that failed
    /// staged. Staging a corrected operation then appends to the same set, so
    /// the next commit re-plans the original failure and returns the identical
    /// error forever: the transaction is wedged, and no advice the error can
    /// carry ("use the entity id") is reachable without also abandoning it.
    /// Clearing here is what makes a failure recoverable, and it is only ever
    /// called before the publication fence, where nothing has been applied.
    ///
    /// Returns the discarded operations. Clearing takes the whole staged set,
    /// not just the operation that failed, so the caller loses correct work it
    /// staged earlier and needs to know exactly what to re-stage. Handing the
    /// operations back is what lets the refusal name them.
    pub fn clear_staged_operations(
        &self,
        transaction_id: &str,
    ) -> std::result::Result<Vec<McpMutationOperation>, String> {
        let mut map = self
            .transactions
            .lock()
            .expect("transactions lock poisoned");
        let tx = map
            .get_mut(transaction_id)
            .ok_or_else(|| format!("Transaction not found: {transaction_id}"))?;
        if !matches!(tx.state.as_str(), "active" | "validated") {
            return Err(format!(
                "Cannot clear staged operations on transaction {} in state: {}",
                transaction_id, tx.state
            ));
        }
        let cleared = std::mem::take(&mut tx.staged_operations);
        tx.state = "active".to_string();
        tx.commit_payload_hash = None;
        Ok(cleared)
    }

    /// End an editable transaction and discard everything it staged.
    ///
    /// Only `active` and `validated` transactions may abort, because those are
    /// the states in which nothing has been fenced and the staged set is the
    /// only thing to undo.
    ///
    /// A `committing` transaction is owned by the commit path instead:
    /// `prepare_transaction_commit` has persisted its payload digest and
    /// repository authority may already have moved, so the way out is to
    /// re-enter the commit with the same staged operations, which resumes
    /// idempotently and resolves whether the commit landed. Relabelling that
    /// state `aborted` would make the resume unreachable and strand the
    /// transaction in exactly the case the fence exists to survive. A
    /// `committed` transaction refuses for a different reason: overwriting a
    /// real receipt with `aborted` records provenance that never happened.
    pub fn abort_transaction(
        &self,
        transaction_id: &str,
    ) -> std::result::Result<McpTransaction, String> {
        let mut map = self
            .transactions
            .lock()
            .expect("transactions lock poisoned");
        let tx = map
            .get_mut(transaction_id)
            .ok_or_else(|| format!("Transaction not found: {transaction_id}"))?;
        if !matches!(tx.state.as_str(), "active" | "validated") {
            let recovery = if tx.state == "committing" {
                "its commit is already fenced, so repository authority may have moved: \
                 re-send kin_transaction_commit with the same transaction id, which \
                 resumes the fenced payload idempotently and reports whether it landed"
            } else {
                "the transaction already reached a terminal state and holds nothing to \
                 discard: begin a new one with kin_transaction_begin"
            };
            return Err(format!(
                "Cannot abort transaction {} in state: {}. {recovery}.",
                transaction_id, tx.state
            ));
        }
        tx.staged_operations.clear();
        tx.state = "aborted".to_string();
        Ok(tx.clone())
    }

    pub fn get_transaction(&self, transaction_id: &str) -> Option<McpTransaction> {
        self.transactions
            .lock()
            .expect("transactions lock poisoned")
            .get(transaction_id)
            .cloned()
    }

    /// Persistently fence one daemon-owned transaction before repository
    /// authority can move.
    ///
    /// Re-entering with the same digest is idempotent and supports recovery
    /// after a crash or an indeterminate durable-install acknowledgement.
    /// Re-entering with a different digest fails closed.
    pub fn prepare_transaction_commit(
        &self,
        transaction_id: &str,
        payload_hash: &str,
    ) -> std::result::Result<McpTransaction, String> {
        let mut map = self
            .transactions
            .lock()
            .expect("transactions lock poisoned");
        let tx = map
            .get_mut(transaction_id)
            .ok_or_else(|| format!("Transaction not found: {transaction_id}"))?;
        match tx.state.as_str() {
            "active" | "validated" => {
                tx.state = "committing".to_string();
                tx.commit_payload_hash = Some(payload_hash.to_string());
                Ok(tx.clone())
            }
            "committing"
                if tx.commit_payload_hash.as_deref() == Some(payload_hash) =>
            {
                Ok(tx.clone())
            }
            "committing" => Err(format!(
                "Cannot resume transaction {transaction_id}: the staged payload differs from the persisted committing payload"
            )),
            _ => Err(format!(
                "Cannot prepare transaction {} in state: {}",
                transaction_id, tx.state
            )),
        }
    }

    /// Return a failed pre-publication attempt to an editable state.
    ///
    /// This is only valid while no repository receipt exists. Once authority
    /// may have moved, callers retain `committing` and recover by operation ID.
    pub fn reset_transaction_commit(
        &self,
        transaction_id: &str,
    ) -> std::result::Result<McpTransaction, String> {
        let mut map = self
            .transactions
            .lock()
            .expect("transactions lock poisoned");
        let tx = map
            .get_mut(transaction_id)
            .ok_or_else(|| format!("Transaction not found: {transaction_id}"))?;
        if tx.state != "committing" {
            return Err(format!(
                "Cannot reset transaction {} in state: {}",
                transaction_id, tx.state
            ));
        }
        tx.state = "active".to_string();
        tx.commit_payload_hash = None;
        Ok(tx.clone())
    }

    /// Snapshot every transaction currently held by this registry.
    ///
    /// Used by the daemon to persist transaction state into its long-lived store
    /// after a tool call, since the daemon rebuilds a fresh registry per request.
    pub fn list_transactions(&self) -> Vec<McpTransaction> {
        self.transactions
            .lock()
            .expect("transactions lock poisoned")
            .values()
            .cloned()
            .collect()
    }

    /// Replace all transactions in this registry with `transactions`.
    ///
    /// The daemon calls this before dispatching a tool so a registry built fresh
    /// for the request sees transactions staged by earlier requests; without it,
    /// `begin`/`stage`/`commit` issued across separate HTTP calls never share
    /// state and the transaction is reported "not found".
    pub fn replace_transactions(&self, transactions: Vec<McpTransaction>) {
        let mut map = self
            .transactions
            .lock()
            .expect("transactions lock poisoned");
        map.clear();
        for transaction in transactions {
            map.insert(transaction.transaction_id.clone(), transaction);
        }
    }
}

impl Default for SessionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl SessionRegistry {
    /// An empty registry for a handler unit test; compiled out of every non-test build.
    pub(crate) fn empty_for_test() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutation_operation_rejects_missing_exact_target_field() {
        let json = serde_json::json!({
            "verb": "update",
            "description": "malformed op without target"
        });
        let error = serde_json::from_value::<McpMutationOperation>(json)
            .expect_err("operation without the schema-required target must fail");
        assert!(error.to_string().contains("target"));
    }

    #[test]
    fn register_and_get_session() {
        let registry = SessionRegistry::new();
        let id = registry.register("sess-1", "claude-code");
        assert_eq!(id, "sess-1");

        let session = registry.get("sess-1").unwrap();
        assert_eq!(session.assistant_name, "claude-code");
        assert_eq!(registry.count(), 1);
    }

    #[test]
    fn remove_session() {
        let registry = SessionRegistry::new();
        registry.register("sess-2", "codex");
        assert_eq!(registry.count(), 1);

        let removed = registry.remove("sess-2");
        assert!(removed.is_some());
        assert_eq!(registry.count(), 0);
    }

    #[test]
    fn list_sessions() {
        let registry = SessionRegistry::new();
        registry.register("a", "claude-code");
        registry.register("b", "codex");
        registry.register("c", "gemini");

        let sessions = registry.list();
        assert_eq!(sessions.len(), 3);
    }

    #[test]
    fn get_nonexistent_session() {
        let registry = SessionRegistry::new();
        assert!(registry.get("does-not-exist").is_none());
    }

    #[test]
    fn start_agent_session_and_heartbeat() {
        let registry = SessionRegistry::new();
        let session = registry.start_agent_session(
            "claude-code",
            "test-client",
            SessionTransport::Mcp,
            Some(1234),
            PathBuf::from("/project"),
            SessionCapabilities::default(),
        );

        assert_eq!(session.vendor, "claude-code");
        assert!(registry.get_agent_session(&session.session_id).is_some());

        let ok = registry.heartbeat(&session.session_id);
        assert!(ok);

        let fake_id = SessionId::new();
        let ok = registry.heartbeat(&fake_id);
        assert!(!ok);
    }

    #[test]
    fn end_agent_session_releases_intents() {
        let registry = SessionRegistry::new();
        let session = registry.start_agent_session(
            "codex",
            "test",
            SessionTransport::Cli,
            None,
            PathBuf::from("/tmp"),
            SessionCapabilities::default(),
        );

        let intent = match registry.register_intent_checked(
            session.session_id,
            vec![IntentScope::Entity(EntityId::new())],
            LockType::Soft,
            "testing".into(),
            None,
        ) {
            IntentRegistrationAttempt::Registered { intent, .. } => intent,
            other => panic!("expected registered intent, got {other:?}"),
        };

        assert_eq!(
            registry.list_intents_for_session(&session.session_id).len(),
            1
        );

        let ended = registry.end_agent_session(&session.session_id);
        assert!(ended.is_some());
        assert!(registry.get_agent_session(&session.session_id).is_none());
        // Intents should be cleaned up.
        assert!(registry
            .list_intents_for_session(&session.session_id)
            .is_empty());
        // Suppress unused variable warning.
        let _ = intent;
    }

    #[test]
    fn replace_agent_sessions_and_intents_hydrates_daemon_state() {
        let registry = SessionRegistry::new();
        let session = AgentSession {
            session_id: SessionId::new(),
            vendor: "codex".into(),
            client_name: "daemon-proxy".into(),
            transport: SessionTransport::Mcp,
            pid: None,
            cwd: PathBuf::from("/repo"),
            started_at: Timestamp::now(),
            last_heartbeat: Timestamp::now(),
            capabilities: SessionCapabilities::default(),
        };
        let entity_id = EntityId::new();
        let intent = Intent {
            intent_id: IntentId::new(),
            session_id: session.session_id,
            scopes: vec![IntentScope::Entity(entity_id)],
            lock_type: LockType::Soft,
            task_description: "editing".into(),
            registered_at: Timestamp::now(),
            expires_at: None,
        };

        registry.replace_agent_sessions_and_intents(vec![session], vec![intent]);

        let traffic = registry.get_traffic_near_entity(&entity_id);
        assert_eq!(traffic.len(), 1);
        assert_eq!(traffic[0].vendor, "codex");
    }

    #[test]
    fn register_intent_requires_valid_session() {
        let registry = SessionRegistry::new();
        let fake_session = SessionId::new();

        let result = registry.register_intent_checked(
            fake_session,
            vec![IntentScope::Entity(EntityId::new())],
            LockType::Soft,
            "test".into(),
            None,
        );
        assert!(matches!(result, IntentRegistrationAttempt::SessionNotFound));
    }

    #[test]
    fn intent_registration_enforces_limit_and_foreign_hard_conflict() {
        let registry = SessionRegistry::new();
        registry.set_coordination_mode(CoordinationEnforcementMode::Enforce);
        let capabilities = SessionCapabilities {
            can_write: true,
            can_commit: true,
            max_concurrent_intents: 1,
            ..SessionCapabilities::default()
        };
        let first = registry.start_agent_session(
            "codex",
            "first",
            SessionTransport::Mcp,
            None,
            PathBuf::from("/tmp"),
            capabilities.clone(),
        );
        let second = registry.start_agent_session(
            "claude-code",
            "second",
            SessionTransport::Mcp,
            None,
            PathBuf::from("/tmp"),
            capabilities,
        );
        let entity = EntityId::new();

        let registered = registry.register_intent_checked(
            first.session_id,
            vec![IntentScope::Entity(entity)],
            LockType::Hard,
            "first write".into(),
            None,
        );
        assert!(matches!(
            registered,
            IntentRegistrationAttempt::Registered { .. }
        ));

        let limited = registry.register_intent_checked(
            first.session_id,
            vec![IntentScope::Entity(EntityId::new())],
            LockType::Hard,
            "second write".into(),
            None,
        );
        assert!(matches!(
            limited,
            IntentRegistrationAttempt::LimitExceeded {
                active: 1,
                limit: 1,
                ..
            }
        ));

        let blocked = registry.register_intent_checked(
            second.session_id,
            vec![IntentScope::Entity(entity)],
            LockType::Hard,
            "conflicting write".into(),
            None,
        );
        assert!(matches!(blocked, IntentRegistrationAttempt::Blocked { .. }));
    }

    #[test]
    fn hard_intent_requires_declared_write_capability() {
        let registry = SessionRegistry::new();
        registry.set_coordination_mode(CoordinationEnforcementMode::Enforce);
        let session = registry.start_agent_session(
            "read-only-agent",
            "reader",
            SessionTransport::Mcp,
            None,
            PathBuf::from("/tmp"),
            SessionCapabilities::default(),
        );
        let result = registry.register_intent_checked(
            session.session_id,
            vec![IntentScope::Entity(EntityId::new())],
            LockType::Hard,
            "must not block writers".into(),
            None,
        );
        assert!(matches!(
            result,
            IntentRegistrationAttempt::CapabilityDenied {
                capability: "can_write",
                ..
            }
        ));
        assert!(registry
            .list_intents_for_session(&session.session_id)
            .is_empty());
    }

    #[test]
    fn warn_and_off_modes_preserve_registration_compatibility() {
        let registry = SessionRegistry::new();
        let session = registry.start_agent_session(
            "read-only-agent",
            "reader",
            SessionTransport::Mcp,
            None,
            PathBuf::from("/tmp"),
            SessionCapabilities::default(),
        );

        registry.set_coordination_mode(CoordinationEnforcementMode::Warn);
        let warned = registry.register_intent_checked(
            session.session_id,
            vec![IntentScope::Entity(EntityId::new())],
            LockType::Hard,
            "warn compatibility".into(),
            None,
        );
        match warned {
            IntentRegistrationAttempt::Registered {
                policy_warnings, ..
            } => assert!(policy_warnings
                .iter()
                .any(|warning| warning.contains("can_write"))),
            other => panic!("warn mode should register with evidence, got {other:?}"),
        }

        registry.set_coordination_mode(CoordinationEnforcementMode::Off);
        let off = registry.register_intent_checked(
            session.session_id,
            vec![IntentScope::Entity(EntityId::new())],
            LockType::Hard,
            "off compatibility".into(),
            None,
        );
        match off {
            IntentRegistrationAttempt::Registered {
                policy_warnings, ..
            } => assert!(policy_warnings.is_empty()),
            other => panic!("off mode should register without evaluation, got {other:?}"),
        }
    }

    #[test]
    fn transaction_preflight_enforce_fails_closed_before_apply() {
        let registry = SessionRegistry::new();
        let capabilities = SessionCapabilities {
            can_write: true,
            can_commit: true,
            ..SessionCapabilities::default()
        };
        let owner = registry.start_agent_session(
            "claude-code",
            "owner",
            SessionTransport::Mcp,
            None,
            PathBuf::from("/tmp"),
            capabilities.clone(),
        );
        let caller = registry.start_agent_session(
            "codex",
            "caller",
            SessionTransport::Mcp,
            None,
            PathBuf::from("/tmp"),
            capabilities,
        );
        let entity = EntityId::new();
        assert!(matches!(
            registry.register_intent_checked(
                owner.session_id,
                vec![IntentScope::Entity(entity)],
                LockType::Hard,
                "owner write".into(),
                None,
            ),
            IntentRegistrationAttempt::Registered { .. }
        ));

        let denied = registry.evaluate_transaction_write_with_mode(
            &caller.session_id.to_string(),
            vec![IntentScope::Entity(entity)],
            CoordinationEnforcementMode::Enforce,
        );
        assert!(!denied.allowed);
        assert_eq!(denied.blocking_intents.len(), 1);
        assert!(denied.capability_violations.is_empty());
        assert!(!denied.coverage.contract_scopes);

        let warned = registry.evaluate_transaction_write_with_mode(
            &caller.session_id.to_string(),
            vec![IntentScope::Entity(entity)],
            CoordinationEnforcementMode::Warn,
        );
        assert!(warned.allowed);
        assert_eq!(warned.blocking_intents.len(), 1);

        let off = registry.evaluate_transaction_write_with_mode(
            "legacy-session",
            vec![IntentScope::Entity(entity)],
            CoordinationEnforcementMode::Off,
        );
        assert!(off.allowed);
        assert!(!off.evaluated);
        assert!(off.blocking_intents.is_empty());
        assert!(off.capability_violations.is_empty());

        let unknown = registry.evaluate_transaction_write_with_mode(
            "legacy-session",
            vec![IntentScope::Entity(EntityId::new())],
            CoordinationEnforcementMode::Enforce,
        );
        assert!(!unknown.allowed);
        assert!(!unknown.capability_violations.is_empty());
    }

    #[test]
    fn release_intent_checks_ownership() {
        let registry = SessionRegistry::new();
        let session = registry.start_agent_session(
            "claude-code",
            "test",
            SessionTransport::Mcp,
            None,
            PathBuf::from("/tmp"),
            SessionCapabilities {
                can_write: true,
                ..SessionCapabilities::default()
            },
        );

        let intent = match registry.register_intent_checked(
            session.session_id,
            vec![IntentScope::Entity(EntityId::new())],
            LockType::Hard,
            "editing".into(),
            None,
        ) {
            IntentRegistrationAttempt::Registered { intent, .. } => intent,
            other => panic!("expected registered intent, got {other:?}"),
        };

        // Wrong session cannot release.
        let other_session = SessionId::new();
        let result = registry.release_intent(&other_session, &intent.intent_id);
        assert!(result.is_none());

        // Correct session can release.
        let result = registry.release_intent(&session.session_id, &intent.intent_id);
        assert!(result.is_some());
    }

    #[test]
    fn check_traffic_returns_reports() {
        let registry = SessionRegistry::new();
        let session = registry.start_agent_session(
            "claude-code",
            "test",
            SessionTransport::Mcp,
            None,
            PathBuf::from("/tmp"),
            SessionCapabilities::default(),
        );

        let entity_id = EntityId::new();
        let scope = IntentScope::Entity(entity_id);
        registry.register_intent(
            session.session_id,
            vec![scope.clone()],
            LockType::Soft,
            "working on entity".into(),
            None,
        );

        let reports = registry.check_traffic(std::slice::from_ref(&scope));
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].active_intents.len(), 1);
        assert_eq!(reports[0].active_intents[0].vendor, "claude-code");

        // Unrelated scope returns empty traffic.
        let other_scope = IntentScope::Entity(EntityId::new());
        let reports = registry.check_traffic(&[other_scope]);
        assert_eq!(reports.len(), 1);
        assert!(reports[0].active_intents.is_empty());
    }

    #[test]
    fn get_traffic_near_entity() {
        let registry = SessionRegistry::new();
        let session = registry.start_agent_session(
            "gemini-cli",
            "test",
            SessionTransport::Mcp,
            None,
            PathBuf::from("/tmp"),
            SessionCapabilities {
                can_write: true,
                ..SessionCapabilities::default()
            },
        );

        let entity_id = EntityId::new();
        registry.register_intent(
            session.session_id,
            vec![IntentScope::Entity(entity_id)],
            LockType::Hard,
            "editing entity".into(),
            None,
        );

        let traffic = registry.get_traffic_near_entity(&entity_id);
        assert_eq!(traffic.len(), 1);
        assert_eq!(traffic[0].vendor, "gemini-cli");
        assert_eq!(traffic[0].lock_type, LockType::Hard);

        let other_id = EntityId::new();
        let traffic = registry.get_traffic_near_entity(&other_id);
        assert!(traffic.is_empty());
    }

    #[test]
    fn list_agent_sessions() {
        let registry = SessionRegistry::new();
        registry.start_agent_session(
            "claude-code",
            "a",
            SessionTransport::Mcp,
            None,
            PathBuf::from("/tmp"),
            SessionCapabilities::default(),
        );
        registry.start_agent_session(
            "codex",
            "b",
            SessionTransport::Cli,
            None,
            PathBuf::from("/tmp"),
            SessionCapabilities::default(),
        );

        let sessions = registry.list_agent_sessions();
        assert_eq!(sessions.len(), 2);
    }

    #[test]
    fn transaction_lifecycle() {
        let registry = SessionRegistry::new();
        registry.register("sess-1", "test");
        let tx = registry.begin_transaction("sess-1", "src/lib.rs").unwrap();
        assert_eq!(tx.session_id, "sess-1");
        assert_eq!(tx.scope, "src/lib.rs");
        assert_eq!(tx.state, "active");
        assert!(tx.staged_operations.is_empty());

        let op = McpMutationOperation {
            verb: "create".to_string(),
            target: "function".to_string(),
            payload: None,
            body: None,
            description: "add dummy function".to_string(),
        };
        let tx_staged = registry
            .stage_transaction(&tx.transaction_id, vec![op])
            .unwrap();
        assert_eq!(tx_staged.staged_operations.len(), 1);

        let tx_validated = registry.validate_transaction(&tx.transaction_id).unwrap();
        assert_eq!(tx_validated.state, "validated");

        let tx_committed = registry.commit_transaction(&tx.transaction_id).unwrap();
        assert_eq!(tx_committed.state, "committed");

        // Cannot stage on committed
        assert!(registry
            .stage_transaction(&tx.transaction_id, vec![])
            .is_err());
    }

    fn staged_edit(registry: &SessionRegistry, session: &str) -> McpTransaction {
        let tx = registry.begin_transaction(session, "src/lib.rs").unwrap();
        registry
            .stage_transaction(
                &tx.transaction_id,
                vec![McpMutationOperation {
                    verb: "update".to_string(),
                    target: "value".to_string(),
                    payload: None,
                    body: Some("pub fn value() -> u8 { 2 }".to_string()),
                    description: "replace the body".to_string(),
                }],
            )
            .unwrap()
    }

    #[test]
    fn abort_discards_the_staged_mutations_it_says_it_discards() {
        let registry = SessionRegistry::new();
        registry.register("sess-1", "test");
        let staged = staged_edit(&registry, "sess-1");
        assert_eq!(staged.staged_operations.len(), 1);

        let aborted = registry.abort_transaction(&staged.transaction_id).unwrap();
        assert_eq!(aborted.state, "aborted");
        assert!(
            aborted.staged_operations.is_empty(),
            "abort promises to discard the staged mutations, so the returned \
             transaction must not still carry them"
        );
        let stored = registry.get_transaction(&staged.transaction_id).unwrap();
        assert!(
            stored.staged_operations.is_empty(),
            "the registry's own copy must be discarded too, not just the clone \
             handed back to the caller"
        );
        assert!(
            registry
                .stage_transaction(&staged.transaction_id, vec![])
                .is_err(),
            "an aborted transaction must not accept further operations"
        );
    }

    #[test]
    fn abort_is_refused_once_a_commit_is_fenced_and_the_commit_stays_resumable() {
        let registry = SessionRegistry::new();
        registry.register("sess-1", "test");
        let staged = staged_edit(&registry, "sess-1");

        let fenced = registry
            .prepare_transaction_commit(&staged.transaction_id, "payload-digest")
            .unwrap();
        assert_eq!(fenced.state, "committing");

        let refused = registry
            .abort_transaction(&staged.transaction_id)
            .expect_err("a fenced transaction must not be abortable");
        assert!(
            refused.contains("committing"),
            "the refusal must name the state that blocks it: {refused}"
        );
        assert!(
            refused.contains("kin_transaction_commit"),
            "the refusal must name the call that owns a fenced transaction: {refused}"
        );

        // Refusing is only worth anything if it keeps the documented recovery
        // reachable: re-entering the fence with the same digest still resumes,
        // and the payload it resumes is the one that was fenced.
        let resumed = registry
            .prepare_transaction_commit(&staged.transaction_id, "payload-digest")
            .expect("the fenced commit must remain resumable after a refused abort");
        assert_eq!(resumed.state, "committing");
        assert_eq!(
            resumed.staged_operations.len(),
            1,
            "a refused abort must not touch the fenced payload"
        );
        assert_eq!(
            registry
                .commit_transaction(&staged.transaction_id)
                .unwrap()
                .state,
            "committed"
        );
    }

    #[test]
    fn abort_is_refused_on_a_terminal_transaction() {
        let registry = SessionRegistry::new();
        registry.register("sess-1", "test");

        let committed = staged_edit(&registry, "sess-1");
        registry
            .commit_transaction(&committed.transaction_id)
            .unwrap();
        let refused = registry
            .abort_transaction(&committed.transaction_id)
            .expect_err(
                "aborting a committed transaction would record a receipt that never happened",
            );
        assert!(refused.contains("committed"), "{refused}");
        assert_eq!(
            registry
                .get_transaction(&committed.transaction_id)
                .unwrap()
                .state,
            "committed",
            "a refused abort must not relabel the transaction"
        );

        let aborted = staged_edit(&registry, "sess-1");
        registry.abort_transaction(&aborted.transaction_id).unwrap();
        assert!(
            registry.abort_transaction(&aborted.transaction_id).is_err(),
            "a second abort must be refused rather than silently succeeding"
        );
    }

    #[test]
    fn abort_of_an_unknown_transaction_names_the_id() {
        let registry = SessionRegistry::new();
        let err = registry
            .abort_transaction("no-such-transaction")
            .expect_err("aborting an id that names nothing must fail");
        assert!(
            err.contains("no-such-transaction"),
            "the failure must name the id the caller passed: {err}"
        );
        assert!(err.contains("not found"), "{err}");
    }

    // ── Stage-time validation (D.7 Track A) ──────────────────────────────────

    fn entity_named(name: &str) -> kin_model::Entity {
        use kin_model::entity::{
            EntityKind, EntityMetadata, EntityRole, FingerprintAlgorithm, SemanticFingerprint,
            Visibility,
        };
        use kin_model::ids::{Hash256, LanguageId};
        kin_model::Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0; 32]),
                signature_hash: Hash256::from_bytes([0; 32]),
                behavior_hash: Hash256::from_bytes([0; 32]),
                equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: None,
            span: None,
            signature: format!("fn {name}()"),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    fn op(verb: &str, payload: Option<McpMutationPayload>) -> McpMutationOperation {
        McpMutationOperation {
            verb: verb.to_string(),
            target: "function".to_string(),
            payload,
            body: None,
            description: "d".to_string(),
        }
    }

    #[test]
    fn parse_staged_operations_names_a_field_it_does_not_model() {
        // The whole point: a misspelled `body` used to decode to no body at
        // all, so the operation staged clean and committed nothing.
        let error = parse_staged_operations(&serde_json::json!([{
            "verb": "update",
            "target": "value",
            "content": "pub fn value() -> u8 { 2 }",
            "description": "misspelled body key",
        }]))
        .expect_err("an unknown field must be refused, not dropped");
        assert!(error.contains("'content'"), "got: {error}");
        assert!(error.contains("body"), "the fix must be named: {error}");
    }

    #[test]
    fn parse_staged_operations_rejects_a_non_object_element() {
        let error = parse_staged_operations(&serde_json::json!(["update value"]))
            .expect_err("a string element is not an operation");
        assert!(error.contains("element #0"), "got: {error}");
    }

    #[test]
    fn staged_operations_match_distinguishes_a_resume_from_an_edit() {
        let staged = vec![op(
            "update",
            Some(McpMutationPayload::Entity(entity_named("foo"))),
        )];
        assert!(staged_operations_match(&staged, &staged.clone()));

        let mut edited = staged.clone();
        edited[0].body = Some("pub fn foo() {}".to_string());
        assert!(
            !staged_operations_match(&staged, &edited),
            "a changed body is a different payload, not a resume"
        );
        assert!(!staged_operations_match(&staged, &[]));
    }

    #[test]
    fn commit_refusal_renders_prose_and_machine_readable_evidence() {
        let refusal = CommitRefusal::new(
            CommitRefusalCode::SourceBodyRequiresDaemonCommit,
            "tx-1",
            vec!["operation #0 ('update'): needs projection".to_string()],
        );
        let rendered = refusal.render();
        assert!(rendered.contains("tx-1"));
        assert!(rendered.contains("needs projection"));

        let evidence: CommitRefusal =
            serde_json::from_str(rendered.lines().next_back().unwrap()).unwrap();
        assert_eq!(evidence.schema, CommitRefusal::SCHEMA);
        assert_eq!(
            evidence.code,
            CommitRefusalCode::SourceBodyRequiresDaemonCommit
        );
        assert!(!evidence.applied);
        assert_eq!(evidence.operations.len(), 1);
    }

    #[test]
    fn carries_source_body_covers_every_shape_whose_substance_is_the_body() {
        let mut payload_less = op("update", None);
        payload_less.body = Some("pub fn value() {}".to_string());
        assert!(carries_source_body(&payload_less));

        let mut with_payload = op(
            "update",
            Some(McpMutationPayload::Entity(entity_named("value"))),
        );
        with_payload.body = Some("pub fn value() {}".to_string());
        assert!(
            carries_source_body(&with_payload),
            "an entity payload does not make the body optional"
        );

        let mut blank = with_payload.clone();
        blank.body = Some("   \n".to_string());
        assert!(!carries_source_body(&blank), "whitespace is not source");
        assert!(!carries_source_body(&op("update", None)));
    }

    #[test]
    fn validate_staged_operations_accepts_well_formed_and_empty() {
        assert!(validate_staged_operations(&[]).is_ok());
        let ops = vec![op(
            "create",
            Some(McpMutationPayload::Entity(entity_named("foo"))),
        )];
        assert!(validate_staged_operations(&ops).is_ok());
    }

    #[test]
    fn validate_staged_operations_rejects_missing_payload() {
        // The commit path silently skips payload-less ops; stage time must not.
        // (A payload-less UPDATE with target and body is the one valid form.)
        let err = validate_staged_operations(&[op("create", None)]).unwrap_err();
        assert!(err.contains("missing payload"), "{err}");
        assert!(err.contains("entity source edit"), "{err}");
    }

    #[test]
    fn validate_staged_operations_rejects_unknown_and_empty_verb() {
        let unknown = validate_staged_operations(&[op(
            "frobnicate",
            Some(McpMutationPayload::Entity(entity_named("foo"))),
        )])
        .unwrap_err();
        assert!(unknown.contains("unknown verb 'frobnicate'"), "{unknown}");

        let empty = validate_staged_operations(&[op(
            "  ",
            Some(McpMutationPayload::Entity(entity_named("foo"))),
        )])
        .unwrap_err();
        assert!(empty.contains("missing verb"), "{empty}");
    }

    #[test]
    fn validate_staged_operations_rejects_empty_entity_name() {
        let err = validate_staged_operations(&[op(
            "create",
            Some(McpMutationPayload::Entity(entity_named("   "))),
        )])
        .unwrap_err();
        assert!(err.contains("empty name"), "{err}");
    }

    #[test]
    fn validate_staged_operations_reports_offending_index() {
        let ops = vec![
            op(
                "create",
                Some(McpMutationPayload::Entity(entity_named("ok"))),
            ),
            op("create", None),
        ];
        let err = validate_staged_operations(&ops).unwrap_err();
        assert!(err.contains("operation #1"), "{err}");
    }

    #[test]
    fn validate_staged_operations_rejects_relation_modify() {
        // Relation update/modify is committable-looking but the commit path drops
        // it; stage time must reject it now, not just at commit.
        for verb in ["modify", "update"] {
            let err =
                validate_staged_operations(&[op(verb, Some(relation_payload()))]).unwrap_err();
            assert!(
                err.contains("not committable for relation payloads"),
                "verb {verb}: {err}"
            );
        }
    }

    #[test]
    fn validate_staged_operations_rejects_blob_payload() {
        let err =
            validate_staged_operations(&[op("create", Some(McpMutationPayload::Blob(vec![1, 2])))])
                .unwrap_err();
        assert!(
            err.contains("blob payloads are not yet committable"),
            "{err}"
        );
    }

    #[test]
    fn validate_staged_operations_accepts_relation_add_remove() {
        // create/add and delete/remove ARE committable for relations and must
        // still pass stage time.
        for verb in ["add", "create", "remove", "delete"] {
            assert!(
                validate_staged_operations(&[op(verb, Some(relation_payload()))]).is_ok(),
                "relation verb {verb} should stage cleanly"
            );
        }
    }

    #[test]
    fn stage_time_rejection_is_superset_of_commit_drop() {
        // Parity invariant: any batch the commit path would reject as
        // uncommittable must also be rejected at stage time. Guards against the
        // stage/commit asymmetry where an op stages green then drops at commit.
        let drop_batches = vec![
            vec![op("modify", Some(relation_payload()))],
            vec![op("update", Some(relation_payload()))],
            vec![op("create", Some(McpMutationPayload::Blob(vec![9])))],
            vec![op("create", None)],
            vec![op(
                "frobnicate",
                Some(McpMutationPayload::Entity(entity_named("x"))),
            )],
        ];
        for ops in &drop_batches {
            assert!(
                !uncommittable_operations(ops).is_empty(),
                "fixture should be uncommittable: {ops:?}"
            );
            assert!(
                validate_staged_operations(ops).is_err(),
                "commit would drop this but stage accepted it: {ops:?}"
            );
        }
    }

    fn relation_payload() -> McpMutationPayload {
        McpMutationPayload::Relation {
            from: EntityId::new(),
            to: EntityId::new(),
            kind: kin_model::relation::RelationKind::Calls,
        }
    }

    #[test]
    fn uncommittable_operations_accepts_commit_supported_payloads() {
        let ops = vec![
            op(
                "create",
                Some(McpMutationPayload::Entity(entity_named("foo"))),
            ),
            op("add", Some(relation_payload())),
            op("remove", Some(relation_payload())),
        ];
        assert!(uncommittable_operations(&ops).is_empty());
    }

    #[test]
    fn uncommittable_operations_reports_commit_silent_drop_cases() {
        let ops = vec![
            op("modify", Some(relation_payload())),
            op("create", Some(McpMutationPayload::Blob(vec![1, 2, 3]))),
        ];
        let reasons = uncommittable_operations(&ops);
        assert_eq!(reasons.len(), 2);
        assert!(reasons[0].contains("operation #0"), "{reasons:?}");
        assert!(
            reasons[0].contains("not committable for relation payloads"),
            "{reasons:?}"
        );
        assert!(reasons[1].contains("operation #1"), "{reasons:?}");
        assert!(reasons[1].contains("blob payloads"), "{reasons:?}");
    }
}

#[cfg(test)]
mod target_body_update_tests {
    use super::*;

    fn target_op(verb: &str, target: &str, body: Option<&str>) -> McpMutationOperation {
        McpMutationOperation {
            verb: verb.to_string(),
            target: target.to_string(),
            payload: None,
            body: body.map(str::to_string),
            description: "test".to_string(),
        }
    }

    #[test]
    fn target_body_update_is_recognized_and_committable() {
        let op = target_op("update", "resolve_binary", Some("fn resolve_binary() {}"));
        assert!(is_target_body_update(&op));
        assert!(uncommittable_reason(&op).is_none());
        assert!(validate_staged_operations(std::slice::from_ref(&op)).is_ok());
    }

    #[test]
    fn target_body_update_requires_verb_target_and_body() {
        // "create" used to be a wrong verb for this shape; it now names the
        // new-source-file operation (`is_new_source_file`), so a payload-less
        // "create" with a target and body is a valid create, not a rejected
        // update. "upsert" stays wrong on purpose: it is deliberately not one
        // of the create verbs (see `is_new_source_file`), so it still matches
        // neither payload-less shape and must still fail closed.
        let wrong_verb = target_op("upsert", "resolve_binary", Some("x"));
        assert!(!is_target_body_update(&wrong_verb));
        assert!(!is_new_source_file(&wrong_verb));
        assert!(validate_staged_operations(std::slice::from_ref(&wrong_verb)).is_err());

        let no_target = target_op("update", "", Some("x"));
        assert!(!is_target_body_update(&no_target));
        assert!(validate_staged_operations(std::slice::from_ref(&no_target)).is_err());

        let empty_body = target_op("update", "resolve_binary", Some("   "));
        assert!(!is_target_body_update(&empty_body));
        assert!(validate_staged_operations(std::slice::from_ref(&empty_body)).is_err());

        let no_body = target_op("update", "resolve_binary", None);
        assert!(!is_target_body_update(&no_body));
        assert!(validate_staged_operations(std::slice::from_ref(&no_body)).is_err());
    }

    #[test]
    fn begin_transaction_requires_a_known_session() {
        let registry = SessionRegistry::new();
        assert!(
            registry.begin_transaction("", "scope").is_err(),
            "empty session id must be rejected"
        );
        assert!(
            registry
                .begin_transaction("no-such-session", "scope")
                .is_err(),
            "unknown session id must be rejected"
        );

        let session = registry.start_agent_session(
            "anthropic",
            "test",
            SessionTransport::Mcp,
            None,
            PathBuf::from("/tmp"),
            SessionCapabilities::default(),
        );
        let ok = registry.begin_transaction(&session.session_id.to_string(), "scope");
        assert!(ok.is_ok(), "known agent session must be accepted: {ok:?}");

        let legacy = registry.register("legacy-session", "legacy");
        let ok = registry.begin_transaction(&legacy, "scope");
        assert!(
            ok.is_ok(),
            "legacy registered session must be accepted: {ok:?}"
        );
    }
}
