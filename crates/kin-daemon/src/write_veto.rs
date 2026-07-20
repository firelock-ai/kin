// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Rung-3 write veto: pre-write rejection of agent writes that touch an entity
//! or artifact scope held under another session's *hard* intent.
//!
//! ## What this enforces today
//!
//! The daemon already *detects* hard-intent collisions during reconcile: the
//! reconciler's traffic checker reverts the overlay so a blocked write is never
//! folded into the graph. What it did **not** do is *reject* the write at the
//! HTTP boundary — `vfs_write_notify` reported a collision as a soft
//! `200 {reindexed:false}` notification *after* the file had already landed on
//! disk. That is "post-write notification, not pre-write rejection".
//!
//! With `KIN_WRITE_VETO=enforce`, the agent-write apply path runs
//! [`evaluate_write_veto`] *before* applying the overlay and returns a
//! structured `409 Conflict` naming the blocking intent(s)/scope(s). The set of
//! "contracts" checkable with today's intent data is exactly entity/artifact
//! scope containment versus other sessions' hard intents — so that is what this
//! builds, and nothing more.
//!
//! ## What remains future work
//!
//! - Content-hash / semantic-contract vetoes (e.g. "this edit changes a public
//!   signature under a frozen contract"): there is no contract-content data at
//!   the apply boundary today.
//! - [`IntentScope::Contract`] vetoes: the model has the variant, but file
//!   writes only ever produce `Entity` / `Artifact` touched-scopes, so nothing
//!   emits a `Contract` touched-scope to check against.
//!
//! The veto **warns by default**: with `KIN_WRITE_VETO` unset it evaluates
//! collisions and, on a would-be veto, logs and annotates the response envelope
//! (`write_veto_warning`) naming the blocking intent(s) — but the write still
//! proceeds (no `409`). `KIN_WRITE_VETO=enforce` upgrades the warn to a pre-write
//! `409`; `KIN_WRITE_VETO=off` restores the byte-identical pre-veto path (no
//! evaluation, no annotation).

use kin_model::session::{Intent, IntentScope, IntentSummary, LockType};
use kin_model::SessionId;

/// How the write veto reacts when a write collides with a foreign hard intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteVetoMode {
    /// Explicit escape hatch (`KIN_WRITE_VETO=off`). The veto never evaluates;
    /// the apply path is byte-identical to pre-veto behavior.
    Off,
    /// Default. A would-be veto is logged and annotated onto the response
    /// envelope ("you would have been blocked, and by whom") but the write is
    /// NOT rejected — no `409`.
    Warn,
    /// Reject a write that touches a scope held under a foreign hard intent
    /// with a pre-write `409` (`KIN_WRITE_VETO=enforce`).
    Enforce,
}

impl Default for WriteVetoMode {
    fn default() -> Self {
        Self::Warn
    }
}

impl WriteVetoMode {
    /// Resolve the mode from the `KIN_WRITE_VETO` environment variable.
    pub fn from_env() -> Self {
        Self::parse(std::env::var("KIN_WRITE_VETO").ok().as_deref())
    }

    /// Parse a raw flag value into a mode. `enforce` selects hard rejection;
    /// `off` selects [`WriteVetoMode::Off`]; every other value — including
    /// `None`, empty, `warn`, and unrecognized strings — resolves to the default
    /// [`WriteVetoMode::Warn`], matching the env registry's enum fallback (a
    /// value outside the documented set falls back to the default at the read
    /// site). Pure, so it is testable without touching process env.
    fn parse(raw: Option<&str>) -> Self {
        match raw.map(str::trim) {
            Some(v) if v.eq_ignore_ascii_case("enforce") => Self::Enforce,
            Some(v) if v.eq_ignore_ascii_case("off") => Self::Off,
            _ => Self::Warn,
        }
    }

    /// Whether the veto is in enforcing mode (rejects with `409`).
    pub fn is_enforcing(self) -> bool {
        matches!(self, Self::Enforce)
    }

    /// Whether the veto is fully off (never evaluates a collision).
    pub fn is_off(self) -> bool {
        matches!(self, Self::Off)
    }

    /// Whether the veto evaluates collisions at all (warn or enforce). When
    /// false, the apply path stays byte-identical to pre-veto behavior.
    pub fn evaluates(self) -> bool {
        !self.is_off()
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Warn => "warn",
            Self::Enforce => "enforce",
        }
    }
}

/// Outcome of [`evaluate_write_veto`].
#[derive(Debug, Clone)]
pub enum WriteVetoDecision {
    /// No foreign hard intent overlaps the touched scopes; the write proceeds.
    Allow,
    /// At least one foreign hard intent overlaps a touched scope. Carries the
    /// blocking intents for the structured rejection body.
    Deny {
        /// The foreign hard intents whose scopes overlap the write.
        blocking: Vec<IntentSummary>,
    },
}

impl WriteVetoDecision {
    /// Whether the write is denied.
    pub fn is_denied(&self) -> bool {
        matches!(self, Self::Deny { .. })
    }
}

/// Decide whether a write touching `touched` scopes may proceed, given the
/// currently active `intents` and the `caller` session performing the write.
///
/// A write is denied iff some intent satisfies all of:
/// - it is owned by a *different* session than `caller` (own-write guard: a
///   session is never blocked by its own intent), and
/// - its lock type is [`LockType::Hard`] (soft intents are advisory), and
/// - one of its scopes equals one of the `touched` scopes.
///
/// This is a pure function: it performs no I/O and is the single source of
/// truth for both the veto decision and the rejection body.
pub fn evaluate_write_veto(
    intents: &[Intent],
    touched: &[IntentScope],
    caller: Option<SessionId>,
) -> WriteVetoDecision {
    let mut blocking = Vec::new();
    for intent in intents {
        // Own-write guard: an agent must never be blocked by its own intent.
        if let Some(caller) = caller {
            if intent.session_id == caller {
                continue;
            }
        }
        if intent.lock_type != LockType::Hard {
            continue;
        }
        if intent.scopes.iter().any(|s| touched.contains(s)) {
            blocking.push(summarize(intent));
        }
    }

    if blocking.is_empty() {
        WriteVetoDecision::Allow
    } else {
        WriteVetoDecision::Deny { blocking }
    }
}

/// Project an [`Intent`] into the display-oriented [`IntentSummary`] used in
/// the rejection body. The `vendor` field is left empty — it is not carried on
/// the active-intent record and is informational only.
fn summarize(intent: &Intent) -> IntentSummary {
    IntentSummary {
        intent_id: intent.intent_id,
        session_id: intent.session_id,
        vendor: String::new(),
        task_description: intent.task_description.clone(),
        lock_type: intent.lock_type,
        registered_at: intent.registered_at.clone(),
    }
}

/// Serialize the blocking intents into the attribution array shared by the
/// enforce `409` body and the warn annotation: session, intent, lock, and task
/// so an agent can see exactly who holds the colliding scope.
fn blocking_intents_json(blocking: &[IntentSummary]) -> Vec<serde_json::Value> {
    blocking
        .iter()
        .map(|b| {
            serde_json::json!({
                "intent_id": b.intent_id.to_string(),
                "session_id": b.session_id.to_string(),
                "lock_type": format!("{:?}", b.lock_type),
                "task_description": b.task_description,
            })
        })
        .collect()
}

/// Build the structured `409 Conflict` JSON body naming the blocking intents.
///
/// Mirrors the shape of the existing commit-path `lease_conflict` body so a
/// client can handle both with one code path, but uses a distinct
/// `error: "write_veto"` code so the agent-write rung is identifiable.
pub fn veto_conflict_body(file_path: &str, blocking: &[IntentSummary]) -> serde_json::Value {
    serde_json::json!({
        "error": "write_veto",
        "conflict_type": "HardCollision",
        "file_path": file_path,
        "blocking_intents": blocking_intents_json(blocking),
        "message": format!(
            "write blocked: {} scope(s) held by active foreign hard intent(s)",
            blocking.len()
        ),
    })
}

/// Build the `write_veto_warning` annotation attached to a write response under
/// warn mode. The write PROCEEDED, but the annotation names the foreign hard
/// intent(s) that WOULD have rejected it under `enforce`, so an agent (and the
/// MCP envelope that carries this payload) sees the collision without a `409`.
pub fn veto_warning_annotation(file_path: &str, blocking: &[IntentSummary]) -> serde_json::Value {
    serde_json::json!({
        "would_block": true,
        "conflict_type": "HardCollision",
        "file_path": file_path,
        "blocking_intents": blocking_intents_json(blocking),
        "message": format!(
            "write would be rejected under KIN_WRITE_VETO=enforce: {} scope(s) held by \
             active foreign hard intent(s); the write proceeded (warn mode)",
            blocking.len()
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{EntityId, FilePathId, IntentId, Timestamp};

    fn intent(session: SessionId, scope: IntentScope, lock: LockType) -> Intent {
        Intent {
            intent_id: IntentId::new(),
            session_id: session,
            scopes: vec![scope],
            lock_type: lock,
            task_description: "test task".into(),
            registered_at: Timestamp::now(),
            expires_at: None,
        }
    }

    #[test]
    fn mode_parse_maps_off_warn_enforce() {
        // Default (unset / empty / unrecognized, incl. "0"/"false") → Warn.
        assert_eq!(WriteVetoMode::parse(None), WriteVetoMode::Warn);
        assert_eq!(WriteVetoMode::parse(Some("")), WriteVetoMode::Warn);
        assert_eq!(WriteVetoMode::parse(Some("warn")), WriteVetoMode::Warn);
        assert_eq!(WriteVetoMode::parse(Some("banana")), WriteVetoMode::Warn);
        assert_eq!(WriteVetoMode::parse(Some("0")), WriteVetoMode::Warn);
        assert_eq!(WriteVetoMode::parse(Some("false")), WriteVetoMode::Warn);
        // The documented off-switch → Off (case-insensitive, trimmed).
        assert_eq!(WriteVetoMode::parse(Some("off")), WriteVetoMode::Off);
        assert_eq!(WriteVetoMode::parse(Some("  OFF  ")), WriteVetoMode::Off);
        // Enforce is explicit only.
        assert_eq!(
            WriteVetoMode::parse(Some("enforce")),
            WriteVetoMode::Enforce
        );
        assert_eq!(
            WriteVetoMode::parse(Some("  ENFORCE  ")),
            WriteVetoMode::Enforce
        );
        // Predicates + default.
        assert_eq!(WriteVetoMode::default(), WriteVetoMode::Warn);
        assert!(!WriteVetoMode::Off.is_enforcing());
        assert!(!WriteVetoMode::Warn.is_enforcing());
        assert!(WriteVetoMode::Enforce.is_enforcing());
        assert!(WriteVetoMode::Off.is_off());
        assert!(!WriteVetoMode::Warn.is_off());
        assert!(!WriteVetoMode::Enforce.is_off());
        assert!(!WriteVetoMode::Off.evaluates());
        assert!(WriteVetoMode::Warn.evaluates());
        assert!(WriteVetoMode::Enforce.evaluates());
    }

    #[test]
    fn foreign_hard_intent_on_entity_denies() {
        let entity = EntityId::new();
        let caller = SessionId::new();
        let other = SessionId::new();
        let intents = vec![intent(other, IntentScope::Entity(entity), LockType::Hard)];
        let touched = vec![IntentScope::Entity(entity)];

        let decision = evaluate_write_veto(&intents, &touched, Some(caller));
        match decision {
            WriteVetoDecision::Deny { blocking } => {
                assert_eq!(blocking.len(), 1);
                assert_eq!(blocking[0].session_id, other);
                assert_eq!(blocking[0].lock_type, LockType::Hard);
            }
            WriteVetoDecision::Allow => panic!("expected Deny on foreign hard intent"),
        }
    }

    #[test]
    fn foreign_hard_intent_on_artifact_denies() {
        let file = FilePathId::new("src/lib.rs");
        let caller = SessionId::new();
        let other = SessionId::new();
        let intents = vec![intent(
            other,
            IntentScope::Artifact(file.clone()),
            LockType::Hard,
        )];
        let touched = vec![IntentScope::Artifact(file)];

        assert!(evaluate_write_veto(&intents, &touched, Some(caller)).is_denied());
    }

    #[test]
    fn own_hard_intent_is_allowed() {
        // The critical own-write guard: a session editing a file it has itself
        // hard-locked must never be blocked.
        let entity = EntityId::new();
        let caller = SessionId::new();
        let intents = vec![intent(caller, IntentScope::Entity(entity), LockType::Hard)];
        let touched = vec![IntentScope::Entity(entity)];

        assert!(!evaluate_write_veto(&intents, &touched, Some(caller)).is_denied());
    }

    #[test]
    fn foreign_soft_intent_is_allowed() {
        // Soft intents are advisory; they warn elsewhere but never veto a write.
        let entity = EntityId::new();
        let caller = SessionId::new();
        let other = SessionId::new();
        let intents = vec![intent(other, IntentScope::Entity(entity), LockType::Soft)];
        let touched = vec![IntentScope::Entity(entity)];

        assert!(!evaluate_write_veto(&intents, &touched, Some(caller)).is_denied());
    }

    #[test]
    fn non_overlapping_scope_is_allowed() {
        let caller = SessionId::new();
        let other = SessionId::new();
        let intents = vec![intent(
            other,
            IntentScope::Entity(EntityId::new()),
            LockType::Hard,
        )];
        // Touching a *different* entity than the one held.
        let touched = vec![IntentScope::Entity(EntityId::new())];

        assert!(!evaluate_write_veto(&intents, &touched, Some(caller)).is_denied());
    }

    #[test]
    fn no_caller_treats_all_intents_as_foreign() {
        // When the write carries no session attribution, no own-write exclusion
        // applies, so a present hard intent blocks. (Only reachable under
        // KIN_WRITE_VETO=enforce; the default path never calls this.)
        let entity = EntityId::new();
        let other = SessionId::new();
        let intents = vec![intent(other, IntentScope::Entity(entity), LockType::Hard)];
        let touched = vec![IntentScope::Entity(entity)];

        assert!(evaluate_write_veto(&intents, &touched, None).is_denied());
    }

    #[test]
    fn no_intents_is_allowed() {
        let touched = vec![IntentScope::Entity(EntityId::new())];
        assert!(!evaluate_write_veto(&[], &touched, Some(SessionId::new())).is_denied());
    }

    #[test]
    fn conflict_body_names_blocking_intent() {
        let other = SessionId::new();
        let blocking = vec![summarize(&intent(
            other,
            IntentScope::Entity(EntityId::new()),
            LockType::Hard,
        ))];
        let body = veto_conflict_body("src/lib.rs", &blocking);

        assert_eq!(body["error"], "write_veto");
        assert_eq!(body["file_path"], "src/lib.rs");
        assert_eq!(body["blocking_intents"].as_array().unwrap().len(), 1);
        assert_eq!(body["blocking_intents"][0]["session_id"], other.to_string());
        assert_eq!(body["blocking_intents"][0]["lock_type"], "Hard");
    }

    #[test]
    fn warning_annotation_names_blocking_intent_without_error() {
        let other = SessionId::new();
        let blocking = vec![summarize(&intent(
            other,
            IntentScope::Entity(EntityId::new()),
            LockType::Hard,
        ))];
        let ann = veto_warning_annotation("src/lib.rs", &blocking);

        // Warn annotation names who-would-block, carries no error code, and
        // never claims the write was rejected.
        assert_eq!(ann["would_block"], true);
        assert!(ann.get("error").is_none());
        assert_eq!(ann["file_path"], "src/lib.rs");
        assert_eq!(ann["blocking_intents"].as_array().unwrap().len(), 1);
        assert_eq!(ann["blocking_intents"][0]["session_id"], other.to_string());
        assert_eq!(ann["blocking_intents"][0]["lock_type"], "Hard");
    }
}
