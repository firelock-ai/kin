// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Background daemon for Kin.
//!
//! Owns the graph lifecycle, runs the file watcher and
//! reconciliation loop, and exposes an HTTP API for CLI, MCP, and UI.
//!
//! Phase 7 adds session coordination and intent arbitration via
//! the `SessionCoordinator`.
//!
//! # Freshness & coverage signals
//!
//! Two honest signals let clients (and the MCP envelope) judge how fresh and
//! how complete a retrieval answer is:
//!
//! - **`graph_generation`** on `GET /health`: the monotonic snapshot generation
//!   marker (`.kin/kindb/head-generation`), bumped on each committed authority
//!   generation. This
//!   is the *universal* freshness token — it applies to every retrieval payload
//!   because the MCP envelope wraps each tool result and can lift it into
//!   `graph_as_of`. (The kin-mcp `Envelope::with_health` lift that reads this
//!   field lives in the kin-mcp lane.)
//! - **`semantic_coverage`** on retrieval payloads: the fraction of the graph
//!   that has embeddings indexed (`indexed / total`). It is only meaningful for
//!   *embedding-backed* retrieval. In the daemon the sole embedding-backed
//!   retrieval payload is `semantic_locate` (`build_semantic_locate_result`),
//!   which already emits it. `semantic_search` is a name/metadata filter and
//!   the structural tools (references, neighborhood, trace, impact, dead-code)
//!   do not consult the vector index, so attaching `semantic_coverage` to them
//!   would misrepresent — those payloads rely on `graph_generation`/`graph_as_of`
//!   for freshness instead. Retrieval payloads whose constructors live in
//!   kin-cli / kin-mcp are out of this crate; their coverage is owned by those
//!   lanes.
//!
//! # Write veto (`KIN_WRITE_VETO`)
//!
//! Rung-3 of the write path. The agent-write apply paths (`POST /vfs/write-notify`,
//! `POST /vfs/file-changed`, and MCP `kin_transaction_commit`) evaluate whether
//! a write touches a scope held under another session's hard intent and, by
//! default, surface the collision without blocking. Intent registration,
//! automatic expiry/orphan sweeps, and transaction apply share the same gates,
//! so enforce mode cannot race lifecycle cleanup against preflight and graph
//! apply.
//!
//! - Default (unset): **warn**. The write still proceeds — a colliding write is
//!   declined by the reconciler's own check and reported as a soft notification —
//!   but a would-be veto is logged and the response is annotated with
//!   `write_veto_warning` naming the blocking intent(s), so an agent sees the
//!   collision it would hit under enforce.
//! - `KIN_WRITE_VETO=enforce`: the write is rejected *before* it is folded into
//!   the graph with a structured `409 Conflict` (`error: "write_veto"`) naming
//!   the blocking intent(s). Missing, mismatched, unknown, or read-only VFS
//!   caller identity is rejected first with `403 Forbidden`.
//! - `KIN_WRITE_VETO=off`: the veto never evaluates and never annotates or
//!   rejects. MCP transaction responses still carry the additive coordination
//!   coverage attestation with `evaluated:false`.
//!
//! What rung-3 enforces today is exactly **entity/artifact scope containment
//! versus other sessions' hard intents** — the only "contract" expressible with
//! current intent data. MCP relation mutations cover their endpoint entities.
//! A session is never blocked by its own intent, and soft
//! intents stay advisory. Content-hash and semantic-contract (e.g.
//! [`IntentScope::Contract`](kin_model::session::IntentScope)) vetoes are future
//! work: no contract-content data exists at the apply boundary, and file writes
//! do not yet emit `Contract` touched-scopes. See [`write_veto`] for the
//! evaluator.
//!
//! ## Write-path inventory
//!
//! Every state-mutating route and its current *pre-write* gate, as of this
//! change. The two VFS apply paths (`vfs_write_notify`, `vfs_file_changed`)
//! evaluate the write-veto (default **warn** → annotate; `enforce` → pre-write
//! 409; `off` → byte-identical) and `graph_commit` is always-on; the rest either
//! rely on the reconciler's own soft-block, gate upstream, or are out of this
//! crate's veto scope.
//!
//! - `POST /vfs/write-notify` (`vfs_write_notify`): **write-veto**. Default
//!   **warn** annotates the soft `200 {reindexed:false}` with `write_veto_warning`
//!   on a would-be veto; `KIN_WRITE_VETO=enforce` upgrades to a pre-write `409`;
//!   `KIN_WRITE_VETO=off` restores the byte-identical soft path.
//! - `POST /vfs/file-changed` (`vfs_file_changed`): **write-veto**, same
//!   default-warn / enforce-409 / off ladder (soft `200 {status:"error"}` under
//!   warn/off). The general-purpose sibling of write-notify; gated through the
//!   same shared `write_veto_precheck` / `write_veto_collision_response` helpers
//!   so the two paths cannot drift and enforce cannot be bypassed by choosing one
//!   endpoint over the other.
//! - `POST /graph/commit` (`graph_commit`): always-on lease **409** on a
//!   foreign hard intent (the CLI semantic-commit path).
//! - `POST /commands/commit` (`command_commit`): commits the already-reconciled
//!   overlay; relies on the reconcile loop's upstream collision gating; no
//!   separate pre-write veto.
//! - `POST /reconcile` (`reconcile`): delegates to the kin-cli reconcile path; a
//!   scoped reconcile mutates a session-private graph isolated from HEAD.
//! - `POST /graph/mutations` (`graph_mutations`): work-item / annotation / audit
//!   metadata, not entity truth; ungated.
//! - `PUT /v2/graph/branches/{name}/head`: compare-and-swap against the live
//!   head plus ancestry validation; stale, sideways, and backward moves fail
//!   before mutation. The v1 mutation route is retired with `410 Gone`.
//!   `DELETE /graph/branches/{name}` remains a ref-management operation outside
//!   the entity write-veto policy.
//! - `POST /mcp/tools/call` (`kin_transaction_commit`): **write-veto** before
//!   exact repository-v6 publication, plus `can_write`/`can_commit` capability
//!   checks. Existing source entity bodies are spliced and reparsed from
//!   repository CAS before one journaled tree/change/ref transaction; the
//!   working filesystem is never semantic answer authority. Enforce mode fails
//!   closed for an unknown/non-rich session. Exact entity, entity-file artifact,
//!   and relation-endpoint scopes are covered; contract scopes and
//!   non-transaction graph-mutating MCP tools are explicitly not claim-eligible
//!   yet. Each terminal outcome is submitted to
//!   `.kin/coordination_events.jsonl` with sequence, repo/session/intent,
//!   effective mode, and release attribution. A write-ahead reservation is
//!   fsynced before mutation, the terminal event is fsynced before live
//!   broadcast, and any persistence failure makes health `attention` and the
//!   stream ineligible rather than reporting a misleading success.

pub mod api;
pub mod background_work;
pub mod commit_deltas;
pub mod commit_liveness;
pub mod daemon;
pub mod error;
pub mod graph_only_members;
pub mod lifecycle;
mod local_repository_authority;
pub mod loop_runner;
mod mcp_commit;
mod pending_commits;
pub mod replica_adoption;
mod repository_admit;
mod repository_branch;
mod repository_checkout;
pub mod repository_commit;
mod repository_drift;
mod repository_merge;
mod repository_merge_state;
mod repository_purge;
mod repository_rename;
mod repository_rollback;
mod repository_stash;
mod repository_tag;
pub mod session_registry;
mod source_cas;
pub mod state;
pub mod supervisor;
pub mod traffic_adapter;
pub mod write_veto;

pub use daemon::{
    acquire_daemon_authority, acquire_daemon_authority_within, run, run_with_authority,
    DaemonConfig,
};
pub use error::{DaemonError, Result};
pub use lifecycle::{daemon_is_up, AutoStartError, MCP_IDLE_TIMEOUT_SECS};
pub use loop_runner::LoopConfig;
pub use session_registry::SessionCoordinator;
pub use state::{ChangeType, DaemonEvent, DaemonState, LspEnrichmentMessage, LspEnrichmentRequest};

/// Re-export kin_spine so consumers (MCP server, API) can use it via kin_daemon.
pub use kin_spine;

/// Exact test-harness entrypoint for the shared process-group guardian.
#[cfg(all(test, unix))]
#[test]
fn kin_process_group_guardian_worker() {
    let requested = std::env::var_os(kin_daemon_spawn::PROCESS_GROUP_GUARDIAN_MODE_ENV).is_some();
    let dispatched = kin_daemon_spawn::run_process_group_guardian_if_requested()
        .expect("run daemon process-group guardian worker");
    assert_eq!(dispatched, requested);
}

/// Process-global serialization for tests that mutate shared `KIN_*` environment
/// variables.
///
/// `std::env::set_var`/`remove_var` mutate one process-wide table that is not
/// synchronized against concurrent reads on other test threads, and several
/// `KIN_*` variables (notably `KIN_REGISTRY_PATH`) are read by code under test in
/// more than one module. A single shared lock keeps every env-mutating test in
/// this binary inside one serialization domain so their opposite expectations
/// can never race the parallel test runner.
#[cfg(test)]
pub(crate) fn test_env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Capture `tracing` events emitted on this thread, holding the process-global
/// callsite cache open for as long as the capture lives.
///
/// `tracing` caches one `Interest` per `event!` callsite for the whole process,
/// and the first thread to reach an unregistered callsite is the one that fills
/// that cache. `tracing_core`'s registry takes a shortcut whenever exactly one
/// dispatcher is registered: it resolves the interest against
/// `dispatcher::get_default()` on the *calling* thread rather than against the
/// dispatcher that is actually registered. A thread-local capture subscriber is
/// one dispatcher, so a test running in parallel that reaches the callsite first
/// resolves it against its own absent subscriber, `NoSubscriber` answers
/// `Interest::never()`, and every later thread short-circuits on that cached
/// answer, including the one doing the capturing. That is how the commit-phase
/// capture once collected the two phases emitted through one timing helper and
/// none of the eight emitted through the other.
///
/// Registering a second dispatcher for the life of the capture takes the
/// shortcut off the table. Registration then unions the live dispatchers, the
/// capture is always one of them, and interests that disagree settle at
/// `Interest::sometimes()`, which asks the emitting thread's own subscriber once
/// per event: this thread answers yes and every other thread answers no, so a
/// test running in parallel neither gains nor loses a line. Building the capture
/// dispatcher second also repairs a callsite an earlier test already cached as
/// never, because registering a dispatcher rebuilds every registered callsite
/// against the live set.
///
/// This is a test seam only. The daemon installs its subscriber as the global
/// default, which `get_default()` returns on every thread, so the shortcut
/// resolves against the real subscriber in a running daemon.
#[cfg(test)]
pub(crate) fn capture_events_on_this_thread<S>(subscriber: S) -> EventCapture
where
    S: tracing::Subscriber + Send + Sync + 'static,
{
    let pinned = tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default());
    let capture = tracing::Dispatch::new(subscriber);
    let default = tracing::dispatcher::set_default(&capture);
    EventCapture {
        _default: default,
        _capture: capture,
        _pinned: pinned,
    }
}

/// A live capture from [`capture_events_on_this_thread`]. Dropping it restores
/// the thread's previous subscriber and then releases the pinned dispatcher, in
/// that order.
#[cfg(test)]
pub(crate) struct EventCapture {
    _default: tracing::subscriber::DefaultGuard,
    _capture: tracing::Dispatch,
    _pinned: tracing::Dispatch,
}
