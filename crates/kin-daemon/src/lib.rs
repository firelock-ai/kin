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
//!   marker (`.kin/kindb/generation`), bumped on each committed snapshot. This
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
//! Rung-3 of the write path. The agent-write apply path (`POST /vfs/write-notify`)
//! can reject a write *before* it is folded into the graph when it touches a
//! scope held under another session's hard intent.
//!
//! - Default (unset / any value other than `enforce`): **off**. The apply path
//!   is byte-identical to prior behavior — a colliding write is declined by the
//!   reconciler's own check and reported as a soft `200 {reindexed:false}`
//!   notification.
//! - `KIN_WRITE_VETO=enforce`: the write is rejected with a structured
//!   `409 Conflict` (`error: "write_veto"`) naming the blocking intent(s).
//!
//! What rung-3 enforces today is exactly **entity/artifact scope containment
//! versus other sessions' hard intents** — the only "contract" expressible with
//! current intent data. A session is never blocked by its own intent, and soft
//! intents stay advisory. Content-hash and semantic-contract (e.g.
//! [`IntentScope::Contract`](kin_model::session::IntentScope)) vetoes are future
//! work: no contract-content data exists at the apply boundary, and file writes
//! do not yet emit `Contract` touched-scopes. See [`write_veto`] for the
//! evaluator.
//!
//! ## Write-path inventory
//!
//! Every state-mutating route and its current *pre-write* gate, as of this
//! change. The two VFS apply paths (`vfs_write_notify`, `vfs_file_changed`) are
//! flag-gated by the write-veto and `graph_commit` is always-on; the rest
//! either rely on the reconciler's own soft-block, gate upstream, or are out of
//! this crate's veto scope.
//!
//! - `POST /vfs/write-notify` (`vfs_write_notify`): **write-veto** under
//!   `KIN_WRITE_VETO=enforce` (pre-write 409); default = reconciler soft-block
//!   (`200 {reindexed:false}`).
//! - `POST /vfs/file-changed` (`vfs_file_changed`): **write-veto** under
//!   `KIN_WRITE_VETO=enforce` (pre-write 409); default = reconciler soft-block
//!   (`200 {status:"error"}`). The general-purpose sibling of write-notify;
//!   gated through the same shared `write_veto_precheck` /
//!   `write_veto_collision_response` helpers so the two paths cannot drift and
//!   enforce cannot be bypassed by choosing one endpoint over the other.
//! - `POST /graph/commit` (`graph_commit`): always-on lease **409** on a
//!   foreign hard intent (the CLI semantic-commit path).
//! - `POST /commands/commit` (`command_commit`): commits the already-reconciled
//!   overlay; relies on the reconcile loop's upstream collision gating; no
//!   separate pre-write veto.
//! - `POST /reconcile` (`reconcile`): delegates to the kin-cli reconcile path; a
//!   scoped reconcile mutates a session-private graph isolated from HEAD.
//! - `POST /graph/mutations` (`graph_mutations`): work-item / annotation / audit
//!   metadata, not entity truth; ungated.
//! - `PUT /graph/branches/{name}/head`, `DELETE /graph/branches/{name}`: branch
//!   ref operations; ungated.
//! - `POST /mcp/tools/call` (`mcp_tools_call`): MCP write transactions — out of
//!   this crate's veto scope (kin-mcp lane), with its own stage/commit
//!   validation.

pub mod api;
pub mod commit_deltas;
pub mod daemon;
pub mod error;
pub mod lifecycle;
pub mod loop_runner;
pub mod projection_wiring;
pub mod session_registry;
pub mod state;
pub mod supervisor;
pub mod traffic_adapter;
pub mod write_veto;

pub use daemon::{run, DaemonConfig};
pub use error::{DaemonError, Result};
pub use lifecycle::{
    daemon_is_up, ensure_daemon_running, ensure_daemon_running_with_idle_timeout, AutoStartError,
    MCP_IDLE_TIMEOUT_SECS,
};
pub use loop_runner::LoopConfig;
pub use session_registry::SessionCoordinator;
pub use state::{ChangeType, DaemonEvent, DaemonState, LspEnrichmentMessage, LspEnrichmentRequest};

/// Re-export kin_spine so consumers (MCP server, API) can use it via kin_daemon.
pub use kin_spine;

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
