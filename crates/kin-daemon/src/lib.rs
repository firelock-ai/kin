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
//! change. Only `vfs_write_notify` (flag-gated) and `graph_commit` (always-on)
//! reject before mutating; the rest either rely on the reconciler's own
//! soft-block, gate upstream, or are out of this crate's veto scope.
//!
//! - `POST /vfs/write-notify` (`vfs_write_notify`): **write-veto** under
//!   `KIN_WRITE_VETO=enforce` (pre-write 409); default = reconciler soft-block
//!   (`200 {reindexed:false}`).
//! - `POST /vfs/file-changed` (`vfs_file_changed`): reconciler soft-block only
//!   (`200` on `CollisionBlocked`); **NOT veto-wired**. This is the *third*
//!   graph-truth write path and shares the same post-write-notification gap;
//!   it was left outside the confirmed `/vfs/write-notify` scope and reported
//!   as a finding rather than fixed here.
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
pub mod daemon;
pub mod error;
pub mod lifecycle;
pub mod loop_runner;
pub mod session_registry;
pub mod state;
pub mod supervisor;
pub mod traffic_adapter;
pub mod write_veto;

pub use daemon::{run, DaemonConfig};
pub use error::{DaemonError, Result};
pub use lifecycle::{daemon_is_up, ensure_daemon_running, AutoStartError};
pub use loop_runner::LoopConfig;
pub use session_registry::SessionCoordinator;
pub use state::{ChangeType, DaemonEvent, DaemonState, LspEnrichmentMessage, LspEnrichmentRequest};

/// Re-export kin_spine so consumers (MCP server, API) can use it via kin_daemon.
pub use kin_spine;
