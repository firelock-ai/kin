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
