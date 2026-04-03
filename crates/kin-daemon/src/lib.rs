// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Background daemon for Kin.
//!
//! Owns the graph lifecycle, runs the file watcher and
//! reconciliation loop, and exposes an HTTP API for CLI, MCP, and UI.
//!
//! Phase 7 adds session coordination and intent arbitration via
//! the `SessionCoordinator`.

pub mod api;
pub mod daemon;
pub mod error;
pub mod lifecycle;
pub mod loop_runner;
pub mod session_registry;
pub mod state;

pub use daemon::{run, DaemonConfig};
pub use error::{DaemonError, Result};
pub use lifecycle::{daemon_is_up, ensure_daemon_running, AutoStartError};
pub use loop_runner::LoopConfig;
pub use session_registry::SessionCoordinator;
pub use state::{ChangeType, DaemonEvent, DaemonState, LspEnrichmentMessage, LspEnrichmentRequest};

/// Re-export kin_spine so consumers (MCP server, API) can use it via kin_daemon.
pub use kin_spine;
