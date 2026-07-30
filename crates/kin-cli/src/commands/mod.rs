// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

pub mod approvals;
pub mod assistant;
pub mod audit;
pub mod auth;
pub mod backup;
pub mod bench;
pub mod bench_meta;
pub mod blame;
pub mod branch;
pub mod cache;
pub mod capabilities;
pub mod checkout;
pub mod clone;
pub mod cochange;
pub mod commit;
pub mod conflicts;
pub mod context;
pub mod contextbench_locate;
pub mod daemon;
pub mod dead_code;
pub mod deps;
pub mod diff;
pub mod drift;
pub mod eject;
pub mod embed;
pub mod git;
pub mod graph;
pub mod graph_health;
pub mod graph_viz;
pub mod health;
pub mod history;
pub mod impact;
pub mod init;
pub mod intent;
pub mod locate;
pub mod locate_cursor;
pub mod locate_debug;
pub mod locate_sizing;
pub mod locate_telemetry;
pub mod log;
pub mod managed_config_scope;
pub mod mcp;
pub mod merge;
pub mod migrate;
pub mod note;
pub mod notify;
pub mod overview;
pub mod pipeline;
pub mod prepared_state;
pub mod publish;
pub mod reconcile;
pub mod ref_lookup;
pub mod refs;
pub mod registry;
pub mod release_cmd;
pub mod release_orch;
pub mod remote;
pub mod rename;
pub(crate) mod repository_authority;
pub mod resolve;
pub mod resources;
pub mod review;
pub mod rollback;
pub mod scope;
pub mod search;
pub mod secret;
pub mod security;
pub mod semver;
pub mod session_run;
pub mod session_workspace;
pub mod setup;
pub mod setup_ledger;
pub mod spec;
pub mod stash;
pub mod status;
pub mod support;
pub mod tag;
pub mod telemetry;
#[cfg(test)]
pub(crate) mod test_subprocess;
pub mod trace;
pub mod trace_data_flow;
pub mod traffic;
pub mod transfer;
pub mod update;
pub mod verify;
pub mod work;
pub mod xref;

/// Discover the Kin repository a command is bound to, or refuse by naming the
/// command that creates one.
///
/// Every command that needs a repository refuses through here so the refusal
/// cannot drift per command. Running a repository command from the wrong
/// directory is an ordinary first mistake, and a refusal that only states the
/// absence leaves the caller to guess the remedy.
pub(crate) fn require_repository_layout() -> anyhow::Result<kin_core::KinLayout> {
    require_repository_layout_at(&std::env::current_dir()?)
}

/// Discover the Kin repository containing `start`, refusing the same way.
pub(crate) fn require_repository_layout_at(
    start: &std::path::Path,
) -> anyhow::Result<kin_core::KinLayout> {
    kin_core::KinLayout::discover(start).ok_or_else(|| {
        anyhow::anyhow!(
            "not a Kin repository (no .kin/ found)\nhint: run `kin init .` to initialize a Kin repository here"
        )
    })
}

#[cfg(test)]
mod repository_refusal_tests {
    use super::require_repository_layout_at;

    #[test]
    fn refusing_outside_a_repository_names_the_command_that_creates_one() {
        let empty = tempfile::tempdir().expect("temp dir");
        let err = require_repository_layout_at(empty.path())
            .expect_err("a directory with no .kin/ is not a repository");
        let message = err.to_string();
        assert!(
            message.contains("not a Kin repository"),
            "refusal must state the condition: {message}"
        );
        assert!(
            message.contains("kin init"),
            "refusal must name the remedy: {message}"
        );
    }
}
