// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The CLI's daemon-compatibility probe runs `kin-daemon --compat-json` and
//! parses the child process's stdout as JSON. That stdout must therefore carry
//! ONLY the compat payload — no startup log line may precede it, even when
//! correctness-relevant `KIN_*` overrides are set (which make the env registry
//! emit startup warnings). A regression here makes the CLI treat a perfectly
//! good daemon binary as "stale or incompatible".

use std::time::Duration;
use tokio::process::Command;

mod common;

use common::{daemon_test_output, isolate_daemon_test_command};

#[tokio::test]
async fn compat_json_stdout_is_pure_json_under_env_overrides() {
    // These correctness-relevant overrides make the env registry emit startup
    // WARNs. Because the tracing subscriber's default writer is stdout, those
    // warnings previously landed on stdout ahead of the JSON and broke the
    // probe. The compat payload must now be emitted before any logging.
    let mut command = Command::new(env!("CARGO_BIN_EXE_kin-daemon"));
    isolate_daemon_test_command(&mut command);
    command
        .arg("--compat-json")
        .env("KIN_BYPASS_EMBEDDING_COVERAGE_CHECK", "1")
        .env("KIN_DAEMON_DISABLE_LSP", "1");
    let output = daemon_test_output(command, "kin-daemon --compat-json", Duration::from_secs(30))
        .await
        .expect("run kin-daemon --compat-json");

    assert!(
        output.status.success(),
        "--compat-json must exit 0; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let parsed: serde_json::Value =
        serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "--compat-json stdout must be pure JSON even with KIN_* overrides set: {error}; \
                 stdout was: {:?}",
                String::from_utf8_lossy(&output.stdout)
            )
        });

    assert_eq!(parsed["schema"], "kin.daemon.compat.v2");
    assert!(
        parsed["graph_snapshot_version"].is_number(),
        "compat payload must carry a numeric graph_snapshot_version"
    );
    assert_eq!(
        parsed["graph_snapshot_min_supported_version"],
        kin_db::GraphSnapshot::MIN_SUPPORTED_VERSION,
        "compat payload must expose the compiled minimum reader schema"
    );
    assert_eq!(
        parsed["graph_snapshot_max_supported_version"],
        kin_db::GraphSnapshot::CURRENT_VERSION,
        "compat payload must expose the compiled maximum reader schema"
    );
    assert_eq!(parsed["supervisor_startup_protocol"], 2);
    let capabilities = parsed["supervisor_startup_capabilities"]
        .as_array()
        .expect("compat payload must carry startup capabilities");
    for required in [
        "generation-adoption-ack-v2",
        "legacy-directory-sentinel-v1",
        "bounded-legacy-rollback-v1",
    ] {
        assert!(
            capabilities.iter().any(|capability| capability == required),
            "compat payload must advertise {required}: {parsed}"
        );
    }
    assert!(parsed["build"]["sha"].is_string());
    assert!(parsed["build"]["dirty"].is_boolean());
    assert!(parsed["build"]["source_known"].is_boolean());
    assert!(parsed["build"]["dependency_provenance"].is_string());
    assert!(parsed["build"]["branch"].is_string());
    assert!(parsed["build"]["built_at"].is_string());
}
