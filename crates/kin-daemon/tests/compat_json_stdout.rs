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

    // The exact top-level key set. kin-infra reads this payload by name and
    // records it verbatim as the evidence a hosted pin is graded against, so a
    // key that quietly appears or disappears changes what that evidence means.
    // Adding one is fine and this is where it is acknowledged.
    let mut keys: Vec<&str> = parsed
        .as_object()
        .expect("the compat payload must be an object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec![
            "build",
            "graph_snapshot_max_supported_version",
            "graph_snapshot_min_supported_version",
            "graph_snapshot_version",
            "hosted_start_requirements",
            "schema",
            "supervisor_startup_capabilities",
            "supervisor_startup_protocol",
            "version",
        ],
        "the compat payload's top-level shape changed"
    );

    // The hosted declaration itself, from the real binary rather than from the
    // in-process renderer, so the block a deployment reads off an image is the
    // one under test.
    let hosted = &parsed["hosted_start_requirements"];
    assert_eq!(hosted["schema"], "kin.daemon.hosted-start.v1");
    assert!(
        hosted["features"]["gcs"].is_boolean() && hosted["features"]["firestore"].is_boolean(),
        "the declaration must report the build features hosted service needs: {hosted}"
    );
    let requirements = hosted["requirements"]
        .as_array()
        .expect("the declaration must carry a requirements array");
    let project = requirements
        .iter()
        .find(|entry| entry["name"] == "GOOGLE_CLOUD_PROJECT")
        .unwrap_or_else(|| panic!("the declaration must name GOOGLE_CLOUD_PROJECT: {hosted}"));
    assert_eq!(project["required"], true);
    assert_eq!(
        project["absence"], "readiness-closed",
        "a missing project does not stop the process, it holds readiness shut, and a deployment \
         reading this block has to be told which"
    );
    assert_eq!(
        project["refusals"][0]["message"],
        "GOOGLE_CLOUD_PROJECT is required for hosted durable spine"
    );
}
