// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! First publication into an object-store destination, end to end through the
//! adapter, for a build that carries the client.
//!
//! Its own file rather than three more cases beside the filesystem suite,
//! because the whole file is gated on the `gcs` feature and the workspace's
//! ordinary test job runs default features. A feature-gated case sitting inside
//! an ungated binary is compiled by clippy's `--all-features` pass and executed
//! by nothing, and the CI step that grades this file counts what it lists:
//! a gated case added here and not added to that step's list would make the
//! listing and the enumeration disagree, which is the assertion that fires.
//! Scoping the file to the feature is what makes that count exact.
//!
//! Nothing here reaches a bucket. The endpoint points at a port nothing is
//! listening on, so a real client is built and a real request is made and it
//! fails, which is enough to exercise the entire dispatch: the feature wiring,
//! the manifest, the destination's validation, the endpoint precedence, the
//! client construction, the backend call and the evidence composition. Reaching
//! an actual emulator is covered by the daemon's ignored GCS round trip; reaching the
//! real service is production's own acceptance.

#![cfg(feature = "gcs")]

use std::fs;
use std::net::TcpListener;
use std::path::PathBuf;

use kin_cli::commands::hosted_publication::{
    run_publish_with_env, run_verify_with_env, DestinationEnv, EvidenceRecord, IntentRecord,
    Outcome, PublishArgs, VerifyArgs, EXIT_INDETERMINATE,
};
use serde_json::json;
use tempfile::tempdir;

const RESERVED_ID: &str = "9f1c2e04-3b7a-4d21-9c55-0ab61d7e8f30";
const SOURCE_INPUT_HASH: &str = "a71b0f5c2d9e4813a6c07f52b8d31e94a05c76fb28d13e0947ab65cf2081d3e7";
const REQUEST_HASH: &str = "5f2c81a30bd47e6915c8f0234ab7de91c605f3821de74a90bc3f2178e045a6d1";
const BUCKET: &str = "kin-hosted-prod";
const PREFIX: &str = "publications/v1";

/// A local port nothing is listening on.
///
/// Claimed and released, so it is closed but almost certainly still unclaimed:
/// a stopped emulator. The same shape the daemon's own endpoint tests use.
fn closed_endpoint() -> String {
    let port = {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind a port to claim it");
        listener
            .local_addr()
            .expect("read the claimed address")
            .port()
    };
    format!("http://127.0.0.1:{port}")
}

struct Case {
    _temp: tempfile::TempDir,
    root: PathBuf,
}

impl Case {
    fn new() -> Self {
        let temp = tempdir().expect("temp dir");
        let root = temp.path().to_path_buf();
        Self { _temp: temp, root }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    /// A manifest whose destination is a bucket rather than a directory.
    fn write_manifest(&self) {
        let manifest = json!({
            "schema": "kin.hosted-first-publication-manifest.v1",
            "operation": {
                "org_id": "org-7f3c",
                "operation_id": "2a91c3f0-51bd-4e77-9a06-8c4127de35b1",
                "operation_revision": 7,
                "request_hash": REQUEST_HASH,
                "holder_id": "worker-3",
                "fencing_token": 4,
            },
            "repository_id": RESERVED_ID,
            "source": { "kind": "native-empty", "default_branch": "trunk" },
            "source_input_hash": SOURCE_INPUT_HASH,
            "destination": { "kind": "gcs", "bucket": BUCKET, "prefix": PREFIX },
            "expected_authority": serde_json::Value::Null,
        });
        fs::write(
            self.path("manifest.json"),
            serde_json::to_vec_pretty(&manifest).expect("encode manifest"),
        )
        .expect("write manifest");
    }

    fn publish_args(&self) -> PublishArgs {
        PublishArgs {
            manifest: self.path("manifest.json"),
            source: self.path("source"),
            intent_out: self.path("intent.json"),
            evidence_out: self.path("evidence.json"),
            expect_repository_id: RESERVED_ID.to_string(),
            expect_mode: "native-empty".to_string(),
        }
    }

    fn verify_args(&self) -> VerifyArgs {
        VerifyArgs {
            manifest: self.path("manifest.json"),
            intent: Some(self.path("intent.json")),
            evidence_out: self.path("verify-evidence.json"),
            expect_repository_id: RESERVED_ID.to_string(),
            expect_mode: "native-empty".to_string(),
        }
    }

    fn evidence(&self, name: &str) -> EvidenceRecord {
        let bytes = fs::read(self.path(name)).expect("read evidence");
        serde_json::from_slice(&bytes).expect("decode evidence")
    }
}

/// An intent naming this operation and this destination, so verification has
/// something to compare a reading against.
fn write_intent(case: &Case) {
    let intent = json!({
        "schema": "kin.hosted-first-publication-intent.v1",
        "repository_id": RESERVED_ID,
        "operation": {
            "org_id": "org-7f3c",
            "operation_id": "2a91c3f0-51bd-4e77-9a06-8c4127de35b1",
            "operation_revision": 7,
            "request_hash": REQUEST_HASH,
            "holder_id": "worker-3",
            "fencing_token": 4,
        },
        "mode": "native-empty",
        "intended_snapshot_sha256": SOURCE_INPUT_HASH,
        "intended_roots": {
            "version": 1, "generation": 1,
            "history": { "version": 1, "hash": SOURCE_INPUT_HASH },
            "ref_state": { "version": 1, "hash": SOURCE_INPUT_HASH },
            "ref_log": { "version": 1, "hash": SOURCE_INPUT_HASH },
            "collaboration": { "version": 1, "hash": SOURCE_INPUT_HASH },
            "replication": { "version": 1, "hash": SOURCE_INPUT_HASH },
            "local_state": { "version": 1, "hash": SOURCE_INPUT_HASH },
        },
        "intended_source_closure": {
            "algorithm": "kin.first-publication-body-closure.v1",
            "digest": SOURCE_INPUT_HASH,
            "body_count": 0,
            "total_bytes": 0,
        },
        "intended_default_branch": "trunk",
        "intended_head_change_id": serde_json::Value::Null,
        "intended_ref_bindings": [],
        "destination": { "kind": "gcs", "bucket": BUCKET, "prefix": PREFIX },
        "written_at": "2026-09-08T00:00:00Z",
    });
    fs::write(
        case.path("intent.json"),
        serde_json::to_vec_pretty(&intent).expect("encode intent"),
    )
    .expect("write intent");
    // Decoded back through the adapter's own type, so a fixture that has
    // drifted from the record's shape fails here rather than as a confusing
    // refusal inside the run under test.
    let bytes = fs::read(case.path("intent.json")).expect("read intent");
    let _: IntentRecord = serde_json::from_slice(&bytes).expect("the fixture intent decodes");
}

/// A destination the client cannot reach is INDETERMINATE, never ABSENT, and
/// the record names the service it failed to reach.
///
/// Reporting a destination nobody could read as holding no publication is
/// exactly the mistake that turns an unknown storage state into a second
/// publication under one reserved identity, so the two outcomes are asserted
/// apart rather than together.
#[test]
fn an_unreachable_bucket_is_indeterminate_and_names_its_service() {
    let case = Case::new();
    case.write_manifest();
    let endpoint = closed_endpoint();
    let env = DestinationEnv {
        kin_gcs_endpoint: Some(endpoint.clone()),
        storage_emulator_host: None,
    };

    assert_eq!(
        run_publish_with_env(case.publish_args(), &env).expect("the run completes"),
        EXIT_INDETERMINATE,
        "a destination that could not be read is neither published nor absent"
    );

    let record = case.evidence("evidence.json");
    assert_eq!(record.outcome, Outcome::Indeterminate);
    assert!(
        record.measured.is_none(),
        "nothing was read back, so nothing is measured"
    );
    let service = record
        .destination_service
        .expect("an object-store run records the service it talked to");
    assert_eq!(
        service.class, "emulator",
        "an endpoint override is an emulator, never the real service"
    );
    assert_eq!(
        service.endpoint_url.as_deref(),
        Some(endpoint.as_str()),
        "the record names the exact endpoint the client was built against"
    );

    // The source was never materialized: an unreadable destination is reported
    // before an import is spent on it.
    assert!(
        !case.path("source").exists(),
        "a destination this run could not read must not have cost an import"
    );
}

/// The Google-client convention reaches the client, not just the resolver.
///
/// `STORAGE_EMULATOR_HOST` is the second lever, and a unit test can only show
/// that it resolves. This shows the value it resolved to is the one the client
/// was actually built against, which is the part a resolver test cannot reach.
#[test]
fn the_google_convention_alone_points_the_client_at_the_same_endpoint() {
    let case = Case::new();
    case.write_manifest();
    let endpoint = closed_endpoint();
    let env = DestinationEnv {
        kin_gcs_endpoint: None,
        storage_emulator_host: Some(endpoint.clone()),
    };

    assert_eq!(
        run_publish_with_env(case.publish_args(), &env).expect("the run completes"),
        EXIT_INDETERMINATE
    );
    let service = case
        .evidence("evidence.json")
        .destination_service
        .expect("an object-store run records its service");
    assert_eq!(service.endpoint_url.as_deref(), Some(endpoint.as_str()));
}

/// Verification reaches the same client and writes nothing.
///
/// The hosted control plane calls `verify` as well as `publish`, so the arm has
/// its own dispatch through the same destination and its own record. A wiring
/// that reached the client on one path and not the other would leave the
/// recovery half of a hosted operation refusing for a reason nobody could see.
#[test]
fn verification_reaches_the_same_object_store_and_records_its_service() {
    let case = Case::new();
    case.write_manifest();
    write_intent(&case);
    let endpoint = closed_endpoint();
    let env = DestinationEnv {
        kin_gcs_endpoint: Some(endpoint.clone()),
        storage_emulator_host: None,
    };

    assert_eq!(
        run_verify_with_env(case.verify_args(), &env).expect("the run completes"),
        EXIT_INDETERMINATE
    );
    let record = case.evidence("verify-evidence.json");
    assert_eq!(record.outcome, Outcome::Indeterminate);
    let service = record
        .destination_service
        .expect("a verification records the service it read through");
    assert_eq!(service.class, "emulator");
    assert_eq!(service.endpoint_url.as_deref(), Some(endpoint.as_str()));
}
