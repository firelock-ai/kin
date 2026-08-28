// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use kin_db::{GcsFullAuthorityEnvelopeCompatibility, GCS_FULL_AUTHORITY_ENVELOPE_COMPATIBILITY};

// This test target is run with `--no-default-features`. Keeping the crate-root
// initializer outside the test body makes loss of the unconditional public
// export a compile-time failure before any runtime assertion can pass.
const CRATE_ROOT_COMPATIBILITY_WITHOUT_GCS: GcsFullAuthorityEnvelopeCompatibility =
    GCS_FULL_AUTHORITY_ENVELOPE_COMPATIBILITY;

#[test]
fn gcs_envelope_compatibility_is_available_at_the_crate_root_without_gcs() {
    let compatibility = CRATE_ROOT_COMPATIBILITY_WITHOUT_GCS;

    assert_eq!(compatibility.min_supported_version, 2);
    assert_eq!(compatibility.current_version, 2);
    assert!(compatibility.supports(2));
    assert!(!compatibility.supports(1));
    assert!(!compatibility.supports(3));
}
