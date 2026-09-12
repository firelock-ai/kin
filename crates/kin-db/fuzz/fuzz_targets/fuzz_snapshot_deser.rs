// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC
//
// Fuzz target: GraphSnapshot::from_bytes with arbitrary input.
//
// This exercises the entire snapshot deserialization path:
// - Magic byte validation
// - Version parsing
// - Body length bounds checking
// - MessagePack deserialization
// - SHA-256 checksum verification (v3)
// - Legacy v1/v2 migration path
//
// Run: cd crates/kin-db && cargo +nightly fuzz run fuzz_snapshot_deser
//
// The goal is to ensure that no input can cause a panic, unbounded
// allocation, or undefined behavior in the deserialization path.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Attempt to deserialize — we only care that it doesn't panic.
    // All errors are expected and fine.
    let _ = kin_db::GraphSnapshot::from_bytes(data);

    // If deserialization somehow succeeds, verify the round-trip:
    // serialize back and check it doesn't panic.
    if let Ok(snapshot) = kin_db::GraphSnapshot::from_bytes(data) {
        let _ = snapshot.to_bytes();

        // Also verify from_snapshot doesn't panic on valid data
        let _graph = kin_db::InMemoryGraph::from_snapshot(snapshot);
    }
});
