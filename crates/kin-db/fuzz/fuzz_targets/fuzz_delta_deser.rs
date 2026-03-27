// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC
//
// Fuzz target: GraphSnapshotDelta::from_bytes with arbitrary input.
//
// This exercises the delta deserialization path:
// - Magic byte validation
// - Version parsing
// - Body length bounds checking
// - MessagePack deserialization of delta collections
//
// Run: cd crates/kin-db && cargo +nightly fuzz run fuzz_delta_deser
//
// The goal is to ensure that no input can cause a panic, unbounded
// allocation, or undefined behavior in the delta deserialization path.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Attempt to deserialize — we only care that it doesn't panic.
    let _ = kin_db::GraphSnapshotDelta::from_bytes(data);
});
