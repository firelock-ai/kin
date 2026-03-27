// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC
//
// Generate seed corpus files for fuzzing.
//
// Run once: rustc --edition 2021 generate_seeds.rs -L ../target/debug/deps -o generate_seeds && ./generate_seeds
//
// Or more easily, use the included seed_empty file which is a minimal
// valid v3 snapshot (empty graph, valid header + checksum).

fn main() {
    // The simplest seed: just the magic bytes "KNDB" — tests header validation
    let magic_only = b"KNDB";
    std::fs::write("corpus/fuzz_snapshot_deser/seed_magic_only", magic_only).unwrap();

    // Invalid magic
    let bad_magic = b"XXXX\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    std::fs::write("corpus/fuzz_snapshot_deser/seed_bad_magic", bad_magic).unwrap();

    // Valid header, zero body length
    let mut empty_header = Vec::new();
    empty_header.extend_from_slice(b"KNDB");
    empty_header.extend_from_slice(&3u32.to_le_bytes()); // version 3
    empty_header.extend_from_slice(&0u64.to_le_bytes()); // body_len = 0
    std::fs::write("corpus/fuzz_snapshot_deser/seed_empty_header", &empty_header).unwrap();

    // Truncated file
    let truncated = b"KNDB\x03\x00";
    std::fs::write("corpus/fuzz_snapshot_deser/seed_truncated", truncated).unwrap();

    // Version 1 marker
    let mut v1_header = Vec::new();
    v1_header.extend_from_slice(b"KNDB");
    v1_header.extend_from_slice(&1u32.to_le_bytes());
    v1_header.extend_from_slice(&0u64.to_le_bytes());
    std::fs::write("corpus/fuzz_snapshot_deser/seed_v1_header", &v1_header).unwrap();

    // Version 2 marker
    let mut v2_header = Vec::new();
    v2_header.extend_from_slice(b"KNDB");
    v2_header.extend_from_slice(&2u32.to_le_bytes());
    v2_header.extend_from_slice(&0u64.to_le_bytes());
    std::fs::write("corpus/fuzz_snapshot_deser/seed_v2_header", &v2_header).unwrap();

    // Bogus future version
    let mut v99_header = Vec::new();
    v99_header.extend_from_slice(b"KNDB");
    v99_header.extend_from_slice(&99u32.to_le_bytes());
    v99_header.extend_from_slice(&0u64.to_le_bytes());
    std::fs::write("corpus/fuzz_snapshot_deser/seed_v99_header", &v99_header).unwrap();

    println!("Seed corpus files generated in corpus/fuzz_snapshot_deser/");
}
