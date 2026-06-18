// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC
//
// Fuzz target: graph delta INGESTION (apply) path.
//
// Where fuzz_delta_deser stops after GraphSnapshotDelta::from_bytes, this
// target drives the next stage — the incremental ingestion that mutates the
// semantic entity graph:
//   - GraphSnapshotDelta::from_bytes  (decode adversarial delta bytes)
//   - apply_graph_delta               (merge adds/removes into a snapshot)
//   - InMemoryGraph::from_snapshot     (rebuild the entity graph + adjacency
//                                       indexes from the mutated snapshot)
//
// The goal is to ensure no adversarial delta can panic, over-allocate, or
// produce a snapshot that crashes the graph builder. Most raw inputs fail the
// KNDD magic/version check; the seed corpus and accumulated corpus drive the
// fuzzer past the header into apply + rebuild.
//
// Run: cd crates/kin-db && cargo +nightly fuzz run fuzz_delta_apply

#![no_main]

use libfuzzer_sys::fuzz_target;

use kin_db::{apply_graph_delta, GraphSnapshot, GraphSnapshotDelta, InMemoryGraph};

fuzz_target!(|data: &[u8]| {
    let Ok(delta) = GraphSnapshotDelta::from_bytes(data) else {
        return;
    };

    // Apply the decoded delta onto an empty base snapshot — the incremental
    // ingestion path that merges entity/relation/adjacency changes.
    let mut snapshot = GraphSnapshot::empty();
    apply_graph_delta(&mut snapshot, &delta);

    // Building the in-memory entity graph from the mutated snapshot must not
    // panic regardless of how inconsistent the delta left the snapshot.
    let _graph = InMemoryGraph::from_snapshot(snapshot);
});
