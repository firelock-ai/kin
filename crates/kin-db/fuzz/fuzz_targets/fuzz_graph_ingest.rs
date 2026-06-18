// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC
//
// Fuzz target: semantic entity-graph INGESTION + extraction read path.
//
// kin-db has no source-language parser of its own (tree-sitter parsing lives
// in `kin`); kin-db's "ingestion entry point that builds the semantic entity
// graph" is the binary snapshot decoder + graph/index builder + the entity
// extraction read surfaces that walk the adjacency built during ingestion.
//
// This target exercises that whole pipeline on adversarial input:
//   - GraphSnapshot::from_bytes            (decode adversarial snapshot bytes)
//   - InMemoryGraph::from_snapshot          (build entities, relations, the
//                                            entity name/file/kind index, and
//                                            the relation adjacency indexes)
//   - EntityStore::get_relations /
//     get_all_relations_for_entity          (entity extraction: walk every
//                                            ingested entity's adjacency)
//
// Where fuzz_snapshot_deser only checks decode + re-encode, this target also
// queries every extracted entity, so adversarial graph shapes (dangling edges,
// self-edges, duplicate ids) are walked, not just parsed.
//
// Run: cd crates/kin-db && cargo +nightly fuzz run fuzz_graph_ingest

#![no_main]

use libfuzzer_sys::fuzz_target;

use kin_db::{EntityStore, GraphSnapshot, InMemoryGraph};

fuzz_target!(|data: &[u8]| {
    let Ok(snapshot) = GraphSnapshot::from_bytes(data) else {
        return;
    };

    // Capture entity ids before from_snapshot consumes the snapshot.
    let entity_ids: Vec<_> = snapshot.entities.keys().cloned().collect();

    let graph = InMemoryGraph::from_snapshot(snapshot);

    // Walk the entity-extraction read surfaces for every ingested entity.
    // These traverse the adjacency indexes built during ingestion and must
    // never panic, even on dangling/self/duplicate edges.
    for id in &entity_ids {
        let _ = graph.get_relations(id, &[]);
        let _ = graph.get_all_relations_for_entity(id);
    }
});
