# Kin Search

`kin-search` is the extraction target for Kin's graph-native retrieval, ranking, and proof-aware search policy layer.

This crate stays inside the `kin` workspace so ranking strategy can evolve independently from raw storage and any single UI surface without paying separate-repo overhead.

## What This Repo Owns

- search query models
- proof-aware ranking
- result explanations
- weighting across lexical, semantic, graph, proof, and provenance signals

## Current State

Today this crate provides a small Rust library in [`src/lib.rs`](/Users/troyfortinjr/GitHub/kin-ecosystem/kin/crates/kin-search/src/lib.rs) with:

- `SearchQuery`
- `CandidateSignals`
- `SearchCandidate`
- `RankedResult`
- `rank_candidates(...)`

The current ranking logic already demonstrates the intended direction:

- proof can be required explicitly
- multiple signal families contribute to the final score
- every ranked result includes an explanation string

That makes this crate a natural home for future shared search policy used by `kin`, `kin-code`, `kin-codex`, and `kinhub`.

## Validate

```bash
cargo test
```

## Relationship To Other Repos

- `kin-db`
  keeps the low-level storage, index, and vector primitives
- `kin`
  owns the local semantic search UX and command surfaces
- `kin-code`, `kin-codex`, and `kinhub`
  should eventually consume the same ranking and explanation model

## Boundary Rule

Put code here when it answers:

- how candidates are ranked
- how proof and provenance influence ranking
- how to explain why a result surfaced

Do not put:

- raw storage/index implementation
- editor-specific search UI
- hosted memory product logic

For architecture notes, see [docs/architecture.md](docs/architecture.md).
