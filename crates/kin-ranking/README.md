# Kin Ranking

`kin-ranking` is Kin's bundled ranking and explanation policy layer.

The low-level extraction target is `kin-search`, which owns raw retrieval primitives. `kin-ranking` stays inside the `kin` workspace so Kin-local ranking strategy can evolve independently from storage and any single UI surface without paying separate-repo overhead.

## What This Repo Owns

- Kin-local search policy models
- proof-aware ranking
- result explanations
- weighting across lexical, semantic, graph, proof, and provenance signals

## Current State

Today this crate provides a small Rust library in [`src/lib.rs`](src/lib.rs) with:

- `SearchQuery`
- `CandidateSignals`
- `SearchCandidate`
- `RankedResult`
- `rank_candidates(...)`

The current ranking logic already demonstrates the intended direction:

- proof can be required explicitly
- multiple signal families contribute to the final score
- every ranked result includes an explanation string

That makes this crate a natural home for future shared search policy used by `kin`, `kin-editor`, `kin-mcp`, and `kinlab`.

## Validate

```bash
cargo test
```

## Relationship To Other Repos

- `kin-search`
  keeps the low-level retrieval primitives and query mechanics
- `kin-db`
  consumes the retrieval primitive layer and owns graph/storage integration
- `kin`
  owns the local semantic search UX, ranking policy, and command surfaces
- `kin-editor`, `kin-mcp`, and `kinlab`
  should consume the same ranking and explanation model

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
