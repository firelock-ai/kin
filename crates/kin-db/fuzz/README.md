<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Firelock, LLC -->

# kin-db fuzzing

Bounded `cargo-fuzz` (libFuzzer) coverage for kin-db's binary ingestion and
semantic-entity-graph build paths.

kin-db has no source-language parser of its own — tree-sitter parsing lives in
`kin`. kin-db's "parser/ingestion entry points that build the semantic entity
graph" are therefore the **binary snapshot/delta decoders**, the
**graph + index builder**, and the **entity-extraction read surfaces** that
walk the adjacency built during ingestion. These targets fuzz exactly those.

## Targets

| Target | Entry point | What it exercises |
| --- | --- | --- |
| `fuzz_snapshot_deser` | `GraphSnapshot::from_bytes` → `from_snapshot` → `to_bytes` | Snapshot header/version/checksum + MessagePack decode + round-trip |
| `fuzz_delta_deser` | `GraphSnapshotDelta::from_bytes` | Delta header/version/length-bound + MessagePack decode |
| `fuzz_delta_apply` | `from_bytes` → `apply_graph_delta` → `from_snapshot` | **Incremental ingestion**: merging a decoded delta into a snapshot, then rebuilding the graph |
| `fuzz_graph_ingest` | `from_bytes` → `from_snapshot` → `get_relations` / `get_all_relations_for_entity` | **Entity-graph build + extraction**: index/adjacency construction, then walking every ingested entity's adjacency (dangling/self/duplicate edges) |

## Prerequisites

```sh
rustup toolchain install nightly      # libFuzzer requires nightly
cargo install cargo-fuzz --locked
```

## Run (bounded / reproducible)

From `crates/kin-db`:

```sh
# Single target, 60s smoke (matches CI's bounded tier)
cargo +nightly fuzz run fuzz_graph_ingest -- -max_total_time=60 -rss_limit_mb=4096

# All targets
for t in fuzz_snapshot_deser fuzz_delta_deser fuzz_delta_apply fuzz_graph_ingest; do
  cargo +nightly fuzz run "$t" -- -max_total_time=60 -rss_limit_mb=4096
done

# Replay a single input (e.g. a crash artifact)
cargo +nightly fuzz run fuzz_graph_ingest fuzz/artifacts/fuzz_graph_ingest/<id>
```

The committed `corpus/<target>/` seeds drive the fuzzer past the magic/version
header into the decode → ingest → build → extract stages. The accumulated
corpus is intentionally **not** committed; only the hand-authored seeds are.

## CI

`.github/workflows/fuzz.yml`:

- **On PRs** (touching the parser/ingestion/storage surface): deterministic
  regression — replays the committed seed corpus only (`-runs=0`, no mutation),
  so a PR is gated on known-bad inputs (e.g. `seed_body_len_overflow`) without
  mutation-based flakiness blocking unrelated changes.
- **Weekly schedule + manual dispatch**: bounded mutation fuzzing
  (`-max_total_time=600`) for discovery.

A crash fails the job and uploads the reproducing artifact.

> Found by this harness: `seed_body_len_overflow` — a header `body_len` near
> `usize::MAX` wrapped `16 + body_len` and panicked on the body slice in both
> the snapshot and delta decoders. Fixed with checked arithmetic;
> the seed is committed as a permanent regression guard.

### Reproduce the seed corpus locally

```sh
cd crates/kin-db
cargo +nightly fuzz run fuzz_snapshot_deser -- -runs=0   # replay seeds, no mutation
```

## Triage

A finding must be tied to a concrete decoder/ingestion fixture (commit the
reproducing input under `corpus/<target>/`), then either fixed in kin-db or
filed as parser/ingestion hardening work before that workstream closes.
