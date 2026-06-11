<!--
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Firelock, LLC
-->

# Enrichment per-identifier loop — evidence & closure

External adversarial diligence flagged the per-identifier-per-line loops at
`src/file_enrichment.rs` (`enrich_file_definitions`) and `src/enrichment.rs`
(`enrich_entity_uses_type`) as a scaling concern. This note records the
code-verified consumption path, the measured local cost, the recommendation,
and the real levers that the diligence pass *should* have flagged.

**Bottom line:** the loops are dominated by sequential external LSP round-trips,
not by Kin's CPU, and the whole path is disabled during benchmarks. The flagged
"per-identifier scan" is noise. The one safe, output-identical win — gating LSP
round-trips on lines that lie inside a known entity — is implemented here; the
remaining levers are LSP-RPC-layer work that is out of scope for the freeze.

## 1. Consumption-path verdict (where the loops actually run)

| Question | Finding | Evidence (file:line) |
| --- | --- | --- |
| What reaches `enrich_file_definitions` (the `:109` loop)? | Only the daemon's `LspEnrichmentMessage::Sweep` arm. | `kin/crates/kin-daemon/src/daemon.rs:1400` |
| What reaches `enrich_entity_uses_type` (the `:367` loop)? | `enrich_single_entity`, called from both the Sweep and Incremental (editor-edit) arms. | `kin/crates/kin-daemon/src/daemon.rs:296`; `:1201`, `:1418` |
| Where does that run? | A fire-and-forget background tokio task, gated by `config.lsp_enabled`. | `kin/crates/kin-daemon/src/daemon.rs:369`, `:955` |
| Is each loop iteration CPU or RPC? | An external LSP RPC (`textDocument/definition` / `typeDefinition`) to rust-analyzer/pyright over stdio, sequentially awaited, 2s per-request timeout. | `src/file_enrichment.rs:112`; `src/enrichment.rs:368` |
| Extra latency around the loop? | 25s/language server-warmup sleep + 5s first-`didOpen` sleep before any query. | `kin/crates/kin-daemon/src/daemon.rs:1333`, `:1372` |
| On the `kin init` critical path? | No. `init` does no synchronous enrichment; behind `!no_lsp` it only fire-and-forget POSTs `/v1/lsp/sweep` (2s timeout). Comment confirms sync enrichment "would add 30-60s to init time". | `kin/crates/kin-cli/src/commands/init.rs:561`, `:572` |
| On the `kin commit` path? | No. Only prints "enriching in background". | `kin/crates/kin-cli/src/commands/commit.rs:553` |
| Reachable during benchmarks? | **No — doubly disabled.** Bench init runs `kin init --no-lsp`, and the bench daemon runs with `KIN_DAEMON_DISABLE_LSP=1`, so the enrichment worker is never even created. | `kin-bench/crates/kin-bench-engine/src/live/workspace.rs:2385`; `kin-bench/crates/kin-bench-prep/src/bin/kin-bench-eval.rs:2367`; `kin/crates/kin-daemon/src/bin/kin-daemon.rs:365` |
| Requires anything else? | Yes — rust-analyzer/pyright must be present (discovered via `which::which`). | `src/discovery.rs:49` |

Net: zero impact on freeze/locate numbers; latency is owned by the external LSP
server, not by the per-identifier scan.

## 2. Measured local cost (the only thing a "batch" could remove)

Honest timing of `identifier_positions_in_line` — the local CPU run before each
LSP request — on an adversarial fixture (5,000 lines, periodic ~500-col lines,
unicode identifiers/strings/comments). Release build, Apple Silicon. Test:
`file_enrichment::tests::measure_identifier_scan_throughput_on_large_unicode_file`.

| Metric | Value |
| --- | --- |
| File size | 5,000 lines / 1.32 MB |
| Identifiers scanned | 102,500 per file |
| Per-file scan time | **~2.95 ms** |
| Per-identifier | **~29 ns** |
| Throughput | **~450 MB/s** |

A single LSP round-trip is milliseconds (typical) to 2 s (timeout). The local
scan is therefore 5–8 orders of magnitude below one RPC. The loop is
**LSP-RPC-bound, not scan-bound.** The scanner is already a single O(line) pass;
there is no local batching win to capture.

## 3. Recommendation: wontfix the flagged item; ship the one safe gate

The diligence framing ("nested per-identifier loop = scaling hot spot") misreads
an RPC-bound background path as a CPU hot loop. The naive fix it implies —
deduping by identifier *text* so each unique token issues one RPC — is **not
output-identical**: `textDocument/definition` is position-dependent, so the same
token text on different lines can resolve to different definitions and so to
different relations. Text dedupe would silently drop legitimate edges.

The genuinely safe, output-identical win is different and is implemented in this
branch (`enrich_file_definitions`):

- **Source-line gating.** A relation is emitted only when `(source, target)` are
  both `Some`. `source = entity_index.find_at(uri, line)` depends solely on the
  line, never the column. So lines outside every known entity span (imports,
  blank lines, inter-entity gaps, module glue not captured as an entity) can
  never contribute a relation. We resolve `source` once per line and skip the
  whole line's LSP round-trips when it is `None`.
- **Why it is output-identical.** It removes only queries whose results were
  structurally guaranteed to be discarded. The returned `FileEnrichmentResult`
  is byte-identical: `relations` unchanged, `definitions_resolved` unchanged
  (it was only ever incremented when `source` was `Some`), and
  `positions_queried` unchanged (still counts every scanned position).
- **Tested.** `source_line_gate_skips_only_lines_outside_entity_spans` proves
  the skip predicate (`find_at(...).is_none()`) fires exactly on lines outside
  all entity spans. Full end-to-end golden parity needs a mock-LSP harness that
  this crate does not yet have; equivalence here rests on that predicate test
  plus the structural invariant above.

## 4. Real levers, if production enrichment latency ever matters

None of these are benchmark-relevant; they belong to the background daemon path
and are listed so the genuine costs are on record (this is what the diligence
pass should have surfaced instead of the CPU scan):

1. **Sequential per-identifier RPC awaits (largest lever).** Every identifier is
   queried one-at-a-time with `.await`. For a several-thousand-line file this is
   tens of thousands of serial round-trips. Bounded-concurrency in-flight
   requests (e.g. a `FuturesUnordered` window of N) or LSP request batching would
   cut wall-clock by ~N×. Output-identical if results are reassembled per
   position. **Non-trivial; follow-up, not freeze scope.**
2. **Warmup sleeps.** Fixed `25s`/language + `5s` first-`didOpen` sleeps
   (`daemon.rs:1333`, `:1372`) dominate small-repo enrichment latency. Replacing
   them with a readiness signal (poll until the server answers, capped) would
   remove dead waiting. Behavior-affecting; needs care.
3. **Cross-line identifier dedupe — status: intentionally absent, unsafe to add.**
   The `seen` HashSet dedupes resolved `(src, dst, kind)` *relations* after the
   RPC; it does not gate RPC issuance, so a symbol on K lines still fires K
   queries. Deduping by token text to collapse those is **not** output-identical
   (position-dependent resolution; see §3). Do not "fix" this by text dedupe.
4. **Same gate for `enrich_entity_uses_type`?** No safe pre-RPC gate exists
   there: the source is always the passed-in entity (always `Some`), and the
   only filter is on the post-RPC resolved *target*. RPC count there can only be
   reduced by lever (1).
