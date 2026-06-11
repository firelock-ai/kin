# Locate entity-granular fusion — flip plan (`KIN_LOCATE_ENTITY_FUSION`)

Status: **default OFF**, experiment wired, awaiting post-freeze A/B. Flipping the
default is **out of scope** for the implementing lane — it requires the measured
evidence below, gathered on the serialized de-cliff A/B harness after the active
benchmark freeze lifts.

## What the flag does

`KIN_LOCATE_ENTITY_FUSION=1` replaces the **fusion stage** of `locate` with an
entity-granular fuser, then projects back to files at the fusion boundary:

1. The two entity-derived signals — `entity_resolve` (list idx 7) and `embedding`
   (idx 9) — are re-keyed by **entity id** recovered from the Phase-1 discovery
   seeds (`entity_seed_keyed`). Multiple entities defined in the same file stay
   **distinct items**, the granularity `to_ranked` collapses to one (path, score).
2. Every other signal (traceback, multihop, tests, snippets, imports, errors,
   cochange, source_text) keeps its **file-path key** — its `FileHit`s carry no
   entity identity.
3. `reciprocal_rank_fusion_entities` fuses the mixed-key lists in rank space
   (rank term + per-list max-normalized raw term + cross-signal bonus), skipping
   vendored files by path.
4. `entity_granular_fused_files` **projects** the fused entity ranking down to
   files: each file takes its best entity's fused score. That file list then
   feeds the **unchanged** file-keyed post-fusion pipeline (boosts, demotes,
   floors, `adaptive_cap`).

When the flag is unset, none of the above runs: the original `match track`
regime-based path fusion executes verbatim, so default output is **byte-identical
by construction** (the flag gates a single `if`; the entity path is the `else`
arm of the existing fusion expression).

## Why it is gated, not shipped

This is the 3.1 architecture bet: *entity ranking should survive into fusion
instead of terminating at discovery.* It is plausible but unproven, and it
deliberately diverges from the current scoring regimes in ways that can help or
hurt depending on the corpus. It must be earned by an A/B, not asserted.

## Deliberate first-cut limits (each is a follow-up, not a hidden gap)

1. **Projection at the fusion boundary.** Dominance, support floors, and
   `adaptive_cap` still operate on **files**, not entity keys. Re-keying the
   ~40-function post-fusion pipeline (which indexes `all_hits` by path
   throughout) to entities is not a surgical change and would risk the
   just-proven locate determinism. Full entity-granular floors/cap is the
   natural next step **after** this fuser proves out.
2. **Only entity-derived signals carry entity keys.** Text/traceback/import
   signals stay file-granular because their `FileHit{score,spans}` hold no
   entity id (the documented seam). Extending entity granularity to them means
   populating `FileHit.entity` at the ~25 extractor sites where `entity.id` is in
   scope — additive, but out of scope under freeze.
3. **Per-entity resolve scores are discovery scores**, not the full
   direct/graph blend + definition-authority weighting that
   `resolve_entities_to_files` applies at file granularity. RRF is rank-dominated
   so this is a reasonable first cut; a richer per-entity score is a refinement.
4. **Uniform rank-space RRF, no track regimes.** The entity fuser drops the
   TracebackDominant / EntityDominant / BroadBlend cliff regimes, matching the
   scoring-mechanics-map recommendation (shrink mechanisms, move to rank space).
   This is intentional and is part of what the A/B measures.

## Evidence required to flip the default

Run the serialized post-freeze A/B (OFF vs `KIN_LOCATE_ENTITY_FUSION=1`) on the
same gold sets and machine profile the freeze used. Decision metrics, in
priority order:

1. **Top-entity MRR** (bench metric added in 3.3) — the bet's primary target.
   Entity-granular fusion should move this if the thesis holds. A flat or
   negative top-entity MRR is a direct refutation.
2. **Symbol-level and line-level F1** (added to the active eval suite) — the
   downstream surface most sensitive to which entity ranks first. Must not
   regress.
3. **File-level F1 / precision / recall** — the legacy headline. The flip is only
   defensible if file-level metrics hold (no worse than noise) while entity/symbol
   metrics improve.
4. **Per-task whiplash** — count tasks that flip. Because the ON path removes the
   track cliffs, expect movement; confirm it is *net positive*, not churn.

### Success gate (proposed)

Flip the default only if, on the combined gold sets:

- top-entity MRR improves by more than run-to-run variance, **and**
- symbol-level and line-level F1 each hold or improve, **and**
- file-level F1 does not regress beyond noise, **and**
- no previously-passing gold drops to F1 = 0 without a named, accepted reason.

If top-entity MRR improves but file-level F1 regresses, do **not** flip globally;
instead consider routing entity fusion only for entity/symbol-shaped queries, or
land limit (1) (entity-granular floors/cap) first and re-measure.

## A/B procedure notes

- Honor the freeze contract: serialize the run (one workstream on the shared
  GPU), key liveness on persisted-progress delta, and capture a machine profile.
- Compare against the byte-identity baseline already captured for the freeze
  verdict; OFF must reproduce it exactly (a cheap guardrail that the gating did
  not perturb the default path).
- Report which Kin surface was exercised honestly: this is Kin's own
  retrieval/fusion under test, not a local heuristic.

## Pointers

- Implementation: `crates/kin-cli/src/commands/locate.rs` —
  `entity_seed_keyed`, `reciprocal_rank_fusion_entities`,
  `entity_granular_fused_files`, and the flag branch at the `let mut fused = …`
  fusion point. Identity recovery for `--explain`: `entity_resolve_identity`.
- Background: `planning/kin-scoring-mechanics-map-jun9.md` (the 240-knob
  diagnosis and the rank-space recommendation this fuser follows).
