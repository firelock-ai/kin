# kin-cli clippy triage — path to clippy-green without churning frozen ranking code

Read-only triage (no code changed). Counts captured from `cargo clippy -p kin-cli
--lib --tests --message-format=json` at kin main `7f652c4`; treat exact counts as
±small drift until ci-green's re-pre-flight after the ci-fix merge — the
**bucketing and policy below are the deliverable** and are drift-stable.

## Totals (kin-cli-own warnings only; dependency-crate warnings excluded)

| | distinct warnings |
|---|---|
| **kin-cli total** | **140** |
| in `src/commands/locate.rs` (FROZEN ranking) | 59 |
| in the other 24 kin-cli files | 81 |
| → mechanical/auto-fixable (FIX) | 99 (32 in locate.rs, 67 elsewhere) |
| → signature/semantic-risk (ALLOW) | 41 (27 in locate.rs, 14 elsewhere) |

`daemon_client.rs` alone holds 36 (all `needless_question_mark`); the next 23
files hold 1–6 each.

## Bucketed table (lint × where × treatment)

`tot` = kin-cli total · `loc` = in locate.rs · `oth` = other kin-cli files.

| tot | loc | oth | bucket | lint | treatment |
|----:|----:|----:|--------|------|-----------|
| 36 | 0 | 36 | FIX | needless_question_mark | `clippy --fix` (daemon_client.rs) |
| 19 | 5 | 14 | FIX | needless_borrow | `clippy --fix` (defer the 5 in locate.rs) |
| 14 | 9 | 5 | ALLOW | **deprecated** (ArtifactId::from_path) | scoped `#[allow(deprecated)]` + tracked migration follow-up |
| 8 | 5 | 3 | ALLOW | too_many_arguments | crate/per-fn `#[allow]` (ranking fns carry many knobs) |
| 8 | 7 | 1 | FIX | unnecessary_map_or | `clippy --fix` (defer the 7 in locate.rs) |
| 7 | 6 | 1 | FIX | clone_on_copy | `clippy --fix` (defer the 6 in locate.rs) |
| 7 | 7 | 0 | ALLOW | **ptr_arg** (&Vec→&[T]) | `#[allow]` — signature change ripples to ranking callers |
| 4 | 4 | 0 | FIX | needless_option_as_deref | defer (all in locate.rs) |
| 4 | 2 | 2 | ALLOW | type_complexity | `#[allow]` or type alias post-freeze |
| 3 | 0 | 3 | FIX | doc_overindented_list_items | `clippy --fix` |
| 3 | 2 | 1 | ALLOW | **if_same_then_else** | `#[allow]` — **DO NOT auto-fix** (see callouts) |
| 3 | 1 | 2 | FIX | manual_contains | `clippy --fix` (defer the 1 in locate.rs) |
| 3 | 3 | 0 | FIX | manual_pattern_char_comparison | defer (all in locate.rs) |
| 2 | 1 | 1 | FIX | collapsible_if | `clippy --fix` (defer locate.rs one) |
| 2 | 1 | 1 | ALLOW | field_reassign_with_default | easy real fix; defer locate.rs one |
| 2 | 2 | 0 | FIX | filter_map_bool_then | defer (locate.rs) |
| 2 | 0 | 2 | FIX | manual_is_multiple_of | `clippy --fix` |
| 2 | 0 | 2 | FIX | needless_return | `clippy --fix` |
| 1 | 1 | 0 | ALLOW | **regex_creation_in_loops** | real PERF fix, but in ranking hot path → post-freeze (see callouts) |
| 1 | 0 | 1 | ALLOW | only_used_in_recursion | `#[allow]` or drop param post-freeze |
| 1 | 0 | 1 | ALLOW | items_after_test_module | move item (trivial) |
| — | — | — | FIX | derivable_impls, for_kv_map, format_in_format_args, manual_strip, redundant_closure, redundant_field_names, unnecessary_sort_by, unnecessary_unwrap (1 each) | `clippy --fix` |

## Recommended minimal path to kin-cli-clippy-green

**Step 1 — fix the 67 mechanical non-locate warnings (safe now, zero ranking risk).**
`cargo clippy --fix -p kin-cli` then `git checkout -- crates/kin-cli/src/commands/locate.rs`
to drop any auto-edits to the frozen file. Clears ~67 warnings across daemon_client.rs
(36) + 23 small files. Review the diff (mechanical, but `unnecessary_unwrap`/
`field_reassign_with_default` deserve a glance).

**Step 2 — unblock locate.rs's 59 without touching ranking.** Add ONE
module-level `#[allow(...)]` block at the top of `locate.rs` enumerating the lints
present there, with a comment that the ranking module is under freeze and a
post-freeze cleanup task owns the real fixes. This is **attributes-only → byte-identical
ranking output**, so it does not jeopardize the freeze verdict, and it touches no
ranking expression. (Alternative: a crate-level `[lints.clippy]` in Cargo.toml, but
that over-suppresses the non-locate files we just fixed — prefer the scoped module attr.)

**Step 3 — post-freeze cleanup task (new slot).** `cargo clippy --fix` the 32
cosmetic locate.rs lints, then shrink the Step-2 allow list to only the
permanent-justified lints: `if_same_then_else`, `ptr_arg`, `too_many_arguments`,
`type_complexity`, and `deprecated` (until the ArtifactId migration lands). Re-run
the locate byte-identity snapshot after to confirm no ranking drift.

## Freeze callouts (read before anyone runs `clippy --fix` on locate.rs)

- **`if_same_then_else` (2 in locate.rs) — NEVER auto-fix.** These are the
  intentional identical branches in the dominance/compression scoring regimes.
  `clippy --fix` would collapse them and silently change ranking structure. Permanent
  `#[allow]` (or a deliberate, A/B'd refactor post-freeze).
- **`deprecated` / ArtifactId::from_path (9 in locate.rs).** A real migration to
  graph-assigned ids via artifact_index lookup — behavior-adjacent (artifact
  resolution), not cosmetic. Coordinate with the deprecation owner; `#[allow(deprecated)]`
  for now, not a freeze-window edit.
- **`ptr_arg` (7 in locate.rs).** `&Vec<T>`→`&[T]` changes ranking-fn signatures and
  ripples to every caller — defer.
- **`regex_creation_in_loops` (1 in locate.rs).** A genuine perf bug (regex compiled
  inside a loop), but it sits in ranking code; fixing alters a hot path. Track as a
  post-freeze perf fix, not a clippy cosmetic.

## Status

No code changed by this triage. Policy decision (which lints → fix vs scoped-allow vs
crate lint-config, and when to run Steps 1–2 relative to the freeze) is for team-lead,
with ci-green's authoritative re-pre-flight counts after the ci-fix merge.
