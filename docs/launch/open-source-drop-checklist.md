# Public Alpha Drop Checklist (Historical Claude 4-Arm Draft)

> Archived working draft: this checklist was written around an earlier Claude-focused 4-arm benchmark story. It is not the current public benchmark headline for Kin's public alpha, and it should not be linked from launch posts or used as the release source of truth. For the current checked public benchmark summary, use [validated-popular-repos-2026-03-20.md](../benchmarks/validated-popular-repos-2026-03-20.md) and the root launch materials.

This document preserves a superseded launch draft for historical context.

It assumed:

- the main public story was about **Kin as a useful tool today**
- the benchmark headline was based on the **validated 4-arm Claude slice**
- `kin-pilot` was shown as **promising but experimental**

## 1. Safe Launch Story

Use this story for the public alpha drop:

- Kin makes AI codebase understanding materially faster on real repos after indexing.
- `compat` is the low-friction path.
- `native-cli` is the highest-performance path today.
- `native-mcp` is real and useful, but not the current winner.
- `kin-pilot` is an experimental Kin-first runtime direction, not the core launch claim.

Do not use this story:

- "every assistant behaves this way"
- "MCP is the best path today"
- "`kin-pilot-native` is production-ready"
- "these numbers are universal outside the tested tasks/repos"

## 2. Historical Evidence Snapshot

These older Claude-only 4-arm reports informed an earlier draft story, but they are superseded by the current public benchmark package:

- `live-20260313-151549.json` (`express`)
- `live-20260313-151622.json` (`flask`)
- `live-20260313-153000.json` (`hono`)
- `live-20260313-153049.json` (`zod`)
- `live-20260313-154507.json` (`typer`)
- `live-20260313-161229.json` (`fastapi`)

What these support:

- Kin beats raw git on all 6 tested repos.
- `compat` is consistently useful.
- `native-cli` is usually the best performer.
- `native-mcp` is slower than `native-cli`, but still beats git and even beats compat on `fastapi`.

## 3. Main Table Scope

The main public benchmark table should include only:

- assistant: `Claude Code`
- arms: `git`, `compat`, `native-mcp`, `native-cli`
- repos: 6 to 10 recognizable open source repos
- task type: code-understanding / cross-file tracing tasks

The main table should not include:

- `kin-pilot-native`
- multi-assistant averages
- mixed assistant/runtime rows
- failed or timeout rows

Those belong in a separate **experimental** appendix.

## 4. Benchmark Methodology Checklist

Before publishing the table:

- Run the benchmark on an idle machine.
- Kill competing `claude`, `codex`, `gemini`, and other heavy local processes.
- Record machine details: CPU, RAM, OS, Node version, CLI versions.
- Record the exact repo commit SHA for every repo.
- Record the exact prompt for every repo.
- Run each repo at least `3x`.
- Publish the **median** per arm, not a single lucky run.
- Save and link the raw JSON report for every benchmarked repo.
- Save the final benchmark command used to generate the table.

Benchmark guardrails:

- Use the default 4-arm matrix for the main table.
- Treat `kin-pilot-native` as opt-in experimental only.
- Exclude runs with clear contention or machine sleep.
- Do not average successful and timeout runs together.
- If a row times out, label it as a timeout, not as a missing datapoint.

## 5. Product Claims Checklist

These claims are safe if the reruns hold:

- "Kin beats raw git on these code-understanding tasks."
- "`compat` is the easiest on-ramp."
- "`native-cli` is the fastest path today."
- "Warm Kin queries use dramatically fewer tokens than file-first exploration."

These claims need extra qualification:

- "`native-mcp` should be dropped"
- "all assistants benefit equally"
- "`kin-pilot` is ready as the default experience"

These claims are now partially supported:

- "Kin supports full coding workflows" — acceptance tests prove edit, create, delete, and round-trip mutation (see Section 7). Mutation benchmark task exists (`--task-set mutation`) but has not yet been run at scale.
- "Kin is good for docs" — README editing is tested in acceptance suite. No doc-specific benchmark task yet.
- "Kin helps with implementation, not just discovery" — mutation benchmark task (`add-status-endpoint`) exists. Needs scale runs for publishable data.

## 6. Code Story Checklist

This is the code-facing story that needs to be true at launch.

Already done:

- benchmark harness hardening
- native MCP wiring for Codex and Gemini
- timeout handling for native arms
- real repo-name reporting instead of workspace IDs
- default live benchmark narrowed back to the 4 core product arms
- `kin-pilot-native` moved behind an explicit opt-in flag

Still worth checking before launch:

- verify the all-arm timeout policy with a real Gemini run
- verify the default summary output never mentions `kin-pilot-native` unless the flag is set
- verify report JSON always includes the real repo name and commit SHA
- verify raw transcripts and step traces are saved for every published row
- verify `kin bench live --help` matches actual behavior exactly

## 7. Capability Parity Checklist

This is the missing pre-launch gate if the product story is "Kin can support real coding work, not just semantic discovery."

### What We Can Prove Today

These capabilities are implemented in the codebase with unit or integration tests:

- **Managed assistant docs** are a real write path via `kin assistant sync`. Managed blocks preserve user-written content outside the Kin block. (Tested in `assistant_sync.rs`.)
- **Session reconciliation detects added, modified, and deleted files** in session workspaces and copies changes back to the source tree. (Unit-tested in `reconcile.rs`: `diff_detects_added_file`, `diff_detects_deleted_file`, `diff_detects_modified_file`, `diff_detects_mixed_changes`, `diff_handles_nested_directories`.)
- **Session creation** works via `kin shell`, `kin open <editor>`, and `kin workspace create`. (Tested in `shell.rs`, `open.rs`, `workspace.rs`.)
- **`kin shell` auto-reconciles on exit** — the full materialize → shell → reconcile → cleanup flow is wired end-to-end. (Tested in `shell.rs`.)
- **`kin open --wait` blocks until the editor exits**, then auto-reconciles and cleans up. Error paths preserve the workspace. (Tested in `open.rs`.)
- **`kin exec <command>`** runs an arbitrary command in a materialized workspace with optional entity-scoped materialization. (Tested in `exec.rs`.)
- **Read/search parity**: `kin trace`, `kin search --show-body`, `kin overview`, `kin context` all work in both `compat` and `native-cli` modes. These are the capabilities validated by the current benchmark harness.
- **Native mode restrictions**: `--restrict-discovery` and `--restrict-filesystem` are implemented and tested.

### What Is Now Proven by End-to-End Acceptance Tests

These workflows are covered by the `p11_mutation_parity` acceptance test suite (`tests/integration/src/p11_mutation_parity.rs`):

- **[PROVEN] Edit an existing source file** → re-index → verify fingerprint changed and new entities appear (`test_edit_source_reconcile`)
- **[PROVEN] Edit a doc file like `README.md`** → re-index → verify handled gracefully (`test_edit_readme_round_trips_as_opaque_artifact`)
- **[PROVEN] Create a new source file** → index → verify entities appear in graph (`test_create_file_reconcile`)
- **[PROVEN] Delete a source file** → re-index → verify entities removed (`test_delete_file_reconcile`)
- **[PROVEN] Execute commands in workspace** → `kin exec` runs commands and returns output (`test_exec_in_workspace`)
- **[PROVEN] Full mutation round-trip** → create file → add function → remove original → verify graph state at each step (`test_full_mutation_round_trip`)

Still not tested:

- **Session cleanup safety**: no test verifies that cleanup never destroys unreconciled user work after a failed reconcile.
- **Build/test/fix cycle**: `kin exec` is proven for single commands, but no test exercises edit → test → fix → reconcile as a loop.

### What Was Not Implemented (Now Fixed)

These capabilities have been added:

- **[DONE] `kin workspace delete <name>`** — removes workspace directory and metadata, clears active marker if needed.
- **[DONE] `kin workspace rename <old> <new>`** — renames workspace metadata and updates active marker.
- **[DONE] Mutation benchmark task** — `add-status-endpoint` task asks agents to find the entry point and add a health check function. Selectable via `--task-set mutation`. Not yet run at scale.
- **[DONE] JS parser prototype methods** — `expression_statement` → `assignment_expression` with function RHS now extracted. Express.js coverage gap fixed.

Still not implemented:

- **Doc-update benchmark tasks** — no benchmark task asks an agent to update docs after a code change.

### Pre-launch Parity Checks

Items marked [PROVEN] have tests today. Items marked [NEEDED] require new tests before claiming the capability publicly.

- Read/search parity:
  - [PROVEN] agents can find the right files, symbols, and call chains in both `compat` and `native-cli` (validated by 6-repo benchmark)
  - [PROVEN] fallback file reads work where they are supposed to (native shim tests)
- Edit parity:
  - [PROVEN] end-to-end test that edits a source file and verifies graph update (`test_edit_source_reconcile`)
  - [PROVEN] end-to-end test that edits `README.md` and verifies graceful handling (`test_edit_readme_round_trips_as_opaque_artifact`)
  - [PROVEN] `kin assistant sync` preserves user content outside managed blocks (unit tests in `assistant_sync.rs`)
- Create parity:
  - [PROVEN] end-to-end test that creates a new source file and confirms entities appear (`test_create_file_reconcile`)
  - [PROVEN] end-to-end test that creates a new non-code doc file in session, reconciles it, and confirms it persists (`test_session_reconcile_adds_doc_file`)
- Delete parity:
  - [PROVEN] end-to-end test that deletes a source file and confirms entities removed (`test_delete_file_reconcile`)
  - [PROVEN] end-to-end test that deletes a doc file in session and confirms the result is predictable (`test_session_reconcile_deletes_doc_file`)
- Rename/move parity:
  - [DONE] `kin workspace rename` is implemented
  - [PROVEN] end-to-end test that renames a source file and confirms reconcile handles remove + add correctly (`test_session_reconcile_renames_source_file`)
- Session UX parity:
  - [PROVEN] `kin open --wait` blocks, reconciles, and cleans up (unit tests in `open.rs`)
  - [PROVEN] failed reconcile preserves the workspace with a recovery message (tested in `open.rs`)
  - [NEEDED] explicit test that session cleanup never destroys unreconciled user work
- Build/test parity:
  - [NEEDED] acceptance test where a script edits code in session, runs the repo test command, fixes the issue, then reconciles
  - [NEEDED] verify common generated artifacts or test output do not poison reconciliation
- Native-mode parity:
  - [PROVEN] `--restrict-discovery` and `--restrict-filesystem` block only what they are supposed to (tested in `shell.rs`, `open.rs`, `with.rs`)
  - [NEEDED] full round-trip (edit → reconcile → verify) tested in both `compat` and `native`
- Docs/story parity:
  - [PROVEN] living docs generation is separated from user-authored docs via managed blocks
  - [NEEDED] one benchmark or demo task where code is changed and the relevant docs are updated afterward

### Mutation Benchmark Tasks

One mutation task now exists in the harness: `add-status-endpoint` (add a health check function to any repo). Run with `--task-set mutation`.

Future mutation tasks to consider:

- fix a deliberately broken test by tracing the failure to the right module
- rename a public symbol across multiple files and update callers
- remove dead code and clean up imports / call sites
- update `README.md` or `AGENTS.md` after a command or API change

### Publishable Claim Threshold

- "Kin supports coding workflows": create, edit, delete, and full round-trip mutation are now **proven by acceptance tests**. Build/test/fix loop and doc-update paths still need tests.
- "Kin is good for docs": README editing acceptance test exists. No doc-specific benchmark task yet.
- **Discovery benchmark evidence is strong**: 6 repos, 4 arms, consistent speedups.
- **Mutation benchmark evidence is pending**: task exists (`--task-set mutation`) but has not been run at scale yet. Run it before claiming "Kin helps with implementation."

## 8. First-Run vs Warm-Run Story

The launch materials should separate:

- **conversion/indexing cost**
- **warm query performance**

Include both:

1. A small appendix or side table for `kin init + kin commit` conversion cost
2. The main benchmark table for post-index code-understanding performance

Without this split, readers will correctly call out that the main table hides first-run setup cost.

## 9. Experimental `kin-pilot` Checklist

`kin-pilot` should be shown, but clearly labeled experimental until all of the following are true:

- it finishes reliably across small, medium, and large repos
- it exits cleanly under timeout pressure
- it consistently produces output/tokens in benchmark runs
- it uses the intended Kin-native access path, not accidental prompt-only luck
- it can beat or match generic Codex on the tasks you show publicly

Before putting `kin-pilot` in a public comparison table:

- rerun it on at least 3 repos
- keep the prompts identical to the Codex comparison
- inspect step traces, not just wall time
- confirm whether success is:
  - prompt-first answer quality
  - MCP-native behavior
  - CLI-native behavior

Do not mix those three into one unlabeled result.

## 10. Launch Assets Checklist

Prepare these artifacts before the drop:

- main benchmark table
- raw JSON links for every row
- a short methodology section
- one benchmark command example
- one "how to reproduce" section
- one small appendix for conversion cost
- one experimental appendix for `kin-pilot`
- one honest capability-parity section noting that edit/create/delete are now covered by acceptance tests, while no scaled public mutation benchmark has been published yet (see Section 7)

Recommended table columns:

- Repo
- Commit
- Language
- Files
- Git
- Compat
- Native-MCP
- Native-CLI
- Best Speedup
- Best Token Reduction

Experimental appendix columns:

- Repo
- Assistant
- Arm
- Time
- Tokens
- Status
- Raw Report

## 11. Suggested Final Run Order

Use this order to get to publishable numbers quickly:

1. Freeze the prompt set.
2. Freeze the repo list and repo SHAs.
3. Run the 6 validated Claude repos again on an idle machine, `3x` each.
4. Compute medians and publish the 4-arm main table.
5. Add the conversion-cost appendix.
6. Add the capability-parity status (see Section 7 — mutation acceptance tests now exist, but no scaled public mutation benchmark has been published yet).
7. Run a smaller experimental `kin-pilot` matrix on 3 repos.
8. Only include `kin-pilot` publicly if all rows are stable and explainable.

## 12. Go / No-Go Checklist

Go:

- 4-arm Claude table rerun cleanly on an idle machine
- medians preserve the current story
- raw artifacts are linked
- benchmark methodology is written down
- capability-parity status is documented honestly (see Section 7 — edit/create/delete are acceptance-tested; mutation benchmarks are still unpublished)
- no broken or hidden rows in the main table

No-go:

- published table depends on one-off noisy runs
- main table includes experimental arms
- repo names or commits are missing
- raw reports are not available
- launch copy claims coding/doc-edit support that has not been tested end to end
- `kin-pilot` is still timing out or behaving inconsistently

## 13. Launch Message Template

Use a simple message:

> Kin gives AI agents a semantic operating layer for codebases. On real open source repos and repeatable code-understanding tasks, Kin beats raw git exploration, with `compat` as the easy path and `native-cli` as the fastest path today. We are also building a Kin-first Codex fork, `kin-pilot`, and will publish that separately as an experimental runtime.
