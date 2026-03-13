# Open Source Drop Checklist

This document turns the current benchmark and product work into a concrete launch plan.

It assumes:

- the main public story is about **Kin as a useful tool today**
- the benchmark headline is based on the **validated 4-arm Claude slice**
- `kin-codex` is shown as **promising but experimental**

## 1. Safe Launch Story

Use this story for the open source drop:

- Kin makes AI codebase understanding materially faster on real repos after indexing.
- `compat` is the low-friction path.
- `native-cli` is the highest-performance path today.
- `native-mcp` is real and useful, but not the current winner.
- `kin-codex` is an experimental Kin-first runtime direction, not the core launch claim.

Do not use this story:

- "every assistant behaves this way"
- "MCP is the best path today"
- "`kin-codex-native` is production-ready"
- "these numbers are universal outside the tested tasks/repos"

## 2. Validated Evidence We Already Have

The current Claude-only 4-arm reports are the right baseline for launch messaging:

- [express](.kin/bench/live-20260313-151549.json)
- [flask](.kin/bench/live-20260313-151622.json)
- [hono](.kin/bench/live-20260313-153000.json)
- [zod](.kin/bench/live-20260313-153049.json)
- [typer](.kin/bench/live-20260313-154507.json)
- [fastapi](.kin/bench/live-20260313-161229.json)

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

- `kin-codex-native`
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
- Treat `kin-codex-native` as opt-in experimental only.
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
- "`kin-codex` is ready as the default experience"

These claims are NOT yet supported by any evidence:

- "Kin supports full coding workflows" — no mutation acceptance tests or benchmarks exist (see Section 7)
- "Kin is good for docs" — no doc-editing acceptance test or benchmark exists
- "Kin helps with implementation, not just discovery" — all benchmarks are read-only discovery tasks

## 6. Code Story Checklist

This is the code-facing story that needs to be true at launch.

Already done:

- benchmark harness hardening
- native MCP wiring for Codex and Gemini
- timeout handling for native arms
- real repo-name reporting instead of workspace IDs
- default live benchmark narrowed back to the 4 core product arms
- `kin-codex-native` moved behind an explicit opt-in flag

Still worth checking before launch:

- verify the all-arm timeout policy with a real Gemini run
- verify the default summary output never mentions `kin-codex-native` unless the flag is set
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

### What Is Implemented but Not Yet Proven by End-to-End Tests

These workflows are wired in the code but have no acceptance test that exercises the full pipeline (materialize → user edit → reconcile → verify graph state):

- **Edit an existing source file** in a session workspace, reconcile, and confirm the graph reflects the change.
- **Edit a doc file like `README.md`** in a session workspace, reconcile, and confirm it persists correctly.
- **Create a new source file** in session, reconcile, and confirm it is indexed with entities in the graph.
- **Create a new non-code file** in session, reconcile, and confirm it persists.
- **Delete a source file** in session and confirm reconcile removes it and its entities cleanly.
- **Build/test/fix loops**: `kin exec` can run build/test commands, but no acceptance test exercises the cycle of edit → test → fix → reconcile.
- **Session cleanup safety**: no test verifies that cleanup never destroys unreconciled user work after a failed reconcile.

### What Is Not Yet Implemented

These capabilities do not exist in the codebase today:

- **`kin workspace delete`** — there is no delete subcommand. Only `list`, `create`, and `switch` exist.
- **`kin workspace rename`** — there is no rename subcommand.
- **Mutation benchmarks** — the benchmark harness (`kin bench live`) only runs code-understanding / discovery tasks. All benchmark prompts ask agents to trace, search, and explain code. Zero benchmark tasks involve editing, implementing, fixing, or creating code.
- **Doc-update benchmark tasks** — no benchmark task asks an agent to update docs after a code change.

### Pre-launch Parity Checks

Items marked [PROVEN] have tests today. Items marked [NEEDED] require new tests before claiming the capability publicly.

- Read/search parity:
  - [PROVEN] agents can find the right files, symbols, and call chains in both `compat` and `native-cli` (validated by 6-repo benchmark)
  - [PROVEN] fallback file reads work where they are supposed to (native shim tests)
- Edit parity:
  - [NEEDED] end-to-end test that edits an existing source file in a session workspace and reconciles it back
  - [NEEDED] end-to-end test that edits `README.md` in a session workspace and reconciles it back
  - [PROVEN] `kin assistant sync` preserves user content outside managed blocks (unit tests in `assistant_sync.rs`)
- Create parity:
  - [NEEDED] end-to-end test that creates a new source file in session, reconciles it, and confirms it is indexed
  - [NEEDED] end-to-end test that creates a new non-code doc file in session, reconciles it, and confirms it persists
- Delete parity:
  - [NEEDED] end-to-end test that deletes a source file in session and confirms reconcile removes it cleanly
  - [NEEDED] end-to-end test that deletes a doc file in session and confirms the result is predictable
- Rename/move parity:
  - [NOT IMPLEMENTED] `kin workspace rename` does not exist yet
  - [NEEDED] end-to-end test that renames a source file and confirms reconcile handles remove + add correctly
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

### Recommended Mutation Benchmark Tasks (Not Yet Built)

None of these exist in the benchmark harness today. All current benchmarks are read-only discovery tasks.

- implement a small cross-file feature, then run tests
- fix a deliberately broken test by tracing the failure to the right module
- rename a public symbol across multiple files and update callers
- remove dead code and clean up imports / call sites
- update `README.md` or `AGENTS.md` after a command or API change
- write a short architecture note for a subsystem using Kin-discovered context

### Publishable Claim Threshold

- Do not say "Kin supports full coding workflows" until at least one create, one edit, one delete, one rename, one build/test/fix, and one doc-update path are covered by end-to-end acceptance tests. **Current status: none of these acceptance tests exist yet.**
- Do not say "Kin is good for docs" until `README.md`-style editing is proven by an acceptance test and at least one benchmark/demo task. **Current status: not proven.**
- The current benchmark evidence supports only this claim: **"Kin makes AI-driven code understanding and discovery faster."** Mutation/implementation claims are not yet supported by any benchmark data.

## 8. First-Run vs Warm-Run Story

The launch materials should separate:

- **conversion/indexing cost**
- **warm query performance**

Include both:

1. A small appendix or side table for `kin init + kin commit` conversion cost
2. The main benchmark table for post-index code-understanding performance

Without this split, readers will correctly call out that the main table hides first-run setup cost.

## 9. Experimental `kin-codex` Checklist

`kin-codex` should be shown, but clearly labeled experimental until all of the following are true:

- it finishes reliably across small, medium, and large repos
- it exits cleanly under timeout pressure
- it consistently produces output/tokens in benchmark runs
- it uses the intended Kin-native access path, not accidental prompt-only luck
- it can beat or match generic Codex on the tasks you show publicly

Before putting `kin-codex` in a public comparison table:

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
- one experimental appendix for `kin-codex`
- one honest capability-parity section noting that edit/create/delete are implemented but not yet proven by acceptance tests or benchmarks (see Section 7)

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
6. Add the capability-parity status (see Section 7 — currently no mutation acceptance tests or benchmarks exist).
7. Run a smaller experimental `kin-codex` matrix on 3 repos.
8. Only include `kin-codex` publicly if all rows are stable and explainable.

## 12. Go / No-Go Checklist

Go:

- 4-arm Claude table rerun cleanly on an idle machine
- medians preserve the current story
- raw artifacts are linked
- benchmark methodology is written down
- capability-parity status is documented honestly (see Section 7 — edit/create/delete are implemented but unproven; mutation benchmarks do not exist yet)
- no broken or hidden rows in the main table

No-go:

- published table depends on one-off noisy runs
- main table includes experimental arms
- repo names or commits are missing
- raw reports are not available
- launch copy claims coding/doc-edit support that has not been tested end to end
- `kin-codex` is still timing out or behaving inconsistently

## 13. Launch Message Template

Use a simple message:

> Kin gives AI agents a semantic operating layer for codebases. On real open source repos and repeatable code-understanding tasks, Kin beats raw git exploration, with `compat` as the easy path and `native-cli` as the fastest path today. We are also building a Kin-first Codex fork, `kin-codex`, and will publish that separately as an experimental runtime.
