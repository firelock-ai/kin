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

- [express](/Users/troyfortinjr/GitHub/kin/.kin/bench/live-20260313-151549.json)
- [flask](/Users/troyfortinjr/GitHub/kin/.kin/bench/live-20260313-151622.json)
- [hono](/Users/troyfortinjr/GitHub/kin/.kin/bench/live-20260313-153000.json)
- [zod](/Users/troyfortinjr/GitHub/kin/.kin/bench/live-20260313-153049.json)
- [typer](/Users/troyfortinjr/GitHub/kin/.kin/bench/live-20260313-154507.json)
- [fastapi](/Users/troyfortinjr/GitHub/kin/.kin/bench/live-20260313-161229.json)

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

What is already true in the codebase:

- managed assistant docs are a real write path via `kin assistant sync`
- managed blocks preserve user-written content outside the Kin block
- session reconciliation copies modified and newly added files back into the source tree
- non-indexable files can still be written back during reconcile
- `kin open --wait` already supports the expected "edit, reconcile, clean up" flow

What is not yet proven well enough for launch messaging:

- generic doc authoring on files like `README.md`
- end-to-end create / rename / delete workflows in a real Kin session
- build / test / fix loops after edits
- doc updates that follow code changes
- mutation benchmarks that show Kin helps with implementation work, not just discovery

Pre-launch parity checks:

- Read/search parity:
  - verify an agent can find the right files, symbols, and call chains in both `compat` and `native-cli`
  - verify fallback file reads still work where they are supposed to
- Edit parity:
  - add an end-to-end test that edits an existing source file in a session workspace and reconciles it back
  - add an end-to-end test that edits `README.md` in a session workspace and reconciles it back
  - add an end-to-end test that edits `AGENTS.md` manually, runs `kin assistant sync`, and confirms user content survives
- Create parity:
  - add an end-to-end test that creates a new source file in session, reconciles it, and confirms it is indexed
  - add an end-to-end test that creates a new non-code doc file in session, reconciles it, and confirms it persists
- Delete parity:
  - add an end-to-end test that deletes a source file in session and confirms reconcile removes it cleanly
  - add an end-to-end test that deletes a doc file in session and confirms the result is predictable
- Rename/move parity:
  - add an end-to-end test that renames a source file and confirms reconcile handles remove + add correctly
  - add an end-to-end test that moves a doc file across directories and confirms it persists
- Session UX parity:
  - verify `kin open --wait` succeeds for edit + reconcile + cleanup on a real repo fixture
  - verify failed reconcile leaves the session workspace intact with a clear recovery message
  - verify session cleanup never destroys unreconciled user work
- Build/test parity:
  - add an acceptance test where an agent-or-script edits code in session, runs the repo test command, fixes the issue, then reconciles
  - verify common generated artifacts or test output do not poison reconciliation
- Native-mode parity:
  - verify all of the above work in both `compat` and `native`
  - verify restrictions like `--restrict-discovery` and `--restrict-filesystem` block only what they are supposed to block
  - verify native-to-compat restore still protects against collisions and data loss
- Docs/story parity:
  - verify living docs generation is clearly separated from user-authored docs
  - verify generated docs are not presented as manually editable project docs
  - add one benchmark or demo task where code is changed and the relevant docs are updated afterward

Recommended mutation benchmark tasks:

- implement a small cross-file feature, then run tests
- fix a deliberately broken test by tracing the failure to the right module
- rename a public symbol across multiple files and update callers
- remove dead code and clean up imports / call sites
- update `README.md` or `AGENTS.md` after a command or API change
- write a short architecture note for a subsystem using Kin-discovered context

Publishable claim threshold:

- Do not say "Kin supports full coding workflows" until at least one create, one edit, one delete, one rename, one build/test/fix, and one doc-update path are covered by end-to-end tests.
- Do not say "Kin is good for docs" until `README.md`-style editing is proven by an acceptance test and at least one benchmark/demo task.

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
- one small capability-parity section covering edit/create/delete/docs support

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
6. Add the capability-parity checklist results for edit/create/delete/docs flows.
7. Run a smaller experimental `kin-codex` matrix on 3 repos.
8. Only include `kin-codex` publicly if all rows are stable and explainable.

## 12. Go / No-Go Checklist

Go:

- 4-arm Claude table rerun cleanly on an idle machine
- medians preserve the current story
- raw artifacts are linked
- benchmark methodology is written down
- capability-parity checks are written down and at least the critical ones are green
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
