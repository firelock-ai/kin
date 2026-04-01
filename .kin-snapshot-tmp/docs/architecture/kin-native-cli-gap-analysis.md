# Kin-Native CLI Gap Analysis

This document captures what is still missing to make Kin-native workflows work well across external code assistants such as Claude Code, Codex, and Gemini CLI.

## Thesis

Kin-native mode is not just "hide files at the root". It is a process-specific projection model:

- Graph + blobs are truth
- Agents should see a control root and Kin-first workflow
- Compilers, test runners, shells, editors, and Docker-like tools should see materialized execution workspaces
- Files are compatibility projections, not the source of truth

The central question is not "do files exist?" It is:

> Does each process get the right projection for its job?

## Current State

What is already real:

- `kin mode native`
- `kin with`
- `kin shell`
- `kin open`
- `kin exec`
- native source-root layout
- assistant bootstrap docs
- Claude/Codex/Gemini benchmark arms
- conversion caching and warm-cache benchmark restores
- step traces, subagent rollups, shim logs, cost attribution

What this means in practice:

- Kin-native is no longer just a spec
- Native mode can be benchmarked today
- Native mode is already competitive on some focused workloads
- But external assistants still carry file-first instincts that frequently fight the product

## What Is Still Missing

### 1. External CLIs still think file-first

Even in native mode, the outside assistant runtimes still:

- fall back to filesystem exploration
- overuse broad search
- spawn subagents that do generic repo exploration
- treat Kin commands as extra tools, not the primary navigation model

This is the core mismatch.

### 2. Native mode still relies too much on prompt shaping

Improved bootstrap docs and prompt guidance helped materially, but this is still a weak control mechanism.

Prompt guidance is:

- necessary
- useful
- not enough

If the model's default policy is file-first, prompt-only steering will continue to leak.

### 3. The shell contract is not yet the product contract

The real Kin-native end state requires:

- filesystem discovery commands to be redirected or denied
- content reads to be redirected or denied
- execution commands to be routed through Kin
- different process classes to see different realities

Today this exists partially through shims and benchmark controls, but not yet as a complete, default, product-quality runtime contract.

### 4. Session lifecycle still needs tightening

Native mode still needs a more cohesive loop around:

- session start
- workspace materialization
- editing/running
- reconcile
- cleanup

This is especially important for editor-driven flows and human/native hybrid workflows.

### 5. Benchmarks still mix product questions

There are really three different benchmark questions:

1. How expensive is conversion into Kin?
2. How much better is work inside Kin once converted?
3. How much better is true Kin-native work than file-first work?

These need distinct benchmark modes and distinct success criteria.

## External CLI Specific Gaps

### Claude Code

Strengths:

- strongest telemetry now
- good stream-json output
- subagent activity is visible
- prompt shaping has clear effects

Gaps:

- builtin tools (`Read`, `Grep`, `Glob`, `LS`) must be actively constrained in strict native mode
- subagents (`Task` / Explore-style delegation) can still create off-policy work unless explicitly disabled
- still prone to broad `kin search --show-body` fan-out instead of precise `kin trace` flows

Required improvements:

- better default Kin-native task planning
- stronger native strict-mode policies
- more one-shot Kin commands that reduce search staircases

### Codex

Strengths:

- best diagnostic assistant today
- strongest step-level traceability
- CLI shape fits Kin's workflow well
- easiest path to eventual fork

Gaps:

- still tends to treat Kin as additive rather than substitutive unless the environment is carefully constrained
- still falls back to shell habits without strong enforcement

Required improvements:

- native shell contract should feel natural, not exceptional
- semantic commands must beat shell exploration on both latency and utility

### Gemini CLI

Strengths:

- viable future surface

Gaps:

- runtime/auth stability still lags
- not yet a reliable optimization target

Required improvements:

- stabilize execution first
- only optimize once runs are consistent and comparable

## Cross-CLI Product Gaps

These matter regardless of assistant vendor.

### A. Better one-shot semantic commands

Native mode improves when agents need fewer turns.

The main pattern so far:

- `kin trace` beats repeated `kin search`
- broad `kin search --show-body` calls are expensive

Needed direction:

- push more work into high-signal one-shot commands
- reduce output volume
- optimize around exact symbol flow tracing

### B. Better policy separation

Kin should support explicit workflow modes:

- `compat`
- `native`
- `native-strict-discovery`
- `native-strict-filesystem`

This is both a product feature and a benchmark feature.

### C. Better session orchestration

The system still needs a cleaner story for:

- `kin open`
- editor-integrated terminals
- session close/reconcile/cleanup
- multiple simultaneous projections

### D. Better native observability

Telemetry is now strong enough to optimize with, but we still want:

- per-step token attribution
- richer shim-log usage in normal product flows
- more direct comparison of "what the agent wanted to do" vs "what Kin made cheap"

## What "Done" Looks Like For External CLIs

Kin-native is working well across external CLIs when the following are true:

- native mode beats or matches compat mode on focused symbolic tasks
- strict native mode shows high Kin-first ratios without huge token blowups
- the assistant does not need repeated prompt babysitting to behave semantically
- most discovery happens through Kin primitives, not shell probing
- subagents either inherit Kin policy or become unnecessary

At that point, external CLIs become acceptable frontends.

## Why This Still Points Toward A Fork

Even if all of the above is improved, external CLIs still own:

- planner behavior
- fallback behavior
- subagent spawning rules
- tool preference policy
- output verbosity policy

That means Kin can guide them, but not fully define them.

If Kin-native is the end-state product, then eventually Kin needs a runtime where:

- semantic navigation is the default
- file-first behavior is not the dominant fallback
- subagents are Kin-native by construction
- telemetry is first-class and complete

That is the argument for a Kin-first fork.

## Recommended Near-Term Order

1. Keep hardening Claude as the best benchmarked external frontend
2. Keep Codex as the best diagnostic frontend
3. Stabilize benchmark methodology and native shell policy
4. Continue tightening one-shot Kin-native commands
5. Pivot to a Kin-first Codex-derived runtime once the behavioral contract is well understood

## Decision Rule

Every feature should be tested against this question:

> Does this make the graph more essential and the filesystem more disposable?

If yes, it is moving Kin-native mode forward.
If no, it is probably compatibility debt.
