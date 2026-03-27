# ADR: Command Surface Consistency

**Status:** Informational
**Date:** 2026-03-26
**Authors:** Troy Fortin

## Context

The CLI has five commands that execute or launch external processes in the
context of a Kin workspace: `exec`, `run`, `with`, `shell`, and `open`.
Their names suggest overlap, but each has distinct semantics.

## Command Semantics

### `kin exec <command>` — Materialized execution

Materializes a workspace copy (via `kin-runtime`), runs the command in it,
optionally keeps the workspace afterward (`--keep`). Supports
`--strategy` (copy/reflink/hardlink) and `--scope` for partial
materialization. Primary use: running tests, builds, or linters against
a clean materialized snapshot.

### `kin run <command>` — Validation run with evidence capture

Executes a command and captures structured evidence (stdout, stderr,
exit code, duration) via `kin-runtime::create_run` / `execute_run`.
Does NOT materialize a workspace — runs in the current working directory.
Primary use: benchmark runs and validation evidence for `kin-bench`.

### `kin with <assistant> -- <task>` — Launch an AI assistant with guidance

Generates a Kin-specific system prompt for the given assistant type
(claude-code, codex, gemini-cli) and launches it with the task.
Injects guidance about the semantic graph, entity structure, and
Kin commands. Primary use: AI-assisted development with Kin awareness.

### `kin shell [--strategy <s>]` — Interactive shell in materialized workspace

Creates a materialized workspace, launches an interactive shell in it,
and reconciles changes back on exit. The session is isolated — changes
are applied to the graph only after the shell exits. Supports
`--restrict-discovery` and `--restrict-filesystem` for native mode
VFS controls. Primary use: interactive development sessions.

### `kin open <editor>` — Launch editor in materialized workspace

Like `shell`, but launches a GUI editor instead of a terminal shell.
Creates a materialized workspace, opens the editor, and optionally
waits (`--wait`) for the editor to close before reconciling.
Primary use: VS Code / editor-based development sessions.

## Consistency Analysis

| Command | Materializes? | Captures evidence? | Interactive? | AI-specific? |
|---------|--------------|-------------------|-------------|-------------|
| `exec`  | Yes          | No                | No          | No          |
| `run`   | No           | Yes               | No          | No          |
| `with`  | No           | No                | Yes         | Yes         |
| `shell` | Yes          | No                | Yes         | No          |
| `open`  | Yes          | No                | Yes         | No          |

### Observations

1. **`exec` vs `run`:** Despite similar names, these are fundamentally different.
   `exec` materializes + executes; `run` captures evidence without materialization.
   The naming could confuse users who expect `run` to be the simpler version of `exec`.

2. **`shell` vs `open`:** Nearly identical in behavior (materialize + launch + reconcile).
   The only difference is shell launches `$SHELL` while open launches an editor.
   These could be consolidated: `kin open $SHELL` would be equivalent to `kin shell`.

3. **`with`:** Unique and well-named — clearly indicates "with this assistant."

### Consolidation Candidates

- **`shell` into `open`:** `kin open shell` or `kin open --shell` could replace
  `kin shell`. Both create materialized workspaces and reconcile on exit.

- **`run` rename consideration:** `kin bench-run` or `kin validate` would better
  convey the evidence-capture purpose vs. general execution.

## Decision

No changes in this phase. The current five commands are all actively used and
have distinct purposes. The `shell`/`open` consolidation is the strongest
candidate for a future simplification pass.

For now, this ADR documents the semantics for reference and identifies the
consolidation opportunity.
