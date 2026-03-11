# Assistant Benchmarks

Kin can benchmark agent work on `git` vs `kin` by ingesting task-run artifacts into `kin bench`.

Published real-world benchmark pass:

- [Real Agent Benchmarks: Git vs Kin](./real-agent-git-vs-kin.md)

Primary commands:

- `kin bench run --assistant-run ...`
- `kin bench corpus --repo ...` or `--github-dir ...`
- `kin bench capture --assistant ...`
- `kin bench capture-artifact --vendor claude|codex|gemini --path ...`

Important distinction:

- `kin bench capture` records **manual** benchmark numbers supplied on the CLI.
- `kin bench capture-artifact` records numbers derived from raw assistant artifacts.
- the live harness in [`run_real_agent_benchmarks.py`](./run_real_agent_benchmarks.py) records end-to-end agent behavior against disposable repos.

For public benchmark claims, prefer artifact-derived or live-harness runs over manual captures.

## Native Run JSON

If you already have normalized run data, provide a single `AssistantTaskRun` object or an array:

```json
{
  "task_name": "refactor auth flow",
  "assistant_name": "Claude Code",
  "model_name": "claude-opus-4-6",
  "substrate": "kin",
  "duration_ms": 2500.0,
  "input_tokens": 1800,
  "output_tokens": 700,
  "total_tokens": 2500,
  "estimated_cost_usd": 0.17,
  "first_pass_success": true,
  "validation_passed": true,
  "notes": "Used semantic context pack",
  "recorded_at": "2026-03-10T18:00:00Z"
}
```

Run:

```bash
kin bench run --assistant-run claude-kin.json --assistant-run claude-git.json
```

## Import Specs

For external CLIs, point Kin at the artifact and tell it how to normalize it:

```json
{
  "task_name": "phase-7-gap-fix",
  "substrate": "kin",
  "source_format": "claude_code_jsonl",
  "source_path": "/Users/troyfortinjr/.claude/projects/-Users-troyfortinjr-GitHub-kin/674454d3-58de-42ff-acf3-582a88e9e4e2.jsonl",
  "first_pass_success": true,
  "validation_passed": true,
  "notes": "Imported from local Claude Code session"
}
```

The following source formats are supported:

- `codex_jsonl`
- `claude_code_jsonl`
- `gemini_cli_json`

## Codex

Codex stores session JSONL under `~/.codex/sessions/...`. Kin reads cumulative `token_count` events from those files.

Example spec:

```json
{
  "task_name": "semantic review",
  "substrate": "git",
  "source_format": "codex_jsonl",
  "source_path": "/Users/troyfortinjr/.codex/sessions/2026/02/13/rollout-2026-02-13T16-36-09-019c58ee-c854-7bf3-8fd8-ad4663778a9a.jsonl",
  "assistant_name": "Codex",
  "first_pass_success": false,
  "validation_passed": true
}
```

## Claude Code

Claude Code stores project and subagent JSONL under `~/.claude/projects/...`. Kin aggregates the `message.usage` records for assistant turns.

Example spec:

```json
{
  "task_name": "phase-7-gap-fix",
  "substrate": "kin",
  "source_format": "claude_code_jsonl",
  "source_path": "/Users/troyfortinjr/.claude/projects/-Users-troyfortinjr-GitHub-kin/674454d3-58de-42ff-acf3-582a88e9e4e2/subagents/agent-ae1f0ba4160e4eb74.jsonl",
  "assistant_name": "Claude Code",
  "first_pass_success": true,
  "validation_passed": true
}
```

## Gemini CLI

Gemini CLI supports machine-readable output directly:

```bash
gemini -p "Reply with OK and nothing else." --output-format json > gemini-run.json
```

Then import that JSON:

```json
{
  "task_name": "fallback classifier design",
  "substrate": "kin",
  "source_format": "gemini_cli_json",
  "source_path": "./gemini-run.json",
  "assistant_name": "Gemini CLI",
  "first_pass_success": true,
  "validation_passed": true
}
```

## Output

`kin bench` writes:

- `.kin/bench/bench-<timestamp>.json`
- `.kin/bench/bench-dashboard-<timestamp>.json`

The dashboard JSON includes:

- per-assistant/per-substrate totals
- per-task Git-vs-Kin comparison cards
- token, duration, and cost deltas
