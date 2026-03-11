# Real Agent Benchmarks: Git vs Kin

This is the first honest side-by-side benchmark pass using the local agent CLIs we actually have on this machine:

- Claude Code
- Codex
- Gemini CLI

Each agent ran the same task twice:

- once in a plain Git workspace
- once in a Kin-initialized workspace, after `kin init`, a baseline `kin commit`, and assistant guidance sync

Raw artifacts live under:

- [`docs/benchmarks/results/2026-03-10-real-agent-git-vs-kin/`](./results/2026-03-10-real-agent-git-vs-kin/REPORT.md)

## Benchmark Tasks

1. `snapdocs_sort_helper` on `snapdocs`
   - add a reusable newest-first sorting helper
   - wire it into both runtime files
   - update tests

2. `coachai_gameplan_trace` on `CoachAI`
   - produce a structured JSON trace of the game-plan generation flow
   - include UI, API, prompt, and persistence references

## Bottom Line

Kin is promising, but this run does **not** justify claiming that Kin universally beats Git yet.

What the data says:

- Kin already helps on a **focused code-edit task**.
- Kin is **not yet consistently better** on a broader repo-tracing task.
- Codex is the cleanest current signal.
- Claude shows upside on targeted edits, but the Kin flow for the larger CoachAI trace stalled badly enough that I recorded it as a failed run.
- Gemini can be faster and cheaper with Kin on narrow tasks, but reliability is not there yet.

## Highlights

### SnapDocs code-change task

This is the strongest signal in the current batch.

| Agent | Git | Kin | Result |
| --- | --- | --- | --- |
| Claude | 253406 ms, 1393534 tokens, pass | 209912 ms, 1403840 tokens, pass | Kin was 17.16% faster with roughly flat token use |
| Codex | 205362 ms, 669418 tokens, pass | 208407 ms, 569487 tokens, pass | Kin used 14.93% fewer tokens, with similar wall time |
| Gemini | 193209 ms, 779047 tokens, pass | 145679 ms, 402600 tokens, fail | Kin was faster and cheaper, but missed the test update |

### CoachAI repo-trace task

This is where Kin still needs work.

| Agent | Git | Kin | Result |
| --- | --- | --- | --- |
| Claude | 151272 ms, 743802 tokens, pass | 190732 ms, no usable token data, fail | Kin path stalled and had to be terminated |
| Codex | 184292 ms, 877923 tokens, pass | 231460 ms, 1078455 tokens, pass | Kin completed successfully, but was slower and more expensive |
| Gemini | 42194 ms, 120920 tokens, fail | 82663 ms, 432927 tokens, fail | Both failed; Kin was worse on time and tokens |

## What Kin Already Seems Good At

- Narrow, local code changes where `kin search` can point the agent at the right implementation sites quickly
- Giving Codex and Claude a cleaner starting point for targeted edits
- Preserving a local-first workflow without needing a monorepo-style scan just to find the right symbols

## What Still Needs Work

- Large, repo-level analysis tasks where the agent still has to synthesize broad flow across many files
- Agent prompt shaping for Kin mode
- Better context-pack delivery than simple `kin search` + `kin support`
- Reliability for Gemini on validation-critical tasks
- More benchmark tasks before making broad public claims

## Recommended Public Framing

Good framing:

- “First real Git-vs-Kin agent benchmarks”
- “Promising wins on targeted code edits”
- “Mixed results on broader repo tracing; more work underway”

Bad framing:

- “Kin already beats Git everywhere”
- “All agents are better on Kin today”

The honest story is stronger: Kin is already producing measurable wins on some real tasks, and the losses point directly at what the next iteration should improve.

## Next Benchmark Priorities

1. Add richer Kin-mode prompts and context packs for repo-trace tasks.
2. Run a second coding task on a medium-size repo where all three agents have a fair chance to pass validation.
3. Benchmark `kin exec` and proof-linked verification flows once they are being used in the task loop.
