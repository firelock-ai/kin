# Kin-First Codex Fork Plan

This document lays out the case for pivoting from "make external assistants behave better in Kin" toward a Kin-first agent runtime derived from Codex.

## Recommendation

Use **`kin-codex`** as the repo name.

Why:

- clear and descriptive
- keeps the relationship obvious
- no branding ambiguity
- good as both an internal project name and an external engineering repo

Recommended naming split:

- Product concept: **Kin Codex**
- Repo: **`kin-codex`**
- Short internal label: **KCX**

If the fork matures into a broader runtime beyond Codex lineage, the product can later keep "Kin Codex" as the bridge name while the underlying runtime evolves.

## Why A Fork Makes Sense

External assistants keep revealing the same truth:

- they are optimized for file-first workflows
- Kin-native mode only shines when the assistant starts thinking in semantic terms
- guidance helps, but guidance is not ownership

So the long-term move is not:

- "teach generic assistants to use Kin forever"

It is:

- "build a Kin-native runtime whose defaults already assume the graph is truth"

Codex is the best starting point because:

- it is already CLI-oriented
- it already fits tool-driven workflows well
- it has been the best diagnostic surface for Kin benchmarking
- it is the most natural substrate for a Kin-first planner

## Product Thesis

Kin is not just replacing files with a graph.

Kin is replacing the assumption that every process deserves the same projection of the codebase.

`kin-codex` is the agent runtime that is built around that thesis from day one.

## Core Design Principles

### 1. Kin-first planning

If a task names exact symbols:

- start with `kin trace`

If a task is architectural:

- start with `kin overview`

If a task is about dependencies or impact:

- start with `kin context`

If a task is about review:

- start with `kin review`

Shell/file tools are fallback tools, not the default planning surface.

### 2. Projection-aware execution

The runtime must understand three surfaces:

- truth: graph + blobs
- control root: what the agent sees
- execution workspace: what dumb tools see

It should know when to:

- stay semantic
- materialize files
- reconcile changes
- clean up

### 3. Kin-native subagents

Subagents should not be generic "Explore" workers that rediscover file habits.

They should be:

- disabled by default unless needed
- spawned with explicit Kin-native task types
- governed by the same semantic-first tool policy as the parent

### 4. First-class telemetry

The runtime must expose:

- step traces
- tool traces
- subagent trees
- token/cost attribution
- shimmed shell logs

This is not an afterthought. It is how the runtime gets better.

### 5. Files as projections, not assumptions

The runtime should treat files as:

- an execution compatibility artifact
- a projection for tools that still require them
- never the source of truth

## What To Keep From Codex

Keep:

- CLI interaction model
- tool-driven execution style
- headless benchmarkability
- JSON/event streaming where possible
- strong shell integration

Do not keep as-is:

- generic file-first planner behavior
- uncontrolled fallback to grep/read habits
- generic subagent exploration policy
- treating Kin as just another optional tool

## What To Replace

### Planner

Replace the default planner with a Kin-first planner that:

- prefers semantic commands first
- uses exact-name flows before broad search
- avoids output-heavy search staircases unless necessary

### Tool policy

Replace "everything available all the time" with:

- semantic tools first
- shell tools second
- strict/diagnostic policy modes

### Subagent model

Replace generic Explore-style delegation with explicit Kin-native roles such as:

- TraceSymbol
- ReviewDiff
- FollowDependencyChain
- ValidateWorkItem
- GatherProof

### Runtime contract

Replace naive cwd/file assumptions with explicit support for:

- control-root launches
- execution workspace materialization
- reconcile on write
- benchmark and telemetry hooks

## Proposed Fork Phases

### Phase 1 — Specification

Define:

- Kin-first planner rules
- allowed/disallowed fallback behavior
- subagent policy
- session/workspace model
- telemetry contract

This should be informed directly by current Claude/Codex benchmark evidence.

### Phase 2 — Thin fork

Create `kin-codex` as a thin behavioral fork:

- preserve CLI shell
- swap in Kin-first prompt/planner defaults
- add Kin-native tool policies
- add first-class telemetry

### Phase 3 — Projection-aware runtime

Teach the fork to understand:

- control root
- native session workspace
- `kin exec`
- `kin shell`
- reconcile lifecycle

### Phase 4 — Kin-native subagents

Move from generic subagents to Kin-aware decomposition.

### Phase 5 — First-class product surface

At this stage, `kin-codex` is no longer just a fork experiment.
It becomes the strongest expression of the Kin-native interaction model.

## Immediate Practical Goal

Do not fork blindly.

Use the current benchmark program to learn:

- where external assistants waste time
- what command patterns actually win
- which fallback behaviors must be removed
- which one-shot commands help the most

Then encode those lessons into the fork.

## What Success Looks Like

`kin-codex` is successful when:

- it reliably beats generic external assistants on Kin-native tasks
- it uses far fewer exploratory steps to solve the same symbolic problem
- subagents stay semantic-first instead of falling back to filesystem exploration
- it turns native mode from "promising but delicate" into the default best experience

## Strategic Position

The path becomes:

1. Prove Kin inside today’s assistant ecosystem
2. Learn the exact Kin-native interaction contract from telemetry
3. Build `kin-codex` to own that contract directly

That is how Kin moves from:

- semantic VCS with integrations

to:

- the runtime that decides what code reality each process deserves
