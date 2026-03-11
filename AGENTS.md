# AGENTS.md

## Source of Truth

Public source of truth in this repository:

- the code itself
- **[README.md](./README.md)**
- **[docs/architecture/kin-system-architecture.md](./docs/architecture/kin-system-architecture.md)**
- **[docs/architecture/kin-open-core-coverage-roadmap.md](./docs/architecture/kin-open-core-coverage-roadmap.md)** for open-core language and artifact coverage direction

Private planning and commercialization materials live outside this repository and are intentionally not part of the public repository contract.

## Mission

Kin is a sovereign, local-first semantic version control system. Semantic entities, relations, contracts, and `SemanticChange` history are primary. Files are projections of semantic state. `kin init` must work without Git.

## Repo Status

- This repository contains the open local-first Kin core.
- Keep documentation accurate about current behavior and durable architecture.
- Do not add references to private planning docs in public-facing files.

## Using Kin Tools (IMPORTANT — read this first)

This repository uses Kin semantic VCS. Kin indexes every function, class, type, and trait into a graph with cross-file relations. **Use Kin tools instead of raw file operations whenever possible.**

### Finding Code — use `kin search` instead of grep

```bash
# Instead of: grep -r "function_name" or rg "function_name"
kin search function_name

# Filter by kind or language
kin search MyStruct --kind struct
kin search handler --language typescript
```

`kin search` returns exact entity definitions with file:line — not noisy text matches. On this codebase it produces 4-22x less noise than grep.

### Understanding Code — use `kin context` instead of reading files

```bash
# Instead of: reading 5 files to find callers
kin context <entity_name>

# Instead of: guessing which files matter
kin support
```

`kin context` returns a token-budgeted pack (focal entity + callers + dependencies) using ~84% fewer tokens than reading all matching files.

### Reviewing Changes — use `kin review` instead of git diff

```bash
# Instead of: git diff
kin review
```

Shows entity-level diff + downstream impact (callers, dependents, contracts, tests) + risk assessment.

### Committing — use `kin commit` for semantic history

```bash
# Instead of: git commit
kin commit -m "message"
```

### MCP Tools

If connected via MCP (`kin mcp`), use these tools:

| MCP Tool | CLI Equivalent | Use Instead Of |
|----------|---------------|----------------|
| `semantic_search` | `kin search` | grep, rg, find |
| `get_context_pack` | `kin context` | Reading entire files |
| `impact_analysis` | `kin review` | Manually tracing callers |
| `semantic_review` | `kin review` | git diff |
| `graph_neighborhood` | — | Exploring dependencies |

**Key principle**: Search semantically first, read files second. Only fall back to raw file reads when Kin doesn't have what you need.

## Before Making Changes

1. Read the relevant public architecture docs and inspect the owning crate.
2. Treat external private planning material as supplemental, never as the public contract.
3. Stay within your ownership boundary unless the task explicitly spans crates or top-level docs.
4. Add or update tests when you change core behavior or invariants.
5. Keep `README.md` and this file aligned with the public repository state.

## Hard Constraints

- Rust for the core implementation. No Python or Node.js in the core.
- KuzuDB is the embedded graph database.
- The blob store holds raw content; graph nodes do not store code bodies.
- Tree-sitter is the parsing foundation.
- Git support lives in `kin-git` and is optional.
- Keep the system local-first and fast.
- Do not introduce distributed infrastructure in V1.
- Do not overbuild enterprise or hosted features into the open core.

## Critical Invariants

- `kin init` creates a functional `.kin/` repository without requiring `.git`.
- `SemanticChange` is Kin's native commit and history unit.
- Branches are refs to `SemanticChange` nodes, not properties of a change.
- Indexing writes to the `WorkingCopy` overlay. Only `kin commit`, `kin merge`, and `kin git import` create committed history.
- Broken ASTs preserve Last Known Good fingerprints and do not sever lineage.
- Projection must preserve formatting and trivia outside mutated entity ranges.
- Projected files must remain valid, runnable code.
- Deleting `.kin/` leaves the working directory intact.
- No raw Cypher outside `crates/kin-graph`; other crates go through the `GraphStore` trait.

## Phase Ownership

- **Phase 1**: `kin-model` (`agent-model`), `kin-graph` (`agent-graph`), `kin-blobs` (`agent-blobs`), `kin-core` (`agent-core`)
- **Phase 2**: `kin-parser` (`agent-parser`), `kin-index` (`agent-index`)
- **Phase 3**: `kin-projection` (`agent-projection`), `kin-reconcile` (`agent-reconcile`), `kin-git` (`agent-git`)
- **Phase 4**: `kin-context` (`agent-context`), `kin-contracts` (`agent-contracts`), `kin-review` (`agent-review`)
- **Phase 5**: `kin-cli` (`agent-cli`), `kin-daemon` (`agent-daemon`), `kin-mcp` (`agent-mcp`)
- **Phase 6**: `kin-bench` (`agent-bench`), `kin-migrate` (`agent-migrate`), `kin-runtime` (`agent-runtime`), `apps/kin-local-ui` (`agent-ui`)

Do not modify crates outside your assignment unless the task explicitly requires cross-cutting changes. Top-level docs such as `README.md` and `AGENTS.md` are cross-cutting and may be updated when requested.

## Workspace Guidance

- `crates/` contains the Rust workspace for the semantic core.
- `apps/kin-local-ui/` is the local web UI.
- `docs/research/` contains background material and archived research, not source-of-truth architecture.
- `docs/architecture/` is for ADRs and durable architecture notes when needed.
- `.kin/docs/` is reserved for generated living docs at runtime and is not the human source of truth for the repository.

## Working Style

- Be pragmatic. Prefer boring, durable decisions.
- Make progress through useful vertical slices.
- Surface tradeoffs explicitly.
- Keep docs concise and current.
- Preserve naming: product `Kin`, CLI `kin`.
- Use relationship language where appropriate: code kinship, semantic neighborhoods, dependency families.

## End-of-Task Report

When finishing a substantial task, report:

1. What was built
2. What remains incomplete
3. The next 3 recommended milestones
4. Any architectural decisions made and why
