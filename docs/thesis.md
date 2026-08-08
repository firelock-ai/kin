# Architectural Thesis: Graph-First Software Repositories

## The Problem: The File-First, Diff-First Trap

For decades, software development and collaboration have been built on a file-first,
line-based, diff-first substrate. Git, text editors, code review tools, and CI/CD
pipelines all view a codebase's evolution through a narrow lens:

1. A repository is a collection of hierarchical text files.
2. A change is a set of added or deleted lines of characters (diffs).

This substrate is simple and served human developers well, but it is poorly suited to
modern AI-native software development. Line diffs destroy semantic meaning:

- A signature change to a method looks like one line deleted and another added.
- Refactors and moves appear as unrelated deletions and additions, losing provenance.
- AI models must repeatedly search, parse, and rebuild ASTs from text to recover
  relationships, burning tokens and tool-call budget.

---

## The Solution: Semantic Graph as Canonical Truth

Kin replaces the file-first, diff-first substrate with a semantic, graph-first model:

1. **The graph is authority**: The canonical system of record is a graph of semantic
   entities (functions, structs, classes, schemas) and their relations (calls, imports,
   implementations).
2. **The filesystem is a projection**: Editor views and on-disk files are not the source
   of truth; they are derived views computed from the graph state.
3. **Change tracking via semantic fingerprints**: Changes are tracked as semantic changes
   to graph nodes rather than as line diffs, using AST hashes, signature hashes, behavior
   hashes, and stability scores.

---

## Adoption and Brownfield Compatibility

Adopting a new substrate is hard because it usually breaks existing tools. Kin makes
adoption survivable through explicit migration and compatibility projections:

### 1. Git migration and interoperability
Kin can import an exact Git snapshot or complete reachable history, and can export
graph-owned state back to Git when interoperability is required. Git is an input/output
boundary during migration, never a runtime answer authority or silent repair path.

### 2. The virtual filesystem (`kin-vfs`)
`kin-vfs` acts as a "Trojan horse" for graph-first adoption. By intercepting filesystem
calls (via `LD_PRELOAD` / `DYLD_INSERT_LIBRARIES`), it serves graph-backed files as normal
files to any compiler, linter, or legacy tool. To the host OS the codebase looks like
ordinary files on disk, while the underlying data is served from the semantic graph.

### 3. Agent integration (MCP)
Kin's built-in MCP server exposes semantic primitives directly to AI agents. Instead of
giving an assistant raw directory reads and grep loops, it calls semantic endpoints
(`get_context_pack`, `trace_data_flow`, `semantic_locate`) to interact directly with code
structure.

---

## Intended End State

The goal is to make software engineering graph-native. In this model:

- Codebases evolve by mutating graph nodes directly.
- Code review happens at the level of semantic changes, so type changes, contract
  breakages, and downstream impacts are surfaced and checked before a commit is finalized.
- AI agents and humans collaborate on the same semantic graph, enabling low-overhead,
  high-precision context sharing.

> File-first and Git-interoperable paths are transitional migration debt, not the
> steady-state model. The durable thesis is graph-owned semantic truth, with the
> filesystem as a derived projection over it.
