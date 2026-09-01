# AGENTS.md

This repository (`kin`) is part of the Kin ecosystem.

The canonical source of truth for agent and contributor guidance (repo roles,
boundaries, multi-session lane arbitration, commit hygiene, investor-hygiene
rules, the ordered vision, and the public narrative) lives in the umbrella
workspace `AGENTS.md`:

**`kin-ecosystem/AGENTS.md`** (also symlinked as `kin-ecosystem/CLAUDE.md`)

When working inside this repo as part of the umbrella workspace, that file is
loaded automatically by agent CLIs that read `CLAUDE.md`. If working in this repo in isolation,
read the umbrella `AGENTS.md` before making architectural or process decisions.
`CLAUDE.md` at this repo's root is a symlink to this file, because Claude Code reads
`CLAUDE.md` and not `AGENTS.md`, so a standalone checkout still loads this note.

## This repo's role

`kin` is the semantic system of record: CLI, daemon, MCP server, projections,
reconcile, review, provenance, execution, and the bundled seam packages and
crates under `crates/` and `packages/`.

Boundary rule: put work here when it changes local semantic repo truth,
projections/reconcile, CLI/daemon/MCP behavior, or provenance/review/execution
semantics. Graph internals go in `kin-db`; hosted collaboration goes in
`kinlab`.
