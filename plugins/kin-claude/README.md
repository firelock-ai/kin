# Kin for Claude Code

Kin keeps a living map of the software itself so humans and agents can understand what
every change touches. Locate, search, context packs, data-flow tracing, and impact
analysis without raw file search.

## Install

```
/plugin marketplace add firelock-ai/kin
/plugin install kin@kin
```

## What it ships

The bundled MCP server runs `npx -y @kinlab/kin-mcp`, which downloads the matching Kin
release for your platform on first run, verifies its published SHA-256, and serves the
curated `agent-default` tool profile.

Three skills come with it. `kin-retrieval` teaches when to reach for `semantic_search`,
`semantic_locate`, `get_context_pack`, and `find_references` instead of grep and whole-file
reads. `blast-radius-review` builds a review workflow on `impact_analysis` and
`trace_data_flow`, so a change is judged by what it can reach rather than by the lines it
moved. `kin-setup` walks a repository from nothing to a first graph-backed answer.

## Before the tools can answer

Kin answers from a graph, so a repository has to be admitted first. Run `kin init .` in the
repository, or set `KIN_MCP_AUTO_INIT=1` to let the server do it. Then run `kin embed` to
build the vector index that `semantic_locate` ranks against. The structural tools work as
soon as admission finishes. The `kin-setup` skill covers this end to end, and
[llms-install.md](https://github.com/firelock-ai/kin/blob/main/llms-install.md) is the
unattended version.

Every response names the graph state that produced it, and an empty result says whether the
absence can be trusted. A graph gap is reported as a gap rather than filled in from raw file
search.

## Links

- Repository: https://github.com/firelock-ai/kin
- Tool reference: https://github.com/firelock-ai/kin/blob/main/docs/mcp-tools.md
- Home: https://kinlab.ai

Apache-2.0.
