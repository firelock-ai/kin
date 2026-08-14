---
name: kin-setup
description: Connect the bundled Kin MCP server and get a repository answering graph-backed questions. Use on first run of the Kin plugin, when Kin's tools return no graph, when a repository has no .kin/ directory yet, or when semantic_locate reports missing embedding coverage.
---

# Getting Kin answering for this repository

The plugin bundles the Kin MCP server and starts it automatically when the plugin is
enabled. Nothing needs to be added to a settings file. What the server still needs is a
repository that has been admitted into Kin, because it answers from a graph rather than
from the files on disk.

Work through the steps in order and stop at the first one that already passes.

## 1. Check what is already there

Call `kin_graph_status`. A response with entity and relation counts means the server is
connected and this repository is admitted, and there is nothing to set up. Note the
embedding coverage it reports, because `semantic_locate` depends on it.

If the tools are not available at all, the server did not start. It runs
`npx -y @kinlab/kin-mcp`, so it needs Node 20 or newer on PATH, and on its first run it
needs network access to download the matching Kin release. That first run fetches the
release archive for this platform, verifies the SHA-256 published beside it, and extracts
the `kin` and `kin-daemon` binaries into a per-user cache. Later runs use the cache.

## 2. Admit the repository

If the server reports no repository, this directory has no `.kin/` yet. The wrapper says so
plainly: it refuses to start against a directory with no `.kin/` unless it is allowed to
create one.

Ask the user which they want, and say what each does:

- Run `kin init .` in the repository. In a Git repository this admits the complete reachable
  history, refs, raw objects, the exact workspace tree, and the derived semantic entity and
  relation layer. Uncommitted work is not lost: init admits the committed state and reports
  what it did not admit.
- Or set `KIN_MCP_AUTO_INIT=1` in the server's environment, which lets the wrapper run
  `kin init .` itself when `.kin/` is missing. Convenient, and worth naming out loud before
  turning on, because it means an agent session can admit a repository without being asked.

Admission is a one-time cost that scales with history depth rather than checkout size.
Seconds on a small repository, minutes on one with thousands of commits, and the store it
writes under `.kin/` can be considerably larger than the Git object store it came from.
`kin init` prints its phase ladder while it runs, so the terminal is never silent.

## 3. Build the vector index

Admission derives the entities. It does not embed them. Run `kin embed` in the repository
to build the vector index that `semantic_locate` ranks against. Until it finishes,
`semantic_locate` and `kin locate` degrade honestly rather than erroring: they rank over
whatever is embedded so far and report their coverage. The structural tools,
`semantic_search`, `find_references`, `graph_neighborhood`, `trace_data_flow`, and
`impact_analysis`, do not wait on embeddings and work as soon as admission finishes.

## 4. Verify

Call `kin_graph_status` again and read the coverage line, or run `kin graph status` in the
terminal. Then ask a real question through `semantic_locate` and check that the `_kin`
envelope reports `semantic_authoritative`. That is the end-to-end proof, and it is worth
doing once.

## Notes worth knowing

The `kin` CLI is a separate install from this plugin. The plugin's server manages its own
cached binaries, which are not added to your PATH. To get `kin` in the terminal too, use
`curl -fsSL https://get.kinlab.dev/install | sh` on macOS or Linux,
`npm install -g @kinlab/kin`, or `brew install firelock-ai/kin/kin`.

If the user has also run `kin setup --intent agent`, they have a second Kin MCP server
configured at user scope, pointing at their own installed binary. Both work. Two entries in
one client is redundant rather than broken, and the plugin is the one to keep if they want
the server to travel with the plugin.

The server serves the curated `agent-default` tool profile, which is the small belt these
skills use. `KIN_MCP_TOOL_PROFILE=full` exposes the whole surface, including
`semantic_review`, `semantic_diff`, and `shadow_gate_report`, at a real cost in context.
