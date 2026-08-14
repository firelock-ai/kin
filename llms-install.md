# Installing Kin's MCP server, unattended

This file is written for an AI agent installing Kin on a user's machine with no human
watching. Follow it in order. Every command below is real and every path is exact.

## The one thing to know first

Kin answers from a semantic graph, not from the files on disk. A repository has to be
admitted into that graph before any tool returns an answer, and the natural-language search
tool additionally needs a vector index built over it. An install that stops at "the server
is connected" will look broken, because the tools will correctly report an empty or missing
graph.

So the install is four steps, not one: install the CLI, admit the repository, build the
vector index, wire the server into the client. Verify at the end with a real query.

## Step 1: install the Kin CLI

macOS and Linux:

```sh
curl -fsSL https://get.kinlab.dev/install | sh
```

The installer downloads the latest release, verifies its published SHA-256, installs `kin`
and `kin-daemon` under `~/.kin/bin`, updates the shell profile, and then launches the
`kin setup` wizard. Running unattended, set `KIN_NO_SETUP=1` to skip the wizard and drive
setup yourself in step 4.

Windows, in PowerShell:

```powershell
irm https://get.kinlab.dev/install.ps1 | iex
```

Native Windows x86_64 support is early: repository admission and graph, lexical, and
daemon-backed queries work natively, filesystem projection does not ship there, and the
end-to-end install proof does not yet cover MCP on native Windows. Prefer WSL2 and follow
the Linux path inside it.

From npm:

```sh
npm install -g @kinlab/kin
```

From Homebrew:

```sh
brew install firelock-ai/kin/kin
```

Confirm the install before continuing:

```sh
kin --version
```

If `kin` is not on PATH, start a new login shell, or call the binary at `~/.kin/bin/kin`.

## Step 2: admit the repository

Run this inside the repository the user wants Kin to answer for:

```sh
cd /path/to/repository
kin init .
```

In a Git repository this admits the complete reachable history, refs, raw objects, the
exact workspace tree, and the derived semantic entity and relation layer. Uncommitted work
is safe: `kin init` admits the committed state and reports what it did not admit. In an
empty directory with no `.git/`, it creates a new native repository instead, and it refuses
a non-empty non-Git directory rather than treating loose files as graph truth.

Two things to tell the user before running it on a large repository. Time scales with
history depth rather than checkout size, so it takes seconds on a small repository and
minutes on one with thousands of commits. Disk scales the same way, and the store under
`.kin/` can be several times the size of the Git object store it came from. `kin init`
prints a phase ladder to stderr while it runs, so a long run is never silent.

## Step 3: build the vector index

Admission derives the entities. It does not embed them.

```sh
kin embed
```

Embeddings are generated locally. Until this finishes, `semantic_locate` and `kin locate`
degrade honestly rather than failing: they rank over whatever is embedded so far and report
their coverage. The structural tools, `semantic_search`, `find_references`,
`graph_neighborhood`, `trace_data_flow`, and `impact_analysis`, do not depend on the vector
index and work as soon as step 2 finishes.

Check coverage at any time:

```sh
kin graph status
```

## Step 4: wire the server into the client

The guided path configures every detected client in one command:

```sh
kin setup --intent agent --no-interactive
```

It writes Kin's MCP server entry into the clients it finds:

| Client | File |
| --- | --- |
| Claude Code | `~/.claude.json` |
| Cursor | `~/.cursor/mcp.json` |
| Codex CLI | `~/.codex/config.toml` |
| Gemini CLI | `~/.gemini/settings.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |
| Google Antigravity | `~/.gemini/config/mcp_config.json` |

The merge is defensive. It refuses to write to a file that is not valid JSON, only touches
the `command`, `args`, and `env` keys under its own entry, and records every write to a
ledger so `kin setup uninstall` can reverse it.

To configure a client by hand, use this entry, substituting the absolute path that
`which kin` reports:

```json
{
  "mcpServers": {
    "kin": {
      "command": "/absolute/path/to/kin",
      "args": ["mcp", "start"],
      "env": { "KIN_MCP_TOOL_PROFILE": "agent-default" }
    }
  }
}
```

An absolute path matters here: agent clients do not reliably inherit your shell PATH, so a
bare `kin` command is not a supported shortcut.

The npm wrapper is the alternative when you would rather not manage a path. It needs Node
20 or newer, and on its first run it downloads the matching Kin release, verifies its
SHA-256, and caches the binaries per user:

```json
{
  "mcpServers": {
    "kin": {
      "command": "npx",
      "args": ["-y", "@kinlab/kin-mcp"]
    }
  }
}
```

Codex CLI uses TOML rather than JSON:

```toml
[mcp_servers.kin]
command = "npx"
args = ["-y", "@kinlab/kin-mcp"]
```

The wrapper refuses to start against a directory with no `.kin/`. If you want it to admit a
repository on its own instead of running step 2 first, add
`"env": { "KIN_MCP_AUTO_INIT": "1" }` to the entry. Say so out loud before enabling it,
because it means an agent session can admit a repository without being asked.

## Step 5: verify

Two checks. First, the configuration:

```sh
kin setup status
```

Then the real one. From the client, with the repository from step 2 as the working
directory, make one `semantic_locate` call with a plain-language description of something
the repository does. A successful install returns ranked entities and a `_kin` envelope
reporting `semantic_authoritative`. That envelope is the proof, because it names the graph
generation and the embedding coverage that produced the answer.

If the envelope reports `coverage_partial` or `coverage_unknown`, step 3 has not finished.
Rerun `kin graph status` and wait for coverage to complete before concluding anything about
the result.

## When something is wrong

**The tools are not listed at all.** The server did not start. Check Node 20 or newer for
the npx path, and network access for its first-run download. Otherwise, check that the
absolute path in the client config still exists.

**Every tool reports no repository.** The client's working directory has no `.kin/`. Run
step 2 there, or set `KIN_MCP_AUTO_INIT=1`.

**`semantic_locate` returns nothing while `semantic_search` works.** The vector index is
missing or incomplete. Run `kin embed`.

**A result is empty and you want to conclude the code does not exist.** Read the `negative`
object on the response. Its `safe_to_conclude_absent` field says whether that absence can be
trusted. When it is false, the honest answer is "unknown", not "absent".
