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
vector index, wire the server into the client. Then verify with a real query, and stop the
daemon if you were only proving the install works. Six sections follow, in that order.

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

A shallow clone is refused, so check for one first. If you cloned the repository yourself
with `--depth 1`, or you are running in CI where `actions/checkout` defaults to a shallow
fetch, deepen it before going further:

```sh
git rev-parse --is-shallow-repository   # prints true on a shallow clone
git fetch --unshallow                   # only needed when that printed true
```

In CI, set `fetch-depth: 0` on `actions/checkout` instead. Skipping this is not silent:
`kin init` exits 1 and prints `shallow Git repositories cannot be imported losslessly`,
naming `git fetch --unshallow` as the fix. Recovering costs a full history fetch you could
have done up front.

Then run this inside the repository the user wants Kin to answer for:

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

Cline is supported, and it is one of the clients `kin setup` does not detect, so wire it by
hand with the entry below. Cline reads the same `mcpServers` shape. The CLI reads
`~/.cline/mcp.json`. In the VS Code extension, open the MCP Servers panel, then the
Configure tab, then Configure MCP Servers, which opens the settings JSON the extension
uses. Anything else that takes an `mcpServers` block works the same way.

Two more warnings for an unattended run. `kin setup --intent agent --no-interactive` writes
to real files in the user's home directory, so do not run it inside a sandbox that must
leave the user's configuration alone. And when `kin setup status` reports clients as
MISCONFIGURED, its printed fix is to run `kin setup` or `kin doctor --fix`, both of which
rewrite every detected client's config on the machine. That is the right call for a user
who asked for it and the wrong one for an agent tidying up on its own, so surface it rather
than run it.

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

Three checks, in order. First the graph, from inside the repository from step 2:

```sh
kin graph status
```

It prints an `Embeddings: <indexed>/<total> indexed (<pending> pending)` line. Step 3 is
finished when pending is 0.

Then the configuration, also from inside that repository, because this command reads the
working directory. Run it anywhere else and it reports a different repository, or none, and
a healthy-looking result says nothing about the install you just did:

```sh
kin setup status
```

Then the real one. From the client, with the repository from step 2 as the working
directory, make one `semantic_locate` call with a plain-language description of something
the repository does. A successful install returns ranked results and a `_kin` envelope
beside them. Read three fields on that envelope, all of which the response actually carries:

- `_kin.semantic_coverage.complete` is `true` and `_kin.semantic_coverage.pending` is 0.
  That is step 3 finished. When `complete` is `false`, embedding is still running, so rerun
  `kin embed` or wait, and do not conclude anything from the ranking yet.
- `_kin.graph_as_of.generation` is a number. That names the graph the answer came from.
- `_kin.runtime` is `repo-daemon`. That is graph-owned truth. `offline-in-process` means
  the daemon did not answer and you are reading a fallback surface.

Do not test for the string `semantic_authoritative`. It is a trust verdict Kin attaches
only to an empty result, in the `negative` object, alongside `coverage_partial` and
`coverage_unknown`. A successful call has results, so it carries no `negative` object and
none of those three strings appear. An install checked by matching that token reports
failure on a working server.

The `negative` object is worth reading when a result comes back empty. Its
`safe_to_conclude_absent` field says whether the absence can be trusted, and its reason
names which gate ruled.

### One thing to tell the user before they judge the answers

`kin setup status` prints a `Retrieval quality profile` line naming the profile serving
queries and which retrieval levers are on. A stock install serves `accuracy-v2`, the
measured-accuracy default: `semantic_locate` and `kin locate` both answer from the fused
multi-signal pipeline, entity fusion and the lexical parity floor are on, and the
cross-encoder reranker stays off. `KIN_PROFILE` selects a different profile: `accuracy-v1`
adds the budget-gated cross-encoder when its model is already cached, and `compat-v0` keeps
the pre-profile lever defaults as an A/B escape hatch. Two facts matter if you change it.
The profile is read by the process that serves queries, so it has to be set where the daemon
starts and not on the MCP client entry, and a daemon already running has to be restarted
under it.

## Step 6: stop the daemon when you are done

Kin answers from a resident daemon, which keeps running after your commands return. An
unattended install that is only proving the setup works should clean up after itself.

```sh
kin daemon status              # what is running, and under which repository
kin daemon stop                # stop this repository's daemon
kin daemon stop --all          # then the rest under this KIN_HOME, and the supervisor
```

The supervisor is machine-wide rather than per `KIN_HOME`, so `--all` skips and names
daemons belonging to other managed homes rather than stopping them, and leaves the
supervisor up while any of them remain. Leave a daemon running if the user is about to work
in the repository. It is the normal serving state, not a leak.

## When something is wrong

**`kin init` exits 1 saying the repository is shallow.** Run `git fetch --unshallow`, then
run `kin init .` again. Nothing from the failed attempt needs cleaning up first.

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
