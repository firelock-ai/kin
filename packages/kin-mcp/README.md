# @kinlab/kin-mcp

> **Superseded by [`@kinlab/kin`](https://www.npmjs.com/package/@kinlab/kin)**, the
> canonical Kin install surface. It includes the MCP server (`kin mcp start`) along
> with the full CLI. This package keeps working for existing configurations, but new
> setups should install `@kinlab/kin`.

`@kinlab/kin-mcp` is the npm-friendly launcher for Kin's MCP server (the installed
command is still `kin-mcp`).

It downloads the matching Kin release archive from GitHub, verifies the published
SHA-256 checksum, extracts both the `kin` CLI and the `kin-daemon` it depends on
into a local cache, and runs:

```sh
kin mcp start
```

On first run it:

- provisions `kin-daemon` next to `kin` and points the CLI at it with
  `KIN_DAEMON_BIN`, so the MCP path never depends on a locally-built `kin`, a
  stale daemon on `PATH`, or a pre-existing daemon;
- defaults `KIN_MCP_TOOL_PROFILE=agent-default`, so agents see the small curated
  tool surface instead of the full internal one;
- starts (or reuses) the repo daemon automatically, and only then serves tools;
- never sets a folder up on its own. When the folder is not a Kin repository,
  the first answer says so, and your agent can set it up by calling the
  `kin_init` tool (`init` on the `agent-routed` profile) when you ask it to. It
  is a write, so the read-only profiles do not offer it. From a
  terminal, `npx -y @kinlab/kin init .` does the same with no install. Set
  `KIN_MCP_AUTO_INIT=1` to have the wrapper run `kin init .` at launch instead;
- when the folder is inside another Kin repository with none of its own, opens
  every answer with which repository answered, in `_kin.advice`, and carries
  both folders in `_kin.repository`.

The release archive is about 45 MB, and downloading it does not hold up the
client's startup. While it downloads, the wrapper answers the client's
`initialize` itself, with the instructions `kin mcp start` gives the tool
profile it will serve, since a client reads those only once. It answers
`tools/list` with one tool, `kin_startup_status`, which reports how far the
download has come, and answers a Kin tool called that early with the same
status. When the download finishes it
starts `kin mcp start`, hands it the session, and sends
`notifications/tools/list_changed` so the client lists Kin's tools. A request made
while `kin mcp start` is coming up waits for it. A client that does not refresh
its tools on that notification sees them after one reconnect. Later launches of
the same version start from the cache and skip all of this.

With `KIN_MCP_AUTO_INIT=1` and no `.kin/`, the first launch runs `kin init .`
after the download, and `kin_startup_status` says so while it runs.

If a runnable Kin cannot be provisioned, the wrapper gives a precise guided fix
instead of a stack trace. An unsupported target is refused at once, on stderr. A
failed download, a failed `kin init`, or a `kin mcp start` that does not come up
is also reported in the answer to every tool call, so the agent can relay it,
until the client disconnects.

## Usage

The Kin plugins for Claude Code, Codex and Cursor, and the Kin extension for Gemini
CLI, run this wrapper as `npx -y @kinlab/kin-mcp`, and a configuration that already
names it keeps working.

For a configuration you write by hand, use the canonical package instead. This is
the entry `kin doctor` checks:

```json
{
  "mcpServers": {
    "kin": {
      "command": "npx",
      "args": ["-y", "@kinlab/kin", "mcp", "start"]
    }
  }
}
```

`@kinlab/kin` downloads Kin before `kin mcp start` reads the client's first
message, so when it has no Kin yet, or an older one than it pins, the client's
`initialize` waits for the download, and a client with a short startup timeout
can give up first. Running `npx -y @kinlab/kin --version` once in a terminal
fetches it ahead of time.

A Codex CLI, Grok CLI or Google Antigravity entry also names one repository with
`--repo`.
The [Codex plugin README](https://github.com/firelock-ai/kin/blob/main/plugins/kin-codex/README.md#install)
gives the exact TOML.

`kin doctor` recognizes only the exact entries Kin documents. It reports an entry
that names `@kinlab/kin-mcp`, or one that pins a version in the package spec, as
MISCONFIGURED, even though that server starts. To pin this wrapper anyway, put the
version in the spec, as in `npx -y @kinlab/kin-mcp@<version>`. Take the number
from the
[published version list](https://www.npmjs.com/package/@kinlab/kin-mcp?activeTab=versions)
rather than from this page, because a version written into a README is stale by
the next release and pins whoever copies it to the release that was current when
the line was typed.

## Requirements

- Node.js 20+
- macOS, Linux, or native Windows x64
- A Git repository, or an empty folder, for Kin to set up; the `kin_init` tool
  or `npx -y @kinlab/kin init .` does it

Native Windows x64 support is early. The end-to-end install proof runs agent
setup and graph-backed MCP tool calls there, but review workflows are not yet
tested on Windows, so WSL2 is the recommended path on Windows. The native
Windows archive carries semantic vector search but does not include transparent
filesystem projection. Use WSL2 when you need projection.

## Background daemons

The first tool call starts a daemon for the repository you are working in,
plus one supervisor for the machine. They keep running between calls so later
answers are fast. The daemon exits on its own once nothing has used it for 30
minutes, and the supervisor a minute after its last daemon.

To stop them now, such as right after you remove `kin` from your client's config:

```sh
npx -y @kinlab/kin-mcp --stop
```

That stops every daemon nothing is using. A daemon still in use, by another
editor window or a request in flight, is left running and named, and exits on
its own once it is free. `kin daemon stop --all` stops them regardless.

## What stays on disk

Stopping the daemons leaves these in place:

| Path | Size | What it holds |
| --- | --- | --- |
| `~/Library/Caches/kin-mcp` (macOS), `~/.cache/kin-mcp` (Linux), `%LOCALAPPDATA%\kin-mcp\Cache` (Windows) | about 150 MB per version | the `kin` and `kin-daemon` binaries this wrapper downloaded |
| `~/.kin` | grows with the repositories Kin has embedded | Kin's home: daemon records, logs and the embedding cache |
| `~/.cache/huggingface/hub/models--nomic-ai--nomic-embed-text-v1.5` | about 523 MB | the embedding model, fetched the first time Kin embeds a repository |
| `.kin/` in each repository you initialized | grows with history | that repository's graph |

`kin-mcp --stop` prints each path with its size on your machine and the command
that removes it. By hand, once the daemons have stopped (macOS shown):

```sh
rm -rf ~/Library/Caches/kin-mcp ~/.kin ~/.cache/huggingface/hub/models--nomic-ai--nomic-embed-text-v1.5
rm -rf .kin   # in each repository you initialized
```

Keep `~/.kin` if you also installed Kin with its installer or `@kinlab/kin`;
`kin setup uninstall --all` removes that install instead.

Set `KIN_MCP_CACHE_DIR` to move the binary cache.

## Environment

- `KIN_MCP_KIN_BINARY`: run a specific local `kin` binary instead of downloading
  one (you are then responsible for its `kin-daemon`)
- `KIN_BINARY_PATH`: alias for `KIN_MCP_KIN_BINARY`
- `KIN_MCP_CACHE_DIR`: override the cache directory
- `KIN_MCP_AUTO_INIT=1`: allow the wrapper to run `kin init .` when `.kin/` is missing
- `KIN_MCP_TOOL_PROFILE`: override the default `agent-default` tool profile
- `KIN_MCP_RELEASE_BASE_URL`: override the GitHub release download base URL

## Local Check

```sh
npx -y @kinlab/kin-mcp --print-bin         # provisioned kin path
npx -y @kinlab/kin-mcp --print-daemon-bin  # provisioned kin-daemon path
npx -y @kinlab/kin-mcp --stop              # stop idle daemons, list what stays on disk
```

Then initialize a repository and let the MCP client launch `kin-mcp`.

## First-run smoke proof

`test/smoke-first-run.mjs` exercises the whole first-run path against built Kin
binaries: it stages `kin` + `kin-daemon` into a throwaway cache (no pre-existing
daemon, no dev `PATH` state), runs the wrapper, and drives the MCP stdio protocol
through one safe semantic tool (`kin_graph_status`). Run it with:

```sh
cargo build --release -p kin-cli -p kin-daemon
KIN_BIN=target/release/kin \
KIN_DAEMON_BIN=target/release/kin-daemon \
npm run smoke
```
