# Kin Quickstart Guide

This is the recommended first-run path for Kin. One flow works on macOS, Linux, and
Windows (via WSL2):

1. **Install** the binaries with the one-line installer.
2. **`kin setup`** — answer a couple of questions; the guided wizard configures your
   shell, daemon, and AI clients.
3. **`kin init`** + **`kin embed`** — build the semantic graph and the vector index.
4. **Verify** with `kin setup status` and read the health checklist.

Manual / per-tool configuration is available in the
[Advanced configuration](#9-advanced-configuration) section, but you do not need it for a
normal first run.

---

## 1. Install

### macOS and Linux

```sh
curl -fsSL https://get.kinlab.dev/install | sh
```

The installer downloads the latest release from GitHub, **verifies its SHA-256 checksum**
(and refuses to install an unverified or tampered download), installs the `kin` and
`kin-daemon` binaries — plus the optional `kin-vfs` projection client and shim where the
archive bundles them — into `~/.kin/bin` (and `~/.kin/lib`), updates your shell profile
(`.zshrc` / `.bashrc`), and then runs the `kin setup` wizard. `kin-daemon` is mandatory;
the installer aborts cleanly rather than leaving a daemon-less install. Re-running the
installer upgrades an existing install in place and reports the version change.

### Windows

On native Windows, use PowerShell:

```powershell
irm https://get.kinlab.dev/install.ps1 | iex
```

The native Windows build is a **limited, vector-free convenience binary with no filesystem
projection** — the installer prints this up front. For the complete, vector-enabled Kin
with working projection, install under **WSL2** and follow the Linux path inside it. See
[windows-wsl2.md](./windows-wsl2.md).

### Installer options

Configure the installer with environment variables (supported by both `install.sh` and
`install.ps1`):

- `KIN_VERSION`: pin a specific version (e.g. `0.1.0`); otherwise the latest release is
  resolved automatically.
- `KIN_DIR`: custom install directory (defaults to `~/.kin`).
- `KIN_NO_SETUP=1`: skip the `kin setup` wizard after the binaries are installed (run
  `kin setup` yourself when ready).
- `KIN_BASE_URL`: install from a mirror or local path instead of GitHub releases
  (offline / airgapped installs and CI smoke tests).

---

## 2. Guided setup (`kin setup`)

`kin setup` is the guided wizard the installer launches for you (run it again any time).
It opens with **"What do you want Kin for?"** and asks for your **intent** rather than a
bag of independent toggles:

| Intent | What it configures |
| --- | --- |
| **AI agents** (default) | Kin's MCP server for every detected AI client, plus shell integration and daemon auto-start. The smallest path to value. |
| **Local-only** | Shell integration + daemon auto-start; no AI client config. |
| **Editor** | Local-only, plus how to install the `kin-editor` VS Code extension. |
| **Hosted / KinLab** | Local setup, plus a note that hosted connect is coming soon (see below). |
| **Advanced / manual** | Choose shell, per-client MCP, and daemon options yourself. |

You can pre-select non-interactively (handy in scripts / CI):

```sh
kin setup --intent agent --no-interactive
```

Other flags (`global`, honored across every intent):

- `--intent <local|agent|editor|hosted|advanced>`: pick the first-run intent up front.
- `--shell <zsh|bash|powershell>`: target a specific shell for the profile update.
- `--auto-daemon`: force daemon auto-start on (enabled by default for every intent).
- `--no-interactive`: run with defaults / provided flags (no prompts). The
  non-interactive default intent is **agent**.

When the wizard finishes, it prints the **health checklist** (the same engine as
`kin setup status`, see step 8) and your next steps.

> **Hosted / KinLab is not yet a first-run flow.** There is no public `kin login` /
> connect command shipped today. The wizard is honest about this; your local setup is
> fully functional in the meantime.

---

## 3. Initialize a repository

Build a semantic graph over an existing Git repository or folder:

```sh
# Initialize in the current directory
kin init

# Or initialize a specific path
kin init path/to/project
```

*Flags:*
- `--git-history <off|recent|full>`: how much Git history to import into the graph on init
  (default: `recent`).
- `--force`: initialize even if a `.git/` directory is already present.
- `--no-lsp`: skip LSP enrichment (faster, tree-sitter-only init).

---

## 4. Add embeddings for semantic search

`kin init` builds the graph instantly **without** embeddings. To enable semantic
(vector) search, `kin locate`, and the MCP `semantic_locate` tool, build the vector
index:

```sh
kin embed
```

Embeddings are generated locally with `nomic-embed-text-v1.5` (768 dimensions; override
via `KIN_EMBED_MODEL_ID`). You can check coverage at any time:

```sh
kin status --json   # see the "enrichment" block: embeddingsIndexed / embeddingsPending / embeddingsTotal
```

> Until embedding is complete, `kin search --semantic` and `kin locate` degrade
> gracefully (vector hits over whatever is already embedded, plus a text fallback) and
> report their coverage honestly rather than erroring. In the health checklist, semantic
> query readiness shows **yellow / STALE** until the vector index exists.

---

## 5. Basic development workflow

### Check working copy status

```sh
kin status
```

### Commit changes

Save a new semantic change snapshot:

```sh
kin commit -m "refactor: optimize user query path"
```

### View history

```sh
kin log -n 10
```

### Semantic diff

Inspect changes at the level of entities rather than raw lines:

```sh
kin diff
```

---

## 6. Semantic exploration and retrieval

### Search

```sh
# Name / kind / language matching over declarations
kin search "save_user"

# Semantic (vector) search using a query description
kin search "persist user session to database" --semantic --show-body
```

### Trace

Resolve a focal entity, show its body, and summarize nearby context in one call:

```sh
kin trace "save_user" --max-lines 50
```

### Build context packs

Package a target entity along with its callers and dependencies for an AI assistant:

```sh
kin context "UserService" --budget 16k
```

### Locate

Rank the files most relevant to a problem description:

```sh
kin locate "users can't reset their password" --explain
```

---

## 7. Using Kin from an AI agent (MCP)

If you chose the **AI agents** intent in step 2, `kin setup` already wrote Kin's MCP
server entry into every detected AI client (Claude Code, Cursor, Codex CLI, Gemini CLI,
Windsurf) and added a Kin-first discovery reminder to your agent instruction files. There
is **nothing else to configure** — open your agent in a Kin repository and ask it to use
the semantic tools:

```
Use Kin to explore this codebase: run semantic_locate to find the
main entry point, then get_context_pack on that file.
```

The wizard writes this entry to each client:

```json
{
  "mcpServers": {
    "kin": {
      "command": "kin",
      "args": ["mcp", "start", "--global"],
      "env": { "KIN_MCP_TOOL_PROFILE": "agent-default" }
    }
  }
}
```

`KIN_MCP_TOOL_PROFILE=agent-default` exposes the small curated tool surface instead of the
full internal one. (The wizard writes an absolute path to the installed `kin` binary as
the `command`, so the entry works in agent processes that do not inherit your `PATH`.)

> Vector-backed MCP retrieval (`semantic_locate`) and the stateful session / transaction /
> work / review tools operate against the repo's running Kin daemon. Daemon auto-start is
> on by default, so these tools have a live graph to query — `semantic_locate` returns an
> explicit error in offline / no-daemon mode.

For the full tool surface, see the [MCP Tools Reference](mcp-tools.md). To wire up a
client by hand (or use the npm wrapper), see
[Advanced configuration](#9-advanced-configuration).

---

## 8. Verify your setup (`kin setup status`)

Run the health checklist at any time. It probes real filesystem, daemon, and agent state —
nothing is assumed healthy:

```sh
kin setup status          # human-readable table
kin setup status --json   # machine-readable report
```

Each line shows a status mark:

- `✓` **ok** — healthy.
- `✗` **MISSING** / **MISCONFIGURED** — failing; these are the only states that make the
  overall report unhealthy.
- `!` **STALE** — present but not fully ready (e.g. embeddings pending).
- `→` **n/a** — unsupported / not applicable on this platform or context.

The checks (IDs as emitted in `--json`):

| Check (id) | What "ok" means |
| --- | --- |
| `kin_binary` | The `kin` binary resolved (reports version + path). |
| `kin_daemon_binary` | `kin-daemon` found beside `kin` or on `PATH`. |
| `vfs_projection` | The VFS shim is installed and non-zero in `~/.kin/lib` (macOS/Linux). On Windows this is **n/a** — projection uses ProjFS (planned), not the shell-injected shim. |
| `repo_init` | The current directory is inside a Kin repository. |
| `shell_path` | The `kin-vfs` shell hook is installed and sourced from your rc. |
| `mcp_client_*` (e.g. `mcp_client_claude`) | A detected AI client has the `kin` MCP server with the `agent-default` profile. With no client configs present, a single `mcp_clients` check reports ok ("nothing to configure"). |
| `editor` | The `kin-editor` VS Code extension is detected in `~/.vscode/extensions`. **n/a** if not found / non-VS Code. |
| `kinlab_connect` | A stored KinLab credential is present. **n/a** today — hosted connect is not yet a first-run flow. |
| `semantic_query_readiness` | The daemon is reachable and the vector index exists. **yellow/STALE** until you run `kin embed`; **MISSING** if the daemon isn't running. |

### When a check is yellow or red

Each failing/incomplete check prints its own `fix:` line. The most common ones:

- **`shell_path` / `mcp_client_*` red** → run `kin doctor --fix` (or `kin setup`) to
  reinstall the shell hook and re-merge the MCP entries.
- **`semantic_query_readiness` STALE** → run `kin embed` to build the vector index.
- **`semantic_query_readiness` MISSING** → run any `kin` command in the repo to auto-start
  the daemon.
- **`repo_init` MISSING** → run `kin init .` to initialize a repository here.
- **`vfs_projection` MISSING** → run `kin setup` to (re)install the shim into `~/.kin/lib`.
- **`kin_daemon_binary` MISSING** → reinstall Kin so `kin-daemon` lands beside `kin`.

`kin doctor` (or `kin setup doctor`) runs the same checklist; add `--fix` to apply the
safe repairs (shell hook, MCP configs, config dirs, stale-daemon cleanup) and then re-run
the checks to show the post-fix state:

```sh
kin doctor          # report only
kin doctor --fix    # apply safe repairs, then re-check
```

---

## 9. Advanced configuration

You do not need anything here for a normal first run — the guided wizard covers it. This
section is for manual wiring, troubleshooting, and non-standard environments.

### Manual MCP client configuration

If you skipped the wizard's agent step, or your client wasn't auto-detected, add Kin's MCP
server to your client's config by hand. Match the wizard exactly — including the
`agent-default` profile:

```json
{
  "mcpServers": {
    "kin": {
      "command": "kin",
      "args": ["mcp", "start", "--global"],
      "env": { "KIN_MCP_TOOL_PROFILE": "agent-default" }
    }
  }
}
```

Config file locations the wizard targets (and `kin setup status` inspects):

| Client | Config path |
| --- | --- |
| Claude Code | `~/.claude.json` (falls back to `~/.claude/config.json`) |
| Cursor | `~/.cursor/mcp.json` |
| Codex CLI | `~/.codex/mcp.json` |
| Gemini CLI | `~/.gemini/settings.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |

`kin mcp start` launches the MCP **stdio** server. You normally do not run this by hand —
your AI client launches it as a subprocess via the config above.

### npm wrapper (`@kinlab/kin-mcp`)

If you'd rather not install the binaries first, the published `@kinlab/kin-mcp` package
downloads, checksum-verifies, and runs Kin's MCP server for you. Point your client at it:

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

On first run it provisions `kin-daemon` next to `kin`, defaults
`KIN_MCP_TOOL_PROFILE=agent-default`, starts (or reuses) the repo daemon, and **requires an
explicit `kin init`** (no silent init) unless you set `KIN_MCP_AUTO_INIT=1`. Requires
Node.js 20+ on macOS or Linux (Windows users go through WSL2). See the
[`@kinlab/kin-mcp` README](../packages/kin-mcp/README.md) for cache locations and the full
environment-variable surface.

### Runtime / daemon configuration

The Kin daemon is the canonical authority for graph truth and auto-starts as needed for
normal use. The escape hatches:

- `KIN_NO_DAEMON=1`: disable daemon auto-start (use only an already-running daemon or
  `KIN_DAEMON_URL`).
- `KIN_DAEMON_URL`: point the CLI at an explicit daemon endpoint.
- `KIN_ALLOW_DAEMON_BOOTSTRAP_ADMIN=1`: offline/admin escape hatch that lets the read-only
  in-process commands fall back to reading the local `.kin` snapshot directly. Never used
  for writes — all graph mutations still route through the daemon.

---

## 10. Removing Kin

Kin is ejectable — there is no data lock-in. There are two modes, and they
do different things:

```sh
kin eject                 # safe default
```

Stops the Kin daemon and removes the `.kin/` directory (the graph and all Kin
metadata). **Your working files are left exactly as they are** — whatever is on
disk right now stays on disk. This is the everyday "walk away with my files"
path.

```sh
kin eject --revert-files  # destructive: restore the pre-init snapshot
```

Additionally overwrites every working file with the copy Kin snapshotted at
`kin init`, discarding changes made since. It asks you to type `revert` to
confirm (use `--yes` to skip the prompt in scripts), and it writes a timestamped
backup of your current files to `.kin-backup-eject-<timestamp>/` first, so
nothing is lost. If the snapshot is missing or incomplete, eject refuses and
touches nothing rather than half-restoring.

**What eject never touches: `.git`.** Kin snapshots your *working tree* at init
(excluding `.git`, `.kin*`, and ignored paths) and restores those files only. It
never reads, rewrites, or restores Git history — your commit history is owned by
Git the entire time. After eject, the directory is a plain Git repository with
its history intact; `git log`, `git status`, and `git fsck` all work unchanged.
