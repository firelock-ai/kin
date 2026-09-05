# Kin Quickstart Guide

This is the recommended first-run path for Kin. One flow works on macOS, Linux, and
Windows. On native Windows the support boundary is narrower, and WSL2 remains the
recommended path for the full Kin experience. See step 1.

1. **Install** the binaries with the one-line installer.
2. **`kin setup`** asks a couple of questions, and the guided wizard configures your
   shell, PATH, daemon, and AI clients.
3. **`kin init`** admits repository authority atomically and derives the semantic
   entity layer for supported sources; embeddings are a separate graph-native stage.
4. **Verify** with `kin setup status` and read the health checklist.

Manual / per-tool configuration is available in the
[Advanced configuration](#9-advanced-configuration) section, but you do not need it for a
normal first run.

Every command below, and every command this guide does not reach, is documented
in the [CLI reference](cli-reference.md).

---

## 1. Install

### macOS and Linux

```sh
curl -fsSL https://get.kinlab.dev/install | sh
```

The installer downloads the latest release from GitHub, **verifies its SHA-256 checksum**
(and refuses to install an unverified or tampered download), installs the `kin` and
`kin-daemon` binaries into `~/.kin/bin` (and `~/.kin/lib`), updates your shell profile
(`.zshrc` / `.bashrc`), and then runs the `kin setup` wizard. Where the archive bundles
them, the optional `kin-vfs` projection client and shim are installed alongside.
Setup then picks a projection mode for this host, prints what each of the shim,
NFS and FUSE would need, and records the one it chose. `kin vfs status` shows it
again later, and `kin vfs on --mode <mode>` changes it.
`kin-daemon` is mandatory; the installer aborts cleanly rather than leaving a daemon-less
install. Re-running the installer upgrades an existing install in place and reports the
version change.

### npm / npx

If your workflow starts from npm, use the canonical launcher and then run the same setup:

```sh
npm install -g @kinlab/kin
kin setup --intent agent
```

For zero-install provisioning:

```sh
npx -y @kinlab/kin setup --intent agent --no-interactive
```

The launcher provisions the same managed native `kin` + `kin-daemon` release under
`~/.kin/bin`; `kin setup` writes MCP configs with an absolute path to that binary and
adds the managed bin directory to your shell profile for new sessions.

A global install needs a writable npm prefix. Where the prefix is root-owned and you are
not root, npm refuses with `EACCES: permission denied, mkdir
'/usr/local/lib/node_modules/@kinlab'` and installs nothing, which is the usual case inside
a container whose default user is not root. The zero-install line above needs no writable
prefix. Otherwise move the prefix somewhere you own and put it on your `PATH`:

```sh
npm config set prefix ~/.npm-global
export PATH="$HOME/.npm-global/bin:$PATH"   # add this to your shell profile too
npm install -g @kinlab/kin
```

A user prefix is read by your interactive shell and by nothing else. Scripts, CI steps,
`docker exec`, and agent clients do not inherit it, so register `kin` with those by its
absolute path (`$(npm prefix -g)/bin/kin`, or `~/.kin/bin/kin` once `kin setup` has run)
rather than by name. Installing as root does not fix that on an image where every user
shares one `HOME`: root's npm reads the same `.npmrc`, reinstalls into the user prefix, and
reports success. Use `npm install -g --prefix /usr/local @kinlab/kin` when the system prefix
is what you want.

### Windows

On native Windows, use PowerShell:

```powershell
irm https://get.kinlab.dev/install.ps1 | iex
```

Native Windows x86_64 support is early. Repository admission works: `kin init` imports a Git repository and publishes graph authority, and graph, lexical, and daemon-backed queries answer natively. Transparent filesystem projection is not shipped on Windows, and the end-to-end install proof does not yet cover MCP or review workflows there, so WSL2 remains the recommended path for the full Kin experience.
The PowerShell installer prints that boundary before downloading anything. Native
Windows ARM64 has no release archive; an x64 PowerShell process may use the x86_64
archive under Windows emulation, but WSL2 is the recommended path. Follow the Linux
flow inside WSL2; see [windows-wsl2.md](./windows-wsl2.md).

Git for Windows sets `core.autocrlf=true` in its system config, which rewrites line
endings on checkout. `kin init` admits the committed tree, so a repository cloned that
way still admits successfully. Init reports the rewritten files under `Uncommitted
worktree state:` rather than treating them as your edits. To make the worktree match
what Kin admitted, run `git config --global core.autocrlf false` and clone again.

### Installer options

Configure the installers with environment variables (supported by both `install.sh`
and `install.ps1` unless noted):

- `KIN_VERSION`: pin a specific version (e.g. `0.5.25`); otherwise the latest release is
  resolved automatically.
- `KIN_HOME`: custom managed install directory (preferred; defaults to `~/.kin`).
- `KIN_DIR`: compatibility alias for `KIN_HOME`.
- `KIN_NO_SETUP=1`: on macOS and Linux, skip the `kin setup` wizard after the
  binaries are installed (run `kin setup` yourself when ready).
  Native Windows always skips repository setup because the install proof does not yet cover MCP or review workflows there.
  `KIN_NO_SETUP` is accepted there only for CI compatibility and selects the
  CI-oriented skip message.
- `KIN_BASE_URL`: install from a mirror or local path instead of GitHub releases
  (offline / airgapped installs and CI smoke tests).

---

## 2. Guided setup (`kin setup`)

On macOS and Linux, `kin setup` is the guided wizard the installer launches for you
(run it again any time). Native Windows does not launch repository setup; use the
Linux flow inside WSL2. The wizard opens with **"What do you want Kin for?"** and asks
for your **intent** rather than a bag of independent toggles:

| Intent | What it configures |
| --- | --- |
| **AI agents** (default) | Kin's MCP server for every detected AI client, plus shell integration and daemon auto-start. The smallest path to value. |
| **Local-only** | Shell integration + daemon auto-start; no AI client config. |
| **Editor** | Local-only, plus how to install the `kin-editor` VS Code extension. |
| **Hosted / KinLab** | Local setup, plus this machine's KinLab sign-in state and the commands that change it (see below). |
| **Advanced / manual** | Choose shell, per-client MCP, and daemon options yourself. |

To configure the editor path directly:

```sh
kin setup --intent editor
```

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

> **Hosted / KinLab.** The wizard reads the credential this machine already holds and
> reports it: signed in as an account with its expiry, present but encrypted, or not
> signed in. Connecting is `kin auth login --provider github` if you have a GitHub
> account, or `kin auth login` for the Google sign-in, which is the default
> (`--base-url <url>`, or `KINLAB_URL`, for a workspace other than the default).
> `kin auth whoami` confirms the account the workspace sees, and `kin auth status`
> names the provider the login asked for. Local setup does not depend on any of it.

---

## 3. Initialize a repository

Start a brand-new Kin-native repository:

```sh
mkdir my-app
kin init my-app
cd my-app
```

In an empty directory with no `.git/`, `kin init` creates an unborn native
repository-v6 authority with an empty exact workspace and no synthetic commit.
It refuses a non-empty non-Git directory rather than silently treating
filesystem contents as graph truth.

Convert an existing Git repository or folder:

```sh
# Initialize in the current directory
kin init

# Or initialize a specific path
kin init path/to/project
```

In a detected Git repository, `kin init` imports complete reachable
history, refs, raw objects, the exact workspace tree, and admission policy into
graph-owned authority. A worktree with uncommitted edits, staged changes, or
untracked files still admits: `kin init` admits the committed state and
discloses what it did not admit. It also derives the semantic entity and relation layer
for every supported entity-source file in that history, and reports the durable,
generation-bound counts it committed. Git stays in place as an explicit
interoperability boundary; Kin runtime queries do not fall back to it.
Repository-local remote URLs, refspecs, branch tracking, and push defaults that
Kin can represent safely are sealed into its Git coexistence configuration.
Unsafe, ambiguous, or unsupported transfer settings fail closed before
publication.

*Flags:*
- `--json`: report the exact committed repository/workspace authority result,
  including the semantic enrichment admission produced.

### How long admission takes, and what it prints

Admission is a one-time cost that scales with the size of your history rather
than the size of your checkout, because every reachable commit's tree is
observed and recorded. On a small repository it takes seconds. On a repository
with thousands of commits it takes minutes and can hold several gigabytes of
memory while it runs.

`kin init` prints its phase ladder to stderr so the terminal is never silent
while that happens:

```
  [ 1/17] check admission blockers 0.2s
  [ 2/17] capture Git repository 1.4s
  [ 3/17] build Git authority 0.2s
  [ 4/17] plan semantic import 3.1s
  [ 5/17] derive semantic history 41.7s
  ...
  [17/17] seal published content 12.9s
  admitted exact Git repository in 118.3s
```

The long phases report their own progress while they run, so a phase that is
walking history shows how far it has gone. Stdout stays clean, so
`kin init --json` is still safe to pipe.

### How much disk the store takes

Disk scales the same way time does, with history depth rather than checkout
size, and for the same reason. Kin derives a semantic layer over every reachable
revision, so the store carries a parsed representation of source that Git only
ever carried as compressed bytes.

That means `.kin/` is not bounded by the packfile it was admitted from, and the
ratio between them varies widely between repositories. A repository with a long
history in a language Kin parses expands the most. A repository with almost no
history can finish smaller than its Git object store.

`kin init` reports both sizes and the ratio when it finishes, and `kin status`
reports the same line afterwards. On ripgrep at `e89fff89`, 2,261 commits, it
reads:

```
  Store size: 405.4 MiB under .kin/, 66.5x the 6.1 MiB Git object store
```

Read that multiple as one measurement, not as a constant. The ratio moves by
more than 3x across repositories of similar size in different languages, and a
repository that has reset away a large commit can land below its Git object
store entirely. [Store size](./store-size.md) explains what drives the number
and records every repository measured so far. `kin init --json` carries the raw
byte counts under `store_footprint`. Kin does not cap store size or refuse a
repository for being large, so plan disk against your history rather than
against your checkout.

### Profiling a slow command

Every `kin` command can profile itself. No rebuild, no external profiler, and
no debug symbols are needed:

```sh
# Print the hottest stages to stderr when the command finishes
kin init --profile-summary

# Write the full machine-readable profile to a file
kin init --profile-out /tmp/kin-init-profile.json
```

`--profile-summary` (or `KIN_PROFILE_SUMMARY=1`) prints a ranked list of the
slowest stages with their self time, plus peak CPU, peak resident memory, and
peak thread count. `--profile-out` (or `KIN_PROFILE_OUT=<path>`) writes a JSON
report carrying every instrumented span with its start and end offsets, a
resource timeline sampled every 250 ms (`KIN_PROFILE_SAMPLE_MS`), and per-stage
rollups. Use `--profile-out` when reporting a performance problem: it is the
fastest way to say which phase owns the time rather than guessing from wall
clock.

---

## 4. Add embeddings for semantic search

Admission derives the semantic entities, not their vectors. Build the vector
index over them with:

```sh
kin embed
```

Embeddings are generated locally with `nomic-embed-text-v1.5` (768 dimensions; override
via `KIN_EMBED_MODEL_ID`).

The model is not bundled with any install. The first embed on a machine downloads about
523 MB of it from huggingface.co into the Hugging Face hub cache under your home
directory (`~/.cache/huggingface/hub/models--nomic-ai--nomic-embed-text-v1.5`), and
nothing embeds until that download lands. While it runs, `kin graph status` and `kin
resources inspect` name the download and its progress rather than reporting a pass with
nothing to show. `kin init` says up front whether this machine still owes the download,
and `kin doctor` carries an **Embedding model** check that reports whether the weights
are present and fails when the host cannot reach huggingface.co.

To embed on a host with no egress, copy an existing hub cache from a machine that has
the model into the same path, or point `KIN_EMBED_MODEL_ID` at a local model directory.
Note that `HF_HOME` does not move where the embedder looks: it loads from the home cache
root regardless, so seed that root rather than a relocated one.

You can check coverage at any time:

```sh
kin graph status   # "Embeddings: <indexed>/<total> indexed (<pending> pending)"
kin status --json  # durable authority entity/relation/change counts and generations
```

These commands intentionally answer for different views. `kin status` reports
the immutable repository/workspace authority generation it opened.
`kin graph status` reports the daemon's mutable live query graph, including
derived runtime enrichment that has not become repository authority.

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

### Orient to the graph

```sh
kin overview
```

### Commit changes

Save a new semantic change snapshot:

```sh
kin commit -m "refactor: optimize user query path"
```

### Branch and merge

A branch is a ref over the same immutable history, and a merge composes both
sides by entity identity against their common base rather than by line:

```sh
kin branch create cap-backoff   # a new ref at the current head
kin branch switch cap-backoff   # move the workspace onto it; uncommitted work comes along
kin commit -m "Raise the backoff cap to a minute"
kin branch switch main
kin merge cap-backoff           # one merge change carrying both parents
```

A merge that does not compose is parked as a durable conflict record rather
than refused: `kin conflicts` shows it and `kin resolve` settles it. The
[README runs this loop end to end](../README.md#version-control-without-git)
in an empty directory, with the output of a real run.

### View history

```sh
kin log -n 10
```

### Semantic diff

Inspect changes at the level of entities rather than raw lines:

```sh
kin diff
```

### Run your normal tools

Ordinary project commands run through a graph-backed **session workspace**, the
venv-like execution contract, so you never need to know which files are
materialized before running the repo:

```sh
kin exec -- npm test          # one-shot command
kin shell                     # interactive shell in a session workspace
kin with claude -- "fix the failing test"             # agent inside a session
```

On success the session reconciles back into the graph (generated dirs like
`node_modules/` are skipped by policy); on failure the workspace is preserved
with recovery commands. See [Session runtime](session-runtime.md) for closeout
flags, Docker and Compose caveats, and what is not claimed yet.

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

### Run the checked fixture query

Kin's bounded onboarding smoke copies the readable
[quickstart checkout fixture](../crates/kin-cli/tests/fixtures/quickstart/checkout.py)
into a temporary repository, initializes it, and uses this exact graph query:

```sh
kin locate "apply_quickstart_discount"
kin refs apply_quickstart_discount
```

The smoke then resolves `refs` from the entity ID returned by `locate`. It runs
without background embedding and has a 120-second wall-clock limit. This is an
onboarding check, not benchmark evidence or a performance claim.

### Review a branch range

```sh
kin review shadow "$(git rev-parse BASE_BRANCH)..$(git rev-parse HEAD)"
```

Replace `BASE_BRANCH` with the branch you want to compare, and run `kin init`
after both commits exist so the exact SHAs are part of Kin's imported graph.

---

## 7. Using Kin from an AI agent (MCP)

If you chose the **AI agents** intent in step 2, `kin setup` already wrote Kin's MCP
server entry into every detected AI client (Claude Code, Cursor, Codex CLI, Gemini CLI,
Windsurf, Google Antigravity) and added a Kin-first discovery reminder to your agent
instruction files. There
is **nothing else to configure**. Open your agent in a Kin repository and ask it to use
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
      "command": "/absolute/path/to/kin",
      "args": ["mcp", "start"],
      "env": { "KIN_MCP_TOOL_PROFILE": "agent-default" }
    }
  }
}
```

`KIN_MCP_TOOL_PROFILE=agent-default` names the small curated tool surface. That is also
what an unconfigured `kin mcp start` serves, so a hand-wired entry gets the same surface;
set `full` (or pass `--tool-profile full`) when you want every tool. (The wizard writes an
absolute path to the installed `kin` binary as the `command`, so the entry works in agent
processes that do not inherit your `PATH`.)

> Vector-backed MCP retrieval (`semantic_locate`) and the stateful session / transaction /
> work / review tools operate against the repo's running Kin daemon. Daemon auto-start is
> on by default, so these tools have a live graph to query. `semantic_locate` returns an
> explicit error in offline / no-daemon mode.

### What to ask for on a brand new project

Adjust the ask when the repository is one you just started. Kin ranks on cross-file
structure, and a five-file project has the least of it. The tools that pay off from the
first checkpoint are `kin commit`, `kin graph status` to watch the graph fill in,
`trace_data_flow` for how the pieces wire together, and `get_entity_source` for reading
code back. Description-shaped `semantic_locate` queries need more entities than a new
project has, so ask by exact name at that size and let ranked retrieval earn your trust as
the graph grows. When the graph is small enough for this to bite, `semantic_locate` says so
in its `degradations` array rather than leaving you to find out from a weak answer.

For the full tool surface, see the [MCP Tools Reference](mcp-tools.md). To wire up a
client by hand (or use the npm wrapper), see
[Advanced configuration](#9-advanced-configuration).

---

## 8. Verify your setup (`kin setup status`)

Run the health checklist at any time. It probes real filesystem, daemon, and agent state,
so nothing is assumed healthy:

```sh
kin setup status          # human-readable table
kin setup status --json   # machine-readable report
```

Each line shows a status mark:

- `✓` **ok** means healthy.
- `✗` **MISSING** / **MISCONFIGURED** means the install itself is wrong.
- `✗` **DEGRADED** means the machine is short of ground Kin measured it needs. Nothing
  about the install is wrong and the row still costs you work, so it reads red.
- `!` **STALE** means present but drifted, such as a shim that is installed and not
  injected into this shell.
- `…` **PENDING** means expected first-run work still in flight, such as the first
  embedding pass or the model download.
- `→` **n/a** means unsupported, so the check does not apply on this platform or in this
  context.

The report closes with one verdict over all of them, emitted in `--json` as `verdict`
beside the `healthy` boolean:

- `ready`, and `healthy: true`. Every check in scope is ok. `n/a` rows do not count
  against it, which is why a correct Windows install can still read ready.
- `needs_attention`, and `healthy: false`. Something is not answering at full strength:
  a PENDING or DEGRADED or STALE row. Kin works; the row tells you what you are not
  getting yet.
- `failing`, and `healthy: false`. A MISSING or MISCONFIGURED check, or a semantic
  readiness Kin cannot read.

`healthy` is true only for `ready`. It used to be true whenever nothing was MISSING or
MISCONFIGURED, which meant a fresh install printing "2 checks need attention" on its last
line also reported `"healthy": true` to every machine reader (FIR-2919). Read `verdict`
when you need to tell a warming install from a broken one; the boolean cannot carry that
difference.

The checks (IDs as emitted in `--json`):

| Check (id) | What "ok" means |
| --- | --- |
| `kin_binary` | The `kin` binary resolved (reports version + path). |
| `kin_daemon_binary` | `kin-daemon` found beside `kin` or on `PATH`. |
| `vfs_projection` | The VFS shim is installed and non-zero in `~/.kin/lib`, and the `kin-vfs` driver beside `kin`, in `~/.kin/bin`, or on PATH runs when probed (macOS/Linux). A driver that is present but will not load is **MISCONFIGURED** and the row quotes the loader; no driver and no shim is **n/a**. On native Windows this is **unsupported**; use WSL2. |
| `projection_mode` | Which projection is in force and whether it works, read `mode/mounted/readable/writable/degraded` from a live probe across the shim, an NFS mount, a FUSE mount and Windows ProjFS. **n/a** when no projection is available and none is configured, which is what an install that ships without one looks like; Windows never gets that reading, because ProjFS is on every SKU and only needs enabling. A configured mode that is not running is **MISCONFIGURED**. A shim that is installed but not injected into this process is **STALE**, which is what running `kin` from a shell without the hook looks like. |
| `repo_init` | The current directory is inside a Kin repository. |
| `shell_path` | The `kin-vfs` shell hook is installed and sourced from your rc, and the managed `~/.kin/bin` directory is on PATH now or will be after shell restart. On an install that does not create `~/.kin/bin`, such as an archive or Homebrew one, no PATH line is written and the row says so. |
| `mcp_client_*` (e.g. `mcp_client_claude`) | A detected AI client has the `kin` MCP server with the `agent-default` profile. With no client configs present, a single `mcp_clients` check reports ok when no client is installed either, and **n/a** naming the detected clients that `kin setup` would configure. |
| `editor` | The `kin-editor` VS Code extension is detected in `~/.vscode/extensions`. **n/a** if not found / non-VS Code. |
| `kinlab_connect` | A stored KinLab credential is present, and the provider its login asked for when the credential records one. **n/a** when nothing is stored; `kin auth login` connects this machine. A credential minted before `--provider` existed, or one this row cannot read without a prompt, names no provider and the row says nothing rather than guessing. |
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
- **`projection_mode` MISCONFIGURED** → run `kin vfs status` for each mode's probe result,
  then `kin vfs on` to engage one. See [Filesystem projection](projection.md).
- **`kin_daemon_binary` MISSING** → reinstall Kin so `kin-daemon` lands beside `kin`.
- **`commit_identity` MISCONFIGURED** → set `git config --global user.name` and
  `git config --global user.email`, or put `default_author = "Your Name <you@example.com>"`
  in `.kin/config.toml`. Kin refuses to commit rather than attribute a change to nobody,
  because a change record is permanent and its author cannot be corrected afterwards.

`kin doctor` (or `kin setup doctor`) runs the same checklist; add `--fix` to apply the
safe repairs (shell hook, MCP configs, config dirs, stale-daemon cleanup) and then re-run
the checks to show the post-fix state:

```sh
kin doctor          # report only
kin doctor --fix    # apply safe repairs, then re-check
```

---

## 9. Advanced configuration

You do not need anything here for a normal first run, because the guided wizard covers
it. This section is for manual wiring, troubleshooting, and non-standard environments.

### Manual MCP client configuration

If you skipped the wizard's agent step, or your client wasn't auto-detected, add Kin's MCP
server to your client's config by hand. Use `$KIN_HOME/bin/kin` (normally `~/.kin/bin/kin`)
when that managed launcher exists; otherwise run `command -v kin`. Substitute that exact
absolute path for `/absolute/path/to/kin` below. Match the wizard exactly, including the
`agent-default` profile:

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

Config file locations the wizard targets (and `kin setup status` inspects):

| Client | Config path |
| --- | --- |
| Claude Code | `~/.claude.json` (falls back to `~/.claude/config.json`) |
| Cursor | `~/.cursor/mcp.json` |
| Codex CLI | `~/.codex/config.toml` (TOML, see below) |
| Gemini CLI | `~/.gemini/settings.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |
| Google Antigravity | `~/.gemini/config/mcp_config.json` (global) and `<repo>/.agents/mcp_config.json` (workspace) |

Codex is the exception: it reads TOML (`[mcp_servers.<name>]` tables), not JSON. The wizard
merges this table into `~/.codex/config.toml`, leaving the rest of the file untouched:

```toml
[mcp_servers.kin]
command = "/absolute/path/to/kin"
args = ["mcp", "start", "--repo", "/absolute/path/to/repository"]
env = { KIN_MCP_TOOL_PROFILE = "agent-default" }
```

`kin mcp start` launches the MCP **stdio** server. You normally do not run this by hand,
because your AI client launches it as a subprocess via the config above. The server binds
per invocation: it uses `KIN_DAEMON_URL` when set (agent sessions launched with
`kin with` pin it), and otherwise resolves the repository by walking up
from the working directory, so each agent session talks to the daemon of the
repository it is actually working in.

### npm wrapper (`@kinlab/kin`)

If you'd rather not install the binaries first, the canonical `@kinlab/kin` package
downloads, checksum-verifies, and runs the managed Kin CLI for you. For setup:

```sh
npx -y @kinlab/kin setup --intent agent --no-interactive
```

For a manually configured MCP client:

```json
{
  "mcpServers": {
    "kin": {
      "command": "npx",
      "args": ["-y", "@kinlab/kin", "mcp", "start"],
      "env": { "KIN_MCP_TOOL_PROFILE": "agent-default" }
    }
  }
}
```

`kin setup status` and `kin doctor` recognize this exact canonical npm topology instead of
flagging it for repair. Nearby wrapper shapes and a bare `kin` command are not treated as
equivalent: agent clients do not reliably inherit your shell `PATH`. Codex and Antigravity
entries are repository-bound; when configuring
either by hand, append `"--repo", "/absolute/path/to/repository"` to the argument vector
(and set Antigravity's workspace `cwd` to that same absolute repository path).

The older `@kinlab/kin-mcp` package remains published for existing configurations. New
setups should use `@kinlab/kin`, which includes the same MCP server as `kin mcp start`.

### Runtime / daemon configuration

The Kin daemon is the canonical authority for graph truth and auto-starts as needed for
normal use. The escape hatches:

- `KIN_NO_DAEMON=1`: never start or revive a daemon (use only an already-running daemon or
  `KIN_DAEMON_URL`). This is the probe contract: `kin mcp start --no-spawn` sets it so
  scheduled and boot-time checks can hold the full MCP handshake while provably spawning
  nothing, and graph calls without a running daemon fail loud instead of starting one.
- `KIN_DAEMON_URL`: point the CLI at an explicit daemon endpoint.
- `KIN_ALLOW_DAEMON_BOOTSTRAP_ADMIN=1`: offline/admin escape hatch that lets the read-only
  in-process commands fall back to reading the local `.kin` snapshot directly. It is never
  used for writes, and all graph mutations still route through the daemon.

---

## 10. Removing Kin

Kin is ejectable, with no data lock-in. Eject remains graph-first all the
way through the exit:

```sh
kin eject
```

Kin resolves the current branch from graph history, verifies every referenced
blob and every projected file byte, kind, symlink target, and executable mode,
then builds and strictly verifies a complete ordinary Git replacement off to
the side. Every replacement Git object, ref, config, directory, and index when
one exists is flushed before Kin authority is detached, as are the publication
parent entries. It stops the daemon and checks the persisted graph and working
projection again before changing either authority namespace. If anything is
missing, locally edited, unsupported (including a Gitlink/submodule), or raced
during shutdown, eject refuses before detaching Kin.

On success, working files are not rewritten. The exact graph-derived Git
repository is durably installed at `.git/` first, then the locked `.kin/`
namespace is atomically detached with a no-replace rename. The detached
metadata and the pre-eject repository-local `.git` entry are retained in a
private sibling archive as `kin/` and `previous-git/`. Credential-free remote
URLs, refspecs, branch tracking, and push defaults sealed during Git import are
restored; credentials and ambient Git configuration are never copied. The
command prints the exact archive path. A finished eject leaves no journal in
the archived `kin/`, so copying that directory back to `.kin` re-attaches the
store and the next `kin commit` records what changed in the working tree
since. An archive an older Kin wrote still carries its eject journal; a copy
made from it is accepted the same way once the archive proves the eject
finished, and a journal Kin cannot verify is refused with the file and the
remedy named. Kin intentionally leaves irreversible
archive deletion to the operator after an independent backup; the eject
transaction never follows an ambient path to recursively delete detached
authority. The capability-anchored transaction is currently supported on Unix
hosts. Windows eject fails before namespace mutation until the same durable
retained-handle guarantees are implemented there. Kin never restores an
initialization-time filesystem snapshot or treats the old `.git/` as authority.

To keep Kin attached and instead create a standalone interoperability
projection, export one exact authority generation to a new bare repository:

```sh
kin git export --output ../project-export.git
```

The destination parent must already exist. The destination itself must not
exist and cannot be inside the Kin working repository. Working-file edits and
the ambient `.git/` object store are not export inputs. Exact publication is
currently supported on Unix hosts; other hosts refuse before creating the
export until an equivalent retained-handle namespace transaction is available.
