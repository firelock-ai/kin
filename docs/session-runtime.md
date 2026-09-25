# Session runtime

Kin's session runtime is the venv-like execution contract for a Kin repository.
You, or an agent, run normal project commands such as `npm test`, `make`,
`docker compose config`, an editor, or a coding assistant, without knowing which
files are graph-owned, projected, or materialized. Kin materializes graph truth
into a **session workspace**, the tool runs there like in any ordinary checkout,
and Kin reconciles the results back into the semantic graph when the session
ends.

Four surfaces share this contract:

| Surface | What it is | When to use it |
| --- | --- | --- |
| `kin exec -- <cmd>` | One-shot command in a fresh session workspace | `kin exec -- npm test`, `kin exec -- make build` |
| `kin shell` | Interactive shell inside a session workspace | exploratory work, multiple commands in one session |
| `kin with <assistant> -- <task>` | AI assistant launched inside a session workspace | agent work that should start Kin-native |
| `kin open <code\|cursor>` | Supported editor launched over a retained session projection | human editing sessions |

`kin setup` is **not** part of this contract: it is one-time configuration that
installs Kin's MCP server entry into your AI clients (Claude Code, Cursor,
Codex, Gemini, Windsurf, Google Antigravity, LM Studio, Grok CLI) and your shell hook. In short:

- **`kin setup`**: configure clients once (MCP install, shell hook).
- **`kin exec` / `kin shell`**: run ordinary commands through a session workspace.
- **`kin with`**: launch an assistant inside a
  session workspace with session-coherent MCP.

## What ships, and what does not

Exact session materialization is implemented at the daemon boundary, including
non-code and binary artifacts, executable bits, symlinks, exact source-CAS
reads, and a durable base record that reconcile authenticates. `kin exec`,
`kin shell`, `kin open`, `kin with`, and `kin reconcile` are exposed: the daemon
materializes the whole repository as the projection and the process runs inside
it. A clean exit of `kin exec`, `kin shell` or `kin with` admits the observed
delta through the reconcile boundary; `kin open` keeps the projection for a
later `kin reconcile`.

Four things are deliberately not claimed yet.

- **Docker and Compose** are represented and materializable, but are not
  claimed end to end through these launchers. The
  [caveats below](#docker-and-compose-caveats) describe what does work today.
- **Byte-exact non-UTF-8 repository paths** fail closed at the physical session
  boundary. They are retained in repository authority and in Git export, but the
  UTF-8 workspace boundary does not project them.
- **Gitlinks** also fail closed there. They are retained exactly as imported
  targets, and they await the graph-native cross-repository model and recursive
  materialization.
- **Parts of the detail below** state the contract these commands satisfy rather
  than a walkthrough of one observed run.

`kin capabilities --json` reports live per-command availability, and it is the
authority when it and this page disagree. So is the code.

## The execution contract

1. **Materialize.** The repo daemon materializes graph-owned truth into
   `.kin/runs/session-<id>/`. This is a real directory containing real files,
   so any tool works unchanged. Every session launcher materializes the whole
   repository: a scoped session, one that holds only selected artifacts, is
   refused until its selected set can be authenticated outside the editable
   session.
2. **Run.** The command executes locally in that workspace (never through the
   daemon), with `KIN_SESSION=1`, `KIN_SESSION_DIR` and `KIN_WORKSPACE_ROOT`
   (the workspace root), and `KIN_SESSION_ID` (the session the launcher
   registered, or removed when it registered none) set. Nested Kin and MCP
   calls find the same repository by walking up from the workspace, and carry
   `KIN_SESSION_ID` to its daemon.
3. **Reconcile.** On success, Kin admits the workspace's own changes against
   the exact repository authority it was materialized from, not as a
   whole-tree overwrite, and then removes the workspace. A repository that
   moved on in the meantime is covered under
   [Reconcile against newer authority](#reconcile-against-newer-authority).
4. **Fail loud, lose nothing.** On a non-zero exit, or if reconcile itself
   fails, the workspace is **preserved** and Kin prints the recovery
   commands:

   ```
   Process exited <code>; session workspace kept at: .kin/runs/session-<id>
     admit its changes anyway: kin reconcile <id>
     discard it: rm -rf .kin/runs/session-<id>
   ```

   `kin reconcile <id>` admits the workspace and then removes it, so a
   preserved workspace lives exactly until its changes land. A reconcile that
   is itself refused leaves the workspace alone.

`kin doctor` reports leftover session workspaces and the same recovery
commands under its **Session runtime** check.

### Closeout flags (`kin exec`)

- default: reconcile on success, clean up; preserve on failure.
- `--keep`: keep the workspace and defer reconcile (`kin reconcile <id>`
  when ready, which admits it and then removes it).
- `--discard`: throw the workspace away without reconciling (pure scratch
  run).

Put kin flags **before** the command; everything after belongs to the command:
`kin exec --keep -- npm run build`.

### Generated files and build outputs

Reconcile never admits a new build output from any session. A file graph truth
does not already hold is withheld when:

- its first bytes are an executable, object or library format Kin recognizes:
  ELF, Mach-O (32-bit, 64-bit and universal), PE, `ar` archives, Java class
  files and WebAssembly; or its extension is one of `.o`, `.obj`, `.a`, `.lib`,
  `.so`, `.dylib`, `.dll`, `.exe`, `.rlib`, `.rmeta`, `.class`, `.pyc`, `.pyo`
  and `.wasm`;
- or any directory in its path is a name the repository never admits new files
  from by default: `target/`, `node_modules/`, `bower_components/`,
  `__pypackages__/`, `dist/`, `__pycache__/`, `.venv/`, `.tox/`, `.nox/`,
  `.pytest_cache/`, `.mypy_cache/`, `.ruff_cache/`, `.ipynb_checkpoints/`,
  `.eggs/`, `.next/`, `.nuxt/`, `.svelte-kit/`, `.turbo/`, `.parcel-cache/`,
  `.nyc_output/`, `.gradle/` and `.terraform/`, and the names `.kin-coord` and
  `.DS_Store`. Such a directory with nothing
  graph truth tracks beneath it is not walked at all, so a dependency tree or a
  build directory costs the observation nothing.

So:

- `kin exec -- go build ./...` runs, and the compiled binary it leaves is
  reported and not admitted. A run whose only output is the binary publishes
  nothing.
- `kin exec -- npm install` reconciles `package-lock.json` and never walks or
  imports `node_modules/`.

The rule applies to new files only. A file graph truth already tracks is the
repository's own, so a session that rebuilds a tracked binary changes it as
before. Recognition is by those formats, extensions and names and nothing
else: a compiler output in another format, under an ordinary directory name, is
admitted like any other new file. `build/`, `out/`, `bin/` and `vendor/` are
not on the list, because they routinely hold hand-written source; a repository
that wants them excluded says so in its `.kinignore`, which this session policy
does not read.

The reconcile summary lists every change it did not admit under `withheld`,
with its path, whether it was added, modified or removed, and the reason. A
withheld change is not counted in `added`, `modified` or `removed`.

Anything else the tool writes **is** treated as a real change and reconciled on
success. Use `--discard` for runs whose outputs you do not want, or `--keep` to
inspect before reconciling.

### External tools

Some tools read far more than the files you name: package managers resolve
manifests, lockfiles, and workspaces; `make` follows arbitrary prerequisites;
Docker sends a whole build context to the daemon. Because every session
workspace is the whole repository, these tools see the same complete tree they
would in an ordinary checkout, and nothing is widened or detected on their
behalf.

## Docker and Compose caveats

Container workflows cross a process boundary (the Docker daemon), so a few
session-workspace realities matter:

- **Build context.** `docker build` from a session workspace sends the
  *materialized* workspace as the build context. That is graph truth, but it
  is a copy. Absolute `COPY`/`ADD` assumptions about your repo's on-disk path
  do not apply.
- **Bind mounts.** `-v $(pwd):/app` style mounts point at
  `.kin/runs/session-<id>/…`, which is **removed after successful closeout**.
  Do not leave long-lived containers bind-mounted into a one-shot `kin exec`
  workspace. For iterative container work, use `kin shell` (the workspace
  lives as long as your shell) or `kin exec --keep`.
- **Daemon-side writes.** Files written by containers into bind mounts land in
  the session workspace and follow normal reconcile rules (generated dirs are
  skipped; everything else reconciles on success).
- **Safe validation.** `kin exec -- docker compose config` validates your
  compose file against materialized graph truth without starting anything,
  which makes it the recommended smoke check.
- **Cleanup.** Kin removes the workspace, not your containers/volumes/images.
  Stop containers that reference a session path before closeout.

## Agent sessions and MCP session coherence

`kin with <assistant> -- <task>` starts the assistant **inside** the
session workspace. It runs in one of two ways.

**Compatibility launch** (`kin with claude|codex|gemini -- <task>`). The
assistant keeps its own tools, so its shell commands and file edits operate on
the materialized workspace, a copy of graph truth, and reach the graph only
through reconcile:

- cwd is the session workspace root.
- The environment carries the session identity: `KIN_SESSION=1`,
  `KIN_SESSION_ID` (the registered session), and `KIN_SESSION_DIR` and
  `KIN_WORKSPACE_ROOT` (the workspace root).
- On a clean exit the workspace's changes reconcile into the graph and the
  workspace is removed; on failure the workspace is preserved with recovery
  commands, same as `kin exec`.

**Semantic-only launch** (`kin with --semantic-only claude -- <task>`). Claude
Code starts with every built-in tool removed, Bash, Read, Edit and Write
included, and with Kin's MCP server as the only one loaded; a hook refuses any
other tool call. The agent reads and changes code through Kin's tools, by
entity, and its changes commit to repository authority through `kin_mutate`,
not through the workspace. The workspace therefore stays unchanged, and its
closeout publishes nothing (see
[Reconcile against newer authority](#reconcile-against-newer-authority)).
It builds, tests and runs the project with `kin_session_exec` (see
[Agent toolchain runs](#agent-toolchain-runs)), which the `agent-default`
profile it is served carries, in a session workspace of its own. A person can
also verify outside the session with `kin exec -- <command>`. `--semantic-only`
is enforced for Claude only: Codex
and Gemini refuse the flag rather than launch with guidance they cannot
enforce.

**MCP session coherence.** The MCP server ships inside the `kin` binary
(`kin mcp start`) and binds per invocation:

1. If `KIN_DAEMON_URL` is set, the MCP server forwards every graph tool call
   to exactly that daemon. No cwd guessing, no stale global config. A session
   launch does not set it, so a session relies on the next step.
2. Otherwise it discovers the repository by walking up from the working
   directory. Because agents launched with `kin with` start inside
   `.kin/runs/session-<id>`, the walk lands on the same repository's `.kin/`.
3. When `KIN_SESSION_ID` is set, each forwarded tool call that names no session
   of its own carries it as the `X-Kin-Session` header, so the daemon can serve
   session-scoped graph state where it applies and the live HEAD graph
   otherwise.

Semantic answers stay graph-backed throughout: `semantic_locate`,
`get_context_pack`, `trace_data_flow`, and the other MCP tools are answered by
the daemon's graph authority, never by grepping the materialized workspace.
The workspace is an execution surface, not a search authority: for semantic
work, ask Kin, and do not read or search the workspace's files instead.

`kin with` registers a session with the daemon before it starts the assistant,
under its own process id, and ends it when the assistant exits, before the
closeout reconcile. `kin exec`, `kin shell` and `kin open` register none, so
their children carry `KIN_SESSION`, `KIN_SESSION_DIR` and `KIN_WORKSPACE_ROOT`
but no `KIN_SESSION_ID`; an MCP client started from `kin shell` binds its
repository by walking up from the workspace.

`kin open` accepts VS Code (`code`) and Cursor (`cursor`) only. It passes the
workspace to the editor and keeps it: editors detach from the process that
launched them, so there is no exit to reconcile on. Run `kin reconcile <id>`
when you are done, which admits the workspace's changes and removes it. If the
editor launch itself fails, the workspace is kept and Kin says where.

The daemon has no command-execution endpoint. `kin exec` always launches the
requested argv locally inside the materialized workspace; shell evaluation is
available only through the explicit `kin exec --shell` mode. Shell mode accepts
one script argument, so quote the complete script:
`kin exec --shell -- 'printf "%s\n" "$KIN_SESSION_DIR"'`.

## Agent toolchain runs

An agent that reaches Kin only through MCP runs the project's toolchain with
`kin_session_exec`, served by name on `agent-default` and as the `exec` command
on `agent-routed`. It is the same session workspace with a narrower contract:

- **What runs.** Only the project's toolchain entry points, run directly with
  no shell, in a workspace materialized from the session's current graph head.
  The defaults follow the languages detected from the workspace's names, and
  the repository can add commands under `[execution.agent]` in
  `.kin/config.toml`. Shells, command runners, inline code, file utilities,
  toolchain flags that hand a build to another program, and paths outside the
  workspace are refused before anything runs, whatever that configuration
  says. A call may set plain application variables, such as `TASKS_FILE`; one
  that changes how a program is found, loaded, built or fetched, such as
  `PATH`, `LD_*`, `GOFLAGS` or a proxy, is refused.
- **What comes back.** A command that succeeds is reconciled under the agent
  write-back policy: the manifests and lockfiles of the toolchain that ran,
  `go.mod` and `go.sum` for a `go` command, are admitted and recorded as one
  change attributed to the session. The change is recorded only while the
  workspace still holds exactly the tree that admission published, so another
  writer's content is never attributed to the session. Source code the command
  created, changed or removed is refused and reported, because an agent writes
  code through entity operations; every other file, an application's own data
  files included, is refused; build outputs are never admitted. A command that
  fails or times out keeps nothing it wrote, and the workspace is removed
  either way.
- **What the answer says.** The exit code, the elapsed time, stdout and stderr
  bounded with a disclosure of what was cut, what was admitted and withheld,
  and `ran_on`: the committed head, tree and workspace generation the
  workspace was materialized from, read from its base record before the
  command started.

The command still runs the project's own code, which can do whatever that code
does. What the contract governs is what an agent can run directly and what
comes back into the graph.

## Daemon environment boundary

The repo daemon is a long-lived, per-user singleton. The **first** `kin` command
that needs it spawns it, and the daemon inherits **that** command's environment.
Every later command reaches the already-running daemon over HTTP and does **not**
re-export its own environment into the worker. So a behavior-relevant knob that
is read inside the daemon worker, or in the embedding / inference substrate it
hosts, is fixed at whatever value the daemon captured when it started.

The consequence is a quiet footgun: running

```
KIN_EMBED_HYBRID=balanced kin embed
```

against a daemon that started **without** that variable applies the daemon's
captured value, not the one on this command line. The override is silently
ignored, because the substrate reads it at the worker's process start, not per
request.

Kin makes that mismatch loud rather than fixing the value in place:

- The daemon reports the value it holds for each behavior-relevant variable in
  its `/health` payload (`behavior_env`).
- Environment-sensitive commands (`kin embed`, `kin resources`) compare the
  current environment against that report and, on any divergence, print a
  warning to stderr naming each variable with both sides' values.
- The remedy is to restart the daemon so it re-inherits the current environment:
  stop it (`kin daemon stop`, or `kill $(cat .kin/daemon.pid)`; it also self-stops
  after its `KIN_DAEMON_IDLE_TIMEOUT_SECS` idle window) and the next `kin` command
  respawns it.
- Set `KIN_STRICT_BEHAVIOR_ENV=1` to escalate the warning to a hard error, so
  scripted and proof runs fail closed instead of measuring the wrong lever.

The authoritative list of behavior-relevant variables is defined once in
`kin-core` (`behavior_env`) and shared by both the daemon (which reports them)
and the CLI (which compares them), so the two sides cannot drift apart.

## When an MCP session starts a daemon

`kin mcp start` starts no daemon until a caller asks for a graph answer. The
first `tools/call` is that ask, and it is the only one: `initialize`, the tool
list and the client's `roots/list` answer all arrive before anything has been
asked of Kin, so none of them starts a daemon.

Before that first call, every bind the server performs attaches to a daemon that
is already serving the repository and starts none. A session opened beside a
warm daemon is therefore exactly as fast as it ever was; a session opened on a
repository nothing is serving stays at the cost of the stdio process until it is
used.

The reason is what a daemon start costs. Starting one opens the store and
schedules the background embedding pass, which on a repository of any size is
minutes of CPU or GPU and gigabytes of resident memory. Measured on 2026-09-02
against a 657.8 KiB fixture store, the old behavior reached 1.80 GiB resident and
99 percent of a core sixty seconds after a handshake, in a session that made no
Kin call at all.

Most of that memory is the embedding model, not the store. The pass loads the
model the first time it embeds and keeps it until the daemon exits. The default
model is 523 MiB of weights, held in memory at that size, and each batch adds
working memory while it runs. With the model on the CPU the daemon holds one
copy, and with it on a GPU the daemon builds a second, CPU copy when it hands a
batch to the CPU. Measured on 2026-09-22 against a snapshot of a 708-file Go
repository, with the model on the CPU, the daemon's physical footprint peaked at
0.74 GiB with embedding off and at 2.56 GiB in the first two minutes of the
pass. An idle daemon's resident size can later read far lower, because the
operating system compresses or pages out memory nothing is touching. The model
is still held.

The first call on a cold repository still pays for the start it needs. When the
daemon is not ready inside the server's brief grace, that call is answered with
the honest still-starting report naming the phase and the elapsed seconds, and
the remedy is to retry rather than to restart anything. `KIN_DAEMON_AUTO_EMBED=0`
remains the way to keep a daemon from embedding at all once it is running.

## When daemons exit

A repository daemon is started by the first client that needs it: a `kin`
command, or `kin mcp start` on its first tool call. It detaches from that
client, so it outlives it by design. The supervisor is started by the first
`kin` command that needs routing, and it never starts repository daemons
itself.

A repository daemon exits on its own once all of these hold:

- nothing is attached: no client session and no event subscriber;
- nothing would be lost: no request in flight, no publication being prepared,
  no first scan, reconciliation, embedding or language-server enrichment still
  running;
- nothing has used it for its idle window: 30 minutes after an AI client
  started it, between one and thirty minutes after a command did (ten times
  what the store's last open took), set by `KIN_DAEMON_IDLE_TIMEOUT_SECS`.

It flushes an unwritten graph before it goes, and stays up if that flush
fails. The supervisor exits a minute after its last repository daemon has.

The supervisor reads every repository daemon's `/health` every 15 seconds to
decide whether one has wedged. Those reads send a watchdog header and do not
count as use; before they did, no repository daemon idled out while a
supervisor ran, and no supervisor idled out while it had a repository daemon.

`kin daemon stop --all --when-unused` asks each daemon under this `KIN_HOME`
to exit as soon as nothing needs it. It keeps every gate above and drops only
the idle wait, so a daemon an editor is still using is left running and
named, and exits by itself once it is free. `kin-mcp --stop` runs it for a
registry install. Plain `kin daemon stop --all` stops everything now.

## Supervisor scope: what `KIN_HOME` does and does not bound

Kin runs one worker daemon per repository and one **supervisor** per machine.
The supervisor directory hangs off the registry path, which resolves from the
real home directory (or an explicit `KIN_REGISTRY_PATH`). It is deliberately
**not** derived from `KIN_HOME`.

That split is the contract:

- `KIN_HOME` (and its `KIN_DIR` alias) bounds the managed install root and store
  state.
- The supervisor layer is machine-wide by design. One supervisor per box keeps
  the number of inference-capable daemons bounded; a supervisor per pinned home
  would multiply them.
- Consequently a single supervisor legitimately holds daemons launched under
  several managed homes, and a session that pins `KIN_HOME` still registers into
  the machine's supervisor.

Because that surprises operators who read a pinned `KIN_HOME` as full isolation,
the surfaces above it partition by home rather than hiding the seam:

- Every daemon records the managed home it was launched under at registration.
  A daemon that reports none stays **unrecorded**, which is a distinct answer
  from matching or not matching; the supervisor never fills the gap from its own
  environment, which describes a different process.
- `kin daemon status` and `kin registry daemons` label each daemon with its home
  and whether that is the caller's, and state that the supervisor is
  machine-wide.
- `kin daemon stop --all` stops only daemons under the caller's `KIN_HOME`. It
  names what it skipped, and it leaves the shared supervisor running while any
  skipped daemon still depends on it.
- `kin daemon stop --all --machine` performs the machine-wide sweep and names
  the daemons from other homes it is taking down.
- Full uninstall stays machine-wide with no opt-out, because it removes the
  binaries every daemon on the box is running from.

An unrecorded home is excluded from a scoped sweep rather than assumed to match.
Failing to stop a daemon is visible and recoverable; stopping a daemon that
belongs to another session is neither.

### What this means for supervisor-level policies

Supervisor-level behavior still sees every registered daemon regardless of home:
the rogue-daemon reaper, idle accounting, and the stop-before-update preflight
census all operate on the machine-wide registry. That is what an install-wide
update requires, since it must account for every process running the binaries it
replaces. Expect those paths to act on daemons from other managed homes, and use
the scoped `kin daemon stop --all` when you mean only your own.

## Recovery reference

| Situation | What Kin does | Your move |
| --- | --- | --- |
| Command/agent succeeded | reconcile + clean up | nothing |
| Command/agent failed | keep workspace, print recovery | fix and rerun, or `kin reconcile <id>`, or `rm -rf` |
| Reconcile failed | keep workspace, print recovery | `kin reconcile <id>` after resolving, then clean up |
| Ran with `--keep` | keep workspace, defer reconcile | `kin reconcile <id>` when ready |
| Ran with `--discard` | delete workspace, no reconcile | nothing |
| Not sure what's pending | n/a | `kin doctor` lists leftover session workspaces |

### Reconcile against newer authority

When a workspace is materialized, Kin records the exact repository authority
it started from. Reconcile admits only the edits the workspace itself made
relative to that base, and only onto that same authority. The repository can
move on while a workspace is open, through another writer or through the
session's own Kin changes, such as a `--semantic-only` agent's `kin_mutate`:

- **An unchanged workspace closes without publishing anything.** Kin first
  proves, from the repository's recorded operation history, that the base the
  workspace names is authentic, and then removes the workspace. Nothing is
  committed for it, and its summary reports the repository's current
  generations, with no changes.
- **A changed workspace is refused and kept.** Kin does not merge a workspace's
  edits into newer authority, so nothing is admitted and newer changes are
  never overwritten. Re-run the work in a fresh session, or discard the
  workspace.
- **An interrupted reconcile of the same session** is recovered from the
  receipt its own operation recorded.

A workspace whose recorded base is missing, altered, or not part of the
repository's recorded history is refused, whether or not it changed.
