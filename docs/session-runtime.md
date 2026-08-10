# Session Runtime Acceptance Contract

> **Current development status:** repository-v6 exact session materialization is
> implemented at the daemon boundary, including non-code/binary artifacts,
> executable bits, symlinks, exact source-CAS reads, scoped artifact selection,
> and a durable three-way-reconcile base record. `kin exec`, `kin shell`,
> `kin open`, `kin with`, and `kin reconcile` are exposed: the daemon
> materializes the projection, the process runs inside it, and a clean exit
> admits the observed delta through the reconcile boundary. Docker and Compose
> are represented and materializable, but are **not yet claimed as end-to-end
> dogfood-ready through these launchers**. Check `kin capabilities --json` for
> live availability.
>
> Parts of the remainder of this document are still the contract these commands
> must satisfy rather than a description of shipped behavior. Where the two
> disagree, `kin capabilities --json` and the code are authoritative.

Two exact-tree cases still fail closed at the physical session boundary:
byte-exact non-UTF-8 repository paths (retained in repository authority and Git
export, but not yet projected by the UTF-8 workspace boundary) and gitlinks
(retained exactly as imported targets, but awaiting the graph-native
cross-repository model and recursive materialization).

Kin's session runtime is the venv-like execution contract for a Kin repository.
You, or an agent, run normal project commands such as `npm test`, `make`,
`docker compose config`, an editor, or a coding assistant, without knowing which
files are graph-owned, projected, or materialized. Kin materializes graph truth
into a **session workspace**, the tool runs there like in any ordinary checkout,
and Kin reconciles the results back into the semantic graph when the session
ends.

Three surfaces share this contract:

| Surface | What it is | When to use it |
| --- | --- | --- |
| `kin exec -- <cmd>` | One-shot command in a fresh session workspace | `kin exec -- npm test`, `kin exec -- make build` |
| `kin shell` | Interactive shell inside a session workspace | exploratory work, multiple commands in one session |
| `kin with <assistant> -- <task>` | AI assistant launched inside a session workspace | agent work that should start Kin-native |
| `kin open <code\|cursor>` | Supported editor launched over a retained session projection | human editing sessions |

`kin setup` is **not** part of this contract: it is one-time configuration that
installs Kin's MCP server entry into your AI clients (Claude Code, Cursor,
Codex, Gemini, Windsurf) and your shell hook. In short:

- **`kin setup`**: configure clients once (MCP install, shell hook).
- **`kin exec` / `kin shell`**: run ordinary commands through a session workspace.
- **`kin with`**: launch an assistant inside a
  session workspace with session-coherent MCP.

## The execution contract

1. **Materialize.** The repo daemon materializes graph-owned truth into
   `.kin/runs/session-<id>/`. This is a real directory containing real files,
   so any tool works unchanged. Scoped materialization (`--scope file:<path>`,
   `--scope entity:<name>`) materializes a subset; `entity:` scopes are
   resolved against the graph and fail loudly if the entity does not exist.
2. **Run.** The command executes locally in that workspace (never through the
   daemon), with `KIN_SESSION`, `KIN_SESSION_ID`, and `KIN_SESSION_DIR` set.
   Every session launcher pins the verified `KIN_DAEMON_URL`,
   `KIN_DAEMON_AUTH_TOKEN` (when configured), and `KIN_REPO_ID` so nested
   Kin/MCP calls bind to the same repo and session. Inherited Git, Compose,
   projection, and repository-path authority is removed before the child
   starts.
3. **Reconcile.** On success, Kin reconciles the workspace's own changes into
   the graph as a change-set replay against the base state it was materialized
   from, not a whole-tree overwrite, and then removes the workspace.
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

### Generated files and tool output

Reconcile skips generated and vendored directories by policy:
`node_modules/`, `target/`, `__pycache__/`, `vendor/`, `.next/`, `dist/`,
`build/`, `out/`, and hidden directories. So:

- `kin exec -- npm install` reconciles `package-lock.json` but never imports
  `node_modules/` into the graph.
- `kin exec -- make build` reconciles source changes but not `build/` output.

Anything outside the skip list that the tool writes **is** treated as a real
change and reconciled on success. Use `--discard` for runs whose outputs you
do not want, or `--keep` to inspect before reconciling.

### External tools and scoped execution

Some tools read far more than the files you name: package managers resolve
manifests, lockfiles, and workspaces; `make` follows arbitrary prerequisites;
Docker sends a whole build context to the daemon. Running these in a partially
materialized workspace produces confusing failures, so Kin detects them and
widens scoped execution to a **full** workspace under the default
(`workspace`) execution policy:

- Docker/Podman: `docker compose`, `docker build`, `docker buildx bake`,
  `docker-compose`, `podman …`
- Make: `make`, `gmake`
- Package managers: `npm`, `npx`, `pnpm`, `pnpx`, `yarn`, `bun`, `bunx`,
  `corepack`

Under the `strict` policy Kin refuses instead of widening, and tells you to
drop `--scope` or switch policy. Either way, the decision is printed, so scoped
materialization never silently surprises you.

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
session workspace:

- cwd is the session workspace root, so the agent's shell commands and file
  edits operate on materialized graph truth.
- The environment carries the session identity and repo binding:
  `KIN_SESSION` / `KIN_SESSION_ID` (session UUID), `KIN_SESSION_DIR`
  (workspace root), `KIN_DAEMON_URL` (this repo's daemon), and `KIN_REPO_ID`
  (repo identity).
- Native-mode PATH shims target the session workspace, so `cat`/`rg`/`find`
  from the agent resolve against the files it is editing.
- On a clean exit the session reconciles into the graph and the workspace is
  removed; on failure the workspace is preserved with recovery commands, same
  as `kin exec`.

**MCP session coherence.** The MCP server ships inside the `kin` binary
(`kin mcp start`) and binds per invocation:

1. If `KIN_DAEMON_URL` is set, which a session launch guarantees, the MCP
   server forwards every graph tool call to exactly that daemon. No cwd
   guessing, no stale global config.
2. Otherwise it discovers the repository by walking up from the working
   directory. Because agents launched with `kin with` start inside
   `.kin/runs/session-<id>`, the walk lands on the same repository's `.kin/`.
3. Each forwarded tool call carries the session id (from `KIN_SESSION_ID`) as
   the `X-Kin-Session` header, so the daemon can serve session-scoped graph
   state where it applies and the live HEAD graph otherwise.

Semantic answers stay graph-backed throughout: `semantic_locate`,
`get_context_pack`, `trace_data_flow`, and the other MCP tools are answered by
the daemon's graph authority, never by grepping the materialized workspace.
The workspace is an execution surface, not a search authority.

`kin shell` uses the same session identity and daemon binding, so any agent or
MCP client you launch manually from that shell inherits the session-coherent
environment.

Each launcher registers that session ID with the daemon before starting the
child, heartbeats it for the child lifetime, and ends it after closeout. This
keeps the daemon alive without tying it to the short-lived launcher PID.

`kin open` accepts VS Code (`code`) and Cursor (`cursor`) only. Both are invoked
with their blocking `--wait` lifecycle so Kin never reconciles or deletes the
workspace while the editor can still be writing to it.

The daemon has no command-execution endpoint. `kin exec` always launches the
requested argv locally inside the materialized workspace; shell evaluation is
available only through the explicit `kin exec --shell` mode. Shell mode accepts
one script argument, so quote the complete script:
`kin exec --shell -- 'printf "%s\n" "$KIN_REPO_ID"'`.

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

## Recovery reference

| Situation | What Kin does | Your move |
| --- | --- | --- |
| Command/agent succeeded | reconcile + clean up | nothing |
| Command/agent failed | keep workspace, print recovery | fix and rerun, or `kin reconcile <id>`, or `rm -rf` |
| Reconcile failed | keep workspace, print recovery | `kin reconcile <id>` after resolving, then clean up |
| Ran with `--keep` | keep workspace, defer reconcile | `kin reconcile <id>` when ready |
| Ran with `--discard` | delete workspace, no reconcile | nothing |
| Not sure what's pending | n/a | `kin doctor` lists leftover session workspaces |

One reconcile semantic to know: reconcile replays the **workspace's own
change-set**, not a whole-tree state sync. When a workspace is materialized Kin
records the base graph version it started from; at reconcile it applies only the
edits the workspace itself made relative to that base and leaves files the
workspace never touched alone, even if the source advanced in the meantime. So a
kept workspace reconciled late does **not** revert source changes made since it
was materialized, and does not delete files created in the source afterward.

If the workspace and the source both changed the same file, reconcile merges
them when they agree. When they do not, it **fails loud**, naming the
conflicting files and exiting non-zero, rather than overwriting newer source
truth. The workspace is preserved on conflict so you can resolve it by hand or
discard it. Workspaces materialized before base tracking carry no recorded base;
reconcile refuses them unless they are already identical to the source, and asks
you to re-run the work in a fresh session or discard the workspace.
