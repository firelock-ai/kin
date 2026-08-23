# @kinlab/kin

The canonical npm install surface for [Kin](https://github.com/firelock-ai/kin), the
system of record for AI-written software.

Install it without root, without `sudo`, and without a writable global npm prefix. This
is the default path because it is the one that works everywhere, including the container
and locked-down developer box where the global install below is refused outright:

```sh
npx -y @kinlab/kin --version
export PATH="$HOME/.kin/bin:$PATH"
kin --version
```

The first line downloads the native `kin` and `kin-daemon` for your platform into
`~/.kin/bin`, verified against their published SHA-256. That install is persistent: `npx`
provisions the same managed binaries the global install does, so the second and third
lines are reading a real binary on disk, not re-downloading anything. `kin setup` writes
the `PATH` line into your shell profile, so you type the `export` once:

```sh
kin setup --intent agent
```

If your global npm prefix is writable, or you are root, `npm install -g` puts the
launcher on `PATH` for you and is the shorter route:

```sh
npm install -g @kinlab/kin
kin --version
kin setup --intent agent
```

Native Windows x86_64 support is early. Repository admission works: `kin init` imports a Git repository and publishes graph authority, and graph, lexical, and daemon-backed queries answer natively. Transparent filesystem projection is not shipped on Windows, and the end-to-end install proof does not yet cover MCP or review workflows there, so WSL2 remains the recommended path for the full Kin experience.
No native Windows ARM64 archive is published. An x64 Node process under Windows
emulation can provision the x86_64 archive; use WSL2 for the repository workflow
documented below.

## If the global install is refused

On a machine whose global npm prefix is root-owned, and where you are not root and have no
`sudo`, `npm install -g` fails before Kin runs. This is why the install at the top of this
page leads with `npx`, which never touches that prefix:

```
npm error code EACCES
npm error syscall mkdir
npm error path /usr/local/lib/node_modules/@kinlab
npm error Error: EACCES: permission denied, mkdir '/usr/local/lib/node_modules/@kinlab'
```

npm fails here before it unpacks anything, so no Kin code has run and nothing in this
package can catch it or print a fix. Containers whose default user is not root are the
common case. Two ways out. The `npx` path at the top of this page needs no writable prefix
and installs the same native binaries under `~/.kin/bin`, which is why it is the default
rather than a fallback. Or move the npm prefix somewhere you own, and put it on your
`PATH`:

```sh
npm config set prefix ~/.npm-global
export PATH="$HOME/.npm-global/bin:$PATH"   # add this to your shell profile too
npm install -g @kinlab/kin
```

A user prefix is read by your interactive shell and by nothing else. Scripts, CI steps,
`docker exec`, and agent clients do not inherit it, so register `kin` with those by its
absolute path (`$(npm prefix -g)/bin/kin`, or `~/.kin/bin/kin` after `kin setup`) rather
than by name. Installing as root does not fix that on an image where every user shares one
`HOME`: root's npm reads the same `.npmrc`, reinstalls into the user prefix, and reports
success. Pass `npm install -g --prefix /usr/local @kinlab/kin` when you want the system
prefix.

## What it does

`@kinlab/kin` ships two thin launchers, not a JavaScript reimplementation:

- **`kin`**: provisions the managed native `kin` + `kin-daemon` release for your
  platform on first run (downloaded from the matching GitHub release, verified against
  its published SHA-256), installs it under `~/.kin/bin`, then passes every invocation
  straight through to the real binary and mirrors its exit.
- **`kin-mcp`**: compatibility entrypoint that starts Kin's MCP server
  (`kin mcp start`). MCP is one included mode of Kin, not a separate product.

The launcher and the shell installer (`scripts/install.sh`) share the same install
contract (`$KIN_HOME`, default `~/.kin`): either lane satisfies the other, and neither
silently downgrades an install the other made.

On macOS, Linux, or WSL2, run `kin setup --intent agent` after provisioning. Setup writes the Kin MCP server into
detected AI clients with the `agent-default` tool profile, adds the managed bin directory
to your shell profile, installs the shell/session hook, and records the install ledger used
by `kin setup status`, `kin doctor --fix`, and `kin setup uninstall`.

## Version pinning

Every `@kinlab/kin` release pins one managed `kin` release: its own package version.
Each run compares that pin against whatever is already installed at `$KIN_HOME`:

- **installed is older than the pin**: upgrades it automatically (a one-line notice
  on stderr, no prompt, no opt-in required).
- **installed is newer than the pin**: refuses the downgrade and exits with an
  actionable error instead of running anything; re-run with `KIN_LAUNCHER_ADOPT=1` to
  force it on purpose (e.g. deliberately pinning to an older release).
- **installed matches the pin**: runs it as-is.

`KIN_LAUNCHER_ADOPT=1` always forces a fresh provision of the pinned release, even when
the installed version already matches.

## Environment

| Variable | Effect |
| --- | --- |
| `KIN_HOME` | Root of the managed install (default `~/.kin`). |
| `KIN_MANAGED_BIN` | Explicit path to a `kin` binary; disables provisioning entirely. |
| `KIN_NO_PROVISION=1` | Never touch the network; fail loud if no binary is present. |
| `KIN_LAUNCHER_ADOPT=1` | Force re-provisioning to the pinned release, including over a newer install that would otherwise be refused as a downgrade. |

## MCP setup

`kin setup --intent agent` is the preferred MCP setup path. It writes an absolute path to
the managed native `kin` binary, so agents do not depend on inheriting your shell `PATH`.

Any MCP client can also use the included server manually:

```json
{
  "command": "npx",
  "args": ["-y", "@kinlab/kin", "mcp", "start"],
  "env": { "KIN_MCP_TOOL_PROFILE": "agent-default" }
}
```

`kin setup status` and `kin doctor` recognize this exact canonical wrapper topology instead
of flagging it for repair. Do not shorten `command` to a bare `kin`: agent clients do not
reliably inherit your shell `PATH`. Codex and Antigravity bindings also require
`"--repo", "/absolute/path/to/repository"` at the end of the argument vector; an Antigravity
workspace entry also uses that path as `cwd`.

`@kinlab/kin-mcp` remains published for existing configurations; new setups should use
this package.
