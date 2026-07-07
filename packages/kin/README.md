# @kinlab/kin

The canonical npm install surface for [Kin](https://github.com/firelock-ai/kin), the
semantic system of record for software work.

```sh
npm install -g @kinlab/kin
kin --version
```

or zero-install:

```sh
npx -y @kinlab/kin --version
```

## What it does

`@kinlab/kin` ships two thin launchers, not a JavaScript reimplementation:

- **`kin`** — provisions the managed native `kin` + `kin-daemon` release for your
  platform on first run (downloaded from the matching GitHub release, verified against
  its published SHA-256), installs it under `~/.kin/bin`, then passes every invocation
  straight through to the real binary and mirrors its exit.
- **`kin-mcp`** — compatibility entrypoint that starts Kin's MCP server
  (`kin mcp start`). MCP is one included mode of Kin, not a separate product.

The launcher and the shell installer (`scripts/install.sh`) share the same install
contract (`$KIN_HOME`, default `~/.kin`): either lane satisfies the other, and neither
silently downgrades an install the other made.

## Version pinning

Every `@kinlab/kin` release pins one managed `kin` release — its own package version.
Each run compares that pin against whatever is already installed at `$KIN_HOME`:

- **installed is older than the pin** — upgrades it automatically (a one-line notice
  on stderr, no prompt, no opt-in required).
- **installed is newer than the pin** — refuses the downgrade and exits with an
  actionable error instead of running anything; re-run with `KIN_LAUNCHER_ADOPT=1` to
  force it on purpose (e.g. deliberately pinning to an older release).
- **installed matches the pin** — runs it as-is.

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

Any MCP client can use the included server:

```json
{ "command": "npx", "args": ["-y", "@kinlab/kin", "mcp", "start"] }
```

`@kinlab/kin-mcp` remains published for existing configurations; new setups should use
this package.
