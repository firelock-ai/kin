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

## Environment

| Variable | Effect |
| --- | --- |
| `KIN_HOME` | Root of the managed install (default `~/.kin`). |
| `KIN_MANAGED_BIN` | Explicit path to a `kin` binary; disables provisioning entirely. |
| `KIN_NO_PROVISION=1` | Never touch the network; fail loud if no binary is present. |
| `KIN_LAUNCHER_ADOPT=1` | Allow re-provisioning over a version-skewed non-npm install. |

## MCP setup

Any MCP client can use the included server:

```json
{ "command": "npx", "args": ["-y", "@kinlab/kin", "mcp", "start"] }
```

`@kinlab/kin-mcp` remains published for existing configurations; new setups should use
this package.
