# @kinlab/kin

The canonical npm install surface for [Kin](https://github.com/firelock-ai/kin), the
system of record for AI-written software.

```sh
npm install -g @kinlab/kin
kin --version
kin setup --intent agent
```

or zero-install:

```sh
npx -y @kinlab/kin --version
npx -y @kinlab/kin setup --intent agent --no-interactive
```

Native Windows x86_64 support is early. Repository admission works: `kin init` imports a Git repository and publishes graph authority, and graph, lexical, and daemon-backed queries answer natively. Transparent filesystem projection is not shipped on Windows, and the end-to-end install proof does not yet cover MCP or review workflows there, so WSL2 remains the recommended path for the full Kin experience.
No native Windows ARM64 archive is published. An x64 Node process under Windows
emulation can provision the x86_64 archive; use WSL2 for the repository workflow
documented below.

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
reliably inherit your shell `PATH`. Codex and Antigravity bindings additionally require
`"--repo", "/absolute/path/to/repository"` at the end of the argument vector; an Antigravity
workspace entry also uses that path as `cwd`.

`@kinlab/kin-mcp` remains published for existing configurations; new setups should use
this package.
