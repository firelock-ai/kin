# Kin MCPB candidate

Kin's MCPB is a local stdio extension for one Kin workspace. It keeps the workspace
selection in the extension settings and starts the matching published Kin MCP launcher
from that directory.

## Build

Run this from a public Kin checkout:

```sh
bash scripts/mcpb/build.sh
```

The script reads the matching versions from `packages/kin-mcp/package.json` and
`packages/kin/package.json`, writes that version into a staging manifest, and pins the
bundle launcher to `@kinlab/kin-mcp@<that-version>`. It refuses package-version drift.
The source `manifest.json` is a `0.0.0` template and is not itself a distributable
bundle manifest.

The output defaults to `scripts/mcpb/kin.mcpb`; set `KIN_MCPB_OUTPUT` to choose a
separate path. The bundle includes `release-identity.json`, which records the pinned npm
launcher and native-release tag. At first start the launcher downloads and verifies the
matching public Kin release archive, then caches it locally.

This is a candidate builder only. It does not upload a bundle, create a GitHub release
asset, or prove that the selected npm package and native release have published. Verify
those facts separately before representing an artifact as released.

## Regression check

Run the scaffold regression without contacting npm or the MCPB registry:

```sh
node --test scripts/mcpb/test-build.mjs
```

It builds a temporary minimal fixture through a controlled `npx`, checks the packed
manifest and the staged launcher's exact `npx -y @kinlab/kin-mcp@<version>` invocation,
and proves package-version drift fails before packing. `npm test --prefix
packages/kin-mcp` includes the same check in CI.

## Setup

Choose a Kin workspace in the extension settings. Initialize it with `kin init .` before
graph tool calls. The Node 20 or newer runtime and first-start network requirement remain
part of this wrapper-based bundle. For a fully self-contained platform-specific bundle,
embed a verified published release archive instead.

## Privacy and support

- https://kinlab.ai/privacy
- https://github.com/firelock-ai/kin/blob/main/docs/security/what-leaves-the-machine.md
- https://github.com/firelock-ai/kin/issues
