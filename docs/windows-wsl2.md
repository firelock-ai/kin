# Windows: use WSL2

Kin repository workflows are fully supported on **Linux and macOS**. Native
Windows admits repositories, but does not yet carry the whole workflow.

Native Windows x86_64 support is early. Repository admission works: `kin init` imports a Git repository and publishes graph authority, and graph, lexical, and daemon-backed queries answer natively. Transparent filesystem projection is not shipped on Windows, and the end-to-end install proof does not yet cover MCP or review workflows there, so WSL2 remains the recommended path for the full Kin experience.

Use **WSL2 (Windows Subsystem for Linux 2)** running a Linux distribution for
the supported Windows-hosted experience.

## Why WSL2 and not native Windows

Two parts of Kin are built around Unix runtime mechanics:

- **Transparent filesystem projection (`kin-vfs`)** works by intercepting libc
  calls via `LD_PRELOAD` (Linux) / `DYLD_INSERT_LIBRARIES` (macOS). That
  interception model does not exist on native Windows, so the "any tool sees
  graph-backed files as normal files" experience is Linux/macOS only.
- **MCP and review workflows** are not yet covered end to end on native Windows
  by the public install proof, so WSL2 is the supported path for connecting
  agents and running review. Repository admission itself is not the blocker:
  `kin init` admits a Git repository on native Windows and publishes graph
  authority, and graph, lexical, and daemon-backed queries answer from it.
- **Semantic vector search** ships enabled on every published platform. The
  native Windows CLI artifact (`kin-windows-x86_64.zip`, published as
  `kin-windows-x86_64.tar.gz` as well) is built with the same
  default feature set as Linux and macOS, so semantic search and embedding are
  compiled in rather than stripped. Embedding runs on the portable CPU backend;
  the Metal GPU backend is macOS-only and is not part of any Windows build.

Running under WSL2 gives you the complete Kin with working filesystem
projection and the same behavior the project tests and benchmarks against.

## Setup

1. Install WSL2 with a Linux distribution (Ubuntu is a good default). From an
   elevated PowerShell:

   ```powershell
   wsl --install -d Ubuntu
   ```

   Reboot if prompted, then open the **Ubuntu** shell to finish first-time
   user setup.

2. Inside the WSL2 Linux shell, install Kin the same way you would on Linux.
   This is the **same one-path flow** documented in the
   [quickstart](./quickstart.md):

   ```sh
   curl -fsSL https://get.kinlab.dev/install | sh
   ```

   The installer launches the `kin setup` guided wizard for you. Answer its
   "What do you want Kin for?" prompt (the **AI agents** intent is the default),
   then verify with `kin setup status`. Inside WSL2 the VFS projection check is
   supported, unlike native Windows.

3. Work on your repositories from inside the WSL2 filesystem (e.g.
   `~/projects/...`). Initialize, embed, and use Kin as usual:

   ```sh
   kin init
   kin embed     # build the vector index for semantic search / kin locate
   kin status
   ```

   For best performance, keep repositories on the WSL2 ext4 filesystem rather
   than under `/mnt/c`; cross-OS filesystem access through `/mnt/*` is
   noticeably slower and does not support the projection layer cleanly.

## Native Windows binary

If you only need the core CLI and cannot use WSL2, install with PowerShell:

```powershell
irm https://get.kinlab.dev/install.ps1 | iex
```

The installer prints the current support boundary before downloading, verifies
the download's SHA-256 checksum, and installs the x86_64 CLI release shape. The
archive carries semantic vector search but does not provide transparent
filesystem projection, so `kin setup status` reports VFS readiness as
unsupported on native Windows. Health checks run outside a Kin repository
report repository, daemon, and semantic-query readiness as missing because they
are repo-scoped; run them from inside an admitted repository.

Git for Windows sets `core.autocrlf=true` in its system config, which rewrites
line endings on checkout. `kin init` admits only a worktree whose bytes match
the committed tree, so it refuses a repository cloned that way with `tracked
blob ... bytes differ from the committed tree`. Run `git config --global
core.autocrlf false` and clone again.

No native Windows ARM64 archive is published. Use WSL2, or run x64 PowerShell
under Windows x64 emulation to install the x86_64 archive for repository-free
diagnostics. WSL2 remains required for usable Kin repository workflows.
