# Windows: use WSL2

Kin repository workflows are supported on **Linux and macOS**. Native Windows
currently has no repository-admission path.

Native Windows x86_64 can install and run repository-free CLI diagnostics, but repository admission is currently unavailable: kin init fails closed, so graph, lexical, daemon, repository setup, MCP, and review workflows are unsupported. Use WSL2 for usable Kin repositories.

Use **WSL2 (Windows Subsystem for Linux 2)** running a Linux distribution for
the supported Windows-hosted experience.

## Why WSL2 and not native Windows

Two parts of Kin are built around Unix runtime mechanics:

- **Transparent filesystem projection (`kin-vfs`)** works by intercepting libc
  calls via `LD_PRELOAD` (Linux) / `DYLD_INSERT_LIBRARIES` (macOS). That
  interception model does not exist on native Windows, so the "any tool sees
  graph-backed files as normal files" experience is Linux/macOS only.
- **Repository admission** currently fails closed on native Windows before a
  `.kin` repository is published. Without an admitted repository, graph,
  lexical, daemon/query, repository setup, MCP, and review flows have no
  supported native-Windows starting point.
- **Semantic vector search** ships enabled on every published platform. The
  native Windows CLI artifact (`kin-windows-x86_64.zip`) is built with the same
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

2. Inside the WSL2 Linux shell, install Kin the same way you would on Linux —
   this is the **same one-path flow** documented in the
   [quickstart](./quickstart.md):

   ```sh
   curl -fsSL https://get.kinlab.dev/install | sh
   ```

   The installer launches the `kin setup` guided wizard for you. Answer its
   "What do you want Kin for?" prompt (the **AI agents** intent is the default),
   then verify with `kin setup status` — inside WSL2 the VFS projection check is
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

## Native Windows binary (repository-free only)

If you only need the core CLI and cannot use WSL2, install with PowerShell:

```powershell
irm https://get.kinlab.dev/install.ps1 | iex
```

The installer prints the admission limitation before downloading, verifies the
download's SHA-256 checksum, and installs the x86_64 CLI release shape. It does
not run repository setup or claim a usable native repository. The archive
carries semantic vector search but does not provide transparent filesystem
projection; native Windows health reports repository, daemon, semantic-query,
and VFS readiness as missing or unsupported.

No native Windows ARM64 archive is published. Use WSL2, or run x64 PowerShell
under Windows x64 emulation to install the x86_64 archive for repository-free
diagnostics. WSL2 remains required for usable Kin repository workflows.
