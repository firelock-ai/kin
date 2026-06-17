# Windows: use WSL2

Kin's first-class platforms are **Linux and macOS**. On Windows, the supported
path is **WSL2 (Windows Subsystem for Linux 2)** running a Linux distribution.
Install and run Kin inside WSL2 exactly as you would on native Linux.

## Why WSL2 and not native Windows

Two parts of Kin are built around Unix runtime mechanics:

- **Transparent filesystem projection (`kin-vfs`)** works by intercepting libc
  calls via `LD_PRELOAD` (Linux) / `DYLD_INSERT_LIBRARIES` (macOS). That
  interception model does not exist on native Windows, so the "any tool sees
  graph-backed files as normal files" experience is Linux/macOS only.
- **Semantic vector search** ships enabled on Linux/macOS. The native Windows
  CLI artifact (`kin-windows-x86_64.zip`) is built **vector-free**
  (`--no-default-features`) and is intended as a limited convenience binary, not
  the full product surface.

Running under WSL2 gives you the complete, vector-enabled Kin with working
filesystem projection and the same behavior the project tests and benchmarks
against.

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

## Native Windows binary (limited)

If you only need the core CLI and cannot use WSL2, install with PowerShell:

```powershell
irm https://get.kinlab.dev/install.ps1 | iex
```

The installer prints the limitation up front, verifies the download's SHA-256
checksum, and still requires `kin-daemon` (it aborts on a daemon-less archive).
The native `kin-windows-x86_64.zip` it installs is **vector-free** (semantic
search disabled) and does **not** provide the transparent filesystem projection:
projection relies on Unix library injection (`LD_PRELOAD` /
`DYLD_INSERT_LIBRARIES`), which native Windows does not offer. Windows projection
is planned via ProjFS — an optional feature started by an explicit daemon init,
not injected by the shell hook — so on native Windows the `vfs_projection` health
check reports **n/a** rather than ok. Treat the native binary as experimental;
WSL2 remains the recommended path.
