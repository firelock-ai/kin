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

2. Inside the WSL2 Linux shell, install Kin the same way you would on Linux:

   ```sh
   curl -fsSL https://get.kinlab.dev/install | sh
   ```

3. Work on your repositories from inside the WSL2 filesystem (e.g.
   `~/projects/...`). Initialize and use Kin as usual:

   ```sh
   kin init
   kin status
   ```

   For best performance, keep repositories on the WSL2 ext4 filesystem rather
   than under `/mnt/c`; cross-OS filesystem access through `/mnt/*` is
   noticeably slower and does not support the projection layer cleanly.

## Native Windows binary (limited)

If you only need the core CLI and cannot use WSL2, the release page publishes a
native `kin-windows-x86_64.zip`. It is **vector-free** and does not provide the
transparent filesystem projection. Treat it as experimental; WSL2 remains the
recommended path.
