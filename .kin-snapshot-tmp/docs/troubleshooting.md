# Kin Troubleshooting Guide

## Binary Hangs on Startup (even `kin --version`)

**First step: ALWAYS run `sample <pid>` (macOS) or `strace -p <pid>` (Linux).** The stack trace tells you exactly where it's blocked. Do not guess.

### dyld Deadlock After Binary Replacement

If you `cp` a new binary over `~/.kin/bin/kin` while old processes (including zombie MCP servers) have the original inode mapped, the new process's dynamic linker can deadlock.

**Symptoms:** 100% of samples in `_dyld_start`, zero output, process never reaches `main()`.

**Fix:**
```bash
rm -f ~/.kin/bin/kin
cp target/release/kin ~/.kin/bin/kin
```

**Prevention:** Always use `install -m 755` when replacing a running binary — it does atomic inode replacement.

## MCP Server Won't Start or Returns Empty Results

1. Check if `.kin/` exists: `ls -d .kin`
2. Check the auto-init guard — MCP only auto-inits in directories with `.git/`
3. Check the registry: `kin registry` lists all known repos
4. Check for zombie MCP processes:
   ```bash
   ps aux | grep "kin mcp" | grep -v grep
   ```
5. If zombies exist in `UE+` state, they may hold file locks — `kill -9` or reboot

## Cargo Build Is Slow or Uses Excessive Memory

1. Check for zombie processes: `ps aux | grep kin | grep -v grep`
2. Check swap usage: `sysctl vm.swapusage` (macOS) or `free -h` (Linux)
3. The workspace has 19 crates — parallel compilation can spike memory
4. Build a single crate to isolate: `cargo build -p kin-cli`
5. Reduce parallelism if needed:
   ```bash
   CARGO_BUILD_JOBS=4 cargo build
   ```

## Feature Flag Confusion

- `kin-cli` default features include `vector` — usearch HNSW is compiled by default, but candle/embeddings are NOT
- `kin-db` default features include `vector` and `embeddings` — but the workspace overrides with `default-features = false, features = ["vector"]`
- `.cargo/config.toml` patches git deps to local paths — local kin-db may resolve different features than CI
- To check what's actually compiled:
  ```bash
  cargo tree -p kin-cli -e features -f '{p} {f}' | grep kin-db
  ```

## Graph Lock Contention

`kin-db` uses `fs2::flock` for exclusive snapshot access. If the daemon or MCP server holds the lock, other `kin` commands will block.

**Diagnosis:**
```bash
lsof +D .kin/kindb/ 2>/dev/null | grep -i lock
```

**Key detail:** The daemon (`:4219`) and MCP server (stdio) are separate processes — both can hold locks simultaneously.

**Workaround:** Stop the daemon (`kin daemon stop`) before running manual commands that need write access.

## KinLab Won't Connect to Kin

1. Control plane needs `kin` binary in PATH or `KIN_BINARY_PATH` env var
2. It spawns `kin mcp start` as a subprocess — test the binary standalone first:
   ```bash
   kin --version
   kin status
   ```
3. Dev mode auto-detects sibling workspace — ensure `kin-ecosystem/kin` has `.kin/` initialized
4. Fallback: set `KIN_REPO_PATH` explicitly in `.env`

## VS Code Extension Issues

1. Check that the kin binary is accessible: open terminal in VS Code, run `kin --version`
2. Check the extension output channel: View > Output > select "Kin" from dropdown
3. If hover/definition/search return nothing, verify `.kin/` exists and has indexed entities:
   ```bash
   kin search "" --json | head -5
   ```
4. Reload the window after initializing a new repo (`Cmd+Shift+P` > "Developer: Reload Window")

## Common Error Messages

| Error | Cause | Fix |
|-------|-------|-----|
| `Binary not found` | kin not in PATH or `~/.kin/bin/` | Install kin or set `KIN_BINARY_PATH` |
| `Graph not initialized` | No `.kin/` directory | Run `kin init` in the project root |
| `Snapshot lock timeout` | Another process holds the graph lock | Stop daemon or kill zombie processes |
| `Parse error: invalid JSON` | Binary version mismatch | Rebuild: `cargo build -p kin-cli --release` |
| `Entity not found` | Index is stale | Run `kin index` to re-index |
