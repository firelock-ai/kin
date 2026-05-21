# ADR: Runtime Ownership Convergence

**Status:** Accepted
**Date:** 2026-03-26
**Authors:** Troy Fortin

## Context

Kin previously had three independent processes that accessed the graph:

1. **CLI** (`kin`) — Opened a fresh snapshot per command via `SnapshotManager::open()`.
2. **MCP server** (`kin mcp start`) — Loaded a snapshot once at startup and held it in memory.
3. **Daemon** (`kin daemon`) — Has the live graph with the reconciliation loop, session overlays, and the authoritative working copy.

This creates a **split-brain problem**:
- CLI commands see a potentially stale snapshot (another process may have committed).
- MCP sees a frozen graph from startup time.
- The daemon has the most current state but nobody consults it.
- The generation marker at `.kin/kindb/generation` (P2-2.7) exists but nothing reads it.

## Decision

**The daemon is THE authoritative runtime.** It owns the live graph, session state, overlays, and arbitrates all reads and writes.

### Read path

When the daemon is running, CLI and MCP read commands query the daemon's HTTP API (`http://127.0.0.1:4219`) instead of opening their own snapshots. This eliminates:
- Snapshot lock contention between CLI, MCP, and daemon
- Stale reads from frozen snapshots
- Memory waste from multiple processes loading the same graph

### Daemon-required product mode

Core graph-backed CLI and MCP product paths require daemon authority. They fail
when no daemon route is available instead of silently falling back to a local
snapshot.

### Exceptions

- `kin init` — Runs before any daemon exists; always direct.
- `kin commit` — Write operations remain direct for now with generation-based optimistic concurrency (CAS via `.kin/kindb/generation`).
- `kin daemon start` — The daemon itself opens the snapshot; it does not recurse.
- Explicit offline/test harnesses may still instantiate in-process graph handlers, but `kin mcp start` does not.

## Implications

### CLI
- New global `--offline` flag on the `Cli` struct.
- New `GraphAccess` enum: `Daemon(DaemonClient)` vs `Snapshot(Arc<InMemoryGraph>)`.
- Read commands (`search`, `status`, `trace`, etc.) use `open_graph()` which tries daemon first.
- Write commands (`commit`, `merge`, `checkout`) remain on the direct snapshot path for now.

### MCP
- `kin mcp start` is a transport shim over stdio.
- It does not load a graph snapshot.
- Every graph-backed MCP `tools/call` is forwarded to the repo daemon's `/mcp/tools/call` endpoint.
- Session and intent tools are forwarded to daemon session endpoints.

### kin-core
- New `DaemonClient` in `crates/kin-core/src/daemon_client.rs`.
- New error variants: `DaemonUnavailable`, `DaemonError`, `StaleSnapshot`.
- New `RuntimeMode` enum for diagnostics.

### Performance
- Daemon queries add one HTTP round-trip (~1ms loopback) vs direct mmap.
- Acceptable for interactive CLI; offset by eliminating snapshot open + lock acquisition (~10-50ms).
- Bulk operations (e.g., `kin search` returning thousands of entities) may need streaming or pagination in the future.

## Alternatives Considered

### Shared memory / mmap-based IPC
Higher performance but significantly more complex. The daemon already has an HTTP API; adding another IPC mechanism doubles the surface area.

### Unix domain socket
Lower overhead than TCP but not portable to Windows. HTTP over loopback is fast enough and already works cross-platform.

### gRPC
More structured than REST but adds a code generation dependency. The daemon API is small enough that JSON over HTTP is sufficient.

## Migration Path

1. **Phase 1:** CLI reads route through daemon-required access. MCP session handlers delegate to daemon.
2. **Phase 2:** CLI write commands (commit, merge) go through daemon for proper locking.
3. **Phase 3:** MCP entity queries route through daemon. MCP no longer loads its own snapshot. **Complete for `kin mcp start`.**
4. **Phase 4:** Remove remaining direct snapshot access from CLI/MCP except for explicit offline/test mode.
