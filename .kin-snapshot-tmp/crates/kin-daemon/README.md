# kin-daemon

Background daemon service for Kin.

## Overview

kin-daemon owns the graph lifecycle, runs the file watcher and reconciliation loop, and exposes an HTTP API (`:4219`) for the CLI, MCP server, and UI. It coordinates concurrent sessions via the `SessionCoordinator` for intent arbitration, ensuring multiple AI agents or human editors don't conflict on the same entities.

## Key Types

- **`DaemonConfig`** -- Configuration for the daemon (port, reconcile interval, etc.).
- **`DaemonState`** / **`DaemonEvent`** -- Runtime state and event stream for the daemon lifecycle.
- **`SessionCoordinator`** -- Session registry for multi-agent intent arbitration.
- **`LoopConfig`** -- Configuration for the reconciliation loop timing.
- **`ChangeType`** -- Enum for file change classifications.

## Feature Flags

- `gcs` -- Enables GCS `StorageBackend` for cloud deployment (forwards to `kin-db/gcs`).

## Usage

```bash
# Start the daemon (typically launched by kin CLI)
kin daemon start

# The daemon exposes an HTTP API at :4219
curl http://localhost:4219/health
```

## Modules

| Module | Role |
|--------|------|
| `daemon` | Main orchestrator: startup, shutdown, graph lifecycle |
| `api` | Axum HTTP API handlers |
| `loop_runner` | File watch + reconcile loop |
| `session_registry` | Multi-session coordination and intent locks |
| `state` | Runtime state and event stream |

## Testing

```bash
cargo test -p kin-daemon
```

## License

Apache-2.0 -- Copyright 2026 Firelock, LLC
