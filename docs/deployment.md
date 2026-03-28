# Kin Open-Core Deployment Guide

This document covers deployment and operations for the open-core Kin stack in
this repo. KinLab is a separate product surface above Kin and is intentionally
not built or orchestrated from the public Kin repo.

## Scope

This guide covers:

- `kin-daemon`
- Kin workspace storage under `.kin/`
- `kin-db` test and validation containers
- health checks, backup, restore, and troubleshooting for open-core services

This guide does not cover:

- KinLab control-plane or web deployment
- private full-stack compose files
- private cloud orchestration for hosted KinLab

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Rust | stable (1.82+) | `kin-daemon` and Kin binaries |
| Docker | 24+ | Container deployment and validation |
| Docker Compose | 2.20+ | Optional local orchestration for open-core services |

## Environment Variables

### `kin-daemon`

| Variable | Default | Description |
|----------|---------|-------------|
| `RUST_LOG` | `info` | Tracing filter level (`trace`, `debug`, `info`, `warn`, `error`) |

`kin-daemon` also accepts CLI flags:

- `--repo <path>`: path to the Kin workspace
- `--port <port>`: HTTP API port, default `4219`

## Local Setup

### 1. Build `kin-daemon`

```bash
cd kin
cargo build --release --bin kin-daemon
```

### 2. Initialize a Kin workspace

```bash
cd /path/to/your/project
kin init
```

This creates `.kin/`, including object storage, working state, and the graph
database.

### 3. Run `kin-daemon`

```bash
kin-daemon --repo /path/to/your/project --port 4219
```

For verbose logs:

```bash
RUST_LOG=debug kin-daemon --repo /path/to/your/project --port 4219
```

## Docker

### `kin-daemon`

```bash
cd kin
docker build -t kin-daemon .
docker run -d \
  --name kin-daemon \
  -p 4219:4219 \
  -v /path/to/workspace:/workspace \
  -e RUST_LOG=info \
  kin-daemon
```

### `kin-db` test runner

```bash
cd kin-db
docker build --target test-runner -t kin-db-tests .
docker run --rm kin-db-tests
```

### Open-core Compose

The compose file in this repo starts only public open-core services.

```bash
cd kin
docker compose up -d
docker compose logs -f
docker compose down
```

## Health Checks

| Service | Endpoint | Purpose |
|---------|----------|---------|
| `kin-daemon` | `http://localhost:4219/health` | Liveness and version |
| `kin-daemon` | `http://localhost:4219/readiness` | Readiness once the graph is loaded |
| `kin-daemon` | `http://localhost:4219/status` | Working-copy overlay status |

Example response:

```json
{
  "status": "ok",
  "version": "0.1.0",
  "uptime_seconds": 3600,
  "graph_entity_count": 1542,
  "graph_loaded": true,
  "reconciliation_status": "idle"
}
```

## Monitoring

Watch:

- `kin-daemon /health` for unexpected restarts and entity growth
- `kin-daemon /readiness` for initialization failures
- container restart counts when running under Docker

Recommended log levels:

- `info` for production
- `debug` for troubleshooting
- `trace` for deep local investigation

Key events to alert on:

- `reconciliation error`
- `overlay projection failed`
- `session sweeper error`

## Backup And Restore

The critical state lives under `.kin/` in each workspace.

| Path | Contents |
|------|----------|
| `.kin/kindb/graph.kndb` | graph database snapshot |
| `.kin/objects/` | content-addressed blob store |
| `.kin/working/` | reconcile working state |

### Backup

1. Stop `kin-daemon`, or ensure no writes are in progress.
2. Archive `.kin/`.

```bash
kill -TERM $(pgrep kin-daemon)
tar czf kin-backup-$(date +%Y%m%d-%H%M%S).tar.gz /path/to/workspace/.kin/
kin-daemon --repo /path/to/workspace
```

For Docker:

```bash
docker compose stop kin-daemon
docker cp kin-kin-daemon-1:/workspace/.kin/ ./backup/
docker compose start kin-daemon
```

### Restore

```bash
kill -TERM $(pgrep kin-daemon)
rm -rf /path/to/workspace/.kin/
tar xzf kin-backup-YYYYMMDD-HHMMSS.tar.gz -C /
kin-daemon --repo /path/to/workspace
```

## Troubleshooting

### Port conflicts

```bash
lsof -i :4219
kin-daemon --port 4220 --repo /path/to/workspace
```

If using Docker Compose, change the host-side port mapping.

### Lock errors

Kin uses OS-level file locking on `.kin/kindb/graph.kndb.lock`.

- only one `kin-daemon` should access a workspace at a time
- stale `flock` state usually clears when the old process exits
- avoid NFS-style filesystems that do not support locking semantics reliably

### `kin-daemon` will not start

- run `kin init` first if the workspace has no `.kin/`
- check permissions on `.kin/`
- ensure another daemon is not already holding the workspace

### Health check failures

- readiness stays `503` until the graph loads
- allow startup time before declaring failure
- check logs with `docker compose logs kin-daemon`
