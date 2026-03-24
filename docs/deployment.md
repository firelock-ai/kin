# Kin Ecosystem Deployment Guide

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Node.js | 22+ | kinlab control plane and web |
| pnpm | 9+ | kinlab package management |
| Rust | stable (1.82+) | kin-daemon and kin-db |
| Docker | 24+ | Container deployment (optional) |
| Docker Compose | 2.20+ | Full-stack orchestration (optional) |

## Environment Variables

### kinlab (control plane)

| Variable | Default | Description |
|----------|---------|-------------|
| `KIN_SESSION_SECRET` | (required in production) | Session signing key, minimum 32 characters |
| `KIN_REQUIRE_AUTH` | `0` | Set to `1` to enable authentication |
| `KINLAB_CORS_ORIGIN` | `http://localhost:5173` | Allowed CORS origin for the web frontend |
| `PORT` | `4010` | HTTP server port |
| `KIN_BINARY_PATH` | (auto-detected) | Path to the kin binary |
| `KIN_REPO_PATH` | (auto-detected) | Path to the kin workspace/repo |
| `KIN_SESSION_ROLE` | `admin` | Default session role (`admin` or `viewer`) |
| `NODE_ENV` | `development` | Node environment (`development`, `production`) |

### kin-daemon

| Variable | Default | Description |
|----------|---------|-------------|
| `RUST_LOG` | `info` | Tracing filter level (`trace`, `debug`, `info`, `warn`, `error`) |

kin-daemon also accepts CLI flags:
- `--repo <path>` — Path to the workspace (default: current directory)
- `--port <port>` — API server port (default: `4219`)

## Local Development Setup

### 1. Clone the ecosystem

```bash
git clone <ecosystem-url> kin-ecosystem
cd kin-ecosystem
```

### 2. Build kin-daemon

```bash
cd kin
cargo build --release --bin kin-daemon
```

The binary is at `kin/target/release/kin-daemon`.

### 3. Initialize a kin workspace

```bash
cd /path/to/your/project
kin init
```

This creates a `.kin/` directory with subdirectories for objects, working state, and the graph database.

### 4. Run kin-daemon

```bash
kin-daemon --repo /path/to/your/project --port 4219
```

Set `RUST_LOG=debug` for verbose output:

```bash
RUST_LOG=debug kin-daemon --repo /path/to/your/project
```

### 5. Build and run kinlab

```bash
cd kinlab
pnpm install
pnpm --filter @kinlab/contracts build
pnpm --filter @kinlab/control-plane build
pnpm --filter @kinlab/web build

# Start the control plane
node services/control-plane/dist/index.js

# Start the web frontend (dev mode)
pnpm --filter @kinlab/web dev
```

## Docker Single-Service Deployment

### kinlab control plane

```bash
cd kinlab
docker build -t kinlab-control-plane .
docker run -d \
  --name kinlab-control-plane \
  -p 4010:4010 \
  -e KIN_SESSION_SECRET=your-secret-key-min-32-characters \
  -e KIN_REQUIRE_AUTH=1 \
  -e NODE_ENV=production \
  kinlab-control-plane
```

### kinlab web

```bash
cd kinlab
docker build -f Dockerfile.web -t kinlab-web .
docker run -d \
  --name kinlab-web \
  -p 5173:80 \
  kinlab-web
```

### kin-daemon

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

### kin-db (test runner)

```bash
cd kin-db
docker build --target test-runner -t kin-db-tests .
docker run --rm kin-db-tests
```

## Docker Compose Full Stack

The `kin-stack/docker-compose.yml` orchestrates all services together.

```bash
cd kin-stack

# Start all services
docker compose up -d

# View logs
docker compose logs -f

# Stop everything
docker compose down

# Rebuild after code changes
docker compose up -d --build
```

Services start in dependency order:
1. **kin-daemon** — graph engine and reconciliation loop (port 4219)
2. **kinlab-control-plane** — API server (port 4010), waits for health check
3. **kinlab-web** — static web frontend (port 5173), starts after control plane is healthy

### Customizing environment

Create a `.env` file in `kin-stack/`:

```env
KIN_SESSION_SECRET=your-production-secret-key-at-least-32-chars
KIN_REQUIRE_AUTH=1
NODE_ENV=production
RUST_LOG=info
```

## Health Check URLs

| Service | Endpoint | Purpose |
|---------|----------|---------|
| kin-daemon | `http://localhost:4219/health` | Liveness check — returns status, version, uptime, entity count, graph state |
| kin-daemon | `http://localhost:4219/readiness` | Readiness probe — 200 when graph loaded, 503 when initializing |
| kin-daemon | `http://localhost:4219/status` | Working copy overlay status (entity/relation mutations) |
| kinlab | `http://localhost:4010/api/health` | Liveness check — returns status and version |

### Example health response (kin-daemon)

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

## Monitoring Guidance

### What to watch

- **kin-daemon `/health`** — Check `uptime_seconds` for unexpected restarts, `graph_entity_count` for graph growth, `reconciliation_status` for stuck states
- **kin-daemon `/readiness`** — Use for load balancer health checks; returns 503 during initialization
- **kinlab `/api/health`** — Basic liveness; check periodically for uptime monitoring
- **Container restart counts** — Docker's `restart: unless-stopped` will restart crashed services; monitor `docker inspect --format='{{.RestartCount}}'`

### Log levels

- **kin-daemon**: Set via `RUST_LOG` env var. Use `info` for production, `debug` for troubleshooting, `trace` for deep debugging
- **kinlab**: Structured JSON logs to stdout. Set `NODE_ENV=production` for production log format

### Key log events to alert on

- `reconciliation error` — File reconciliation failed for an event
- `overlay projection failed` — Working copy projection to disk failed
- `session sweeper error` — Stale session cleanup encountered an error

## Backup and Restore

### What to back up

The critical data lives in the `.kin/` directory within your workspace:

| Path | Contents |
|------|----------|
| `.kin/kindb/graph.kndb` | The graph database snapshot (entities, relations, sessions) |
| `.kin/objects/` | Blob store (file content addressed by hash) |
| `.kin/working/` | Reconciler working state |

### Backup procedure

1. Stop kin-daemon (or ensure no writes are in progress)
2. Copy the `.kin/` directory:

```bash
# Stop the daemon gracefully
kill -TERM $(pgrep kin-daemon)

# Create a backup
tar czf kin-backup-$(date +%Y%m%d-%H%M%S).tar.gz /path/to/workspace/.kin/

# Restart the daemon
kin-daemon --repo /path/to/workspace
```

For Docker deployments:

```bash
docker compose stop kin-daemon
docker cp kin-stack-kin-daemon-1:/workspace/.kin/ ./backup/
docker compose start kin-daemon
```

### Restore procedure

1. Stop kin-daemon
2. Replace the `.kin/` directory with the backup:

```bash
kill -TERM $(pgrep kin-daemon)
rm -rf /path/to/workspace/.kin/
tar xzf kin-backup-YYYYMMDD-HHMMSS.tar.gz -C /
kin-daemon --repo /path/to/workspace
```

## GCP Cloud Deployment (Pulumi)

For production deployment on Google Cloud Platform with managed services, see:

- **`GCP_ARCHITECTURE.md`** — Complete cloud architecture design (1500+ lines, service topology, security model, networking)
- **`GCP_PULUMI_SUMMARY.md`** — Summary of deliverables and deployment artifacts
- **`pulumi/`** — Infrastructure-as-code configuration:
  - `Pulumi.yaml` — Project manifest
  - `__main__.py` — Pulumi Python IaC (~1000 lines)
  - `requirements.txt` — Python dependencies
- **`.github/workflows/deploy-gcp.yml`** — CI/CD pipeline for automated GCP deployment

### Quick Start: 5-Minute GCP Deploy

Prerequisites: `gcloud`, `pulumi`, `docker`, `jq`

```bash
# 1. Create and configure GCP project
export GCP_PROJECT_ID="my-kin-project"
gcloud projects create $GCP_PROJECT_ID
gcloud config set project $GCP_PROJECT_ID
gcloud services enable compute.googleapis.com run.googleapis.com sqladmin.googleapis.com \
  storage-component.googleapis.com artifactregistry.googleapis.com

# 2. Initialize Pulumi stack
cd pulumi/
pulumi stack init dev
pulumi config set gcp:project $GCP_PROJECT_ID
pulumi config set gcp:region us-central1

# 3. Deploy infrastructure
pulumi up

# 4. Retrieve outputs
pulumi stack output
```

Expected output: 15–20 minute deployment time, then receive load balancer IP, KinLab URL, API endpoints, and database details.

### Services Deployed on GCP

| Service | Type | Memory | Scaling | Port |
|---------|------|--------|---------|------|
| kin-daemon | Cloud Run (Rust) | 2 GB | 1–3 | 4219 |
| kinlab-control-plane | Cloud Run (Node.js) | 1 GB | 1–5 | 4010 |
| kin-graph-service | Cloud Run (Node.js) | 1.5 GB | 1–5 | 4311 |
| kinlab-web | Cloud Run (SPA) | 512 MB | 0–10 | 80 |
| Cloud SQL | Managed PostgreSQL | 2 vCPU, 8 GB | HA + Auto-backup | 5432 |

External access via HTTPS Load Balancer (port 443) with DNS routing to subdomains.

## Troubleshooting

### Port conflicts

If ports 4219, 4010, or 5173 are already in use:

```bash
# Find what's using a port
lsof -i :4219

# Use different ports
kin-daemon --port 4220
PORT=4011 node services/control-plane/dist/index.js
```

In docker-compose, change the host port mapping (left side of `:`):
```yaml
ports:
  - "4220:4219"  # host:container
```

### Auth failures (kinlab)

- Ensure `KIN_SESSION_SECRET` is set and at least 32 characters in production
- If `KIN_REQUIRE_AUTH=1`, sessions need valid credentials
- Check `KIN_SESSION_ROLE` is set to `admin` for write access

### Lock errors (kin-db)

kin-db uses OS-level file locking (`flock`) on `.kin/kindb/graph.kndb.lock`:

- Only one kin-daemon instance can access a workspace at a time
- If a previous process crashed, the lock file may be stale — the OS releases `flock` locks on process exit, so simply restarting should work
- If using NFS or network filesystems, `flock` may not be supported — use local storage

### kin-daemon won't start

- **"no .kin directory found"** — Run `kin init` in the workspace first, or pass `--repo` pointing to a directory containing `.kin/`
- **"failed to open daemon state"** — Check file permissions on `.kin/` and its subdirectories
- **"Already running"** — Another kin-daemon instance is running for this workspace

### Container health check failures

- kin-daemon readiness returns 503 until the graph loads — allow `start_period` (15s default) for initialization
- Ensure `curl` is installed in the container image (included in the provided Dockerfiles)
- Check container logs: `docker compose logs kin-daemon`
