# Performance Profiling

Use Kin's built-in `--profile-out` when you only need the tracing span tree.

Use one of the wrappers below when you want a full profiling bundle without hand-adding timers:

- `scripts/profile-command.sh`
  Lightweight shell wrapper around `--profile-out`, `sample`, and periodic system snapshots.
- `scripts/profile_kin_command.py`
  Full bundle generator. This is the recommended path when you want merged timelines, a summary, sampled native stacks, resource telemetry, and optional `xctrace` captures.

## What You Get

The richer Python harness combines four layers:

- Kin's built-in span profile from `--profile-out`
- macOS `/usr/bin/sample` call-stack sampling
- periodic process and system telemetry
- optional `xctrace` capture for `Time Profiler` or `Metal System Trace`

Typical bundle outputs:

- `kin-profile.json`
  Raw Kin span report
- `timeline.trace.json`
  Merged trace for Perfetto or `chrome://tracing`
- `summary.md`
  Hotspots and peak resource summary
- `manifest.json`
  Machine-readable run metadata
- `sample.txt`
  Native sampled stacks
- `stdout.log`, `stderr.log`
  Command output

## Build

Build the Kin binary you want to profile:

```bash
cd /Users/troyfortinjr/GitHub/kin-ecosystem/kin
PATH="$HOME/.cargo/bin:$PATH" cargo build --release -p kin-cli --bin kin
```

## Recommended: Full Bundle

Profile repo conversion on a fresh clone:

```bash
tmp="$(mktemp -d /tmp/kin-init-profile.XXXXXX)"
git clone --local /Users/troyfortinjr/GitHub/kin-ecosystem/kin "$tmp/repo"

cd /Users/troyfortinjr/GitHub/kin-ecosystem/kin
python3 scripts/profile_kin_command.py \
  --bundle-dir "$tmp/.kin-profile/init" \
  --cwd "$tmp/repo" \
  --sample-duration-sec 45 \
  -- \
  /Users/troyfortinjr/GitHub/kin-ecosystem/kin/target/release/kin \
  init --json
```

Profile `kin locate` on an initialized repo:

```bash
python3 scripts/profile_kin_command.py \
  --bundle-dir /tmp/kin-profile-locate \
  --cwd /Users/troyfortinjr/GitHub/kin-ecosystem/kin \
  --sample-duration-sec 20 \
  -- \
  /Users/troyfortinjr/GitHub/kin-ecosystem/kin/target/release/kin \
  locate 'traceback when locate falls back to snapshot open' \
  --json --explain
```

When GPU activity matters, add one or more `xctrace` templates:

```bash
python3 scripts/profile_kin_command.py \
  --bundle-dir /tmp/kin-profile-locate-gpu \
  --cwd /Users/troyfortinjr/GitHub/kin-ecosystem/kin \
  --xctrace-template 'Time Profiler' \
  --xctrace-template 'Metal System Trace' \
  -- \
  /Users/troyfortinjr/GitHub/kin-ecosystem/kin/target/release/kin \
  locate 'vector search regression' --json
```

## Lightweight Wrapper

If you only want the Kin profile JSON plus `sample` and simple snapshots:

```bash
scripts/profile-command.sh \
  --cwd /Users/troyfortinjr/GitHub/kin-ecosystem/kin \
  --out /tmp/kin-profile-lite \
  --sample-seconds 20 \
  -- \
  /Users/troyfortinjr/GitHub/kin-ecosystem/kin/target/release/kin \
  locate 'warm cache fallback' --json
```

## Repeated Locate Benchmark

Use the Python harness when you want medians and p95s over a query corpus.

Corpus format:

- one query per line, or
- `LABEL<TAB>QUERY` when you want stable names in the report

Example corpus:

```text
repo-open
build failures after snapshot reconcile
ranking	regression in locate ranking after index refresh
```

Run the benchmark:

```bash
python3 scripts/profile_kin_command.py \
  --bundle-dir /tmp/kin-locate-bench \
  --cwd /Users/troyfortinjr/GitHub/kin-ecosystem/kin \
  --locate-corpus /tmp/kin-locate-corpus.txt \
  --locate-repeats 7 \
  --locate-warmups 1 \
  -- \
  /Users/troyfortinjr/GitHub/kin-ecosystem/kin/target/release/kin \
  locate __QUERY__ --json --explain
```

The harness will:

- run the warmups first to stabilize caches
- execute each query the requested number of times
- write one full profiling bundle per run under `runs/`
- summarize median, p95, min, and max in `summary.md`
- emit machine-readable per-run metrics in `runs.csv`

## How To Read It

Start with `summary.md` or the `resources.summary` block in `kin-profile.json`.

Then drill down in this order:

- `kin-profile.json`
  Which Kin spans took the time
- `timeline.trace.json`
  How spans, samples, and telemetry line up on a shared timeline
- `sample.txt`
  Where native CPU time went when spans are too coarse
- optional `xctrace`
  Use when GPU or scheduler behavior matters more than Kin spans

For the main workflows in this repo, the next layer down is usually:

- `init`
  `snapshot_repo`, warm-cache open/reuse, text-index rebuild/commit, snapshot save
- `migrate`
  Git import, semantic persistence, read-index build, snapshot save
- `locate`
  signal extraction, graph expansion, text search, semantic search, ranking fusion

## Current Limits

- The built-in Kin profile now records resource samples in the JSON report, but GPU utilization is still not emitted there as structured metrics.
- For precise per-kernel or per-command GPU analysis on macOS, use the optional `xctrace` outputs.
- Thread-count telemetry is best-effort on macOS.
