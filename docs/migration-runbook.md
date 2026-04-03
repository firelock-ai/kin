# Kin Brownfield Migration Runbook

> Historical note: this runbook documents the earlier brownfield proof workflow and keeps its original `kin-stack` / `kin-workspace` commands for reproducibility. Those names are retained here as proof-history labels, not as the current canonical product surface.

This is the operator runbook for evaluating Kin's brownfield migration path. It covers
everything from initial setup through a full migration drill, benchmark suite, popular
repo sweep, and clean rollback. Every command is copy-pasteable.

---

## 1. Prerequisites

### Operating System

macOS (ARM or Intel) or Linux (x86_64). Windows is not tested.

### Required Tools

| Tool | Minimum Version | Check | Notes |
| --- | --- | --- | --- |
| Git | 2.30+ | `git --version` | Any recent version works |
| Rust (cargo) | stable 1.75+ | `rustup show` | Needed to build `kin-cli` from source |
| Python | 3.10+ | `python3 --version` | The `kin-stack` CLI is Python |
| Node.js | 22.22.0 | `node --version` | Must match `.nvmrc`; use `nvm install 22.22.0` |
| gh CLI | 2.40+ | `gh --version` | Required for GitHub coexistence (issue/PR import) |
| nvm | any | `nvm --version` | Recommended for managing the Node version |

### Optional Tools

| Tool | Version | Purpose |
| --- | --- | --- |
| Codex CLI | 0.114.0+ | Required only for the popular repo sweep benchmark |

### Authentication

- `gh auth login` must be completed before any GitHub coexistence commands.
  The `migrate-repo` and `migration-drill` commands call `gh api` and `gh issue list`
  under the hood. Without auth, GitHub metadata import is skipped silently.

### Disk Space

- The ecosystem repos total roughly 2 GB after clone and build.
- Each migration drill uses a scratch clone; budget an extra 500 MB for temp artifacts.
- The popular repo sweep clones 10 repos and runs Codex against each; budget 5 GB.

### Network

- GitHub API access is required for `migrate-repo` with GitHub metadata import.
- No other external network dependencies during the drill or benchmark flows.

---

## 2. Quick Start (Get Running in 5 Minutes)

```bash
# Clone the ecosystem umbrella
git clone https://github.com/anthropics/kin-ecosystem.git ~/GitHub/kin-ecosystem
cd ~/GitHub/kin-ecosystem/kin-stack

# Install all repos for the full profile
bin/kin-stack install full

# Build kin-cli from source (required before any kin commands work)
cd ~/GitHub/kin-ecosystem/kin
cargo build --release -p kin-cli
cd ~/GitHub/kin-ecosystem/kin-stack

# Run doctor to verify everything is wired
bin/kin-stack doctor full --checks

# Run a migration drill against any local Git repo
bin/kin-stack migration-drill /path/to/any/git/repo
```

If `doctor` passes and the drill prints `Kin brownfield migration drill complete.`,
the stack is operational.

---

## 3. Full Migration Drill

The migration drill is the primary proof artifact. It runs the complete brownfield
lifecycle on a scratch clone: migrate, re-sync, export, rollback.

### 3.1 Run the Drill

Against a local Git repo:

```bash
bin/kin-stack migration-drill /path/to/your/repo
```

Against a GitHub repo (clones it for you):

```bash
bin/kin-stack migration-drill https://github.com/expressjs/express.git
```

With GitHub metadata import (issues and PRs):

```bash
bin/kin-stack migration-drill https://github.com/expressjs/express.git \
  --github-issue-limit 10 \
  --github-pr-limit 10
```

### 3.2 What Happens (Six Phases)

1. **Clone/Prepare** -- The source repo is cloned into a scratch directory under
   `kin-stack/.generated/migration-drills/`. You can override this with `--scratch-dir`.

2. **First migration pass** -- Runs `kin migrate <repo> --depth deep`, applies the
   `brownfield` preset, imports inline TODOs, detects the GitHub remote, and imports
   issues/PRs if a GitHub origin is found and `gh` is authenticated.

3. **Second migration pass** -- Runs the same `migrate-repo` command again. The second
   pass detects `already-initialized` and re-syncs GitHub metadata without re-migrating.
   This proves idempotency.

4. **Git export** -- Runs `kin git export` inside the migrated repo. This creates a
   `.git-export/` directory as a valid bare Git repository reflecting the Kin state.

5. **Rollback** -- Removes `.kin/` and `.git-export/` entirely. Verifies that Git HEAD
   is unchanged from the pre-migration value and `git status --porcelain` is empty.

6. **Report** -- Writes a structured JSON drill report next to the scratch repo.

### 3.3 Expected Output

```
Running first brownfield migration drill pass in /path/to/scratch/repo...
Migrating /path/to/scratch/repo into Kin (deep)...
...
ok: Kin workspace already present at /path/to/scratch/repo
Applying `brownfield` preset...
Importing inline TODOs into the work graph...
Running second migration drill pass to prove rerunnable sync...
...

Kin brownfield migration drill complete.
  Scratch repo: /path/to/scratch/repo
  Drill report: /path/to/brownfield-migration-drill.json
  Initial Git HEAD: abc1234...
  Post-migration Git HEAD unchanged: True
  Git export created: True
  Git export valid repo: True
  Rollback cleanup removed .kin: True
  Rollback cleanup removed .git-export: True
```

### 3.4 Assertions Verified

The drill report is programmatically validated. These assertions cause a hard exit on
failure:

| Assertion | Field Path | Expected |
| --- | --- | --- |
| First pass migrated | `afterFirstMigration.report.migration.status` | `"migrated"` |
| Second pass idempotent | `afterSecondMigration.report.migration.status` | `"already-initialized"` |
| HEAD unchanged across migration | `afterSecondMigration.head` | equals `initialGit.head` |
| Git export directory exists | `gitExport.exists` | `true` |
| Git export is valid repo | `gitExport.validRepo` | `true` |
| Rollback removed .kin | `rollback.removedKin` | `true` |
| Rollback removed .git-export | `rollback.removedGitExport` | `true` |
| HEAD unchanged after rollback | `rollback.headAfterRollback` | equals `initialGit.head` |
| Working tree clean after rollback | `rollback.statusAfterRollback` | `""` (empty) |

### 3.5 Drill Report Location

- Standalone drill: `<scratch-repo-parent>/brownfield-migration-drill.json`
- Benchmark-embedded drill: `kin-stack/.generated/migration-drills/brownfield-migration-drill-smoke.json`
- Full drill (committed): `kin-stack/.generated/migration-drills/brownfield-migration-drill.json`

### 3.6 Useful Flags

| Flag | Purpose |
| --- | --- |
| `--scratch-dir <path>` | Override the scratch clone destination |
| `--depth shallow` | Shallow migration (faster, less semantic analysis) |
| `--skip-rollback` | Keep `.kin/` and `.git-export/` in the scratch clone for inspection |
| `--skip-github-issues` | Skip GitHub issue import |
| `--skip-github-prs` | Skip GitHub PR import |
| `--skip-github-comments` | Skip comment import on issues and PRs |
| `--github-issue-limit N` | Cap the number of GitHub issues imported |
| `--github-pr-limit N` | Cap the number of GitHub PRs imported |
| `--github-repo owner/repo` | Override the GitHub repo for metadata import |
| `--preset compatibility\|native` | Migration mode preset (default: `brownfield`) |

---

## 4. Benchmark Suite

The benchmark exercises the full Kin stack -- CLI commands, KinLab HTTP surfaces,
adapter smoke tests, and optionally the migration drill -- and writes timing reports.

### 4.1 Run the Benchmark

```bash
bin/kin-stack benchmark full --migration-drill
```

This will:

1. Initialize the workspace if needed (`init-workspace`)
2. Generate config (`write-config`)
3. Run `doctor` checks
4. Start managed services (`up --wait`)
5. Run 43 timed steps across all surfaces
6. Run a migration drill on a generated tiny repo
7. Write JSON and Markdown reports to the workspace bench directory
8. Tear down services (`down`)

### 4.2 The 43 Steps

| Category | Surfaces Tested |
| --- | --- |
| Kin CLI | `kin status`, `kin overview`, `kin verify summary`, `kin verify change`, `kin remote list`, `kin work list`, `kin note list`, `kin work verify`, `kin bench`, `kin remote plan-push` |
| Adapter smoke | `kin-fs-adapter context`, `kin-scm-adapter context`, `kin-pilot smoke` |
| KinLab HTTP | health (4 services), dashboard, search, repos, repo detail, repo history, repo activity, repo work, repo work detail, repo refs, repo compare, repo blob, domains, domain detail, domain file, review queue, review detail, review file diff, review assignment, review discussion, review reply, review resolve, review decision, native remote, native remote publish, repo activity publish, native remote refresh |

### 4.3 Benchmark Artifacts

Reports land in the workspace bench directory:

```
~/GitHub/kin-ecosystem/kin-workspace/.kin/bench/
  stack-benchmark-YYYYMMDD-HHMMSS.json    # full structured report
  stack-benchmark-YYYYMMDD-HHMMSS.md      # human-readable summary
```

The Markdown summary includes total duration, per-step timings, warnings, and
migration drill results if `--migration-drill` was used.

### 4.4 Benchmark Against a Real Repo

To run the migration drill portion against a real GitHub repo instead of the generated
tiny repo:

```bash
bin/kin-stack benchmark full --migration-drill \
  --migration-drill-source https://github.com/expressjs/express.git \
  --migration-drill-github-issue-limit 10 \
  --migration-drill-github-pr-limit 10
```

### 4.5 Keep Services Running

Add `--keep-running` to leave the stack up after the benchmark finishes. Useful for
manual inspection:

```bash
bin/kin-stack benchmark full --migration-drill --keep-running
bin/kin-stack status full    # see what's running
bin/kin-stack down full      # tear down when done
```

---

## 5. Popular Repo Sweep

The popular repo sweep runs a head-to-head `git` vs `kin-native` benchmark across 10
real open-source repos with 7 task types, producing 70 validated comparisons.

### 5.1 Prerequisites

- Codex CLI 0.114.0+ installed and authenticated (`codex --version`)
- `kin-cli` built from source (`cargo build --release -p kin-cli`)
- Roughly 25 minutes of wall-clock time
- Roughly 5 GB of free disk space

### 5.2 Run the Sweep

```bash
cd ~/GitHub/kin-ecosystem/kin
cargo build --release -p kin-cli
python3 scripts/run_popular_validated_benchmarks.py --assistant codex
```

### 5.3 What It Tests

**Repos:** express, axios, hono, zod, flask, typer, requests, redux, click, dayjs
(JavaScript, TypeScript, Python)

**Task types:**
- `count-real-callers` -- Count all call sites for a given function
- `find-dead-code` -- Identify unreachable/unused code
- `find-planted-secret` -- Locate a planted secret value in the source
- `fix-planted-bug` -- Find and fix a planted bug
- `implement-stub` -- Implement a stubbed-out function
- `trace-computation` -- Trace data flow through the codebase
- `trace-type-imports` -- Follow type import chains across files

### 5.4 Fairness Controls

- Randomized planted artifacts injected before arm split
- Identical source files and task prompts per arm
- Random UUIDs for secrets (no training data leakage)
- Planted files import real symbols from the repo's dependency graph
- Automatic output validation against ground truth
- Kin conversion forced fresh per repo; conversion cost reported separately
- Arm order rotation built in

### 5.5 Interpreting the Results

The sweep writes artifacts to:

```
~/GitHub/kin-ecosystem/kin/.kin/bench/
  popular-validated-YYYYMMDD-Nrepo.json    # aggregate JSON
  popular-validated-YYYYMMDD-Nrepo.md      # aggregate Markdown
  live-*.json                              # per-run raw reports
```

The aggregate Markdown contains:

- **Repo matrix**: per-repo win count, time savings, token savings
- **Task summary**: per-task-type win rate and average savings
- **Loss cases**: every comparison where `git` beat `kin-native`, with exact times
- **Environment notes**: load average, swap usage, competing processes

The headline metrics from the 2026-03-15 validated sweep were:

| Metric | Value |
| --- | --- |
| Task comparisons won by kin-native | 69/70 |
| Wall-clock time savings | 50.0% (1659.7s git vs 829.8s kin-native) |
| Token savings | 44.6% (5,539,366 git vs 3,068,820 kin-native) |

### 5.6 Known Limitations

- The sweep has not yet been run on a lab-clean machine. Absolute times are noisy.
- Rust (ripgrep) is excluded due to a workspace setup failure during indexing.
- Arm order rotation reduces bias but a single repetition per repo means individual
  times can be affected by system load.

---

## 6. GitHub Coexistence

The `migrate-repo` command imports GitHub metadata into the Kin work graph. This
section documents what transfers and what does not.

### 6.1 What Imports

| Feature | Creates | Syncs on Re-Run | Dedup Mechanism |
| --- | --- | --- | --- |
| Issues (title, state, body) | Yes | Yes (update) | External URL match |
| Issue labels | Yes | Yes | `--label` / `--clear-labels` |
| Issue milestones | Yes | Yes | `--milestone` / `--clear-milestone` |
| Issue assignees | Yes | Yes | `--assignee` / `--clear-assignees` |
| Issue comments | Yes | Yes (incremental) | `[github-issue-comment:<id>]` marker |
| Issue priority | Yes | Yes | Inferred from GitHub labels |
| Issue kind | Yes | N/A | Inferred (bug/feature/task) from labels |
| Issue external URL | Yes | N/A | `html_url` stored |
| Issue author | Yes | N/A | GitHub login + kind=human |
| Pull requests (title, state, body, draft) | Yes | Yes (update) | External URL match |
| PR labels | Yes | Yes | Same as issues |
| PR milestones | Yes | Yes | Same as issues |
| PR assignees | Yes | Yes | Same as issues |
| PR review comments | Yes | Yes (incremental) | `[github-review:<id>]` marker |
| PR file scope links | Yes | Yes | Each changed file linked as `artifact:<path>` |
| PR base/head branches | Yes (in description) | Yes | Documented in work item description |
| Inline TODOs | Yes | Yes | `kin todo import` dedup |
| GitHub remote config | Yes | Skip if already set | Origin remote detected |

### 6.2 What Does Not Import

| Feature | Status |
| --- | --- |
| GitHub Actions / CI status | Not imported |
| GitHub Releases / Tags | Not imported |
| GitHub Projects (v2 boards) | Not imported |
| GitHub Discussions | Not imported |
| Wiki pages | Not imported |
| Two-way sync (Kin -> GitHub) | Not implemented |
| Webhook-driven incremental sync | Not implemented |

Re-syncing requires a manual `migrate-repo` re-run. Changes made in Kin do not push
back to GitHub.

### 6.3 Running a GitHub Coexistence Import

```bash
# Full import with issues and PRs
bin/kin-stack migrate-repo https://github.com/expressjs/express.git \
  --github-issue-limit 25 \
  --github-pr-limit 25

# Re-run to prove idempotent sync (updates existing, imports new)
bin/kin-stack migrate-repo https://github.com/expressjs/express.git \
  --github-issue-limit 25 \
  --github-pr-limit 25
```

Expected output on second run:

```
ok: Kin workspace already present at .../express
Applying `brownfield` preset...
Importing inline TODOs into the work graph...
...
Kin brownfield migration complete.
  Repo: .../express
  Source kind: github-url
  GitHub issues: 0 imported, 25 updated, 0 skipped
  GitHub pull requests: 0 imported, 25 updated, 0 skipped
```

---

## 7. Rollback

To completely remove Kin from a migrated repo and restore it to its pre-migration
Git state:

### 7.1 Manual Rollback

```bash
cd /path/to/migrated/repo

# Remove the Kin workspace
rm -rf .kin

# Remove the Git export (if one was created)
rm -rf .git-export

# Verify Git state is clean
git log --oneline -1     # HEAD should be unchanged
git status --porcelain   # should print nothing
```

### 7.2 Verify the Rollback

After removing `.kin/` and `.git-export/`, the repo should be byte-identical to its
pre-migration state from Git's perspective. The migration drill automates and verifies
this -- see Section 3.4.

### 7.3 What the Migration Does Not Touch

- `.git/` is never modified. No commits are added, no refs are changed.
- Existing source files are never modified.
- The only additions are the `.kin/` directory and optionally `.git-export/`.

---

## 8. Troubleshooting

### 8.1 Doctor

`doctor` is the first diagnostic to run:

```bash
bin/kin-stack doctor full --checks
```

It checks:
- Every repo in the profile is present
- Every repo has a `.git` directory
- Node version matches `.nvmrc` (22.22.0)
- Quick checks pass (e.g. `cargo test -p kin-db`)
- The Kin workspace exists

### 8.2 Common Failures

**`kin-cli` not found or not built**

```
error: missing command kin
```

Fix: Build the CLI from source.

```bash
cd ~/GitHub/kin-ecosystem/kin
cargo build --release -p kin-cli
```

The built binary lands at `target/release/kin`. The stack CLI finds it automatically
via the `$CARGO_TARGET_DIR` or by looking in `<root>/kin/target/release/kin`.

**Node version mismatch**

```
warning: kin-code: resolved node 20.11.0 differs from .nvmrc 22.22.0
```

Fix:

```bash
nvm install 22.22.0
nvm use 22.22.0
```

**Missing repos**

```
FAILURE: kin-pilot: missing directory ...
```

Fix: Re-run install.

```bash
bin/kin-stack install full
```

**gh CLI not authenticated**

GitHub issue/PR import silently skips if `gh` is not authenticated. If you expect
GitHub metadata and see `0 imported, 0 updated`, run:

```bash
gh auth login
gh auth status
```

**Port conflict on `up`**

```
error: port 4010 already in use by process outside kin-stack state
```

Fix: Find and stop whatever is using the port, or use a different state directory:

```bash
lsof -i :4010
bin/kin-stack up full --state-dir /tmp/kin-state --wait
```

**Workspace missing**

```
FAILURE: kin workspace missing at .../kin-workspace
```

Fix:

```bash
bin/kin-stack init-workspace
```

### 8.3 Verify Flow

If doctor passes but you suspect runtime issues, run the full verify flow:

```bash
bin/kin-stack verify full
```

This runs the complete cycle: init workspace, write config, doctor, bring services up,
exercise every runtime surface, and bring services down. It exits non-zero on any
failure.

Add `--keep-running` to leave services up for manual debugging:

```bash
bin/kin-stack verify full --keep-running
bin/kin-stack status full
```

---

## 9. Interpreting Results

### 9.1 Drill Reports (JSON)

The drill report is a single JSON object. Key fields:

```json
{
  "initialGit": {
    "head": "abc1234...",          // Git HEAD before migration
    "status": ""                    // git status --porcelain (empty = clean)
  },
  "afterFirstMigration": {
    "report": {
      "migration": {
        "status": "migrated"        // first pass creates .kin/
      }
    },
    "head": "abc1234..."            // should match initialGit.head
  },
  "afterSecondMigration": {
    "report": {
      "migration": {
        "status": "already-initialized"  // second pass proves idempotency
      }
    },
    "head": "abc1234..."            // should match initialGit.head
  },
  "gitExport": {
    "exists": true,                 // .git-export/ was created
    "validRepo": true               // it's a valid Git repository
  },
  "rollback": {
    "removedKin": true,             // .kin/ was deleted
    "removedGitExport": true,       // .git-export/ was deleted
    "headAfterRollback": "abc1234...",  // should match initialGit.head
    "statusAfterRollback": ""       // working tree is clean
  }
}
```

**What to look for:**
- All `head` values should be identical. If they differ, the migration mutated Git state.
- `afterSecondMigration.report.migration.status` must be `"already-initialized"`.
  If it says `"migrated"`, idempotency is broken.
- `rollback.statusAfterRollback` must be empty. Any content means the migration left
  files behind.

### 9.2 Benchmark Reports (JSON + Markdown)

The Markdown summary at
`kin-workspace/.kin/bench/stack-benchmark-YYYYMMDD-HHMMSS.md` is the quickest
way to read results. It contains:

- Total duration across all steps
- Per-step timing table
- Warnings (any steps that failed or returned unexpected results)
- Migration drill summary (if `--migration-drill` was used)
- List of new `kin bench` artifacts generated during the run

The JSON report has the same structure but is machine-readable for trend analysis.

### 9.3 Popular Repo Sweep (Markdown)

The aggregate Markdown at `kin/.kin/bench/popular-validated-*.md` contains:

- **Repo matrix**: one row per repo with entity count, file count, git time, native
  time, savings percentage, and win count out of 7 tasks
- **Task summary**: one row per task type with win rate and average savings
- **Loss cases**: every instance where git beat kin-native, with exact wall-clock times
- **Environment notes**: system load, swap, competing processes

A healthy sweep shows 60+ wins out of 70 with 40-60% time savings. Individual loss
cases in the single-digit millisecond range are measurement noise. Losses with
significant time deltas (>5s) warrant investigation.

---

## Command Reference

| Command | Purpose | Example |
| --- | --- | --- |
| `install <profile>` | Clone repos for a profile | `bin/kin-stack install full` |
| `init-workspace` | Create/validate the default Kin workspace | `bin/kin-stack init-workspace` |
| `doctor <profile>` | Check repo presence and smoke tests | `bin/kin-stack doctor full --checks` |
| `verify <profile>` | Full-stack runtime verification | `bin/kin-stack verify full` |
| `benchmark <profile>` | Timed full-stack benchmark | `bin/kin-stack benchmark full --migration-drill` |
| `migrate-repo <source>` | Import a Git/GitHub repo into Kin | `bin/kin-stack migrate-repo https://github.com/org/repo.git` |
| `migration-drill <source>` | Full lifecycle proof on a scratch clone | `bin/kin-stack migration-drill https://github.com/org/repo.git` |
| `up <profile>` | Start managed services | `bin/kin-stack up full --wait` |
| `down <profile>` | Stop managed services | `bin/kin-stack down full` |
| `status <profile>` | Show service status | `bin/kin-stack status full` |
| `write-config <profile>` | Generate config/env files | `bin/kin-stack write-config full` |
| `bootstrap <profile>` | Install + config + doctor in one shot | `bin/kin-stack bootstrap full --checks` |
