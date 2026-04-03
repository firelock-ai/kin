# Brownfield Evidence Index

> Historical note: this document inventories the earlier brownfield proof stack and preserves artifact paths and commands from that phase. References to `kin-stack`, `kin-workspace`, or other older proof tooling are historical evidence labels, not the current canonical ecosystem map.

This document inventories every proof artifact, drill, benchmark, and verification flow
that exists today in the Kin ecosystem for the brownfield migration path. Its purpose is
to answer: *Could an external operator run the full drill from scratch and get meaningful,
auditable results?*

Last updated: 2026-03-17

---

## 1. End-to-End Migration Path (Step-by-Step)

The brownfield migration path is a six-phase lifecycle. Every phase is automated by a
single `kin-stack` subcommand.

### Phase 1: Git Import

**Command:**
```bash
bin/kin-stack migrate-repo <source> [--depth deep] [--preset brownfield]
```

**What happens:**
1. If `<source>` is a GitHub/Git URL, clone it into `--root` (default `~/GitHub/kin-ecosystem`).
   Local paths are used in-place.
2. Run `kin migrate <repo-path> --depth deep` to create the `.kin/` semantic workspace inside the repo.
3. Apply the brownfield world preset (`kin mode preset brownfield`).
4. Scan for inline TODOs and import them as work items (`kin todo import`).
5. Auto-detect GitHub origin remote and configure it.
6. Import GitHub issues (with labels, milestones, assignees, comments).
7. Import GitHub pull requests (with file scope links, labels, milestones, assignees, review comments).
8. Optionally configure a KinLab native remote.
9. Write a structured JSON migration report alongside the repo.

**Source:** `kin-stack/bin/kin-stack` lines 329-483 (`cmd_migrate_repo`)

### Phase 2: Idempotent Re-Sync

Running `migrate-repo` again on the same repo detects `already-initialized` and re-syncs
GitHub metadata (issues, PRs, labels, milestones, assignees) without re-migrating. The
migration-drill proves this explicitly with two passes.

### Phase 3: Work in Kin

The migrated repo has a full `.kin/` workspace. Standard `kin` CLI commands work:
`kin status`, `kin overview`, `kin verify summary`, `kin verify change`, `kin work list`,
`kin note list`, `kin bench`, `kin remote plan-push`.

### Phase 4: Git Export

**Command:**
```bash
kin git export          # run inside the migrated repo
```

Creates `.git-export/` as a valid bare Git repository reflecting the Kin state. The
migration-drill verifies this produces a valid repo (HEAD file present, `is_git_repository_path` passes).

### Phase 5: Rollback

The migration-drill performs rollback by:
1. Removing `.kin/` entirely (`shutil.rmtree`)
2. Removing `.git-export/` entirely
3. Verifying Git HEAD is unchanged from the initial pre-migration value
4. Verifying `git status --porcelain` is clean (empty)

After rollback the repo is byte-identical to its pre-migration state.

### Phase 6: Full Drill (Automated Proof)

**Command:**
```bash
bin/kin-stack migration-drill <source> [--scratch-dir <dir>]
```

Runs phases 1-5 in sequence on a scratch clone, producing a JSON drill report that
captures every intermediate state. The drill is the primary proof artifact.

---

## 2. Proof Artifact Inventory

### 2.1 Migration Drill Reports

| Artifact | Location | What It Proves | Status | Reproducible? |
| --- | --- | --- | --- | --- |
| Full drill report | `kin-stack/.generated/migration-drills/brownfield-migration-drill.json` | Full lifecycle: migrate, re-sync, export, rollback, HEAD preservation | Current (2026-03-17T15:08:51Z) | Yes -- `bin/kin-stack migration-drill <any-git-repo>` |
| Smoke drill report | `kin-stack/.generated/migration-drills/brownfield-migration-drill-smoke.json` | Same lifecycle on a generated tiny repo (used in benchmark flows) | Current (2026-03-17T15:15:06Z) | Yes -- `bin/kin-stack benchmark full --migration-drill` |

**Key assertions verified in both reports:**
- `afterFirstMigration.report.migration.status == "migrated"`
- `afterSecondMigration.report.migration.status == "already-initialized"` (idempotency)
- `initialGit.head == afterSecondMigration.head` (HEAD unchanged)
- `gitExport.exists == true` and `gitExport.validRepo == true`
- `rollback.removedKin == true`, `rollback.removedGitExport == true`
- `rollback.headAfterRollback == initialGit.head` (clean rollback)
- `rollback.statusAfterRollback == ""` (no dirty files)

**Programmatic validation:** `ensure_brownfield_migration_drill_report()` (line 3485) enforces all of the above with hard `SystemExit` on any failure.

### 2.2 Stack Benchmark Reports

| Artifact | Location | What It Proves | Count |
| --- | --- | --- | --- |
| Stack benchmark JSON | `kin-workspace/.kin/bench/stack-benchmark-*.json` | Full-stack seam timing: every `kin` CLI command, every KinLab HTTP surface, adapter smoke tests | ~38 runs on 2026-03-17 |
| Stack benchmark Markdown | `kin-workspace/.kin/bench/stack-benchmark-*.md` | Human-readable summary of the same | ~38 |
| Kin bench JSON | `kin-workspace/.kin/bench/bench-*.json` | Per-repo semantic metrics: entity count, dependency coverage, token savings, dead code detection | 100 files |
| Kin bench dashboard JSON | `kin-workspace/.kin/bench/bench-dashboard-*.json` | Dashboard-ready aggregate: coverage gauges, token savings chart, assistant comparison | 38 files |

**Total bench artifacts:** 138 files in `kin-workspace/.kin/bench/`

**What the latest stack benchmark covers (43 steps):**

| Category | Surfaces Tested |
| --- | --- |
| Kin CLI commands | `kin status`, `kin overview`, `kin verify summary`, `kin verify change`, `kin remote list`, `kin work list`, `kin note list`, `kin work verify`, `kin bench`, `kin remote plan-push` |
| Adapter smoke | `kin-fs-adapter context`, `kin-scm-adapter context`, `kin-pilot smoke` |
| KinLab HTTP surfaces | health (4 services), dashboard, search, repos, repo detail, repo history, repo activity, repo work, repo work detail, repo refs, repo compare, repo blob, domains, domain detail, domain file, review queue, review detail, review file diff, review assignment, review discussion, review reply, review resolve, review decision, native remote, native remote publish, repo activity publish, native remote refresh |

**Reproducibility:** `bin/kin-stack benchmark full` reproduces the entire 43-step benchmark from scratch.

### 2.3 Validated Popular Repo Benchmark Sweep

| Artifact | Location | What It Proves |
| --- | --- | --- |
| Validated benchmark report | `kin/docs/benchmarks/validated-popular-repos-2026-03-20.md` | Head-to-head `git` vs `kin-native` across 10 popular repos, 7 task types, 70 comparisons |

**Headline results:**
- 69/70 task comparisons won by `kin-native`
- 50.0% less wall-clock time (1659.7s git vs 829.8s kin-native)
- 44.6% fewer tokens (5,539,366 git vs 3,068,820 kin-native)

**Repos tested:** express, axios, hono, zod, flask, typer, requests, redux, click, dayjs
(JavaScript, TypeScript, Python)

**Task types:** count-real-callers, find-dead-code, find-planted-secret, fix-planted-bug,
implement-stub, trace-computation, trace-type-imports

**Fairness controls:**
- Randomized planted artifacts injected before arm split
- Identical source files and task prompts per arm
- Random UUIDs for secrets (no training data leakage)
- Planted files import real symbols from the repo's dependency graph
- Automatic output validation against ground truth
- Kin conversion forced fresh per repo; conversion cost reported separately
- Arm order rotation built in

**Reproducibility:** `python3 scripts/run_popular_validated_benchmarks.py --assistant codex`
from `kin/` reproduces the sweep. Requires `cargo build --release -p kin-cli` first.

**Caveat:** The 2026-03-15 sweep was not run on a lab-clean machine (load average 5.3-8.8,
competing processes). Absolute times are noisy; the value is in breadth (10 repos, 70 tasks).
Rust (ripgrep) was excluded due to a workspace setup failure -- not hand-waved.

### 2.4 Verify Flow

| Artifact | Command | What It Proves |
| --- | --- | --- |
| Full-stack verify | `bin/kin-stack verify full` | End-to-end: init workspace, write config, doctor, bring services up, exercise every surface, bring services down |

**Source:** `cmd_verify` lines 893-947

**Steps:** init-workspace -> ensure remote -> ensure demo content -> write-config -> doctor -> up -> verify_runtime_surfaces -> down

The verify flow runs the same surface probes as the benchmark but asserts pass/fail rather
than timing. It exits non-zero on any failure.

### 2.5 Doctor Flow

| Artifact | Command | What It Proves |
| --- | --- | --- |
| Doctor check | `bin/kin-stack doctor <profile> [--checks]` | All repos present, .git exists, Node version matches .nvmrc, quickChecks pass |

**Source:** `cmd_doctor` lines 618-687

Checks per repo:
- Directory exists
- `.git` directory exists
- `.nvmrc` Node version matches installed version (warning if not)
- Optional `quickChecks` (e.g. `cargo test -p kin-db`) when `--checks` flag is set
- Kin workspace presence validated

### 2.6 Unit Tests

| Artifact | Location | What It Proves |
| --- | --- | --- |
| `test_migrate_repo.py` | `kin-stack/tests/test_migrate_repo.py` | 18 test cases covering: Git remote detection, repo name inference, TODO import parsing, GitHub issue/PR description building, tracker metadata (labels/milestones/assignees) on create and update, external ref parsing, note marker parsing, drill report validation, drill report path resolution, idempotent issue import, PR rerun metadata sync, lifecycle reliability (service cleanup) |

**Reproducibility:** `python3 -m pytest kin-stack/tests/` from the ecosystem root.

---

## 3. GitHub Coexistence Coverage Map

The `migrate-repo` command has full GitHub coexistence support for the following:

| Feature | Imports? | Syncs on Re-Run? | Notes |
| --- | --- | --- | --- |
| Issues (title, state, body) | Yes | Yes (update) | Maps state to Kin status |
| Issue labels | Yes | Yes | `--label` on create, `--label`/`--clear-labels` on update |
| Issue milestones | Yes | Yes | `--milestone`/`--clear-milestone` |
| Issue assignees | Yes | Yes | `--assignee`/`--clear-assignees` |
| Issue comments | Yes | Yes (incremental via markers) | `[github-issue-comment:<id>]` dedup |
| Issue priority | Yes | Yes | Inferred from GitHub labels |
| Issue kind | Yes | N/A | Inferred (bug/feature/task) from labels |
| Issue external URL | Yes | N/A | `html_url` stored |
| Issue author | Yes | N/A | GitHub login + kind=human |
| Pull requests (title, state, body, draft) | Yes | Yes (update) | Draft -> planned, open -> in_progress, closed -> done |
| PR labels | Yes | Yes | Same as issues |
| PR milestones | Yes | Yes | Same as issues |
| PR assignees | Yes | Yes | Same as issues |
| PR review comments | Yes | Yes (incremental) | `[github-review:<id>]` dedup |
| PR file scope links | Yes | Yes | Each changed file linked as `artifact:<path>` |
| PR base/head branches | Yes (in description) | Yes | Documented in work item description |
| TODO import | Yes | Yes | Inline `TODO` comments -> work items |
| GitHub remote config | Yes | Skip if already set | Origin remote detected and configured |

### What's Missing

| Feature | Status | Impact |
| --- | --- | --- |
| GitHub Actions / CI status | Not imported | No CI pass/fail visibility in Kin |
| GitHub Releases / Tags | Not imported | Release history not in work graph |
| GitHub Projects (v2 boards) | Not imported | Board/sprint state not synced |
| GitHub Discussions | Not imported | Community Q&A not imported |
| Wiki pages | Not imported | No wiki -> Kin note pipeline |
| Two-way sync (Kin -> GitHub) | Not implemented | Changes in Kin don't push back to GitHub |
| Webhook-driven incremental sync | Not implemented | Re-sync requires manual `migrate-repo` re-run |

---

## 4. Gaps in the Proof Chain

### 4.1 Critical Gaps (Block External Auditability)

| Gap | Why It Matters | Recommendation |
| --- | --- | --- |
| No real-repo drill artifact | Both drill reports used local temp repos with 0-1 source files and no GitHub remote. The popular-repo benchmark covers real repos but doesn't run the migration-drill lifecycle. | Run `migration-drill` against a real GitHub repo (e.g. `express`) and commit the report. |
| No GitHub coexistence drill | GitHub issue/PR import is tested in unit tests with mocks but no integration drill report exists with real GitHub API calls. | Run `migration-drill https://github.com/expressjs/express.git --github-issue-limit 10 --github-pr-limit 10` and commit the report. |
| Benchmark sweep not in bench/ | The popular-repo sweep wrote to `kin/.kin/bench/` (the kin repo, not kin-workspace), and its aggregate file is not committed or discoverable from kin-workspace. | Copy or link the sweep results into `kin-workspace/.kin/bench/` or add a stable path pointer. |
| No operator runbook | The commands exist, but there is no single document that says "start here, do X, expect Y". This index is the closest thing. | Write a `RUNBOOK.md` with exact prerequisites, environment setup, and step-by-step commands. |

### 4.2 Important Gaps (Reduce Confidence)

| Gap | Why It Matters | Recommendation |
| --- | --- | --- |
| Benchmark environment noise | The 2026-03-15 sweep ran with load average 5.3-8.8 and competing processes. | Re-run on a clean machine or CI runner with controlled load. |
| Rust exclusion | ripgrep was excluded from the sweep due to a workspace setup failure. | Fix the Rust workspace indexing and re-include. |
| No stack benchmark trend | 38 runs on the same day give stability data but not trend data over time. | Schedule a weekly benchmark run and track regression over days/weeks. |
| kin bench workspace metrics thin | The kin-workspace demo has only 7 entities. Dependency coverage is 28.6%, test coverage is 0%. | Seed the workspace with a richer demo project or benchmark against a real migrated repo. |
| No export-then-clone-back proof | `kin git export` creates `.git-export/` but nothing proves you can clone from it and get a working repo. | Add a drill step: `git clone .git-export /tmp/roundtrip && diff -r`. |

### 4.3 Nice-to-Have

| Gap | Recommendation |
| --- | --- |
| No CI-integrated benchmark | Wire `kin-stack benchmark full --migration-drill` into a CI pipeline so artifacts are produced automatically. |
| No multi-machine reproducibility test | Run the drill on a second machine to confirm no local-path dependencies. |
| Token savings not validated end-to-end | The 82.5% token savings in `kin bench` are computed against a naive file-dump baseline. Connect this to the popular-repo sweep's 44.6% figure and explain the difference. |

---

## 5. Operator Readiness Assessment

**Can an external operator run the full drill from scratch?**

**Partially.** Here is what works and what doesn't:

| Step | Operator Ready? | Blocker |
| --- | --- | --- |
| Clone the ecosystem | Yes | `bin/kin-stack install full` handles it |
| Build kin-cli from source | Yes | `cargo build --release -p kin-cli` |
| Initialize workspace | Yes | `bin/kin-stack init-workspace` |
| Run doctor | Yes | `bin/kin-stack doctor full --checks` |
| Run verify | Yes | `bin/kin-stack verify full` |
| Run benchmark | Yes | `bin/kin-stack benchmark full` |
| Run migration-drill (local) | Yes | `bin/kin-stack migration-drill <local-git-repo>` |
| Run migration-drill (GitHub) | Mostly | Requires `gh` CLI authenticated for API calls |
| Run popular-repo sweep | Mostly | Requires Codex CLI 0.114.0 + auth; takes ~25 min |
| Interpret results | No | No runbook; operator must read this index + source code |
| Reproduce on CI | No | No CI config exists |

**Bottom line:** The tooling is solid. Every command is a single invocation. The gap is
packaging -- a runbook, a CI pipeline, and one drill report against a real GitHub repo
would make this fully auditable by someone who has never seen the codebase.

---

## 6. Command Reference

| Command | Purpose | Typical Invocation |
| --- | --- | --- |
| `migrate-repo` | Import a Git/GitHub repo into Kin | `bin/kin-stack migrate-repo https://github.com/org/repo.git` |
| `migration-drill` | Run full lifecycle proof on a scratch clone | `bin/kin-stack migration-drill https://github.com/org/repo.git` |
| `doctor` | Verify repo presence and smoke checks | `bin/kin-stack doctor full --checks` |
| `verify` | Full-stack runtime verification | `bin/kin-stack verify full` |
| `benchmark` | Timed full-stack benchmark with optional drill | `bin/kin-stack benchmark full --migration-drill` |
| `kin bench` | Per-repo semantic metrics benchmark | `kin bench` (inside a .kin workspace) |
| `kin bench live` | Head-to-head git vs kin-native benchmark | `kin bench live --repo <url> --task-set validated` |
| Popular sweep | 10-repo validated benchmark matrix | `python3 scripts/run_popular_validated_benchmarks.py --assistant codex` |
