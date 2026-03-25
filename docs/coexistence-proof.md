# Git + Kin Coexistence Proof

This document describes how Git and Kin coexist in a daily workflow, the evidence that
proves this coexistence is safe and reversible, and how teams can adopt Kin without
abandoning Git.

Last updated: 2026-03-17

---

## 1. Core Design Principle

Kin does not replace Git. It layers semantic structure alongside it:

- `kin init` works with or without an existing `.git` directory.
- All Kin state lives inside `.kin/` -- source files are never rewritten by Kin unless
  explicitly requested via projection.
- Adoption is fully reversible: run `kin eject` and the repository is byte-identical to
  its pre-Kin state.
- `.git` and `.kin` are independent data stores. Neither touches the other's internals.

## 2. The Daily Workflow: Git + Kin Side by Side

A typical day working in a repo that has both Git and Kin looks like this:

### Step 1: Normal Git Work

Developers use Git exactly as they always have:

```bash
git checkout -b feature/my-change
# ... edit files ...
git add -A && git commit -m "implement feature"
```

Kin is unaffected. The `.kin/` directory is listed in Git's tracking but Kin's internal
state is independent of Git commits.

### Step 2: Kin Reconcile

After Git commits land, Kin's reconcile loop detects file-system changes and pulls them
back into semantic state. This happens automatically if the Kin daemon is running, or
manually:

```bash
kin reconcile          # pull filesystem changes into Kin semantic state
kin status             # see updated entity counts, change tracking
kin verify change      # verify semantic consistency of recent changes
```

The reconcile step uses a last-known-good (LKG) fallback for broken ASTs, so a
half-written file from an in-progress edit does not corrupt semantic state.

### Step 3: Kin Commit (Semantic Snapshot)

When the semantic state is consistent, take a Kin snapshot:

```bash
kin commit -m "semantic snapshot after feature work"
```

This records the semantic state (entities, relations, proofs, work items) as a Kin
commit. It does not affect `.git` in any way.

### Step 4: Git Export (Optional)

To produce a Git-compatible view of the Kin state:

```bash
kin git export         # creates .git-export/ as a bare Git repo
```

This is useful for CI pipelines, code review tools, or any system that expects a Git
repository. The export is a one-way projection -- changes flow from Kin to Git, not
the reverse.

### Step 5: Round-Trip Verification

To verify that the semantic state survives a full round trip:

```bash
kin verify summary     # check verification coverage
kin verify change      # check that recent changes are semantically valid
```

The daily-driver proof script (`scripts/daily-driver-proof.sh`) exercises this entire
lifecycle automatically: status, context, verify, work items, remotes, and release gating.

## 3. Migration Path: Bringing Kin to an Existing Git Repo

For teams adopting Kin on an existing codebase, the brownfield migration path is:

```bash
# Step 1: Migrate (imports Git history, GitHub issues/PRs, labels, milestones)
kin migrate <repo-path> --depth deep --preset brownfield

# Step 2: Verify migration
kin status && kin verify summary

# Step 3: Continue using Git normally -- Kin reconcile handles the rest
```

**Idempotency**: Running `migrate-repo` a second time detects `already-initialized` and
re-syncs GitHub metadata without re-migrating. The migration drill proves this with
explicit two-pass verification.

**Rollback**: Run `kin eject` to fully undo migration (removes `.kin/` and `.git-export/`). Git HEAD and
working tree are unchanged -- verified programmatically in every drill run.

## 4. Evidence: What the Scripts Prove

### 4.1 `scripts/daily-driver-proof.sh`

Exercises the core Kin CLI workflow against `kin-workspace`:

| Step | Command | What it proves |
|------|---------|----------------|
| 1 | Detect `.kin` repo | Kin workspace exists alongside Git |
| 2 | `kin status` | Branch and entity count are healthy |
| 3 | `kin context` / search | Entity search returns results |
| 4 | `kin verify summary` | Verification coverage is tracked |
| 5 | `kin verify change` | Change verification runs cleanly |
| 6 | `kin work list` | Work items are tracked |
| 7 | `kin remote list` | Remote configuration is intact |
| 8 | `kin semver` | Release gating works |

**Key proof**: The Kin CLI is usable as a daily driver alongside Git, exercising all
major subsystems without interfering with the Git repository.

### 4.2 `scripts/real-repo-migration-drill.sh`

Runs the full brownfield migration lifecycle against the real `kin` repository (not a
toy test repo):

| Phase | Assertion |
|-------|-----------|
| First migration | `status == "migrated"` |
| Second migration | `status == "already-initialized"` (idempotency) |
| HEAD preservation | Git HEAD unchanged across both migrations |
| Git export | `.git-export/` is a valid bare Git repository |
| Rollback: .kin removed | `rollback.removedKin == true` |
| Rollback: .git-export removed | `rollback.removedGitExport == true` |
| Rollback: HEAD intact | `rollback.headAfterRollback == initialGit.head` |
| Rollback: clean tree | `git status --porcelain` is empty |

**Key proof**: A real repository with meaningful Git history survives the full
migration cycle (init, re-run, export, rollback) with zero data loss.

### 4.3 `scripts/publish-recovery-e2e.sh`

Proves the native remote publish and divergence/recovery flow:

| Step | What it proves |
|------|----------------|
| Plan push | Local-to-remote diff is computed correctly |
| Publish | Remote head advances, divergence state becomes `in-sync` |
| Activity | Publish events are recorded in the activity feed |
| Idempotent re-publish | No divergence after publishing the same state |
| Stale rejection | Stale publish with wrong `expectedRemoteHead` is rejected (HTTP 4xx) |

**Key proof**: The native Kin remote protocol handles publish, sync, and conflict
detection correctly -- Git-style push semantics without Git.

### 4.4 `scripts/package-proof-report.sh`

Assembles all of the above into a single reproducible proof package with:

- Environment metadata (OS, CPU, RAM, toolchain versions)
- Source commit hashes for every ecosystem repo
- Test results (Rust cargo tests, Python pytest)
- Doctor/Verify/Benchmark gate results
- Migration drill results
- Benchmark timing highlights

The proof package can be independently verified using `scripts/verify-proof-package.sh`.

## 5. What Coexistence Looks Like in Practice

### For Individual Developers

- Use Git for commits, branches, and PRs as usual.
- Use Kin for semantic queries (`kin search`, `kin overview`), change verification
  (`kin verify change`), and work tracking (`kin work list`).
- Kin reconcile runs in the background; no manual sync needed.
- If anything goes wrong, run `kin eject` -- no damage to Git state.

### For Teams

- Git remains the collaboration backbone: PRs, code review, CI/CD all use Git.
- Kin adds a semantic layer: automated verification, entity-aware change tracking,
  structured work items, and proof generation.
- Migration is per-repo and reversible. Teams can adopt incrementally.
- The `kin-stack migrate-repo` command handles the full onboarding including GitHub
  issue/PR import.

### For CI/CD

- `kin git export` produces a Git-compatible artifact for any system that needs one.
- `kin verify change` can gate merges on semantic consistency.
- `package-proof-report.sh` produces an auditable proof package for each build.

## 6. Known Limitations and Active Gaps

| Gap | Status | Mitigation |
|-----|--------|------------|
| Projection/reconcile hardening | In progress | LKG fallback prevents corruption; full hardening is the primary trust goal |
| No export-then-clone-back proof | Open | `kin git export` creates `.git-export/` but no automated test clones from it and diffs back |
| No CI-integrated benchmark | Open | Wire `package-proof-report.sh` into CI for automated artifact generation |
| GitHub coexistence drill with real API | Partial | Unit-tested with mocks; full integration drill requires `gh` CLI authentication |

## 7. Reproducing the Evidence

To reproduce all coexistence proofs from scratch:

```bash
# 1. Run the daily-driver lifecycle proof
./kin/scripts/daily-driver-proof.sh

# 2. Run a brownfield migration drill against a real repo
kin migrate <repo-path> --depth deep --preset brownfield
kin migrate <repo-path> --depth deep --preset brownfield  # re-run to prove idempotency

# 3. Verify migration results
kin status && kin verify summary
```

---

*This document is part of the Kin ecosystem proof package. See also:
[brownfield-evidence-index.md](brownfield-evidence-index.md),
[ecosystem-master-document.md](ecosystem-master-document.md).*
