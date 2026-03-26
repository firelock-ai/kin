# kin-migrate

GitHub/Git repo migration pipeline for Kin.

## Overview

kin-migrate converts Git repositories into sovereign Kin repos. The pipeline scans the repo for source files, branches, and commits; plans the migration strategy (shallow HEAD-only or deep full-history); initializes the `.kin/` directory; imports Git history as SemanticChange objects; indexes source files for entity/relation extraction; and writes everything to the graph store.

## Key Types

- **`MigrationPlan`** / **`MigrationStrategy`** -- Plan and strategy (shallow vs. deep) for a migration.
- **`MigrationResult`** -- Outcome of a completed migration (entities imported, files indexed).
- **`RepoScan`** -- Result of scanning a Git repo (files, branches, commit count).

## Key Functions

- **`scan_repo`** -- Scan a Git repo for files, branches, and history.
- **`plan_migration`** -- Generate a migration plan from a repo scan.
- **`execute_migration`** / **`migrate_repo`** -- Run the full migration pipeline.
- **`execute_migration_persisted`** -- Migration with persistence to disk.

## Usage

```bash
# Migrate a Git repo to Kin
kin migrate /path/to/git-repo

# Shallow migration (HEAD only, faster)
kin migrate --shallow /path/to/git-repo
```

## Testing

```bash
cargo test -p kin-migrate
```

## License

Apache-2.0 -- Copyright 2026 Firelock, LLC
