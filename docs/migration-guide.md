# Migration Guide: Git to Kin

This guide covers migrating an existing Git repository to Kin. Migration is non-destructive -- Kin creates a `.kin/` directory alongside your `.git/`, and your Git workflows continue unchanged.

## Prerequisites

- Kin installed and configured (`kin setup` completed)
- A Git repository with at least one commit
- Supported source files: TypeScript, JavaScript, Python, Go, Java, Rust, C, C++, C#, Ruby

## Shallow Migration (Recommended)

Shallow migration imports only the current HEAD state. It is fast (typically under 15 seconds) and is the default:

```bash
cd ~/projects/my-repo
kin migrate
```

This performs five steps:

1. **Scan** -- Walks the repository to find source files, detects the default branch, and skips hidden directories, `node_modules`, `target`, `vendor`, `__pycache__`, and `build`.

2. **Plan** -- Creates a migration plan: which files to index, which branch to use, shallow vs deep strategy.

3. **Initialize** -- Creates the `.kin/` directory with graph storage, blob store, and config.

4. **Import** -- Creates a single SemanticChange from HEAD's tree state. Each file's content is stored in the content-addressable blob store (SHA-256). Git commit metadata (author, timestamp, message) is preserved.

5. **Index** -- Parses all source files with tree-sitter, extracts entities (functions, classes, types, modules) and relations (calls, imports, references), and writes them to the graph.

```
Migration complete:
  Strategy:    Shallow
  Commits:     1
  Files:       87
  Entities:    1,204
  Relations:   2,831
  Branch:      main
  Duration:    4.2s
```

## Deep Migration (Full History)

To import the full Git commit history as a semantic DAG:

```bash
kin migrate --depth deep
```

Each Git commit becomes a SemanticChange with proper parent links. Root commits attach to the Kin genesis change. Commit author, timestamp, and message are preserved.

Limit the number of imported commits for large repositories:

```bash
kin migrate --depth deep    # imports all reachable commits
```

Deep migration is slower but gives you entity-level history tracking across your entire project timeline.

## GitHub Metadata Import

To import a remote GitHub repository (clones and migrates in one step):

```bash
kin import https://github.com/org/repo
```

This clones the repository locally and runs a shallow migration. The Git remote URL is preserved for future sync operations.

## Verifying the Migration

After migration, verify the graph was built correctly:

```bash
# Check overall status
kin status
```

```
Branch: main
Head:   a1b2c3...
Graph:  1,204 entities, 2,831 relations
```

```bash
# Search for known entities
kin search "main"

# Trace a specific entity
kin trace App

# Get a codebase overview
kin overview
```

If the entity count looks low, check that your source files have supported extensions and are not in excluded directories.

## Coexistence: .kin/ alongside .git/

After migration, your project directory contains both:

```
my-repo/
├── .git/          # unchanged -- all Git operations still work
├── .kin/          # Kin graph, blobs, config, snapshots
│   ├── config.toml
│   ├── kindb/     # graph snapshots (MessagePack)
│   ├── objects/   # content-addressable blob store
│   ├── snapshot/  # pre-init file snapshot (for eject)
│   └── HEAD       # current branch pointer
├── src/
└── ...
```

Both systems are fully independent:

- `git commit` does not affect the Kin graph
- `kin commit` does not create Git commits
- Sync between them with `kin git sync --in-place`

Your existing Git workflows (branches, PRs, CI, remotes) continue working. Kin adds a semantic layer on top.

## Reversibility: Ejecting Kin

If you want to completely remove Kin from a project:

```bash
kin eject
```

This will:

1. Stop `kin-daemon` and `kin-vfs-daemon` if running
2. Restore all files from the snapshot taken during initialization
3. Remove the `.kin/` directory entirely

Use `--force` to skip the confirmation prompt. After eject, the project is restored to its exact pre-migration state.

## Common Issues

**"Not a Git repository"**
`kin migrate` requires a `.git/` directory. Initialize Git first: `git init && git add -A && git commit -m "initial"`.

**"Already initialized"**
The target directory already has a `.kin/` directory. Remove it first (`rm -rf .kin/`) or use `kin eject` to cleanly restore state, then re-migrate.

**Low entity count after migration**
Check that source files have supported extensions (`.ts`, `.js`, `.py`, `.go`, `.java`, `.rs`, `.c`, `.cpp`, `.cs`, `.rb`). Files in hidden directories, `node_modules`, `target`, `vendor`, and `build` are excluded by default.

**Migration is slow on large repos**
Use shallow migration (the default). Deep migration walks every reachable commit. For repos with thousands of commits, this can take minutes.

**Graph lock contention**
If another Kin process (daemon, MCP server) holds the graph lock, migration may block. Check with: `lsof +D .kin/kindb/ 2>/dev/null | grep -i lock`. Stop other Kin processes before migrating.
