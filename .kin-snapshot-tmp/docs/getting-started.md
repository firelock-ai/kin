# Getting Started with Kin

Kin is a semantic version control system that understands your code as a graph of entities (functions, types, modules) and their relationships — not just lines in files. It coexists with Git and works with any AI coding assistant via MCP.

## 1. Install

```bash
curl -fsSL https://get.kinlab.dev/install | sh
```

This installs the `kin` binary to `~/.kin/bin/` and adds it to your PATH.

Verify the installation:

```bash
kin --version
# kin 0.x.y
```

## 2. Setup

Run the interactive setup wizard to configure your environment:

```bash
kin setup
```

The wizard walks through four phases:

1. **Shell integration** -- Installs a shell hook (zsh, bash, fish, or PowerShell) that auto-activates the VFS overlay when you `cd` into a Kin workspace.

2. **AI assistant MCP configuration** -- Detects installed AI tools (Claude Code, Cursor, Codex CLI) and writes the Kin MCP server entry into their config files. This gives your AI assistant access to 37 semantic tools (search, trace, impact analysis, review, etc.) with zero manual setup.

3. **Daemon configuration** -- Optionally enables auto-start of `kin-daemon` when entering workspaces. The daemon runs a background file watcher and reconciliation loop.

4. **Verification** -- Checks that all components are installed and reachable.

After setup, verify everything is healthy:

```bash
kin setup status    # show what's installed
kin setup doctor    # run health checks
```

## 3. Initialize Your First Repository

Navigate to an existing project (with or without Git) and initialize Kin:

```bash
cd ~/projects/my-app
kin init
```

This creates a `.kin/` directory alongside your existing `.git/` (if present). Kin takes a snapshot of your files, parses all source code with tree-sitter, and builds the entity graph.

```
Initialized Kin repository: my-app
  Repo ID:    a1b2c3d4-...
  Entities:   347
  Relations:  512
  Files:      42
  Branch:     main
```

Supported languages: TypeScript, JavaScript, Python, Go, Java, Rust, C, C++, C#, Ruby.

## 4. Explore Your Codebase

### Status

See the current state of your repository:

```bash
kin status
```

```
Branch: main
Head:   abc123...

Modified:
  src/api/routes.ts      (3 entities changed)
  src/models/user.ts     (1 entity added)

Graph: 347 entities, 512 relations
```

### Search

Find entities by name, with support for OR patterns:

```bash
kin search "handleRequest"
```

```
  Function  handleRequest        src/api/routes.ts:42      TypeScript
  Function  handleRequestError   src/api/errors.ts:15      TypeScript
```

Filter by kind or language:

```bash
kin search "User" --kind class --language typescript
```

### Trace

Deep-dive into a specific entity -- see its source, relationships, and nearby context:

```bash
kin trace handleRequest
```

```
=== handleRequest ===
Kind:     Function
File:     src/api/routes.ts:42-67
Language: TypeScript

--- Body ---
async function handleRequest(req: Request): Promise<Response> {
  const user = await getUser(req.headers.authorization);
  ...
}

--- Calls ---
  getUser            src/auth/session.ts:10
  validatePayload    src/validation.ts:22

--- Called by ---
  router.post        src/api/index.ts:8
```

### Impact analysis

See what would be affected by changing an entity:

```bash
kin impact handleRequest --depth 3
```

## 5. First Review

After making changes to your code, run a semantic review:

```bash
kin review
```

Kin analyzes changes at the entity level -- not just line diffs -- and produces risk analysis showing which entities changed, what relationships were affected, and potential downstream impact.

## 6. Context Packs

Build a token-budgeted context pack for any entity, ready to paste into an AI conversation:

```bash
kin context handleRequest --budget 8k
```

This assembles the entity's source, its callers, callees, type definitions, and related tests into a coherent context block that fits within your token budget. Available budgets: `8k`, `16k`, `32k`, or any custom number.

## 7. AI Integration

If you ran `kin setup`, your AI assistants are already configured. Kin exposes 37 semantic tools via MCP (Model Context Protocol) over stdio.

Your AI assistant can now:

- **Search** the entity graph (`semantic_search`)
- **Trace** dependencies and call chains (`find_references`, `graph_neighborhood`)
- **Analyze impact** before making changes (`impact_analysis`)
- **Review** changes semantically (`semantic_review`)
- **Build context** for focused work (`get_context_pack`)

No extra configuration needed -- `kin setup` wrote the MCP server entry to:

| Assistant   | Config file                        |
|-------------|------------------------------------|
| Claude Code | `~/.claude.json`                   |
| Cursor      | `~/.cursor/mcp.json`               |
| Codex CLI   | `~/.codex/mcp.json`                |

To verify MCP is working, start the server manually:

```bash
kin mcp start
```

## 8. Coexistence with Git

Kin is designed for brownfield adoption. It lives alongside Git, not instead of it.

- `.kin/` sits next to `.git/` in your project root
- `git commit` and `kin commit` are independent operations
- You can sync between them: `kin git export`, `kin git import`, `kin git sync`
- Your Git workflows (PRs, CI, remotes) continue unchanged
- Kin adds a semantic layer on top: entity-level tracking, impact analysis, and review

To remove Kin from a project and restore it to its pre-init state:

```bash
kin eject
```

This stops daemons, restores files from the snapshot taken during `kin init`, and removes the `.kin/` directory entirely.

## Quick Reference

| Command                        | What it does                                    |
|--------------------------------|-------------------------------------------------|
| `kin init`                     | Initialize Kin in the current directory          |
| `kin status`                   | Show working copy status                         |
| `kin search <pattern>`         | Search entities by name                          |
| `kin trace <entity>`           | Deep-dive into an entity                         |
| `kin impact <entity>`          | Show downstream impact                           |
| `kin review`                   | Semantic review of changes                       |
| `kin context <entity>`         | Build a context pack for AI                      |
| `kin commit -m "message"`      | Create a semantic commit                         |
| `kin log`                      | Show semantic change log                         |
| `kin branch list`              | List branches                                    |
| `kin diff`                     | Show entity diff between changes                 |
| `kin overview`                 | Codebase summary (entity counts, top files)      |
| `kin eject`                    | Remove Kin, restore pre-init state               |
| `kin setup doctor`             | Run health checks                                |

## Next Steps

- **Migrate an existing Git repo**: See the [Migration Guide](migration-guide.md)
- **Browse the full CLI**: `kin --help` or `kin <command> --help`
- **Use with KinLab**: Connect to the web dashboard at [kinlab.dev](https://kinlab.dev)
