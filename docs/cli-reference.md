# Kin CLI Reference

Complete reference for every `kin` command. Generated from `kin-cli` clap definitions.

---

## Repository Basics

### `kin init`

Initialize a new Kin repository.

```
kin init [PATH]
```

| Argument | Description |
|----------|-------------|
| `PATH` | Directory to initialize (defaults to current directory) |

---

### `kin status`

Show working copy status. Displays which entities have changed since the last commit.

```
kin status
```

---

### `kin commit`

Create a semantic commit.

```
kin commit -m <MESSAGE> [-q]
```

| Flag | Description |
|------|-------------|
| `-m, --message` | Commit message (required) |
| `-q, --quiet` | Suppress progress output (only print final summary) |

---

### `kin log`

Show semantic change log.

```
kin log [-n <COUNT>]
```

| Flag | Description |
|------|-------------|
| `-n, --count` | Maximum number of entries (default: 10) |

---

### `kin eject`

Remove Kin and restore files to pre-init state.

```
kin eject [--force]
```

| Flag | Description |
|------|-------------|
| `--force` | Skip confirmation prompt |

---

### `kin update`

Update Kin to the latest release.

```
kin update
```

---

### `kin setup`

First-time setup and health checks for the Kin system.

```
kin setup [status|doctor] [--mode <MODE>] [--shell <SHELL>] [--auto-daemon] [--no-interactive]
```

| Subcommand | Description |
|------------|-------------|
| *(none)* | Run the interactive setup wizard |
| `status` | Show what's installed |
| `doctor` | Quick health check |

| Flag | Description |
|------|-------------|
| `--mode` | Repository mode: `native` or `compatibility` |
| `--shell` | Shell to configure: `zsh`, `bash`, or `powershell` |
| `--auto-daemon` | Auto-start kin-daemon when entering workspaces |
| `--no-interactive` | Run non-interactively using defaults or provided flags |

---

## Branching

### `kin branch`

Branch operations.

```
kin branch <list|create|delete|switch> [ARGS]
```

| Subcommand | Description |
|------------|-------------|
| `list` | List branches |
| `create <NAME>` | Create a new branch |
| `delete <NAME>` | Delete a branch |
| `switch <NAME>` | Switch to a branch |

---

### `kin merge`

Semantic merge from another branch.

```
kin merge <BRANCH> [-s <STRATEGY>]
```

| Flag | Description |
|------|-------------|
| `-s, --strategy` | Merge strategy: `structural` or `semantic` (default: `structural`) |

---

### `kin checkout`

Restore a file from a specific change.

```
kin checkout <PATH> [--change <ID>]
```

| Flag | Description |
|------|-------------|
| `--change` | Change ID (defaults to current branch head) |

---

### `kin stash`

Stash working copy state.

```
kin stash <push|pop|list>
```

| Subcommand | Description |
|------------|-------------|
| `push` | Save current working state |
| `pop` | Restore the most recent stash entry |
| `list` | List stash entries |

---

## Graph Exploration

### `kin search`

Search entities in the graph.

```
kin search <PATTERN> [-k <KIND>] [-l <LANGUAGE>] [--show-body] [--limit <N>] [--semantic]
```

| Flag | Description |
|------|-------------|
| `PATTERN` | Search pattern (use `\|` for OR, e.g. `"save\|load\|persist"`) |
| `-k, --kind` | Filter by entity kind |
| `-l, --language` | Filter by language |
| `--show-body` | Show entity source body inline |
| `--limit` | Max lines per entity body (with `--show-body`) |
| `--semantic` | Use vector similarity search instead of name matching |

---

### `kin trace`

Trace a focal entity in one shot: resolve it, show the body, and summarize nearby context.

```
kin trace <ENTITY> [--compact] [-b <BUDGET>] [--assistant <HINT>] [--max-lines <N>] [--nearby <N>] [--transitive <N>]
```

| Flag | Description |
|------|-------------|
| `ENTITY` | Entity name or ID |
| `--compact` | Render a smaller, cheaper trace tuned for assistant workflows |
| `-b, --budget` | Token budget: `8k`, `16k`, `32k`, or custom number (default: `8k`) |
| `--assistant` | Assistant hint for tuning context pack strategy |
| `--max-lines` | Max lines to print for any single source snippet (default: 40) |
| `--nearby` | Max nearby entries to print (default: 4) |
| `--transitive` | Max transitive entries to print (default: 2) |

---

### `kin context`

Build a context pack for an entity.

```
kin context <ENTITY> [-b <BUDGET>] [--assistant <HINT>]
```

| Flag | Description |
|------|-------------|
| `ENTITY` | Entity name or ID |
| `-b, --budget` | Token budget: `8k`, `16k`, `32k`, or custom number (default: `8k`) |
| `--assistant` | Assistant hint for tuning context pack strategy |

---

### `kin refs`

Show upstream callers/importers/references for an entity.

```
kin refs <ENTITY> [--kind <KIND>]
```

| Flag | Description |
|------|-------------|
| `ENTITY` | Entity name or ID |
| `--kind` | Filter relation kinds: `all`, `calls`, `imports`, or `references` (default: `all`) |

---

### `kin impact`

Show downstream impact of an entity.

```
kin impact <ENTITY> [-d <DEPTH>]
```

| Flag | Description |
|------|-------------|
| `ENTITY` | Entity name or ID |
| `-d, --depth` | Maximum depth (default: 3) |

---

### `kin overview`

Show a quick codebase overview (entity counts by kind, language, top files).

```
kin overview [--compact] [--json]
```

| Flag | Description |
|------|-------------|
| `--compact` | Only show counts, no entity listings |
| `--json` | Output all entities as JSON (for programmatic use) |

---

### `kin deps`

Show cross-repo dependencies.

```
kin deps
```

---

### `kin dead-code`

Find dead code (entities with no incoming relations).

```
kin dead-code
```

---

## Diff, Review & History

### `kin diff`

Show entity diff between changes.

```
kin diff [BASE] [HEAD]
```

| Argument | Description |
|----------|-------------|
| `BASE` | Base change ID (optional) |
| `HEAD` | Head change ID (optional) |

---

### `kin review`

Run semantic review on changes.

```
kin review [CHANGE]
```

| Argument | Description |
|----------|-------------|
| `CHANGE` | Change ID to review (defaults to latest) |

---

### `kin history`

Show entity history.

```
kin history <ENTITY>
```

---

### `kin blame`

Show blame (version history) for an entity.

```
kin blame <ENTITY>
```

---

## Verification & Quality

### `kin verify`

Verify test coverage for entities.

```
kin verify <entity|plan|change|summary|missing|run> [ARGS]
```

| Subcommand | Description |
|------------|-------------|
| `entity <ENTITY>` | Check coverage for a specific entity |
| `plan <ENTITY> [--depth N]` | Plan a targeted proof set from an entity and its downstream impact |
| `change [CHANGE_ID] [--depth N]` | Plan a targeted proof set for a semantic change or the current HEAD |
| `summary` | Show repository-wide coverage summary |
| `missing` | Show only entities missing test coverage |
| `run <ENTITY> [--runner R] [--depth N]` | Execute tests for an entity and record a VerificationRun |

`run` flags:

| Flag | Description |
|------|-------------|
| `--runner` | Test runner: `cargo`, `jest`, `pytest`, `go`, `junit`, or custom command (default: `cargo`) |
| `--depth` | Dependent traversal depth used to widen the proof set (default: 2) |

---

### `kin run`

Run a validation command and capture evidence.

```
kin run <COMMAND>
```

---

### `kin support`

Show support and coverage report.

```
kin support
```

---

### `kin security`

Scan entity graph for security patterns.

```
kin security [--propagate]
```

| Flag | Description |
|------|-------------|
| `--propagate` | Trace transitive dependency vulnerabilities |

---

### `kin audit`

Show audit trail.

```
kin audit [--actor <ID>] [--limit <N>] [--action <TYPE>] [--since <DATE>] [--scope <SCOPE>]
```

| Flag | Description |
|------|-------------|
| `--actor` | Filter by actor ID |
| `--limit` | Maximum number of events (default: 50) |
| `--action` | Filter by action type |
| `--since` | Filter events since date (ISO 8601) |
| `--scope` | Filter by target scope |

---

### `kin approvals`

Manage change approvals.

```
kin approvals <show|list>
```

| Subcommand | Description |
|------------|-------------|
| `show <CHANGE_ID>` | Show approvals for a change |
| `list` | List all actors and delegations |

---

## Release & Rollback

### `kin release`

Create a release snapshot. Alias: `kin tag`.

```
kin release <TAG> [--require-proof] [--require-approval] [--force]
```

| Flag | Description |
|------|-------------|
| `TAG` | Release tag |
| `--require-proof` | Block release if entities lack linked passing tests |
| `--require-approval` | Block release if unapproved agent changes exist |
| `--force` | Force release even with low coverage |

---

### `kin semver`

Analyze semver impact of changes.

```
kin semver
```

---

### `kin rollback`

Rollback to a previous change. Alias: `kin revert`.

```
kin rollback <CHANGE_ID> [--feature <WORK_ID>]
```

| Flag | Description |
|------|-------------|
| `CHANGE_ID` | Change ID to rollback to |
| `--feature` | Rollback all changes linked to a work item ID |

---

## Remote & Sync

### `kin auth`

Authenticate with KinLab for native remotes.

```
kin auth <login|logout|whoami|status> [--base-url <URL>]
```

| Subcommand | Description |
|------------|-------------|
| `login [--no-browser]` | Log into KinLab and store a CLI credential |
| `logout` | Log out and remove the stored KinLab credential |
| `whoami` | Show the authenticated KinLab user |
| `status` | Show whether a KinLab credential is stored |

---

### `kin remote`

Manage native and compatibility remotes.

```
kin remote <list|add|plan-push|lease|sessions> [ARGS]
```

| Subcommand | Description |
|------------|-------------|
| `list` | List configured and detected remotes |
| `add <NAME> --host <H> --transport <T> [--url <U>] [--publish-review-state] [--publish-proofs] [--default]` | Add or update a configured remote |
| `plan-push [--remote <NAME>]` | Show the push plan for a remote |
| `lease [--remote <NAME>] [--actor-id <ID>] [--ttl-seconds <N>] [--json]` | Acquire a graph-aware session lease for a native Kin remote |
| `sessions [--remote <NAME>] [--json]` | List active hosted repo sessions for a native Kin remote |

`add` flags:

| Flag | Description |
|------|-------------|
| `--host` | Host kind: `github` or `kinlab` |
| `--transport` | Transport kind: `git-export` or `native-kin` |
| `--url` | Optional remote URL or locator |
| `--publish-review-state` | Publish review state to this remote |
| `--publish-proofs` | Publish proofs to this remote |
| `--default` | Set as the default remote |

---

### `kin push`

Plan or prepare a publish to the default remote.

```
kin push [--remote <NAME>]
```

---

### `kin pull`

Pull changes from a remote. Alias: `kin fetch`.

```
kin pull [--remote <NAME>]
```

---

### `kin clone`

Clone a repository.

```
kin clone <URL> [PATH]
```

| Argument | Description |
|----------|-------------|
| `URL` | Repository URL (Git or Kin) |
| `PATH` | Target directory (defaults to repo name) |

---

### `kin import`

Import a repository (git URL or local path) into Kin.

```
kin import <URL>
```

---

## Git Interop

### `kin git`

Git interop commands.

```
kin git <export|import|sync> [ARGS]
```

| Subcommand | Description |
|------------|-------------|
| `export [--output <DIR>] [--in-place]` | Export current state to Git |
| `import [PATH]` | Import from Git history |
| `sync [--in-place]` | Sync with Git remote |

---

### `kin migrate`

Run schema migrations.

```
kin migrate [SOURCE] [-d <DEPTH>]
```

| Flag | Description |
|------|-------------|
| `SOURCE` | Source repository path (defaults to current directory) |
| `-d, --depth` | Migration depth: `shallow` (HEAD only) or `deep` (full history) (default: `shallow`) |

---

## Agent Coordination

### `kin intent`

Manage agent intents (locks on scopes).

```
kin intent <list|register|release|clear> [ARGS]
```

| Subcommand | Description |
|------------|-------------|
| `list` | List all active intents |
| `register <SCOPE> -t <TASK> [-l <LOCK>] [-s <SESSION>]` | Register a new intent (lock a scope) |
| `release <INTENT_ID>` | Release a specific intent |
| `clear <SESSION_ID>` | Clear all intents for a session |

`register` flags:

| Flag | Description |
|------|-------------|
| `SCOPE` | Scope to lock (`entity:<uuid>`, `file:<path>`, or bare UUID/path) |
| `-l, --lock` | Lock type: `hard` or `soft` (default: `soft`) |
| `-t, --task` | Task description (required) |
| `-s, --session` | Session ID (defaults to a new CLI session) |

---

### `kin traffic`

Show traffic (active intents) on a scope.

```
kin traffic <show|sessions>
```

| Subcommand | Description |
|------------|-------------|
| `show <SCOPE>` | Show active traffic on a scope |
| `sessions` | List all active sessions |

---

## Work Items

### `kin work`

Manage work items (features, tasks, issues, debt, TODOs).

```
kin work <create|list|show|link|decompose|block|implement|status|close|verify> [ARGS]
```

| Subcommand | Description |
|------------|-------------|
| `create -k <KIND> -t <TITLE> [-d <DESC>] [-s <SCOPE>] [-p <PRIORITY>]` | Create a new work item |
| `list [-s <STATUS>] [-k <KIND>] [--scope <SCOPE>]` | List work items |
| `show <WORK_ID>` | Show work item details |
| `link <WORK_ID> <SCOPE>` | Link a work item to a scope |
| `decompose <PARENT_ID> <CHILD_ID>` | Link a parent work item to a child |
| `block <BLOCKED_ID> <BLOCKER_ID>` | Mark one work item as blocked by another |
| `implement <WORK_ID> <SCOPE>` | Link semantic scopes that implement a work item |
| `status <WORK_ID> <STATUS>` | Update a work item status |
| `close <WORK_ID>` | Close a work item |
| `verify <WORK_ID>` | Verify test coverage for a work item's implementing entities |

Work kinds: `feature`, `task`, `issue`, `debt`, `todo`, `investigation`.

Work statuses: `proposed`, `planned`, `in_progress`, `blocked`, `done`, `verified`, `archived`.

Priorities: `critical`, `high`, `medium`, `low`, `none`.

---

### `kin feature`

Create a feature (alias for `kin work create --kind feature`).

```
kin feature <TITLE> [-d <DESCRIPTION>]
```

---

### `kin todo import`

Import inline TODOs from source files.

```
kin todo import [PATH]
```

| Argument | Description |
|----------|-------------|
| `PATH` | Path to scan (defaults to working directory) |

---

## Annotations

### `kin note`

Manage annotations (comments, warnings, instructions, reasoning).

```
kin note <add|list|stale>
```

| Subcommand | Description |
|------------|-------------|
| `add <TARGET> -k <KIND> -b <BODY>` | Add an annotation to a semantic scope or work item |
| `list <TARGET>` | List annotations for a semantic scope or work item |
| `stale` | Show stale annotations |

Target format: `entity:<uuid>`, `contract:<uuid>`, `artifact:<path>`, `change:<id>`, `work:<uuid>`, or bare path.

Annotation kinds: `comment`, `warning`, `instruction`, `reasoning`.

---

## Specs

### `kin spec`

Manage specs.

```
kin spec <create|list|show>
```

| Subcommand | Description |
|------------|-------------|
| `create <INTENT>` | Create a new spec |
| `list` | List specs |
| `show <ID>` | Show a spec |

---

## Workspaces & Sessions

### `kin workspace`

Manage workspaces.

```
kin workspace <list|create|switch|delete|rename>
```

| Subcommand | Description |
|------------|-------------|
| `list` | List workspaces |
| `create <NAME>` | Create a new workspace |
| `switch <NAME>` | Switch to a workspace |
| `delete <NAME>` | Delete a workspace |
| `rename <OLD_NAME> <NEW_NAME>` | Rename a workspace |

---

### `kin exec`

Execute a command in a materialized workspace.

```
kin exec <COMMAND> [--keep] [--strategy <S>] [--scope <S>]
```

| Flag | Description |
|------|-------------|
| `COMMAND` | Command to execute |
| `--keep` | Keep the workspace after execution |
| `--strategy` | Materialization strategy |
| `--scope` | Scope filter |

---

### `kin open`

Launch an editor in a materialized session workspace.

```
kin open <EDITOR> [--restrict-discovery] [--restrict-filesystem] [--wait]
```

| Flag | Description |
|------|-------------|
| `EDITOR` | Editor to launch: `code`, `cursor`, or any editor command |
| `--restrict-discovery` | In native mode, block filesystem discovery commands and require Kin discovery |
| `--restrict-filesystem` | In native mode, block both filesystem discovery and direct file reads |
| `--wait` | Wait for the editor to exit, then reconcile and clean up automatically |

---

### `kin shell`

Open an interactive shell in a materialized session workspace.

```
kin shell [--strategy <S>] [--restrict-discovery] [--restrict-filesystem]
```

| Flag | Description |
|------|-------------|
| `--strategy` | Materialization strategy |
| `--restrict-discovery` | In native mode, block filesystem discovery commands |
| `--restrict-filesystem` | In native mode, block both discovery and direct file reads |

---

### `kin reconcile`

Reconcile session workspace changes back into the graph.

```
kin reconcile [SESSION] [--cleanup]
```

| Flag | Description |
|------|-------------|
| `SESSION` | Session ID (defaults to most recent session) |
| `--cleanup` | Remove the session workspace after successful reconciliation |

---

## Mode

### `kin mode`

Manage repository mode (compat or native).

```
kin mode <native|compat|show|preset>
```

| Subcommand | Description |
|------------|-------------|
| `native` | Switch to Kin-native mode (source files move to `.kin/source-root/`) |
| `compat` | Switch back to compatibility mode (source files at repo root) |
| `show` | Show current repository mode |
| `preset <NAME>` | Apply a world-policy preset for non-code artifacts and external tools |

---

## Assistant Integration

### `kin with`

Launch an assistant with Kin guidance injected.

```
kin with <ASSISTANT> [--passive-guidance] [--restrict-discovery] [--restrict-filesystem] [-- <TASK>...]
```

| Flag | Description |
|------|-------------|
| `ASSISTANT` | Assistant to launch: `claude`, `codex`, `gemini` |
| `--passive-guidance` | Pass the raw task only; keep docs on disk but do not inject prompt guidance |
| `--restrict-discovery` | In native mode, block filesystem discovery commands |
| `--restrict-filesystem` | In native mode, block both discovery and file reads |
| `TASK` | Task prompt (trailing arguments after `--`) |

---

### `kin assistant`

Manage assistant adapters.

```
kin assistant <install|doctor|list|sync|configure|snippets|hooks|prompt> [ARGS]
```

| Subcommand | Description |
|------------|-------------|
| `install <ASSISTANT>` | Install an assistant adapter (`claude-code`, `codex`, `gemini-cli`, `cursor`, `generic`) |
| `doctor [ASSISTANT]` | Run connectivity checks (checks all if omitted) |
| `list` | List installed adapters |
| `sync` | Sync managed doc blocks |
| `configure [--sync-mode <MODE>] [--enable <FILE>] [--disable <FILE>]` | Configure managed doc sync targets |
| `snippets [ASSISTANT]` | Generate ready-to-paste config snippets |
| `hooks [ASSISTANT]` | Show recommended hook templates |
| `prompt --assistant <A> [--mode <M>]` | Generate injectable prompt guidance |

---

## MCP Server

### `kin mcp start`

Start the MCP stdio server.

```
kin mcp start [--global]
```

| Flag | Description |
|------|-------------|
| `--global` | Run in global mode, serving all registered repos from `~/.kin/registry.toml` |

---

## Registry

### `kin registry`

Show or manage the global Kin repository registry.

```
kin registry [clean]
```

| Subcommand | Description |
|------------|-------------|
| *(none)* | List all registered repos |
| `clean` | Remove stale entries (paths that no longer contain `.kin/`) |

---

## Benchmarks

### `kin bench`

Run benchmarks.

```
kin bench [run|corpus|capture|capture-artifact|live] [ARGS]
```

| Subcommand | Description |
|------------|-------------|
| *(none)* | Run benchmarks with defaults |
| `run [--assistant-run <FILE>...]` | Run benchmarks with optional assistant run files |
| `corpus [--repo <PATH>...] [--github-dir <DIR>]` | Run corpus benchmarks across repos |
| `capture --assistant <A> --task <T> --substrate <S> [--model <M>] --duration-ms <N> --tokens-in <N> --tokens-out <N> --cost <F> --passed` | Capture a benchmark run from flags |
| `capture-artifact --vendor <V> --path <P> [--task <T>] [--substrate <S>]` | Capture a benchmark run from a vendor artifact file |
| `live [OPTIONS]` | Run live benchmark arms using detected assistant CLIs |

`live` flags:

| Flag | Description |
|------|-------------|
| `--repo` | Repository URL or local path (defaults to current directory) |
| `--task` | Custom task prompts (repeatable) |
| `--task-name` | Only run built-in tasks with these exact names (repeatable) |
| `--task-set` | Built-in task set: `discovery`, `mutation`, `validated`, or `all` (default: `all`) |
| `--assistant` | Only run with this assistant CLI (`claude`, `codex`, or `gemini`) |
| `--exclude` | Exclude specific CLIs (repeatable) |
| `--repeat` | Number of repetitions per task (default: 1) |
| `--arm` | Only run these arms: `git`, `kin-compat`, `kin-native`, `kin-native-cli`, `kin-pilot-native` |
| `--no-monitor` | Skip resource monitoring during runs |
| `--keep-workspace` | Keep workspace after benchmark |
| `--native-restrict-discovery` | Inject PATH shims that block discovery commands |
| `--native-restrict-filesystem` | Inject PATH shims that block discovery and file reads |
| `--fresh-conversion` | Force fresh kin init + commit, ignoring cached conversion |
| `--claude-disable-explore` | Disable subagent delegation for Claude across all arms |
| `--plugin-dir` | Path to a Claude Code plugin directory for Kin arms |
| `--include-kin-pilot-native` | Include the experimental kin-pilot-native arm |
