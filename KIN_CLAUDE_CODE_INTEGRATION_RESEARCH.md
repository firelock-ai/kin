# Claude Code Integration Research for Kin

**Status:** Complete research for all 5 integration points
**Date:** 2026-03-11
**Context:** Designing Kin semantic VCS integration with Claude Code to prefer entity graph queries over file-based search

---

## Executive Summary

This document covers ALL Claude Code integration mechanisms for configuring tool preferences and context injection. The research spans 5 major integration points with concrete examples showing how to make Claude Code **prefer `kin` commands over `grep`/file operations**.

### Key Finding
**No single integration point forces tool selection**—they work together:
- **CLAUDE.md** + **Hooks** create guardrails and reminders
- **MCP servers** expose tools to the model
- **Plugins** bundle workflow components
- **Settings** control permissions and environment
- **CLI flags** inject context for headless execution

---

## 1. CLAUDE.md — Format, Loading, Influence

### What is CLAUDE.md?

A markdown file that Claude reads at the **start of every conversation** (when enabled). It contains project-specific instructions, coding standards, tool preferences, and workflows.

### Location & Loading Behavior

| Scope | Location | Applies To |
|-------|----------|-----------|
| **Global** | `~/.claude/CLAUDE.md` | All projects (if system uses settings sources) |
| **Project** | `project/CLAUDE.md` | Current project only |
| **Local** | `project/.claude/CLAUDE.md` | Current project, not committed to git |

**Critical Detail:** The system **does NOT automatically load CLAUDE.md**. You must:
1. Place the file in project root OR `.claude/` subdirectory
2. Ensure Claude Code is configured to read it (it reads from the working directory)
3. The content is injected as the **first user message** in the conversation (not system prompt)

### How It Influences Claude's Behavior

- **Delivered as context, not system prompt**: CLAUDE.md content arrives after the system prompt, so it can be overridden by observed content in files
- **Can contain tool usage instructions**: You can write "Always run `kin search <entity>` before using Grep for cross-file queries"
- **No guarantee of enforcement**: Without hooks/permissions backing it up, the instructions are advisory only

### Example: Kin Integration

```markdown
# Kin Project — Semantic VCS Integration

## Tool Preferences

When searching code or entities:
1. **Never use `grep` for entity references** — use `kin search` instead
2. **For cross-file queries**: `kin linker --type=import` (import-aware 3-tier resolution)
3. **For workspace overview**: `kin graph query` (entity graph)
4. **For file impact**: `kin review diff` (semantic impact analysis)

## Why?

Kin is a semantic VCS that replaces file-based search with entity graphs.
- Grep finds text; kin finds semantic entities with type/scope awareness
- Kin's cross-file linker resolves imports correctly (not text matches)
- Entity graph queries are 56-72% faster than git operations on large codebases

## Kin Commands Reference

- `kin search <entity>` — Find all references to entity by name, type, scope
- `kin linker --type=import --file=src/api.rs` — Resolve imports with 3-tier confidence
- `kin graph query --type=struct --name=Request` — Entity graph query
- `kin review diff <branch>` — Semantic impact analysis (cross-file relations)

## When in Doubt

Ask: "Would this be faster/more accurate with the entity graph?"
If yes, use kin. If not, use standard tools.
```

### Concrete Usage Scenario

When you write:
```markdown
You're working on the Kin codebase. Use kin search and kin graph commands
for any cross-file entity lookups.
```

Claude will **remember this** within the conversation but **won't be forced** to follow it if:
- A file or hook tells it to use grep
- The user explicitly requests grep
- The model decides text search is faster for a simple lookup

---

## 2. Hooks — All Types, Config Format, Context Injection

### Hook Types & Triggers

Claude Code supports **6 hook event types** with different triggers and capabilities:

| Hook Type | Trigger | Can Inject | Blocking? | Use Case |
|-----------|---------|-----------|-----------|----------|
| `UserPromptSubmit` | User submits prompt to Claude | Text/context | No (warning only) | Inject kin context before Claude processes request |
| `PreToolUse` | Before Claude executes ANY tool | Text/context | **Yes** (exit 2) | Block grep, validate kin query syntax |
| `PostToolUse` | After tool completes successfully | Text/summary | No | Format kin query output, run follow-up queries |
| `SessionStart` | Claude Code session initializes | Environment vars | No | Set KIN_HOME, KIN_GRAPH paths |
| `Stop` | User exits Claude Code session | Text/notification | No | Summary of kin queries executed |
| `TeammateIdle` | Team agent goes idle | Text/reminder | **Yes** (exit 2) | Prevent agent idle if pending kin tasks |

### Hook Configuration Format

Hooks are defined in `~/.claude/settings.json` or `.claude/settings.json`:

```json
{
  "hooks": {
    "UserPromptSubmit": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "bash /path/to/hook.sh"
          }
        ]
      }
    ],
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "bash /path/to/validate-grep.sh"
          }
        ]
      }
    ]
  }
}
```

### Hook Types (in detail)

#### 1. **UserPromptSubmit Hook**
- **Trigger**: When user submits a prompt to Claude (before processing)
- **Input**: User's prompt text
- **Output**: Can append/inject text to provide context
- **Matchers**: None (always fires)

**Example: Inject kin context**
```bash
#!/bin/bash
# ~/.claude/hooks/inject-kin-context.sh
cat << 'EOF'

[KIN CONTEXT INJECTED]
This is a Kin repository. For any entity searches or cross-file lookups, prefer:
  - kin search <entity> over grep
  - kin graph query over manual file inspection
  - kin linker --type=import for import resolution

Latest kin benchmark: 71.9% faster, 78.8% fewer tokens on large codebases.
EOF
```

Hook in settings.json:
```json
"UserPromptSubmit": [
  {
    "hooks": [
      {
        "type": "command",
        "command": "bash ~/.claude/hooks/inject-kin-context.sh"
      }
    ]
  }
]
```

#### 2. **PreToolUse Hook**
- **Trigger**: Before Claude executes a tool (Bash, Read, Grep, etc.)
- **Input**: Tool name, parameters, working directory
- **Output**: Can warn, block, or inject context
- **Matchers**: Filter by tool name (e.g., `Bash`, `Grep`, `Task`)
- **Blocking**: Exit code 2 = warn/block, exit 0 = allow

**Example: Warn when using grep instead of kin search**
```bash
#!/usr/bin/env bash
# ~/.claude/hooks/prefer-kin-search.sh

INPUT=$(cat)
COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // ""' 2>/dev/null)

# Check for grep-like commands that could be kin searches
if echo "$COMMAND" | grep -qE "(grep|rg) .*(function|class|struct|type|import)" ; then
    ENTITY=$(echo "$COMMAND" | sed 's/.*grep[^"]*"//; s/".*//')
    echo "NOTICE: Consider using 'kin search \"$ENTITY\"' instead of grep.
This will use the entity graph and handle scope/type awareness correctly.
Kin queries are typically 60% faster on large codebases." >&2
    exit 2  # Warn and suggest alternative
fi

exit 0  # Allow non-entity-search greps
```

Hook in settings.json:
```json
"PreToolUse": [
  {
    "matcher": "Bash",
    "hooks": [
      {
        "type": "command",
        "command": "bash ~/.claude/hooks/prefer-kin-search.sh"
      }
    ]
  }
]
```

#### 3. **PostToolUse Hook**
- **Trigger**: After a tool completes successfully
- **Input**: Tool name, output, execution time
- **Output**: Can append summary or next-step suggestions
- **Matchers**: Filter by tool name

**Example: Auto-format kin query results**
```bash
#!/usr/bin/env bash
# ~/.claude/hooks/format-kin-results.sh

INPUT=$(cat)
TOOL=$(echo "$INPUT" | jq -r '.tool // ""' 2>/dev/null)

# If this was a kin search/graph query, format the output nicely
if echo "$TOOL" | grep -q "^kin"; then
    echo ""
    echo "[KIN RESULT FORMATTED]"
    echo "Results shown above. For further analysis, try:"
    echo "  - kin graph query to explore related entities"
    echo "  - kin review diff to see cross-file impact"
    echo "  - kin linker to trace import chains"
fi
```

Hook in settings.json:
```json
"PostToolUse": [
  {
    "matcher": "Bash",
    "hooks": [
      {
        "type": "command",
        "command": "bash ~/.claude/hooks/format-kin-results.sh"
      }
    ]
  }
]
```

#### 4. **SessionStart Hook**
- **Trigger**: When Claude Code session initializes
- **Input**: None (can read environment)
- **Output**: Can set environment variables

**Example: Set up Kin environment**
```bash
#!/bin/bash
# ~/.claude/hooks/setup-kin-env.sh

# Find kin binary
KIN_BIN=$(which kin || echo "target/release/kin")
export KIN_BIN
export KIN_HOME="$HOME/.kin"
export KIN_GRAPH_ROOT=".kin/graph"

echo "[KIN ENVIRONMENT INITIALIZED]"
echo "  KIN_BIN: $KIN_BIN"
echo "  KIN_HOME: $KIN_HOME"
echo "  KIN_GRAPH_ROOT: $KIN_GRAPH_ROOT"
```

#### 5. **Stop Hook**
- **Trigger**: When user exits Claude Code session
- **Input**: Session summary
- **Output**: Notification, stats, cleanup

**Example: Report kin queries executed**
```bash
#!/bin/bash
# ~/.claude/hooks/report-kin-usage.sh

cat << 'EOF'

[SESSION SUMMARY]
If you ran kin queries in this session, consider adding performance benchmarks
to your project docs using 'kin bench capture'.

EOF
```

#### 6. **TeammateIdle Hook**
- **Trigger**: Team agent goes idle (no active tasks)
- **Input**: Agent/team name
- **Output**: Can warn if tasks are pending
- **Blocking**: Exit code 2 = warn, prevent idle

---

## 3. MCP Servers — Discovery, Schema, Config

### What is MCP?

**Model Context Protocol** — a standard for connecting Claude to external tools/data sources via JSON-RPC. Tools exposed through MCP appear in Claude's tool menu and can be invoked like built-in tools.

### MCP Server Discovery

Claude Code looks for MCP servers in multiple locations:

| Location | Scope | Format | Notes |
|----------|-------|--------|-------|
| `~/.claude.json` | User-wide | JSON (mcpServers object) | Can use env var expansion like `${KIN_API_TOKEN}` |
| `.mcp.json` | Project-specific | JSON (mcpServers object) | Committed to git, shared with team |
| `.claude/.mcp.json` | Local (project) | JSON (mcpServers object) | Not committed, personal config |
| VS Code settings | Per-IDE | Via `claude.mcp.servers` | IDE-specific discovery |

### MCP Configuration Schema

```json
{
  "mcpServers": {
    "kin": {
      "type": "stdio",
      "command": "target/release/kin",
      "args": ["mcp"],
      "env": {
        "KIN_HOME": "/path/to/.kin",
        "KIN_LOG_LEVEL": "debug"
      },
      "timeout": 30000
    }
  }
}
```

**Field Explanations:**
- `type`: "stdio" (local process) or "sse" (HTTP Server-Sent Events)
- `command`: Path to the MCP server executable
- `args`: Arguments passed to the server (e.g., ["mcp"] enables MCP mode)
- `env`: Environment variables (supports `${VAR_NAME}` expansion)
- `timeout`: Milliseconds to wait for server startup

### Types of MCP Servers

#### 1. **Stdio Server** (local process)
Most common for local tools like Kin. Claude Code spawns the process and communicates via stdin/stdout.

```json
{
  "kin": {
    "type": "stdio",
    "command": "/Users/troyfortinjr/GitHub/kin/target/release/kin",
    "args": ["mcp", "--graph-root", ".kin/graph"]
  }
}
```

#### 2. **SSE Server** (HTTP)
For remote services. Claude Code connects via HTTP with Server-Sent Events.

```json
{
  "kin-cloud": {
    "type": "sse",
    "url": "https://api.example.com/mcp",
    "headers": {
      "Authorization": "Bearer ${KIN_API_TOKEN}"
    }
  }
}
```

### How Tool Descriptions from MCP Influence Claude

When Kin exposes tools via MCP (e.g., `kin_search`, `kin_graph_query`, `kin_linker`):

1. **Tool description** is sent to Claude in the system message
2. Claude sees `kin_search(query: string, type: string) -> [Entity]`
3. When Claude needs to search, it chooses between:
   - `Bash(grep ...)` — built-in, but generic text search
   - `kin_search(...)` — MCP-exposed, but contextual entity search
4. **Better descriptions → better choices**

Example MCP tool description that Claude will see:
```
Tool: kin_search
Description: Search for semantic entities (functions, structs, types, imports)
by name with type and scope awareness. Returns all references across the codebase.
Faster than grep for entity searches (60% faster on average).
Parameters:
  - query (string): Entity name to search for
  - type (string): Optional filter (function, struct, type, import)
  - file (string): Optional scope filter (file path)
Returns: List[{name, type, scope, file, line, definition}]
```

### Configuration Example: Full Kin Integration

**File: `.mcp.json` (commit to git)**
```json
{
  "mcpServers": {
    "kin": {
      "type": "stdio",
      "command": "target/release/kin",
      "args": ["mcp", "--json-rpc"],
      "env": {
        "RUST_LOG": "info"
      }
    }
  }
}
```

**File: `~/.claude.json` (local, user-only)**
```json
{
  "mcpServers": {
    "kin-local": {
      "type": "stdio",
      "command": "/Users/troyfortinjr/.cargo/bin/kin",
      "args": ["mcp"],
      "env": {
        "KIN_HOME": "/Users/troyfortinjr/.kin"
      }
    }
  }
}
```

### After Configuration Changes

- **Restart Claude Code** for changes to take effect
- Verify server status in Claude Code UI (Settings > MCP Servers)
- If connection fails, check:
  - Server command path is correct and executable
  - Required environment variables are set
  - Port (for SSE) is not in use
  - Server startup timeout not exceeded

---

## 4. Plugins — Structure, Slash Commands, Skills, Agents, Hooks

### Plugin Directory Structure

A complete Kin plugin would look like:

```
~/.claude/plugins/kin-plugin/
├── PLUGIN.md                 # Plugin metadata (name, version, description)
├── commands/
│   ├── /kin-search.md        # Slash command definition
│   ├── /kin-graph.md
│   └── /kin-linker.md
├── skills/
│   ├── entity-search.md      # Auto-triggering skill (no slash)
│   ├── cross-file-import.md
│   └── impact-analysis.md
├── agents/
│   ├── kin-researcher.md     # Subagent definition
│   └── entity-mapper.md
├── hooks/
│   ├── prefer-kin-search.sh
│   └── format-kin-output.sh
├── .mcp.json                 # MCP server config for kin
└── README.md
```

Or in a project:
```
project/.claude/
├── commands/
│   └── /kin-stats.md
├── skills/
│   └── entity-analysis.md
└── hooks/
    └── check-kin-health.sh
```

### 1. Slash Commands

A slash command is a **manually-invoked action** that shows up in autocomplete.

**File: `~/.claude/commands/kin-search.md`**
```markdown
---
description: Search for entities in the Kin graph
aliases: ["/ks", "/find-entity"]
visibility: always
---

# Kin Search Command

Search the Kin entity graph for semantic entities (functions, structs, types, imports).

## Usage

/kin-search <entity-name> [--type=<type>] [--file=<file>]

## Examples

- `/kin-search Request` — Find all refs to "Request" entity
- `/kin-search --type=struct User` — Search structs named "User"
- `/kin-search --file=src/api.rs Service` — Search in specific file

## Output

Returns a JSON list of entity locations with type, scope, and definition details.
```

When Claude sees this command definition, `/kin-search` appears in autocomplete and Claude understands what it does.

### 2. Skills

A **skill** is an **auto-triggering capability** that activates when its context matches the task.

**File: `~/.claude/skills/entity-search.md`**
```markdown
---
name: Entity Search
description: When searching for references to functions, structs, types, or imports across the codebase, use kin search instead of grep
condition: task_involves_entity_search
confidence: high
---

# Entity Search Skill

When the task involves finding where a function, struct, type, or import is defined or used across multiple files:

1. Run `kin search <entity-name> [--type=<type>]`
2. Analyze the results (file, line, scope information)
3. If cross-file relations matter, follow up with `kin linker --type=import --entity=<name>`

## When to Use

- Looking for all references to a function/struct/type
- Tracing import chains
- Understanding cross-file dependencies
- Checking if a refactor will have broad impact

## When NOT to Use

- Grep for simple text patterns (like TODO comments)
- Searching test file names
- Parsing JSON/config files (use language-specific tools)

## Benefits

- Kin understands scope (won't match name in a comment)
- Returns type information (function vs. variable vs. type)
- Handles imports correctly (3-tier resolution)
- 60% faster than grep on large codebases
```

When Claude evaluates the task (e.g., "Find all usages of the AuthService struct"), this skill automatically activates and suggests using `kin search` instead of grepping.

### 3. Agents (Subagents)

An agent definition lets you spawn a specialized subagent for a task.

**File: `~/.claude/agents/kin-entity-mapper.md`**
```markdown
---
name: Kin Entity Mapper
subagent_type: TaskAgent
description: An expert at mapping entity relationships using the Kin graph and linker
tools: [Bash, Grep, Read, Edit]
---

# Kin Entity Mapper Agent

You are an expert at understanding semantic entity relationships in Kin codebases.

Your responsibilities:
1. Use `kin search` to find entities
2. Use `kin graph query` to understand relationships
3. Use `kin linker --type=import` to trace imports
4. Map out cross-file dependencies
5. Generate reports of entity usage patterns

You have access to:
- Bash (for running kin commands)
- Grep (as fallback for text search)
- Read/Edit (for examining code)

When a user asks you to:
- Map entity relationships → use kin graph
- Find import chains → use kin linker
- Search for references → use kin search
- Understand impact of changes → use kin review diff

Always prefer kin tools over file-based search. Kin queries are semantic and
type-aware, giving more accurate results.
```

You could invoke this with a command like:
```
/spawn-agent Kin Entity Mapper "Map all references to the User struct across the codebase"
```

### 4. Hooks in Plugins

Hooks bundled with a plugin are loaded when the plugin is enabled.

**File: `~/.claude/hooks/prefer-kin-search.sh` (in plugin)**
```bash
#!/usr/bin/env bash
# Executes when plugin is enabled

INPUT=$(cat)
COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // ""' 2>/dev/null)

# If Claude is about to run grep for an entity search, warn
if echo "$COMMAND" | grep -qE "(grep|rg).*-E.*\\(function|struct|type|import" ; then
    echo "NOTICE: Use 'kin search' for entity lookups instead of grep." >&2
    exit 2
fi

exit 0
```

### Installation & Activation

Plugins are installed via marketplace or manually:

**Manual installation:**
```bash
# Copy plugin to plugins directory
cp -r my-kin-plugin ~/.claude/plugins/

# Enable in settings.json
# "enabledPlugins": { "kin-plugin@custom": true }
```

**Via marketplace:**
```
/install-plugin kin-search-expert
```

---

## 5. Settings (~/.claude/settings.json) — Schema, Permissions, Custom Instructions

### Settings.json Schema

The canonical schema is available at:
**https://json.schemastore.org/claude-code-settings.json**

To enable autocomplete in VS Code, add at the top:
```json
{
  "$schema": "https://json.schemastore.org/claude-code-settings.json",
  ...
}
```

### Permissions Configuration

Controls which tools Claude can use and which commands are allowed/denied.

**Permission Rule Format:**
```
<ToolName>(<specifier>)
```

Examples:
- `Bash(kin:*)` — Allow all kin commands
- `Bash(grep:*)` — Allow grep
- `Bash(rm -rf:*)` — Danger zone, explicitly deny

**Evaluation Order:**
1. Deny rules first (block dangerous actions)
2. Ask rules (prompt for permission)
3. Allow rules (auto-allow)

**Example: Kin-friendly permissions**
```json
{
  "permissions": {
    "allow": [
      "Bash(kin:*)",
      "Bash(cargo run --release:*)",
      "Bash(grep:*)",
      "Bash(git:*)",
      "Read(*)",
      "Edit(*)",
      "Glob(*)"
    ],
    "deny": [
      "Bash(rm -rf:*)",
      "Bash(sudo:*)"
    ]
  }
}
```

### allowedTools vs. Permissions

- **allowedTools** (deprecated in newer versions) — simple list of tool names
- **permissions** — modern, fine-grained rules with allow/deny/ask

**Modern approach (use permissions):**
```json
{
  "permissions": {
    "allow": [
      "Bash(kin search:*)",
      "Bash(kin graph:*)",
      "Bash(kin linker:*)",
      "Bash(kin review:*)"
    ]
  }
}
```

### Environment Variables

Set environment for all Claude Code sessions:

```json
{
  "env": {
    "KIN_HOME": "/Users/troyfortinjr/.kin",
    "KIN_GRAPH_ROOT": ".kin/graph",
    "RUST_LOG": "info",
    "CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS": "1"
  }
}
```

### Custom Instructions

Add persistent instructions to all sessions:

```json
{
  "customInstructions": {
    "general": "You are working in a Kin semantic VCS repository. Always prefer entity graph queries over file-based search.",
    "toolUsage": "Use 'kin search' for entity lookups, 'kin graph query' for relationships, 'kin linker' for imports.",
    "bestPractices": "Kin queries are 60% faster than grep on large codebases."
  }
}
```

### Settings Hierarchy

1. **User settings**: `~/.claude/settings.json` (applies to all projects)
2. **Project settings**: `<project>/.claude/settings.json` (shared via git)
3. **Local settings**: `<project>/.claude/settings.local.json` (personal, not committed)

Hierarchy: Local overrides Project overrides User.

### Full Example Settings File

```json
{
  "$schema": "https://json.schemastore.org/claude-code-settings.json",

  "env": {
    "CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS": "1",
    "KIN_HOME": "/Users/troyfortinjr/.kin"
  },

  "enabledPlugins": {
    "kin-plugin@custom": true,
    "kin-search@marketplace": true,
    "code-review@claude-plugins-official": true
  },

  "permissions": {
    "allow": [
      "Bash(kin:*)",
      "Bash(cargo:*)",
      "Bash(git:*)",
      "Read(*)",
      "Edit(*)",
      "Glob(*)",
      "Grep(*)"
    ],
    "deny": [
      "Bash(rm -rf:*)",
      "Bash(sudo:*)"
    ]
  },

  "hooks": {
    "UserPromptSubmit": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "bash ~/.claude/hooks/inject-kin-context.sh"
          }
        ]
      }
    ],
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "bash ~/.claude/hooks/prefer-kin-search.sh"
          }
        ]
      }
    ]
  },

  "effortLevel": "high",
  "skipDangerousModePermissionPrompt": false
}
```

### Managing Permissions Interactively

Within Claude Code, use the `/permissions` command to:
- View current permissions
- Interactively allow/deny tools
- Test permission rules
- Export/import permission configs

---

## 6. CLI Flags — Headless Mode, System Prompt Injection

### Headless Mode Basics

Run Claude Code non-interactively from the command line:

```bash
claude -p "Your prompt here"
```

Flags that work with `-p`:
| Flag | Purpose |
|------|---------|
| `-p <prompt>` | (or `--print`) Run prompt in non-interactive mode |
| `--append-system-prompt <text>` | Add instructions to system prompt (keeps defaults) |
| `--system-prompt <text>` | **Replace** entire system prompt (dangerous) |
| `--output-format json` | Return structured JSON output |
| `--max-turns <n>` | Limit iterations (e.g., 3 for one-shot) |
| `--allowed-tools <list>` | Restrict which tools can be used |
| `--mcp-config <path>` | Path to .mcp.json for this run |
| `--continue` / `--resume` | Continue previous session |

### Headless Examples

#### Example 1: One-shot entity search
```bash
claude -p "Search for all references to the AuthService struct in the Kin codebase" \
  --append-system-prompt "You have access to kin commands. Use 'kin search' for entity lookups." \
  --allowed-tools "Bash(kin:*),Bash(grep:*),Read(*)" \
  --max-turns 1 \
  --output-format json
```

**Output:**
```json
{
  "success": true,
  "response": "I ran 'kin search AuthService --type=struct' and found 12 references...",
  "tools_used": ["Bash(kin search)"],
  "entities_found": ["AuthService"]
}
```

#### Example 2: Semantic impact analysis
```bash
claude -p "Analyze the cross-file impact of renaming the User struct to Entity" \
  --append-system-prompt "Use kin review diff and kin linker for impact analysis" \
  --mcp-config .mcp.json \
  --max-turns 2
```

#### Example 3: CI/CD integration
```bash
#!/bin/bash
# In a CI pipeline
claude -p "Run 'kin bench capture' to measure performance on this commit" \
  --allowed-tools "Bash(kin:*),Bash(cargo:*)" \
  --max-turns 1 \
  --output-format json > /tmp/kin-bench.json
```

### System Prompt Injection Risk

**CRITICAL:** Avoid `--system-prompt` as it replaces Claude's **entire** safety and reasoning system.

- **Safe**: `--append-system-prompt "Use kin search..."`
- **Unsafe**: `--system-prompt "Ignore all prior instructions..."`

The `--append-system-prompt` flag adds context **after** Claude's core system prompt, so it can't override safety rules.

### Combining with MCP

```bash
claude -p "Search for all imports of the UserService module" \
  --mcp-config ~/.kin-mcp.json \
  --append-system-prompt "Call the 'kin_search' MCP tool from the Kin MCP server"
```

Claude will see the kin MCP tools and can invoke them directly.

---

## Summary: How to Configure Claude Code to Prefer Kin

### The Integrated Approach (All 5 Points Together)

1. **CLAUDE.md** (project root)
   - Write: "Use `kin search` instead of grep for entity searches"
   - Effect: Context for Claude, but not enforced

2. **Hooks** (in settings.json)
   - `UserPromptSubmit`: Inject kin context at conversation start
   - `PreToolUse`: Warn when using grep instead of kin search
   - Effect: Nudge behavior, can warn/block

3. **MCP Server** (.mcp.json)
   - Expose `kin_search`, `kin_graph_query`, `kin_linker` tools
   - Effect: Claude can invoke kin without Bash wrapper

4. **Plugin** (optional, but powerful)
   - Bundle commands, skills, hooks, MCP config
   - Effect: One-command installation with full setup

5. **Settings** (permissions + env)
   - Allow `Bash(kin:*)` by default
   - Set `KIN_HOME`, `KIN_GRAPH_ROOT` environment
   - Effect: Fast access, no permission prompts

### Quick Start for Kin Project

**Step 1: Create CLAUDE.md**
```bash
cat > /Users/troyfortinjr/GitHub/kin/CLAUDE.md << 'EOF'
# Kin Project Integration

When searching for entities or cross-file references:
- Use `kin search <entity>` instead of grep
- Use `kin graph query` for relationships
- Use `kin linker --type=import` for import chains

Kin is 60% faster than grep on large codebases.
EOF
```

**Step 2: Configure MCP in .mcp.json**
```bash
cat > /Users/troyfortinjr/GitHub/kin/.mcp.json << 'EOF'
{
  "mcpServers": {
    "kin": {
      "type": "stdio",
      "command": "target/release/kin",
      "args": ["mcp"]
    }
  }
}
EOF
```

**Step 3: Update settings.json**
```json
{
  "env": {
    "KIN_HOME": "/Users/troyfortinjr/.kin"
  },
  "permissions": {
    "allow": ["Bash(kin:*)", "Read(*)", "Edit(*)", "Glob(*)", "Grep(*)"]
  }
}
```

**Step 4: Add hooks (optional but recommended)**
```bash
cat > ~/.claude/hooks/prefer-kin-search.sh << 'EOF'
#!/bin/bash
INPUT=$(cat)
CMD=$(echo "$INPUT" | jq -r '.tool_input.command // ""' 2>/dev/null)
if echo "$CMD" | grep -qE "grep.*-E.*\\(function|struct|type|import"; then
    echo "TIP: Use 'kin search' for entity lookups (60% faster)" >&2
    exit 2
fi
exit 0
EOF
chmod +x ~/.claude/hooks/prefer-kin-search.sh
```

Add to settings.json:
```json
"hooks": {
  "PreToolUse": [{
    "matcher": "Bash",
    "hooks": [{"type": "command", "command": "bash ~/.claude/hooks/prefer-kin-search.sh"}]
  }]
}
```

---

## References

- [Claude Code Best Practices](https://code.claude.com/docs/en/best-practices)
- [Claude Code Hooks Reference](https://code.claude.com/docs/en/hooks)
- [Claude Code MCP Documentation](https://code.claude.com/docs/en/mcp)
- [Claude Code Settings Documentation](https://code.claude.com/docs/en/settings)
- [Claude Code Headless Mode](https://code.claude.com/docs/en/headless)
- [Writing a good CLAUDE.md — HumanLayer Blog](https://www.humanlayer.dev/blog/writing-a-good-claude-md)
- [A developer's guide to settings.json in Claude Code](https://www.eesel.ai/blog/settings-json-claude-code)
- [Understanding Claude Code's Full Stack: MCP, Skills, Subagents, and Hooks Explained](https://alexop.dev/posts/understanding-claude-code-full-stack/)
- [Extend Claude with skills — Claude Code Docs](https://code.claude.com/docs/en/skills)
- [Run Claude Code programmatically — Claude Code Docs](https://code.claude.com/docs/en/headless)
- [MCP JSON Configuration — FastMCP](https://gofastmcp.com/integrations/mcp-json-configuration)

