# Kin MCP Tool Reference

Legacy reference for the MCP tools exposed by `kin mcp start`. The current codebase exposes 48 tools; treat `kin/crates/kin-mcp/src/tools.rs` as the source of truth if this snapshot drifts.

Start the server: `kin mcp start` (stdio transport).

All examples use JSON-RPC 2.0 over stdio. Pipe them to `kin mcp start`:

```bash
echo '<json>' | kin mcp start
```

---

## Core Analysis (12 tools)

### `semantic_search`

Search the semantic code graph for entities (functions, classes, types, traits, constants) by name, kind, or language. Returns exact file:line locations, signatures, and entity IDs. Faster and more precise than text search -- matches parsed declarations, not string occurrences.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `query` | string | yes | -- | Name pattern to search for |
| `kind` | string | no | -- | Entity kind filter (function, class, etc.) |
| `language` | string | no | -- | Language filter (rust, typescript, etc.) |
| `limit` | integer | no | 20 | Max results to return |
| `compact` | boolean | no | true | If true, return only id/name/kind/language/file_path/start_line/end_line/signature. If false, also include doc_summary |

**Example -- find all functions named "auth":**

```json
{
  "jsonrpc": "2.0", "id": 1,
  "method": "tools/call",
  "params": {
    "name": "semantic_search",
    "arguments": { "query": "auth", "kind": "function", "limit": 5 }
  }
}
```

**Example -- find all Rust traits:**

```json
{
  "jsonrpc": "2.0", "id": 2,
  "method": "tools/call",
  "params": {
    "name": "semantic_search",
    "arguments": { "query": "Store", "kind": "trait", "language": "rust" }
  }
}
```

---

### `get_entity`

Retrieve a specific entity by ID. Returns full entity metadata including kind, language, file path, line range, and signature.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `entity_id` | string | yes | Entity UUID |

**Example -- retrieve full metadata for an entity found via `semantic_search`:**

```json
{
  "jsonrpc": "2.0", "id": 1,
  "method": "tools/call",
  "params": {
    "name": "get_entity",
    "arguments": { "entity_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890" }
  }
}
```

---

### `get_context_pack`

Build a focused context pack for an entity -- returns the entity's source body plus nearby dependencies within a token budget. One call replaces reading multiple files when you need implementation context.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `entity_id` | string | yes | -- | Focal entity UUID |
| `token_budget` | integer | no | 16000 | Token budget (8000, 16000, or 32000) |
| `depth` | integer | no | 2 | Dependency traversal depth |
| `include_traffic` | boolean | no | true | Include active nearby agent traffic in response |
| `compact` | boolean | no | false | If true, all entities returned as SignatureOnly (~2-5KB). If false, focal gets FullBody, deps get SignatureOnly, transitive get NameAndKind |

**Example -- get full implementation context for a function with a small budget:**

```json
{
  "jsonrpc": "2.0", "id": 1,
  "method": "tools/call",
  "params": {
    "name": "get_context_pack",
    "arguments": {
      "entity_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "token_budget": 8000,
      "depth": 1
    }
  }
}
```

**Example -- compact signatures only (for quick overview):**

```json
{
  "jsonrpc": "2.0", "id": 2,
  "method": "tools/call",
  "params": {
    "name": "get_context_pack",
    "arguments": {
      "entity_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "compact": true,
      "include_traffic": false
    }
  }
}
```

---

### `find_references`

Find direct upstream callers/importers/references for an entity. Accepts either an entity_id or an exact query name, resolves the best matching canonical definition, and returns one row per upstream file with relation kinds and file paths.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `entity_id` | string | no | Exact entity UUID. Optional if query is provided |
| `query` | string | no | Exact symbol name to resolve. Optional if entity_id is provided |
| `relation_kinds` | string[] | no | Filter relation kinds. Supported: `calls`, `imports`, `references`. Defaults to all three |

At least one of `entity_id` or `query` must be provided.

**Example -- find all callers of a function by name:**

```json
{
  "jsonrpc": "2.0", "id": 1,
  "method": "tools/call",
  "params": {
    "name": "find_references",
    "arguments": { "query": "handle_request" }
  }
}
```

**Example -- find only imports of a specific entity:**

```json
{
  "jsonrpc": "2.0", "id": 2,
  "method": "tools/call",
  "params": {
    "name": "find_references",
    "arguments": {
      "entity_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "relation_kinds": ["imports"]
    }
  }
}
```

---

### `impact_analysis`

Analyze downstream impact of changes between two semantic change IDs. Shows all affected entities, contracts, and tests -- traces the full call graph automatically.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `base` | string | yes | -- | Base semantic change ID (hex) |
| `head` | string | yes | -- | Head semantic change ID (hex) |
| `include_traffic` | boolean | no | true | Include active traffic on impacted entities |

**Example -- analyze impact between two commits (use change IDs from `kin log`):**

```json
{
  "jsonrpc": "2.0", "id": 1,
  "method": "tools/call",
  "params": {
    "name": "impact_analysis",
    "arguments": {
      "base": "abc123def456",
      "head": "789012fed345"
    }
  }
}
```

**Example -- impact without traffic overlay (faster):**

```json
{
  "jsonrpc": "2.0", "id": 2,
  "method": "tools/call",
  "params": {
    "name": "impact_analysis",
    "arguments": {
      "base": "abc123def456",
      "head": "789012fed345",
      "include_traffic": false
    }
  }
}
```

---

### `semantic_diff`

Compute entity-level diff between two semantic changes. Shows which entities were added, modified, or removed -- structured by declaration, not raw line changes.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `base` | string | yes | Base semantic change ID (hex) |
| `head` | string | yes | Head semantic change ID (hex) |

**Example -- see what entities changed between two commits:**

```json
{
  "jsonrpc": "2.0", "id": 1,
  "method": "tools/call",
  "params": {
    "name": "semantic_diff",
    "arguments": {
      "base": "abc123def456",
      "head": "789012fed345"
    }
  }
}
```

---

### `semantic_review`

Full semantic review: diff + impact + risk assessment. The most comprehensive analysis tool -- combines entity-level diff, downstream impact analysis, and risk scoring in one call.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `base` | string | yes | -- | Base semantic change ID (hex) |
| `head` | string | yes | -- | Head semantic change ID (hex) |
| `include_traffic` | boolean | no | true | Include active traffic on reviewed entities |

**Example -- full review of a change (the "one call to rule them all"):**

```json
{
  "jsonrpc": "2.0", "id": 1,
  "method": "tools/call",
  "params": {
    "name": "semantic_review",
    "arguments": {
      "base": "abc123def456",
      "head": "789012fed345"
    }
  }
}
```

---

### `dead_code`

Find dead/unreachable code in the semantic graph. Without filters, returns entities with no incoming relations. For task-scoped checks, pass `files` to return only dead functions/classes from those files, ignoring same-file references.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `limit` | integer | no | 50 | Max results |
| `files` | string[] | no | -- | Optional repo-relative file paths. When provided, returns only dead functions/classes from those files |

**Example -- find all dead code in the repo (top 10):**

```json
{
  "jsonrpc": "2.0", "id": 1,
  "method": "tools/call",
  "params": {
    "name": "dead_code",
    "arguments": { "limit": 10 }
  }
}
```

**Example -- check specific files for dead code after a refactor:**

```json
{
  "jsonrpc": "2.0", "id": 2,
  "method": "tools/call",
  "params": {
    "name": "dead_code",
    "arguments": {
      "files": ["src/handlers/auth.rs", "src/handlers/session.rs"]
    }
  }
}
```

---

### `entity_history`

Get the change history of a specific entity.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `entity_id` | string | yes | Entity UUID |

**Example -- trace the history of a function across commits:**

```json
{
  "jsonrpc": "2.0", "id": 1,
  "method": "tools/call",
  "params": {
    "name": "entity_history",
    "arguments": { "entity_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890" }
  }
}
```

---

### `graph_neighborhood`

Get the dependency neighborhood of an entity -- what it depends on and what depends on it. Traverses the semantic relation graph (calls, imports, implements) to the specified depth.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `entity_id` | string | yes | -- | Entity UUID |
| `depth` | integer | no | 2 | Traversal depth |
| `limit` | integer | no | 30 | Max entities to return |

**Example -- see immediate dependencies (depth 1):**

```json
{
  "jsonrpc": "2.0", "id": 1,
  "method": "tools/call",
  "params": {
    "name": "graph_neighborhood",
    "arguments": {
      "entity_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "depth": 1,
      "limit": 15
    }
  }
}
```

**Example -- wide neighborhood for architecture mapping:**

```json
{
  "jsonrpc": "2.0", "id": 2,
  "method": "tools/call",
  "params": {
    "name": "graph_neighborhood",
    "arguments": {
      "entity_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "depth": 3,
      "limit": 50
    }
  }
}
```

---

### `benchmark`

Get benchmark results and metrics.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `category` | string | no | Metric category: `velocity`, `reliability`, or `economic` |

**Example -- get velocity metrics:**

```json
{
  "jsonrpc": "2.0", "id": 1,
  "method": "tools/call",
  "params": {
    "name": "benchmark",
    "arguments": { "category": "velocity" }
  }
}
```

**Example -- get all benchmark categories:**

```json
{
  "jsonrpc": "2.0", "id": 2,
  "method": "tools/call",
  "params": {
    "name": "benchmark",
    "arguments": {}
  }
}
```

---

### `explore_codebase`

One-shot codebase exploration -- replaces multi-round-trip MCP calls with a single request. Use `overview` for entity counts and top declarations, `search` to find entities and their context packs, or `trace` to follow an ordered call chain from a matched entity with real source bodies and imported constants.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `query` | string | yes | -- | Natural language question or entity name to explore |
| `strategy` | string | no | `search` | Exploration strategy: `overview`, `search`, or `trace` |
| `token_budget` | integer | no | 8000 | Max response tokens |

**Example -- get a high-level overview of the codebase:**

```json
{
  "jsonrpc": "2.0", "id": 1,
  "method": "tools/call",
  "params": {
    "name": "explore_codebase",
    "arguments": { "query": "project structure", "strategy": "overview" }
  }
}
```

**Example -- search for entities and get context packs:**

```json
{
  "jsonrpc": "2.0", "id": 2,
  "method": "tools/call",
  "params": {
    "name": "explore_codebase",
    "arguments": { "query": "authentication handler", "strategy": "search" }
  }
}
```

**Example -- trace a call chain from an entry point:**

```json
{
  "jsonrpc": "2.0", "id": 3,
  "method": "tools/call",
  "params": {
    "name": "explore_codebase",
    "arguments": {
      "query": "handle_request",
      "strategy": "trace",
      "token_budget": 16000
    }
  }
}
```

---

## Session / Intent / Traffic (7 tools)

### `register_session`

Register an assistant session with Kin (legacy, prefer `kin_session_start`).

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `assistant_name` | string | yes | Name of the assistant (e.g. claude-code, codex) |
| `session_id` | string | no | Unique session identifier |

**Example:**

```json
{
  "jsonrpc": "2.0", "id": 1,
  "method": "tools/call",
  "params": {
    "name": "register_session",
    "arguments": { "assistant_name": "claude-code" }
  }
}
```

---

### `kin_session_start`

Start a rich agent session with capabilities, transport, and vendor info.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `vendor` | string | yes | -- | Vendor identifier (claude-code, codex, gemini-cli, etc.) |
| `client_name` | string | yes | -- | Human-readable client name |
| `cwd` | string | yes | -- | Working directory of the agent |
| `transport` | string | no | `mcp` | Connection type: `mcp`, `cli`, `wrapper`, or `ui` |
| `pid` | integer | no | -- | OS process ID of the agent |
| `capabilities` | object | no | -- | Agent capabilities object |

Capabilities object:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `can_read` | boolean | true | Can read files |
| `can_write` | boolean | false | Can write files |
| `can_execute` | boolean | false | Can execute commands |
| `can_branch` | boolean | false | Can create branches |
| `can_commit` | boolean | false | Can create commits |
| `max_concurrent_intents` | integer | 1 | Max concurrent intents |

**Example -- start a read-only session:**

```json
{
  "jsonrpc": "2.0", "id": 1,
  "method": "tools/call",
  "params": {
    "name": "kin_session_start",
    "arguments": {
      "vendor": "claude-code",
      "client_name": "Claude Code",
      "cwd": "/home/user/my-project"
    }
  }
}
```

**Example -- start a session with full write capabilities:**

```json
{
  "jsonrpc": "2.0", "id": 2,
  "method": "tools/call",
  "params": {
    "name": "kin_session_start",
    "arguments": {
      "vendor": "codex",
      "client_name": "Codex CLI",
      "cwd": "/home/user/my-project",
      "transport": "cli",
      "pid": 12345,
      "capabilities": {
        "can_read": true,
        "can_write": true,
        "can_execute": true,
        "can_branch": true,
        "can_commit": true,
        "max_concurrent_intents": 3
      }
    }
  }
}
```

---

### `kin_session_heartbeat`

Send a heartbeat to keep an agent session alive.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session UUID |

**Example -- keep a session alive (call periodically):**

```json
{
  "jsonrpc": "2.0", "id": 1,
  "method": "tools/call",
  "params": {
    "name": "kin_session_heartbeat",
    "arguments": { "session_id": "550e8400-e29b-41d4-a716-446655440000" }
  }
}
```

---

### `kin_session_end`

End an agent session and release all its intents.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session UUID |

**Example:**

```json
{
  "jsonrpc": "2.0", "id": 1,
  "method": "tools/call",
  "params": {
    "name": "kin_session_end",
    "arguments": { "session_id": "550e8400-e29b-41d4-a716-446655440000" }
  }
}
```

---

### `kin_register_intent`

Declare what scopes the agent intends to modify, enabling collision detection.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `session_id` | string | yes | -- | Session UUID |
| `scopes` | object[] | yes | -- | Target scopes: `[{"Entity": "uuid"}, {"Contract": "uuid"}, {"Artifact": "path"}]` |
| `task_description` | string | yes | -- | What the agent plans to do |
| `lock_type` | string | no | `soft` | Lock strength: `soft` or `hard` |
| `expires_at` | string | no | -- | Optional ISO 8601 expiry timestamp |

**Example -- declare intent to modify a function (soft lock):**

```json
{
  "jsonrpc": "2.0", "id": 1,
  "method": "tools/call",
  "params": {
    "name": "kin_register_intent",
    "arguments": {
      "session_id": "550e8400-e29b-41d4-a716-446655440000",
      "scopes": [
        { "Entity": "a1b2c3d4-e5f6-7890-abcd-ef1234567890" }
      ],
      "task_description": "Refactoring authentication handler for OAuth2 support"
    }
  }
}
```

**Example -- hard lock on a file with expiry:**

```json
{
  "jsonrpc": "2.0", "id": 2,
  "method": "tools/call",
  "params": {
    "name": "kin_register_intent",
    "arguments": {
      "session_id": "550e8400-e29b-41d4-a716-446655440000",
      "scopes": [
        { "Artifact": "src/auth/middleware.ts" }
      ],
      "task_description": "Rewriting auth middleware",
      "lock_type": "hard",
      "expires_at": "2026-03-25T18:00:00Z"
    }
  }
}
```

---

### `kin_release_intent`

Release a previously registered intent.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `session_id` | string | yes | Session UUID |
| `intent_id` | string | yes | Intent UUID to release |

**Example:**

```json
{
  "jsonrpc": "2.0", "id": 1,
  "method": "tools/call",
  "params": {
    "name": "kin_release_intent",
    "arguments": {
      "session_id": "550e8400-e29b-41d4-a716-446655440000",
      "intent_id": "660f9500-f3ac-52e5-b827-557766551111"
    }
  }
}
```

---

### `kin_check_traffic`

Check what agents are actively working on or near given scopes.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `scopes` | object[] | yes | Target scopes to check: `[{"Entity": "uuid"}, {"Contract": "uuid"}, {"Artifact": "path"}]` |

**Example -- check if anyone is working on a file before starting:**

```json
{
  "jsonrpc": "2.0", "id": 1,
  "method": "tools/call",
  "params": {
    "name": "kin_check_traffic",
    "arguments": {
      "scopes": [
        { "Artifact": "src/auth/middleware.ts" },
        { "Entity": "a1b2c3d4-e5f6-7890-abcd-ef1234567890" }
      ]
    }
  }
}
```

---

## Work Graph (12 tools)

### `kin_work_create`

Create a new work item (feature, task, issue, debt, todo, investigation).

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `kind` | string | yes | Work kind: `feature`, `task`, `issue`, `debt`, `todo`, `investigation` |
| `title` | string | yes | Work item title |
| `description` | string | no | Detailed description |
| `scopes` | string[] | no | Semantic scopes: `entity:<uuid>`, `contract:<uuid>`, `artifact:<path>` |
| `acceptance_criteria` | string[] | no | List of acceptance criteria |

**Example -- create a feature with scopes and acceptance criteria:**

```json
{
  "jsonrpc": "2.0", "id": 1,
  "method": "tools/call",
  "params": {
    "name": "kin_work_create",
    "arguments": {
      "kind": "feature",
      "title": "Add OAuth2 support to auth middleware",
      "description": "Replace basic auth with OAuth2 bearer tokens",
      "scopes": [
        "artifact:src/auth/middleware.ts",
        "entity:a1b2c3d4-e5f6-7890-abcd-ef1234567890"
      ],
      "acceptance_criteria": [
        "Bearer token validation works end-to-end",
        "Existing basic auth tests still pass",
        "Token refresh is handled transparently"
      ]
    }
  }
}
```

**Example -- create a simple todo:**

```json
{
  "jsonrpc": "2.0", "id": 2,
  "method": "tools/call",
  "params": {
    "name": "kin_work_create",
    "arguments": {
      "kind": "todo",
      "title": "Remove deprecated session handler"
    }
  }
}
```

---

### `kin_work_list`

List work items with optional status and kind filters.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `status` | string | no | Filter by status: `proposed`, `planned`, `in_progress`, `blocked`, `done`, `verified`, `archived` |
| `kind` | string | no | Filter by kind: `feature`, `task`, `issue`, `debt`, `todo`, `investigation` |
| `scope` | string | no | Filter by scope |

**Example -- list all in-progress work:**

```json
{
  "jsonrpc": "2.0", "id": 1,
  "method": "tools/call",
  "params": {
    "name": "kin_work_list",
    "arguments": { "status": "in_progress" }
  }
}
```

**Example -- list all open issues:**

```json
{
  "jsonrpc": "2.0", "id": 2,
  "method": "tools/call",
  "params": {
    "name": "kin_work_list",
    "arguments": { "kind": "issue" }
  }
}
```

**Example -- list all work items (no filters):**

```json
{
  "jsonrpc": "2.0", "id": 3,
  "method": "tools/call",
  "params": {
    "name": "kin_work_list",
    "arguments": {}
  }
}
```

---

### `kin_work_show`

Show full details of a work item including parents, children, blockers, implementors, and attached annotations.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `work_id` | string | yes | Work item UUID |

**Example:**

```json
{
  "jsonrpc": "2.0", "id": 1,
  "method": "tools/call",
  "params": {
    "name": "kin_work_show",
    "arguments": { "work_id": "b2c3d4e5-f6a7-8901-bcde-f23456789012" }
  }
}
```

---

### `kin_work_link`

Link a work item to semantic scopes (entities, contracts, artifacts).

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `work_id` | string | yes | Work item UUID |
| `scopes` | string[] | yes | Scopes to link |

**Example -- link a work item to the files and entities it affects:**

```json
{
  "jsonrpc": "2.0", "id": 1,
  "method": "tools/call",
  "params": {
    "name": "kin_work_link",
    "arguments": {
      "work_id": "b2c3d4e5-f6a7-8901-bcde-f23456789012",
      "scopes": [
        "artifact:src/auth/middleware.ts",
        "entity:a1b2c3d4-e5f6-7890-abcd-ef1234567890"
      ]
    }
  }
}
```

---

### `kin_work_decompose`

Link a parent work item to a child work item.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `parent_work_id` | string | yes | Parent work item UUID |
| `child_work_id` | string | yes | Child work item UUID |

**Example -- break a feature into sub-tasks:**

```json
{
  "jsonrpc": "2.0", "id": 1,
  "method": "tools/call",
  "params": {
    "name": "kin_work_decompose",
    "arguments": {
      "parent_work_id": "b2c3d4e5-f6a7-8901-bcde-f23456789012",
      "child_work_id": "c3d4e5f6-a7b8-9012-cdef-345678901234"
    }
  }
}
```

---

### `kin_work_block`

Mark one work item as blocked by another.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `blocked_work_id` | string | yes | Blocked work item UUID |
| `blocker_work_id` | string | yes | Blocking work item UUID |

**Example -- mark a feature as blocked by a dependency:**

```json
{
  "jsonrpc": "2.0", "id": 1,
  "method": "tools/call",
  "params": {
    "name": "kin_work_block",
    "arguments": {
      "blocked_work_id": "b2c3d4e5-f6a7-8901-bcde-f23456789012",
      "blocker_work_id": "d4e5f6a7-b8c9-0123-defa-456789012345"
    }
  }
}
```

---

### `kin_work_implement`

Link semantic scopes that implement a work item.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `work_id` | string | yes | Work item UUID |
| `scopes` | string[] | yes | Implementing scopes |

**Example -- record which entities implement a feature:**

```json
{
  "jsonrpc": "2.0", "id": 1,
  "method": "tools/call",
  "params": {
    "name": "kin_work_implement",
    "arguments": {
      "work_id": "b2c3d4e5-f6a7-8901-bcde-f23456789012",
      "scopes": [
        "entity:a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "entity:e5f6a7b8-c9d0-1234-efab-567890123456"
      ]
    }
  }
}
```

---

### `kin_work_status`

Update a work item status.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `work_id` | string | yes | Work item UUID |
| `status` | string | yes | New status: `proposed`, `planned`, `in_progress`, `blocked`, `done`, `verified`, `archived` |

**Example -- move a task to in-progress:**

```json
{
  "jsonrpc": "2.0", "id": 1,
  "method": "tools/call",
  "params": {
    "name": "kin_work_status",
    "arguments": {
      "work_id": "b2c3d4e5-f6a7-8901-bcde-f23456789012",
      "status": "in_progress"
    }
  }
}
```

**Example -- mark a task as done:**

```json
{
  "jsonrpc": "2.0", "id": 2,
  "method": "tools/call",
  "params": {
    "name": "kin_work_status",
    "arguments": {
      "work_id": "b2c3d4e5-f6a7-8901-bcde-f23456789012",
      "status": "done"
    }
  }
}
```

---

### `kin_annotation_add`

Add a semantic annotation (comment, warning, instruction, reasoning) to scopes or work items.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `kind` | string | yes | Annotation kind: `comment`, `warning`, `instruction`, `reasoning` |
| `body` | string | yes | Annotation text |
| `targets` | string[] | no | Target scopes or work items: `entity:<uuid>`, `contract:<uuid>`, `artifact:<path>`, `change:<id>`, `work:<uuid>` |
| `scopes` | string[] | no | Legacy alias for scope-only targets |

**Example -- add a warning annotation to an entity:**

```json
{
  "jsonrpc": "2.0", "id": 1,
  "method": "tools/call",
  "params": {
    "name": "kin_annotation_add",
    "arguments": {
      "kind": "warning",
      "body": "This function has O(n^2) complexity -- consider optimizing before adding more callers",
      "targets": ["entity:a1b2c3d4-e5f6-7890-abcd-ef1234567890"]
    }
  }
}
```

**Example -- add reasoning to a work item:**

```json
{
  "jsonrpc": "2.0", "id": 2,
  "method": "tools/call",
  "params": {
    "name": "kin_annotation_add",
    "arguments": {
      "kind": "reasoning",
      "body": "Chose OAuth2 over API keys because the existing middleware already handles token refresh",
      "targets": ["work:b2c3d4e5-f6a7-8901-bcde-f23456789012"]
    }
  }
}
```

---

### `kin_annotation_list`

List annotations for given scopes or work items.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `targets` | string[] | no | -- | Targets to query: `entity:<uuid>`, `contract:<uuid>`, `artifact:<path>`, `change:<id>`, `work:<uuid>` |
| `scopes` | string[] | no | -- | Legacy alias for scope-only targets |
| `include_stale` | boolean | no | true | Include stale annotations |

**Example -- list all annotations on an entity:**

```json
{
  "jsonrpc": "2.0", "id": 1,
  "method": "tools/call",
  "params": {
    "name": "kin_annotation_list",
    "arguments": {
      "targets": ["entity:a1b2c3d4-e5f6-7890-abcd-ef1234567890"]
    }
  }
}
```

**Example -- list fresh annotations only (exclude stale):**

```json
{
  "jsonrpc": "2.0", "id": 2,
  "method": "tools/call",
  "params": {
    "name": "kin_annotation_list",
    "arguments": {
      "targets": ["artifact:src/auth/middleware.ts"],
      "include_stale": false
    }
  }
}
```

---

### `kin_annotation_mark_resolved`

Mark an annotation as resolved (removes it).

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `annotation_id` | string | yes | Annotation UUID |

**Example:**

```json
{
  "jsonrpc": "2.0", "id": 1,
  "method": "tools/call",
  "params": {
    "name": "kin_annotation_mark_resolved",
    "arguments": { "annotation_id": "f6a7b8c9-d0e1-2345-faba-678901234567" }
  }
}
```

---

### `kin_todo_import`

Scan source files for inline TODO/FIXME/HACK markers and import them as work items.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `path` | string | no | Root directory to scan (defaults to working directory) |

**Example -- import TODOs from the entire repo:**

```json
{
  "jsonrpc": "2.0", "id": 1,
  "method": "tools/call",
  "params": {
    "name": "kin_todo_import",
    "arguments": {}
  }
}
```

**Example -- import TODOs from a specific subdirectory:**

```json
{
  "jsonrpc": "2.0", "id": 2,
  "method": "tools/call",
  "params": {
    "name": "kin_todo_import",
    "arguments": { "path": "src/handlers" }
  }
}
```

---

## Verification / Security / Release (6 tools)

### `kin_verify_entity`

Inspect linked tests and recorded coverage for a specific entity. Returns linked tests and coverage statistics; does not execute verification runs.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `entity_id` | string | yes | Entity UUID to verify |
| `runner` | string | no | Optional test runner filter (e.g. cargo, jest, pytest) |

**Example -- check test coverage for a function:**

```json
{
  "jsonrpc": "2.0", "id": 1,
  "method": "tools/call",
  "params": {
    "name": "kin_verify_entity",
    "arguments": { "entity_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890" }
  }
}
```

**Example -- check only cargo tests for a Rust entity:**

```json
{
  "jsonrpc": "2.0", "id": 2,
  "method": "tools/call",
  "params": {
    "name": "kin_verify_entity",
    "arguments": {
      "entity_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "runner": "cargo"
    }
  }
}
```

---

### `kin_coverage_summary`

Get repo-wide test coverage statistics. Shows total entities, covered count, coverage ratio, and entities missing proof.

*No parameters.*

**Example:**

```json
{
  "jsonrpc": "2.0", "id": 1,
  "method": "tools/call",
  "params": {
    "name": "kin_coverage_summary",
    "arguments": {}
  }
}
```

---

### `kin_security_scan`

Run security analysis on the semantic graph. Finds dead/unreachable code and optionally propagates downstream impact for each finding.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `propagate` | boolean | no | false | If true, compute downstream impact for each finding |

**Example -- quick scan (dead code only):**

```json
{
  "jsonrpc": "2.0", "id": 1,
  "method": "tools/call",
  "params": {
    "name": "kin_security_scan",
    "arguments": {}
  }
}
```

**Example -- deep scan with impact propagation:**

```json
{
  "jsonrpc": "2.0", "id": 2,
  "method": "tools/call",
  "params": {
    "name": "kin_security_scan",
    "arguments": { "propagate": true }
  }
}
```

---

### `kin_release_check`

Pre-release gate check. Validates coverage thresholds and approval status before a release.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `require_proof` | boolean | no | false | Require all entities to have test proof |
| `require_approval` | boolean | no | false | Require approval on the latest change |

**Example -- basic release check (no gates):**

```json
{
  "jsonrpc": "2.0", "id": 1,
  "method": "tools/call",
  "params": {
    "name": "kin_release_check",
    "arguments": {}
  }
}
```

**Example -- strict release gate (require both proof and approval):**

```json
{
  "jsonrpc": "2.0", "id": 2,
  "method": "tools/call",
  "params": {
    "name": "kin_release_check",
    "arguments": {
      "require_proof": true,
      "require_approval": true
    }
  }
}
```

---

### `kin_contract_check`

Check test coverage for a specific contract. Returns linked tests and coverage status.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `contract_id` | string | yes | Contract UUID to check |

**Example:**

```json
{
  "jsonrpc": "2.0", "id": 1,
  "method": "tools/call",
  "params": {
    "name": "kin_contract_check",
    "arguments": { "contract_id": "d4e5f6a7-b8c9-0123-defa-456789012345" }
  }
}
```

---

### `kin_provenance_query`

Query who changed an entity and its approval status. Returns recent audit events and any approvals for the entity's latest change.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `entity_id` | string | yes | Entity UUID to query provenance for |

**Example -- check who last modified a function and whether it was approved:**

```json
{
  "jsonrpc": "2.0", "id": 1,
  "method": "tools/call",
  "params": {
    "name": "kin_provenance_query",
    "arguments": { "entity_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890" }
  }
}
```

---

## Common Workflows

These multi-tool workflows show how tools compose together.

### Understand a function before modifying it

```
1. semantic_search   -- find the function by name
2. get_context_pack  -- get its source + dependencies
3. find_references   -- see who calls it
4. kin_check_traffic  -- make sure no other agent is working on it
5. kin_register_intent -- declare your intent to modify
```

### Review a change

```
1. semantic_diff     -- see what entities changed
2. impact_analysis   -- see downstream effects
3. semantic_review   -- get the full review with risk scoring
```

### Create and manage a feature

```
1. kin_work_create    -- create the feature work item
2. kin_work_decompose -- break it into child tasks
3. kin_work_status    -- move tasks through the pipeline
4. kin_work_implement -- link implementing entities as you build
5. kin_annotation_add -- leave reasoning/notes for the next agent
```

### Pre-release validation

```
1. kin_coverage_summary -- check overall test coverage
2. kin_security_scan    -- find dead code and security issues
3. kin_release_check    -- run the gate check with required flags
```
