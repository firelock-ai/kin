// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use crate::types::{ToolDefinition, ToolsListResult};

/// Build the list of all MCP tools that Kin exposes.
pub fn tool_definitions() -> ToolsListResult {
    ToolsListResult {
        tools: vec![
            ToolDefinition {
                name: "semantic_search".into(),
                description: "Search the semantic code graph for entities (functions, classes, types, traits, constants) by name, kind, or language. Returns exact file:line locations, signatures, and entity IDs. Faster and more precise than text search — matches parsed declarations, not string occurrences.".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "query": { "type": "string", "description": "Name pattern to search for" },
                        "kind": { "type": "string", "description": "Entity kind filter (function, class, etc.)" },
                        "language": { "type": "string", "description": "Language filter (rust, typescript, etc.)" },
                        "limit": { "type": "integer", "description": "Max results to return", "default": 20 },
                        "compact": { "type": "boolean", "description": "If true (default), return only id/name/kind/language/file_path/start_line/end_line/signature. If false, also include doc_summary.", "default": true }
                    },
                    "required": ["query"]
                }),
            },
            ToolDefinition {
                name: "get_entity".into(),
                description: "Retrieve a specific entity by ID. Returns full entity metadata including kind, language, file path, line range, and signature.".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "entity_id": { "type": "string", "description": "Entity UUID" }
                    },
                    "required": ["entity_id"]
                }),
            },
            ToolDefinition {
                name: "get_context_pack".into(),
                description: "Build a focused context pack for an entity — returns the entity's source body plus nearby dependencies within a token budget. One call replaces reading multiple files when you need implementation context. Pass an entity_id from semantic_search results.".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "entity_id": { "type": "string", "description": "Focal entity UUID" },
                        "token_budget": { "type": "integer", "description": "Token budget (8000, 16000, or 32000)", "default": 16000 },
                        "depth": { "type": "integer", "description": "Dependency traversal depth", "default": 2 },
                        "include_traffic": { "type": "boolean", "description": "Include active nearby agent traffic in response", "default": true },
                        "compact": { "type": "boolean", "description": "If true, all entities returned as SignatureOnly (~2-5KB). If false (default), focal gets FullBody, deps get SignatureOnly, transitive get NameAndKind.", "default": false }
                    },
                    "required": ["entity_id"]
                }),
            },
            ToolDefinition {
                name: "find_references".into(),
                description: "Find direct upstream callers/importers/references for an entity. Accepts either an entity_id or an exact query name, resolves the best matching canonical definition, and returns one row per upstream file with relation kinds and file paths.".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "entity_id": { "type": "string", "description": "Exact entity UUID. Optional if query is provided." },
                        "query": { "type": "string", "description": "Exact symbol name to resolve. Optional if entity_id is provided." },
                        "relation_kinds": {
                            "type": "array",
                            "description": "Filter relation kinds. Supported values: calls, imports, references. Defaults to all three.",
                            "items": { "type": "string" }
                        }
                    }
                }),
            },
            ToolDefinition {
                name: "impact_analysis".into(),
                description: "Analyze downstream impact of changes. Accepts base/head change IDs, OR entity_ids (UUIDs), OR files (paths), OR change_ids (list of change hashes). Only one mode at a time.".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "base": { "type": "string", "description": "Base semantic change ID (hex)" },
                        "head": { "type": "string", "description": "Head semantic change ID (hex)" },
                        "entity_ids": { "type": "array", "items": { "type": "string" }, "description": "Entity UUIDs to analyze impact for" },
                        "files": { "type": "array", "items": { "type": "string" }, "description": "File paths — resolves to entities, then analyzes impact" },
                        "change_ids": { "type": "array", "items": { "type": "string" }, "description": "Change ID hexes to combine and analyze impact" },
                        "include_traffic": { "type": "boolean", "description": "Include active traffic on impacted entities", "default": true }
                    }
                }),
            },
            ToolDefinition {
                name: "semantic_diff".into(),
                description: "Compute entity-level diff. Accepts base/head change IDs, OR entity_ids (UUIDs), OR files (paths), OR change_ids (list of change hashes to combine). Only one mode at a time.".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "base": { "type": "string", "description": "Base semantic change ID (hex)" },
                        "head": { "type": "string", "description": "Head semantic change ID (hex)" },
                        "entity_ids": { "type": "array", "items": { "type": "string" }, "description": "Entity UUIDs to diff (current state vs history)" },
                        "files": { "type": "array", "items": { "type": "string" }, "description": "File paths — resolves to entities, then diffs" },
                        "change_ids": { "type": "array", "items": { "type": "string" }, "description": "Change ID hexes to combine into one diff" }
                    }
                }),
            },
            ToolDefinition {
                name: "semantic_review".into(),
                description: "Full semantic review: diff + impact + risk. Accepts base/head change IDs, OR entity_ids (UUIDs), OR files (paths), OR change_ids (list of change hashes). Only one mode at a time.".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "base": { "type": "string", "description": "Base semantic change ID (hex)" },
                        "head": { "type": "string", "description": "Head semantic change ID (hex)" },
                        "entity_ids": { "type": "array", "items": { "type": "string" }, "description": "Entity UUIDs to review (current state vs history)" },
                        "files": { "type": "array", "items": { "type": "string" }, "description": "File paths — resolves to entities, then reviews" },
                        "change_ids": { "type": "array", "items": { "type": "string" }, "description": "Change ID hexes to combine into one review" },
                        "include_traffic": { "type": "boolean", "description": "Include active traffic on reviewed entities", "default": true }
                    }
                }),
            },
            ToolDefinition {
                name: "dead_code".into(),
                description: "Find dead/unreachable code in the semantic graph. Without filters, returns entities with no incoming relations. For task-scoped checks, pass `files` to return only dead functions/classes from those files, ignoring same-file references.".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "limit": { "type": "integer", "description": "Max results", "default": 50 },
                        "files": {
                            "type": "array",
                            "items": { "type": "string" },
                            "description": "Optional repo-relative file paths. When provided, dead_code returns only dead functions/classes from those files."
                        }
                    }
                }),
            },
            ToolDefinition {
                name: "entity_history".into(),
                description: "Get the change history of a specific entity".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "entity_id": { "type": "string", "description": "Entity UUID" }
                    },
                    "required": ["entity_id"]
                }),
            },
            ToolDefinition {
                name: "graph_neighborhood".into(),
                description: "Get the dependency neighborhood of an entity — what it depends on and what depends on it. Traverses the semantic relation graph (calls, imports, implements) to the specified depth. Returns compact summaries (name, kind, file) to stay within token budgets.".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "entity_id": { "type": "string", "description": "Entity UUID" },
                        "depth": { "type": "integer", "description": "Traversal depth", "default": 2 },
                        "limit": { "type": "integer", "description": "Max entities to return (default 30)", "default": 30 }
                    },
                    "required": ["entity_id"]
                }),
            },
            ToolDefinition {
                name: "benchmark".into(),
                description: "Get benchmark results and metrics".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "category": { "type": "string", "description": "Metric category: velocity, reliability, or economic" }
                    }
                }),
            },
            ToolDefinition {
                name: "register_session".into(),
                description: "Register an assistant session with Kin (legacy, prefer kin_session_start)".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "assistant_name": { "type": "string", "description": "Name of the assistant (e.g. claude-code, codex)" },
                        "session_id": { "type": "string", "description": "Unique session identifier" }
                    },
                    "required": ["assistant_name"]
                }),
            },
            // ── Phase 7: Session/Intent/Traffic tools ──
            ToolDefinition {
                name: "kin_session_start".into(),
                description: "Start a rich agent session with capabilities, transport, and vendor info".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "vendor": { "type": "string", "description": "Vendor identifier (claude-code, codex, gemini-cli, etc.)" },
                        "client_name": { "type": "string", "description": "Human-readable client name" },
                        "transport": { "type": "string", "description": "Connection type: mcp, cli, wrapper, or ui", "default": "mcp" },
                        "pid": { "type": "integer", "description": "OS process ID of the agent (optional)" },
                        "cwd": { "type": "string", "description": "Working directory of the agent" },
                        "capabilities": {
                            "type": "object",
                            "description": "Agent capabilities",
                            "properties": {
                                "can_read": { "type": "boolean", "default": true },
                                "can_write": { "type": "boolean", "default": false },
                                "can_execute": { "type": "boolean", "default": false },
                                "can_branch": { "type": "boolean", "default": false },
                                "can_commit": { "type": "boolean", "default": false },
                                "max_concurrent_intents": { "type": "integer", "default": 1 }
                            }
                        }
                    },
                    "required": ["vendor", "client_name", "cwd"]
                }),
            },
            ToolDefinition {
                name: "kin_session_heartbeat".into(),
                description: "Send a heartbeat to keep an agent session alive".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "session_id": { "type": "string", "description": "Session UUID" }
                    },
                    "required": ["session_id"]
                }),
            },
            ToolDefinition {
                name: "kin_session_end".into(),
                description: "End an agent session and release all its intents".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "session_id": { "type": "string", "description": "Session UUID" }
                    },
                    "required": ["session_id"]
                }),
            },
            ToolDefinition {
                name: "kin_register_intent".into(),
                description: "Declare what scopes the agent intends to modify, enabling collision detection".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "session_id": { "type": "string", "description": "Session UUID" },
                        "scopes": {
                            "type": "array",
                            "description": "Target scopes: [{\"Entity\": \"uuid\"}, {\"Contract\": \"uuid\"}, {\"Artifact\": \"path\"}]",
                            "items": { "type": "object" }
                        },
                        "lock_type": { "type": "string", "description": "Lock strength: soft or hard", "default": "soft" },
                        "task_description": { "type": "string", "description": "What the agent plans to do" },
                        "expires_at": { "type": "string", "description": "Optional ISO 8601 expiry timestamp" }
                    },
                    "required": ["session_id", "scopes", "task_description"]
                }),
            },
            ToolDefinition {
                name: "kin_release_intent".into(),
                description: "Release a previously registered intent".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "session_id": { "type": "string", "description": "Session UUID" },
                        "intent_id": { "type": "string", "description": "Intent UUID to release" }
                    },
                    "required": ["session_id", "intent_id"]
                }),
            },
            ToolDefinition {
                name: "kin_check_traffic".into(),
                description: "Check what agents are actively working on or near given scopes".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "scopes": {
                            "type": "array",
                            "description": "Target scopes to check: [{\"Entity\": \"uuid\"}, {\"Contract\": \"uuid\"}, {\"Artifact\": \"path\"}]",
                            "items": { "type": "object" }
                        }
                    },
                    "required": ["scopes"]
                }),
            },
            ToolDefinition {
                name: "explore_codebase".into(),
                description: "One-shot codebase exploration — replaces multi-round-trip MCP calls with a single request. Use 'overview' for entity counts and top declarations, 'search' to find entities and their context packs, or 'trace' to follow an ordered call chain from a matched entity with real source bodies and imported constants.".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "query": { "type": "string", "description": "Natural language question or entity name to explore" },
                        "strategy": { "type": "string", "enum": ["overview", "search", "trace"], "description": "Exploration strategy: overview (entity counts + top declarations), search (find + context packs for top 3), trace (find + ordered call chain with source bodies)", "default": "search" },
                        "token_budget": { "type": "integer", "description": "Max response tokens", "default": 8000 }
                    },
                    "required": ["query"]
                }),
            },
            // Phase 8: Work graph tools
            ToolDefinition {
                name: "kin_work_create".into(),
                description: "Create a new work item (feature, task, issue, debt, todo, investigation)".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "kind": { "type": "string", "description": "Work kind: feature, task, issue, debt, todo, investigation" },
                        "title": { "type": "string", "description": "Work item title" },
                        "description": { "type": "string", "description": "Detailed description" },
                        "scopes": { "type": "array", "items": { "type": "string" }, "description": "Semantic scopes: entity:<uuid>, contract:<uuid>, artifact:<path>" },
                        "acceptance_criteria": { "type": "array", "items": { "type": "string" }, "description": "List of acceptance criteria" }
                    },
                    "required": ["kind", "title"]
                }),
            },
            ToolDefinition {
                name: "kin_work_list".into(),
                description: "List work items with optional status and kind filters".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "status": { "type": "string", "description": "Filter by status: proposed, planned, in_progress, blocked, done, verified, archived" },
                        "kind": { "type": "string", "description": "Filter by kind: feature, task, issue, debt, todo, investigation" },
                        "scope": { "type": "string", "description": "Filter by scope" }
                    }
                }),
            },
            ToolDefinition {
                name: "kin_work_show".into(),
                description: "Show full details of a work item including parents, children, blockers, implementors, and attached annotations".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "work_id": { "type": "string", "description": "Work item UUID" }
                    },
                    "required": ["work_id"]
                }),
            },
            ToolDefinition {
                name: "kin_work_link".into(),
                description: "Link a work item to semantic scopes (entities, contracts, artifacts)".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "work_id": { "type": "string", "description": "Work item UUID" },
                        "scopes": { "type": "array", "items": { "type": "string" }, "description": "Scopes to link" }
                    },
                    "required": ["work_id", "scopes"]
                }),
            },
            ToolDefinition {
                name: "kin_work_decompose".into(),
                description: "Link a parent work item to a child work item".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "parent_work_id": { "type": "string", "description": "Parent work item UUID" },
                        "child_work_id": { "type": "string", "description": "Child work item UUID" }
                    },
                    "required": ["parent_work_id", "child_work_id"]
                }),
            },
            ToolDefinition {
                name: "kin_work_block".into(),
                description: "Mark one work item as blocked by another".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "blocked_work_id": { "type": "string", "description": "Blocked work item UUID" },
                        "blocker_work_id": { "type": "string", "description": "Blocking work item UUID" }
                    },
                    "required": ["blocked_work_id", "blocker_work_id"]
                }),
            },
            ToolDefinition {
                name: "kin_work_implement".into(),
                description: "Link semantic scopes that implement a work item".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "work_id": { "type": "string", "description": "Work item UUID" },
                        "scopes": { "type": "array", "items": { "type": "string" }, "description": "Implementing scopes" }
                    },
                    "required": ["work_id", "scopes"]
                }),
            },
            ToolDefinition {
                name: "kin_work_status".into(),
                description: "Update a work item status".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "work_id": { "type": "string", "description": "Work item UUID" },
                        "status": { "type": "string", "description": "New status: proposed, planned, in_progress, blocked, done, verified, archived" }
                    },
                    "required": ["work_id", "status"]
                }),
            },
            // Phase 8: Annotation tools
            ToolDefinition {
                name: "kin_annotation_add".into(),
                description: "Add a semantic annotation (comment, warning, instruction, reasoning) to scopes or work items".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "kind": { "type": "string", "description": "Annotation kind: comment, warning, instruction, reasoning" },
                        "body": { "type": "string", "description": "Annotation text" },
                        "targets": { "type": "array", "items": { "type": "string" }, "description": "Target scopes or work items: entity:<uuid>, contract:<uuid>, artifact:<path>, change:<id>, work:<uuid>" },
                        "scopes": { "type": "array", "items": { "type": "string" }, "description": "Legacy alias for scope-only targets" }
                    },
                    "required": ["kind", "body"]
                }),
            },
            ToolDefinition {
                name: "kin_annotation_list".into(),
                description: "List annotations for given scopes or work items".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "targets": { "type": "array", "items": { "type": "string" }, "description": "Targets to query: entity:<uuid>, contract:<uuid>, artifact:<path>, change:<id>, work:<uuid>" },
                        "scopes": { "type": "array", "items": { "type": "string" }, "description": "Legacy alias for scope-only targets" },
                        "include_stale": { "type": "boolean", "description": "Include stale annotations", "default": true }
                    }
                }),
            },
            ToolDefinition {
                name: "kin_annotation_mark_resolved".into(),
                description: "Mark an annotation as resolved (removes it)".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "annotation_id": { "type": "string", "description": "Annotation UUID" }
                    },
                    "required": ["annotation_id"]
                }),
            },
            ToolDefinition {
                name: "kin_todo_import".into(),
                description: "Scan source files for inline TODO/FIXME/HACK markers and import them as work items".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "description": "Root directory to scan (defaults to working directory)" }
                    }
                }),
            },
            // Phase 9-10: Verification, security, release, contract, and provenance tools
            ToolDefinition {
                name: "kin_verify_entity".into(),
                description: "Inspect linked tests and recorded coverage for a specific entity. Returns linked tests and coverage statistics; does not execute verification runs.".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "entity_id": { "type": "string", "description": "Entity UUID to verify" },
                        "runner": { "type": "string", "description": "Optional test runner filter (e.g. cargo, jest, pytest)" }
                    },
                    "required": ["entity_id"]
                }),
            },
            ToolDefinition {
                name: "kin_coverage_summary".into(),
                description: "Get repo-wide test coverage statistics. Shows total entities, covered count, coverage ratio, and entities missing proof.".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {}
                }),
            },
            ToolDefinition {
                name: "kin_security_scan".into(),
                description: "Run security analysis on the semantic graph. Finds dead/unreachable code and optionally propagates downstream impact for each finding.".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "propagate": { "type": "boolean", "description": "If true, compute downstream impact for each finding", "default": false }
                    }
                }),
            },
            ToolDefinition {
                name: "kin_release_check".into(),
                description: "Pre-release gate check. Validates coverage thresholds and approval status before a release.".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "require_proof": { "type": "boolean", "description": "Require all entities to have test proof", "default": false },
                        "require_approval": { "type": "boolean", "description": "Require approval on the latest change", "default": false }
                    }
                }),
            },
            ToolDefinition {
                name: "kin_contract_check".into(),
                description: "Check test coverage for a specific contract. Returns linked tests and coverage status.".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "contract_id": { "type": "string", "description": "Contract UUID to check" }
                    },
                    "required": ["contract_id"]
                }),
            },
            ToolDefinition {
                name: "kin_provenance_query".into(),
                description: "Query who changed an entity and its approval status. Returns recent audit events and any approvals for the entity's latest change.".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "entity_id": { "type": "string", "description": "Entity UUID to query provenance for" }
                    },
                    "required": ["entity_id"]
                }),
            },
            // Phase 11: Review mutation tools
            ToolDefinition {
                name: "kin_review_create".into(),
                description: "Create a new review for a set of changes. Supports base/head refs or repo-local scope-driven review creation.".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "title": { "type": "string", "description": "Review title" },
                        "base": { "type": "string", "description": "Optional base ref (branch name or change ID)" },
                        "head": { "type": "string", "description": "Optional head ref (branch name or change ID)" },
                        "description": { "type": "string", "description": "Optional review description" },
                        "scopes": { "type": "array", "items": { "type": "string" }, "description": "Optional semantic scopes to restrict review to" },
                        "scope_type": { "type": "string", "description": "Optional KinLab-style scope type: entity, module, or work-item" },
                        "entity_ids": { "type": "array", "items": { "type": "string" }, "description": "Optional entity IDs or artifact paths for repo-local review creation" },
                        "created_by": { "type": "string", "description": "Optional creator identity" },
                        "created_by_kind": { "type": "string", "description": "Optional creator kind: human, assistant, agent, or system" },
                        "requested_reviewers": { "type": "array", "items": { "type": "string" }, "description": "Optional initial reviewer assignments" }
                    },
                    "required": ["title"],
                    "anyOf": [
                        { "required": ["base", "head"] },
                        { "required": ["scope_type", "entity_ids"] },
                        { "required": ["scopes"] }
                    ]
                }),
            },
            ToolDefinition {
                name: "kin_review_decide".into(),
                description: "Record a review decision: approve, needs-work, or block.".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "review_id": { "type": "string", "description": "Review UUID" },
                        "state": { "type": "string", "description": "Decision state: approved, needs_work, blocked" },
                        "comment": { "type": "string", "description": "Optional comment explaining the decision" },
                        "summary": { "type": "string", "description": "Alias for comment, used by KinLab review flows" },
                        "reviewer": { "type": "string", "description": "Reviewer identity (defaults to mcp-client)" },
                        "reviewer_kind": { "type": "string", "description": "Optional reviewer kind: human, assistant, agent, or system" }
                    },
                    "required": ["review_id", "state"]
                }),
            },
            ToolDefinition {
                name: "kin_review_note_add".into(),
                description: "Add a note to a review, optionally scoped to a specific entity.".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "review_id": { "type": "string", "description": "Review UUID" },
                        "body": { "type": "string", "description": "Note body text" },
                        "scope": { "type": "string", "description": "Optional scope (entity:<uuid> or artifact:<path>)" },
                        "file_path": { "type": "string", "description": "Optional file anchor path (translated to artifact scope)" },
                        "line": { "type": "integer", "description": "Optional line anchor. Stored as metadata on the caller side; graph stores artifact scope only." },
                        "author": { "type": "string", "description": "Author identity (defaults to mcp-client)" },
                        "author_kind": { "type": "string", "description": "Optional author kind: human, assistant, agent, or system" }
                    },
                    "required": ["review_id", "body"]
                }),
            },
            ToolDefinition {
                name: "kin_review_discuss".into(),
                description: "Start a discussion thread on a review, optionally scoped to a specific entity.".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "review_id": { "type": "string", "description": "Review UUID" },
                        "body": { "type": "string", "description": "Initial discussion message" },
                        "scope": { "type": "string", "description": "Optional scope (entity:<uuid> or artifact:<path>)" },
                        "file_path": { "type": "string", "description": "Optional file anchor path (translated to artifact scope)" },
                        "line": { "type": "integer", "description": "Optional line anchor. Stored as caller metadata; graph stores artifact scope only." },
                        "author": { "type": "string", "description": "Author identity (defaults to mcp-client)" },
                        "author_kind": { "type": "string", "description": "Optional author kind: human, assistant, agent, or system" }
                    },
                    "required": ["review_id", "body"]
                }),
            },
            ToolDefinition {
                name: "kin_review_discuss_reply".into(),
                description: "Reply to an existing discussion thread on a review.".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "discussion_id": { "type": "string", "description": "Discussion UUID" },
                        "body": { "type": "string", "description": "Reply message text" },
                        "author": { "type": "string", "description": "Author identity (defaults to mcp-client)" },
                        "author_kind": { "type": "string", "description": "Optional author kind: human, assistant, agent, or system" }
                    },
                    "required": ["discussion_id", "body"]
                }),
            },
            ToolDefinition {
                name: "kin_review_discuss_resolve".into(),
                description: "Resolve or reopen a discussion thread.".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "discussion_id": { "type": "string", "description": "Discussion UUID" },
                        "resolved": { "type": "boolean", "description": "true to resolve, false to reopen", "default": true },
                        "state": { "type": "string", "description": "Alias for resolved/open, used by KinLab review flows" },
                        "actor": { "type": "string", "description": "Optional actor identity for audit parity" },
                        "actor_kind": { "type": "string", "description": "Optional actor kind: human, assistant, agent, or system" }
                    },
                    "required": ["discussion_id"]
                }),
            },
            ToolDefinition {
                name: "kin_review_assign".into(),
                description: "Assign one or more reviewers to a review.".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "review_id": { "type": "string", "description": "Review UUID" },
                        "reviewer": { "type": "string", "description": "Reviewer identity (email or handle)" },
                        "reviewers": { "type": "array", "items": { "type": "string" }, "description": "Optional batch reviewer assignment list" },
                        "assigned_by": { "type": "string", "description": "Optional assigner identity" },
                        "assigned_by_kind": { "type": "string", "description": "Optional assigner kind: human, assistant, agent, or system" }
                    },
                    "required": ["review_id"],
                    "anyOf": [
                        { "required": ["reviewer"] },
                        { "required": ["reviewers"] }
                    ]
                }),
            },
            ToolDefinition {
                name: "kin_review_unassign".into(),
                description: "Remove a reviewer assignment from a review.".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "review_id": { "type": "string", "description": "Review UUID" },
                        "reviewer": { "type": "string", "description": "Reviewer identity to remove" }
                    },
                    "required": ["review_id", "reviewer"]
                }),
            },
            ToolDefinition {
                name: "kin_review_list".into(),
                description: "List reviews with optional state filter.".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "state": { "type": "string", "description": "Filter by decision state: pending, approved, needs_work, blocked" }
                    }
                }),
            },
            ToolDefinition {
                name: "kin_review_get".into(),
                description: "Get a specific review with all details: decisions, notes, discussions, and assignments.".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "review_id": { "type": "string", "description": "Review UUID" }
                    },
                    "required": ["review_id"]
                }),
            },
            ToolDefinition {
                name: "kin_graph_status".into(),
                description: "Report the health and staleness status of the loaded graph snapshot. Returns entity count and, when a generation file is configured, whether the in-memory graph is stale relative to the on-disk snapshot. Call this if query results seem outdated — if stale, restart the MCP server to pick up the latest data.".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {},
                    "additionalProperties": false
                }),
            },
        ],
    }
}

pub fn benchmark_tool_names() -> &'static [&'static str] {
    &[
        "semantic_search",
        "get_entity",
        "get_context_pack",
        "find_references",
        "dead_code",
        "graph_neighborhood",
        "explore_codebase",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_tools_have_names_and_descriptions() {
        let list = tool_definitions();
        assert!(!list.tools.is_empty());
        for tool in &list.tools {
            assert!(!tool.name.is_empty());
            assert!(!tool.description.is_empty());
        }
    }

    #[test]
    fn tool_definitions_serialize() {
        let list = tool_definitions();
        let json = serde_json::to_string(&list).unwrap();
        assert!(json.contains("semantic_search"));
        assert!(json.contains("find_references"));
        assert!(json.contains("impact_analysis"));
        assert!(json.contains("register_session"));
        // Phase 7 tools
        assert!(json.contains("kin_session_start"));
        assert!(json.contains("kin_session_heartbeat"));
        assert!(json.contains("kin_session_end"));
        assert!(json.contains("kin_register_intent"));
        assert!(json.contains("kin_release_intent"));
        assert!(json.contains("kin_check_traffic"));
    }

    #[test]
    fn expected_tool_count() {
        let list = tool_definitions();
        // 12 original + 1 explore_codebase + 6 Phase 7 + 12 Phase 8 + 6 Phase 9-10 + 1 graph_status + 10 Phase 11 review = 48
        assert_eq!(list.tools.len(), 48);
    }

    #[test]
    fn key_tools_have_descriptive_guidance() {
        let list = tool_definitions();
        let guided_tools = [
            "semantic_search",
            "get_context_pack",
            "impact_analysis",
            "semantic_diff",
            "graph_neighborhood",
            "explore_codebase",
        ];
        for name in &guided_tools {
            let tool = list.tools.iter().find(|t| t.name == *name).unwrap();
            assert!(
                tool.description.len() > 50,
                "{} should have a substantive description (got {} chars)",
                name,
                tool.description.len()
            );
        }
    }

    #[test]
    fn include_traffic_param_present_on_extended_tools() {
        let list = tool_definitions();
        let extended_tools = ["get_context_pack", "impact_analysis", "semantic_review"];
        for name in &extended_tools {
            let tool = list.tools.iter().find(|t| t.name == *name).unwrap();
            let schema = tool.input_schema.as_object().unwrap();
            let props = schema["properties"].as_object().unwrap();
            assert!(
                props.contains_key("include_traffic"),
                "{} should have include_traffic param",
                name
            );
        }
    }
}
