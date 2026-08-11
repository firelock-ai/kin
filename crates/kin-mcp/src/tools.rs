// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use crate::types::{ToolDefinition, ToolsListResult};

/// Honest JSON Schema for one transaction operation.
///
/// The product daemon accepts two materially different shapes. A source-body
/// edit is intentionally payload-less; structured entity/relation mutations
/// require `payload`. Keeping these as disjoint `oneOf` branches prevents MCP
/// clients from being told that the preferred source-edit form is invalid.
fn transaction_operation_schema() -> serde_json::Value {
    serde_json::json!({
        "oneOf": [
            {
                "title": "Entity source body edit",
                "type": "object",
                "properties": {
                    "verb": {
                        "type": "string",
                        "enum": ["update", "modify"],
                        "description": "Update an existing source entity."
                    },
                    "target": {
                        "type": "string",
                        "minLength": 1,
                        "description": "Exact repository entity UUID or unambiguous exact entity name."
                    },
                    "body": {
                        "type": "string",
                        "minLength": 1,
                        "description": "The entity's complete new UTF-8 source text, including its own leading indentation. Do not submit a truncated retrieval body."
                    },
                    "description": {
                        "type": "string",
                        "description": "Human-readable explanation of this change."
                    }
                },
                "required": ["verb", "target", "body", "description"],
                "additionalProperties": false
            },
            {
                "title": "Structured entity or relation mutation",
                "type": "object",
                "properties": {
                    "verb": {
                        "type": "string",
                        "enum": [
                            "create", "add", "upsert", "insert",
                            "update", "modify", "delete", "remove"
                        ],
                        "description": "Entity or relation mutation verb."
                    },
                    "target": {
                        "type": "string",
                        "description": "Exact repository entity UUID for an Entity payload; empty string for a Relation payload."
                    },
                    "payload": {
                        "type": "object",
                        "description": "Exact mutation payload: {\"Entity\": { ...existing entity identity... }} or {\"Relation\": {\"from\": \"...\", \"to\": \"...\", \"kind\": \"...\"}}."
                    },
                    "body": {
                        "type": "string",
                        "description": "Full new UTF-8 source text for a source-bound Entity update. Omit for Relation operations."
                    },
                    "description": {
                        "type": "string",
                        "description": "Human-readable explanation of this change."
                    }
                },
                "required": ["verb", "target", "payload", "description"],
                "additionalProperties": false
            }
        ]
    })
}

/// Build the list of all MCP tools that Kin exposes.
pub fn tool_definitions() -> ToolsListResult {
    ToolsListResult {
        tools: vec![
            ToolDefinition {
                name: "kin_artifact_list".into(),
                description: crate::handlers::artifacts::ARTIFACT_LIST_DESC.into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "source_change_id": {
                            "type": "string",
                            "pattern": "^[0-9a-f]{64}$",
                            "description": "Exact semantic change ID. Defaults to the current branch head."
                        },
                        "offset": { "type": "integer", "minimum": 0, "default": 0 },
                        "limit": { "type": "integer", "minimum": 1, "maximum": 1000, "default": 200 }
                    },
                    "additionalProperties": false
                }),
            },
            ToolDefinition {
                name: "kin_artifact_read".into(),
                description: crate::handlers::artifacts::ARTIFACT_READ_DESC.into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "artifact_id": { "type": "string", "format": "uuid" },
                        "path": {
                            "type": "object",
                            "properties": {
                                "bytes_hex": {
                                    "type": "string",
                                    "pattern": "^(?:[0-9a-f]{2})+$"
                                }
                            },
                            "required": ["bytes_hex"],
                            "additionalProperties": false
                        },
                        "source_change_id": {
                            "type": "string",
                            "pattern": "^[0-9a-f]{64}$",
                            "description": "Exact semantic change ID. Defaults to the current branch head."
                        }
                    },
                    "anyOf": [
                        { "required": ["artifact_id"] },
                        { "required": ["path"] }
                    ],
                    "additionalProperties": false
                }),
            },
            ToolDefinition {
                name: "semantic_search".into(),
                description: crate::handlers::entities::SEMANTIC_SEARCH_DESC.into(),
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
                name: "semantic_locate".into(),
                description: crate::handlers::entities::SEMANTIC_LOCATE_DESC.into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "query": { "type": "string", "description": "Natural-language description of the code to find. Optional when paging with `cursor`." },
                        "queries": {
                            "type": "array",
                            "items": { "type": "string" },
                            "description": "Optional additional query variants for multi-query fan-out. When present, `query` plus each variant are retrieved independently and their rankings RRF-fused into one deduped result, with each hit's `match_evidence.matched_variants` naming the variants that surfaced it. Diverse variants (identifiers, behavior, subsystem) recover more relevant hits than any single phrasing. Requires the fused pipeline (automatic when set)."
                        },
                        "limit": { "type": "integer", "description": "Max ranked entities per page (page size). Default 20.", "default": 20 },
                        "page_size": { "type": "integer", "description": "Entities per page; overrides `limit` for paging when set." },
                        "cursor": { "type": "string", "description": "Opaque cursor from a prior result's `next_cursor`: returns the NEXT page of ranked entities from the cached ranking with no re-search. Omit for a fresh query." },
                        "granularity": {
                            "type": "string",
                            "enum": ["file", "entity"],
                            "description": "Rank entities ('entity', default) or roll up to files ('file')",
                            "default": "entity"
                        },
                        "include_snippet": {
                            "type": "boolean",
                            "description": "Attach a bounded inline source snippet to each entity hit, projected from graph-owned content. Read it from the hit's `snippet` field (the fused pipeline also carries the same text as `body` for locate-schema parity). Entity granularity only: a file hit has no single entity body. A hit with no graph-owned body carries no snippet rather than a placeholder.",
                            "default": true
                        },
                        "pipeline": {
                            "type": "string",
                            "enum": ["fused", "cosine"],
                            "description": "Force a retrieval pipeline for this call: 'fused' (full multi-signal locate ranking) or 'cosine' (legacy single-vector). Defaults to the daemon's active KIN_PROFILE — the stock compat-v0 profile serves 'cosine'; accuracy-v1 serves 'fused'."
                        },
                        "explain": {
                            "type": "boolean",
                            "description": "Include the fused pipeline's debug object (per-stage scores and the prune ledger). Fused pipeline only.",
                            "default": false
                        }
                    },
                    "required": ["query"]
                }),
            },
            ToolDefinition {
                name: "get_entity".into(),
                description: crate::handlers::entities::GET_ENTITY_DESC.into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "entity_id": { "type": "string", "description": "Entity UUID" }
                    },
                    "required": ["entity_id"]
                }),
            },
            ToolDefinition {
                name: "get_entity_source".into(),
                description: crate::handlers::entities::GET_ENTITY_SOURCE_DESC.into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "entity_id": { "type": "string", "description": "Entity UUID" }
                    },
                    "required": ["entity_id"]
                }),
            },
            ToolDefinition {
                name: "get_entity_body".into(),
                description: crate::handlers::entities::GET_ENTITY_BODY_DESC.into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "entity_id": { "type": "string", "description": "Entity UUID" }
                    },
                    "required": ["entity_id"]
                }),
            },
            ToolDefinition {
                name: "get_entity_sources".into(),
                description: crate::handlers::entities::GET_ENTITY_SOURCES_DESC.into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "entity_ids": {
                            "type": "array",
                            "description": "Entity UUIDs to fetch source for, in priority order. Minimum 1, maximum 50.",
                            "items": { "type": "string" },
                            "minItems": 1,
                            "maxItems": 50
                        },
                        "token_budget": {
                            "type": "integer",
                            "description": "Optional token budget shared across all bodies. Bodies are filled in request order until the budget is reached; remaining entities return signature-only with reason \"budget\". Omit for unbounded."
                        },
                        "compact": {
                            "type": "boolean",
                            "description": "If true, return signature-only rows (no bodies) for every entity. Default false.",
                            "default": false
                        },
                        "max_lines_per_body": {
                            "type": "integer",
                            "description": "Clamp each body to at most this many lines before token budgeting. Default 10000."
                        },
                        "max_bytes_per_body": {
                            "type": "integer",
                            "description": "Clamp each body to at most this many bytes before token budgeting. Default 1000000."
                        }
                    },
                    "required": ["entity_ids"]
                }),
            },
            ToolDefinition {
                name: "get_context_pack".into(),
                description: crate::handlers::entities::GET_CONTEXT_PACK_DESC.into(),
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
                name: "trace_computation".into(),
                description: crate::handlers::entities::TRACE_COMPUTATION_DESC.into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "entity_id": { "type": "string", "description": "Focal entity UUID. Required if `query` is not given." },
                        "query": { "type": "string", "description": "Exact entity name to resolve to a focal entity. Required if `entity_id` is not given." },
                        "depth": { "type": "integer", "description": "Dependency traversal depth across the trace neighborhood", "default": 3 },
                        "token_budget": { "type": "integer", "description": "Token budget for the assembled trace response", "default": 8000 },
                        "compact": { "type": "boolean", "description": "If true, return signature-only entries for everyone (smaller). If false (default), focal gets FullBody, deps get SignatureOnly — better for trace-style reasoning.", "default": false }
                    }
                }),
            },
            ToolDefinition {
                name: "trace_data_flow".into(),
                description: crate::handlers::entities::TRACE_DATA_FLOW_DESC.into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "focal": { "type": "string", "description": "Focal entity UUID or exact entity name to start tracing from" },
                        "depth": { "type": "integer", "description": "Maximum traversal depth from the focal (default 3, capped at 8)", "default": 3, "minimum": 1, "maximum": 8 },
                        "direction": {
                            "type": "string",
                            "enum": ["calls", "callers", "both"],
                            "description": "Direction of traversal: 'calls' walks outgoing edges (focal -> callees), 'callers' walks incoming edges (callers -> focal), 'both' merges. Default 'both'.",
                            "default": "both"
                        },
                        "limit_per_step": { "type": "integer", "description": "Max relations expanded per step (default 5, capped at 25)", "default": 5, "minimum": 1, "maximum": 25 }
                    },
                    "required": ["focal"]
                }),
            },
            ToolDefinition {
                name: "find_references".into(),
                description: crate::handlers::entities::FIND_REFERENCES_DESC.into(),
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
                name: "bulk_check_references".into(),
                description: crate::handlers::entities::BULK_CHECK_REFERENCES_DESC.into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "entity_ids": {
                            "type": "array",
                            "description": "Entity UUIDs to classify. Minimum 1, maximum 200.",
                            "items": { "type": "string" },
                            "minItems": 1,
                            "maxItems": 200
                        },
                        "relation_kind": {
                            "type": "string",
                            "description": "Relation kind to check for: 'Calls', 'Imports', 'References', or 'Any' for the union.",
                            "enum": ["Calls", "Imports", "References", "Any"],
                            "default": "Any"
                        },
                        "compact": {
                            "type": "boolean",
                            "description": "If true (default), return only {entity_id, has_references, reference_count} per result. If false, also include name/kind/file_path/matched_kinds.",
                            "default": true
                        }
                    },
                    "required": ["entity_ids"]
                }),
            },
            ToolDefinition {
                name: "impact_analysis".into(),
                description: crate::handlers::review::IMPACT_ANALYSIS_DESC.into(),
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
                description: crate::handlers::review::SEMANTIC_DIFF_DESC.into(),
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
                description: crate::handlers::review::SEMANTIC_REVIEW_DESC.into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "base": { "type": "string", "description": "Base semantic change ID (hex)" },
                        "head": { "type": "string", "description": "Head semantic change ID (hex)" },
                        "entity_ids": { "type": "array", "items": { "type": "string" }, "description": "Entity UUIDs to review (current state vs history)" },
                        "files": { "type": "array", "items": { "type": "string" }, "description": "File paths — resolves to entities, then reviews" },
                        "change_ids": { "type": "array", "items": { "type": "string" }, "description": "Change ID hexes to combine into one review" },
                        "format": { "type": "string", "enum": ["text", "json"], "description": "Response format. Use json for editor integrations.", "default": "text" },
                        "include_traffic": { "type": "boolean", "description": "Include active traffic on reviewed entities", "default": true }
                    }
                }),
            },
            ToolDefinition {
                name: "shadow_gate_report".into(),
                description: crate::handlers::review::SHADOW_GATE_REPORT_DESC.into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "base": { "type": "string", "description": "Base ref: branch name, semantic change ID (hex), or imported Git commit SHA" },
                        "head": { "type": "string", "description": "Head ref: branch name, semantic change ID (hex), or imported Git commit SHA" },
                        "title": { "type": "string", "description": "Change title for the report (e.g. PR title)" },
                        "source_url": { "type": "string", "description": "Source URL for the report (e.g. PR URL)" },
                        "author": { "type": "string", "description": "Change author identity for the report" },
                        "actor": { "type": "string", "description": "Identity running the evaluation (defaults to mcp-client)" }
                    },
                    "required": ["base", "head"]
                }),
            },
            ToolDefinition {
                name: "dead_code".into(),
                description: crate::handlers::entities::DEAD_CODE_DESC.into(),
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
                name: "find_dead_code_seeded".into(),
                description: crate::handlers::entities::FIND_DEAD_CODE_SEEDED_DESC.into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Search query — concept or partial name to seed candidates"
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Max candidates to classify (default 20, max 200)",
                            "default": 20,
                            "minimum": 1,
                            "maximum": 200
                        }
                    },
                    "required": ["query"]
                }),
            },
            ToolDefinition {
                name: "entity_history".into(),
                description: crate::handlers::review::ENTITY_HISTORY_DESC.into(),
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
                description: crate::handlers::entities::GRAPH_NEIGHBORHOOD_DESC.into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "entity_id": { "type": "string", "description": "Entity UUID" },
                        "depth": { "type": "integer", "description": "Traversal depth", "default": 2 },
                        "limit": { "type": "integer", "description": "Max entities to return (default 30)", "default": 30 },
                        "direction": { "type": "string", "description": "Direction of traversal: 'out' walks what the focal depends on, 'in' walks what depends on the focal (dependents / blast radius), 'both' merges. Default 'both'.", "default": "both" }
                    },
                    "required": ["entity_id"]
                }),
            },
            ToolDefinition {
                name: "benchmark".into(),
                description: crate::handlers::bench::BENCHMARK_DESC.into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "category": { "type": "string", "description": "Metric category: velocity, reliability, or economic" }
                    }
                }),
            },
            ToolDefinition {
                name: "register_session".into(),
                description: crate::handlers::sessions::REGISTER_SESSION_DESC.into(),
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
                description: crate::handlers::sessions::SESSION_START_DESC.into(),
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
                description: crate::handlers::sessions::SESSION_HEARTBEAT_DESC.into(),
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
                description: crate::handlers::sessions::SESSION_END_DESC.into(),
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
                description: crate::handlers::sessions::REGISTER_INTENT_DESC.into(),
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
                description: crate::handlers::sessions::RELEASE_INTENT_DESC.into(),
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
                description: crate::handlers::sessions::CHECK_TRAFFIC_DESC.into(),
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
                name: "kin_transaction_begin".into(),
                description: "Begin an exact repository mutation transaction. Product commits currently support full-body edits of existing source entities and relation add/upsert/remove operations; unsupported source insertion/deletion fails before repository mutation. Returns a unique transaction_id.".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "session_id": { "type": "string", "description": "Session UUID owning the transaction" },
                        "scope": { "type": "string", "description": "Target scope (e.g. filename, module, etc.)" }
                    },
                    "required": ["session_id", "scope"]
                }),
            },
            ToolDefinition {
                name: "kin_transaction_stage".into(),
                description: crate::handlers::sessions::TRANSACTION_STAGE_DESC.into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "transaction_id": { "type": "string", "description": "Transaction UUID" },
                        "session_id": { "type": "string", "description": "Optional owning session UUID mirror; when present in enforce mode it must match the authenticated caller and transaction owner" },
                        "operations": {
                            "type": "array",
                            "description": "Array of mutation operations to stage",
                            "items": transaction_operation_schema()
                        }
                    },
                    "required": ["transaction_id", "operations"]
                }),
            },
            ToolDefinition {
                name: "kin_transaction_validate".into(),
                description: "Validate the intrinsic shape and supported verb/payload combinations of staged mutations without committing them. Repository-entity existence, exact spans, source bytes, tree cleanliness, and semantic reparse are validated against authority at commit time.".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "transaction_id": { "type": "string", "description": "Transaction UUID" },
                        "session_id": { "type": "string", "description": "Optional owning session UUID mirror; when present in enforce mode it must match the authenticated caller and transaction owner" }
                    },
                    "required": ["transaction_id"]
                }),
            },
            ToolDefinition {
                name: "kin_transaction_commit".into(),
                description: crate::handlers::sessions::TRANSACTION_COMMIT_DESC.into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "transaction_id": { "type": "string", "description": "Transaction UUID" },
                        "session_id": { "type": "string", "description": "Optional owning session UUID mirror; when present in enforce mode it must match the authenticated caller and transaction owner" },
                        "operations": {
                            "type": "array",
                            "description": "Optional exact mutation operations to stage atomically in this commit request",
                            "items": transaction_operation_schema()
                        }
                    },
                    "required": ["transaction_id"]
                }),
            },
            ToolDefinition {
                name: "kin_transaction_abort".into(),
                description: "Abort an active or validated transaction and discard all staged mutations. Once kin_transaction_commit has fenced the transaction for publication this is refused, because repository authority may already have moved; re-send the commit instead, which resumes the fenced payload idempotently and reports whether it landed. You do not need abort to recover from a refused commit: a commit refused before publication already clears its staged operations and names them, so corrected ones go on the same transaction.".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "transaction_id": { "type": "string", "description": "Transaction UUID" },
                        "session_id": { "type": "string", "description": "Optional owning session UUID mirror; when present in enforce mode it must match the authenticated caller and transaction owner" }
                    },
                    "required": ["transaction_id"]
                }),
            },
            ToolDefinition {
                name: "explore_codebase".into(),
                description: crate::handlers::entities::EXPLORE_CODEBASE_DESC.into(),
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
                description: crate::handlers::work::WORK_CREATE_DESC.into(),
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
                description: crate::handlers::work::WORK_LIST_DESC.into(),
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
                description: crate::handlers::work::WORK_SHOW_DESC.into(),
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
                description: crate::handlers::work::WORK_LINK_DESC.into(),
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
                description: crate::handlers::work::WORK_DECOMPOSE_DESC.into(),
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
                description: crate::handlers::work::WORK_BLOCK_DESC.into(),
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
                description: crate::handlers::work::WORK_IMPLEMENT_DESC.into(),
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
                description: crate::handlers::work::WORK_STATUS_DESC.into(),
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
                description: crate::handlers::work::ANNOTATION_ADD_DESC.into(),
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
                description: crate::handlers::work::ANNOTATION_LIST_DESC.into(),
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
                description: crate::handlers::work::ANNOTATION_MARK_RESOLVED_DESC.into(),
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
                description: crate::handlers::work::TODO_IMPORT_DESC.into(),
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
                description: crate::handlers::verification::VERIFY_ENTITY_DESC.into(),
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
                description: crate::handlers::verification::COVERAGE_SUMMARY_DESC.into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {}
                }),
            },
            ToolDefinition {
                name: "kin_security_scan".into(),
                description: crate::handlers::verification::SECURITY_SCAN_DESC.into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "propagate": { "type": "boolean", "description": "If true, compute downstream impact for each finding", "default": false }
                    }
                }),
            },
            ToolDefinition {
                name: "kin_release_check".into(),
                description: crate::handlers::verification::RELEASE_CHECK_DESC.into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "branch": { "type": "string", "description": "Branch authority to evaluate; may be omitted only when main exists or graph truth has exactly one branch" },
                        "source_change_id": { "type": "string", "description": "Optional observed branch head; a moved branch fails the advisory CAS check" },
                        "expected_entity_count": { "type": "integer", "minimum": 0, "description": "Optional release-marker count to validate against the immutable source" },
                        "force": { "type": "boolean", "description": "Override only the baseline 50% immutable source-bound proof coverage threshold", "default": false },
                        "require_proof": { "type": "boolean", "description": "Require every entity to have immutable source-bound passing proof", "default": false },
                        "require_approval": { "type": "boolean", "description": "Require a known human approval for every reachable non-root change", "default": false }
                    }
                }),
            },
            ToolDefinition {
                name: "kin_contract_check".into(),
                description: crate::handlers::verification::CONTRACT_CHECK_DESC.into(),
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
                description: crate::handlers::provenance::PROVENANCE_QUERY_DESC.into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "entity_id": { "type": "string", "description": "Entity UUID to query provenance for" },
                        "offset": { "type": "integer", "minimum": 0, "default": 0, "description": "Index into the entity's changes, newest first. Follow a prior result's next_offset to reach older changes." },
                        "limit": { "type": "integer", "minimum": 1, "maximum": 200, "default": 20, "description": "Max changes per page. Default 20." },
                        "compact": { "type": "boolean", "default": true, "description": "If true (default), each change reports its entity/relation/tree deltas by count. If false, the full delta payloads are included, which is unbounded in size and not for agent context." }
                    },
                    "required": ["entity_id"],
                    "additionalProperties": false
                }),
            },
            // Phase 11: Review mutation tools
            ToolDefinition {
                name: "kin_review_create".into(),
                description: crate::handlers::review::REVIEW_CREATE_DESC.into(),
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
                description: crate::handlers::review::REVIEW_DECIDE_DESC.into(),
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
                description: crate::handlers::review::REVIEW_NOTE_ADD_DESC.into(),
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
                description: crate::handlers::review::REVIEW_DISCUSS_DESC.into(),
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
                description: crate::handlers::review::REVIEW_DISCUSS_REPLY_DESC.into(),
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
                description: crate::handlers::review::REVIEW_DISCUSS_RESOLVE_DESC.into(),
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
                description: crate::handlers::review::REVIEW_ASSIGN_DESC.into(),
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
                description: crate::handlers::review::REVIEW_UNASSIGN_DESC.into(),
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
                description: crate::handlers::review::REVIEW_LIST_DESC.into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "state": { "type": "string", "description": "Filter by decision state: pending, approved, needs_work, blocked" }
                    }
                }),
            },
            ToolDefinition {
                name: "kin_review_get".into(),
                description: crate::handlers::review::REVIEW_GET_DESC.into(),
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
                description: crate::handlers::entities::GRAPH_STATUS_DESC.into(),
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
        "get_entity_source",
        "get_entity_body",
        "get_context_pack",
        "trace_computation",
        "trace_data_flow",
        "find_references",
        "dead_code",
        "find_dead_code_seeded",
        "graph_neighborhood",
        "explore_codebase",
    ]
}

/// Tool names for the small default agent profile.
pub fn agent_default_tool_names() -> &'static [&'static str] {
    &[
        "kin_artifact_list",
        "kin_artifact_read",
        "kin_graph_status",
        "semantic_locate",
        "semantic_search",
        "get_context_pack",
        // The flagship question a Kin agent is asked is "what breaks if I change
        // this". Its named tool belongs in the profile every configured agent
        // receives; without it the CLI can answer what the agent cannot.
        "impact_analysis",
        // A profile carrying the transaction write surface must carry a direct
        // entity-body read. Staging a body update means restating the entity's
        // current source, so an agent without a body read can only guess it --
        // and a guessed body silently overwrites the real one on commit. The
        // discovery tools hand back ids and bounded snippets; this is the tool
        // that turns an id into the exact graph-owned body.
        "get_entity_source",
        "trace_data_flow",
        "find_references",
        "graph_neighborhood",
        "kin_session_start",
        "kin_session_heartbeat",
        "kin_session_end",
        "kin_transaction_begin",
        "kin_transaction_stage",
        "kin_transaction_commit",
        // Without abort, an agent that decides against a transaction, or that
        // wants to start clean after a refusal, has no way out of the one it
        // holds: begin/stage/commit can only push work forward. A write profile
        // that cannot abandon a transaction cannot honor "nothing half-applies".
        "kin_transaction_abort",
        "kin_provenance_query",
    ]
}

/// Tool names for the READ-ONLY graph-native ContextBench profile.
///
/// This is the belt the graph-native benchmark agent arm drives: purely
/// graph-native retrieval/read tools and NO write-side session/transaction tools
/// (which `agent_default_tool_names` carries) and NO filesystem tools (there are
/// none to expose — the entire MCP surface is graph-backed). It includes
/// `semantic_locate` (entity-centric + paged), which `benchmark_tool_names`
/// omits, so the agent can do natural-language entity retrieval, drill via
/// `find_references`/`trace_data_flow`/`graph_neighborhood`, and read bodies via
/// `get_entity_source`/`get_context_pack` — all without ever touching a file.
pub fn context_bench_tool_names() -> &'static [&'static str] {
    &[
        "kin_artifact_list",
        "kin_artifact_read",
        "kin_graph_status",
        "semantic_locate",
        "semantic_search",
        "get_entity",
        "get_entity_source",
        "get_entity_body",
        "get_context_pack",
        "trace_data_flow",
        "find_references",
        "graph_neighborhood",
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
        assert!(json.contains("semantic_locate"));
        assert!(json.contains("get_entity_source"));
        assert!(json.contains("get_entity_sources"));
        assert!(json.contains("find_references"));
        assert!(json.contains("bulk_check_references"));
        assert!(json.contains("impact_analysis"));
        assert!(json.contains("register_session"));
        // Phase 7 tools
        assert!(json.contains("kin_session_start"));
        assert!(json.contains("kin_session_heartbeat"));
        assert!(json.contains("kin_session_end"));
        assert!(json.contains("kin_register_intent"));
        assert!(json.contains("kin_release_intent"));
        assert!(json.contains("kin_check_traffic"));
        // Transaction tools
        assert!(json.contains("kin_transaction_begin"));
        assert!(json.contains("kin_transaction_stage"));
        assert!(json.contains("kin_transaction_validate"));
        assert!(json.contains("kin_transaction_commit"));
        assert!(json.contains("kin_transaction_abort"));
    }

    #[test]
    fn serialized_tools_list_exposes_the_real_transaction_operation_contract() {
        fn required_set(schema: &serde_json::Value) -> std::collections::BTreeSet<String> {
            schema["required"]
                .as_array()
                .expect("schema branch must declare required fields")
                .iter()
                .map(|field| {
                    field
                        .as_str()
                        .expect("required field must be a string")
                        .to_string()
                })
                .collect()
        }

        let serialized =
            serde_json::to_value(tool_definitions()).expect("tools/list must serialize");
        let tools = serialized["tools"]
            .as_array()
            .expect("serialized tools/list must contain a tools array");

        for (tool_name, expected_description, expected_top_required) in [
            (
                "kin_transaction_stage",
                crate::handlers::sessions::TRANSACTION_STAGE_DESC,
                ["operations", "transaction_id"].as_slice(),
            ),
            (
                "kin_transaction_commit",
                crate::handlers::sessions::TRANSACTION_COMMIT_DESC,
                ["transaction_id"].as_slice(),
            ),
        ] {
            let tool = tools
                .iter()
                .find(|tool| tool["name"] == tool_name)
                .unwrap_or_else(|| panic!("{tool_name} must be exposed by tools/list"));
            assert_eq!(tool["description"], expected_description);
            assert!(
                tool["description"]
                    .as_str()
                    .is_some_and(|description| description.contains("payload-less")),
                "{tool_name} must advertise the preferred payload-less source-edit form"
            );
            if tool_name == "kin_transaction_stage" {
                let description = tool["description"].as_str().unwrap();
                assert!(description.contains("indentation"), "{description}");
                assert!(description.contains("[truncated]"), "{description}");
            }

            let top_required = required_set(&tool["inputSchema"]);
            let expected_top_required: std::collections::BTreeSet<String> = expected_top_required
                .iter()
                .map(|field| (*field).into())
                .collect();
            assert_eq!(top_required, expected_top_required, "{tool_name}");

            let variants = tool["inputSchema"]["properties"]["operations"]["items"]["oneOf"]
                .as_array()
                .expect("transaction operations must be disjoint oneOf variants");
            assert_eq!(variants.len(), 2, "{tool_name}");

            let body_edit = variants
                .iter()
                .find(|variant| variant["title"] == "Entity source body edit")
                .expect("payload-less body-edit branch");
            assert_eq!(
                required_set(body_edit),
                ["body", "description", "target", "verb"]
                    .into_iter()
                    .map(String::from)
                    .collect()
            );
            assert!(
                body_edit["properties"].get("payload").is_none(),
                "payload-less body-edit branch must reject payload"
            );

            let structured = variants
                .iter()
                .find(|variant| variant["title"] == "Structured entity or relation mutation")
                .expect("structured payload branch");
            assert_eq!(
                required_set(structured),
                ["description", "payload", "target", "verb"]
                    .into_iter()
                    .map(String::from)
                    .collect()
            );
        }
    }

    #[test]
    fn expected_tool_count() {
        let list = tool_definitions();
        // 54 + 5 transaction tools + 1 semantic_locate + 1 shadow_gate_report
        // + 1 get_entity_sources + 2 exact artifact tools = 64
        assert_eq!(list.tools.len(), 64);
    }

    /// The tool reference must name every tool the registry serves, and its
    /// headline count must be that number.
    ///
    /// The reference presents itself as the whole surface, so a tool the
    /// registry defines but the page never names is invisible to the agents
    /// the page exists for, and two of the tools this caught ship in
    /// `agent-default`. Nothing tied the page to the registry, which is why it
    /// drifted to claiming 62 while serving 64. `docs/env-vars.md` has exactly
    /// this tie and did not drift.
    #[test]
    fn mcp_doc_names_every_registered_tool() {
        let doc = include_str!("../../../docs/mcp-tools.md");
        let list = tool_definitions();
        for tool in &list.tools {
            assert!(
                doc.contains(tool.name.as_str()),
                "{} is served by the registry but named nowhere in docs/mcp-tools.md",
                tool.name
            );
        }
        let headline = format!("exposes {} semantic tools", list.tools.len());
        assert!(
            doc.contains(headline.as_str()),
            "docs/mcp-tools.md must state the served tool count, which is now {}",
            list.tools.len()
        );
        assert!(
            !doc.contains("kin_not_a_real_tool"),
            "the containment probe must be able to answer no, or the assertions \
             above prove nothing"
        );
    }

    #[test]
    fn agent_default_profile_is_small_and_valid() {
        let list = tool_definitions();
        let all: std::collections::HashSet<&str> =
            list.tools.iter().map(|t| t.name.as_str()).collect();
        let profile = agent_default_tool_names();

        assert!(
            profile.len() >= 10 && profile.len() <= 19,
            "agent-default should be small but cover the wedge; got {}",
            profile.len()
        );
        assert!(
            profile.len() < list.tools.len() / 2,
            "agent-default ({}) must be far smaller than the full surface ({})",
            profile.len(),
            list.tools.len()
        );
        for name in profile {
            assert!(
                all.contains(name),
                "agent-default tool '{name}' is not in tool_definitions()"
            );
        }
        for required in [
            "semantic_locate",
            "get_context_pack",
            // The write surface is only safe with a body read beside it.
            "get_entity_source",
            "kin_transaction_commit",
            "kin_provenance_query",
            // kin_session_start tells the agent to keep the session alive with
            // this tool. A profile that carries the advice without the tool
            // strands any agent whose read phase outlasts the idle TTL.
            "kin_session_heartbeat",
            // The only clean exit from a transaction the agent decided against.
            "kin_transaction_abort",
            // The flagship question. A configured agent that cannot ask what a
            // change affects cannot do the thing Kin is described as doing, and
            // the CLI answering it is no help to the agent surface.
            "impact_analysis",
        ] {
            assert!(
                profile.contains(&required),
                "agent-default must include {required}"
            );
        }

        // The body-shaped read tool must say where the source text arrives, so an
        // agent reaching for source knows which field carries it.
        let context_pack = list
            .tools
            .iter()
            .find(|tool| tool.name == "get_context_pack")
            .expect("get_context_pack is in the profile");
        assert!(
            context_pack.description.contains("focal_entity.body"),
            "get_context_pack must name the field carrying the source text"
        );

        // Structural guard on the write half of this profile: any profile that can
        // stage and commit graph writes must also be able to read an entity's
        // exact body. Staging a body update without one means guessing the
        // current source, and a guessed body overwrites the real one on commit.
        let can_write = profile
            .iter()
            .any(|name| name.starts_with("kin_transaction_"));
        if can_write {
            assert!(
                profile
                    .iter()
                    .any(|name| matches!(*name, "get_entity_source" | "get_entity_body")),
                "a profile with the transaction write surface must carry a direct \
                 entity-body read; got {profile:?}"
            );
        }

        let allowed: std::collections::HashSet<&str> = profile.iter().copied().collect();
        let visible = list
            .tools
            .iter()
            .filter(|t| allowed.contains(t.name.as_str()))
            .count();
        assert_eq!(
            visible,
            profile.len(),
            "every profile tool should be listable"
        );
    }

    #[test]
    fn context_bench_profile_is_read_only_and_graph_native() {
        let list = tool_definitions();
        let all: std::collections::HashSet<&str> =
            list.tools.iter().map(|t| t.name.as_str()).collect();
        let profile = context_bench_tool_names();

        // Every belt tool is a real, listable graph tool.
        for name in profile {
            assert!(
                all.contains(name),
                "context-bench tool '{name}' is not in tool_definitions()"
            );
        }
        // It carries semantic_locate (the entity-centric NL retrieval surface)
        // which the benchmark profile omits.
        assert!(profile.contains(&"semantic_locate"));
        assert!(!benchmark_tool_names().contains(&"semantic_locate"));

        // READ-ONLY: no write-side session/transaction/intent tools.
        for forbidden in profile {
            assert!(
                !forbidden.starts_with("kin_session_")
                    && !forbidden.starts_with("kin_transaction_")
                    && !forbidden.contains("intent")
                    && !forbidden.starts_with("register_"),
                "context-bench must be read-only; found write-side tool '{forbidden}'"
            );
        }

        // GRAPH-NATIVE: not a single filesystem tool name in the belt (there are
        // none to expose — the whole MCP surface is graph-backed).
        for fs in ["cat", "ls", "grep", "find", "read_file", "open_file"] {
            assert!(
                !profile.contains(&fs),
                "context-bench belt must have zero filesystem tools; found '{fs}'"
            );
        }
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
