use crate::types::{ToolDefinition, ToolsListResult};

/// Build the list of all MCP tools that Kin exposes.
pub fn tool_definitions() -> ToolsListResult {
    ToolsListResult {
        tools: vec![
            ToolDefinition {
                name: "semantic_search".into(),
                description: "Search for entities (functions, classes, types, traits) by name pattern, kind, or language. USE THIS INSTEAD OF grep/rg/find when looking for code definitions. Returns exact file:line locations with 4-22x less noise than text search.".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "query": { "type": "string", "description": "Name pattern to search for" },
                        "kind": { "type": "string", "description": "Entity kind filter (function, class, etc.)" },
                        "language": { "type": "string", "description": "Language filter (rust, typescript, etc.)" },
                        "limit": { "type": "integer", "description": "Max results to return", "default": 20 }
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
                description: "Build a token-budgeted context pack for an entity. USE THIS INSTEAD OF reading entire files — returns only the focal entity, its callers, and dependencies within a token budget. Typically uses 84% fewer tokens than reading all matching files.".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "entity_id": { "type": "string", "description": "Focal entity UUID" },
                        "token_budget": { "type": "integer", "description": "Token budget (8000, 16000, or 32000)", "default": 16000 },
                        "depth": { "type": "integer", "description": "Dependency traversal depth", "default": 2 },
                        "include_traffic": { "type": "boolean", "description": "Include active nearby agent traffic in response", "default": true }
                    },
                    "required": ["entity_id"]
                }),
            },
            ToolDefinition {
                name: "impact_analysis".into(),
                description: "Analyze downstream impact of changes between two semantic change IDs. USE THIS INSTEAD OF manually tracing callers — shows all affected entities, contracts, and tests.".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "base": { "type": "string", "description": "Base semantic change ID (hex)" },
                        "head": { "type": "string", "description": "Head semantic change ID (hex)" },
                        "include_traffic": { "type": "boolean", "description": "Include active traffic on impacted entities", "default": true }
                    },
                    "required": ["base", "head"]
                }),
            },
            ToolDefinition {
                name: "semantic_diff".into(),
                description: "Compute entity-level diff between two semantic changes. USE THIS INSTEAD OF git diff — shows which entities were added, modified, or removed, not raw line changes.".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "base": { "type": "string", "description": "Base semantic change ID (hex)" },
                        "head": { "type": "string", "description": "Head semantic change ID (hex)" }
                    },
                    "required": ["base", "head"]
                }),
            },
            ToolDefinition {
                name: "semantic_review".into(),
                description: "Full semantic review: diff + impact + risk assessment. The most comprehensive analysis tool — combines entity-level diff, downstream impact analysis, and risk scoring in one call.".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "base": { "type": "string", "description": "Base semantic change ID (hex)" },
                        "head": { "type": "string", "description": "Head semantic change ID (hex)" },
                        "include_traffic": { "type": "boolean", "description": "Include active traffic on reviewed entities", "default": true }
                    },
                    "required": ["base", "head"]
                }),
            },
            ToolDefinition {
                name: "dead_code".into(),
                description: "Find dead/unreachable code in the semantic graph. Identifies entities with no incoming relations — useful for cleanup and refactoring.".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "limit": { "type": "integer", "description": "Max results", "default": 50 }
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
                description: "Get the dependency neighborhood of an entity. USE THIS to understand what an entity depends on and what depends on it — traverses the relation graph to the specified depth.".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "entity_id": { "type": "string", "description": "Entity UUID" },
                        "depth": { "type": "integer", "description": "Traversal depth", "default": 2 }
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
                description: "Show full details of a work item including children and implementors".into(),
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
            // Phase 8: Annotation tools
            ToolDefinition {
                name: "kin_annotation_add".into(),
                description: "Add a semantic annotation (comment, warning, instruction, reasoning) to scopes".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "kind": { "type": "string", "description": "Annotation kind: comment, warning, instruction, reasoning" },
                        "body": { "type": "string", "description": "Annotation text" },
                        "scopes": { "type": "array", "items": { "type": "string" }, "description": "Target scopes" }
                    },
                    "required": ["kind", "body", "scopes"]
                }),
            },
            ToolDefinition {
                name: "kin_annotation_list".into(),
                description: "List annotations for given scopes".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "scopes": { "type": "array", "items": { "type": "string" }, "description": "Scopes to query" },
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
                description: "Check test coverage and run verification for a specific entity. Returns linked tests and coverage statistics.".into(),
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
        ],
    }
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
        // 11 original + 6 Phase 7 + 8 Phase 8 + 6 Phase 9-10 = 31
        assert_eq!(list.tools.len(), 31);
    }

    #[test]
    fn key_tools_have_usage_guidance() {
        let list = tool_definitions();
        let guided_tools = ["semantic_search", "get_context_pack", "impact_analysis", "semantic_diff", "graph_neighborhood"];
        for name in &guided_tools {
            let tool = list.tools.iter().find(|t| t.name == *name).unwrap();
            assert!(
                tool.description.contains("USE THIS") || tool.description.contains("use this"),
                "{} should have 'USE THIS' guidance in description",
                name
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
