// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use crate::types::{ToolAnnotations, ToolDefinition, ToolsListResult};

/// The `max_chars` property every retrieval tool advertises, built from the
/// budget's own constants.
///
/// Nine tools carried a byte-identical copy of this block with the numbers
/// written out, so moving the ceiling meant editing ten homes and a release read
/// whichever one was missed. The stranger who asked for 120,000 characters was
/// reading one of those copies, which advertised 400,000 while a real client
/// refused 117,313. There is one home now, and it is the constant.
fn max_chars_property() -> serde_json::Value {
    serde_json::json!({
        "type": "integer",
        "description": format!(
            "Serialized characters this response may occupy (default {default}, clamped \
             {min}..{max}). The ceiling is what a real MCP client accepts, not what this server \
             could build. The tool enforces the budget itself: it sheds ranking explanation, then \
             duplicated hit shapes, then inline source, and only then withholds entries, and it \
             never empties a list it cut. A list the budget cut keeps at least one entry and is \
             reported under `elisions` with what it kept, what it lost, and why, so an empty array \
             always means the walk found none. Any cut is also reported in `degradations` and in \
             `_kin.response`, which carries the size the response had before the budget.",
            default = crate::budget::RESPONSE_DEFAULT_MAX_CHARS,
            min = crate::budget::RESPONSE_MIN_MAX_CHARS,
            max = crate::budget::RESPONSE_MAX_MAX_CHARS,
        ),
        "default": crate::budget::RESPONSE_DEFAULT_MAX_CHARS,
        "minimum": crate::budget::RESPONSE_MIN_MAX_CHARS,
        "maximum": crate::budget::RESPONSE_MAX_MAX_CHARS,
    })
}

/// `trace_data_flow`'s own spelling of the same budget.
fn trace_max_chars_property() -> serde_json::Value {
    serde_json::json!({
        "type": "integer",
        "description": format!(
            "Serialized characters this response may occupy (default {default}, clamped \
             {min}..{max}, the same budget every retrieval tool answers under). The tool enforces \
             it itself, dropping bodies before edges, and it never returns an empty chain for a \
             walk that found steps: a cut chain keeps at least one step and reports the rest under \
             `elisions.chain` and `steps_omitted`. `max_chars` is the same parameter under the \
             name the other retrieval tools use.",
            default = crate::budget::RESPONSE_DEFAULT_MAX_CHARS,
            min = crate::budget::RESPONSE_MIN_MAX_CHARS,
            max = crate::budget::RESPONSE_MAX_MAX_CHARS,
        ),
        "default": crate::budget::RESPONSE_DEFAULT_MAX_CHARS,
        "minimum": crate::budget::RESPONSE_MIN_MAX_CHARS,
        "maximum": crate::budget::RESPONSE_MAX_MAX_CHARS,
    })
}

/// The alias spelling, which carries the same numbers so a caller cannot read
/// two ceilings off one tool.
fn trace_max_chars_alias_property() -> serde_json::Value {
    serde_json::json!({
        "type": "integer",
        "description": "Alias for max_response_chars, the spelling shared with the other \
                        retrieval tools.",
        "default": crate::budget::RESPONSE_DEFAULT_MAX_CHARS,
        "minimum": crate::budget::RESPONSE_MIN_MAX_CHARS,
        "maximum": crate::budget::RESPONSE_MAX_MAX_CHARS,
    })
}

/// A tool that only reads graph truth.
///
/// `openWorldHint` is false on every tool this crate defines: the whole surface
/// answers from the local repository graph and reaches no external world.
fn read_only(title: &str) -> ToolAnnotations {
    ToolAnnotations {
        title: title.into(),
        read_only_hint: true,
        destructive_hint: false,
        idempotent_hint: true,
        open_world_hint: false,
    }
}

/// A tool that records new state and neither replaces nor removes existing
/// state, where calling it again records more.
fn mutates(title: &str) -> ToolAnnotations {
    ToolAnnotations {
        title: title.into(),
        read_only_hint: false,
        destructive_hint: false,
        idempotent_hint: false,
        open_world_hint: false,
    }
}

/// A tool that changes state without discarding recorded content, where a
/// repeat call with the same arguments leaves the same state behind.
fn mutates_idempotent(title: &str) -> ToolAnnotations {
    ToolAnnotations {
        title: title.into(),
        read_only_hint: false,
        destructive_hint: false,
        idempotent_hint: true,
        open_world_hint: false,
    }
}

/// A tool that can overwrite or discard existing state, where a repeat call
/// with the same arguments leaves the same state behind.
fn destructive_idempotent(title: &str) -> ToolAnnotations {
    ToolAnnotations {
        title: title.into(),
        read_only_hint: false,
        destructive_hint: true,
        idempotent_hint: true,
        open_world_hint: false,
    }
}

/// Honest JSON Schema for one transaction operation.
///
/// The product daemon accepts six materially different shapes. A source-body
/// edit, a new source file, a rewritten source file, a retirement, and a rename
/// are all intentionally payload-less; structured entity/relation mutations
/// require `payload`. Keeping these as disjoint `oneOf` branches prevents MCP
/// clients from being told that the preferred source-edit form is invalid.
///
/// No two branches can match one operation: the five payload-less branches
/// carry disjoint verb enums, and the structured branch requires `payload`,
/// which none of the others accepts. The rewrite has a verb of its own rather
/// than a path reading of `update` for that reason: an entity name and a
/// repository path are both bare strings, so one verb covering both would make
/// an operation's meaning depend on how its target happened to resolve.
fn transaction_operation_schema() -> serde_json::Value {
    serde_json::json!({
        "oneOf": [
            {
                "title": "Retired source file",
                "type": "object",
                "properties": {
                    "verb": {
                        "type": "string",
                        "enum": ["delete", "remove"],
                        "description": "Retire a tracked file. This is the only operation that removes a file, along with every entity derived from it and every edge incident to those entities."
                    },
                    "target": {
                        "type": "string",
                        "minLength": 1,
                        "description": "Repository-relative path of the file to retire, such as \"src/parser.py\". It must be a path repository authority already tracks; a path the graph has never seen is refused."
                    },
                    "description": {
                        "type": "string",
                        "description": "Human-readable explanation of this change."
                    }
                },
                "required": ["verb", "target", "description"],
                "additionalProperties": false
            },
            {
                "title": "Renamed source file",
                "type": "object",
                "properties": {
                    "verb": {
                        "type": "string",
                        "enum": ["rename", "move"],
                        "description": "Relocate a tracked file. Entity identity, history, and incoming edges survive the move, which is what separates this from a delete followed by a create."
                    },
                    "target": {
                        "type": "string",
                        "minLength": 1,
                        "description": "Repository-relative path the file lives at now. It must be a path repository authority already tracks."
                    },
                    "destination": {
                        "type": "string",
                        "minLength": 1,
                        "description": "Repository-relative path the file moves to. It must not be tracked already, and it follows the same path rules as `target`: no leading slash, no \"..\", and no Kin or Git control component."
                    },
                    "description": {
                        "type": "string",
                        "description": "Human-readable explanation of this change."
                    }
                },
                "required": ["verb", "target", "destination", "description"],
                "additionalProperties": false
            },
            {
                "title": "New source file",
                "type": "object",
                "properties": {
                    "verb": {
                        "type": "string",
                        "enum": ["create", "add", "insert"],
                        "description": "Admit a source file the graph has never seen. This is the only operation that introduces a new file."
                    },
                    "target": {
                        "type": "string",
                        "minLength": 1,
                        "description": "Repository-relative path of the new file, such as \"src/parser.py\". No leading slash, no \"..\", and no Kin or Git control component. A path the graph already tracks is refused; rewrite that one with verb 'replace' instead."
                    },
                    "body": {
                        "type": "string",
                        "minLength": 1,
                        "description": "The file's complete UTF-8 source text. Kin parses it with the same extractor the ingest path uses, so every entity in it enters the graph, and writes the file into the working directory when the transaction commits. You do not need to write the file yourself first."
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
                "title": "Replaced source file",
                "type": "object",
                "properties": {
                    "verb": {
                        "type": "string",
                        "enum": ["replace", "overwrite"],
                        "description": "Rewrite a tracked file from its complete new text. This is the operation to use when you hold a path and the file's new contents, which is what a local edit or write leaves you holding."
                    },
                    "target": {
                        "type": "string",
                        "minLength": 1,
                        "description": "Repository-relative path of the file to rewrite, such as \"src/parser.py\". It must be a path repository authority already tracks; a path the graph has never seen is refused, and 'create' is the verb for it."
                    },
                    "body": {
                        "type": "string",
                        "minLength": 1,
                        "description": "The file's complete new UTF-8 source text, never a fragment or a diff. Kin reparses it with the same extractor the ingest path uses, so entities the new text adds enter the graph, entities it drops leave it, and the rest keep their identity. A body identical to the tracked contents is refused as an empty change."
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

/// Build the list of all MCP tools that Kin exposes, in name order.
///
/// The order is part of the contract. A client caches the prompt it builds from
/// `tools/list`, so a surface that reordered between builds would miss that
/// cache for every session. Sorting by name also means the order does not
/// depend on where a new tool is inserted in the registry below.
pub fn tool_definitions() -> ToolsListResult {
    let mut list = registered_tools();
    list.tools.sort_by(|left, right| left.name.cmp(&right.name));
    list
}

fn registered_tools() -> ToolsListResult {
    ToolsListResult {
        tools: vec![
            ToolDefinition {
                name: "kin_artifact_list".into(),
                description: crate::handlers::artifacts::ARTIFACT_LIST_DESC.into(),
                annotations: read_only("List artifacts"),
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
                annotations: read_only("Read artifact"),
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
                annotations: read_only("Semantic search"),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "max_chars": max_chars_property(),
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
                annotations: read_only("Semantic locate"),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "max_chars": max_chars_property(),
                        "compact": { "type": "boolean", "description": "If true (default), omit ranking explanation and per-signal breakdowns and return one shape per hit. Pass false (or explain: true) to get the breakdowns back.", "default": true },
                        "query": { "type": "string", "description": "Natural-language description of the code to find. Optional when paging with `cursor`." },
                        "queries": {
                            "type": "array",
                            "items": { "type": "string" },
                            "description": "Optional additional query variants for multi-query fan-out. When present, `query` plus each variant are retrieved independently and their rankings RRF-fused into one deduped result. The response echoes the fan-out once under `queries`, and each hit's `matched_variant_indexes` gives the positions in that list of the variants that surfaced it. Diverse variants (identifiers, behavior, subsystem) recover more relevant hits than any single phrasing. Requires the fused pipeline (automatic when set)."
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
                            "description": "Attach a bounded inline source excerpt to each entity hit, projected from graph-owned content. Read it from `body` on the fused pipeline (routing `fused-v1`, the default) and from `snippet` on the cosine pipeline (routing `cosine-v0`); `routing` on the response says which answered. Each hit carries the text once. Entity granularity only: a file hit has no single entity body. A hit with no graph-owned body carries no excerpt rather than a placeholder.",
                            "default": true
                        },
                        "snippet_alias": {
                            "type": "boolean",
                            "description": "Repeat each fused hit's `body` under a second `snippet` key, for a consumer that reads that name. Off by default: the repeat doubles the most expensive field on every hit and, under the response budget, evicts real hits to make room for copies. Prefer reading `body` on the fused pipeline. No effect on the cosine pipeline, whose text is already `snippet`.",
                            "default": false
                        },
                        "pipeline": {
                            "type": "string",
                            "enum": ["fused", "cosine"],
                            "description": "Force a retrieval pipeline for this call: 'fused' (full multi-signal locate ranking) or 'cosine' (legacy single-vector). The default is 'fused' on every profile, the same ranking kin locate serves; 'cosine' is the per-call escape hatch for A/B comparison."
                        },
                        "include_tests": {
                            "type": "boolean",
                            "description": "Rank test-role entities alongside source. Off by default: locate demotes test-role entities, and at several stages excludes them, unless the query text itself reads as being about tests. That default is right for `where does this feature live` and wrong when you already know you are asking for a test, and a keyword heuristic over your query was the only thing that lifted it. When the default withholds test paths, the response says how many under `semantic_coverage.graph_bodies.withheld_test_paths` and records a `graph_role_filter` degradation, so `complete` is never claimed over a population the filter removed.",
                            "default": false
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
                annotations: read_only("Get entity"),
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
                annotations: read_only("Get entity source"),
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
                annotations: read_only("Get entity body"),
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
                annotations: read_only("Get entity sources"),
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
                annotations: read_only("Get context pack"),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "max_chars": max_chars_property(),
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
                annotations: read_only("Trace computation"),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "max_chars": max_chars_property(),
                        "entity_id": { "type": "string", "description": "Focal entity UUID. Required if `query` is not given." },
                        "query": { "type": "string", "description": "Exact entity name to resolve to a focal entity. Required if `entity_id` is not given." },
                        "depth": { "type": "integer", "description": "Dependency traversal depth across the trace neighborhood", "default": 3 },
                        "token_budget": { "type": "integer", "description": "Token budget for the assembled trace response", "default": 8000 },
                        "compact": { "type": "boolean", "description": "If true, return signature-only entries for everyone (smaller). If false (default), focal gets FullBody and deps get SignatureOnly, which is better for trace-style reasoning.", "default": false }
                    }
                }),
            },
            ToolDefinition {
                name: "trace_data_flow".into(),
                description: crate::handlers::entities::TRACE_DATA_FLOW_DESC.into(),
                annotations: read_only("Trace data flow"),
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
                        "limit_per_step": { "type": "integer", "description": "Max relations expanded per step (default 5, capped at 25). Kept by relevance, not by relation order; a step whose fan-out was cut says so with the count it dropped.", "default": 5, "minimum": 1, "maximum": 25 },
                        "target": { "type": "string", "description": "A symbol you are trying to reach, by exact name or UUID. Neighbors from which it is still reachable inside the requested depth survive the per-step cap ahead of neighbors that are not, so the question decides what a narrow walk keeps instead of proximity deciding it. Optional; a target that resolves to nothing is reported in degradations and the chain is still returned." },
                        "include_body": {
                            "type": "boolean",
                            "description": "Inline each step's source body (default true). Pass false to ask for the SHAPE of the chain (names, kinds, roles, spans, edges), which is a fraction of the size and is what you want unless you intend to read the code.",
                            "default": true
                        },
                        "compact": {
                            "type": "boolean",
                            "description": "Alias for include_body: false. Ignored when include_body is given explicitly.",
                            "default": false
                        },
                        "include_type_edges": {
                            "type": "boolean",
                            "description": "Walk THROUGH a type-annotation edge to a type this repository defines (default false). A dataclass field typed with a repo class is a real flow into that class, so the hop is available; it is off by default because a shared type name otherwise joins every entity that annotates with it to every other one. An annotation target the repository does not define stays a leaf either way.",
                            "default": false
                        },
                        "max_response_chars": trace_max_chars_property(),
                        "max_chars": trace_max_chars_alias_property()
                    },
                    "required": ["focal"]
                }),
            },
            ToolDefinition {
                name: "find_references".into(),
                description: crate::handlers::entities::FIND_REFERENCES_DESC.into(),
                annotations: read_only("Find references"),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "max_chars": max_chars_property(),
                        "compact": { "type": "boolean", "description": "If true (default), omit ranking explanation and per-signal breakdowns and return one shape per hit. Pass false (or explain: true) to get the breakdowns back.", "default": true },
                        "entity_id": { "type": "string", "description": "Exact entity UUID. Optional if query is provided." },
                        "query": { "type": "string", "description": "Exact symbol name to resolve. Optional if entity_id is provided." },
                        "relation_kinds": {
                            "type": "array",
                            "description": "Filter relation kinds. Supported values: calls, imports, references. Defaults to all three.",
                            "items": { "type": "string" }
                        },
                        "include_snippets": {
                            "type": "boolean",
                            "description": "If true, each row also carries the referencing entity's signature and a bounded body excerpt. Off by default, because one row is one caller and bodies would then scale with the number of callers. Every row still carries entity_id, which drills to the full body via get_entity_source.",
                            "default": false
                        }
                    }
                }),
            },
            ToolDefinition {
                name: "bulk_check_references".into(),
                description: crate::handlers::entities::BULK_CHECK_REFERENCES_DESC.into(),
                annotations: read_only("Bulk check references"),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "max_chars": max_chars_property(),
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
                annotations: read_only("Impact analysis"),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "max_chars": max_chars_property(),
                        "compact": { "type": "boolean", "description": "If true (default), omit ranking explanation and per-signal breakdowns and return one shape per hit. Pass false (or explain: true) to get the breakdowns back.", "default": true },
                        "base": { "type": "string", "description": "Base semantic change ID (hex)" },
                        "head": { "type": "string", "description": "Head semantic change ID (hex)" },
                        "entity_ids": { "type": "array", "items": { "type": "string" }, "description": "Entity UUIDs to analyze impact for" },
                        "files": { "type": "array", "items": { "type": "string" }, "description": "File paths: resolves to entities, then analyzes impact" },
                        "change_ids": { "type": "array", "items": { "type": "string" }, "description": "Change ID hexes to combine and analyze impact" },
                        "include_traffic": { "type": "boolean", "description": "Include active traffic on impacted entities", "default": true }
                    }
                }),
            },
            ToolDefinition {
                name: "semantic_diff".into(),
                description: crate::handlers::review::SEMANTIC_DIFF_DESC.into(),
                annotations: read_only("Semantic diff"),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "base": { "type": "string", "description": "Base semantic change ID (hex)" },
                        "head": { "type": "string", "description": "Head semantic change ID (hex)" },
                        "entity_ids": { "type": "array", "items": { "type": "string" }, "description": "Entity UUIDs to diff (current state vs history)" },
                        "files": { "type": "array", "items": { "type": "string" }, "description": "File paths: resolves to entities, then diffs" },
                        "change_ids": { "type": "array", "items": { "type": "string" }, "description": "Change ID hexes to combine into one diff" }
                    }
                }),
            },
            ToolDefinition {
                name: "semantic_review".into(),
                description: crate::handlers::review::SEMANTIC_REVIEW_DESC.into(),
                annotations: read_only("Semantic review"),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "base": { "type": "string", "description": "Base semantic change ID (hex)" },
                        "head": { "type": "string", "description": "Head semantic change ID (hex)" },
                        "entity_ids": { "type": "array", "items": { "type": "string" }, "description": "Entity UUIDs to review (current state vs history)" },
                        "files": { "type": "array", "items": { "type": "string" }, "description": "File paths: resolves to entities, then reviews" },
                        "change_ids": { "type": "array", "items": { "type": "string" }, "description": "Change ID hexes to combine into one review" },
                        "format": { "type": "string", "enum": ["text", "json"], "description": "Response format. Use json for editor integrations.", "default": "text" },
                        "include_traffic": { "type": "boolean", "description": "Include active traffic on reviewed entities", "default": true }
                    }
                }),
            },
            ToolDefinition {
                name: "shadow_gate_report".into(),
                description: crate::handlers::review::SHADOW_GATE_REPORT_DESC.into(),
                annotations: read_only("Shadow gate report"),
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
                annotations: read_only("Find dead code"),
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
                annotations: read_only("Find dead code by query"),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "max_chars": max_chars_property(),
                        "compact": { "type": "boolean", "description": "If true (default), omit ranking explanation and per-signal breakdowns and return one shape per hit. Pass false (or explain: true) to get the breakdowns back.", "default": true },
                        "query": {
                            "type": "string",
                            "description": "Search query: concept or partial name to seed candidates"
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
                annotations: read_only("Entity history"),
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
                annotations: read_only("Graph neighborhood"),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "max_chars": max_chars_property(),
                        "compact": { "type": "boolean", "description": "If true (default), omit ranking explanation and per-signal breakdowns and return one shape per hit. Pass false (or explain: true) to get the breakdowns back.", "default": true },
                        "entity_id": { "type": "string", "description": "Entity UUID" },
                        "depth": { "type": "integer", "description": "Traversal depth", "default": 2 },
                        "limit": { "type": "integer", "description": "Max entities to return (default 30)", "default": 30 },
                        "direction": { "type": "string", "description": "Direction of traversal: 'out' walks what the focal depends on, 'in' walks what depends on the focal (dependents / blast radius), 'both' merges. Default 'both'.", "default": "both" }
                    },
                    "required": ["entity_id"]
                }),
            },
            ToolDefinition {
                name: crate::handlers::file_entities::TOOL_NAME.into(),
                description: crate::handlers::file_entities::LIST_FILE_ENTITIES_DESC.into(),
                annotations: read_only("List file entities"),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "description": "Repository-relative path of the file to enumerate, such as \"lib/express.js\". No leading slash, no \"..\", and no Kin or Git control component. A leading \"./\" is dropped and backslashes are read as separators; nothing else is rewritten, because a path resolved by suffix resolves to whichever file happened to end that way. Optional only when `cursor` is given, which already names the file." },
                        "page_size": { "type": "integer", "description": "Entities per page (default 200, clamped 1..1000). `total_in_file` is the whole-file count on every page, so a page smaller than it is a page, never the file.", "default": 200, "minimum": 1, "maximum": 1000 },
                        "cursor": { "type": "string", "description": "Opaque token from a prior result's `next_cursor`, returning the next page of the same enumeration. Pass it back unedited; it carries the path and the count the page was cut from, so a file that changed under the walk is reported as `enumeration_shifted` rather than paged silently against a different list." }
                    }
                }),
            },
            ToolDefinition {
                name: "benchmark".into(),
                description: crate::handlers::bench::BENCHMARK_DESC.into(),
                annotations: read_only("Benchmark metrics"),
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
                annotations: mutates("Register assistant session"),
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
                annotations: mutates("Start agent session"),
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
                annotations: mutates("Heartbeat agent session"),
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
                annotations: mutates_idempotent("End agent session"),
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
                annotations: mutates("Register work intent"),
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
                annotations: mutates_idempotent("Release work intent"),
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
                annotations: read_only("Check agent traffic"),
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
                annotations: mutates("Begin transaction"),
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
                annotations: mutates("Stage transaction operations"),
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
                annotations: mutates_idempotent("Validate transaction"),
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
                annotations: destructive_idempotent("Commit transaction"),
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
                annotations: destructive_idempotent("Abort transaction"),
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
                annotations: read_only("Explore codebase"),
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
                annotations: mutates("Create work item"),
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
                annotations: read_only("List work items"),
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
                annotations: read_only("Show work item"),
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
                annotations: mutates("Link work to scopes"),
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
                annotations: mutates("Decompose work item"),
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
                annotations: mutates("Block work item"),
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
                annotations: mutates("Record work implementation"),
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
                annotations: destructive_idempotent("Set work status"),
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
                annotations: mutates("Add annotation"),
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
                annotations: read_only("List annotations"),
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
                annotations: destructive_idempotent("Resolve annotation"),
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
                annotations: mutates("Import TODO markers"),
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
                annotations: read_only("Verify entity"),
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
                annotations: read_only("Coverage summary"),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {}
                }),
            },
            ToolDefinition {
                name: "kin_security_scan".into(),
                description: crate::handlers::verification::SECURITY_SCAN_DESC.into(),
                annotations: read_only("Security scan"),
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
                annotations: read_only("Release readiness check"),
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
                annotations: read_only("Contract check"),
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
                annotations: read_only("Query provenance"),
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
                annotations: mutates("Create review"),
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
                annotations: mutates("Decide review"),
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
                annotations: mutates("Add review note"),
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
                annotations: mutates("Start review discussion"),
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
                annotations: mutates("Reply to review discussion"),
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
                annotations: destructive_idempotent("Resolve review discussion"),
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
                annotations: mutates("Assign reviewer"),
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
                annotations: destructive_idempotent("Unassign reviewer"),
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
                annotations: read_only("List reviews"),
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
                annotations: read_only("Get review"),
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
                annotations: read_only("Graph status"),
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
        // The batch form of the tool above, and the one this profile named
        // without carrying (FIR-2825). `FIND_REFERENCES_DESC` ships here and
        // tells the caller to reach for `bulk_check_references` rather than
        // call per entity, so every agent read an instruction to use a tool the
        // same profile refused. The filter applies to `tools/call` as well as
        // `tools/list`, so the advice named a tool that answered "not enabled in
        // this MCP profile".
        //
        // It is also the reachability half of absence. `list_file_entities`
        // below enumerates what a file holds and this classifies that set, so
        // "which of these has callers" becomes two graph-backed calls. Without
        // it the surface could rank, walk and enumerate but could never say
        // anything was unused, which is the gap the v0.6.1 stranger spent tasks
        // 5 and 6 on before answering both with grep.
        "bulk_check_references",
        "graph_neighborhood",
        // The enumeration half of discovery. Every other retrieval tool in this
        // profile ranks, filters, or walks, and none of them can say what it
        // left out, so "what is in this file" -- the cheapest question the graph
        // answers and the first one a file-first user asks -- had to be answered
        // by scavenging ids out of a locate ranking and hoping it was whole
        // (FIR-2546).
        crate::handlers::file_entities::TOOL_NAME,
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
/// none to expose, because the entire MCP surface is graph-backed). It includes
/// `semantic_locate` (entity-centric + paged), which `benchmark_tool_names`
/// omits, so the agent can do natural-language entity retrieval, drill via
/// `find_references`/`trace_data_flow`/`graph_neighborhood`, and read bodies via
/// `get_entity_source`/`get_context_pack`, all without ever touching a file.
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
    use std::collections::BTreeSet;

    /// Every budget number a tool advertises has to be the number the budget
    /// enforces. Nine schemas carried byte-identical copies of the default, the
    /// floor and the ceiling written out, and one of those copies said 400,000
    /// while a real client refused 117,313. A caller who reads a schema and gets
    /// its result thrown away was told the wrong number by this file.
    ///
    /// This walks every declared tool rather than the ones known to carry the
    /// parameter, so a schema added later with a hand-written number fails here.
    #[test]
    fn every_advertised_budget_matches_the_enforced_one() {
        use crate::budget::{
            RESPONSE_DEFAULT_MAX_CHARS, RESPONSE_MAX_MAX_CHARS, RESPONSE_MIN_MAX_CHARS,
        };
        let mut checked = 0usize;
        for tool in &tool_definitions().tools {
            let Some(properties) = tool.input_schema.get("properties") else {
                continue;
            };
            for key in ["max_chars", "max_response_chars"] {
                let Some(property) = properties.get(key) else {
                    continue;
                };
                checked += 1;
                assert_eq!(
                    property["default"].as_u64(),
                    Some(RESPONSE_DEFAULT_MAX_CHARS as u64),
                    "{}.{key} advertises a default the budget does not serve: {property}",
                    tool.name
                );
                assert_eq!(
                    property["minimum"].as_u64(),
                    Some(RESPONSE_MIN_MAX_CHARS as u64),
                    "{}.{key} advertises a floor the budget does not serve: {property}",
                    tool.name
                );
                assert_eq!(
                    property["maximum"].as_u64(),
                    Some(RESPONSE_MAX_MAX_CHARS as u64),
                    "{}.{key} advertises a ceiling the budget does not serve: {property}",
                    tool.name
                );
                let description = property["description"].as_str().unwrap_or_default();
                assert!(
                    !description.contains("400000"),
                    "{}.{key} still names the ceiling that got a result refused: {description}",
                    tool.name
                );
            }
        }
        assert!(
            checked >= 11,
            "the sweep found only {checked} budget parameters, so it is not reaching the schemas"
        );
    }

    #[test]
    fn all_tools_have_names_and_descriptions() {
        let list = tool_definitions();
        assert!(!list.tools.is_empty());
        for tool in &list.tools {
            assert!(!tool.name.is_empty());
            assert!(!tool.description.is_empty());
        }
    }

    /// Every tool that changes state when it is called.
    ///
    /// Stated by hand rather than derived, because a derived list would agree
    /// with whatever the registry claims and could never disagree with it. Each
    /// name here was classified by reading its handler.
    const WRITING_TOOLS: &[&str] = &[
        "kin_annotation_add",
        "kin_annotation_mark_resolved",
        "kin_register_intent",
        "kin_release_intent",
        "kin_review_assign",
        "kin_review_create",
        "kin_review_decide",
        "kin_review_discuss",
        "kin_review_discuss_reply",
        "kin_review_discuss_resolve",
        "kin_review_note_add",
        "kin_review_unassign",
        "kin_session_end",
        "kin_session_heartbeat",
        "kin_session_start",
        "kin_todo_import",
        "kin_transaction_abort",
        "kin_transaction_begin",
        "kin_transaction_commit",
        "kin_transaction_stage",
        "kin_transaction_validate",
        "kin_work_block",
        "kin_work_create",
        "kin_work_decompose",
        "kin_work_implement",
        "kin_work_link",
        "kin_work_status",
        "register_session",
    ];

    /// Every tool that can overwrite or discard something already recorded.
    ///
    /// `kin_transaction_commit` splices new bodies over existing entity source
    /// and republishes the ref; `kin_transaction_abort` clears the staged
    /// operations outright; `kin_work_status` and `kin_review_discuss_resolve`
    /// replace a state field in place; `kin_annotation_mark_resolved` deletes
    /// the annotation; `kin_review_unassign` removes the assignment.
    const DESTRUCTIVE_TOOLS: &[&str] = &[
        "kin_annotation_mark_resolved",
        "kin_review_discuss_resolve",
        "kin_review_unassign",
        "kin_transaction_abort",
        "kin_transaction_commit",
        "kin_work_status",
    ];

    #[test]
    fn every_tool_carries_a_title_and_honest_hints() {
        let list = tool_definitions();
        let mut titles = BTreeSet::new();
        for tool in &list.tools {
            let annotations = &tool.annotations;
            assert!(
                !annotations.title.trim().is_empty(),
                "{} has no title",
                tool.name
            );
            assert_ne!(
                annotations.title, tool.name,
                "{}'s title repeats the wire name instead of naming it for a human",
                tool.name
            );
            assert!(
                titles.insert(annotations.title.clone()),
                "two tools share the title {:?}, so a client menu cannot tell them apart",
                annotations.title
            );
            // Registry ceiling clients enforce on the identifier they call.
            assert!(
                tool.name.len() <= 64,
                "{} is {} characters, over the 64-character tool-name limit",
                tool.name,
                tool.name.len()
            );
            assert!(
                !annotations.open_world_hint,
                "{} claims an open world; the whole surface answers from the local graph",
                tool.name
            );
            if annotations.read_only_hint {
                assert!(
                    !annotations.destructive_hint,
                    "{} is read-only and cannot also be destructive",
                    tool.name
                );
            }
        }
    }

    /// The hints must be able to disagree with the registry, so both classes are
    /// named here and compared as whole sets. A tool added without a considered
    /// classification fails this rather than inheriting a plausible default.
    #[test]
    fn the_writing_and_destructive_surfaces_are_exactly_these() {
        let list = tool_definitions();
        let writing: BTreeSet<&str> = list
            .tools
            .iter()
            .filter(|tool| !tool.annotations.read_only_hint)
            .map(|tool| tool.name.as_str())
            .collect();
        let destructive: BTreeSet<&str> = list
            .tools
            .iter()
            .filter(|tool| tool.annotations.destructive_hint)
            .map(|tool| tool.name.as_str())
            .collect();

        assert_eq!(writing, WRITING_TOOLS.iter().copied().collect());
        assert_eq!(destructive, DESTRUCTIVE_TOOLS.iter().copied().collect());
        assert!(
            destructive.is_subset(&writing),
            "a destructive tool that reports itself read-only would be auto-approved"
        );
    }

    #[test]
    fn tools_list_order_is_stable_and_sorted() {
        let names = |list: &ToolsListResult| -> Vec<String> {
            list.tools.iter().map(|tool| tool.name.clone()).collect()
        };
        let first = names(&tool_definitions());
        let second = names(&tool_definitions());
        assert_eq!(first, second, "two calls must serve the same order");

        let mut sorted = first.clone();
        sorted.sort();
        assert_eq!(first, sorted, "tools/list must be name-ordered");

        // The registry's own order is not the served order, so the sort is
        // doing real work rather than agreeing with the source by accident.
        assert_ne!(names(&registered_tools()), sorted);
    }

    #[test]
    fn serialized_tools_carry_the_annotation_object() {
        let serialized =
            serde_json::to_value(tool_definitions()).expect("tools/list must serialize");
        let tools = serialized["tools"].as_array().expect("tools array");
        for tool in tools {
            let annotations = tool["annotations"]
                .as_object()
                .unwrap_or_else(|| panic!("{} serialized no annotations", tool["name"]));
            for key in [
                "title",
                "readOnlyHint",
                "destructiveHint",
                "idempotentHint",
                "openWorldHint",
            ] {
                assert!(
                    annotations.contains_key(key),
                    "{} is missing annotations.{key}",
                    tool["name"]
                );
            }
        }

        let locate = tools
            .iter()
            .find(|tool| tool["name"] == "semantic_locate")
            .expect("semantic_locate must be exposed");
        assert_eq!(locate["annotations"]["title"], "Semantic locate");
        assert_eq!(locate["annotations"]["readOnlyHint"], true);
        assert_eq!(locate["annotations"]["destructiveHint"], false);

        let commit = tools
            .iter()
            .find(|tool| tool["name"] == "kin_transaction_commit")
            .expect("kin_transaction_commit must be exposed");
        assert_eq!(commit["annotations"]["readOnlyHint"], false);
        assert_eq!(commit["annotations"]["destructiveHint"], true);
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
            assert_eq!(variants.len(), 6, "{tool_name}");

            let retirement = variants
                .iter()
                .find(|variant| variant["title"] == "Retired source file")
                .expect("payload-less retirement branch");
            assert_eq!(
                required_set(retirement),
                ["description", "target", "verb"]
                    .into_iter()
                    .map(String::from)
                    .collect()
            );
            assert!(
                retirement["properties"].get("payload").is_none(),
                "payload-less retirement branch must reject payload"
            );
            assert!(
                retirement["properties"].get("body").is_none(),
                "a retirement carries no body; accepting one would let a delete read as an edit"
            );

            let rename = variants
                .iter()
                .find(|variant| variant["title"] == "Renamed source file")
                .expect("payload-less rename branch");
            assert_eq!(
                required_set(rename),
                ["description", "destination", "target", "verb"]
                    .into_iter()
                    .map(String::from)
                    .collect()
            );
            assert!(
                rename["properties"].get("payload").is_none(),
                "payload-less rename branch must reject payload"
            );

            let new_source_file = variants
                .iter()
                .find(|variant| variant["title"] == "New source file")
                .expect("payload-less new-source-file branch");
            assert_eq!(
                required_set(new_source_file),
                ["body", "description", "target", "verb"]
                    .into_iter()
                    .map(String::from)
                    .collect()
            );
            assert!(
                new_source_file["properties"].get("payload").is_none(),
                "payload-less new-source-file branch must reject payload"
            );

            let replaced_source_file = variants
                .iter()
                .find(|variant| variant["title"] == "Replaced source file")
                .expect("payload-less replaced-source-file branch");
            assert_eq!(
                required_set(replaced_source_file),
                ["body", "description", "target", "verb"]
                    .into_iter()
                    .map(String::from)
                    .collect()
            );
            assert!(
                replaced_source_file["properties"].get("payload").is_none(),
                "payload-less replaced-source-file branch must reject payload"
            );
            // The rewrite is only decidable from the operation itself while its
            // verbs belong to it alone among the payload-less branches. Sharing
            // one with the entity edit would make the shape depend on how a
            // bare target string happened to resolve. The structured branch is
            // exempt because `payload` already separates it from all five.
            let verbs = |variant: &serde_json::Value| {
                variant["properties"]["verb"]["enum"]
                    .as_array()
                    .expect("every branch pins its verbs")
                    .iter()
                    .map(|verb| verb.as_str().expect("a verb is a string").to_string())
                    .collect::<std::collections::BTreeSet<String>>()
            };
            for other in variants.iter().filter(|variant| {
                variant["title"] != "Replaced source file"
                    && variant["title"] != "Structured entity or relation mutation"
            }) {
                assert!(
                    verbs(replaced_source_file).is_disjoint(&verbs(other)),
                    "the rewrite branch shares a verb with {}",
                    other["title"]
                );
            }

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
        // + 1 get_entity_sources + 2 exact artifact tools
        // + 1 list_file_entities = 65
        assert_eq!(list.tools.len(), 65);
    }

    /// The reference lists each category's members on a line opening with this
    /// marker. That roster is the surface a reader scans, so it is what
    /// membership means here.
    const DOC_ROSTER_MARKER: &str = "*Tools:*";

    /// The names the reference's category rosters enumerate.
    ///
    /// A name that appears only in prose is not a roster entry. Reading the
    /// whole page as one string erases that difference, which is how a tool
    /// mentioned once inside another tool's description can satisfy a guard
    /// while appearing in no category at all.
    fn doc_roster_names(doc: &str) -> BTreeSet<String> {
        let mut names = BTreeSet::new();
        for line in doc.lines() {
            let Some(roster) = line.trim().strip_prefix(DOC_ROSTER_MARKER) else {
                continue;
            };
            // Backticks alternate open/close across the split, so the odd
            // fragments are the code spans.
            for span in roster.split('`').skip(1).step_by(2) {
                let span = span.trim();
                if !span.is_empty() {
                    names.insert(span.to_string());
                }
            }
        }
        names
    }

    /// The tool count the reference's headline claims, read as a number rather
    /// than matched as a string.
    ///
    /// Matching a formatted sentence only ever answers "is this exact number
    /// written somewhere", which a page can satisfy while enumerating a
    /// different set. Reading the number lets it be compared against both the
    /// registry and the rosters.
    fn doc_headline_tool_count(doc: &str) -> Option<usize> {
        let (_, after) = doc.split_once("exposes ")?;
        let (count, _) = after.split_once(" semantic tools")?;
        count.trim().parse().ok()
    }

    /// Every way `docs/mcp-tools.md` and the registry can disagree, stated
    /// plainly. An empty result is the only passing answer.
    fn doc_registry_disagreements(doc: &str, registered: &BTreeSet<String>) -> Vec<String> {
        let rostered = doc_roster_names(doc);
        let mut problems = Vec::new();

        for name in registered.difference(&rostered) {
            problems.push(format!(
                "{name} is served by the registry but listed in no '{DOC_ROSTER_MARKER}' category \
                 roster in docs/mcp-tools.md"
            ));
        }
        for name in rostered.difference(registered) {
            problems.push(format!(
                "{name} is listed in a docs/mcp-tools.md category roster but the registry serves \
                 no such tool"
            ));
        }

        match doc_headline_tool_count(doc) {
            Some(headline) => {
                if headline != registered.len() {
                    problems.push(format!(
                        "the headline claims {headline} tools and the registry serves {}",
                        registered.len()
                    ));
                }
                if headline != rostered.len() {
                    problems.push(format!(
                        "the headline claims {headline} tools and the category rosters enumerate \
                         {}",
                        rostered.len()
                    ));
                }
            }
            None => problems.push(
                "docs/mcp-tools.md states no 'exposes N semantic tools' headline count".to_string(),
            ),
        }

        problems
    }

    /// The tool reference must enumerate every tool the registry serves, name
    /// nothing it does not, and claim the count it enumerates.
    ///
    /// The reference presents itself as the whole surface, so a tool the
    /// registry defines but no category lists is invisible to the agents the
    /// page exists for, and two of the tools this caught ship in
    /// `agent-default`. Nothing tied the page to the registry, which is why it
    /// drifted to claiming 62 while serving 64. `docs/env-vars.md` has exactly
    /// this tie and did not drift.
    ///
    /// The first repair of that drift compared substrings, which restored the
    /// same blind spot in a shape that reported success: any mention anywhere
    /// counted as coverage, and the headline was matched rather than read. The
    /// comparison is between sets now, and `doc_registry_disagreements` is
    /// exercised against synthetic pages below so its ability to fail does not
    /// rest on a plant somebody removed afterward.
    #[test]
    fn mcp_doc_enumerates_exactly_the_registered_tools() {
        let doc = include_str!("../../../docs/mcp-tools.md");
        let list = tool_definitions();
        let registered: BTreeSet<String> =
            list.tools.iter().map(|tool| tool.name.clone()).collect();
        assert_eq!(
            registered.len(),
            list.tools.len(),
            "the registry serves a duplicate tool name, so set comparison would hide one of them"
        );

        let problems = doc_registry_disagreements(doc, &registered);
        assert!(
            problems.is_empty(),
            "docs/mcp-tools.md disagrees with the registry:\n{}",
            problems.join("\n")
        );
    }

    #[test]
    fn a_prose_mention_is_not_roster_membership() {
        let doc = "\
# Reference

The Kin MCP server exposes 2 semantic tools to AI assistants.

## 1. Retrieval
*Tools:* `alpha`, `beta`

- **`alpha`**: the first tool. Pair it with `gamma` when you need a body.
";
        // The substring test the old guard performed still passes here, which
        // is precisely the defect: `gamma` is served by nothing the page lists.
        assert!(doc.contains("gamma"));
        assert!(!doc_roster_names(doc).contains("gamma"));

        let registered = ["alpha", "beta", "gamma"]
            .into_iter()
            .map(String::from)
            .collect();
        let problems = doc_registry_disagreements(doc, &registered);
        assert!(
            problems
                .iter()
                .any(|problem| problem.contains("gamma") && problem.contains("listed in no")),
            "a registered tool mentioned only in prose must be reported: {problems:?}"
        );
    }

    #[test]
    fn a_roster_name_the_registry_does_not_serve_is_reported() {
        let doc = "\
The Kin MCP server exposes 2 semantic tools to AI assistants.

*Tools:* `alpha`, `retired_tool`
";
        let registered = ["alpha", "beta"].into_iter().map(String::from).collect();
        let problems = doc_registry_disagreements(doc, &registered);
        assert!(
            problems
                .iter()
                .any(|problem| problem.contains("retired_tool") && problem.contains("no such tool")),
            "a rostered name the registry does not serve must be reported: {problems:?}"
        );
    }

    #[test]
    fn a_headline_that_disagrees_with_the_rosters_is_reported() {
        let doc = "\
The Kin MCP server exposes 9 semantic tools to AI assistants.

*Tools:* `alpha`, `beta`
";
        let registered = ["alpha", "beta"].into_iter().map(String::from).collect();
        let problems = doc_registry_disagreements(doc, &registered);
        assert!(
            problems.iter().any(|problem| problem.contains("claims 9")),
            "a headline disagreeing with what the page enumerates must be reported: {problems:?}"
        );
    }

    #[test]
    fn a_missing_headline_count_is_reported_rather_than_skipped() {
        let doc = "*Tools:* `alpha`\n";
        assert_eq!(doc_headline_tool_count(doc), None);
        assert_eq!(doc_headline_tool_count("exposes many semantic tools"), None);
        assert_eq!(
            doc_headline_tool_count("exposes 64 semantic tools"),
            Some(64)
        );

        let registered = ["alpha"].into_iter().map(String::from).collect();
        let problems = doc_registry_disagreements(doc, &registered);
        assert!(
            problems
                .iter()
                .any(|problem| problem.contains("states no 'exposes N semantic tools' headline")),
            "a page with no headline count must be reported: {problems:?}"
        );
    }

    #[test]
    fn an_agreeing_page_reports_nothing() {
        let doc = "\
The Kin MCP server exposes 2 semantic tools to AI assistants.

*Tools:* `alpha`, `beta`
";
        let registered = ["alpha", "beta"].into_iter().map(String::from).collect();
        assert_eq!(
            doc_registry_disagreements(doc, &registered),
            Vec::<String>::new(),
            "the check must be able to pass, or its failures say nothing"
        );
    }

    #[test]
    fn agent_default_profile_is_small_and_valid() {
        let list = tool_definitions();
        let all: std::collections::HashSet<&str> =
            list.tools.iter().map(|t| t.name.as_str()).collect();
        let profile = agent_default_tool_names();

        // The ceiling is a budget, not a fact about the current list, and it is
        // raised deliberately rather than tracking whatever the list happens to
        // hold. Every tool here costs its schema in every session on every
        // client, which is the whole reason this profile exists. It went to 21
        // for `bulk_check_references` (FIR-2825), which the profile's own
        // `find_references` description already told callers to use.
        assert!(
            profile.len() >= 10 && profile.len() <= 21,
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
        // none to expose, because the whole MCP surface is graph-backed).
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
