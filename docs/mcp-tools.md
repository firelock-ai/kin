# Model Context Protocol (MCP) Tool Surface Reference

The Kin MCP server exposes 60 semantic tools to AI assistants (Claude, Cursor, Gemini,
Codex, etc.). These tools bridge the gap between traditional file-first navigation and
Kin's graph-first semantic substrate: instead of issuing raw shell commands or reading raw
files, an assistant interacts with the codebase through entity-level primitives.

The tools are grouped below by functional area. Most retrieval and analysis tools answer
directly from the graph. Vector-backed retrieval (`semantic_locate`) and the stateful
session, transaction, work, and review tools operate against the repo's running Kin
daemon; `semantic_locate` returns an explicit error in offline/no-daemon mode.

---

## 1. Retrieval & Codebase Exploration
*Tools:* `semantic_search`, `semantic_locate`, `get_entity`, `get_entity_source`, `get_entity_body`, `get_context_pack`, `explore_codebase`, `graph_neighborhood`

- **`semantic_search`**: Find declarations by **name, kind, or language** (functions, classes, structs, traits, enums, interfaces, types, constants). This matches real parsed declarations — not raw string occurrences like grep — and returns each match's file path, line range, signature, and stable entity ID. Note: despite the name, this is a metadata matcher; it does **not** rank by vector similarity. Use it as your first step to find "the thing called X."
- **`semantic_locate`**: Rank the code most relevant to a **natural-language** query using Kin's vector index — the same embedding-backed retrieval that powers `kin locate`. Use it when you only have a description of the behavior, not an exact symbol name. Supports `granularity` of `entity` (default) or `file`, reports `semantic_coverage`, and requires the running daemon.
- **`get_entity`**: Fetch metadata about a specific entity (kind, language, path, line range, signature) without its source body.
- **`get_entity_source` / `get_entity_body`**: Retrieve the implementation source of an entity, served from the graph.
- **`get_context_pack`**: Package a target entity alongside its caller/import neighborhood into a single prompt-friendly bundle.
- **`explore_codebase`**: Walk the graph namespace to understand structure.
- **`graph_neighborhood`**: Return the local relation neighborhood around an entity.

---

## 2. Tracing & References
*Tools:* `trace_computation`, `trace_data_flow`, `find_references`, `bulk_check_references`, `entity_history`

- **`trace_computation` / `trace_data_flow`**: Follow control-flow or dataflow paths through functions and variables in a single call, avoiding tool-looping.
- **`find_references`**: Find all entities that import, call, or reference a target symbol.
- **`bulk_check_references`**: Classify many entities by reachability in one call.
- **`entity_history`**: Retrieve version changes scoped to a specific entity.

---

## 3. Semantic Change, Impact & Review
*Tools:* `impact_analysis`, `semantic_diff`, `semantic_review`

- **`semantic_diff`**: Compute an entity-level diff — which declarations were added, removed, or changed — rather than a line-by-line text diff. Target it by base/head change IDs, entity IDs, file paths, or a list of change IDs.
- **`impact_analysis`**: Walk the relation graph from what changed to find every downstream entity that could be affected ("if I change this, what else might break?").
- **`semantic_review`**: Produce a complete review of a change in one call — entity-level diff, downstream impact, and an overall risk assessment — in `text` or `json` form.

---

## 4. Collaborative Sessions & Intent
*Tools:* `register_session`, `kin_session_start`, `kin_session_heartbeat`, `kin_session_end`, `kin_register_intent`, `kin_release_intent`, `kin_check_traffic`

- **`kin_session_start` / `kin_session_heartbeat` / `kin_session_end`**: Manage developer/agent working sessions.
- **`kin_register_intent` / `kin_release_intent`**: Register or release intent to modify a specific entity or path, surfacing conflicts before code is edited.
- **`kin_check_traffic`**: Query concurrent work on target entities or paths.

---

## 5. Semantic Transactions
*Tools:* `kin_transaction_begin`, `kin_transaction_stage`, `kin_transaction_validate`, `kin_transaction_commit`, `kin_transaction_abort`

- **`kin_transaction_begin`**: Start a transaction context.
- **`kin_transaction_stage`**: Stage entity changes to the transaction.
- **`kin_transaction_validate`**: Run constraints and validation against staged changes.
- **`kin_transaction_commit` / `kin_transaction_abort`**: Commit changes to the branch head or discard them.

---

## 6. Work & Task Management
*Tools:* `kin_work_create`, `kin_work_list`, `kin_work_show`, `kin_work_link`, `kin_work_decompose`, `kin_work_block`, `kin_work_implement`, `kin_work_status`

- **`kin_work_create`**: Create tasks or issues.
- **`kin_work_link`**: Link tasks to specific entities or commits.
- **`kin_work_decompose`**: Break a task into subtasks.
- **`kin_work_block` / `kin_work_status`**: Manage and query implementation state.

---

## 7. Graph Annotations & TODOs
*Tools:* `kin_annotation_add`, `kin_annotation_list`, `kin_annotation_mark_resolved`, `kin_todo_import`

- **`kin_annotation_add`**: Attach notes or documentation to specific graph nodes.
- **`kin_annotation_list`**: Query unresolved annotations and TODOs.
- **`kin_annotation_mark_resolved`**: Mark annotations as completed.
- **`kin_todo_import`**: Import inline source TODOs as annotations.

---

## 8. Verification & Compliance
*Tools:* `kin_verify_entity`, `kin_coverage_summary`, `kin_security_scan`, `kin_release_check`, `kin_contract_check`, `kin_provenance_query`

- **`kin_verify_entity`**: Check whether an entity satisfies its linked tests.
- **`kin_coverage_summary`**: Generate entity-to-test coverage ratios.
- **`kin_security_scan`**: Analyze security patterns across the entity graph.
- **`kin_release_check` / `kin_contract_check`**: Verify release readiness and interface-schema compliance.
- **`kin_provenance_query`**: Trace historical ownership and modification trails.

---

## 9. Semantic Reviews & Governance
*Tools:* `kin_review_create`, `kin_review_decide`, `kin_review_note_add`, `kin_review_discuss`, `kin_review_discuss_reply`, `kin_review_discuss_resolve`, `kin_review_assign`, `kin_review_unassign`, `kin_review_list`, `kin_review_get`

- **`kin_review_create`**: Open a review request for semantic changes.
- **`kin_review_decide`**: Set review state (e.g. approved, blocked, needs_work).
- **`kin_review_discuss` / `kin_review_discuss_reply` / `kin_review_discuss_resolve`**: Host comment threads attached to a review.
- **`kin_review_assign` / `kin_review_unassign` / `kin_review_list` / `kin_review_get`**: Manage and inspect reviews.

---

## 10. Utility & Health
*Tools:* `dead_code`, `find_dead_code_seeded`, `benchmark`, `kin_graph_status`

- **`dead_code` / `find_dead_code_seeded`**: Identify unreachable or orphaned entities (whole-repo or seeded by a semantic query).
- **`benchmark`**: Run Kin's retrieval/locate benchmarks.
- **`kin_graph_status`**: Retrieve graph telemetry, cache details, and daemon status.
