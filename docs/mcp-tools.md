# Model Context Protocol (MCP) Tool Surface Reference

The Kin MCP server exposes 64 semantic tools to AI assistants (Claude, Cursor, Gemini,
Codex, etc.). These tools bridge the gap between traditional file-first navigation and
Kin's graph-first semantic substrate: instead of issuing raw shell commands or reading raw
files, an assistant interacts with the codebase through entity-level primitives.

The tools are grouped below by functional area. Most retrieval and analysis tools answer
directly from the graph. Vector-backed retrieval (`semantic_locate`) and the stateful
session, transaction, work, and review tools operate against the repo's running Kin
daemon; `semantic_locate` returns an explicit error in offline/no-daemon mode.

---

## Configuring the server

The recommended way to expose these tools is the guided wizard: run `kin setup` and choose
the **AI agents** intent. It writes Kin's MCP server entry into every detected client
(Claude Code, Cursor, Codex CLI, Gemini CLI, Windsurf) with the curated tool profile, and
adds a Kin-first discovery reminder to your agent instruction files. `kin setup status`
then verifies each client config.

The wizard writes this entry, stating the profile explicitly:

```json
{
  "mcpServers": {
    "kin": {
      "command": "/absolute/path/to/kin",
      "args": ["mcp", "start"],
      "env": { "KIN_MCP_TOOL_PROFILE": "agent-default" }
    }
  }
}
```

The wizard substitutes the installation's exact absolute launcher path. A bare `kin`
command is not a supported manual shortcut because agent clients do not reliably inherit
your shell `PATH`. The canonical `npx -y @kinlab/kin mcp start` topology is also accepted;
see the quickstart's advanced configuration for its exact JSON and repository-bound forms.

To wire a client up by hand, or to use the canonical npm wrapper (`@kinlab/kin`, which
can run `kin mcp start` with the same `agent-default` profile), see
[Advanced configuration](quickstart.md#9-advanced-configuration) in the quickstart.

### Tool profiles

`kin mcp start` serves the curated `agent-default` profile whether or not anyone
configures it, and prints the profile and its tool count on stderr at startup. A
hand-written `.mcp.json`, a container entrypoint, or a CI harness therefore gets the same
small surface the wizard writes, instead of every tool the server defines and roughly
twelve thousand extra tokens of schemas in every session.

Select a different surface with `KIN_MCP_TOOL_PROFILE`, or with `--tool-profile` on the
command line (the flag wins):

| profile | surface |
| -- | -- |
| `agent-default` | the curated agent belt, **the default** |
| `full` | every tool this reference documents |
| `benchmark` | the retrieval belt the benchmark arm drives |
| `context-bench` | read-only graph-native retrieval, no write-side session or transaction tools |

A value that is not one of these is not silently treated as "serve everything": the server
falls back to `agent-default` and says on stderr what it was asked for and what it served.

---

## 1. Retrieval & Codebase Exploration
*Tools:* `semantic_search`, `semantic_locate`, `get_entity`, `get_entity_source`, `get_entity_body`, `get_entity_sources`, `get_context_pack`, `explore_codebase`, `graph_neighborhood`

- **`semantic_search`**: Find declarations by **name, kind, or language** (functions, classes, structs, traits, enums, interfaces, types, constants). This matches real parsed declarations rather than raw string occurrences like grep, and returns each match's file path, line range, signature, and stable entity ID. Note: despite the name, this is a metadata matcher; it does **not** rank by vector similarity. Use it as your first step to find "the thing called X."
- **`semantic_locate`**: Rank the code most relevant to a **natural-language** query using Kin's vector index, the same embedding-backed retrieval that powers `kin locate`. Use it when you only have a description of the behavior, not an exact symbol name. Supports `granularity` of `entity` (default) or `file`, reports `semantic_coverage`, and requires the running daemon.
- **`get_entity`**: Fetch metadata about a specific entity (kind, language, path, line range, signature) without its source body.
- **`get_entity_source` / `get_entity_body`**: Retrieve the implementation source of an entity, served from the graph.
- **`get_entity_sources`**: The batch form of `get_entity_source`. Hand it up to 50 entity IDs in priority order and it returns each entity's metadata plus its body in one budgeted call, which replaces the N separate round-trips and N response envelopes those reads would otherwise cost. Bodies fill in the order you list the IDs until the shared `token_budget` is reached, and entities past that point come back signature-only with `omitted=true`.
- **`get_context_pack`**: Package a target entity alongside its caller/import neighborhood into a single prompt-friendly bundle.
- **`explore_codebase`**: Get a one-shot map of the codebase via a selectable strategy (e.g. `overview`: entity counts by kind and language, plus the top public declarations).
- **`graph_neighborhood`**: Return the dependency neighborhood of an entity, traversed to a given depth. The neighborhood covers what it depends on and what depends on it. `direction` selects which side to walk: `out` for dependencies, `in` for dependents (blast radius), `both` (default) for the merged neighborhood; every returned edge is tagged with the direction it was traversed in.

---

## 2. Tracing & References
*Tools:* `trace_computation`, `trace_data_flow`, `find_references`, `bulk_check_references`, `entity_history`

- **`trace_computation`**: Get a focal entity together with its control-/data-flow neighborhood in one structured response (a flat snapshot, not an ordered walk). The response carries its body plus callers, callees, and imports.
- **`trace_data_flow`**: Walk the directional call/data-flow chain rooted at a focal entity and return it as an ordered list of steps (the path-walk counterpart to `trace_computation`'s flat neighborhood).
- **`find_references`**: Find all entities that import, call, or reference a target symbol.
- **`bulk_check_references`**: Classify many entities by reachability in one call.
- **`entity_history`**: Retrieve version changes scoped to a specific entity.

---

## 3. Semantic Change, Impact & Review
*Tools:* `impact_analysis`, `semantic_diff`, `semantic_review`, `shadow_gate_report`

- **`semantic_diff`**: Compute an entity-level diff of which declarations were added, removed, or changed, rather than a line-by-line text diff. Target it by base/head change IDs, entity IDs, file paths, or a list of change IDs.
- **`impact_analysis`**: Walk the relation graph from what changed to find the downstream entities that could be affected ("if I change this, what else might break?").
- **`semantic_review`**: Produce a complete review of a change in one call. It covers entity-level diff, downstream impact, and an overall risk assessment, in `text` or `json` form.
- **`shadow_gate_report`**: Run the shadow-mode merge gate over a PR-shaped change (`base` ref to `head` ref) and return one report covering changed entities, graph-proven blast radius, the verdict the gate would have issued, the repair context needed to fix findings, explicit evidence gaps, and audit evidence. Shadow mode is report-only and never blocks. Refs accept branch names and semantic change IDs, and imported Git commit SHAs resolve once their history is in the graph. Where the graph cannot prove something, the report says so in `evidence_gaps` rather than passing silently.

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
- **`kin_todo_import`**: Scan source files for inline `TODO`/`FIXME`/`HACK` markers and import each as a work item in the graph.

---

## 8. Verification & Compliance
*Tools:* `kin_verify_entity`, `kin_coverage_summary`, `kin_security_scan`, `kin_release_check`, `kin_contract_check`, `kin_provenance_query`

- **`kin_verify_entity`**: Inspect the test coverage recorded for an entity, reporting which tests are linked to it and whether it is covered (optionally filtered by runner).
- **`kin_coverage_summary`**: Report repo-wide test coverage, including total entities, how many are covered, the ratio, and what's still untested.
- **`kin_security_scan`**: Run a graph-based security/quality scan that returns findings with severity (today it surfaces dead/unreachable code; `propagate=true` also computes each finding's downstream impact).
- **`kin_release_check`**: Run a graph-only advisory against a named branch and immutable source change. It checks exact history/tree completeness and an optional source entity count; `require_approval` covers every reachable non-root change, while `require_proof` currently fails closed for every non-empty source because verification runs are not yet source-bound. Final object availability and mutation CAS remain daemon `kin release` authority.
- **`kin_contract_check`**: Check whether a specific behavioral contract has backing tests (which tests cover it, and whether it is covered).
- **`kin_provenance_query`**: Answer who-changed-and-whether-approved for an entity, returning its change count, latest change, recorded approvals, and recent audit events.

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
- **`kin_graph_status`**: Report one schema-bound, point-in-time status view of the exact daemon graph selected for the call, covering entity and relation counts, selected-graph embedding coverage (indexed / total / pending), temporal-session versus HEAD scope, a process-local authority epoch, and backing authority. The daemon holds its normal embedding-work fence while reading internally synchronized coverage counters, then revalidates graph/scope authority before publishing; observed counts still do not attest enrichment completeness.

---

## 11. Repository Artifacts
*Tools:* `kin_artifact_list`, `kin_artifact_read`

Both tools ship in the `agent-default` profile, so an agent configured with
`kin setup --intent agent` already has them.

- **`kin_artifact_list`**: List the exact graph-owned repository artifacts at one semantic change. This is the repository-membership surface, so it covers code and every non-code tracked object, including Docker Compose files, Dockerfiles, lockfiles, configuration, binary assets, unsupported languages, symlinks, executable files, and gitlinks. Identity comes from `artifact_id` and never from a path. Paths are returned as canonical lowercase `bytes_hex` objects, with `path_label` as presentation only. Omit `source_change_id` to read the exact current workspace tree.
- **`kin_artifact_read`**: Read one exact graph-owned repository artifact by stable `artifact_id` or canonical byte-exact `path`. Blob and symlink bytes come back losslessly as base64, and as `text_utf8` only when they are valid UTF-8. Gitlinks return their external object identity and have no repository-owned body. The read is bound to the resolved tree entry and fails loudly when the tree, identity, or content-addressed blob is missing. It never reads the working directory.
