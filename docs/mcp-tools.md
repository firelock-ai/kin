# Model Context Protocol (MCP) Tool Surface Reference

The Kin MCP server exposes 66 semantic tools to AI assistants (Claude, Cursor, Gemini,
Codex, etc.). These tools bridge the gap between traditional file-first navigation and
Kin's graph-first semantic substrate: instead of issuing raw shell commands or reading raw
files, an assistant interacts with the codebase through entity-level primitives.

The tools are grouped below by functional area. Most retrieval and analysis tools answer
directly from the graph. Vector-backed retrieval (`semantic_locate`) and the stateful
session, transaction, work, and review tools operate against the repo's running Kin
daemon; `semantic_locate` returns an explicit error in offline/no-daemon mode.

---

## Every Answer Names Its Authority: the `_kin` Envelope

Every tool response carries a `_kin` envelope (version 1) that names what produced the
answer and how far to trust it. The contract behind it is simple: there is no
configuration under which the server backfills a semantic answer from raw file search
behind a successful response. An answer is graph-backed and names the graph state that
produced it, or the gap is reported as a gap.

The envelope's fields:

- `runtime`: `repo-daemon` (live, graph-owned truth) or `offline-in-process` (an
  in-process store, explicitly a fallback surface and labeled as one).
- `graph_as_of` and `graph_state`: the snapshot generation that answered, plus
  reconciliation status, entity count, and loaded/initialized flags when known.
- `semantic_coverage`: `indexed`, `total`, `pending`, and `complete` for the embedding
  signal, carried only when the daemon computed it and never fabricated here.
- `degraded`: honest flags (`daemon_unreachable`, `embed_worker_failed`,
  `mass_deletion_blocked`, `offline_fallback`, `workspace_mismatch`,
  `daemon_killed_by_memory`, `sweep_suspended`, `memory_pressure`), each present only
  when observed. `workspace_mismatch` is a refusal about which repository an answer would
  be about, not a transport failure: the daemon is reachable and the server declined to
  answer from a repository the client is not looking at. The last three are standing
  facts about the store rather than about the call: a daemon this store has lost to the
  memory limit, enrichment the sweep circuit has switched off, and heavy work the daemon
  declined because the machine had no room for it. Each changes what an absence means,
  because the producer that would have filled it is not running.

Empty results carry a named trust verdict, so an agent can tell "not present" apart from
"not indexed yet". Semantic tools (`semantic_locate`, `semantic_search`) report
`semantic_authoritative` only under complete embedding coverage with no degraded
signals, and `coverage_partial` or `coverage_unknown` otherwise. Structural tools
(`find_references`, `graph_neighborhood`, `trace_data_flow`, and the other
graph-relation readers) report `structural_authoritative` only with the graph
initialized and loaded. Treat every other verdict as "ask again when the graph is
ready" rather than as evidence of absence.

Every retrieval answer, empty or not, also carries `_kin.verdict`, the one verdict
for the response. It is computed from every block that qualifies the answer and the
most pessimistic input wins: a requested edge class that `_kin.completeness.classes`
records as anything but `present` makes the verdict `inconclusive`, with
`limiting_factor` naming the class and its state. `absent` means the scan completed
and found no such cross-file edge, `unknown` means the scan stopped on its budget,
and `unproduced` means the scan completed, saw no entity-level edge of the class at
all, and the source carries sites of it that the linker resolved, so the gap is in
the build rather than in the code. A verdict that certifies over a recorded limit
was the shipped 0.5.52 behaviour (FIR-2672) and is now a contract violation the
tests scan for. `limiting_factor` is one sentence of `label: text` clauses, one per
input that refused, in the order the verdict weighs them (the absence gate's own
composition, then the coverage observation, withheld rows, the run's own
degradations and the completeness signal), each label once. The first clause is
what decided the state and the rest are the other things wrong with the same
answer, so a class gap never hides a dead embedding worker.

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

### Which repository the server serves

A server binds one repository: the one named by `--repo` or `KIN_MCP_REPO`, otherwise the
one containing its working directory, otherwise whatever the client's MCP workspace roots
point at. An editor that moves its window to another Kin repository is followed, because a
confident answer about the codebase you just left is worse than an error.

A server that bound a repository of its own keeps serving it and ignores client workspace
roots it cannot resolve to a Kin repository. That is what makes a container or remote
registration work. Registered as
`docker exec -i -w /work/repo <container> /absolute/path/to/kin mcp start`, the server
serves a container path while the client announces host paths that do not exist inside the
container, and reading those as a workspace change would refuse every call for the life of
the process. Roots that do name a Kin repository the server can see, and does not serve,
are a real disagreement: those calls are refused, and the refusal carries
`degraded.workspace_mismatch` with both paths named.

### Reaching `kin` from `docker exec`

Give `docker exec` the absolute path to the binary. A bare `kin` is resolved against the
image's own `ENV PATH`, which on a stock image carries neither `~/.kin/bin` nor an npm user
prefix, so the registration fails before Kin runs at all:

```
$ docker exec -i -w /work/repo <container> kin mcp start
OCI runtime exec failed: exec failed: unable to start container process:
exec: "kin": executable file not found in $PATH
```

That message names Docker, not Kin, which is why it is worth recognizing. After
`kin setup`, the managed binary is at `~/.kin/bin/kin`. After `npm install -g @kinlab/kin`,
it is under `$(npm prefix -g)/bin/kin`. Either absolute path works as the registration
command. To keep the bare command instead, pass the environment the exec needs:

```sh
docker exec -e PATH=/home/<user>/.kin/bin:$PATH -i -w /work/repo <container> kin mcp start
```

Reinstalling as root is not a shortcut past this on an image that gives every user the same
`HOME`. Root's npm reads that `HOME`'s `.npmrc`, reinstalls into the user prefix, and
reports `changed 1 package` while nothing new lands on the default `PATH`. Name the prefix
outright when a system-wide binary is what you want:

```sh
docker exec -u root <container> npm install -g --prefix /usr/local @kinlab/kin
```

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

A profile shapes the tool surface `kin mcp start` offers. It is not a permission system, and
it does not constrain a local process that already holds your repo daemon's credentials.
Reach for it to keep an agent's belt focused and its context small, not as a capability
boundary you can rely on.

#### `agent-default` serves short descriptions

`agent-default` does not serve the long descriptions on this page. Each tool gets one or two
sentences saying when to call it and what comes back, and an input schema trimmed to the
properties that change which entities come back rather than how the response is shaped
(`max_chars`, `compact`, `explain`, `snippet_alias` and `pipeline` are not advertised there).
Trimming hides a property; it does not remove it. No tool sets `additionalProperties: false`,
so a caller that knows a withheld property can still pass it, and `full` still advertises
every one.

This is a context budget, measured. On 2026-09-02 the profile's `tools/list` was 82,262 bytes
over 20 tools, 47,739 of it descriptions and 30,456 input schemas, spent before the model
asked anything. `full`, `benchmark` and `context-bench` keep the long forms: the last two
because their `tools/list` bytes are an input to a citable benchmark result.

`agent-default` also serves the declaration filter as **`find_declarations`** rather than
`semantic_search`, because it filters declarations by name, kind and language and does not
rank by your query, while `semantic_locate` is the tool that ranks by meaning. The two names
read the wrong way round, and a model reads a name before it reads a description. Nothing is
renamed underneath: the tool is registered as `semantic_search`, both names dispatch to the
same handler on every profile, and `full` serves it under the registered name.

---

## 1. Retrieval & Codebase Exploration
*Tools:* `semantic_search`, `semantic_locate`, `list_file_entities`, `get_entity`, `get_entity_source`, `get_entity_body`, `get_entity_sources`, `get_context_pack`, `explore_codebase`, `graph_neighborhood`

- **`semantic_search`** (served as **`find_declarations`** on `agent-default`): Find declarations by **name, kind, or language** (functions, classes, structs, traits, enums, interfaces, types, constants). This matches real parsed declarations rather than raw string occurrences like grep, and returns each match's file path, line range, signature, and stable entity ID. Note: despite the name, this is a metadata matcher; it does **not** rank by vector similarity. Use it as your first step to find "the thing called X."
- **`semantic_locate`**: Rank the code most relevant to a **natural-language** query using Kin's vector index, the same embedding-backed retrieval that powers `kin locate`. Use it when you only have a description of the behavior, not an exact symbol name. Supports `granularity` of `entity` (default) or `file`, reports `semantic_coverage` as the counter object, and requires the running daemon. Each hit carries its inline source once: on `body` for the fused pipeline (the default, `routing: "fused-v1"`) and on `snippet` for the cosine pipeline. Multi-query fan-out echoes the variants once under `queries`, and a hit names the ones that surfaced it by position in `matched_variant_indexes`. **At entity granularity the default response shape is compact**: per hit `id`, `name`, `kind`, `file`, `line`, `signature` and `score`, plus the ranked file paths, `total_ranked`, `next_cursor`, `all_fallback`, a `ranked_by` clause, and the `semantic_coverage` object the `_kin` envelope carries. Pass `surface: "full"` for the shared `kin locate --json` schema described above; `explain: true` implies it, since every field an explanation adds lives on that shape. File granularity is always full, because there the file roll-up is the answer. The compact default exists because the full shape spends most of its bytes on the back-compat `files[].symbols` roll-up of entities `entities` already carries: on a 730-entity store a twelve-hit page is 38,819 bytes full and 3,472 compact.
- **`list_file_entities`**: Enumerate every entity the graph holds for one repository-relative file. This is the enumeration surface, and it is the one to reach for when the question is "what is in this file" rather than "what is most relevant to this query". `semantic_search` and `semantic_locate` both return a bounded set they cannot certify, so a short answer and a whole one read identically; this one reports `total_in_file` on every page and says whether the set is complete. Completeness rests on the file's own parse record rather than on store-wide health: `file_coverage.parsed` is `full` only when a language adapter parsed the file completely, and `_kin.completeness` and `negative.safe_to_conclude_absent` follow that fact. A path the graph does not track is refused by name instead of answered with an empty list, because a caller cannot tell those two answers apart and only one of them means the file holds no entities. Large files page through `next_cursor`.
- **`get_entity`**: Fetch metadata about a specific entity (kind, language, path, line range, signature) without its source body.
- **`get_entity_source` / `get_entity_body`**: Retrieve the implementation source of an entity, served from the graph.
- **`get_entity_sources`**: The batch form of `get_entity_source`. Hand it up to 50 entity IDs in priority order and it returns each entity's metadata plus its body in one budgeted call, which replaces the N separate round-trips and N response envelopes those reads would otherwise cost. Bodies fill in the order you list the IDs until the shared `token_budget` is reached, and entities past that point come back signature-only with `omitted=true`.
- **`get_context_pack`**: Package a target entity alongside its caller/import neighborhood into a single prompt-friendly bundle. The two directions come back as separate named groups: `dependencies` is what the focal needs to run, `dependents` is what breaks if you change it, and every row carries a `relation` saying which way its edge points. A question that names several things takes several focals: pass `entities` with their names or ids (a name with twins can pin the one it means, `Name@file`, `Name@file:line`, `Name#Kind`), or pass `question` and let Kin's ranking pick them, which needs the running daemon because that is where the ranking lives. That shape carries every focal, the graph route between connected focals before either focal's neighborhood, and each neighborhood water-filled into what remains, and it returns `method` (one sentence naming each focal, how it resolved and what it contributed), `routes`, `route_search.bounded` (true when a search stopped at its bound, so an absent route is not evidence there is none), and `measured_tokens`, which is never above `token_budget` because rows are dropped until it is not.
- **`explore_codebase`**: Get a one-shot map of the codebase via a selectable strategy (e.g. `overview`: entity counts by kind and language, plus the top public declarations).
- **`graph_neighborhood`**: Return the dependency neighborhood of an entity, traversed to a given depth. The neighborhood covers what it depends on and what depends on it. `direction` selects which side to walk: `out` for dependencies, `in` for dependents (blast radius), `both` (default) for the merged neighborhood; every returned edge is tagged with the direction it was traversed in.

**On a new or very small repository, expect the value curve to start later.** Kin ranks on
cross-file structure, and a project of a few files has little of it yet. `kin commit`,
`kin graph status`, `trace_data_flow`, and `get_entity_source` earn their keep from the
first checkpoint. `semantic_locate` by description does not, until the graph is bigger, so
ask by exact name at that size. Below the ranker's fusion constant `semantic_locate`
discloses the limit itself, as a `corpus_scale` entry in `degradations`, so the weakness is
reported rather than served as a confident answer.

---

## 2. Tracing & References
*Tools:* `trace_computation`, `trace_data_flow`, `trace_path`, `find_references`, `bulk_check_references`, `entity_history`

- **`trace_computation`**: Get a focal entity together with its control-/data-flow neighborhood in one structured response (a flat snapshot, not an ordered walk). The response carries its body plus callers, callees, and imports.
- **`trace_data_flow`**: Walk the directional call/data-flow chain rooted at a focal entity and return it as an ordered list of steps (the path-walk counterpart to `trace_computation`'s flat neighborhood).
- **`trace_path`**: The route between two named entities, for the question "how does A reach B" that no single-rooted walk answers. It resolves both ends (by exact name, entity id, or `name@file` to pin a twin; a qualified name that matches nothing takes its bare leaf when that is unique and is refused with the candidates listed when it is not), searches breadth-first over call, instantiation, reference, import and include edges, and returns up to `limit` shortest routes, every hop carrying its kind, file, line, the relation into the next hop and the syntax lines that produced it. A class stands for its members, so a route between two classes runs through the methods that carry it, and those containment hops are shown. `direction` defaults to `either`: forward (A reaches B) is tried first and the answer says which sense held. No route is explicit rather than plausible: `found: false`, `routes: []`, a `gap` naming what stopped the walk and how much of the graph it explored, and the same-name twin count on each end; the `negative` and `_kin.verdict` beside it say whether the absence can be trusted. In the `agent-default` profile.
- **`find_references`**: Find all entities that import, call, or reference a target symbol. One row is one referencing entity, so two callers in one file are two rows, and `total_upstream` counts those entities, the same unit `kin refs` prints. The `counts` object names the unit and adds the file and reference-site totals beside it. A row's `reference_lines` gives the lines inside that caller which reference the target, and names why under `reference_lines_absent_reason` when the graph does not carry them. Rows omit the caller's body by default; pass `include_snippets=true` for it.
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
- **`kin_transaction_stage`**: Stage changes to the transaction. Each staged operation is one of six disjoint shapes, and the verb decides which:
  - `create` (or `add`/`insert`) with `target` set to a repository-relative path and `body` set to the file's complete source text admits a file the graph has never seen. It is the only operation that introduces a new file, and it refuses a path repository authority already tracks.
  - `replace` (or `overwrite`) with `target` set to a repository-relative path and `body` set to the file's complete new source text rewrites a file the graph already tracks. This is the shape for what a local edit or write leaves you holding, a path and the file's new contents, and it needs no entity: Kin reparses the body, so entities the new text adds enter the graph, entities it drops leave it, and the rest keep their ids and their incoming edges. It refuses a path repository authority does not track, and it refuses a body byte-identical to the contents already tracked.
  - `update` (or `modify`) with `target` set to an entity uuid or an unambiguous exact entity name, and `body` set to that entity's complete new source text, edits one entity in place. Prefer it when you are changing one function or class and you know which.
  - `delete` (or `remove`) with `target` set to a repository-relative path and no body retires a tracked file, along with every entity derived from it and every edge incident to those entities.
  - `rename` (or `move`) with `target` and `destination` both repository-relative paths relocates a tracked file. Entity ids, history, and incoming references survive the move.
  - A structured entity or relation mutation carries an explicit `payload`, for callers that already hold Kin's own entity and relation objects.
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
- **`kin_provenance_query`**: Answer who-changed-and-whether-approved for an entity, returning its change count, latest change, recorded approvals, a bounded page of its changes newest first, and recent audit events. `latest_change` is the newest change by timestamp across every origin, so a native or agent write that lands after an imported Git commit is the one reported. Changes come back as summaries carrying delta counts, and every hash is hex, so ids match what `kin log` prints. Page with `offset`/`limit` (default 20, max 200) and follow `next_offset`; `compact=false` adds the full delta payloads and is unbounded in size.

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
