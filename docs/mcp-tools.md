# Model Context Protocol (MCP) Tool Surface Reference

The Kin MCP server exposes 75 semantic tools to AI assistants (Claude, Cursor, Gemini,
Codex, etc.). These tools bridge the gap between traditional file-first navigation and
Kin's graph-first semantic substrate: instead of issuing raw shell commands or reading raw
files, an assistant interacts with the codebase through entity-level primitives.

The tools are grouped below by functional area. Most retrieval and analysis tools answer
directly from the graph. Vector-backed retrieval (`semantic_locate`) and the stateful
session, transaction, work, and review tools operate against the repo's running Kin
daemon; `semantic_locate` returns an explicit error in offline/no-daemon mode.

---

## Every Answer Names Its Authority: the `_kin` Envelope

Every tool response carries a `_kin` envelope (version 2) that names what produced the
answer and how far to trust it. The contract behind it is simple: there is no
configuration under which the server backfills a semantic answer from raw file search
behind a successful response. An answer is graph-backed and names the graph state that
produced it, or the gap is reported as a gap.

For closed JSON payload contracts, use `validateMcpContract(name, response)` from
`@kin/boundary-contracts`. It validates the optional reserved top-level `_kin`
with `mcpEnvelopeV2` and validates all remaining fields against the unchanged
domain schema. Its successful result retains both `payload` and `envelope`.
Only that top-level metadata key is separated; arbitrary domain fields and
nested metadata do not gain an exemption. Additional envelope metadata is
preserved but does not imply understood authority. A present envelope requires
version 2, a recognized runtime and the canonical `degraded` object.

The envelope carries codes and counts, not sentences. Version 1 repeated a sentence beside
most blocks on every response; version 2 sends only the fields those sentences restated,
and what each code means is written here, once. `kin status`, `kin graph status` and
`kin doctor` still print their own sentences for people.

The envelope's fields:

- `advice`: the plain sentences a reader acts on first, present only when one holds, and
  the first key of every envelope, which is the first key of every answer. Two sentences
  can ride it. When the answer came from a Kin repository that is not the client's own
  folder, it says so. When a missing language server leaves cross-file references out of
  the answer, it names what is missing and the command that adds it, spelled `kin ...` on a
  host with `kin` on the server's PATH and as the `npx -y @kinlab/kin@<version>` form of
  the same release on one without, which is every MCP registry install.
- `repository`: which Kin repository answered, on every answer a repository daemon gave:
  `root`, and, when the client works in another folder, `client_root` and a `warning`.
  The client's folder is its first workspace root, or the server's launch directory when
  the client names none. A folder with no repository of its own inside another Kin
  repository is answered from that one, and this is where the answer says so.
- `runtime`: `repo-daemon` (live, graph-owned truth) or `offline-in-process` (an
  in-process store, explicitly a fallback surface and labeled as one).
- `graph_as_of` and `graph_state`: the snapshot generation that answered, plus
  reconciliation status, entity count, and loaded/initialized flags when known.
  `entity_count` counts every entity node the daemon holds, including external reference
  targets this repository does not define; `kin graph status` prints the smaller count of
  definitions the repository owns and names the excluded targets on its own line.
- `semantic_coverage`: `indexed`, `total`, `pending` and `complete` for the embedding
  signal, with `limited_by` naming every reason `complete` is false. Carried only when the
  daemon computed it and never fabricated here.
- `durability`: a `state` over the live and durable entity and relation counts behind it.
  `recorded` means durable authority carries everything that answered. `live_uncommitted`
  means some of it is not committed yet and is lost when the daemon exits, so commit to
  record it. `unknown` means the counts could not be reconciled; `kin status` reads
  durable authority directly.
- `behind`: present when the working copy holds content graph truth never took, or when
  nothing has measured it (`measured: false`). Answers cover admitted content only;
  `kin admit` takes the paths now, and a commit takes them anyway. `changed_paths` and
  `changed_sample` count tracked files the working copy edited or removed while no daemon
  was watching and the daemon's startup catch-up has not admitted yet, and
  `changed_unchecked` is `true` when that check could not run. Either one makes every
  answer `inconclusive`, a populated one included, because until those files land the
  graph answers from their old bytes. The daemon names them before it publishes its
  endpoint and admits them on its own; `kin admit` takes them now.
- `freshness`: whether this daemon recorded a complete admission (`recorded` or
  `no_admission_recorded`), or `stale` when a status sample replays an earlier
  observation.
- `watcher_loss`: present when the filesystem watcher lost events no admission has
  covered or its durable loss record is unreadable. `reason` retains the backend's
  cause; `read_error` retains a record read failure, whose counters are unknown.
  `kin admit` on the repository clears the gap after a complete admission.
- `hydration_semantics`: the store's replay-semantics `standing`. For `behind`, run
  `kin upgrade` in the repository (`npx -y @kinlab/kin@<version> upgrade` when Kin runs
  through npm, with the version the answering build reports): it re-derives the state the
  store serves under this build and keeps every native commit, branch, review and history
  record. For `ahead`, upgrade this Kin build to at least the one that recorded the store's
  semantics. For `unstamped`, upgrade Kin to the newest build first, because a store a
  newer build created can have lost its record, then run `kin upgrade`. For `unreadable`,
  upgrade Kin to the newest build first; if it still cannot read the record, the record is
  damaged: remove `.kin/kindb/hydration-semantics` and run `kin upgrade`. An `unreadable`
  record keeps its concrete read failure in `reason`, also shown by `kin doctor`.
  `upgraded_under` is present once `kin upgrade` has run: the standing compares that
  version, `created_under` still names the version the store was created under, and
  answers that read history from before the upgrade stay qualified with
  `history_predates_upgrade`.
- `degraded`: honest flags (`daemon_unreachable`, `no_repository`, `embed_worker_failed`,
  `mass_deletion_blocked`, `offline_fallback`, `workspace_mismatch`,
  `daemon_killed_by_memory`, `sweep_suspended`, `memory_pressure`), each present only
  when observed. `no_repository` means nothing at or above the server's working directory
  is a Kin repository, so there is no daemon to reach and the remedy is `kin init` or
  `--repo`, not waiting. `workspace_mismatch` is a refusal about which repository an answer would
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
`limiting_factor` naming the class's code. `absent` means the scan completed
and found no such cross-file edge, `unknown` means the scan stopped on its budget,
and `unproduced` means the scan completed, saw no entity-level edge of the class at
all, and the source carries sites of it that the linker resolved, so the gap is in
the build rather than in the code. A verdict that certifies over a recorded limit
was the shipped 0.5.52 behaviour (FIR-2672) and is now a contract violation the
tests scan for.

An entity-level `Imports` edge, the class that answers "who imports this" at entity
level, is minted for TypeScript, JavaScript, Python, C++, HCL, Go, Java, Kotlin, PHP,
Rust and Swift. Go, Java, Kotlin, PHP, Rust and Swift reach it at the `import_scoped`
tier: a Go or Swift import names a package directory whose representative file this
build chooses, and a Java, Kotlin or PHP one names a type through a source root the
repository never writes down, so the module is settled and the name is selected
inside it rather than proven outright. C is the one language named as unable to mint
the class at all, because its adapter emits no module entity for the edge to be
sourced at and its `#include` directives are `Includes` edges. An import naming a
module this repository does not hold mints no edge in any language; it is disclosed
by the per-file import-resolution certificate, which carries how many import
statements the file wrote and how many of them reached this repository.

`limiting_factor` is `null` on a certified answer. Otherwise it is the code of every
input that refused, in the order the verdict weighs them (the absence gate's own
composition, then the coverage observation, withheld rows, the run's own degradations
and the completeness signal), joined by `"; "`, each code once. No code contains the
separator, so splitting on it is safe. The first code is what decided the state and the
rest are the other things wrong with the same answer, so a class gap never hides a dead
embedding worker. The facts behind each code are fields of the blocks the verdict's
`inputs` name. When `state` is `inconclusive`, treat the counts as a lower bound and do
not act on an absence in the answer.

`_kin.completeness` beside it carries `status`, `bound` (`exact` or `at_least`),
`substrate`, `classes`, `decided_by`, `limits`, `counted` and `reference_resolution`.

The embedding class carries a state the edge classes do not, `partial`, and the
difference is load bearing. `absent` means an attached vector index holds no embedding
for any eligible entity, which `kin embed` fixes from a standing start. `partial` means
the index holds some and is still filling, which finishes on its own. The two used to
share the word `absent`, and a store verified at `18124/18124 indexed (0 pending)`,
read a moment later at 18123 indexed with 2 pending, published
`classes.embeddings: "absent"` beside `semantic_coverage.embedding_state: "partial"` in
one response. Read the class and `semantic_coverage`'s counters together: they are one
fact stated twice and they now agree.

A nearly whole index still does not certify, and that is deliberate rather than an
oversight. `bound` is `at_least` whenever the answer cannot be shown to be whole, which
is exactly what entities still queued for embedding mean, and `bound: at_least` under a
certified verdict is itself a contradiction the tests scan for. So a threshold that let
0.011 percent pending certify would have to carry `status` to `complete` and `bound` to
`exact` over a class the same object publishes as `partial`, putting two fields in one
response back into disagreement one field over from where they were fixed. Kin sizes the
shortfall instead of waving it through: act on `classes`, `limits` and the counters
together, and treat `inconclusive` over a 99.99 percent index as "the counts are a floor
by that much" rather than as "the index is missing".

A tool that changes state, which is every session and transaction tool, carries only
`envelope_version`, `runtime` and `degraded`, plus `behind` or `watcher_loss` when
either holds. The store readings ride `kin_graph_status` and every read.

Every code `limiting_factor` carries is below, and so is every label that leads a clause
in `negative.trust_reason`. The list is closed: a code not in it is never sent, and
`unlisted_clause` in its place is a Kin defect worth reporting.

Live source-derived daemon queries add `source_derivation`, also carried under
`_kin` by stdio. It compares persisted parser evidence with admitted source bodies
for graph-owned full-adapter source files. File enumeration checks its exact path;
repository queries check the admitted inventory. A changed body, unavailable
selected authority, or an inventory past the inspection's fixed record and byte
caps makes current source binding unproven or stale and can only downgrade the
answer. The inspection waits for a graph write in flight and has no time budget,
so a graph that did not change discloses the same observation on every call.
Known live admission failures are disclosed separately. Older useful rows remain
available. Reopening the store does not clear a persisted body mismatch.

`body_binding: current` does **not** certify parsing, extraction, dependency
resolution, dispatch, or answer completeness. Those observations and each tool's
existing qualifications remain separate. Excluded source classes are outside this
inventory. The existing call-shape parse predicate is parser-only; it does not
prove all imports or dynamic dispatch resolved. The observation samples the
selected graph after the query, not every earlier payload read atomically. A
historical selected graph is not compared with live HEAD, and history-only
`semantic_diff` modes receive no unrelated live warning. Admission timestamps
continue to describe previous success, not current semantic completeness.

`prior_local_binding` reports `no_recorded_debt`, `outstanding`, or `unproven`
separately from parse and import coverage. It checks the exact reserved record
and source-owned claims; malformed, stale, unavailable or uninspected records
cannot become absence. Its obligation count is null when the binding inspection
is incomplete, and zero only after checked absence. An explicit no-debt status
with a missing or nonzero count is unproven. The count measures prior relation
obligations, not missing modules: a call and an import can contribute two
obligations for one module. An ordinary external import has no prior-local obligation. No recorded debt does not prove all imports or
legacy bindings resolved. Live impact requires this independent prerequisite
before reporting all consumers as shaped calls. Historical and custom impact
adapters without a binding proof keep their rows but cannot certify that combined
prerequisite. Older metadata missing this axis is unproven.

The inspection refuses on contention and on record, logical-copy-byte or
cooperative time limits. Its reason is reported as unproven, never as current.
Source and excluded-artifact counts are null when inspection did not complete;
a completed measured empty inventory reports zero. Paths and error samples are
bounded. No raw filesystem search or epoch cache supplies missing evidence.

<!-- clause-codes:begin -->
| Code | Meaning |
|---|---|
| `absence_coverage_unmeasured` | No coverage class was measured for the answer's language, so an empty result cannot be separated from a declaration the extractor never admitted. |
| `absence_coverage_unreported` | The answer did not report which languages its absence claim spans or whether this build resolves them. |
| `absence_scope_empty` | The graph holds no entity at all under the filter the query applied, so an empty result describes the index rather than the code. |
| `answer_coverage_unmeasured` | No coverage class was measured for the answer's language, so its rows are a floor. |
| `answer_coverage_unreported` | The answer did not report which languages its rows span or whether this build resolves them, so its rows are a floor. |
| `answer_truncated` | The answer stopped early and returned part of what it found, so its counts are a floor. |
| `binding_unproven` | A call site in the answer's scope calls through a value binding, which proves no target, so where that call goes is not known. |
| `call_sites_not_in_build` | A call site in the answer's scope sits in a file no build of the repository compiles, so no resolver proved where that call goes. |
| `call_sites_owed` | A caller in the answer's scope has call sites the graph has not settled yet, because its derivation or its enrichment is still owed, so a call there is not accounted for. |
| `call_sites_server_failed` | The resolver timed out, crashed or broke protocol at a call site in the answer's scope, so where that call goes is not known. |
| `call_sites_unproven_no_resolver` | A caller in the answer's scope has call sites no resolver can prove on this host now, because language-server enrichment is switched off, no language server serves its language, or the one that does cannot start (its analysis environment is missing, say), so waiting for enrichment will not settle them; the clause names which. |
| `call_sites_unresolved` | The resolver answered at a call site in the answer's scope and its answer proves no target, so where that call goes is not known. |
| `caller_arrival_state_unknown` | The answer reported a caller-arrival state this build does not recognise, so an empty reference list cannot be read as whole. |
| `caller_arrival_unmeasured` | The set of files that can reach the focal could not be established, because the language links no imports across files in this graph. |
| `caller_arrival_unresolved` | Some files that can reach the focal have callers the graph did not resolve, so the reference list is a floor. |
| `counts_are_a_floor` | The answer's own accounting reports its numbers as a lower bound. |
| `coverage_absent` | No entity in the store carries an embedding, so an empty semantic result means nothing was ranked. |
| `coverage_graph_body_gap` | Some graph-owned source paths carry no body, so their entities rank on text fallback. |
| `coverage_partial` | The semantic index is incomplete, so an empty result may mean not indexed rather than not present. |
| `coverage_role_filter_withheld` | Test-role source paths were withheld from ranking; pass include_tests to rank them. |
| `coverage_unknown` | Embedding coverage was not reported, so an empty result may mean not indexed rather than not present. |
| `cross_file_edges_absent` | The graph was not observed to hold cross-file edges of a requested class for the language, so a use reaching the target through that class could not have been found; the gap is in extraction or enrichment rather than in the code, and the classes that are present do not stand in for it. |
| `cross_file_edges_unproduced` | The build produced no entity-level edge of a requested class, either because no build mints that class for the language or because the linker resolved its sites without emitting one; the gap is in extraction, not in the code. |
| `cross_repo_authority_incomplete` | The cross-repo spine's topology or the requested relation subtype is incomplete at its revision. |
| `cross_repo_authority_missing` | The answer did not report cross-repo authority. |
| `cross_repo_authority_unknown` | The answer reported a cross-repo authority status this build does not recognise. |
| `cross_repo_not_applicable` | The focal is a symbol outside every repository, so no cross-repo authority applies and the answer lists the callers this repository holds. |
| `cross_repo_not_configured` | No cross-repo spine is configured, so the answer is scoped to this repository. |
| `cross_repo_unavailable` | A configured cross-repo spine could not answer and named no condition. |
| `degraded` | The daemon reported a degraded signal; `_kin.degraded` names which. |
| `dependency_outside_graph` | The question names a dependency this repository imports and this graph holds no definitions for, so the answer may live outside what was searched. |
| `dependency_scan_incomplete` | The scan of unadmitted imports hit its budget before it checked all of them. |
| `dependency_scan_unavailable` | The store could not say which of its imports are unadmitted. |
| `depth_zero` | The walk expanded no edges, so an empty neighbourhood is not evidence of isolation. |
| `derived_source_stale` | Derived source evidence differs from admitted bytes; useful last-good rows do not establish current completeness. |
| `derived_source_unproven` | Bounded graph evidence did not establish source binding in the selected scope. |
| `edge_coverage_budget_exhausted` | The coverage scan for the language stopped before it could establish what the graph holds. |
| `edge_coverage_unknown` | Whether the graph holds cross-file edges of a requested class for the language could not be established. |
| `edge_coverage_unreported` | The answer did not report whether the graph holds the cross-file edges it depends on. |
| `enrichment_incomplete` | Persisted call-site evidence in the selected repository graph is unsettled, so impact counts are a lower bound and review risk may change; the listed entities are not proven dependencies of the change. |
| `enrichment_metadata_unavailable` | Selected graph enrichment detail exceeded its bounded metadata scan. Aggregate counters remain observations, but the unavailable file inventory cannot attest dependency completion or absence. |
| `entity_index_unresolved` | Nothing resolves the program behind the parsed declarations, so an empty name or kind filter cannot separate a missing declaration from one the extractor did not admit. |
| `enumeration_shifted` | The file gained or lost entities between pages, so the pages do not assemble into one state; walk again from the start. |
| `file_bytes_unadmitted` | The working copy holds content at this path that graph truth does not carry, so the spans describe earlier bytes; `kin admit` takes the working tree. |
| `file_bytes_unchecked` | This repository has a working copy the graph is supposed to be level with and nothing is comparing them, so whether the answer describes the file as it is now is not known. |
| `file_coverage_unreported` | The answer did not report whether a language adapter parsed the file. |
| `file_not_parsed` | No language adapter produced a layout for the file, so an empty enumeration is a fact about extraction coverage, not the file. |
| `file_parse_failed` | The adapter could not parse the file, so the entities the graph still carries for it describe an earlier state. |
| `file_parse_state_unknown` | The answer reported a parse state this build does not recognise. |
| `file_parse_unrecorded` | The graph holds entities for the file and no record of how completely they were extracted, so the rows are real and their being the whole set is unestablished. |
| `file_parsed_partially` | The adapter hit parse errors in the file, so its entities are a floor. |
| `file_spans_stale` | Some entity spans in the file were derived from bytes the repository tree no longer holds at this path. |
| `focal_not_in_graph` | The focal entity was not found, so an empty neighbourhood is not evidence that it is isolated. |
| `focal_resolution_ambiguous` | The focal name resolved to several entities and only one was answered for. |
| `focal_resolution_unreported` | The answer did not report how many entities the focal could have resolved to, so it may describe a same-named sibling. |
| `graph_admission_unrecorded` | The daemon reports no complete admission of the repository into graph truth, so how far the graph is behind is unmeasured. |
| `graph_behind_working_tree` | Host paths on disk have never been admitted, or admitted paths are still owed their parse; `_kin.behind` counts each separately. |
| `graph_empty` | The graph that answered holds no entities, so it cannot speak for the repository yet; ask again once its graph is loaded. |
| `graph_not_loaded` | The daemon reports no graph loaded, so an empty structural result is not authoritative. |
| `graph_uninitialized` | The daemon has not confirmed its first reconciliation or snapshot load. |
| `history_predates_upgrade` | The answer reads the store's history, and history recorded before its last `kin upgrade` keeps the replay version that authored it and carries no checked binding history. |
| `lexical_fallback_matched_nothing` | A phrase query matched no name, and the per-token fallback ranks by word overlap rather than meaning. |
| `lexical_lookup_not_structural` | This is lexical evidence over stored graph fields, not a resolved call or reference edge; a hit or a miss here is not proof the identifier is or is not used. |
| `local_binding_outstanding` | Previously local source bindings remain unresolved; current source and parse evidence do not establish complete dependency knowledge. |
| `local_binding_unproven` | Prior-local binding evidence could not be validated for the checked scope; complete dependency knowledge is unproven. |
| `method_call_resolution_incomplete` | Receiver-method calls are linked by bare name and may be unresolved, so an empty result is not authoritative for a method. |
| `name_filter_narrowed_to_zero` | The name pattern selects declarations and the query's other filters removed every one of them. |
| `offline_fallback` | The in-process fallback graph answered, not the daemon's graph truth. |
| `page_bounded` | The response holds one page of the file; follow `next_cursor` to the end before reading the set as whole. |
| `proof_context_stale` | A call site in the answer's scope was proven under a proof context its resolver no longer runs under, so the proof may not hold for the code as it builds now. |
| `proof_context_unverified` | The selected graph has not validated the proof context of recorded call-site evidence, so that evidence does not establish current validity. |
| `ranking_is_bounded` | A ranking is a bounded candidate set, so a name absent from it may belong to an entity the query never ranked. |
| `reference_enrichment_no_language_server` | An adapter is wired for the language but no language server for it is installed on this host. |
| `reference_enrichment_unknown` | No completed language-server readiness observation is recorded for the selected language, so reference-enrichment availability is unestablished. |
| `reference_enrichment_unsupported` | This build cannot link cross-file references for the language, so an unused symbol cannot be told from an unlinked one. |
| `reference_enrichment_unusable` | A language server for the selected language failed to initialize, so reference-enrichment capability is unavailable. |
| `reference_page_partial` | This page contains only part of a reference answer; reconstruct every page and retain the original safety readings before assessing the complete result. |
| `relevance_floor_unmeasured` | Every returned row was a fallback neighbour and no calibrated threshold says any of them answers the concept. |
| `response_bounded` | The response budget withheld part of the answer; `_kin.response` names what was cut. |
| `retrieval_degraded` | The query reported degradations; the payload's `degradations` names them. |
| `selected_graph_sample_stale` | The selected graph could not be sampled live, so the counters replay an earlier observation; `_kin.freshness` has its age. |
| `semantic_authoritative` | Certifying: daemon-owned truth with complete embedding coverage. Appears only when trust is authoritative. |
| `semantic_readmission_failed` | Semantic readmission failed for admitted source; current semantic completeness is not established. |
| `spine_candidate_representation_gap` | The daemon's cross-repo spine refused this repository's graph because it holds an inferred member whose candidate authority the spine format cannot carry, so no cross-repo authority stands behind the answer for as long as the graph holds it. |
| `spine_initialization_deferred` | The daemon's cross-repo spine was not built yet, because its initialization stepped aside while a writer held graph authority, so no cross-repo authority stands behind the answer; a read after the writer finishes builds it. |
| `spine_root_stale` | The cross-repo spine's recorded root for this repository is stale. |
| `store_semantics_ahead` | A newer Kin build recorded this store's replay semantics; upgrade Kin rather than re-deriving the store with this older build. |
| `store_semantics_behind` | This store serves state an older Kin build derived; run `kin upgrade` in this repository (`npx -y @kinlab/kin@<version> upgrade` through npm) to re-derive it under this build, keeping every native commit, branch and review. |
| `store_semantics_unknown` | This store's replay-semantics record is missing or unreadable; upgrade Kin to the newest build, then run `kin upgrade` in this repository. |
| `structural_authoritative` | Certifying: the daemon's graph is initialized and loaded. Appears only when trust is authoritative. |
| `substrate_partial` | A coverage class the answer depended on was observed short of whole; `_kin.completeness.classes` names it and says whether it was `partial`, `absent` or `unproduced`. |
| `substrate_unknown` | The coverage classes the answer depended on were not all observed present; `_kin.completeness.classes` names them. |
| `trace_page_partial` | This page contains only part of a trace; reconstruct every page and retain the original safety readings before assessing the complete result. |
| `trace_spine_clipped` | The per-step cap cut the walk's fan-out, so the chain is one route among those the cap kept and a missing hop was not looked for. |
| `trace_walk_degraded` | The walk reported degradations, so it did not complete under its own work bounds. |
| `trace_walk_truncated` | The walk hit a per-step or total cap before examining everything an empty chain would have to rule out. |
| `tracked_changes_unadmitted` | Tracked files changed or removed while no daemon was watching are not admitted yet, so the answer may describe bytes the working copy no longer holds; the daemon's catch-up takes them on its own, and `kin admit` takes them now. |
| `tracked_changes_unchecked` | The daemon could not check whether tracked files changed while no daemon was watching, so the answer may describe bytes the working copy no longer holds; `kin admit` settles it. |
| `unlisted_clause` | A reason this build carries no code for. The blocks the verdict's `inputs` name hold its facts. Seeing it is a Kin defect. |
| `walk_bounded` | The walk stopped at a work bound before its frontier emptied, so a route may exist beyond what was explored. |
| `walk_depth_bounded` | The walk stopped at max_depth before its frontier emptied; raise max_depth. |
| `watcher_events_lost` | The filesystem watcher lost events no admission has covered; a running daemon retries a full admission, and `kin admit` runs it now. |
| `watcher_loss_unreadable` | The durable watcher-loss record could not be read, so recovery is unknown; `kin admit` rewrites it after a complete admission. |
| `withheld_candidates` | Same-name candidates are held out of the counts and carried in `candidates`. |
| `working_copy_unmeasured` | Nothing has measured the working copy, so whether graph truth is level with it is unknown. |
<!-- clause-codes:end -->

An empty graph is a gap, not a zero. When the graph that answered holds no entities,
`_kin.verdict` is `inconclusive` with a `graph_empty` clause, on `kin_graph_status` as on
every retrieval tool, because a daemon that has just begun serving and a repository no
admission has reached both read that way until their graph is loaded. The status answer
also names the daemon that gave it under `_kin.answered_by`: its pid, repository
root, route and uptime, the same fields `kin daemon status` prints for it.

---

## Configuring the server

The recommended way to expose these tools is the guided wizard: run `kin setup` and choose
the **AI agents** intent. It writes Kin's MCP server entry into every detected client
(Claude Code, Cursor, Codex CLI, Gemini CLI, Windsurf, Google Antigravity, LM Studio, Grok
CLI) with the curated tool profile, and
adds a Kin-first discovery reminder to your agent instruction files. `kin setup status`
then verifies each client config.

For Claude Code the wizard writes this entry, stating the profile explicitly:

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

Cursor, Gemini CLI, Windsurf and LM Studio get it with `agent-routed` as the profile. Codex
CLI and Antigravity get that `agent-routed` entry, and the Grok CLI this one, bound to one
repository with `--repo`.

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
| `agent-query` | the same belt with no session and no transaction tools, for a client that only queries |
| `agent-search` | the measured always-on set, with hidden operations discovered through `kin_tool_search` and read-only matches invoked through `kin_tool_call` |
| `agent-routed` | one tool, `kin`, whose commands reach the agent belt, writes included, and through `describe` and `call` every other tool, for a client that sends every tool with every request; `kin setup` writes it for those clients |
| `agent-routed-query` | the same one tool without a write path: no `session`, no `mutate`, and `call` reaches read-only tools only. It limits what that tool reaches, not what a shell runs: `kin call` in a shell answers as `agent-routed` does |
| `full` | every tool this reference documents |
| `benchmark` | the retrieval belt the benchmark arm drives |
| `context-bench` | read-only graph-native retrieval, no write-side session or transaction tools |

A value that is not one of these is not silently treated as "serve everything": the server
falls back to `agent-default` and says on stderr what it was asked for and what it served.

A profile shapes the tool surface `kin mcp start` offers. It is not a permission system, and
it does not constrain a local process that already holds your repo daemon's credentials.
Reach for it to keep an agent's belt focused and its context small, not as a capability
boundary you can rely on.

Every profile serves each tool's input schema as a plain `type: object` with its properties,
and the same schema to every client. A model provider's tool API refuses a schema that opens
with `anyOf`, `oneOf`, `allOf`, `not` or `if`, and a client loading tools for one drops that
tool without saying so: Claude Code listed 19 of `agent-default`'s 22 tools while
`semantic_locate`, `get_context_pack` and `lexical_lookup` opened with `anyOf`. The rules those
combinators carried are the server's to enforce. A call to `semantic_locate` needs `query` or
`cursor`, `get_context_pack` needs `entity_id`, `entities` or `question`, `lexical_lookup` needs
`literal` or `cursor`, `kin_review_create` needs `base` and `head`, `scope_type` and
`entity_ids`, or `scopes`, and `kin_review_assign` needs `reviewer` or `reviewers`. Any
combination of them is accepted, a null value supplies nothing, and a call supplying none is
refused before anything runs, with the rule and one call that works. A `kin_mutate` call that
carries `request_id` is held to the keyed rules as before: it names its session, takes `scope`
`repository` only, and accepts no other field. A `kin_review_create` call naming only a title,
or a `kin_review_assign` call naming only `requested_reviewers`, was always outside the
advertised schema and is now refused.

#### `agent-default` serves short descriptions

`agent-default` does not serve the long descriptions on this page. Each tool gets one short
sentence saying when to call it and what comes back, and an input schema trimmed to the
properties that change which entities come back rather than how the response is shaped
(`max_chars`, `compact`, `explain`, `snippet_alias` and `pipeline` are not advertised there).
Trimming hides a property; it does not remove it. No tool sets `additionalProperties: false`,
so a caller that knows a withheld property can still pass it, and `full` still advertises
every one.

This is a context budget, measured. On 2026-09-02 the profile's `tools/list` was 82,262 bytes
over 20 tools, 47,739 of it descriptions and 30,456 input schemas, spent before the model
asked anything. `full`, `benchmark` and `context-bench` keep the long forms: the last two
because their `tools/list` bytes are an input to a citable benchmark result.

On 2026-09-22 every served description on `agent-default` and `agent-query`, tool and
parameter, was cut to at most half its bytes, with no parameter dropped. `agent-query`'s
`tools/list` went from 14,610 bytes to 11,079, and `agent-default`'s from 35,118 to 26,420.
`kin_init` joined `agent-default` the same day, so a folder with no repository can be set up
from the client, and costs 366 bytes there: 26,786. Setting a folder up is a write, so
`agent-query` does not serve it.

On 2026-09-25 `kin_session_exec` joined `agent-default`, so an agent Kin sets up, Claude Code
among them, can build, test and run the code it writes without a shell. Measured off a real
`kin mcp start` the way the MCP surface contract grades it, compact JSON as a client reads it,
`agent-default`'s `tools/list` went from 34,119 bytes over 21 tools to 35,183 over 22: the tool
costs 1,064 bytes, and the profile's descriptions total 1,455 of their 1,617-character budget. It
runs the project's code and writes what the toolchain hands back, so `agent-query` does not serve
it.

#### `agent-query` is that belt without its write half

On the agent profiles, `find_references` defaults to `answer_only: true`: the same
reference rows, focal identity, counts, withheld-row disclosures and verdict, with
the graph generation, freshness, hydration, durability and degraded-state observations
preserved. It also keeps `call_site_candidates`: the unsettled call sites whose callee
or caller body spells the focal's name, each addressed by its caller and its line in
that caller, up to 20 of them, and every unsettled site that could reach the focal
counted by why it is kept. None of those sites is proven, and none is in `references`.
Detailed coverage and the full candidate blocks are available with `answer_only: false`.
An explicit `explain: true` or `compact: false` also requests the detailed response unless
`answer_only` itself is set. Errors retain their original message. The full and benchmark
profiles keep the detailed default and advertise the same optional parameter.

Native tool calling re-sends the whole `tools` array on every turn, so the served list is a
per-turn cost, not a per-session one. Measured on 2026-09-02 against a real `kin mcp start`,
`agent-default`'s `tools/list` was 30,194 bytes and 8,627 tokens on google/gemma-4-e4b: 36
percent of that run's 24,000-token ceiling before the model had asked anything, and the run
bought two tool calls. `kin_transaction_stage` and `kin_transaction_commit` alone were 11,245
of those bytes, and across six runs the model never reached for a session or a transaction
tool (FIR-3107).

`agent-query` is `agent-default` minus its write tools: the three session tools, the four
transaction tools, `kin_mutate`, `kin_init` and `kin_session_exec`.
Same served names, same short descriptions, same trimmed schemas, so nothing an agent learned
on one profile is wrong on the other. Point a query-only client at it:

```sh
KIN_MCP_TOOL_PROFILE=agent-query kin mcp start --repo /path/to/repo
```

This is a second served list, not a mode. `agent-default` is unchanged, every write tool is
still served on it, and nothing here makes Kin read-only. What `agent-query` buys is context:
a client that never stages or commits stops paying for those contracts in every prompt. Like
every profile it is a context budget rather than a permission boundary, so the paragraph above
applies: a local process holding your daemon's credentials can still write.

#### `agent-search` is the always-on set, and the rest is found on demand

Every profile above trades bytes. This one changes where the tools live. `agent-search` serves
six tools, including discovery and invocation. Ask `kin_tool_search` for an operation in plain
language, then pass its exact name and input object to `kin_tool_call`:

```json
{"tool":"find_references","arguments":{"query":"handleRequest"}}
```

The discovered definition is the full registered schema. Invocation uses the same handler,
repository and session checks, validation, response limits and persistence as a direct call.
The tool list stays fixed; clients do not need dynamic tool registration. `kin_tool_call`
accepts only registered read-only operations. Mutations require direct calls through a profile
that serves them, preserving client permission granularity. `agent-query` keeps its existing
served set; it does not gain this dispatcher.

```sh
KIN_MCP_TOOL_PROFILE=agent-search kin mcp start --repo /path/to/repo
```

The always-on set is `semantic_locate`, `trace_data_flow`, `get_context_pack`,
`kin_graph_status`, `kin_tool_search` and `kin_tool_call`. The first three are there because they were measured.
Across 40 agentic runs on 2026-09-03, over four questions on three repositories with one local
model, those three took 96 of the 103 tool calls made, `impact_analysis` was offered 24 times and
called none, and nine of the fourteen tools `agent-query` served in that study were never called once. A
four-tool arm answered every question the fourteen-tool control answered, in fewer calls, for 36
percent fewer tokens, and cited fewer symbols that failed to resolve.

Say the shape of that result precisely. It is a cost result. Answered rate, calls to answer and
expected-entity slots did not separate the candidate sets at all, and nothing in it reproduces
the published claims that a smaller tool surface raises accuracy. Whether tool search raises
Kin's own accuracy is unmeasured.

`kin_graph_status` is in the set on a different argument. It was offered 40 times and called
zero, so the call log alone would move it behind search. It stays because it is the only tool
that answers whether the graph can be trusted at all, and the response envelope does not carry
that reading on a healthy answer: `_kin.verdict` is computed from seven inputs and the graph
freshness one is silent by construction. Until a stale graph reaches an agent through the
envelope, this is the tool that says so, and it costs about 610 bytes.

An agent that never searches sees only the always-on tools. No served description
points at a withheld tool in silence: the note names `kin_tool_search` for its schema and
`kin_tool_call` for invocation. The historical four-tool result above did not evaluate this
invocation path; completed-task efficiency for this revised profile still requires measurement.

#### `agent-routed` is one tool for a client that sends every tool

A client that loads every tool it is handed re-sends every definition with every request.
Codex CLI, Cursor, Gemini CLI, Windsurf, Antigravity and LM Studio work this way. In the
corrected rerun pilot of 2026-09-22, Codex CLI 0.153.4 carried `agent-query`'s fifteen schemas
as one 14,096-byte namespace tool, about 3,500 tokens on every request against about 1,100 for
the raw arm's four tools, and its model never called a Kin tool.

`agent-routed` serves one tool, `kin`, in 1,699 bytes of `tools/list` against a 3,200-byte
budget; `agent-routed-query` serves it in 1,392. Adding the write path and `exec` needed no
larger budget. The tool takes a `command` and that command's `args`:

```json
{"command":"locate","args":{"query":"where failed requests are retried"}}
```

One vocabulary runs across the three surfaces. Each routed command runs one named tool, and
where the `kin` CLI has a subcommand for the same capability it is listed beside it:

| command | named tool | `kin` CLI | for |
| -- | -- | -- | -- |
| `locate` | `semantic_locate` | `kin locate` | code by what it does |
| `search` | `semantic_search`, or `lexical_lookup` when `args` name a `literal` or `cursor` | `kin search` | declarations by name, kind or language, or exact text |
| `context` | `get_context_pack` | `kin context` | code and routes around entities |
| `refs` | `find_references` | `kin refs` | callers, importers and references |
| `trace` | `trace_data_flow` | `kin trace-data-flow` | the call chain out from one entity |
| `path` | `trace_path` | `kin path` | how one entity reaches another |
| `impact` | `impact_analysis` | `kin impact` | what a change could affect |
| `source` | `get_entity_source` | `kin source` | one entity's code |
| `status` | `kin_graph_status` | `kin graph status` | graph counts and freshness |
| `init` | `kin_init` | `kin init` | set the client's folder up as a Kin repository, when it is not one; `agent-routed` only |
| `session` | `kin_session_start` | none | the write session `mutate` needs; `agent-routed` only |
| `mutate` | `kin_mutate` | none | entity and relationship changes in one atomic commit; `agent-routed` only |
| `exec` | `kin_session_exec` | none | build, test or run the project's toolchain in a session workspace; `agent-routed` only |
| `describe` | none | `kin describe` | a command's or tool's `args` schema and an example; with no command, every command and every other tool this connection reaches |
| `call` | any other tool | `kin call` | runs a tool by its registered name |

Any name in the table works as the command: the named tool, and the CLI spelling with or
without its leading `kin`, so `get_entity_source`, `kin source`, `kin graph source` and
`kin trace-data-flow` all run. The name of any other registered tool works too, and runs
that tool the way `call` does. Two CLI names mean something else in a shell: `kin trace` is
a one-shot composite that resolves an entity and summarizes what is around it, and
`kin status` is the workspace's status. The command `trace` is `trace_data_flow`, which the
CLI spells `kin trace-data-flow`, and `status` is `kin graph status`.

A routed call is answered as the named tool it runs: the same belt defaults, the same payload
and the same `_kin` envelope, the write path included, so `mutate` is `kin_mutate` with its
own refusals. The `args` are checked against the named tool's schema before anything runs, and
a field the tool does not declare is refused rather than ignored; a refusal names the fields
and carries one call that works. Where an answer's hints name a tool, they name it by a
spelling that runs both here and in a shell: the CLI spelling of the command that reaches it,
`kin source` for `get_entity_source` and `kin graph status` for `kin_graph_status`, or
`kin call` with the tool's name where that command has no CLI spelling or no command reaches
the tool, `kin call kin_session_start` and `kin call graph_neighborhood`. `kin_tool_search`
and `kin_tool_call` are named `kin describe` and `kin call`, the commands that do their job
here. A hint keeps the tool's own name where its spelling would push the answer past its
budget. The `_kin` envelope is never rewritten. A named tool called directly on a routed
connection is refused with the command that runs it there. On `agent-routed-query` every
write is refused before anything runs, and the refusal names `agent-routed` as the profile
that carries it.

The same words run in a shell. `kin source` is `kin graph source`, and
`kin describe [command]` prints what `describe` answers. `kin call <tool> [arguments]`
sends `call` through the server path `kin mcp start` answers it on, against the repository's
daemon, so the answer is the one this tool gives, `_kin` envelope and hints included. Its
arguments are one JSON object, `-` reads that object from stdin, and it exits 1 when the tool
answers with an error. Both answer as `agent-routed` does, writes included: a read-only
profile limits what its one MCP tool reaches, and a shell on the same machine already writes
through `kin commit` and the rest. `kin call` refuses a name a shell runs another way and
says what works there: `kin init` for `kin_init`, `kin describe` and `kin call` for
`kin_tool_search` and `kin_tool_call`, and for a command's name, the command's CLI spelling
or `kin call` with the tool it runs.

`kin setup` writes `agent-routed` for Codex CLI, Cursor, Gemini CLI, Windsurf, Antigravity and
LM Studio, and `agent-default` for Claude Code, which defers schemas behind its own tool
search, and the Grok CLI, which never sends them.

#### Which profile a client keeps

`kin setup` and `kin update` decide each client's profile the same way, in this order:

1. `kin setup --tool-profile <profile>` writes that profile into every client the run
   configures, and pins it with `KIN_MCP_TOOL_PROFILE_PINNED=1` beside it.
2. A pinned entry keeps its profile.
3. A profile a person set is kept, and pinned so later runs keep it too. The install ledger
   tells it apart from Kin's own write: the entry is the one Kin last wrote with only the
   profile changed. With no ledger record to say, a profile no Kin has written as a default
   counts as chosen.
4. Everything else gets the client's default: a new entry, one exactly as Kin last wrote it,
   and one still carrying a default an earlier Kin wrote. That is how an existing Codex CLI
   entry moves from `agent-default` to `agent-routed`.

`kin doctor` shows each client's profile and says when it is pinned.

Setup also writes a Kin-first discovery block into `~/.claude/CLAUDE.md` and
`~/.codex/AGENTS.md` for a client it registered. The block is the server's operating
procedure worded for that client's profile, `kin locate` and `kin refs` for a routed client
and `semantic_locate` and `find_references` for a named one, and Kin owns only the text
between its `kin-managed:discovery` markers. `kin setup` and `kin update` rewrite it when the
profile changes, and replace the block an earlier Kin appended without markers. A copy of
that older block a person edited is left alone. `kin doctor` flags a block that names a
command or tool its client's profile does not carry.

#### Entity bodies with line offsets

On the profiles with no Kin write path, `agent-query`, `agent-search` and
`agent-routed-query`, an entity's body from `get_entity_source` comes back with each line
starting with `+N` and a tab, where `N` is the line's offset from the entity's first line, and
an `about_body` note directly before it saying so. The plus sign keeps an offset from being
read as a file line. Where the answer carries the graph's own span, as a daemon-served record
does, the note adds `File line = start_line + N`. The entity's file location, `file_path`,
`start_line` and `end_line`, is unchanged, and the listing's description of the source tool
says the lines come as `+N`.

Every surface that restates a body is served the exact bytes: a profile that serves Kin's
write tools, the citable `benchmark` and `context-bench` profiles, and any client that sends
`"capabilities": {"experimental": {"kin": {"exactEntityBodies": true}}}` at `initialize`, which
`kin agent run` always does, because it copies a body byte for byte into the text an edit must
match. Only targeted entity source is exposed.

#### A client that hides the tool schemas

Some clients never send the tool schemas to the model at all. Grok is one: it delivers this
server's `instructions` string verbatim as a synthetic reminder on turn one, and the model has
to call Grok's own `search_tool` with a query to learn any Kin tool's name or schema. Measured
on 2026-09-15 with Kin attached beside Grok's own file and shell tools, three local models made
zero Kin calls across ten runs. Every one of the ten answered from Grok's own file and shell
tools instead, and only three ever called `search_tool` at all.

Two things follow, and both are now Kin's side of the contract rather than the client's.

The `instructions` string is an operating procedure in five numbered steps: find things with
`semantic_locate` or `semantic_search` first and do not grep or list files to explore; use
`find_references` and `get_context_pack` before `get_entity_source`; read code with
`get_entity_source` by entity id; use the shell only to build and run tests; read
`_kin.verdict` first, where inconclusive means the counts are a lower bound. Each profile is
served the wording for what it has. On the routed profiles the same steps name the routed
commands, `kin locate`, `kin search`, `kin refs`, `kin context` and `kin source`, and end by
saying that `kin describe` lists every other Kin tool and `kin call` runs it; on
`agent-routed-query` that sentence says every other read-only tool. Each of those words is also
a `kin` command a shell runs. On `agent-search` the
steps name only what that profile serves and say that `kin_tool_search` finds the rest and
`kin_tool_call` runs it. Every wording tells a model whose client lists tools by search to
search for `kin` before its first file read, and each stays under 1,200 bytes, since a client
spends it once per session on the model's context. The citable `benchmark` and `context-bench`
profiles keep, byte for byte, the tool-list wording their published numbers were measured
under. `kin agent run` builds its own prompt and never reads any of them.

The session and transaction descriptions carry no code vocabulary. A client that ranks tools by
retrieval scores them against the question, and on one real locate question Grok's ranked top
eight came back holding `kin_transaction_commit` and `kin_session_end` while `get_context_pack`,
`find_references`, `trace_path` and `trace_data_flow` did not make the cut. Two of eight slots
went to tools that answer nothing. Each of the seven now opens by saying it is plumbing for
writing and carries no word a code question is phrased in, so the same ranking pass offers the
tools that answer. The tools themselves are unchanged and the write path, begin then stage then
commit, is reachable exactly as before.

If your client only ever reads, `agent-query` removes the seven from the list entirely and is
the better answer than making them rank badly. Use the description rule for the clients that
cannot choose a profile.

`agent-default` serves the declaration filter under its registered name, `semantic_search`,
like every other profile. It also accepts **`find_declarations`** on a `tools/call`, which is
the name it advertised for four landings. That reading was right on its own terms, since the
tool filters declarations by name, kind and language and does not rank by your query while
`semantic_locate` is the tool that ranks by meaning. The served name is what the shipped
install and Windows npm proofs assert, though, so moving it is a product decision that has to
move those proofs too. Both names dispatch to the same handler on every profile.

---

## 1. Retrieval & Codebase Exploration
*Tools:* `semantic_search`, `semantic_locate`, `lexical_lookup`, `get_entity`, `get_entity_source`, `get_entity_body`, `get_entity_sources`, `get_context_pack`, `explore_codebase`, `graph_neighborhood`

- **`semantic_search`** (`agent-default` also accepts the name **`find_declarations`** on a call): Find declarations by **name, kind, or language** (functions, classes, structs, traits, enums, interfaces, types, constants). This matches real parsed declarations rather than raw string occurrences like grep, and returns each match's file path, line range, signature, and stable entity ID. Note: despite the name, this is a metadata matcher; it does **not** rank by vector similarity. Use it as your first step to find "the thing called X."
- **`semantic_locate`**: Rank the code most relevant to a **natural-language** query using Kin's vector index, the same embedding-backed retrieval that powers `kin locate`. Use it when you only have a description of the behavior, not an exact symbol name. Supports only `granularity: "entity"`, reports `semantic_coverage` as the counter object, and requires the running daemon. Each hit carries its inline source once: on `body` for the fused pipeline (the default, `routing: "fused-v1"`) and on `snippet` for the cosine pipeline. Multi-query fan-out echoes the variants once under `queries`, and a hit names the ones that surfaced it by position in `matched_variant_indexes`. **The `agent-default` belt asks for a compact response shape** at entity granularity: per hit the entity `id`, `name`, `kind`, `file`, `line`, `signature`, `score` and `matched` (`name`, `semantic` or `text_fallback`), plus `collapsed_rows` on a Go package's module row when the ranking folded that package's other files into it (at least that many rows were folded; every Go file declares its package, so a word the package is named after would otherwise bring one row per file), plus the ranked file paths, `total_ranked`, `next_cursor`, `all_fallback`, a `ranked_by` clause, and the `semantic_coverage` object the `_kin` envelope carries. The shared `kin locate --json` schema described above stays the default on the wire and on every other profile, because this payload deserializes straight back into that type and a consumer needs one parser across all three locate surfaces. Pass `surface: "compact"` to ask for the small shape yourself, or `surface: "full"` on the belt to opt back out. Two arguments force the shared schema whatever else is set: `explain: true`, since every field an explanation adds lives on it, and an explicit `include_snippet: true`, since that asks for source text per hit and the compact shape carries none. Non-entity candidates are omitted with a conversion coverage gap; file-granularity requests are refused. The compact default exists because the full shape spends most of its bytes on the back-compat `files[].symbols` roll-up of entities `entities` already carries: on a 730-entity store a twelve-hit page is 38,819 bytes full and 3,472 compact.
- **`lexical_lookup`**: Find a bare literal, including punctuation, in stored graph fields: entity name, signature, doc summary, body preview and file import/surface context. Matching folds ASCII case only; it does not use the ranked text index. Each hit names its matched field and excerpt; an exact source line requires verified source/span coherence. Results use entity-ID order with `score: null`. `total_matching` counts the matching entities in the requested kind scope, and content-bound cursors reject changed matches. Following `next_cursor` preserves hits withheld by the response budget. Each page scans and materializes the scoped graph, regardless of `limit`. Body previews may be sampled or truncated, and unadmitted source and paths are outside this lookup, so a miss cannot establish repository absence. Its disclosure and `lexical_lookup_not_structural` clause distinguish literal occurrences from resolved relationships; use `find_references` and `trace_data_flow` for those.

- **`get_entity`**: Fetch metadata about a specific entity (kind, language, path, line range, signature) without its source body. An entity whose calls a language server proved into packages outside the repository also carries `external_calls`. Given `external_reference:<uuid>`, it returns that symbol's record with `caller_count` and `referrer_count`. See [Calls into symbols outside the repository](#calls-into-symbols-outside-the-repository).
- **`get_entity_source` / `get_entity_body`**: Retrieve the implementation source of an entity, served from the graph. The id is the exact address, and a name is accepted in its place. A name returns a body only when it names one entity: one exact whole name, or, when nothing is named it exactly, one owner's member (a method, field or enum variant) that carries it as its member name, such as `get` for `Scaffold.get`. Any other name returns `ambiguous_focal` and no body or edit base, with `resolution` saying why (`same_name`, `shared_member_name` or `partial_name`) and every candidate's `entity_id`, `name`, `member_name`, `owner`, kind, file and signature under `candidates`. Past 25 candidates the rest are listed by id under `more_candidates`, and past 200 `omitted_candidates` says how many were left out. `get_entity_sources` gives such a name a row with `reason: "ambiguous_name"` and the same candidates, never `not_found`. `trace_data_flow`, `trace_computation`, `trace_path` and `get_context_pack` answer a member name several owners share the same way, and `find_references` answers each candidate in its own section under `candidates_by_owner`, listing any past its first 10 sections by id under `unsectioned_candidates`. A symbol outside the repository has no source in this graph, so an `external_reference:<uuid>` id is refused with the error code `external_symbol_has_no_repository_source` and nothing is read, and `get_entity_sources` gives it a row with that code as its `reason`.
- **`get_entity_sources`**: The batch form of `get_entity_source`. Hand it up to 50 entity IDs in priority order and it returns each entity's metadata plus its body in one budgeted call, which replaces the N separate round-trips and N response envelopes those reads would otherwise cost. Bodies fill in the order you list the IDs until the shared `token_budget` is reached, and entities past that point come back signature-only with `omitted=true`.
- **`get_context_pack`**: Package a target entity alongside its caller/import neighborhood into a single prompt-friendly bundle. The two directions come back as separate named groups: `dependencies` is what the focal needs to run, `dependents` is what breaks if you change it, and every row carries a `relation` saying which way its edge points. The focal comes back with its exact body; dependencies and dependents come back as signatures (`projection: "SignatureOnly"`) unless you pass `neighbor_bodies: true`, which adds their exact bodies within the budget. Pass `focal_body: false` when you already hold the focal's body and want its neighborhood alone; the focal then comes back as its signature with `body_omitted: "focal_body:false"`. Both controls apply to a single `entity_id` pack, and passing either with `entities` or `question` is refused. A pack carries no `source_base`: to change an entity, read it with `get_entity_source`, whose `source_base` the guarded full-body and anchored-patch `kin_mutate` forms require. A pack replaces `get_entity_source` for reading, not for editing. A question that names several things takes several focals: pass `entities` with their names or ids (a name with twins can pin the one it means, `Name@file`, `Name@file:line`, `Name#Kind`), or pass `question` and let Kin's ranking pick them, which needs the running daemon because that is where the ranking lives. That shape carries every focal, the graph route between connected focals before either focal's neighborhood, and each neighborhood water-filled into what remains, and it returns `method` (one sentence naming each focal, how it resolved and what it contributed), `routes`, `route_search.bounded` (true when a search stopped at its bound, so an absent route is not evidence there is none), and `measured_tokens`, which is never above `token_budget` because rows are dropped until it is not. `external_calls` lists the calls a focal makes into packages outside the repository, and `dependencies` holds only repository entities. `call_sites` carries the focal's own call sites, one row per site, and a site that is not settled makes the answer inconclusive; see [Call sites](#call-sites).
- **`explore_codebase`**: Get a one-shot map of the codebase via a selectable strategy (e.g. `overview`: entity counts by kind and language, plus the top public declarations).
- **`graph_neighborhood`**: Return the dependency neighborhood of an entity, traversed to a given depth. The neighborhood covers what it depends on and what depends on it. `direction` selects which side to walk: `out` for dependencies, `in` for dependents (blast radius), `both` (default) for the merged neighborhood; every returned edge is tagged with the direction it was traversed in. A proven call into a package outside the repository reaches an `external_symbol` leaf, which the walk never expands, and passing that leaf's id walks from the symbol to its callers. A walk that follows the focal's own calls, `out` or `both`, also carries `call_sites` for the focal; see [Call sites](#call-sites).

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
- **`trace_data_flow`**: Walk the directional call chain rooted at a focal entity. `max_chars` and `max_response_chars` name the same hard UTF-8 JSON byte ceiling, including the page envelope. Values are clamped to 2,000 through 60,000 bytes; defaults are 45,000 on `full` and 24,576 on `agent-default`. A larger result returns `next_cursor`. Repeat the same query with `cursor` to continue; only the byte budget may change. CLI uses the same rule through `kin trace --cursor TOKEN --focal ENTITY --max-response-chars N`. Traversal depth, fan-out and work limits still bound which graph is walked, and their original disclosures remain in the result. Response pagination preserves every reached step, requested source body and ambiguous focal/target candidate. Absolute `step` and `parent_step` identities stay stable across pages. `_kin.page` reports the full totals and whether more remains, and every partial page refuses an absence conclusion, including its last page.

  Ordinary hops remain `chain` rows. A semantic field too large for one page is returned as `record_fragment`, addressed by its collection/index, entity/step/parent identity and `field`. Append `text` fragments in `byte_offset` order until `field_complete`; offsets and `total_bytes` count UTF-8 bytes. `encoding: "utf8"` is the field's original string, including its source text. `encoding: "json_utf8"` is a structured field that must be JSON-decoded after concatenation. `record_complete` marks the last field of that record. Never interpret the temporary empty `chain` on a fragment or metadata page as a missing call. Full original safety readings arrive under `readings` (or their field fragments), so pagination adds a limit and removes no existing caveat.

  Continuations hold a frozen result for at most ten minutes and are evicted under bounded cache pressure. Changed repository, selected graph, caller scope, graph revision or query is refused with restart guidance. The cache admits at most sixteen snapshots and 64 MiB of estimated resident content, with a 16 MiB per-snapshot ceiling; a trace exceeding that work-storage bound asks for a narrower traversal. There is no filesystem fallback.

  Hosted source-read limits remain independent of page bytes: pagination preserves every source projection admitted by the hosted read limits, while any projection withheld by those limits stays disclosed. Local CLI, daemon MCP, offline MCP and hosted MCP use the same continuation contract.

- **`trace_path`**: The route between two named entities, for the question "how does A reach B" that no single-rooted walk answers. It resolves both ends (by exact name, entity id, or `name@file` to pin a twin; a qualified name that matches nothing takes its bare leaf when that is unique and is refused with the candidates listed when it is not), searches breadth-first over call, instantiation, reference, import and include edges, and returns up to `limit` shortest routes, every hop carrying its kind, file, line, the relation into the next hop and the syntax lines that produced it. A class stands for its members, so a route between two classes runs through the methods that carry it, and those containment hops are shown. `direction` defaults to `either`: forward (A reaches B) is tried first and the answer says which sense held. No route is explicit rather than plausible: `found: false`, `routes: []`, a `gap` naming what stopped the walk and how much of the graph it explored, and the same-name twin count on each end; the `negative` and `_kin.verdict` beside it say whether the absence can be trusted. In the `agent-default` profile.
- **`find_references`**: Find all entities that import, call, or reference a target symbol. One row is one referencing entity, so two callers in one file are two rows, and `total_upstream` counts those entities, the same unit `kin refs` prints. The `counts` object names the unit and adds the file and reference-site totals beside it. A row addresses its caller by `entity_id` and each usage inside that caller, never by a file line: see [Reference rows](#reference-rows). Rows omit the caller's body by default; pass `include_snippets=true` for it. Given an `external_reference:<uuid>` id, it lists the entities with an edge into that symbol, and a `query` that names such a symbol, such as `Array.map`, does the same; see [Calls into symbols outside the repository](#calls-into-symbols-outside-the-repository). `caller_arrival.count_exact` says whether every file that imports the focal's file was counted exactly from its callers' call-site ledgers, and `call_sites` tallies those callers' sites; see [Call sites](#call-sites).
- **`bulk_check_references`**: Classify many entities by reachability in one call.
- **`entity_history`**: Read a bounded chronological page of recorded changes to one entity, including a retired entity. `offset` defaults to 0, and `limit` defaults to 20 with a maximum of 100. The reply keeps `result[]` and adds `change_count`, `latest_change_id`, `returned` and `next_offset`. Follow `next_offset`, and compare `change_count` and `latest_change_id` between calls before combining pages; a partial page or one past the end certifies neither the complete history nor its absence. Each entry is a focal projection of a change, not a replayable commit: `id`, `origin` and `parents` keep their original values, and the printable `change_id` is the native semantic ID `semantic_diff` takes. Sections about other entities are replaced by exact omitted counts, and oversized focal details and optional metadata by explicit summaries. A focal detail past 12,000 bytes is not available from history at any budget; its summary names the largest view of that row, a one-row page at `max_chars` 60,000, and its operations and original counts stay exact. `max_chars` bounds the final JSON payload in UTF-8 bytes, the MCP envelope included, and not the escaped size on the JSON-RPC wire (default 45,000, accepted from 2,000 to 60,000). A value outside those bounds, a `limit` outside 1 to 100, a negative `offset`, or any of the three not an integer, is refused with a structured `history_parameters_out_of_range` error rather than clamped. A budget too small to keep exact ancestry and the required qualifications returns a structured error. A change with more parents than history can carry exactly refuses its page with `history_ancestry_exceeds_limit`, and names that change's offset and the pages that read every other row. The page bounds the reply, not the read: a store read from disk may still decode each whole change while building it. The raw daemon route now returns the same paging object instead of a bare array, so a client of that route reads `result[]`.

### Calls into symbols outside the repository

A language server that resolves a call to a declaration in a package the repository depends on records the call as an edge to an external symbol rather than to an entity. A TypeScript function that calls `[value].map(Number)` gets a call into `Array.map` from the `typescript` package, at the version the server loaded. The graph holds that symbol's identity and nothing else. No path, URI or line of its declaration is recorded, and no tool serves one.

Every answer names such a symbol with the same fields.

| Field | Meaning |
| --- | --- |
| `kind` | Always `external_symbol`. |
| `id` | `external_reference:<uuid>`. `get_entity`, `find_references` and `graph_neighborhood` accept it, and they accept the bare uuid an edge's `dst` carries too. Every other tool that takes an entity id refuses it precisely, as described below. |
| `name` | The symbol as a reader writes it, such as `Array.map`. |
| `package` | The `manager`, `name` and `version` of the package the resolver loaded, such as `npm`, `typescript` and `5.6.3`. |
| `stdlib` | Whether that package is a language's standard library. |
| `symbol` | The SCIP descriptor chain, such as `` `lib.es5.d.ts`/Array#map(). `` |

A row about one call adds how it was proven.

| Field | Meaning |
| --- | --- |
| `resolution` | `type_resolved`, as for any edge a language server proved. |
| `site_state` | `proven_external`. |
| `proof` | `resolver` (such as `lsp:tsserver`), `resolver_version`, `context` (the proof context's id) and `rule` (`lsp_definition`, `lsp_definition_alias` or `lsp_call_hierarchy`). |
| `sites` | Each call site as `line_in_entity`, counted from 0 at the caller's first line, and `callee`, the text at the site read from the caller's own body. A site is never given as a file line. When the text cannot be read, `callee` is null and `callee_unavailable` says why. |

Each read tool shows these calls in its own place.

- `get_entity` on a caller adds `external_calls`. On an external id it returns the record with `caller_count` and `referrer_count`.
- `get_context_pack` returns `external_calls` beside `dependencies`, and `dependency_selection.external_calls_returned` counts them. In a pack built from several focals each row names its focal in `caller_id`. A list stops at 50 rows and counts the rest in `external_calls_withheld`.
- `graph_neighborhood` reaches the symbol as a leaf and never walks past it, because every other caller of `Array.map` belongs to that symbol's neighborhood and not to the focal's. The edge row carries `to` and the fields above. On an external id it returns the symbol's callers.
- `find_references` on an external id returns one row per caller, with `site_count` and the fields above, addressed as every reference row is (see [Reference rows](#reference-rows)). Only a call a language server proved is an edge into such a symbol, so the list is a floor, and its `degradations` say so. A `query` reaches the symbol too, as described below.
- `trace_data_flow` reaches the symbol as a leaf step with `terminal: "external_reference"`, `entity_kind: "external_symbol"`, the symbol's id as `entity_id`, and `package`, `stdlib`, `symbol`, `site_state`, `proof` and `sites` in place of file lines. Every other step carries those six keys as null, so a chain keeps one key set. An external leaf takes a `limit_per_step` slot only after the repository's own callees.
- `get_entity_source` refuses an external id with `external_symbol_has_no_repository_source`.

Every other tool that takes an entity id answers an external id by what it is and never as a missing or invalid entity, because the graph holds the symbol. These tools refuse it with the error code `external_symbol_not_served`:

- `get_context_pack` and `trace_computation` (its `entity_id`), `trace_data_flow` (its `focal` or its `target`) and `trace_path` (either end);
- `impact_analysis`, `semantic_review` and `semantic_diff` (in `entity_ids`), `entity_history`, `kin_verify_entity` and `kin_provenance_query`;
- the tools that take a scope: `kin_annotation_add` and `kin_annotation_list` (in `targets` or `scopes`), `kin_work_create`, `kin_work_link` and `kin_work_implement` (in `scopes`), `kin_work_list` (its `scope` filter), `kin_review_create` (in `scopes` or `entity_ids`), `kin_review_note_add` and `kin_review_discuss` (their `scope`), and `kin_register_intent` and `kin_check_traffic` (in `scopes`);
- `kin_mutate`, `kin_transaction_stage` and `kin_transaction_commit`, for a relation operation whose `from` or `to` names one.

A call that names an external symbol among other ids is refused whole, so no answer about the rest reads as covering it. The error carries these fields.

| Field | Meaning |
| --- | --- |
| `code` | `external_symbol_not_served`. |
| `tool` | The tool that refused. |
| `argument` | The argument that named the symbol, such as `entity_ids`, `focal`, `target`, `from`, `to`, `scopes`, `scope` or `operations[0].payload.Relation.to`. |
| `id` | The symbol's `external_reference:<uuid>` id, whichever spelling was passed. |
| `message` | What the id names, why this tool has nothing of the symbol's own to answer from, and the tools that do. |
| `symbol` | The record `get_entity` returns for the id, with `caller_count` and `referrer_count`. |
| `served_by` | `get_entity`, `find_references` and `graph_neighborhood`, the tools that answer about the symbol. |

What a change to an external symbol reaches is its callers here, which `find_references` lists with each call's proof, so `impact_analysis` refuses it and points there rather than building a blast radius from the symbol. Its consumer counts and covering tests are read off repository entities.

A scope names a symbol outside the repository by its `external_reference:<uuid>` address, as `entity:<uuid>`, or by its bare uuid, and a tool that takes a scope refuses all three before it stores anything. None of them becomes a work link, review note or intent lock on an entity no read resolves, and the address is answered by what it names rather than as a spelling the scope parser does not recognise. `kin_work_list`, `kin_annotation_list` and `kin_check_traffic` refuse such a scope as a filter too, because no work, annotation or intent can be anchored to the symbol, so an empty answer would read as an absence. An intent scope is refused in either shape, the string or the `{"Entity": ...}` object. When the server forwards to the daemon, the daemon's intent and traffic routes give the same refusal, and it reaches the caller as the tool's own error.

A relation operation in `kin_mutate`, `kin_transaction_stage` or the inline `operations` of `kin_transaction_commit` is refused before anything is staged when its `from` or `to` names a symbol outside the repository, by its address or by the bare uuid an edge's `dst` carries, whether the verb adds, upserts or removes. An edge into such a symbol exists only where a language server proved the call, and the enrichment sweep derives it again from the caller's source. A relation payload addresses entities at both ends, so an added edge would store the symbol as an entity no read resolves, and a removal would match nothing or be undone by the next sweep. To change what a caller calls, change the caller's source. The refusal's `argument` names the operation and the end, such as `operations[0].payload.Relation.to`.

`trace_data_flow` ranks each step by whether it reaches its `target`, which it reads by walking back from the target's own edges. A symbol outside the repository has none here, so a `target` naming one is refused. Name one of its callers as the target instead; a walk through that caller reaches the symbol as a leaf step.

A `find_references` `query` reaches a symbol outside the repository when no repository entity carries the name. The query matches a symbol exactly in one of three spellings, and the first spelling that matches any symbol wins: its whole SCIP symbol, the package and the descriptor chain such as ``npm typescript 5.6.3 `lib.es5.d.ts`/Array#map().``, with or without the scheme before them; its descriptor chain alone; or the name a reader writes, such as `Array.map`. Nothing is matched by prefix, substring or case. A query that names one symbol is answered as its id is, and `focal_resolution` carries `addressed_by: "name"` and `matched` (`scip_symbol`, `scip_descriptors` or `display_name`). A name several symbols carry, one per package or version the resolver loaded, is answered with `ambiguous_focal: true`, `candidate_count`, and each candidate's record under `candidates` with its id as `entity_id`, and no references; call again with one candidate's id. An id spelled as the `query` is answered as it is under `entity_id`, and an address naming nothing held is `External symbol not found`.

`bulk_check_references` gives an external id a row with `error: "external_symbol_not_served"`, a `detail` sentence and the `symbol` record, with `has_references` null, and classifies the rest of the batch as before. `kin refs --bulk-json` gives it the same row. In a `get_context_pack` built from several focals, an external id named in `entities`, or as the `entity_id` beside them, is listed under `unresolved` with `reason: "external_symbol_not_served"`, the same `detail` and the `symbol` record, and the pack is built from the focals that are entities. `kin_review_create` refuses an external id in `entity_ids` or `scopes` with `external_symbol_not_served`, where its address was otherwise stored as a file path.

An `external_reference` id the graph holds no symbol under is an absence: `get_entity`, `impact_analysis`, `semantic_review`, `semantic_diff`, `entity_history`, `kin_verify_entity`, `kin_provenance_query`, every tool that takes a scope, every relation operation, a `trace_data_flow` `target` and a `find_references` `query` report it as `External symbol not found`, and `trace_data_flow` (its `focal`), `trace_path` and `find_references` (its `entity_id`) as the focal miss they report for any name.

### Impact and review enrichment limits

`impact_analysis` returns an `enrichment` observation, and `semantic_review`
returns the same observation under `impact.enrichment` in JSON mode or beside
`message` in text mode. It reads persisted call-site ledgers over the selected
repository graph. A committed review uses only its replayed entities and ledgers,
with `scope: "committed_graph"` and `selected_change` identifying that snapshot.

`status: "bounded"` means recorded call-site evidence remains unsettled. Impact
counts are a lower bound and review risk may change. `pending_entities` names up
to 20 entity identities, their states, and optional paths under `projection.path`;
`total_pending_entities` and `entities_withheld` disclose the full count and list
limit. This repository-wide bound is conservative: it does not prove that every
listed entity reaches the changed code. The canonical verdict and any absence
qualifier carry `enrichment_incomplete` on empty and populated answers alike.

`status: "no_recorded_call_site_debt"` describes only this ledger observation.
It does not establish current resolver availability, source admission, other
relation enrichment, or a complete and stable review.

### Reference rows

`find_references` pages its complete semantic response when it exceeds `max_chars`
(default 12000, range 2000–60000 bytes). Repeat the same query and filters with
`cursor` set to `next_cursor` until it is null; the byte budget may change. Append
collection rows in order, collect `readings` separately by key, then attach the
collections at their dotted addresses (such as `call_sites.candidates`). Oversized
records use `record_fragment`; concatenate their UTF-8 fragments before interpreting
the record. The frozen response retains caller IDs, site evidence, candidate counts
and trust clauses rather than dropping callers to fit. A partial page cannot prove
absence. Completing the transport does not establish semantic completeness: retain
the reconstructed answer's verdict and limits. Cursors are process-local, bounded
and expiring; changed graph/source authority or an active writer requires a fresh
query. A qualified positive first answer can remain available during a writer, but
its cursor cannot certify the writer's current state.

`find_references` returns one row per referencing entity, in `references`, `candidates`, `interface_dispatch.candidates`, `cross_repo.federated_references` and each section of `candidates_by_owner`. A row addresses its caller by its entity id and each usage inside that caller, the way a call-site row addresses a site. It carries no file line.

| Field | Meaning |
| --- | --- |
| `entity_id` | The caller's id, its address. Null for a federated row, whose caller lives in another repository's graph. |
| `name`, `kind`, `role` | The caller's name, entity kind, and whether it is product source, a test, vendored code and so on. |
| `projection` | `path`, the file the caller is projected into. It is a projection, not an address, and a federated row prefixes it with its repository. |
| `sites` | Each usage of the focal inside the caller, one per line, in order: `line_in_entity`, counted from 0 at the caller's first line as a numbered body counts its `+N` offsets, and `callee`, the text at the site cut from the caller's own body, with a call's argument list left out so the text names what is called. When the text cannot be read, `callee` is null and `callee_unavailable` says why, such as `caller_source_unavailable` for a caller with no body of its own to read, like a file's module scope. `line_in_entity` is null for a site outside the caller's span. |
| `site_count` | How many sites the row lists. |
| `sites_absent_reason` | Why `sites` is empty: `no_evidence_span`, `span_outside_caller_file`, `federated_xref`, `unconfirmed_sites_withheld` or `sites_in_entity`. Null when sites came back. |
| `sites_partial_reason` | Why the sites that came back may not be all of them: `language_server_edge`, `producer_without_site_contract`, `incomplete_call_evidence`, `unconfirmed_sites_in_candidates` or `occurrence_qualification_unavailable`. Null when every edge behind the row came from a complete parse. |
| `relation_kinds`, `resolution`, `via_override_of` | The edge kinds behind the row, how strongly its strongest edge was resolved, and the base method a composed row reaches the focal through. |

`kin refs` prints the same rows: each caller by its id and `projection:` path, and each site as `+N` with the text at it.

The focal of a Go interface method also carries `interface_implementations`, whose candidates are declarations rather than references. Each is addressed the same way, by its `entity_id`, with `projection.path` for its file and no file line.

Every other entity the reply names is addressed the same way. `focal_entity` carries its `id`, `name`, `kind`, `signature` and `projection.path`. Each of `focal_resolution.other_candidates` carries its `id`, `name`, `kind` and `projection.path`, and so does each entry of a sectioned reply's `unsectioned_candidates`. Each row of the `call_sites` block's `candidates`, an unsettled call site that could be a call to the focal, is addressed by its caller's id under `caller`, with `caller_name`, `line_in_entity` and `callee` inside that caller, and the caller's file as `projection.path`. None of them carries a file line.

### Call sites

Every call expression the parser reads in an entity's body is a call site, and a finished enrichment sweep records one state for each in the entity's call-site ledger. What a tool serves for a site is read in one fixed order that every tool, the CLI and the `_kin` envelope share:

1. the caller's file holds bytes its entities were not derived from, so its derivation is owed and nothing about its sites is known;
2. no ledger describes the caller, so its enrichment is owed;
3. the selected graph holds no validated context for the language, or records a failed validation, so recorded sites read as `proof_context_unverified`;
4. the ledger names a different context from the selected graph's validated context, so every site reads as stale;
5. otherwise, each site reads as the state its ledger records.

Validation belongs to the selected graph and its recorded generation. Reopened readers use that record without starting a resolver. A historical view uses its own revision's validation, never the current host's resolver state. Missing legacy validation is unverified, not implicitly current. Recorded targets and proof states remain visible when validation is missing or stale.

A site is settled when a resolver proved where the call goes: `proven_target` (a repository entity), `proven_external` (a symbol outside the repository), `proven_outside` (a declaration outside the repository with no symbol to name) or `proven_declaration` (a declaration that dispatches at run time). Every other state leaves the call's destination unknown: `binding` (a call through a value binding), `not_in_build` (a file no build compiles), `server_failed` (the resolver timed out, crashed or broke protocol), `unresolved` (the resolver answered and proved nothing), `owed_derivation`, `owed_enrichment`, `proof_context_stale` and `proof_context_unverified`.

Each tool serves the sites in its answer's scope as one `call_sites` block.

| Field | Meaning |
| --- | --- |
| `scope` | What the block was taken over: `the focal's own body`, `the focals' own bodies`, `the files that import the focal's file` or `the store`. |
| `settled` | True when every site in scope is known and settled. |
| `callers` | Entities read. |
| `callers_owed_derivation`, `callers_owed_enrichment` | Callers whose sites are not known yet. An owed caller adds no site, because how many it holds is not known. |
| `callers_stale` | Callers whose ledger was proven under a stale proof context. |
| `callers_unverified`, `unverified_contexts` | Callers whose recorded proof context is unverified, and the recorded validation failures or missing-validation reason with caller counts. |
| `sites` | Sites the read ledgers hold. |
| `by_state` | Those sites by the state each reads as. A state the block does not name holds no site. |
| `clauses` | One verdict clause per unsettled kind, each opening with its code. Empty exactly when `settled` is true. |

For a single focal the block adds `reading`, which is `current`, `owed_enrichment`, `owed_derivation`, `proof_context_stale`, `proof_context_unverified` or `no_sites` for an entity with no source text, and `rows`, one per site in the order the sites appear, at most 50, with the rest counted in `rows_withheld`. A stale reading also names the proof context the ledger was proven under in `stale_context`. An unverified reading names it in `unverified_context`, with `validation_reason`.

| Row field | Meaning |
| --- | --- |
| `line_in_entity` | The site's line, counted from 0 at the caller's first line, as a numbered body counts its `+N` offsets. Never a file line. |
| `callee` | The text at the site, cut from the caller's own body. When it cannot be read, `callee` is null and `callee_unavailable` says why. |
| `state` | What the site reads as. A stale or unverified row adds `recorded_state`, the state its ledger records. |
| `reason` | Why an `unresolved`, `server_failed` or `not_in_build` site is what it is, or null. |
| `target` | The proven destination, `entity:<uuid>` or `external_reference:<uuid>`, or null. `get_entity`, `find_references` and `graph_neighborhood` accept either spelling. |

Where each tool serves it:

- `get_context_pack` carries the block for its focal. A pack built from several focals carries the counts over every focal, without rows. Under a token or response budget the rows are cut before any dependency row and before the focal's body, and the cut is recorded under `elisions.call_site_rows`; the counts are never cut.
- `graph_neighborhood` carries the block for its focal on an `out` or `both` walk. An `in` walk reads its callers' edges and none of the focal's sites, so it carries none.
- `find_references` carries the block tallied over every caller in the files that import the focal's file, the same files `caller_arrival` reads. When every caller in such a file holds a current ledger, `caller_arrival` counts that file from its ledgers: the row's `count_source` is `site_ledgers`, `count_exact` is true, `unaccounted_call_sites` is the sites no resolver settled, and `unsettled_by_state` names their states. Otherwise the file keeps the parse-against-edge count, its row's `count_source` is `parse_versus_edges` and `owed_callers` counts the callers no ledger describes, which the block names under `owed_callers` beside `owed_caller_count`. The block's `count_exact` is true when every file was counted from ledgers, and `files_counted_from_site_ledgers` says how many were.
- `kin_graph_status` carries the block over the whole store, with `census` (the sites the ledgers hold), `shares` (for every state its `sites` and its `share` of the census, which add up to it), `callers_owed`, and `owed_files`, each file holding a caller no current ledger describes and a sweep will still reach, with how many, at most 20, with the rest counted in `owed_files_withheld`.

`kin_graph_status` and `kin graph status --json` also expose `enrichment`, a metadata-only
observation fenced to the same selected graph. Each row names an admitted artifact and body
digest, its projection path, parse standing, selected proof-context validation, call-site
reading, and outstanding local-binding obligations. No source bodies are returned. Missing
requested paths, unsupported artifacts and sources without a complete recorded census remain
explicitly unverified. This observation reads persisted context validation, not the host's
runtime readiness cache.

Use MCP `dependencies: ["src/a.py", "src/b.py"]` or repeat CLI `--dependency` to inspect an
exact set. This selection happens before detail construction and proof-input hashing,
so an unrelated large inventory does not consume the requested detail budget.
Unrelated gaps remain in the repository-wide `call_sites` block. Follow
`status_page.next_cursor` for MCP or `enrichment.page.next_cursor` for CLI with the same
dependencies, using MCP `cursor` or CLI `--cursor`.
`max_chars` (`--max-chars`) bounds serialized payload bytes, including the response envelope.
Rows are never silently clipped. An individual row or envelope that cannot fit returns an
explicit budget error. Any selected graph, proof, source-authority or dependency change rejects
a continuation; restart without the cursor. A daemon restart also invalidates it. A cached
observation has `enrichment.current=false` and cannot continue a current page sequence.

The metadata collector retains deterministic limits of 1,000,000 graph records and
8 MiB of path bytes or serialized detail rows, separately from `max_chars`. If a
detail limit is exceeded, fenced aggregate counts remain available while
`enrichment.status=bounded` and `enrichment.unavailable` report `reason`,
`limit_kind` (`records`, `path_bytes`, or `bytes`) and the exact `limit`.
`enrichment_metadata_unavailable` qualifies the verdict. No `enrichment.page` is
produced for that unavailable inventory. Any `status_page` then covers only the
independently available operational transaction rows, not enrichment completion.
Request a bounded dependency set to inspect its exact metadata. This does not
remove an independent repository-wide source-derivation limitation. Cached status
is reusable only for the same dependency selection and selected source scope.

Read three distinct states. `current_completion=recorded` means a successfully published
version-eight marker still matches complete selected source, caller, relation, ledger and
context inputs. `proof=settled` means only that the recorded call-site census is settled.
`outstanding_binding_obligations` counts historical bindings still owed independently of both.
Thus completed analysis may still have unresolved call sites or binding debt. Legacy markers
remain readable as `unverified_legacy_marker`; reading or hashing them never upgrades them.
The supported successful enrichment publication path writes a new full-input marker. Historical
views read their own context and proof records and report workspace completion unavailable.
Neither `page.complete` nor any of these states proves all relationships or safe absence;
`completion_attested` and `all_relationships_attested` remain false.

MCP graph status also reports `open_transactions.items`, a fresh operational observation of
unfinished, nonempty staged transactions owned by live writable sessions. Each row names its
transaction, owner, scope, state, staged operation count and payload digest. Staged bodies are
not exposed. `created_at` and `age_seconds` describe creation time; legacy transactions with no
recorded creation time report both as null. This is separate from selected graph proof and
workspace dirtiness. The graph observation may be cached while staged work is read fresh.

MCP `status_page` pages both metadata collections losslessly, with transaction rows first.
Transaction ownership, state, creation time or staged payload changes reject continuation;
elapsed age alone does not. Each collection retains its own counts and scope. An offline MCP
server still reports graph status unavailable, with an error result, while including its actual
in-process staged work. It never invents daemon graph counters or proof completion. Ordinary
`kin status` and `kin status --json` report the same live staged work separately under
`repository.open_transactions`.

A caller with no ledger reads as owed only while a resolver for its language can still prove its sites. When none can on this host now, because the daemon runs with language-server enrichment switched off, no language server serves the language, or the one that does cannot start, the caller reads as `unproven_no_resolver` instead: the block counts it under `callers_unproven_no_resolver`, `no_resolver` maps each reason (one per language and case, such as `python: no language server for it is installed or wired`) to its callers, and it is not an owed file. The daemon decides this from its own settings and from the language-server readiness it probes at start and at every sweep, so installing the server and letting the next sweep run turns these callers back into owed ones, and then settled ones.

The verdict reads the block as its own input, `_kin.verdict.inputs.call_sites`: inconclusive with the block's clauses while a site in scope is owed, unproven for want of a resolver, unresolved, server-failed, not in any build, a binding that proves no target, or proven under a stale or unverified proof context; certified when every site is settled; and not applicable on an answer with no block. The codes are `call_sites_owed`, `call_sites_unproven_no_resolver`, `call_sites_unresolved`, `call_sites_server_failed`, `call_sites_not_in_build`, `binding_unproven`, `proof_context_stale` and `proof_context_unverified`, listed with the others above. The same clauses reach `negative.trust_reason`, so the absence object and the verdict never disagree about them.

---

## 3. Semantic Change, Impact & Review
*Tools:* `impact_analysis`, `semantic_diff`, `semantic_review`, `shadow_gate_report`

- **`semantic_diff`**: Compute an entity-level diff of which declarations were added, removed, or changed, rather than a line-by-line text diff. Target it by base/head change IDs, entity IDs, or a list of change IDs (file paths still answer through 0.7.16 and are deprecated in favour of entity IDs). Relation changes are counted by origin and kind the way `semantic_review` text counts them.
- **`impact_analysis`**: Walk the relation graph from what changed to find the downstream entities that could be affected ("if I change this, what else might break?"). Each changed entity reported with `consumer_count: 0` is also read by the `caller_arrival` reading `find_references` publishes, in a top-level `caller_arrival` block. When a file that can reach the entity holds call sites that became no edge, or the reading could not be taken, the verdict is `inconclusive` and names the files rather than certifying the zero. The block's `scope` says what the reading can see: it counts a call site as arrived when the graph holds any call edge from it, including a call bound to a same-named definition in the caller's own file, and it reads only files that hold an import edge into the entity's file, so a caller that reaches the entity without one is not read. A zero certified over the reading says both in `negative.trust_reason`, and `_kin.verdict.inputs.caller_arrival` names the reading as one of the inputs the verdict was computed from, on `find_references` and `get_context_pack` absences as well.
- **`semantic_review`**: Produce a complete review of a change in one call. It covers entity-level diff, downstream impact, and an overall risk assessment, in `text` or `json` form. The text form opens with a summary of the risk, the counts and the findings, and counts relation changes by origin and kind, naming them when a group holds ten or fewer. The `json` form carries every relation change.
- **`shadow_gate_report`**: Run the shadow-mode merge gate over a PR-shaped change (`base` ref to `head` ref) and return one report covering changed entities, graph-proven blast radius, the verdict the gate would have issued, the repair context needed to fix findings, explicit evidence gaps, and audit evidence. Shadow mode is report-only and never blocks. Refs accept branch names and semantic change IDs, and imported Git commit SHAs resolve once their history is in the graph. Where the graph cannot prove something, the report says so in `evidence_gaps` rather than passing silently.

---

## 4. Collaborative Sessions & Intent
*Tools:* `register_session`, `kin_session_start`, `kin_session_heartbeat`, `kin_session_end`, `kin_session_exec`, `kin_register_intent`, `kin_release_intent`, `kin_check_traffic`

- **`kin_session_start` / `kin_session_heartbeat` / `kin_session_end`**: Manage developer/agent working sessions.
- **`kin_session_exec`**: Run the project's toolchain for a session, so an agent that reaches Kin alone can build, test and run the code it wrote. It takes `session_id`, `argv` (the command as separate words), and optionally `env` (plain application variables, passed exactly as given and never expanded), `timeout_secs` (default 50, at most 600), `max_output_bytes` (default 6,000 per stream, at most 16,000) and `summary`. The session must declare `can_execute`. The command runs directly, never through a shell, in a session workspace materialized from the session's current graph head, which includes every change the session already committed, and the answer carries `exit_code`, `elapsed_ms`, and `stdout` and `stderr` with `bytes`, `truncated` and, when cut, `omitted_bytes`: the first and last halves of the bound are kept and a marker shows where the middle was cut. A command still running at its timeout is stopped with every process it started and answered as `timed_out`. Every answer for a command that ran carries `ran_on`: the `change_id` the workspace was materialized from (`null` on a branch with no change yet), the workspace `tree_hash` and `workspace_generation`, the change's own `change_tree_hash`, and `uncommitted`, true when the workspace held content no change records yet. It is read from the workspace's base record before the command starts.

  Only the project's toolchain entry points run. The defaults follow the languages Kin detects in the workspace: for Go `go build`, `go test`, `go vet`, `go run`, `go list`, `go version`, `go env`, `go mod init` and `go mod tidy`; for Node `npm test`, `npm run <script>`, `npm install`, `npm ci` and `node <entry>`; for Python `python -m pytest`, `python -m unittest`, `python -m <project module>` and `pytest`; for Rust `cargo build`, `cargo test`, `cargo run` and `cargo check`. `go version` runs by itself, with no flag and no binary to read, and `go env` only reads: with nothing after it, with variable names such as `GOPATH`, or with `-json` before them. A workspace with no detected language allows all four. The repository adds commands, or fixes the languages, under `[execution.agent]` in `.kin/config.toml`:

  ```toml
  [execution.agent]
  allow = ["make test"]
  languages = ["go"]
  ```

  Shells, command runners such as `env` and `xargs`, inline code such as `python -c` and `node -e`, file utilities such as `cat`, `head`, `sed`, `cp` and `tee`, and paths outside the workspace are refused before anything runs, whatever the configuration says. So are the toolchain routes to another program: every word of a Go command is read against its subcommand's flag grammar, so `-exec`, `-toolexec`, `-vettool`, `-overlay` and `-modfile`, an `-ldflags` or `-gcflags` value naming an external linker, and any flag the grammar does not know are refused wherever they appear; npm's `--script-shell`, `--global` and `--prefix`, a node option before the entry point, cargo's `--config` and `-Z`, and Python modules that print or serve files such as `base64`, `json.tool` and `http.server` are refused too. `go version` with anything after it is refused, and so is every `go env` word but a leading `-json` and variable names, `--` included: `go env -w` and `-u` write the user's Go environment file outside the workspace, where a `GOFLAGS` would reach every later go command. A configured prefix adds commands and never lifts these. An `env` name that changes how a program is found, loaded, built or fetched is refused: `PATH`, `HOME`, `SHELL`, `IFS`, `BASH_ENV`, `ENV`, the Go toolchain's own variables such as `GOFLAGS`, `GOTOOLCHAIN`, `GOPROXY` and `GOPATH`, `NODE_OPTIONS`, `PYTHONPATH`, `RUSTFLAGS`, anything starting `LD_`, `DYLD_`, `CGO_`, `CARGO_`, `RUSTUP_`, `NPM_CONFIG_`, `GIT_`, `SSH_` or `KIN_`, and anything ending `_PROXY`. Every refusal says why, lists what the project allows, and carries one call that works.

  When the command succeeds, what it wrote is handed back through the session reconcile boundary under the agent write-back policy: the manifests and lockfiles of the toolchain that ran are admitted, `go.mod`, `go.sum`, `go.work` and `go.work.sum` for Go; `package.json`, `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock` and `pnpm-lock.yaml` for Node; `Cargo.toml` and `Cargo.lock` for Rust; `pyproject.toml`, `requirements.txt`, `poetry.lock`, `uv.lock`, `Pipfile`, `Pipfile.lock` and `pdm.lock` for Python, and any of them for a configured command. They are recorded as one change attributed to the session, exactly as its `kin_mutate` commits are, and only while the workspace still holds exactly the tree that admission published. Source code it created, changed or removed is refused and reported, because code is written through entity operations; every other file, an application's own data files included, is refused too; and build outputs are never admitted. `write_back` names each admitted and withheld path with its reason, and the `change_id` and `tree_hash` of the new head, which the session's next command runs on. A command that fails or times out keeps nothing it wrote. The session needs `can_write` and `can_commit` for its manifests to be kept.

  The command itself runs the project's own code, which can do anything that code can do, and `npm run` runs the scripts `package.json` names. What the policy governs is what an agent can run directly and what comes back into the graph. `kin_session_exec` is served by name on `agent-default` and `full`, and as `exec` on `agent-routed`; a refusal's example call is written in the form the caller holds, `{"name":"kin_session_exec","arguments":{...}}` by name and `{"command":"exec","args":{...}}` routed.
- **`kin_register_intent` / `kin_release_intent`**: Register or release intent to modify a specific entity or path, surfacing conflicts before code is edited. A scope naming a symbol outside the repository is refused with `external_symbol_not_served`; see [Calls into symbols outside the repository](#calls-into-symbols-outside-the-repository).
- **`kin_check_traffic`**: Query concurrent work on target entities or paths. A scope naming a symbol outside the repository is refused the same way.

---

## 5. Semantic Transactions
*Tools:* `kin_transaction_begin`, `kin_transaction_stage`, `kin_transaction_validate`, `kin_transaction_commit`, `kin_transaction_abort`, `kin_mutate`

- **`kin_transaction_begin`**: Start a transaction context.
- **`kin_transaction_stage`**: Stage changes to the transaction. Staged work targets entities and relationships:
  - `patch` with the exact entity UUID as `target` and `payload.EntitySourcePatch` containing the unchanged `source_base` from `get_entity_source` plus `edits: [{old_text, new_text}]` changes unique literal anchors within that original entity body. Omit `body` and `destination`. All anchors address the original body and must be nonempty, unique and nonoverlapping. Stale, missing, ambiguous or no-op edits refuse without partial publication. Use one operation per entity. This avoids resending a large body for a small edit; a guarded full-body update may be smaller for tiny entities. See [guarded source edits](mcp-source-bases.md).
  - `update` (or `modify`) with the exact entity UUID as `target`, `payload.EntitySourceBase` set to the unchanged `source_base` from `get_entity_source`, and `body` set to that entity's complete new source text, replaces one entity's body in place. The payload is required: an update with no payload, or an explicit `Entity` payload with a body, is refused as `source_base_required`, and one fresh `get_entity_source` read and a resend is the fix. When `get_entity_source` answers `source_base_unavailable` instead of a `source_base`, stop and report the verification gap. An older repository may need `kin upgrade`; reread afterward and proceed only if Kin issues a source base. If the repository is already current or no base is issued, report the unresolved gap. See [guarded source edits](mcp-source-bases.md).
  - `create` with the declared name as `target` and `payload.EntityCreate: {repository_base, unit, name, kind, body, imports}` creates one declaration in a source unit named by language identity. It is the form for an empty repository and for every Go declaration kind. See [creating declarations in a unit](#creating-declarations-in-a-unit). Omit outer `body` and `destination`.
  - `create` with an anchor function UUID as `target` and `payload.EntityCreate: {source_base, name, kind: "function", body, placement}` creates exactly one top-level leaf function beside an existing one. Use the unchanged source base of the anchor and the new function's complete declaration. `placement` is `sibling_after` or `new_source_unit`; the daemon derives projection placement from the anchor, with no caller path or offset. Omit outer `body` and `destination`.
  - `update` with the unit's package name as `target` and `payload.UnitImports: {repository_base, unit, add, remove}` adds and removes imports on one unit. Omit `body` and `destination`.
  - `remove` with the function UUID as `target` and `payload.EntityRemove: {source_base}` removes only that declaration. Its source unit and siblings remain. Omit `body` and `destination`.
  - A structured relation mutation carries an explicit `Relation` payload and adds or removes one edge. A structured `Entity` payload is Kin's own internal record for callers that already hold one; it never creates source, and a create-verb operation carrying one is refused as `entity_create_required` with the `EntityCreate` call to send instead. Neither carries a `body`: a change to an entity's source is a guarded patch or a guarded update.

Anchored function creation supports Rust, Python and Go. Separate new source units from an anchor support Python and Go only; Go anchors require plain filenames without underscores or a leading dot, and no build directives. Missing or stale anchors, occupied placement and ambiguous ownership refuse without publication.

#### Creating declarations in a unit

A unit-addressed `EntityCreate` names its source unit the way the language does, never by path. For Go, `unit` is `{"language": "go", "package": <import path relative to the module root, "." for the root package>, "name": <package clause name>, "role": "source" | "test"}`. The module root is the directory of the repository's one `go.mod`, or the repository root when there is none. Kin derives the unit's file by convention (`<package>/<name>.go`, and `<name>_test.go` for the test role), writes its package clause, and places the declaration: a method directly after its receiver type or that type's last method in the unit, anything else at the end. `imports` lists the import paths the declaration needs; Kin merges them into the unit's one import block, standard library first and each group sorted.

`kind` is `function`, `method`, `struct`, `interface`, `type`, `const` or `var`; the graph's own kind names `class`, `type_alias`, `constant` and `static_var` are accepted as synonyms. `name` is the declared name as the graph names it: `Name`, `Receiver.Method` for a method, or the first name of a grouped `const ( ... )` or `var ( ... )`. `body` is exactly the declaration, optionally led by its doc comment, with no package clause, imports or sibling declarations.

A blank var or const, such as the interface assertion `var _ Getter = (*Store)(nil)`, is created with `name` `_`. Go lets the blank identifier repeat, so its entity is named after the assertion itself, `_ Getter = (*Store)(nil)` with whitespace collapsed, and `created_entities` reports that name. A grouped `type ( ... )` is refused with the one-step alternative, one `EntityCreate` per type in the same call, and a spec declaring several names (`const A, B = 1, 2`) with the one-name-per-spec form.

`repository_base` is the workspace instant you last observed, returned unchanged from `session`, `status` or the last `mutate` reply. A successful commit's reply carries the next `repository_base` and `created_entities` (each `entity_id`, `name` and `kind`), so a caller can chain creations and read or patch what it created without a search. A keyed `kin_mutate` receipt keeps its fixed `kin.mutate.receipt.v1` shape, because a retry replays it after the base has moved, so a keyed caller reads the next base with `status`. A stale base is refused as `repository_base_conflict` carrying the base authority holds now as `current_repository_base` and a `next_step`: unit-addressed operations resend with that base in one step, and any operation carrying a `source_base` is listed in `source_reads_required` for a fresh `get_entity_source` read first. A generation that advanced over the same head and tree, such as a toolchain run that published nothing, is not a conflict. See [repository bases](mcp-source-bases.md#repository-bases).

`UnitImports` adds and removes imports on one unit. Adding an import the unit already holds and removing one it does not are no-ops, and a transaction whose every import change is already in place publishes nothing and answers `unit_imports_unchanged`. An import already held under another name is refused. A guarded patch and the `UnitImports` it needs may share one transaction and publish together.

Changing a type's members is an edit of the type. A guarded patch or update of a struct, interface, trait or enum may add, remove or rename the members nested inside it (fields, interface methods, enum variants); new members become entities, and untouched members keep their ids and bytes. An edit that adds or drops a declaration beside the entity it names is still refused.

Every existing declaration in the unit keeps its exact bytes, and the only new entities are the requested declarations and the members nested inside them; anything else refuses without publication. A name the package already declares, a unit whose directory holds another package, a method whose receiver type the package does not declare, and two creations of one name are refused. Python and TypeScript units are not supported yet; their creation is anchored only.

Whole-file creation, replacement, retirement and relocation are refused by the semantic agent surface, including direct calls and previously staged unpublished work. Conversion and materialization remain separate boundaries. Already-published receipts remain recoverable.

- **`kin_transaction_validate`**: Run constraints and validation against staged changes.
- **`kin_transaction_commit` / `kin_transaction_abort`**: Commit changes to the branch head or discard them. An optional `message` on the commit becomes the change's subject in history; without one the change records only `MCP transaction <id>`, which names the call and not the work.
- **`kin_mutate`**: Atomically validate and commit a batch of graph mutations in a single call, the one-shot front for an agent that already knows what it is changing. It begins, stages and commits in one round trip, aborts cleanly on a refusal, and takes the change message as `summary`. Every refusal is a structured tool error the caller can retry from. A relation whose `from` or `to` names a symbol outside the repository is refused with `external_symbol_not_served` before anything is staged, here and in `kin_transaction_stage` and `kin_transaction_commit`; see [Calls into symbols outside the repository](#calls-into-symbols-outside-the-repository).

A body that came back marked `... [truncated]` is refused by `kin_transaction_stage`, `kin_mutate`, and the inline `operations` form of `kin_transaction_commit` before staging or committing it. Bodies rendered inside search results, context packs and trace steps are capped at 40 lines or 2400 characters, and committing one of those would replace the entity's whole span with the part that fit. `get_entity_source` serves an entity's complete span and applies no line or character cap of its own; read the body there.

---

## 6. Work & Task Management
*Tools:* `kin_work_create`, `kin_work_list`, `kin_work_show`, `kin_work_link`, `kin_work_decompose`, `kin_work_block`, `kin_work_implement`, `kin_work_status`

- **`kin_work_create`**: Create tasks or issues.
- **`kin_work_link`**: Link tasks to specific entities or commits. A scope naming a symbol outside the repository is refused with `external_symbol_not_served` by `kin_work_create`, `kin_work_link`, `kin_work_implement` and the `scope` filter of `kin_work_list`; see [Calls into symbols outside the repository](#calls-into-symbols-outside-the-repository).
- **`kin_work_decompose`**: Break a task into subtasks.
- **`kin_work_block` / `kin_work_status`**: Manage and query implementation state.

---

## 7. Graph Annotations & TODOs
*Tools:* `kin_annotation_add`, `kin_annotation_list`, `kin_annotation_mark_resolved`, `kin_todo_import`

- **`kin_annotation_add`**: Attach notes or documentation to specific graph nodes. An annotation is anchored to what the graph holds, so a target naming an entity id the graph holds no entity under is refused with the error code `entity_not_in_graph` and nothing is written. A symbol outside the repository is refused with `external_symbol_not_served`, as described under calls into symbols outside the repository.
- **`kin_annotation_list`**: Query unresolved annotations and TODOs. No annotation is anchored to a symbol outside the repository, so a target naming one is refused with `external_symbol_not_served` rather than answered with an empty list.
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

- **`kin_review_create`**: Open a review request for semantic changes. A scope or entity id naming a symbol outside the repository is refused with `external_symbol_not_served`, and so is one given to `kin_review_note_add` or `kin_review_discuss` as its `scope`.
- **`kin_review_decide`**: Set review state (e.g. approved, blocked, needs_work).
- **`kin_review_discuss` / `kin_review_discuss_reply` / `kin_review_discuss_resolve`**: Host comment threads attached to a review.
- **`kin_review_assign` / `kin_review_unassign` / `kin_review_list` / `kin_review_get`**: Manage and inspect reviews.

---

## 10. Utility & Health
*Tools:* `dead_code`, `find_dead_code_seeded`, `benchmark`, `kin_graph_status`, `kin_tool_search`, `kin_tool_call`, `kin_init`

- **`dead_code` / `find_dead_code_seeded`**: Identify unreachable or orphaned entities (whole-repo or seeded by a semantic query).
- **`benchmark`**: Run Kin's retrieval/locate benchmarks.
- **`kin_graph_status`**: Report one schema-bound, point-in-time status view of the exact daemon graph selected for the call, covering entity and relation counts, selected-graph embedding coverage (indexed / total / pending), temporal-session versus HEAD scope, a process-local authority epoch, and backing authority. The daemon holds its normal embedding-work fence while reading internally synchronized coverage counters, then revalidates graph/scope authority before publishing; observed counts still do not attest enrichment completeness. `call_sites` counts every call site the graph's ledgers hold by state, with each state's share of that census and the callers still owed a ledger; see [Call sites](#call-sites).
- **`kin_init`**: Set a folder up as a Kin repository from inside the MCP client, for the first answer that says the folder is not one. With no `path` it sets up the client's workspace folder, or the server's working directory when the client names none; a relative `path` is taken from that folder. It runs `kin init <folder> --json --no-enrich`, which writes a `.kin` store into the folder and reads its Git history into a graph, so the folder must be a Git repository or empty; cross-file enrichment continues in the daemon that serves it next. In a Git repository it also appends `/.kin/` to `.git/info/exclude`, Git's local ignore file that is never committed, unless a rule there already covers the store. A call waits about 40 seconds and then answers that the setup is still running, which the next `kin_init` call reports on, and graph calls answer once it finishes. A folder that already is a Kin repository is answered as one and nothing is rewritten. The home directory and the filesystem root are refused, and so is a folder inside another Kin repository that is not a Git repository of its own, since that repository already answers for it. It is a write: it creates a store and the repository's canonical state. So only the profiles that write serve it, `agent-default` and `full` by name and `agent-routed` as `init`, and it runs only when called. `agent-query`, `agent-search`, `agent-routed-query`, `benchmark` and `context-bench` never list it or run it by any name, a `kin_tool_call` or a routed `call` included, and on those profiles an answer that finds no repository names the `kin init .` command to run instead.
- **`kin_tool_search`**: Find the tools this server registers but the current profile does not serve, by describing the need in plain language. Each match comes back as the complete tool definition, exactly as the `full` profile serves it, so the input contract is available. `invocation.profile_enabled` reports direct eligibility; when `invocation.callable_via_dispatcher` is true for the match, call `kin_tool_call` with the discovered name and input object. Discovery never changes the connection’s tool list. `matched_names` lists every match and `matches` carries the full definitions for the first `limit` of them, so a bounded answer reports what it did not carry. Omit `need` to enumerate the whole registry. It answers from the registry compiled into the server rather than from the graph, so it needs no daemon.

---

## 11. Semantic Discovery Boundary

Agent discovery targets entities through `semantic_search` and `semantic_locate`,
then follows relationships with `graph_neighborhood` and `find_references`.
File catalogs, whole-artifact reads and routed `read` are not served or callable,
including direct tool names and discovery dispatch. Repository membership and
materialization remain internal conversion diagnostics. Import-created file-module
nodes retain graph relationships but expose no whole-file bodies or edit bases.
Missing parsed coverage is a gap, not permission to fall back to a file catalog.

## 12. Durable Entity Drafts
*Tools:* `kin_draft_capabilities`, `kin_draft_create`, `kin_draft_save`, `kin_draft_read`, `kin_draft_list`, `kin_draft_apply`

Drafts preserve exact editing text independently of parsing and session leases.
Check capabilities before offering durable Save. Create/save/read/list preserve
invalid or empty text without publishing graph source. Explicit Apply uses a
persisted exact source-base expectation and durable keyed mutation; a recovered
older receipt never marks newer draft text applied. These tools are in the full
profile, keeping the default 22-tool agent belt unchanged. See the
[durable draft contract](mcp-entity-drafts.md) for schemas, revision CAS, recovery,
quota configuration and the explicit initial non-Unix write refusal.

- **`kin_tool_call`**: Invoke a registered read-only operation discovered with `kin_tool_search`, using `tool` for its exact name and `arguments` for its input object. Available in `agent-search` and `full`; other profiles keep their existing dispatch restrictions. Recursive dispatch, mutating operations and unknown tool names refuse before execution. All normal repository authority, session, mutation and response checks still apply.
