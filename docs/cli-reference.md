# Kin CLI reference

Every command `kin` exposes, with its real arguments, flags, and defaults. The page is written from the clap definitions in `crates/kin-cli/src/main.rs`, so a flag listed here is a flag the binary parses. Run `kin <command> --help` for the same text from your installed build, and `kin --version` to see which build that is.

Kin is pre-1.0 and the command surface moves. Where this page and your build disagree, `--help` and `kin capabilities` are authoritative.

## Reading this page

Descriptions are the command's own help text. A `--json` flag switches that command to machine-readable output. Angle brackets mark a required argument, square brackets an optional one, and a trailing `...` an argument that takes the rest of the line.

84 commands are documented below. 4 further commands (`bench-meta`, `contextbench-locate`, `prepared-state`, `semantic-only-guard`) are hidden from `kin --help` because they exist for benchmark and internal orchestration, and they are not part of the supported surface.

`kin capabilities` prints the readiness matrix for the Git-replacement command set, and `kin capabilities --json` gives the same inventory to a machine. Reach for it before scripting against a command you have not used.

Changing a command, an argument, or a flag in `crates/kin-cli/src/main.rs` means changing this page in the same commit. Nothing yet fails the build when the two drift apart, so the check is a reviewer's, the way `docs/env-vars.md` and `docs/mcp-tools.md` were before tests pinned them to their registries.

## Global flags

These apply to every command.

| Flag | Description |
| --- | --- |
| `--profile-out <file>` | Write a machine-readable execution profile to this JSON file. |
| `--profile-summary` | Print the hottest profiled stages to stderr after the command finishes. |
| `-h, --help` | Print help. |
| `-V, --version` | Print the build version. |

Every command also shares one rule for a reader that goes away. When the process reading kin's output closes the pipe, as `kin log | head -1` does once `head` has its line, kin stops writing to that stream, finishes what it was doing, and exits with the status its work earned: `0` for a command that completed and its own error status for one that was refused. A `kin commit -m ... 2>&1 | head -1` still records its change and exits `0`, and a `kin init 2>&1 | head -1` still leaves a complete store. The one exception is a write kin could not skip meeting the closed pipe, which ends the command at that write with `141`, the status a shell reports for a process `SIGPIPE` ended, and never with a `0` for work that did not run. Neither is a panic, and a command whose output goes to a file is unaffected.

## Contents

- [Start here](#start-here): `init`, `clone`, `status`, `commit`, `log`, `diff`
- [Ask the graph](#ask-the-graph): `locate`, `search`, `trace`, `path`, `impact`, `refs`, `context`
- [More graph queries](#more-graph-queries): `history`, `blame`, `overview`, `deps`, `xref`, `dead-code`, `trace-data-flow`, `security`, `languages`, `scope`, `locate-debug`
- [Branches, merges, and exact trees](#branches-merges-and-exact-trees): `branch`, `checkout`, `merge`, `conflicts`, `resolve`, `stash`, `rollback`, `tag`, `semver`, `purge-ignored`, `admit`, `reconcile`, `migrate`, `eject`, `git`
- [Review and verification](#review-and-verification): `review`, `approvals`, `verify`, `spec`, `audit`, `rename`
- [Sessions and agents](#sessions-and-agents): `agent`, `exec`, `shell`, `open`, `with`, `mcp`, `assistant`, `intent`, `traffic`, `work`, `note`, `todo`, `feature`
- [Remotes and publishing](#remotes-and-publishing): `auth`, `remote`, `push`, `pull`, `publish`, `release`, `hosted-release`, `pipeline`, `secret`
- [Graph, store, and daemon operations](#graph-store-and-daemon-operations): `graph`, `embed`, `cache`, `backup`, `resources`, `support`, `daemon`, `registry`, `telemetry`, `notify`, `bench`
- [Install and health](#install-and-health): `capabilities`, `setup`, `doctor`, `vfs`, `update`, `completions`

## Start here

The everyday path, in the order the CLI's own help lists it.

### `kin init`

Initialize a new Kin repository

```
kin init [path] [options]
```

| Argument | Required | Description |
| --- | --- | --- |
| `[path]` | no | Directory to initialize (defaults to current directory) |

| Flag | Default | Description |
| --- | --- | --- |
| `--json` |  | Output machine-readable JSON status instead of human text |

Before it captures anything, `kin init` counts the repository's commits and tracked files,
forecasts what converting that much history holds in memory, and compares the forecast to the
memory this machine or container allows. A conversion forecast well past that limit is refused
there, in one sentence, with the numbers and what to do about it, rather than being killed by the
kernel a minute later with no message at all. One forecast to spare and it says what it expects to
hold and carries on; comfortably inside it and it says nothing. The forecast is a floor taken from
measured conversions, so it understates rather than overstates, and it is a statement about memory
and never about time.

Set `KIN_INIT_MEMORY_CEILING_BYTES` to a byte count when Kin reads your machine's ceiling wrongly,
or when you have judged the forecast wrong for your repository and want to convert anyway. A value
that is not a positive whole number is refused rather than ignored, because a ceiling nobody set is
how a conversion gets killed with no warning.

Exit codes: `0` when the conversion finished and nothing died, and `7` when it produced a store but
a daemon serving that store was killed during the run, which leaves the semantic enrichment
unattested. `7` is not a failure. The store is real and answers questions; what nobody can attest is
that its enrichment finished, and the summary says the same thing in words. A scripted or
agent-driven setup should branch on it rather than treating the run as done.

### `kin clone`

Clone a repository

```
kin clone <url> [path]
```

| Argument | Required | Description |
| --- | --- | --- |
| `<url>` | yes | Git repository URL (native Kin transport is an explicit open gate) |
| `[path]` | no | Target directory (defaults to repo name) |

### `kin status`

Show coherent repository-v6 workspace status

```
kin status [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--json` |  | Output machine-readable JSON for editor integrations |
| `--wait-quiesce <seconds>` | `0` | Seconds to keep re-reading while embedding coverage is only momentarily unobservable, such as an embedding pass or a graph mutation batch spanning the sample. Never waits on a coverage that was observed, nor on an absence a re-read cannot clear. 0 reads once |

### `kin commit`

Create an exact semantic and artifact commit

The commit lands in Kin's own authority, not in Git. Nothing is written to `.git`, so `git status` still lists every file this commit recorded and `git log` does not move. That is the design rather than a gap: Kin holds the change, and `kin log`, `kin diff` and `kin review` read it. Hand it back to Git when you want it there, with `kin eject` for the working tree or a push to a Kin remote. Until then, tools that read Git, including CI, hooks and reviewers, see an unchanged repository with a dirty tree. `kin commit` prints the same fact after every commit:

> Recorded in Kin authority, not in git. `git status` stays dirty until you run `kin eject` or push this branch to a Kin remote.

```
kin commit [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `-m, --message <message>` |  | Commit message |
| `-q, --quiet` |  | Suppress progress output (only print final summary) |

### `kin log`

Show the immutable repository-v6 change log

```
kin log [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `-n, --count <count>` | `10` | Maximum number of entries |
| `--json` |  | Output the exact authority-backed report as JSON |

### `kin diff`

Show exact repository-v6 artifact and semantic changes

```
kin diff [base] [head] [options]
```

| Argument | Required | Description |
| --- | --- | --- |
| `[base]` | no | Base ref, change ID, Git object ID, HEAD, or ref-hex:&lt;hex&gt; |
| `[head]` | no | Head ref, change ID, Git object ID, WORKSPACE, or ref-hex:&lt;hex&gt; |

| Flag | Default | Description |
| --- | --- | --- |
| `--json` |  | Output the exact authority-backed report as JSON |

## Ask the graph

The semantic query surface. These answer from the graph, not by reading the tree.

### `kin locate`

Locate files relevant to an issue or problem description

```
kin locate [text] [options]
```

| Argument | Required | Description |
| --- | --- | --- |
| `[text]` | no | Problem text (inline) |

| Flag | Default | Description |
| --- | --- | --- |
| `--query <query>` |  | Additional query variant(s) for multi-query fan-out (repeatable). The primary text plus each variant are retrieved independently and their rankings RRF-fused into one deduped result. Diverse variants (identifiers, behavior, subsystem) recover more relevant files than any single phrasing. Omit for a normal single-query locate. Repeatable. |
| `--file <file>` |  | Read problem text from file |
| `--stdin` |  | Read from stdin |
| `--json` |  | Output JSON |
| `--explain` |  | Include graph-native projection reasons in the output |
| `--diagnose` |  | Diagnostic mode: enables --json --explain, adds per-stage scoring detail, entity seed dump, and timing breakdown. Compares against --gold files if provided. Use this for debugging locate quality. |
| `--gold <gold>` |  | Gold file paths for diagnostic comparison (comma-separated). With --diagnose, shows where each gold file appears/disappears in the scoring pipeline and why. Repeatable. |
| `--max-files <max-files>` |  | Max files to return (omit for adaptive sizing) |
| `--ref <ref>` |  | Resolve locate against a specific ref. Accepts `HEAD`, `HEAD~N`, branch names, `branch:&lt;name&gt;`, imported Git commits as `git:&lt;sha&gt;` or bare 40-hex SHAs, and semantic changes as `kin:&lt;id&gt;`, `change:&lt;id&gt;`, or bare change IDs. |
| `--snippets` |  | Attach a bounded inline source snippet (signature + first body lines) to each top definition symbol. Default ON for `--json` (the agent surface), so an agent can act on the first locate without a follow-up read; force it on for any output with this flag. |
| `--no-snippets` |  | Suppress inline snippets even on the `--json` surface. Conflicts with `--snippets`. |
| `--next` |  | Fetch the NEXT page of ranked entities from the previous query, reading the cursor persisted in `.kin/locate-cursor`. No retrieval re-run; pages the daemon's cached ranking. Query text is not required. Conflicts with `--cursor`. |
| `--cursor <cursor>` |  | Fetch a specific entity page using an explicit cursor token (from a prior result's `next_cursor`). Lower-level alternative to `--next`. |
| `--page-size <page-size>` |  | Entities per page for the graph-native `entities` surface (`KIN_LOCATE_ENTITY_CAP` otherwise). |
| `--include-tests` | off | Rank test-role entities alongside source. Off by default: locate demotes tests unless the query text itself reads as being about them. The response says how many test paths a default run withheld. |
| `--surface <shape>` | `full` | Which JSON shape `--json` emits. `full` is every field, the schema `POST /locate` and the MCP `semantic_locate` tool share. `compact` is the agent surface: per hit `id`, `name`, `kind`, `file`, `line`, `signature` and `score`, plus the ranked file paths, `total_ranked`, `next_cursor`, `all_fallback`, a `ranked_by` clause and a `_kin` object carrying `embedding_state` with its counts. Refused with `--diagnose`, which needs the full payload. |

`--surface compact` is for a tool loop with a token budget. The full shape spends most of its bytes
on the back-compat `files[].symbols` roll-up of entities the `entities` block already carries, and
`--no-snippets` does not remove it: on a 730-entity store, twelve results are 38,819 bytes full and
3,472 compact. Keep `full` for anything that parses the shared locate schema, which includes
ContextBench and the acceptance scripts.

The MCP `semantic_locate` tool is the other way round: compact is its default at entity granularity,
and `surface: "full"` opts back out. See [mcp-tools.md](mcp-tools.md).

### `kin search`

Search entities in the graph

```
kin search <pattern> [options]
```

| Argument | Required | Description |
| --- | --- | --- |
| `<pattern>` | yes | Search pattern (use '\|' for OR, e.g. "save\|load\|persist") |

| Flag | Default | Description |
| --- | --- | --- |
| `--json` |  | Output machine-readable JSON for editor integrations |
| `-k, --kind <kind>` |  | Filter by entity kind |
| `-l, --language <language>` |  | Filter by language |
| `--show-body` |  | Show entity source body inline |
| `--limit <limit>` |  | Max lines per entity body (with --show-body) |
| `--semantic` |  | Use semantic (vector similarity) search instead of name matching |

### `kin trace`

Trace a focal entity in one shot: resolve it, show the body, and summarize nearby context

```
kin trace <entity> [options]
```

| Argument | Required | Description |
| --- | --- | --- |
| `<entity>` | yes | Entity name or ID |

| Flag | Default | Description |
| --- | --- | --- |
| `--file <file>` |  | Exact repo-relative file qualifier for stable identity resolution |
| `--kind <kind>` |  | Exact entity-kind qualifier (for example: function or method) |
| `--json` |  | Output machine-readable JSON for editor integrations |
| `--compact` |  | Render a smaller, cheaper trace tuned for assistant workflows |
| `--show-body` |  | Compatibility no-op: trace already shows the focal body by default |
| `--limit <limit>` |  | Compatibility alias: interpreted as the nearby entry cap when provided |
| `-b, --budget <budget>` | `8k` | Token budget (8k, 16k, 32k, or custom number) |
| `--assistant <assistant>` |  | Assistant hint for tuning context pack strategy |
| `--max-lines <max-lines>` | `40` | Max lines to print for any single source snippet |
| `--nearby <nearby>` | `4` | Max nearby entries to print |
| `--transitive <transitive>` | `2` | Max transitive entries to print |

The argument takes either form. An entity id, exactly as `kin search --json` prints it, names one
entity and needs no qualifier. A name may reach several: a C function declared in a header and
defined in a source file is two entities under one name, and so is an overload set.

When a name reaches several and nothing pins one, `kin trace` prefers the definition over the
declaration, then the earlier file path, then the earlier line, then the id. Every one of those is
read off the entity record, so the same tree answers the same way in every store built from it.
The trace then says which entity it chose and names the others, so you can pin one:

```
kin trace buffer_grow --file src/buffer.h --kind function
```

`--file` takes the repo-relative path the answer prints and `--kind` the lowercase kind, the same
spellings `kin impact` takes.

A query that resolves to no entity exits non-zero and puts the message on stderr, leaving stdout
empty. That holds for the name form, for an id this repository's graph does not hold, and for a
qualifier that excludes every match, which reports what the name alone does reach rather than
claiming the entity is absent. `kin context`, `kin refs`, `kin xref` and `kin impact` refuse the
same way.

### `kin path`

Find the shortest routes from one entity to another over the graph's call, instantiation, reference, import and include edges. Each end is an entity name, an entity id, or `name@file` to pin one of two same-named entities. A class stands for its members, so a route between two classes runs through the methods that carry it. Exits 3 when the graph holds no route inside the depth bound, with the gap on stderr.

```
kin path <from> <to> [options]
```

| Argument | Required | Description |
| --- | --- | --- |
| `<from>` | yes | Source entity: name, id, or name@file |
| `<to>` | yes | Target entity: name, id, or name@file |

| Flag | Default | Description |
| --- | --- | --- |
| `--from-file <file>` |  | Pin the source to the entity of that name in this file (path or path suffix) |
| `--to-file <file>` |  | Pin the target the same way |
| `--max-depth <n>` |  | Hops walked between the two ends (default 6, ceiling 12); containment hops are not counted |
| `--limit <k>` |  | Routes printed, shortest first (default 3, ceiling 25) |
| `--direction <dir>` |  | `forward` (from reaches to), `reverse` (to reaches from), or `either` (default; forward first, reports which held) |
| `--include-type-edges` |  | Walk through type-annotation edges too |
| `--json` |  | Output machine-readable JSON, `_kin` envelope included |
| `--compact` |  | One line per hop and nothing else, sized for a prompt |

Every hop names the entity, its kind, its file and line, the relation that joins it to the next hop and the 1-based lines of the syntax that produced that edge (or, when the graph recorded no site, why under `site_lines_absent_reason`). The answer says which sense held (`direction`), how many shortest routes exist (`routes_total`), what each walk explored and why it stopped (`explored`), and how each end resolved, including how many entities carry the same exact name (`same_name_candidates`). A qualified name (`Worker::search`) that names no entity resolves to its bare leaf when exactly one entity carries it, and is refused with the candidates listed when several do, so a twin is never chosen silently under a qualifier. A no-route answer is explicit: `found: false`, an empty `routes`, and a `gap` naming what stopped the walk (`frontier_exhausted`, `depth_bound`, `edge_ceiling`, `time_budget`) with the remedy, and the `_kin.verdict` beside it says whether that absence can be trusted. The same query is served to agents as the `trace_path` MCP tool.

### `kin impact`

Show downstream impact of an entity

```
kin impact <entity> [options]
```

| Argument | Required | Description |
| --- | --- | --- |
| `<entity>` | yes | Entity name or ID |

| Flag | Default | Description |
| --- | --- | --- |
| `-d, --depth <depth>` | `3` | Maximum depth |
| `--file <file>` |  | Exact repo-relative file qualifier for stable identity resolution |
| `--kind <kind>` |  | Exact entity-kind qualifier (for example: function or method) |
| `--signature <signature>` |  | Whitespace-normalized declaration signature for overload resolution |
| `--json` |  | Emit the ranked graph-evidence report as JSON; ambiguous identities fail closed |

### `kin refs`

Show upstream callers/importers/references for an entity

```
kin refs [entity] [options]
```

| Argument | Required | Description |
| --- | --- | --- |
| `[entity]` | no | Entity name or ID. Required unless --bulk-json + --entities is provided. |

| Flag | Default | Description |
| --- | --- | --- |
| `--kind <kind>` | `all` | Filter relation kinds: all, calls, imports, or references (or Any for bulk mode) |
| `--bulk-json` |  | Bulk mode: classify many entities by reachability in one daemon call. Outputs JSON to stdout. Requires --entities. |
| `--entities <entities>` |  | Comma-separated entity UUIDs for --bulk-json. Required when --bulk-json is set. |
| `--compact` |  | If true (default) emit compact bulk-mode rows ({entity_id, has_references, reference_count}). Set --no-compact for verbose rows with name/kind/file_path/matched_kinds. |
| `--no-compact` |  | Force verbose bulk-mode rows (overrides --compact). Required for clap to accept `--no-compact`. |

### `kin context`

Build a context pack for one entity, several, or a question

```
kin context <entity>... [options]
kin context --question "<text>" [options]
```

| Argument | Required | Description |
| --- | --- | --- |
| `<entity>...` | unless `--question` | Entity names or IDs. A name with twins in the store can pin the one it means: `Name@file`, `Name@file:line`, `Name#Kind` |

| Flag | Default | Description |
| --- | --- | --- |
| `--question <text>` |  | Build the pack from the entities this question ranks for, through kin's own locate ranking |
| `-b, --budget <budget>` | `8k` | Token budget (8k, 16k, 32k, or custom number) |
| `--assistant <assistant>` |  | Assistant hint for tuning context pack strategy |
| `--max-focals <n>` | `5` | Most focal entities a question may resolve to |
| `--json` |  | Emit the resolved targets and the whole context pack as JSON |

A question that names several things needs a pack that carries all of them.
"When I type a character in the editor, how does it end up in the document"
names three, and a pack built around any one of them answers something
narrower. Naming several focals, or asking a question and letting the ranking
name them, builds one pack from all of them: every focal first, then the graph
route between focals the graph connects, then each focal's neighbourhood
water-filled into what is left, so a short neighbourhood never holds budget a
long one needed.

```
kin context handleKeyboardInput TextDocument --budget 1500
kin context --question "when I type a character, how does it reach the document" --budget 1500
kin context 'apply@src/model.c' TextDocument      # pin the twin you mean
```

The output states its method in one line: which focals, how each resolved
(named, pinned, by id, or located from the question with its score), what each
contributed, the route material between connected focals, what the pack
measured, and the store's semantic coverage. `--json` carries the same facts
under `multi_focal`, plus `routes`, `route_search` and the per-section
`budget_elisions`.

**Budgets differ between the two shapes, on purpose.** A multi-focal pack comes
in at or under `--budget`: it is rendered, measured with the estimator kin
builds packs with, and rows are dropped until it fits. A single-focal pack can
exceed its budget, because every section there keeps a row whatever the budget
says, and the rendering says so. Both report `measured_tokens` in `--json`, which
is what the bytes actually cost.

`route_search.bounded` is worth reading before concluding two entities are
unrelated. It is true when a route search stopped at its own bound, in which
case an absent route says nobody looked far enough rather than that the graph
joins nothing.

## More graph queries

Narrower questions over the same graph authority.

### `kin history`

Show entity history

```
kin history <entity> [options]
```

| Argument | Required | Description |
| --- | --- | --- |
| `<entity>` | yes | Entity name or ID |

| Flag | Default | Description |
| --- | --- | --- |
| `--ref <ref>` |  | Resolve history against a specific ref. Accepts `HEAD`, `HEAD~N`, branch names, `branch:&lt;name&gt;`, imported Git commits as `git:&lt;sha&gt;` or bare 40-hex SHAs, and semantic changes as `kin:&lt;id&gt;`, `change:&lt;id&gt;`, or bare change IDs. |

### `kin blame`

Show blame (version history) for an entity

```
kin blame <entity> [options]
```

| Argument | Required | Description |
| --- | --- | --- |
| `<entity>` | yes | Entity name or ID |

| Flag | Default | Description |
| --- | --- | --- |
| `--ref <ref>` |  | Resolve blame against a specific ref. Accepts `HEAD`, `HEAD~N`, branch names, `branch:&lt;name&gt;`, imported Git commits as `git:&lt;sha&gt;` or bare 40-hex SHAs, and semantic changes as `kin:&lt;id&gt;`, `change:&lt;id&gt;`, or bare change IDs. |

### `kin overview`

Show a quick codebase overview (entity counts by kind, language, top files)

```
kin overview [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--compact` |  | Compact mode: only show counts, no entity listings |
| `--json` |  | Output all entities as JSON (for programmatic use) |

### `kin deps`

Show this repository's recorded cross-repo dependencies

```
kin deps [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--all` |  | Report every registered repository instead of this one |
| `--json` |  | Output machine-readable JSON |

### `kin xref`

Show federated cross-repo references (xrefs) for an entity

```
kin xref <entity>
```

| Argument | Required | Description |
| --- | --- | --- |
| `<entity>` | yes | Entity name or ID |

### `kin dead-code`

Find dead code (whole-repo scan, or seeded by semantic query)

```
kin dead-code [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--seed <query>` |  | Seeded mode: run semantic_search(query) → classify each top-N candidate by incoming references → return dead-first ranked JSON. Closes the find-dead-code accuracy gap on large repos where the agent burns the tool-call cap looping search → find_references. |
| `--limit <n>` |  | Max candidates to classify in seeded mode (default 20, max 200). Ignored when --seed is not set. |
| `--name-pattern <substring>` |  | Optional case-insensitive substring filter on the candidate entity name. Lets callers pre-narrow to a known prefix or suffix (e.g., a planted-secret tag like "_eaca1f07") without burning extra tool-call rounds. |

### `kin trace-data-flow`

Trace the call/data-flow chain rooted at a focal entity. Returns the focal body plus a structured chain of callees, callers, or both (with bodies inlined) in a single substrate call. Closes the trace-computation accuracy gap where the agent loops `get_entity_source` per step and burns the 24-round tool-call cap.

```
kin trace-data-flow [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--focal <entity>` |  | Focal entity to start tracing from. Accepts a UUID or an exact entity name (resolved via the same ranking path as `graph source`). |
| `--depth <n>` |  | Maximum traversal depth from the focal (default 3, capped at 8). |
| `--direction <dir>` |  | Traversal direction: `calls`, `callers`, or `both` (default both). |
| `--limit-per-step <m>` |  | Max relations expanded per step (default 5, capped at 25). |

### `kin security`

Scan entity graph for security patterns

```
kin security [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--propagate` |  | Trace transitive dependency vulnerabilities |

### `kin languages`

List the languages Kin extracts semantics from

```
kin languages [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--json` |  | Output machine-readable JSON |

### `kin scope`

Set, show, or clear a temporal scope for the current session

```
kin scope [ref-string] [options]
```

| Argument | Required | Description |
| --- | --- | --- |
| `[ref-string]` | no | Ref to scope to (git:sha, branch name, HEAD~N, etc.) |

| Flag | Default | Description |
| --- | --- | --- |
| `--clear` |  | Clear the current scope |
| `--show` |  | Show the current scope |
| `--session <session>` |  | Session ID (or set KIN_SESSION_ID env var) |

### `kin locate-debug`

Debug locate results: show per-signal breakdown, rank gold files, and diagnose why targets were missed.

```
kin locate-debug <text> [options]
```

| Argument | Required | Description |
| --- | --- | --- |
| `<text>` | yes | Problem text (inline query) |

| Flag | Default | Description |
| --- | --- | --- |
| `--target <target>` |  | Gold file to track (report rank and signal breakdown) |
| `--task-file <task-file>` |  | Load query and gold files from a benchmark task JSON |
| `--max-files <max-files>` | `50` | Max files to search (wider than default to find low-ranked targets) |
| `--json` |  | Output machine-readable JSON |

## Branches, merges, and exact trees

Version-control operations over graph-owned history.

### `kin branch`

Repository-v6 branch operations (see subcommand readiness)

```
kin branch <subcommand>
```

Subcommands:

#### `kin branch list`

List byte-exact repository-v6 branch refs

```
kin branch list [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--json` |  | Output exact ref names and targets as JSON |

#### `kin branch create`

Create a ref with compare-and-swap

```
kin branch create [name] [options]
```

| Argument | Required | Description |
| --- | --- | --- |
| `[name]` | no | UTF-8 short branch name or fully-qualified refs/heads/... name |

| Flag | Default | Description |
| --- | --- | --- |
| `--ref-hex <lower-hex>` |  | Canonical lowercase hex for a fully-qualified byte-exact branch ref |

#### `kin branch delete`

Delete a ref with force-with-lease

```
kin branch delete [name] [options]
```

| Argument | Required | Description |
| --- | --- | --- |
| `[name]` | no | UTF-8 short branch name or fully-qualified refs/heads/... name |

| Flag | Default | Description |
| --- | --- | --- |
| `--ref-hex <lower-hex>` |  | Canonical lowercase hex for a fully-qualified byte-exact branch ref |

#### `kin branch switch`

Switch workspace authority and projection atomically Uncommitted work comes with you, the way it does across a Git checkout. Pending work at a path the destination branch does not track moves across and is still uncommitted when you arrive. Pending work at a path the destination already tracks with identical content becomes an ordinary member of that branch. A pending edit to a member both branches hold identically moves across too. The switch refuses only where replaying the work would lose something: a new file whose path the destination tracks with different content, or an edit to a member the destination holds differently or does not hold at all. It names every blocked path, and commit or `kin stash push` clears the way.

```
kin branch switch [name] [options]
```

| Argument | Required | Description |
| --- | --- | --- |
| `[name]` | no | UTF-8 short branch name or fully-qualified refs/heads/... name |

| Flag | Default | Description |
| --- | --- | --- |
| `--ref-hex <lower-hex>` |  | Canonical lowercase hex for a fully-qualified byte-exact branch ref |

### `kin checkout`

Restore an exact path or subtree from immutable repository-v6 history

```
kin checkout [path] [options]
```

| Argument | Required | Description |
| --- | --- | --- |
| `[path]` | no | UTF-8 repository path to restore |

| Flag | Default | Description |
| --- | --- | --- |
| `--path-hex <path-hex>` |  | Byte-exact repository path as canonical lowercase hexadecimal. Conflicts with `[path]`. |
| `--change <change>` |  | Change ID (defaults to current branch head) |

### `kin merge`

Merge semantic and exact-tree changes from another branch

```
kin merge <branch> [options]
```

| Argument | Required | Description |
| --- | --- | --- |
| `<branch>` | yes | Branch to merge from |

| Flag | Default | Description |
| --- | --- | --- |
| `--json` |  | Emit the machine-readable merge report |

### `kin conflicts`

Show the durable merge transaction held for this workspace

```
kin conflicts [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--json` |  | Emit the machine-readable merge transaction record |

### `kin resolve`

Resolve repository-v6 merge conflicts Nine flags name a resolution and at least one is required, which is a group rather than a per-argument condition. `kin conflicts` is the read-only view of the same transaction, so nothing here has to accept an empty invocation in order to be inspectable.

```
kin resolve [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--ours <selector>` |  | Keep your (target branch) version of a conflicting identity. Repeatable. |
| `--theirs <selector>` |  | Keep the incoming (source branch) version of a conflicting identity. Repeatable. |
| `--base <selector>` |  | Keep the merge base version of a conflicting identity. Repeatable. |
| `--remove <selector>` |  | Settle a conflicting identity by dropping it from the merge. Repeatable. |
| `--keep-path <path=artifact>` |  | Settle a contested path by naming the artifact that keeps it. Repeatable. |
| `--all-ours` |  | Resolve all remaining conflicts keeping your version |
| `--all-theirs` |  | Resolve all remaining conflicts keeping the incoming version |
| `--do-continue`, `--continue` |  | Complete the merge after all conflicts are resolved. `--continue` is an accepted alias that the CLI parses but does not list in `--help`, so a reader coming from Git will find it works. |
| `--abort` |  | Abort the merge and discard conflict state |
| `--expect <hash>` |  | Require the merge transaction to still be the one this identity names |
| `--json` |  | Emit the machine-readable merge transaction record |

### `kin stash`

Seal and restore exact graph-owned workspace state

```
kin stash <subcommand>
```

Subcommands:

#### `kin stash push`

Seal exact graph-owned workspace state and return the workspace to its base.

```
kin stash push [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `-m, --message <message>` |  | Label the sealed state. Defaults to the workspace head it was sealed on. |
| `--yes` |  | Skip the typed confirmation for discarding the projected working files (for non-interactive use). |

#### `kin stash pop`

Restore the most recently sealed workspace state and drop its stash

```
kin stash pop
```

#### `kin stash list`

List sealed workspace states

```
kin stash list [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--json` |  | Output the machine-readable stash report |

### `kin rollback`

Publish an exact restoration of a previous change

```
kin rollback [change-id] [options]
```

| Argument | Required | Description |
| --- | --- | --- |
| `[change-id]` | no | Change ID to rollback to. Omit when naming a work item with --feature. |

| Flag | Default | Description |
| --- | --- | --- |
| `--feature <feature>` |  | Roll back every change the named work item records |

### `kin tag`

Publish an exact repository-v6 tag ref

```
kin tag <tag> [options]
```

| Argument | Required | Description |
| --- | --- | --- |
| `<tag>` | yes | Release tag |

| Flag | Default | Description |
| --- | --- | --- |
| `--require-proof` |  | Block release if entities lack linked passing tests |
| `--require-approval` |  | Require known-human approval for every reachable non-root change |
| `--force` |  | Force release even with low coverage |

### `kin semver`

Analyze semver impact from immutable repository-v6 changes

```
kin semver [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--base <base>` |  | Explicit base endpoint: a ref, change, HEAD, or WORKSPACE |
| `--head <head>` | `HEAD` | Explicit head endpoint (defaults to the committed workspace base) |
| `--json` |  | Emit the machine-readable impact report as JSON |

### `kin purge-ignored`

Retire tracked paths that ignore rules now cover. Reports without changing anything unless --confirm is given.

```
kin purge-ignored [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--confirm` |  | Publish the removal instead of only reporting it |
| `--confirm-mass-deletion` |  | Accept a purge that removes more than 75% of a non-trivial tree |

### `kin admit`

Admit the complete exact working tree into graph authority now The daemon admits a complete tree on startup, on commit, and on what its watcher observes. This is the trigger for the case none of those covers: a graph that fell behind its working tree and is waiting for churn that is not coming.

```
kin admit
```

### `kin reconcile`

Admit one exact disposable-session observation into repository-v6 authority

```
kin reconcile [session] [options]
```

| Argument | Required | Description |
| --- | --- | --- |
| `[session]` | no | Session ID (defaults to most recent session) |

| Flag | Default | Description |
| --- | --- | --- |
| `--confirm-mass-deletion` |  | Confirm an observation that removes more than 75% of a non-trivial tree |

### `kin migrate`

Migrate an existing Git repository into graph-owned Kin truth

```
kin migrate [source] [options]
```

| Argument | Required | Description |
| --- | --- | --- |
| `[source]` | no | Source repository path (defaults to current directory) |

| Flag | Default | Description |
| --- | --- | --- |
| `--target <target>` |  | Distinct destination (defaults to an in-place migration) |

### `kin eject`

Verify graph-derived projection, install exact Git, and detach Kin. Every graph-owned artifact and blob must match one durable authority generation before metadata can be detached.

```
kin eject [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--yes` |  | Skip the typed "eject" confirmation. |

### `kin git`

Exact Git interoperability projections

```
kin git <subcommand>
```

Subcommands:

#### `kin git export`

Export exact objects, refs, aliases, and source CAS to a new Git repo

```
kin git export [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `-o, --output <output>` |  | New target directory (must be outside the Kin working repository) |

## Review and verification

Semantic review, approvals, and the checks around a change.

### `kin review`

Run semantic review on changes, or manage review state

```
kin review [<subcommand>] [change] [options]
```

| Argument | Required | Description |
| --- | --- | --- |
| `[change]` | no | Change ID to review (defaults to latest) |

| Flag | Default | Description |
| --- | --- | --- |
| `--json` |  | Output machine-readable JSON for editor integrations |
| `--entities <entities>` |  | Comma-separated entity IDs to review |
| `--files <files>` |  | Comma-separated file paths to review |
| `--changes <changes>` |  | Comma-separated change IDs to combine into one review |

Run `kin review` with no subcommand for the default behavior above, or one of:

#### `kin review shadow`

Shadow-mode merge gate: evaluate a PR-shaped change and emit a report-only verdict with blast radius, repair context, and audit evidence. Never blocks and never mutates graph state.

```
kin review shadow [range] [options]
```

| Argument | Required | Description |
| --- | --- | --- |
| `[range]` | no | Change range as &lt;base&gt;..&lt;head&gt;. Refs accept branch names, semantic change IDs, and imported Git commit SHAs. |

| Flag | Default | Description |
| --- | --- | --- |
| `--base <base>` |  | Base ref (alternative to the positional range; pair with --head) |
| `--head <head>` |  | Head ref (alternative to the positional range; pair with --base) |
| `--title <title>` |  | Change title for the report (e.g. PR title) |
| `--source-url <source-url>` |  | Source URL for the report (e.g. PR URL) |
| `--author <author>` |  | Change author identity for the report |
| `--json` |  | Emit the report as machine-readable JSON |

#### `kin review create`

Create a new review

```
kin review create [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `-t, --title <title>` |  | Review title |
| `--base <base>` |  | Base ref (branch name or change ID) |
| `--head <head>` |  | Head ref (branch name or change ID) |
| `-d, --description <description>` |  | Optional description |

#### `kin review decide`

Record a review decision (approve, needs-work, block)

```
kin review decide <review-id> [options]
```

| Argument | Required | Description |
| --- | --- | --- |
| `<review-id>` | yes | Review ID |

| Flag | Default | Description |
| --- | --- | --- |
| `--state <state>` |  | Decision state: approved, needs_work, blocked |
| `--comment <comment>` |  | Optional comment |

#### `kin review note`

Add a note to a review

```
kin review note <review-id> [options]
```

| Argument | Required | Description |
| --- | --- | --- |
| `<review-id>` | yes | Review ID |

| Flag | Default | Description |
| --- | --- | --- |
| `--body <body>` |  | Note body |
| `--scope <scope>` |  | Optional scope (entity:&lt;uuid&gt; or artifact:&lt;path&gt;) |

#### `kin review discuss`

Start a discussion thread on a review

```
kin review discuss <review-id> [options]
```

| Argument | Required | Description |
| --- | --- | --- |
| `<review-id>` | yes | Review ID |

| Flag | Default | Description |
| --- | --- | --- |
| `--body <body>` |  | Discussion body |
| `--scope <scope>` |  | Optional scope (entity:&lt;uuid&gt; or artifact:&lt;path&gt;) |

#### `kin review reply`

Reply to a discussion thread

```
kin review reply <discussion-id> [options]
```

| Argument | Required | Description |
| --- | --- | --- |
| `<discussion-id>` | yes | Discussion ID |

| Flag | Default | Description |
| --- | --- | --- |
| `--body <body>` |  | Reply body |

#### `kin review resolve`

Resolve a discussion thread

```
kin review resolve <discussion-id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `<discussion-id>` | yes | Discussion ID |

#### `kin review assign`

Assign a reviewer

```
kin review assign <review-id> [options]
```

| Argument | Required | Description |
| --- | --- | --- |
| `<review-id>` | yes | Review ID |

| Flag | Default | Description |
| --- | --- | --- |
| `--reviewer <reviewer>` |  | Reviewer identity (email or handle) |

#### `kin review list`

List reviews

```
kin review list [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--state <state>` |  | Filter by state: pending, approved, needs_work, blocked |

#### `kin review show`

Show a specific review with all details

```
kin review show <review-id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `<review-id>` | yes | Review ID |

### `kin approvals`

Manage change approvals

```
kin approvals <subcommand>
```

Subcommands:

#### `kin approvals show`

Show approvals for a change

```
kin approvals show <change-id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `<change-id>` | yes | Change ID |

#### `kin approvals list`

List all actors and delegations

```
kin approvals list
```

### `kin verify`

Verify test coverage for entities

```
kin verify <subcommand>
```

Subcommands:

#### `kin verify entity`

Check coverage for a specific entity

```
kin verify entity <entity>
```

| Argument | Required | Description |
| --- | --- | --- |
| `<entity>` | yes | Entity name or ID |

#### `kin verify plan`

Plan a targeted proof set from an entity and its downstream impact

```
kin verify plan <entity> [options]
```

| Argument | Required | Description |
| --- | --- | --- |
| `<entity>` | yes | Entity name or ID |

| Flag | Default | Description |
| --- | --- | --- |
| `--depth <depth>` | `2` | Dependent traversal depth used to widen the proof set |

#### `kin verify change`

Plan a targeted proof set for a semantic change or the current HEAD

```
kin verify change [change-id] [options]
```

| Argument | Required | Description |
| --- | --- | --- |
| `[change-id]` | no | Semantic change ID (defaults to current branch head) |

| Flag | Default | Description |
| --- | --- | --- |
| `--depth <depth>` | `2` | Dependent traversal depth used to widen the proof set |

#### `kin verify summary`

Show repository-wide coverage summary

```
kin verify summary
```

#### `kin verify missing`

Show only entities missing test coverage

```
kin verify missing
```

#### `kin verify run`

Execute tests for an entity and record a VerificationRun

```
kin verify run <entity> [options]
```

| Argument | Required | Description |
| --- | --- | --- |
| `<entity>` | yes | Entity name or ID |

| Flag | Default | Description |
| --- | --- | --- |
| `--runner <runner>` | `cargo` | Test runner: cargo, jest, pytest, go, junit, or custom command |
| `--depth <depth>` | `2` | Dependent traversal depth used to widen the proof set |

### `kin spec`

Manage specs

```
kin spec <subcommand>
```

Subcommands:

#### `kin spec create`

Create a new spec

```
kin spec create <intent>
```

| Argument | Required | Description |
| --- | --- | --- |
| `<intent>` | yes | Spec intent description |

#### `kin spec list`

List specs

```
kin spec list
```

#### `kin spec show`

Show a spec

```
kin spec show <id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `<id>` | yes | Spec ID |

### `kin audit`

Show audit trail

```
kin audit [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--actor <actor>` |  | Filter by actor ID |
| `--limit <limit>` | `50` | Maximum number of events |
| `--action <action>` |  | Filter by action type |
| `--since <since>` |  | Filter events since date (ISO 8601) |
| `--scope <scope>` |  | Filter by target scope |

### `kin rename`

Bounded graph-native rename; unsupported cases fail closed

```
kin rename <symbol> <new-name> [options]
```

| Argument | Required | Description |
| --- | --- | --- |
| `<symbol>` | yes | Entity name or symbol under the cursor |
| `<new-name>` | yes | Replacement name |

| Flag | Default | Description |
| --- | --- | --- |
| `--file <file>` |  | File hint to disambiguate the target entity |
| `--line <line>` |  | 1-based line hint in --file; required when --column is provided |
| `--column <column>` |  | 0-based UTF-8 byte column (tree-sitter coordinate), requires --line |
| `--json` |  | Output machine-readable JSON for editor integrations |

## Sessions and agents

Running tools and assistants against materialized graph truth.

### `kin agent`

Run a task through Kin's own agent loop, or check that it can start

```
kin agent <subcommand>
```

`kin agent` is Kin's own agent, and the path the product recommends for agent work.
It drives any OpenAI-compatible endpoint, so a local model in LM Studio, Ollama,
llama.cpp or vLLM works from the same flags as a hosted one, and it reaches the graph
over the same MCP server `kin mcp start` serves, so it sees the real tools, the `_kin`
freshness envelope, and the `negative` verdict on an empty result.

The policy is the product's thesis, enforced in the agent's own process rather than
borrowed from a vendor's permission layer. The belt is Kin's tools plus exactly two
local tools, `edit_file` and `write_file`. There is no shell, no grep and no
file-reading tool, so there is nothing to fall back to, and a tool the model invents is
refused by name. When a result reports `safe_to_conclude_absent` false, the agent is
told the answer is unknown and given the named gap rather than being allowed to conclude
the thing does not exist. Every edit runs inside a Kin transaction under a Kin session,
so the change carries provenance naming the agent.

Working with Claude Code, Codex, Cursor and Gemini stays first class; `kin setup
--intent agent` still configures every client it detects.

Subcommands:

#### `kin agent run`

Run one task to completion against an OpenAI-compatible endpoint

```
kin agent run --task <FILE|TEXT> --model <ID> --base-url <URL> [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--task <file\|text>` | required | The task: a path to a file holding it, or the text itself |
| `--model <id>` | required | Model id as the endpoint names it |
| `--base-url <url>` | required | OpenAI-compatible base URL, with or without a trailing `/v1` |
| `--api-key-env <name>` |  | Name of an environment variable holding the API key. The key itself is never accepted on the command line, so it cannot land in a process listing. |
| `--repo <path>` | current directory | Repository to work in |
| `--mcp-command <cmd>` | this binary serving `--repo` | Override the MCP server command |
| `--out <dir>` | `.kin/agent/<timestamp>` | Directory for the transcript, the Kin trace and the result record |
| `--max-tool-calls <n>` | `40` | Tool-call budget before the agent is asked for a final answer |
| `--deadline <s>` | `900` | Wall-clock deadline in seconds |
| `--system <file>` |  | File holding a system prompt that replaces the built-in one |
| `--temperature <f>` |  | Sampling temperature passed through to the endpoint |
| `--tool-profile <profile>` |  | Tool surface the MCP server should serve |

Three files land under `--out`. `transcript.jsonl` is the run, one JSON object per line,
in the same stream-json shape Claude Code emits, so existing transcript analyzers read it
unchanged. `kin-trace.jsonl` is one row per tool call carrying the `_kin` envelope, the
`negative` verdict and the policy decision, joinable to the transcript on `tool_use_id`.
`result.json` is the terminal record on its own.

The exit code is the run's outcome: `0` a final answer, `1` a harness error, `2` the
tool-call budget was spent, `3` the deadline expired, `4` the endpoint was unreachable or
answered with nothing usable, `5` the MCP server failed. A transcript is written and
closed on every one of them, so a failed run is still measurable.

#### `kin agent doctor`

Check that the model endpoint and the Kin MCP server both answer

```
kin agent doctor --base-url <URL> [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--base-url <url>` | required | OpenAI-compatible base URL |
| `--model <id>` |  | Model id to look for in the endpoint's list |
| `--repo <path>` | current directory | Repository to serve |
| `--mcp-command <cmd>` | this binary serving `--repo` | Override the MCP server command |
| `--api-key-env <name>` |  | Name of an environment variable holding the API key |
| `--tool-profile <profile>` |  | Tool surface the MCP server should serve |

Exit `0` when both answer, `4` when the endpoint does not, `5` when the MCP server does not.

### `kin exec`

Run a command in an exact graph-derived session workspace

```
kin exec [options] -- <command>...
```

| Argument | Required | Description |
| --- | --- | --- |
| `-- <command>...` | yes | Command to run (put kin flags before it: `kin exec --keep -- npm test`) |

| Flag | Default | Description |
| --- | --- | --- |
| `--shell` |  | Interpret the command through the platform shell instead of preserving argv boundaries |
| `--keep` |  | Keep the session workspace after the run and defer reconcile |
| `--discard` |  | Discard all workspace changes after the run (no reconcile). Conflicts with `--keep`. |
| `--strategy <strategy>` |  | Materialization strategy |
| `--scope <scope>` |  | Scope filter |

### `kin shell`

Open a shell in an exact graph-derived session workspace

```
kin shell [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--strategy <strategy>` |  | Materialization strategy |

### `kin open`

Launch an editor over an exact graph-derived session workspace

```
kin open <editor>
```

| Argument | Required | Description |
| --- | --- | --- |
| `<editor>` | yes | Editor to launch: code or cursor |

### `kin with`

Launch an assistant in an exact graph-derived session workspace

```
kin with <assistant> [options] [-- <task>...]
```

| Argument | Required | Description |
| --- | --- | --- |
| `<assistant>` | yes | Assistant to launch: claude, codex, gemini |
| `[-- <task>...]` | no | Task prompt |

| Flag | Default | Description |
| --- | --- | --- |
| `--semantic-only` |  | Deny the assistant's native discovery tools for this launch, leaving Kin's semantic tools as the only discovery surface; the enforcement tier is printed at launch and differs per assistant |

### `kin mcp`

MCP server commands

```
kin mcp <subcommand>
```

Subcommands:

#### `kin mcp start`

Start the MCP stdio server

```
kin mcp start [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--global` |  | Run in global mode, serving every repo in this home's registry (KIN_REGISTRY_PATH, else <KIN_HOME>/registry.toml, else ~/.kin/registry.toml) |
| `--repo <path>` |  | Bind this server to a specific Kin repository instead of relying on the launching process's working directory. Overrides KIN_MCP_REPO. Use this for a global agent-CLI MCP entry that may launch outside any Kin repository (e.g. an umbrella workspace root). |
| `--tool-profile <profile>` |  | Tool surface to serve: `agent-default` (the curated agent belt, and the default), `agent-query` (that belt without the session and transaction tools, for a client that only queries), `full` (every tool, roughly 12k extra tokens of schemas per session), `benchmark`, or `context-bench`. Overrides KIN_MCP_TOOL_PROFILE. |
| `--no-spawn` |  | Never start or revive a daemon from this server: bind only a daemon that is already running, and answer graph tool calls with an honest "no daemon is running" error otherwise. This is the probe mode for watchdogs and boot-time checks (equivalent to KIN_NO_DAEMON=1): the MCP handshake and tool list are served in full, and nothing heavy is ever spawned by the check itself. |

### `kin assistant`

Manage assistant adapters

```
kin assistant <subcommand>
```

Subcommands:

#### `kin assistant install`

Install an assistant adapter

```
kin assistant install <assistant>
```

| Argument | Required | Description |
| --- | --- | --- |
| `<assistant>` | yes | Assistant name: claude-code, codex, gemini-cli, cursor, generic |

#### `kin assistant doctor`

Run connectivity checks

```
kin assistant doctor [assistant]
```

| Argument | Required | Description |
| --- | --- | --- |
| `[assistant]` | no | Specific assistant to check (checks all if omitted) |

#### `kin assistant list`

List installed adapters

```
kin assistant list
```

#### `kin assistant sync`

Sync managed doc blocks

```
kin assistant sync
```

#### `kin assistant configure`

Configure managed doc sync targets

```
kin assistant configure [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--sync-mode <sync-mode>` |  | Sync mode: manual, on-commit, daemon-auto |
| `--enable <enable>` |  | Enable a target file |
| `--disable <disable>` |  | Disable a target file |

#### `kin assistant snippets`

Generate ready-to-paste config snippets

```
kin assistant snippets [assistant]
```

| Argument | Required | Description |
| --- | --- | --- |
| `[assistant]` | no | Specific assistant (defaults to all MCP-capable) |

#### `kin assistant hooks`

Show recommended hook templates

```
kin assistant hooks [assistant]
```

| Argument | Required | Description |
| --- | --- | --- |
| `[assistant]` | no | Specific assistant (defaults to claude-code) |

#### `kin assistant prompt`

Generate injectable prompt guidance

```
kin assistant prompt [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--assistant <assistant>` |  | Assistant: claude, codex, gemini |
| `--mode <mode>` | `normal` | Mode: normal or benchmark |

### `kin intent`

Manage agent intents (locks on scopes)

```
kin intent <subcommand>
```

Subcommands:

#### `kin intent list`

List all active intents

```
kin intent list
```

#### `kin intent register`

Register a new intent (lock a scope)

```
kin intent register <scope> [options]
```

| Argument | Required | Description |
| --- | --- | --- |
| `<scope>` | yes | Scope to lock (entity:&lt;uuid&gt;, file:&lt;path&gt;, or bare UUID/path) |

| Flag | Default | Description |
| --- | --- | --- |
| `-l, --lock <lock>` | `soft` | Lock type: hard or soft |
| `-t, --task <task>` |  | Task description |
| `-s, --session <session>` |  | Session ID (defaults to a new CLI session) |

#### `kin intent release`

Release a specific intent

```
kin intent release <intent-id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `<intent-id>` | yes | Intent ID to release |

#### `kin intent clear`

Clear all intents for a session

```
kin intent clear <session-id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `<session-id>` | yes | Session ID whose intents to clear |

### `kin traffic`

Show traffic (active intents) on a scope

```
kin traffic <subcommand>
```

Subcommands:

#### `kin traffic show`

Show active traffic on a scope

```
kin traffic show <scope>
```

| Argument | Required | Description |
| --- | --- | --- |
| `<scope>` | yes | Scope to query (entity:&lt;uuid&gt;, file:&lt;path&gt;, or bare UUID/path) |

#### `kin traffic sessions`

List all active sessions

```
kin traffic sessions
```

### `kin work`

Manage work items (features, tasks, issues, debt, TODOs)

```
kin work <subcommand>
```

Subcommands:

#### `kin work create`

Create a new work item

```
kin work create [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `-k, --kind <kind>` |  | Work kind: feature, task, issue, debt, todo, investigation |
| `-t, --title <title>` |  | Work item title |
| `-d, --description <description>` |  | Optional description |
| `-s, --scope <scope>` |  | Scope to link (entity:&lt;uuid&gt;, artifact:&lt;path&gt;, or bare path) |
| `-p, --priority <priority>` |  | Priority: critical, high, medium, low, none |

#### `kin work list`

List work items

```
kin work list [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `-s, --status <status>` |  | Filter by status |
| `-k, --kind <kind>` |  | Filter by kind |
| `--scope <scope>` |  | Filter by scope (entity:&lt;uuid&gt;, contract:&lt;uuid&gt;, artifact:&lt;path&gt;, change:&lt;id&gt;, or bare path) |

#### `kin work show`

Show work item details

```
kin work show <work-id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `<work-id>` | yes | Work item ID |

#### `kin work link`

Link a work item to a scope

```
kin work link <work-id> <scope>
```

| Argument | Required | Description |
| --- | --- | --- |
| `<work-id>` | yes | Work item ID |
| `<scope>` | yes | Scope to link |

#### `kin work decompose`

Link a parent work item to a child work item

```
kin work decompose <parent-work-id> <child-work-id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `<parent-work-id>` | yes | Parent work item ID |
| `<child-work-id>` | yes | Child work item ID |

#### `kin work block`

Mark one work item as blocked by another

```
kin work block <blocked-work-id> <blocker-work-id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `<blocked-work-id>` | yes | Blocked work item ID |
| `<blocker-work-id>` | yes | Blocker work item ID |

#### `kin work implement`

Link semantic scopes that implement a work item

```
kin work implement <work-id> <scope>
```

| Argument | Required | Description |
| --- | --- | --- |
| `<work-id>` | yes | Work item ID |
| `<scope>` | yes | Implementing scope |

#### `kin work status`

Update a work item status

```
kin work status <work-id> <status>
```

| Argument | Required | Description |
| --- | --- | --- |
| `<work-id>` | yes | Work item ID |
| `<status>` | yes | New status: proposed, planned, in_progress, blocked, done, verified, archived |

#### `kin work close`

Close a work item

```
kin work close <work-id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `<work-id>` | yes | Work item ID |

#### `kin work verify`

Verify test coverage for a work item's implementing entities

```
kin work verify <work-id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `<work-id>` | yes | Work item ID |

### `kin note`

Manage annotations (comments, warnings, instructions, reasoning)

```
kin note <subcommand>
```

Subcommands:

#### `kin note add`

Add an annotation to a semantic scope or work item

```
kin note add <target> [options]
```

| Argument | Required | Description |
| --- | --- | --- |
| `<target>` | yes | Target to annotate (entity:&lt;uuid&gt;, contract:&lt;uuid&gt;, artifact:&lt;path&gt;, change:&lt;id&gt;, work:&lt;uuid&gt;, or bare path) |

| Flag | Default | Description |
| --- | --- | --- |
| `-k, --kind <kind>` |  | Annotation kind: comment, warning, instruction, reasoning |
| `-b, --body <body>` |  | Annotation body |

#### `kin note list`

List annotations for a semantic scope or work item

```
kin note list <target>
```

| Argument | Required | Description |
| --- | --- | --- |
| `<target>` | yes | Target to query (entity:&lt;uuid&gt;, contract:&lt;uuid&gt;, artifact:&lt;path&gt;, change:&lt;id&gt;, work:&lt;uuid&gt;, or bare path) |

#### `kin note stale`

Show stale annotations

```
kin note stale
```

### `kin todo`

Import inline TODOs as work items

```
kin todo <subcommand>
```

Subcommands:

#### `kin todo import`

Import inline TODOs from source files

```
kin todo import [path]
```

| Argument | Required | Description |
| --- | --- | --- |
| `[path]` | no | Path to scan (defaults to working directory) |

### `kin feature`

Create a feature (alias for `kin work create --kind feature`)

```
kin feature <title> [options]
```

| Argument | Required | Description |
| --- | --- | --- |
| `<title>` | yes | Feature title |

| Flag | Default | Description |
| --- | --- | --- |
| `-d, --description <description>` |  | Optional description |

## Remotes and publishing

Native Kin remotes, hosted surfaces, and package publishing.

### `kin auth`

Authenticate with KinLab for native remotes

```
kin auth <subcommand>
```

Subcommands:

#### `kin auth login`

Log into KinLab and store a CLI credential

```
kin auth login [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--base-url <base-url>` |  | Override the KinLab base URL |
| `--no-browser` |  | Print a browser URL and exchange a one-time code manually |
| `--provider <google\|github>` | `google` | Which identity provider to sign in with |

Sign in with GitHub if you have a GitHub account, which is the path most people
here already have:

```sh
kin auth login --provider github
```

`--provider` decides which sign-in page the browser lands on. The default is
`google`, which is where every login went before there was a choice, so an
invocation that names no provider behaves the way it did before. A provider this
deployment holds no credentials for sends the browser to the sign-in page with
`authError=provider-unavailable` rather than to that provider.

`kin auth status` and `kin doctor` report the provider a stored credential asked
for, worded that way on purpose: the token exchange carries no provider back, so
what either surface knows is what the login requested. A credential minted before
`--provider` existed names none, and both say nothing rather than guessing.

#### `kin auth logout`

Log out and remove the stored KinLab credential

```
kin auth logout [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--base-url <base-url>` |  | Override the KinLab base URL |

#### `kin auth whoami`

Show the authenticated KinLab user

```
kin auth whoami [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--base-url <base-url>` |  | Override the KinLab base URL |

#### `kin auth status`

Show whether a KinLab credential is stored

```
kin auth status [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--base-url <base-url>` |  | Override the KinLab base URL |

### `kin remote`

Manage native and compatibility remotes

```
kin remote <subcommand>
```

Subcommands:

#### `kin remote list`

List configured and detected remotes

```
kin remote list
```

#### `kin remote add`

Add or update a configured remote

```
kin remote add <name> [options]
```

| Argument | Required | Description |
| --- | --- | --- |
| `<name>` | yes | Remote name |

| Flag | Default | Description |
| --- | --- | --- |
| `--host <host>` |  | Host kind: github or kinlab |
| `--transport <transport>` |  | Transport kind: git-export or native-kin |
| `--url <url>` |  | Optional remote URL or locator |
| `--publish-review-state` |  | Publish review state to this remote |
| `--publish-proofs` |  | Publish proofs to this remote |
| `--default` |  | Set as the default remote |

#### `kin remote plan-push`

Negotiate an exact closure and lease-protected push plan, moving nothing

```
kin remote plan-push [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--remote <remote>` |  | Remote name (defaults to the configured default native-kin remote) |
| `--url <url>` |  | Peer transfer base URL, overriding any configured remote |
| `--ref <reference>` |  | Ref to plan for (defaults to the repository default ref) |
| `--json` |  | Print the negotiated plan as JSON |

#### `kin remote lease`

Acquire a graph-aware session lease for a native Kin remote

```
kin remote lease [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--remote <remote>` |  | Remote name (defaults to configured default) |
| `--actor-id <actor-id>` |  | Override the actor ID sent to KinLab |
| `--ttl-seconds <ttl-seconds>` |  | Optional lease TTL in seconds |
| `--json` |  | Print the full lease payload as JSON |

#### `kin remote sessions`

List active hosted repo sessions for a native Kin remote

```
kin remote sessions [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--remote <remote>` |  | Remote name (defaults to configured default) |
| `--json` |  | Print the full session payload as JSON |

### `kin push`

Publish exact repository-v6 history to a native Kin remote

```
kin push [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--remote <remote>` |  | Remote name (defaults to the configured default native-kin remote) |
| `--url <url>` |  | Peer transfer base URL, overriding any configured remote |
| `--ref <reference>` |  | Ref to publish (defaults to the repository default ref) |
| `--json` |  | Print the negotiated outcome as JSON |

### `kin pull`

Admit exact repository-v6 history from a native Kin remote and move the workspace onto it

```
kin pull [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--remote <remote>` |  | Remote name (defaults to the configured default native-kin remote) |
| `--url <url>` |  | Peer transfer base URL, overriding any configured remote |
| `--ref <reference>` |  | Ref to admit (defaults to the repository default ref) |
| `--json` |  | Print the negotiated outcome as JSON |

### `kin publish`

Package and upload crate(s) to the kin-daemon registry

```
kin publish [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `-p, --package <packages>` |  | Package(s) to publish (can be repeated: -p foo -p bar). Repeatable. |
| `--registry <registry>` | `http://localhost:4219` | Registry URL (default: http://localhost:4219, or KIN_REGISTRY_URL env var) |
| `--dry-run` |  | Don't actually publish, just package and show what would be uploaded |

### `kin release`

Cross-repo release orchestration and per-repo release snapshots

```
kin release <subcommand>
```

Subcommands:

#### `kin release plan`

Read-only bottom-up release plan: which crates need publishing and which downstream pins lag a published crate.

```
kin release plan [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--offline` |  | Skip registry queries; show local versions + pins only. |

#### `kin release apply`

Propagate a published crate version into downstream Cargo.toml pins (registry = "kin"). Edits manifests locally; never commits/pushes/publishes.

```
kin release apply <crate-name> <version> [repos] [options]
```

| Argument | Required | Description |
| --- | --- | --- |
| `<crate-name>` | yes | The registry crate whose pin to bump (e.g. kin-db). |
| `<version>` | yes | The version to pin (e.g. 0.7.21). |
| `[repos]` | no | Repos to update (default: every consumer repo). |

| Flag | Default | Description |
| --- | --- | --- |
| `--no-lock` |  | Do not refresh Cargo.lock with `cargo update --precise` after editing. |

#### `kin release intent`

Release-intent gate for one repo (exit 0 = release intended / nothing to do, non-zero = staged but out of sync). For `kin`, runs the canonical scripts/release-intent.mjs gate.

```
kin release intent <repo>
```

| Argument | Required | Description |
| --- | --- | --- |
| `<repo>` | yes | Repo to gate (e.g. kin, kin-db). |

#### `kin release snapshot`

Publish a release tag and the snapshot bound to its exact repository state.

```
kin release snapshot <tag> [options]
```

| Argument | Required | Description |
| --- | --- | --- |
| `<tag>` | yes | Release tag |

| Flag | Default | Description |
| --- | --- | --- |
| `--require-proof` |  | Block release if entities lack linked passing tests |
| `--require-approval` |  | Require known-human approval for every reachable non-root change |
| `--force` |  | Force release even with low coverage |

### `kin hosted-release`

Manage hosted releases

```
kin hosted-release <subcommand>
```

Subcommands:

#### `kin hosted-release create`

Create a hosted release

```
kin hosted-release create <tag> [options]
```

| Argument | Required | Description |
| --- | --- | --- |
| `<tag>` | yes | Release tag |

| Flag | Default | Description |
| --- | --- | --- |
| `--name <name>` |  | Release name |
| `--notes <notes>` |  | Release notes |

#### `kin hosted-release list`

List hosted releases

```
kin hosted-release list
```

#### `kin hosted-release upload`

Upload an artifact to a release

```
kin hosted-release upload <release-id> <file>
```

| Argument | Required | Description |
| --- | --- | --- |
| `<release-id>` | yes | Release ID |
| `<file>` | yes | File to upload |

### `kin pipeline`

Manage CI/CD pipelines

```
kin pipeline <subcommand>
```

Subcommands:

#### `kin pipeline list`

List pipelines for the current repo

```
kin pipeline list
```

#### `kin pipeline run`

Manually trigger a pipeline

```
kin pipeline run <name>
```

| Argument | Required | Description |
| --- | --- | --- |
| `<name>` | yes | Pipeline name |

#### `kin pipeline logs`

Show logs for a pipeline run

```
kin pipeline logs <run-id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `<run-id>` | yes | Run ID |

#### `kin pipeline cancel`

Cancel a running pipeline

```
kin pipeline cancel <run-id>
```

| Argument | Required | Description |
| --- | --- | --- |
| `<run-id>` | yes | Run ID |

### `kin secret`

Manage secrets (org and repo level)

```
kin secret <subcommand>
```

Subcommands:

#### `kin secret set`

Set an org-level secret (reads value from stdin)

```
kin secret set <name>
```

| Argument | Required | Description |
| --- | --- | --- |
| `<name>` | yes | Secret name |

#### `kin secret list`

List org-level secrets

```
kin secret list
```

#### `kin secret delete`

Delete an org-level secret

```
kin secret delete <name>
```

| Argument | Required | Description |
| --- | --- | --- |
| `<name>` | yes | Secret name |

#### `kin secret set-repo`

Set a repo-level secret (reads value from stdin)

```
kin secret set-repo <name>
```

| Argument | Required | Description |
| --- | --- | --- |
| `<name>` | yes | Secret name |

#### `kin secret list-repo`

List repo-level secrets

```
kin secret list-repo
```

## Graph, store, and daemon operations

Inspecting and bounding the things Kin keeps on disk and in memory.

### `kin graph`

Inspect and validate the semantic graph

```
kin graph <subcommand>
```

Subcommands:

#### `kin graph status`

Quick health check of the semantic graph

```
kin graph status
```

#### `kin graph validate`

Structural integrity validation

```
kin graph validate
```

#### `kin graph inspect`

Look up an entity by name and show its relations

```
kin graph inspect <name> [options]
```

| Argument | Required | Description |
| --- | --- | --- |
| `<name>` | yes | Entity name or UUID to inspect |

| Flag | Default | Description |
| --- | --- | --- |
| `--json` |  | Output machine-readable JSON ({lines, error}); missing entities exit 0 with structured error. |

#### `kin graph source`

Print the exact implementation body for an entity

```
kin graph source <entity> [options]
```

| Argument | Required | Description |
| --- | --- | --- |
| `<entity>` | yes | Entity name or ID |

| Flag | Default | Description |
| --- | --- | --- |
| `--json` |  | Output machine-readable JSON |

#### `kin graph body`

Alias for source: print the exact implementation body for an entity

```
kin graph body <entity> [options]
```

| Argument | Required | Description |
| --- | --- | --- |
| `<entity>` | yes | Entity name or ID |

| Flag | Default | Description |
| --- | --- | --- |
| `--json` |  | Output machine-readable JSON |

#### `kin graph export`

Export the drawable projection of the live graph as JSON. Reads the daemon's live graph, projects it to nodes and links, and samples it server side so every consumer draws the same picture. The payload contract is `graph-export.schema.json` in `packages/boundary-contracts`; `docs/graph-feed.md` explains the sampling rule and how to pair an export with `kin graph watch`.

```
kin graph export [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--limit <n>` | `1400` | Cap the exported node count, sampled by degree with per-module quotas. `0` exports every entity |
| `--kinds <kinds>` |  | Keep only these entity kinds, comma-separated (`function,class`). Any spelling of a kind name matches |
| `--path <prefix>` |  | Keep only entities whose file starts with this repository path prefix |
| `--include <fields>` |  | Attach optional node fields, comma-separated (`signature,line`) |
| `--out <file>` |  | Write the payload to this file instead of stdout |
| `--json` |  | Print the payload instead of a one-line summary |

#### `kin graph watch`

Follow live graph changes, one event per line. Streams the daemon's graph delta events for as long as it runs. `--json` makes it NDJSON, one event object per line, ready to pipe. The frame contract is `graph-event.schema.json` in `packages/boundary-contracts`.

```
kin graph watch [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--types <types>` |  | Keep only these event types, comma-separated (`EntityChanged,RelationChanged`) |
| `--json` |  | Output NDJSON, one event object per line |

#### `kin graph viz`

Serve an interactive force-directed visualization of the semantic graph

```
kin graph viz [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--port <port>` | `4220` | Port to bind the local HTTP server to |
| `--open` |  | Open the visualization in the system default browser |

### `kin embed`

Build embeddings for the current repository's entity graph. Generates vector embeddings for all entities using a local code retriever (nomic-embed-text-v1.5, 768 dimensions; override via KIN_EMBED_MODEL_ID). Embeddings enable semantic similarity search in `kin locate` and `kin search --semantic`. Repository admission and enrichment are separate: `kin init` commits repository authority; `kin embed` adds vectors for graph-owned entities after semantic enrichment exists. The model is not bundled with any install: the first embed on a machine downloads about 523 MB of nomic-embed-text-v1.5 from huggingface.co into the Hugging Face hub cache under the home directory (`~/.cache/huggingface/hub`), and nothing embeds until that download lands. A host with no egress to huggingface.co needs that cache pre-seeded from a machine that has it, or KIN_EMBED_MODEL_ID pointed at a local model directory. `kin doctor` reports whether the model is already here. If a repo was indexed with an older model at a different dimension, pass `--rebuild` to drop the stale index and re-embed every entity at the current model's dimension.

```
kin embed [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--batch-size <batch-size>` |  | Embedding batch size (entities per inference pass). Defaults to 64, or the throughput resource plan's per-chunk budget when KIN_RESOURCE_PROFILE=throughput is set. |
| `--max-seconds <seconds>` |  | Stop after this many seconds, persist completed vectors, and leave the rest pending. |
| `--rebuild`, `--force` |  | Drop the existing vector index and re-embed every entity at the current model's dimension. Use this to migrate a repo indexed with an older model (e.g. a 384-dim index that fails against the 768-dim default). `--force` is a visible alias and appears in `kin embed --help`. |
| `--json` |  | Output JSON status instead of progress text. |

### `kin cache`

Inspect and bound the on-disk embedding cache

```
kin cache <subcommand>
```

Subcommands:

#### `kin cache status`

Report embedding-cache size, composition, and age distribution

```
kin cache status [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--json` |  | Output machine-readable JSON instead of a human summary |
| `--limit <entries>` |  | Stop scanning after this many entries and report the partial totals. Unset scans the whole cache, which on a bench-scale tree takes minutes but is the only way the totals are exact |

#### `kin cache gc`

Reclaim space: drop abandoned schema versions and/or evict oldest entries to a budget

```
kin cache gc [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--dry-run` |  | Report what would be reclaimed without deleting anything |
| `--budget-gb <gb>` |  | Evict the oldest entries until the cache fits this many gigabytes. Overrides KIN_EMBED_CACHE_BUDGET_GB; unset means no budget eviction. |
| `--prune-stale-schema` |  | Also remove every abandoned (non-current) schema-version subtree |

### `kin backup`

Backup and restore graph snapshots

```
kin backup <subcommand>
```

Subcommands:

#### `kin backup create`

Create a backup of the current graph snapshot

```
kin backup create [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `-t, --tag <tag>` |  | Optional tag to label the backup |

#### `kin backup list`

List available backups

```
kin backup list
```

#### `kin backup restore`

Restore the graph from a backup

```
kin backup restore [name] [options]
```

| Argument | Required | Description |
| --- | --- | --- |
| `[name]` | no | Backup name (partial match supported) |

| Flag | Default | Description |
| --- | --- | --- |
| `--latest` |  | Restore from the most recent backup |

#### `kin backup delete`

Delete a specific backup

```
kin backup delete <name>
```

| Argument | Required | Description |
| --- | --- | --- |
| `<name>` | yes | Backup name (partial match supported) |

### `kin resources`

Inspect host/accelerator/memory resources and per-profile budgets

```
kin resources <subcommand>
```

Subcommands:

#### `kin resources set`

Record resource knobs for this repository so they survive a daemon restart

```
kin resources set [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--profile <profile>` |  | Resource profile the daemon adopts at its next start: proof, interactive, throughput, or ci |
| `--embed-batch-size <n>` |  | Batch size for the daemon's background embedding queue |
| `--clear` |  | Remove the recorded knobs and go back to the built-in defaults |

The knobs land in this repository's `.kin/config.toml` under `[resources]`, and
the daemon reads them at startup, so a batch size set to survive an OOM is still
in force on the restart that OOM causes. An operator's own `KIN_RESOURCE_PROFILE`
or `KIN_DAEMON_EMBED_BATCH_SIZE` still outranks the file. A running daemon keeps
the values it started with; stop it, or let it idle out, for the new ones to
take effect.

#### `kin resources inspect`

Report the detected resource plan and live daemon embedding state

```
kin resources inspect [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--json` |  | Output the stable JSON resource plan instead of a human summary |
| `--profile <profile>` |  | Resource profile to plan for: proof, interactive, throughput, or ci |

With no `--profile`, the plan reported is the one the inspected daemon is
actually running under, and the `Profile selector` line names where that came
from: an operator's environment, this repository's config, or kin's own default.
A selector value the runtime cannot act on is reported as `REJECTED` with the
reason, rather than silently replaced by the default.

### `kin support`

Show graph observability

```
kin support [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--json` |  | Output machine-readable JSON for editor integrations |

### `kin daemon`

Inspect Kin daemons, stop them gracefully, or ask one to enrich

```
kin daemon <subcommand>
```

Subcommands:

#### `kin daemon status`

Show the supervisor and every repo worker daemon, with stale-file detection

```
kin daemon status [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--json` |  | Emit machine-readable JSON |

#### `kin daemon stop`

Gracefully stop the current repo's worker daemon (or every daemon with --all)

```
kin daemon stop [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--all` |  | Stop every worker daemon under this KIN_HOME, then the supervisor  The supervisor is machine-wide, so it can hold daemons from other managed homes. Those are skipped and named rather than stopped, and the supervisor itself is left running while any of them remain. Use --machine to stop every daemon on the box regardless of home. |
| `--machine` |  | Widen --all to every daemon on this machine, whatever KIN_HOME it runs under |
| `--json` |  | Emit machine-readable JSON |

#### `kin daemon sweep`

Ask this repository's daemon for a language-server enrichment sweep

```
kin daemon sweep [options]
```

The sweep derives the cross-file reference, override and type-use edges a single-file parse cannot, and it skips files the graph already holds server evidence for. `kin init` runs one and every daemon start queues one, so this is the surface for the case those did not finish: a sweep killed with its daemon, a store converted before a language server was installed, or a repository whose sweeps the daemon has stopped queueing because the last three all died without enriching anything. It prints the daemon's own answer, waits for the sweep by default, and fails loudly when no daemon answers or when the daemon has no language server to enrich with.

| Flag | Default | Description |
| --- | --- | --- |
| `--no-wait` |  | Return as soon as the sweep is queued, instead of waiting for it |
| `--json` |  | Emit machine-readable JSON |

### `kin registry`

Show or manage the global Kin repository registry

```
kin registry [<subcommand>]
```

Run `kin registry` with no subcommand for the default behavior above, or one of:

#### `kin registry authority`

Verify local registry authority without reading its contents

```
kin registry authority [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--json` |  | Emit machine-readable JSON |
| `--fix` |  | Explicitly repair mode bits on structurally safe authority files |
| `--initialize` |  | Create missing private authority files without replacing existing data |

#### `kin registry daemons`

Show repo daemons registered with the central local supervisor

```
kin registry daemons [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--json` |  | Emit machine-readable JSON |

#### `kin registry clean`

Remove stale entries (paths that no longer contain .kin/)

```
kin registry clean
```

### `kin telemetry`

Manage local telemetry consent and the spool

```
kin telemetry <subcommand>
```

Subcommands:

#### `kin telemetry status`

Show consent status and spool statistics

```
kin telemetry status
```

#### `kin telemetry consent`

Record consent to local telemetry collection

```
kin telemetry consent
```

#### `kin telemetry revoke`

Revoke telemetry consent

```
kin telemetry revoke
```

#### `kin telemetry purge`

Delete all spooled telemetry data

```
kin telemetry purge
```

### `kin notify`

Send a user-facing notification through Kin's own identity

```
kin notify [<subcommand>] [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--title <title>` |  | Notification title |
| `--body <body>` |  | Notification body |
| `--level <level>` | `info` | Urgency: info (silent), warn (silent), or urgent (sound, breaks through Focus) |
| `--key <key>` |  | Suppression and replacement identity; reposting under the same key replaces the previous notification instead of stacking another |
| `--cooldown <cooldown>` |  | With --key: re-notify only after this many seconds have passed |
| `--latch` |  | With --key: notify once, then stay quiet until `kin notify clear` |
| `--json` |  | Emit the outcome as JSON |

Run `kin notify` with no subcommand for the default behavior above, or one of:

#### `kin notify clear`

Release a latch or cooldown so the next send is delivered

```
kin notify clear <key> [options]
```

| Argument | Required | Description |
| --- | --- | --- |
| `<key>` | yes | The suppression key to forget |

| Flag | Default | Description |
| --- | --- | --- |
| `--json` |  | Emit the result as JSON |

#### `kin notify status`

Report which backend would deliver and what is currently held back

```
kin notify status [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--json` |  | Emit the report as JSON |

### `kin bench`

Run benchmarks (delegates to kin-bench binary)

```
kin bench [-- <args>...]
```

| Argument | Required | Description |
| --- | --- | --- |
| `[-- <args>...]` | no | Arguments to forward to kin-bench |

## Install and health

First-run setup, readiness, and keeping the install current.

### `kin capabilities`

Show which Git-replacement commands are ready on repository-v6

```
kin capabilities [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--json` |  | Output the versioned capability inventory as JSON |
| `--verbose` |  | Add the per-command notes under each matrix row. Conflicts with `--json`. |

### `kin setup`

First-time setup and health checks for the Kin system

```
kin setup [<subcommand>] [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--intent <intent>` |  | First-run intent: local, agent, editor, hosted, or advanced |
| `--mode <mode>` |  | Repository mode: native or compatibility |
| `--shell <shell>` |  | Shell to configure: zsh, bash, or powershell |
| `--auto-daemon` |  | Auto-start kin-daemon when entering workspaces |
| `--no-interactive` |  | Run non-interactively using defaults or provided flags |
| `--skip-mcp-check` |  | Skip the MCP round trip that proves each configured AI client can actually call Kin (for a scripted install with no repository yet) |
| `--check` |  | Skip the wizard and only run the first-run health check |

Run `kin setup` with no subcommand for the default behavior above, or one of:

#### `kin setup status`

Show what's installed

```
kin setup status [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--json` |  | Emit the machine-readable health report as JSON |

#### `kin setup doctor`

Quick health check

```
kin setup doctor [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--fix` |  | Apply safe automatic repairs (shell hook, MCP configs, config dirs) |
| `--json` |  | Emit the machine-readable health report as JSON |

#### `kin setup ledger`

Show the install ledger and verify it against disk

```
kin setup ledger [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--json` |  | Emit the ledger + verification as JSON |

#### `kin setup uninstall`

Remove exactly what `kin setup` recorded (ledger-verified)

```
kin setup uninstall [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--all` |  | Remove the complete managed install after ledger cleanup (Windows retains an inert authority sidecar) |
| `--dry-run` |  | Show what would be removed without changing anything |
| `--force` |  | Also remove entries modified since install (never done by default) |
| `--json` |  | Emit the per-artifact outcomes as JSON |

### `kin doctor`

Probe first-run health and optionally apply safe repairs

```
kin doctor [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--fix` |  | Apply safe automatic repairs (shell hook, MCP configs, config dirs) |
| `--json` |  | Emit the machine-readable health report as JSON |
| `--drift` |  | Compare an explicit projection observation with graph truth |
| `--heal` |  | Rematerialize the derived projection from graph truth, DISCARDING uncommitted changes to tracked files that diverge from it |

Two rows cover filesystem projection and they answer different questions.
`VFS projection` says whether projection is installed on this machine.
`Projection in force` says whether the file you just edited went through the
graph, reading `mode/mounted/readable/writable/degraded` from a probe that runs
rather than from a configuration file. A machine can pass the first and fail the
second: a container where the loader strips the injected shim has an intact
install and every process reading raw disk.

### `kin vfs`

Engage, disengage, or report the filesystem projection for this repository.

The graph is the authority. A projection is how that truth reaches your tools as
ordinary files, and Kin has four: the injected shim, an NFS mount, a FUSE mount,
and Windows ProjFS. Kin prefers a mount where one is available, because the
kernel serves it and no process can have it stripped. macOS and Linux fall back
to the shim; Windows has no shim and leads with ProjFS, which ships on every
SKU. See [Filesystem projection](projection.md) for the full order and the
per-platform table of what each mode needs.

```
kin vfs on [--mode <shim|nfs|fuse|projfs>]
kin vfs off
kin vfs status [--json]
```

| Subcommand | Description |
| --- | --- |
| `on` | Engage the projection for this repository. `--mode` forces one; without it Kin uses the recorded mode, or picks by the fallback order. A mode that cannot run here falls back with a message naming what is missing and the exact line that installs or enables it, and never reports a mount that is not running. |
| `off` | Disengage the projection. An NFS mount admits whatever is staged through it before unmounting, so turning the projection off strands nothing. The shim is injected per process, so it cannot be withdrawn from a running shell; the command says so and names `KIN_VFS_DISABLE=1`. ProjFS is a Windows feature rather than a process Kin starts, so there is nothing to stop. |
| `status` | Print each mode's live probe result and what is in force, as `mode/mounted/readable/writable/degraded`. |

### `kin update`

Update Kin to the latest release

```
kin update [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--skip-verify` |  | Skip SHA-256 checksum verification (NOT recommended). Conflicts with `--check-only`. |
| `--channel <channel>` |  | Release channel: `stable` (default) or `alpha` (latest pre-release, unstable). A mutating update saves the choice; check-only never writes it. |
| `--expect-version <semver>` |  | Require the selected release to have this exact SemVer. This selects a release; it does not authenticate archive bytes. Automation must provide the complete pinned expectation tuple. Conflicts with `--ack-restart`. |
| `--expect-sha <40hex>` |  | Require the selected release tag to peel to this exact Kin commit. This selects the tag source; it does not authenticate archive bytes. Conflicts with `--ack-restart`. |
| `--expect-archive-sha256 <64hex>` |  | Require the downloaded platform archive to match this exact SHA-256. Supply it only after external cryptographic attestation verification pins firelock-ai/kin, release.yml, the release tag, and source commit. Conflicts with `--ack-restart`. |
| `--check-only` |  | Check whether an update is available without downloading or installing it. |
| `--json` |  | Emit the check-only result as JSON. |
| `--ack-restart` |  | Verify the durable restart fence and exact installed binary identities for the release awaiting acknowledgement. Legacy markers may additionally require explicit replacement-session evidence. |
| `--runtime-session <kind=pid>` |  | Legacy-marker live replacement proof: `daemon=PID`, `mcp=PID`, or `vfs=PID`. New stop-before-update markers reject these arguments and require no replacement session evidence. Repeatable. |
| `--set-policy <policy>` |  | Set how an available update should reach this machine and exit. `auto` (the default) installs unattended through the gated executor: it waits for a moment with no managed Kin process or agent session, defers at most a bounded window, and runs the full stop-install-acknowledge chain. `prompt` notifies with the remedy attached and waits to be told. `manual` never notifies; checks still run. |
| `--apply` |  | Bring this machine current in one gesture: install the release, acknowledge the restart fence, and repair agent configs, in that order. This is what the update notification's button runs. |
| `--dry-run` |  | With --apply: print the ordered steps and change nothing. |
| `--unattended` |  | Run the unattended executor (what the update watchdog invokes on a stale install with policy auto): evaluate the machine-activity gates, and on proceed stop every managed Kin process cooperatively and run the full --apply chain. Blocked runs persist a deferral clock instead of installing. The final stdout line is one JSON record (also appended to ~/.kin/update-ledger.jsonl) carrying the decision, reason, blocked_seconds, and window_seconds. |
| `--force-window` |  | With --unattended: apply despite the activity gates. For the watchdog once a deferred record shows blocked_seconds >= window_seconds (24h). Never overrides a recorded prompt or manual policy, only the executor's own activity gates. |

### `kin completions`

Generate shell completions for bash, zsh, or fish

```
kin completions <shell>
```

| Argument | Required | Description |
| --- | --- | --- |
| `<shell>` | yes | Shell to generate completions for |

