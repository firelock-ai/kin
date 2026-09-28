# Kin CLI reference

Every command `kin` exposes, with its real arguments, flags, and defaults. The page is written from the clap definitions in `crates/kin-cli/src/main.rs`, so a flag listed here is a flag the binary parses. Run `kin <command> --help` for the same text from your installed build, and `kin --version` to see which build that is.

Kin is pre-1.0 and the command surface moves. Where this page and your build disagree, `--help` and `kin capabilities` are authoritative.

## Reading this page

Descriptions are the command's own help text. A `--json` flag switches that command to machine-readable output. Angle brackets mark a required argument, square brackets an optional one, and a trailing `...` an argument that takes the rest of the line.

87 commands are documented below. 5 further commands (`bench-meta`, `contextbench-locate`, `prepared-state`, `revert`, `semantic-only-guard`) are hidden from `kin --help` because they are not part of the supported surface. `revert` specifically refuses on purpose and names `rollback` instead, so typing it out of Git habit gets that explanation rather than a real command.

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
- [Ask the graph](#ask-the-graph): `locate`, `search`, `trace`, `path`, `impact`, `refs`, `context`, `source`
- [More graph queries](#more-graph-queries): `history`, `blame`, `overview`, `deps`, `xref`, `dead-code`, `trace-data-flow`, `security`, `languages`, `scope`, `locate-debug`
- [Branches, merges, and exact trees](#branches-merges-and-exact-trees): `branch`, `checkout`, `merge`, `conflicts`, `resolve`, `stash`, `rollback`, `tag`, `semver`, `purge-ignored`, `admit`, `reconcile`, `migrate`, `eject`, `git`
- [Review and verification](#review-and-verification): `review`, `approvals`, `verify`, `spec`, `audit`, `rename`
- [Sessions and agents](#sessions-and-agents): `agent`, `exec`, `shell`, `open`, `with`, `mcp`, `describe`, `call`, `assistant`, `intent`, `traffic`, `work`, `note`, `todo`, `feature`
- [Remotes and publishing](#remotes-and-publishing): `auth`, `remote`, `push`, `pull`, `publish`, `release`, `hosted-release`, `pipeline`, `secret`
- [Graph, store, and daemon operations](#graph-store-and-daemon-operations): `graph`, `embed`, `cache`, `backup`, `resources`, `support`, `daemon`, `registry`, `telemetry`, `notify`, `bench`
- [Install and health](#install-and-health): `capabilities`, `setup`, `doctor`, `vfs`, `update`, `upgrade`, `completions`

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
| `--no-enrich` |  | Skip the cross-file enrichment phase |
| `--verbose` |  | Print the full record: every admission stage, the ids and the enrichment detail |

On a terminal, `kin init` prints one live line per phase and a short result: rows for reading
history, linking and the search index, what is not linked yet and why, and a `kin refs` command
on a function from the graph. A pipe, CI and `--verbose` print the full record instead, unchanged,
and `--json` prints its one document.

When `kin setup` recorded that Kin may install language servers, `kin init` installs the ones this
repository's languages need before it links. Without that answer it installs nothing, and names
`kin doctor --fix --install-language-servers`.

A second `kin init` in a repository this build can open says so and exits 0. Over a store this
build cannot open it still refuses and exits 1, as does `--json`.

`kin init` stages its conversion beside the repository and publishes `.kin` into the repository
root, so it first checks that it can create entries in both. When either directory is not writable
by the current user, as with `/workspaces` or `/app` in many containers, it refuses before any work
and names the directory.

Before it captures anything, `kin init` counts the repository's commits and tracked files,
forecasts what converting that much history holds in memory, and compares the forecast to the
memory this machine or container allows. A conversion forecast well past that limit is refused
there, in one sentence, with the numbers and what to do about it, rather than being killed by the
kernel a minute later with no message at all. One forecast to spare and it says what it expects to
hold and carries on; comfortably inside it and it says nothing. The forecast is a floor taken from
measured conversions, so it understates rather than overstates, and it is a statement about memory
and never about time.

That forecast counts the history HEAD reaches, and a conversion captures every branch, tag and
other ref under `refs/`. So once it has planned what it captured, and before it derives any
semantic history, `kin init` projects that plan against the memory still free and refuses when the
projection is larger. The capture is removed as it stops and nothing is written. A clone carrying
many refs is the usual cause, and one made with `git clone --single-branch --no-tags` carries only
the history you need.

Set `KIN_INIT_MEMORY_CEILING_BYTES` to a byte count when Kin reads your machine's ceiling wrongly,
or when you have judged the forecast wrong for your repository and want to convert anyway. It
moves both checks, and the one after planning judges the ceiling less the memory already in use. A
value that is not a positive whole number is refused rather than ignored, because a ceiling nobody
set is how a conversion gets killed with no warning.

It checks disk the same way. A conversion holds every file version reachable from HEAD twice while
it runs, uncompressed, so `kin init` refuses before any work when the filesystem it stages on has
less free than that. When free space clears that and is still under what stores measured on current
releases came to, it says so in one line and carries on (`docs/store-size.md` records those
measurements). Set `KIN_INIT_DISK_FREE_BYTES` to judge against a different free-space figure, for
example on a filesystem that compresses what it stores.

Exit codes: `0` when the conversion finished and nothing died, and `7` when it produced a store but
a daemon serving that store was killed during the run, which leaves the semantic enrichment
unattested. `7` is not a failure. The store is real and answers questions; what nobody can attest is
that its enrichment finished, and the summary says the same thing in words. A scripted or
agent-driven setup should branch on it rather than treating the run as done.

After admission, `kin init` runs a cross-file enrichment phase: a daemon asks a language server for
the reference, override and type-use edges a single-file parse cannot derive. `kin init --json`
reports what that phase did under `cross_file_enrichment`, and the exit code does not change with
it:

- `state`: `produced` when a sweep finished, enriched files and owes none, `owed` when the graph
  handed over lacks some or all of those edges, and `unknown` when the run could not read what its
  sweep did.
- `reason`: why, as one of the stable codes below. Absent when `state` is `produced`.
- `detail`: the sentence the human summary prints, naming what is missing and what supplies it.
- `cause`: the error or observation behind `reason`, when there was one.
- `elapsed_ms`: how long the phase took.

| `reason` | What happened |
| --- | --- |
| `not_requested` | `--no-enrich` skipped the sweep. |
| `daemon_spawn_disabled` | `KIN_NO_DAEMON` is set, so no daemon could be started to run the sweep. |
| `loopback_blocked` | The operating system refuses this process every loopback connection, as a sandbox or seccomp filter that denies `connect()` does, so no daemon it started could be reached. |
| `daemon_unavailable` | No daemon could be started or reached for another reason. `cause` says which. |
| `store_unreadable` | The store `kin init` wrote could not be opened as a Kin layout. |
| `sweep_not_started` | A daemon answered and would not queue the sweep. |
| `language_server_unavailable` | The daemon has no usable language server for this repository. |
| `sweep_enriched_nothing` | The sweep walked files and enriched none of them. |
| `sweep_languages_unserved` | The sweep could not serve at least one language. `cause` names each one. |
| `sweep_files_owed` | The language server left questions about some files unanswered, for example because it stopped partway through. Those files are owed: the next sweep after a backoff asks again, and `kin daemon sweep` asks at once. `cause` names the first one and why. |
| `sweep_budget_spent` | The sweep did not finish in the 900 seconds `kin init` waits. The daemon keeps sweeping, publishes the rest when it finishes, and then exits; `kin daemon sweep` waits for it. |
| `sweep_outcome_unreadable` | The run could not read what its sweep did (`state` is `unknown`). |

`daemon_spawn_disabled` and `loopback_blocked` are decided before anything is started, so the phase
returns at once instead of waiting on a daemon that cannot run the sweep. In every `owed` case
`detail` names what supplies the missing edges, and `kin daemon sweep` runs the sweep on demand.

### `kin clone`

Clone a repository

A hosted locator such as `kinlab://<org>/<repository-id>` carries its repository identity with it. A plain peer daemon HTTP endpoint does not, so `--repository` supplies the identity to adopt there. A Git clone URL takes neither, and passing `--repository` with one is refused before any negotiation rather than failing later against a remote that was never a Kin peer.

```
kin clone <url> [path] [options]
```

| Argument | Required | Description |
| --- | --- | --- |
| `<url>` | yes | Native Kin locator or Git repository URL |
| `[path]` | no | Target directory (defaults to repo name) |

| Flag | Default | Description |
| --- | --- | --- |
| `--repository <repository>` |  | Native repository identity when URL is a peer daemon HTTP endpoint |
| `--verbose` |  | Print the full record: Git's own progress, every admission stage, the ids and the enrichment detail |

Over Git transport, `kin clone` runs everything `kin init` runs after admission: `.kin/` goes into
`.git/info/exclude`, the repository joins the registry, the language servers it needs are installed
when `kin setup` recorded consent, and the cross-file linking phase and the first embedding pass run
within `kin init`'s budget. It exits 7 and 8 for what `kin init` exits them for, and it prints the
same short form on a terminal.

### `kin status`

Show coherent repository-v6 workspace status

```
kin status [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--json` |  | Output machine-readable JSON for editor integrations |
| `--wait-quiesce <seconds>` | `0` | Seconds to keep re-reading while embedding coverage is only momentarily unobservable, such as an embedding pass or a graph mutation batch spanning the sample. Never waits on a coverage that was observed, nor on an absence a re-read cannot clear. 0 reads once |
| `--verbose` |  | Print the full record: ids, generations, the working copy's basis, the store and the daemon |

On a terminal `kin status` prints a short page: the graph, whether the working copy matches it, the
search index, every warning the full record raises, and `kin status --verbose` for the rest. A pipe,
CI, `--json` and `--verbose` print the full record, unchanged, and the exit code is the same either
way.

Exit 9 means nothing admitted the working copy, so no count in the report describes the files on disk. It is not a failure: every line is still true about durable authority, and the reading is printed either way. It happens when no daemon is holding the repository, because neither command starts one, and `kin admit` is what takes the working copy. The banner at the top of the output says the same thing, and the exit code is the only place the `--json` form can carry it.

### `kin commit`

Create an exact semantic and artifact commit

The commit lands in Kin's own authority, not in Git. Nothing is written to `.git`, so `git status` still lists every file this commit recorded and `git log` does not move. That is the design rather than a gap: Kin holds the change, and `kin log`, `kin diff` and `kin review` read it. Hand it back to Git when you want it there, with `kin eject` for the working tree or a push to a Kin remote. Until then, tools that read Git, including CI, hooks and reviewers, see an unchanged repository with a dirty tree. `kin commit` prints the same fact after every commit:

> Recorded in Kin authority, not in git. `git status` stays dirty until you run `kin eject` or push this branch to a Kin remote.

`kin commit --amend` replaces the current change with the full working state and keeps that change's parents. The message is kept unless `-m` supplies a new one. The replaced change stays immutable in history with its author, and the amend is recorded as the caller's operation. An amend is refused while a merge is open and when the selected head moved since it was read. A detached workspace amends only its own workspace and moves no ref. A plain `kin commit` with nothing to record still refuses as before.

```
kin commit [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `-m, --message <message>` |  | Commit message; amend preserves the existing message when omitted |
| `--amend` |  | Replace the current change with the full working state, preserving its parents |
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

Exit 9 means the same thing here as it does for `kin status`, and only a workspace endpoint can produce it. A diff between two changes reads durable authority on both sides, needs no admission, and exits 0 with or without a daemon.

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
| `--surface <shape>` | `full` | Which JSON shape `--json` emits. `full` is every field, the schema `POST /locate` and the MCP `semantic_locate` tool share. `compact` is the agent surface: per hit `id` (or `artifact`, its repo-relative path, on a hit for a tracked file the parsers produced no entities for), `name`, `kind`, `file`, `line`, `signature`, `score` and `matched`, plus `collapsed_rows` on a Go package's module row when the ranking folded that package's other files into it (at least that many rows were folded), plus the ranked file paths, `total_ranked`, `next_cursor`, `all_fallback`, a `ranked_by` clause and a `_kin` object carrying `embedding_state` with its counts. Refused with `--diagnose`, which needs the full payload. |

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

A name resolves in tiers. An exact whole name comes first and is never pooled with anything else:
`get` means a function named `get` when one exists. Only when no entity is named it exactly does a
bare member name reach the members that carry it. The graph names a member by its owner,
`Scaffold.get` in Python and `Router::route` in Rust, and the member kinds are methods, fields and
enum variants, so `get` reaches the method `Scaffold.get` but not `get_json`, `__get__`, or a
module named `app.get`. When one owner carries the member, the name answers for it. When several
do, the command lists every candidate with its owner-qualified name, file and id, never a line
number, and answers about none of them, so you choose. `kin refs` answers for each of them in turn
instead, the way `find_references` does over MCP. The rule is the same one `get_entity_source`,
`trace_data_flow`, `trace_path` and `get_context_pack` apply, so the CLI and MCP reach the same
candidates for the same name.

`kin graph source` reads a body, so it answers only a name that names one entity: one exact name,
or one owner's member when nothing is named exactly. Several same-named entities, several owners'
members and a partial name each list their candidates and read nothing, exactly as
`get_entity_source` does over MCP. A long list names every candidate past the first 25 by id, and
past 200 says how many it left out.

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

A call the focal makes into a symbol outside the repository, such as `Array.map` in TypeScript's
own library, is a leaf row under `--- External calls ---`, or under `--- Deps ---` with
`--compact`. The row is the line `kin context` prints for the call, ending in `leaf`: the graph
holds the symbol's identity and no body or edges, so nothing past it can be followed, which is
also where `trace_data_flow` stops. A focal whose calls all leave the repository still reaches
something, so the trace does not qualify it as an absence.

```
[Calls ->] Array.map (external symbol, npm typescript 5.6.3, standard library) proven_external by lsp:tsserver 5.6.3 (lsp_definition), sites +2 `map`, +5 `map`, id external_reference:<uuid>, leaf
```

Given an `external_reference:<uuid>` id, or its bare uuid, `kin trace` and `kin trace --json`
refuse: the message names the symbol and gives `kin refs <id>` as the command that lists its
callers. An `external_reference` id this repository's graph holds no symbol under is refused as
that, not as a missing entity.

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

An end given as an `external_reference:<uuid>` id, or its bare uuid, names a symbol outside the repository, which has no route of its own here. `kin path` refuses it as a request that names the wrong kind of end, with the symbol named and `kin refs <id>` given as the command that lists its callers, and a route to one of those callers ends one call short of it. An `external_reference` id the graph holds no symbol under is reported as an end that did not resolve.

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

An `external_reference:<uuid>` id, or its bare uuid, names a symbol outside the
repository, which has no dependents of its own here to walk. `kin impact`
refuses it with resolution `external_symbol`, names the symbol, and gives
`kin refs <id>` as the command that lists the entities a change to it reaches.
An `external_reference` id this repository's graph holds no symbol under is
reported with resolution `not_found`.

### `kin refs`

Show upstream callers/importers/references for an entity

```
kin refs [entity] [options]
```

| Argument | Required | Description |
| --- | --- | --- |
| `[entity]` | no | Entity name or ID. Required unless --bulk-json + --entities is provided. A name with twins can carry its pin: `Name@file`, `Name@file:line`, `Name#kind` |

| Flag | Default | Description |
| --- | --- | --- |
| `--kind <kind>` | `all` | Filter relation kinds: all, calls, imports, or references (or Any for bulk mode) |
| `--file <file>` |  | Exact repo-relative file of the entity, when its name has twins |
| `--entity-kind <kind>` |  | Exact entity kind (for example: function or method), when its name has twins. `--kind` filters relation kinds here, so the entity's own kind takes this flag |
| `--bulk-json` |  | Bulk mode: classify many entities by reachability in one daemon call. Outputs JSON to stdout. Requires --entities. |
| `--entities <entities>` |  | Comma-separated entity UUIDs for --bulk-json. Required when --bulk-json is set. |
| `--compact` |  | If true (default) emit compact bulk-mode rows ({entity_id, has_references, reference_count, receiver_name_candidate_count, unconfirmed_candidate_count}). A row holding an unconfirmed candidate caller reads `reference_count` null beside `known_reference_count`, and `has_references` null unless a caller is confirmed. Set --no-compact for verbose rows with name/kind/file_path/matched_kinds. |
| `--no-compact` |  | Force verbose bulk-mode rows (overrides --compact). Required for clap to accept `--no-compact`. |
| `--all` |  | List every caller in full, each with its id and projection, instead of the first 20 sized to the terminal. Output that is not a terminal is always complete |
| `--json` |  | Print the complete answer as JSON: its lines, the absence verdict and the call-site block |
| `--max-chars <n>` |  | With `--json`, return a frozen semantic page bounded to 2000–60000 bytes; incompatible with `--all` and `--bulk-json` |
| `--cursor <cursor>` |  | With `--json`, continue the prior bounded answer using its `next_cursor` and the same entity and relation filters |

For a bounded response, run `kin refs <entity> --json --max-chars 12000`, then repeat
with `--cursor '<next_cursor>'` until `next_cursor` is null. These JSON pages use the
same transport as MCP `find_references`: collect `readings` by their keys, then
attach the accumulated collection rows at their dotted addresses (for example
`call_sites.candidates`). Concatenate `record_fragment` UTF-8 fragments before
interpreting that semantic record. The byte budget can change between pages. A
page's absence reading remains qualified until the complete answer is reconstructed;
finishing the pages does not clear any semantic uncertainty in that answer. A changed
graph, source scope or writer epoch, or an expired/evicted cursor, requires a fresh
query. Normal `kin refs --json` retains its complete CLI answer shape.


A bare name that several entities share resolves through the ranking every read
command shares, and the answer lists the others and says it chose. `--file` and
`--entity-kind` pin which one you meant, and they are the same pin `kin impact`
takes as `--file` and `--kind`, spelled apart here because `kin refs --kind`
already filters relation kinds. The entity kind is spelled the way the answer's
own candidate rows spell it, lowercase, so a pair copied out of a note is a pair
the filter compares.

```
kin refs render --file src/panel.rs --entity-kind function
```

A name no entity in the repository carries can name a symbol outside it, and
`kin refs` reads it the way `find_references` reads its `query`: exactly, by the
name a reader writes (`Array.map`), by its SCIP descriptor chain, or by its whole
SCIP symbol. The answer is the one its `external_reference:<uuid>` address gets,
led by a line saying what the name named and which spelling matched. A name
several such symbols share, one per package version the resolver loaded, lists
each by its address and answers about none of them.

A pinned answer says so on the line under the header, naming the pin, the
definition it selected and how many entities the name reaches, because the
candidate note goes quiet exactly when a pin worked. A pin that excludes every
entity the name reaches reports the pin miss and lists what the name alone does
reach, rather than reporting the entity absent.

The count the answer leads with holds the references the graph can stand behind.
A row whose only edge is a bare name match, with nothing at the site settling
which entity the name means, is held out of that count and listed under its own
heading with its own number, beside the receiver-name candidates held out for the
same reason. A local variable or a parameter sharing a function's name produces
exactly that row, and counting those is how one Go function with one caller came
back as seventeen referencing entities. A call is never held out on its
resolution alone: a call site is evidence of use even when the destination was
picked by name, and holding those out would understate a function that is
genuinely called.

Every row ends with its resolution tier, and the answer states once what the
tiers mean whenever a row carries one weaker than proven. `type_resolved` means
the destination entity itself is proven, `import_scoped` means an import singled
out the scope the name was selected in, and `name_only` means the name matched
and nothing at the site settles the destination. A reader working through an
agent has no grep to check a row against, so the tier is the whole of what it
has.

A row names its caller by the caller's id, then the file the caller is
projected into, labelled `projection:` because it is a projection and not an
address. Each site is written `+N`, N lines below the caller's first line, the
offset a numbered body shows, followed by the text at the site cut from the
caller's own body. A call's argument list is left out of that text, so it names
what is called. A site whose text cannot be read is written `+N` alone, and one
that cannot be placed inside its caller is written `+?` with the reason. No row carries a file line, and
the header names the entity the same way. The rows and their sites are the ones
the `find_references` MCP tool returns, and the answer says once what a site's
`+N` means.

```
kin refs get_dependant --kind calls --all
References to 'get_dependant' -> get_dependant (Function) [<id>] (projection: fastapi/dependencies/utils.py)
Call sites in files that import utils.py: 957 across 73 callers.
  Every one of them is accounted for.
referenced by 4 entities:
  solve_dependencies [<id>] (projection: fastapi/dependencies/utils.py) [Calls] (type_resolved) sites +43 `get_dependant`
```

Every answer leads with what qualifies it: the header, then the call-site
summary, every clause that leaves it unsettled, and the unproven call sites
that could still be calls to the entity, the ones that name it listed first,
before any caller. That holds for `--all`, for `--json`'s `lines` and for
output that is not a terminal, as well as at a terminal.

At a terminal the answer is laid out for a person reading it. After that
disclosure, the callers follow, grouped under the
file each is projected into, one row each with the name first and then each
site as `+N` and the text there. A row shows a tag only when it is not a
proven call, such as its resolution tier, `imports` or `references`. The
terminal rows leave out each caller's id; `--all` prints it. At most 20
callers are listed, and a line such as `and 49 more; --all or --json for the
full list` counts the rest. Every line fits the terminal's width, 80 columns
when the width cannot be read: a name or a site's text too long for its room
is cut with an ellipsis, and prose wraps between words. `--all`, `--json` and
output that is not a terminal get the complete answer, with every caller's id
and projection.

```
kin refs get_dependant --kind calls
References to 'get_dependant' -> get_dependant (Function)
  [<id>] (projection: fastapi/dependencies/utils.py)
Call sites in files that import utils.py: 957 across 73 callers.
  Every one of them is accounted for.
referenced by 4 entities:
  (projection: fastapi/dependencies/utils.py)
    get_parameterless_sub_dependant  +7 get_dependant
    solve_dependencies               +43 get_dependant
  (projection: fastapi/routing.py)
    APIRoute.__init__                +137 get_dependant
    APIWebSocketRoute.__init__       +14 get_dependant
```

A symbol outside the repository, such as `Array.map` in TypeScript's own
library, is named by the `external_reference:<uuid>` id that `kin context`,
`kin trace` and the MCP tools print for it, or by its bare uuid. `kin refs`
then lists the entities in this repository that call it. The first line names
the symbol, its package and version, and whether it is a standard library.
Each row is one caller, named by its id and the file it is projected into: the
relation, its resolution tier, its sites and the proof, which names the language
server and version that proved the call. A site is written `+N`, N lines below
the caller's first line, the offset a numbered body shows, with the text at it.
The graph records no location for the external declaration, so none is printed
for it. Only calls a language server
proved are recorded, so the list is a floor, and the answer says so. The rows
are the ones `find_references` returns for the same id.

```
kin refs external_reference:<uuid>
References to 'external_reference:<uuid>' -> Array.map (external symbol, npm typescript 5.6.3, standard library)
referenced by 1 entity:
  render [<id>] (projection: src/app.ts) [Calls] (type_resolved) sites +2 `map`, +5 `map` proven_external by lsp:tsserver 5.6.3 (lsp_definition)
```

An `external_reference` id this repository's graph holds no symbol under is
refused as that, not as a missing entity. `--bulk-json` classifies repository
entities, so an external id there is an error row with `error:
"external_symbol_not_served"`, the `symbol` record `kin refs` names, and a
`detail` naming the symbol and the `kin refs` command that lists its callers.
The `bulk_check_references` MCP tool gives it the same row.

`kin refs` lists incoming references only, so an entity's own calls out of the
repository are listed by `kin context` and `kin trace` instead.

Every answer about a repository entity ends with the call sites of the callers
in the files that import the entity's file, the block the `find_references`
MCP tool serves as `call_sites` over the same files, said in plain words. It
counts the callers read and the sites their ledgers hold, then says what is
still open, one line for each kind, or that every site is accounted for. A
caller still being linked whose whole body never spells the entity's name
cannot call it by name, so it is left out of the count and a line says how
many were. A
caller no ledger describes yet is still being linked while a resolver for its
language can still prove its sites, and the answer names `kin daemon sweep`,
which finishes that now. A site the resolver left unresolved, failed at, found
outside any build or read as a value binding keeps its own count, because a
caller of the entity may be among those sites. When no resolver can prove a
caller's sites on this host now, because the daemon runs with language-server
enrichment switched off, no language server serves the language, or the one
that does cannot start, the caller is counted as one that can't be linked on
this machine, with why for each language. Waiting does not settle those;
installing the server does, once the next sweep runs. The daemon's JSON carries
the block under `call_sites`, with the verdict codes, such as
`call_sites_owed`, that a program reads.

```
Call sites in files that import storage.py: 12 across 5 callers.
  Still linking 1 of the 5 callers, so this answer may be missing calls from it.
  Run `kin daemon sweep` to finish linking now.
```

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

A pack lists the calls its focals make into symbols outside the repository
that a language server proved, such as `Array.map` in TypeScript's own
library, under `--- External calls ---` after the pack. Each line names the
symbol, its package and version, whether it is a standard library, the proof,
the sites as `+N` offsets inside the focal with the text at each one, and the
`external_reference:<uuid>` id that `kin refs` takes to list the symbol's
callers. A pack built from several focals starts each line with the focal
that makes the call. The header counts them on an `External calls` line when
there are any. `--json` carries the same rows under `external_calls`, in the
shape `get_context_pack` serves, with `dependency_selection.external_calls_returned`
and, for several focals, the calling focal's id in `caller_id`. The rows sit
beside the pack rather than inside the part fitted to `--budget`, at most 50
of them, and `measured_tokens` counts them.

Given an `external_reference:<uuid>` id, or its bare uuid, as a focal,
`kin context` refuses the way `get_context_pack` does: the symbol has no body
or neighborhood in this repository to build a pack around, so the message
names it and gives `kin refs <id>` as the command that lists its callers.
Beside other focals it is reported as unresolved with the same message.

A pack also lists its focal's own call sites under `--- Call sites ---`, from
the focal's call-site ledger: one line per site, `+N` lines below the focal's
first line with the text at the site, its state, the reason behind an
unsettled state and the id of the target a resolver proved. The section ends
with one `not settled:` line per unsettled kind, or says every site is
settled. A focal no ledger describes yet reads as `owed_enrichment` and lists
no site. A pack built from several focals counts the sites of every focal
without listing them. `--json` carries the same block under `call_sites`, in
the shape `get_context_pack` serves.

```
Call sites in the focal's own body: 3 across 1 caller(s) (current)
  +1 `load` proven_outside
  +2 `fetch` proven_target -> entity:<uuid>
  +3 `render` unresolved (no_answer)
  not settled: call_sites_unresolved: 1 of the 3 call sites in the focal's own body got an answer that proves no target
```

### `kin source`

Print the exact implementation body for an entity

```
kin source <entity> [options]
```

| Argument | Required | Description |
| --- | --- | --- |
| `<entity>` | yes | Entity name or ID. A name with twins can carry its pin: `Name@file`, `Name@file:line`, `Name#kind` |

| Flag | Default | Description |
| --- | --- | --- |
| `--file <file>` |  | Exact repo-relative file of the entity, when its name has twins |
| `--kind <kind>` |  | Exact entity kind (for example: function), when its name has twins |
| `--json` |  | Output machine-readable JSON |

The same command as [`kin graph source`](#kin-graph-source), with the same arguments and
answer, at the top level so that `kin source`, the word the routed MCP tool teaches for
reading one entity's code, runs in a shell too. [`kin describe`](#kin-describe) and
[`kin call`](#kin-call) are the other two words that tool teaches.

## More graph queries

Narrower questions over the same graph authority.

### `kin history`

Show entity history

```
kin history <entity> [options]
```

| Argument | Required | Description |
| --- | --- | --- |
| `<entity>` | yes | Entity name or ID. A name with twins can carry its pin: `Name@file`, `Name@file:line`, `Name#kind` |

| Flag | Default | Description |
| --- | --- | --- |
| `--file <file>` |  | Exact repo-relative file qualifier for stable identity resolution |
| `--kind <kind>` |  | Exact entity-kind qualifier (for example: function or method) |
| `--all-revisions` |  | List every file-level revision, including ones that did not change this entity |
| `--ref <ref>` |  | Resolve history against a specific ref. Accepts `HEAD`, `HEAD~N`, branch names, `branch:&lt;name&gt;`, imported Git commits as `git:&lt;sha&gt;` or bare 40-hex SHAs, and semantic changes as `kin:&lt;id&gt;`, `change:&lt;id&gt;`, or bare change IDs. |

A symbol outside the repository, named by its `external_reference:<uuid>` id or
its bare uuid, has no revisions in this repository, at the head or at any ref.
`kin history` and `kin blame` refuse it, naming the symbol and giving
`kin refs <id>` as the command that lists its callers.

### `kin blame`

Show blame (version history) for an entity

```
kin blame <entity> [options]
```

| Argument | Required | Description |
| --- | --- | --- |
| `<entity>` | yes | Entity name or ID. A name with twins can carry its pin: `Name@file`, `Name@file:line`, `Name#kind` |

| Flag | Default | Description |
| --- | --- | --- |
| `--file <file>` |  | Exact repo-relative file qualifier for stable identity resolution |
| `--kind <kind>` |  | Exact entity-kind qualifier (for example: function or method) |
| `--all-revisions` |  | List every file-level revision, including ones that did not change this entity |
| `--ref <ref>` |  | Resolve blame against a specific ref. Accepts `HEAD`, `HEAD~N`, branch names, `branch:&lt;name&gt;`, imported Git commits as `git:&lt;sha&gt;` or bare 40-hex SHAs, and semantic changes as `kin:&lt;id&gt;`, `change:&lt;id&gt;`, or bare change IDs. |

`kin blame` refuses a symbol outside the repository the way `kin history` does,
since it has no revisions here to attribute.

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

`kin xref` anchors its cross-repo lookup on an entity of this repository. A
symbol outside every repository, named by its `external_reference:<uuid>` id or
its bare uuid, is no such anchor, so it is refused with the symbol named and
`kin refs <id>` given as the command that lists its callers here.

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
| `--target <entity>` |  | A symbol you are trying to reach. Neighbors from which it is still reachable inside the requested depth survive the per-step cap ahead of ones that are not. |
| `--max-response-chars <c>` |  | UTF-8 bytes the printed JSON may occupy (default 45,000; a value below 2,000 or above 60,000 is served as 2,000 or 60,000). Bodies go first, then whole branches, and at least one step is kept. A walk whose smallest retained form still does not fit is refused with an error naming that floor, rather than printed over the limit. The MCP `trace_data_flow` tool answers the same walk with a disclosed overrun instead. |

A symbol outside the repository is where a walk stops, never where one starts. A focal naming one, by its `external_reference:<uuid>` id or its bare uuid, is refused with the JSON error the `trace_data_flow` MCP tool gives, code `external_symbol_not_served`, which names the symbol and carries its record. A walk from one of its callers reaches it as a leaf step. A `--target` naming one is refused the same way, with `argument` `target`, because a target ranks steps through its own edges and the graph holds none of the symbol's own; name one of its callers as the target instead. A target given as an `external_reference` id the graph holds no symbol under is refused as `External symbol not found`.

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

Resolve repository-v6 merge conflicts Ten flags name a resolution and at least one is required, which is a group rather than a per-argument condition. `kin conflicts` is the read-only view of the same transaction, so nothing here has to accept an empty invocation in order to be inspectable.

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
| `--file <path> <file>` |  | Resolve a conflicted repository path using the exact bytes in `<file>`, which is the form that takes a file you merged by hand. `<path>` is the conflicted repository path or artifact identity from `kin conflicts`. Repeatable; the bodies of one request total at most 8 MiB. |
| `--all-ours` |  | Resolve all remaining conflicts keeping your version |
| `--all-theirs` |  | Resolve all remaining conflicts keeping the incoming version |
| `--do-continue`, `--continue` |  | Complete the merge after all conflicts are resolved. `--continue` is a visible alias for `--do-continue`. |
| `--abort` |  | Abort the merge and discard conflict state |
| `--expect <hash>` |  | Require the merge transaction to still be the one this identity names |
| `--json` |  | Emit the machine-readable merge transaction record |

`--file` is the form for a conflict you settle by writing the merged file yourself, the way a
Git user edits past conflict markers. It takes the repository path and a file holding the
complete body you want, records those exact bytes, and derives the entities from them, so one
call settles the artifact conflict and every entity conflict inside that file. `--all-ours` and
`--all-theirs` are the other way to clear a file in one call, and they keep one side whole, which
is rarely what a two-sided edit wants. A file that both branches changed on one run, and what
settled it:

```
$ kin merge cap-backoff
Merging refs/heads/cap-backoff into refs/heads/main left 3 unresolved conflict(s); the merge is held as merge transaction 7b942cddee6acda03d7fba308215e7b71cd20d08256e68cd9f04ec491b014817 (authority generation 8)
  - artifact retry.py (18564001-2f7e-4247-92ef-ae4e61e36365): changed on both branches with different content
  - entity retry in retry.py (0a69467a-63d6-5c34-ac35-632cefde30b7): changed on both branches with different content
  - entity backoff in retry.py (6cd876cf-cc8a-50bd-94be-e0a2fde3208d): changed on both branches with different content
Settle each conflict with `kin resolve`, then `kin resolve --continue`, or discard the merge with `kin resolve --abort`
Exit 8: the merge is parked with conflicts; `kin conflicts` lists them

$ kin resolve --file retry.py /tmp/retry-merged.py
Settled 3 conflict(s); merge transaction 672a290099aa89f23566753a876674309b3b6e9fae39eb72b969794dffbb397e has 3 of 3 conflict(s) settled
Publish the merge with `kin resolve --continue`

$ kin resolve --continue
Merged refs/heads/cap-backoff into refs/heads/main as change 6aa69c3b80300026f03afa8a4beecf3440beacebfb14445d2d17a257a28481c7 after settling 3 conflict(s) (1 projected entries, authority generation 10)
```

The merge exits 8 while it is parked, and nothing moves until `--continue`. A call carries up
to 8 MiB of authored input; related files can be settled across separate calls, and a later
`--ours` or `--theirs` for the same subject does not overwrite an authored body, though another
`--file` for the path replaces it.

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

Publish a new change restoring an earlier change's complete content

This is not a single-change undo. Later changes remain in immutable history, but their effects are removed from the working view. Unless the target already is the tip, `--discard-later` must accept restoring its complete content, including when the bounded preview cannot count later changes. If repository or workspace authority changes after the preview, rollback refuses; run it again to preview the current state. Restore the previous tip's content with another rollback using `--discard-later`; the output names that command.

```
kin rollback [change-id] [options]
```

| Argument | Required | Description |
| --- | --- | --- |
| `[change-id]` | no | Change whose complete content the new restoring change will carry. Omit when naming a work item with --feature. |

| Flag | Default | Description |
| --- | --- | --- |
| `--feature <feature>` |  | Roll back every change the named work item records |
| `--discard-later` |  | Accept replacing current content, even when the preview count is unknown |

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
| `--relations` |  | List every relation change by name instead of counting them by origin and kind |

The review opens with a summary: the overall risk, how many entities and
relations changed, how many entities the change reaches, and the breaking
changes and other findings. Entity changes, relation changes, inline comments
and the impact analysis follow. Relation changes are counted by origin and
kind, with edges from language-server enrichment counted apart from the ones
parsed from the change, and a group of ten or fewer is listed by name.
`--relations` lists every one. `--json` keeps its own shape and does not carry
the relation list, so the two flags cannot be combined.

`--entities` reviews repository entities, and reads an id no entity carries as
a removed entity. A symbol outside the repository, named by its
`external_reference:<uuid>` id or its bare uuid, was never removed from it, so
it is refused before anything is reviewed, with the symbol named and
`kin refs <id>` given as the command that lists its callers. An
`external_reference` id the graph holds no symbol under is refused as that.

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

A note or discussion is anchored to a repository entity. A `--scope` naming a
symbol outside the repository, by its `external_reference:<uuid>` id, as
`entity:<uuid>` or by its bare uuid, is refused by `kin review note` and `kin
review discuss` with the symbol named and `kin refs <id>` given as the command
that lists its callers, and nothing is written. The `kin_review_note_add`,
`kin_review_discuss` and `kin_review_create` MCP tools refuse the same scopes
with `external_symbol_not_served`.

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

Tests link to repository entities, so a symbol outside the repository, named
by its `external_reference:<uuid>` id or its bare uuid, has none here. `kin
verify entity`, `kin verify plan` and `kin verify run` refuse it with the
symbol named and `kin refs <id>` given as the command that lists its callers,
rather than reporting that no entity matched. An `external_reference` id the
graph holds no symbol under is reported as no entity matching it.

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
borrowed from a vendor's permission layer. The belt is Kin's tools and nothing else.
There is no shell, no grep, no file-reading tool and no file-writing tool, so there is
nothing to fall back to, and a tool the model invents is refused by name. The model
changes code through `kin_mutate`, naming the entity it changes. When a result reports `safe_to_conclude_absent` false, the agent is
told the answer is unknown and given the named gap rather than being allowed to conclude
the thing does not exist. Every change runs under a Kin session, so it carries
provenance naming the agent. The agent creates only what `kin_mutate` can create; for a
change it cannot make, it is told to stop and say so. `KIN_AGENT_PURE_KIN` set to a false value makes `kin agent run`
refuse to start, because the local file tools it used to add are retired.

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
| `--context-tokens <n>` | what the endpoint reports, else `32768` | The model's context window in tokens |
| `--max-result-bytes <n>` | an eighth of the window, at most `32768` | Most bytes of one tool result sent to the model |
| `--system <file>` |  | File holding a system prompt that replaces the built-in one |
| `--temperature <f>` |  | Sampling temperature passed through to the endpoint |
| `--tool-profile <profile>` |  | Tool surface the MCP server should serve |

Three files land under `--out`. `transcript.jsonl` is the run, one JSON object per line,
in the same stream-json shape Claude Code emits, so existing transcript analyzers read it
unchanged. `kin-trace.jsonl` is one row per tool call carrying the `_kin` envelope, the
`negative` verdict and the policy decision, joinable to the transcript on `tool_use_id`.
`result.json` is the terminal record on its own.

`result.json` also carries the run's own account of what it spent, under `kin_agent.cost`,
so a cost claim about a run is read off one object rather than assembled by hand from three
files or estimated.

| Field | Meaning |
| --- | --- |
| `accounting_mode` | Which counting produced the token numbers. Always present. |
| `total_input_tokens` | Prompt tokens over every request, or `null` when nothing counted them |
| `total_output_tokens` | Answer tokens over every request, or `null` when nothing counted them |
| `requests` | Completions the endpoint returned, including one whose choice was rejected after the model had already generated it |
| `requests_with_input_usage` | How many of those carried the endpoint's own prompt count |
| `requests_with_output_usage` | How many carried its own answer count |
| `stop_reason` | The same token as `kin_agent.stop_reason` |
| `tool_calls` | Calls the run attempted |
| `error_calls` | How many of those came back to the model as an error |
| `by_tool` | One row per tool name, as the model called it |

Each `by_tool` row carries `calls`, `error_calls`, `bytes_returned` (what the tool itself
returned), `bytes_shown` (what reached the model, which is less when a result was cut to
`--max-result-bytes` or withheld for the context budget) and `wall_ms`. The rows add up to
`tool_calls` and `error_calls` exactly. A call that was never run because a budget was spent
part way through a batch is counted in `skipped_calls` and is in neither.

`error_calls` counts every call whose result went back marked as an error: a tool name the
router refused, arguments the schema rejected, an `isError` result from Kin, and a result
the conversation could not hold. It sits beside the token totals on purpose. Seven error
calls beside fifty-eight answer tokens is a run that spent its turns being refused, and
reading the tokens without the refusals beside them is how a saving gets claimed for work
that never happened.

`accounting_mode` is never omitted, because a byte heuristic and a model's own tokenizer are
two different rulers and a number off one is not comparable with a number off the other. It
is one of:

- `endpoint_usage`. Every completion carried the endpoint's own `prompt_tokens` and
  `completion_tokens`, and the totals are those. An endpoint's own count is preferred
  whenever it reports one.
- `endpoint_usage_partial`. Some completions carried a count and some did not, so the totals
  cover only part of the run. The two `requests_with_` fields say how much.
- `llama_cpp_tokenizer`. The endpoint reported nothing, and every dispatched request's prompt
  was counted by the server's own `/apply-template` and `/tokenize` under
  `KIN_AGENT_CONTEXT_ACCOUNTING=llama_cpp`. Nothing counted the answers, so
  `total_output_tokens` is `null`.
- `heuristic`. The endpoint reported nothing and at least one prompt count is the labeled
  byte heuristic of three bytes to a token. That is a labeled estimate and not an upper bound
  for every tokenizer, and `total_output_tokens` is `null`.
- `none`. The run stopped before it dispatched a request, so nothing counted anything.

`kin-trace.jsonl` carries the per-request rows the totals are summed from, one
`"event": "request_usage"` per completion with `input_tokens`, `output_tokens`,
`reported_by_endpoint` and `api_ms`, so the summary can be checked against the file rather
than taken on faith.

Three bounds hold on every run. The deadline covers every wait, the endpoint's included: a
request still unanswered when it passes is abandoned and the run stops with `deadline` as
its reason. One tool result is sent to the model up to `--max-result-bytes`, and a longer
one is cut with a note naming its size, the ceiling and how to page. The conversation is
kept inside the model's context window: the window comes from `--context-tokens`, else from
what the endpoint reports for the loaded model (LM Studio's own API, vLLM's
`max_model_len`, OpenRouter's `context_length`), else `32768`, and the first line on
stderr says which. A result the conversation cannot hold is withheld with a note, and the
agent is asked for its final answer before the next request would overflow. The result
record carries the reason in `stop_reason` and `stop_detail`, and the budget under
`context`.

What counts the conversation decides when a run ends, so the rule is explicit. Once the
endpoint has reported a prompt count of its own, every later budget decision is made on
that count plus an estimate of only what the loop appended since, and the byte heuristic
does not overrule it. The heuristic governs only until the first count arrives and for
endpoints that report none. Measured against qwen3-coder-next, the heuristic read 59,029
tokens for a request the server counted at 46,523, and the run stopped for its context
budget with about 19,000 tokens of the window free and the model still working; short runs
agreed within a few hundred tokens, so the overcount bit hardest where it cost the most.
`context.count_source` in the result record and `method` on each `context_admission` row in
`kin-trace.jsonl` name which count governed, as one of `endpoint_usage_anchor`,
`llama_cpp_template_tokenize` or `heuristic`, and the `stop_detail` sentence says it in
words.

The run's Kin session stays open through a long model turn. Every Kin call refreshes it, and
while a request to the endpoint is in flight the runner sends `kin_session_heartbeat` at a
third of the idle window the session reply named in `idle_timeout_secs`, so a turn longer
than that window does not cost the run its session. A reply that names no window gets no
heartbeat rather than a guessed one. The result record counts them in `session_heartbeats`.

Changes go through `kin_mutate` on the server, so a native agent task that changes code
needs a profile that serves it, such as `agent-default`. A query-only or search-only
profile serves no `kin_mutate`, and the agent is told the run is read-only.

The exit code is the run's outcome: `0` a final answer, `1` a harness error, `2` the
tool-call budget was spent, `3` the deadline expired, `4` the endpoint was unreachable or
answered with nothing usable, `5` the MCP server failed, `7` the conversation reached the
model's context window. A transcript is written and closed on every one of them, so a
failed run is still measurable. Code `6` is retired with the file tools, whose unpublished
changes it reported. A change Kin refuses comes back to the model as an error result it
can read and correct, and the run ends on the model's answer, so the result record's
`entities_changed` is what names the entities a run changed.

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

Given `--model`, it also prints the context window the endpoint reports for that model,
which is the window a run budgets for. Exit `0` when both answer, `4` when the endpoint
does not, `5` when the MCP server does not.

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
| `--semantic-only` |  | Launch the assistant with none of its built-in tools and Kin's MCP server as its only other one, so it reads and changes code through Kin, by entity; the enforcement tier is printed at launch and differs per assistant |

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
| `--tool-profile <profile>` |  | Tool surface to serve: `agent-default` (the curated agent belt, and the default), `agent-query` (that belt without the session and transaction tools, for a client that only queries), `agent-search` (the measured always-on set, with every other tool reached through `kin_tool_search`), `agent-routed` (one tool, `kin`, whose commands reach the agent belt, writes included, and every other tool through `describe` and `call`, for a client that sends every tool with every request), `agent-routed-query` (that one tool without a write path), `full` (every tool), `benchmark`, or `context-bench`. Overrides KIN_MCP_TOOL_PROFILE. |
| `--no-spawn` |  | Never start or revive a daemon from this server: bind only a daemon that is already running, and answer graph tool calls with an honest "no daemon is running" error otherwise. This is the probe mode for watchdogs and boot-time checks (equivalent to KIN_NO_DAEMON=1): the MCP handshake and tool list are served in full, and nothing heavy is ever spawned by the check itself. |

What each profile costs before the model has asked anything, measured on 2026-09-15
against `qwen/qwen3.8-27b` (MLX 4-bit) by sending it one identical two-message chat with
that profile's `tools/list` attached and without it and reading the server's own
`prompt_tokens` both times:

| `--tool-profile` | tools served | schema JSON bytes | schema tokens |
| --- | ---: | ---: | ---: |
| `agent-search` | 5 | 5,622 | 1,700 |
| `agent-query` | 14 | 11,873 | 3,596 |
| `agent-default` | 22 | 31,430 | 8,728 |
| `full` | 74 | 160,276 | 37,752 |

The token figures belong to that tokenizer; the ratios between profiles do not. This page
described `full` as "roughly 12k extra tokens of schemas per session", which understated
it by more than three times.

Those are schema costs. What a profile asks one answer to fit is a second number, and on
`agent-default` it is per tool. `trace_data_flow` and `get_context_pack` are served a
24,576-character ceiling, which is the per-result limit `kin agent run` cuts one tool
result to on a 64k-token window. Every other budgeted tool is served 12,000, the size that
lets six answers fit a 24,000-token run. They differ because the answers differ. A ranked
list cut at its ceiling loses its tail and keeps its answer. A chain cut at its ceiling
loses the far end, which is the end the question was about. Both numbers are advertised on
the served schema as the `max_chars` default, so a caller reads the one it will get and can
raise either up to 60,000. `full` serves 45,000 on everything.

`kin agent run` does not put a whole profile on the model. It withholds the session and
transaction tools it drives itself, folds `trace_data_flow` and `trace_path` into one
`trace` tool, and withholds the tools `KIN_AGENT_BELT=wide` exists to restore, so the belt
a model receives is smaller than any row above, and it carries Kin tools only.

`get_entity_source` and its `get_entity_body` alias ask the selected repository daemon on
every call, including retries after a source gap. A committed generation does not describe
every live semantic derivation: the daemon may repair an entity's span against canonical
workspace bytes before a semantic commit. The source response still verifies that the span
belongs to those bytes; an unresolved mismatch remains an error. Retrying a read does not
admit files or create a commit, and a successful precommit read is not durable publication.

### `kin describe`

Show a routed kin tool command's or any Kin tool's arguments

```
kin describe [command]
```

| Argument | Required | Description |
| --- | --- | --- |
| `[command]` | no | A routed command, such as locate or mutate, or any Kin tool's name. Omit it to list them all |

Prints what the routed `kin` MCP tool's `describe` command answers, as JSON: the command's
or tool's arguments as a schema and one call that works, or, with no command, every routed
command with its CLI spelling and every other tool `kin call` runs, each marked where it
writes. It is read from the same table the routed tool reads, answers as the
`agent-routed` profile does, and needs no repository. A name that is neither a command nor
a tool is refused, and exits 1.

```
kin describe
kin describe mutate
kin describe graph_neighborhood
```

### `kin call`

Run any Kin tool by its registered name, as the routed kin tool's call

```
kin call <tool> [arguments]
```

| Argument | Required | Description |
| --- | --- | --- |
| `<tool>` | yes | The tool's registered name, as `kin describe` lists it |
| `[arguments]` | no | The tool's arguments as one JSON object, or `-` to read it from stdin. Omitted, the tool is called with none |

Sends the routed `kin` MCP tool's `call` command through the same server path
`kin mcp start` answers it on, against this repository's daemon, which it reaches the way
`kin graph source` does. The answer is the one the routed tool gives: the tool's payload
with its `_kin` envelope, and hints that name a spelling this shell runs. A call refused on
its fields is answered without a daemon, naming the fields. A tool that answers with an
error exits 1, with the answer printed as usual.

```
kin call graph_neighborhood '{"entity_id":"<entity id from kin locate>","depth":2}'
kin call kin_session_start '{"vendor":"shell","client_name":"my script","cwd":"/path/to/repo"}'
kin call kin_mutate - < change.json
```

`kin call` answers as the `agent-routed` profile does, writes included. A read-only MCP
profile such as `agent-routed-query` limits what its one tool reaches, not what a shell on
the same machine runs, and a shell already writes through `kin commit` and the rest. A
name a shell runs another way is refused with the command that works: `kin init` for
`kin_init`, `kin describe` and `kin call` for `kin_tool_search` and `kin_tool_call`, and
for a routed command's name, such as `locate`, its CLI spelling or `kin call` with the tool
it runs.

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
| `<scope>` | yes | Scope to lock (entity:&lt;uuid&gt;, contract:&lt;uuid&gt;, file:&lt;path&gt;, artifact:&lt;path&gt;, or an entity UUID) |

| Flag | Default | Description |
| --- | --- | --- |
| `-l, --lock <lock>` | `soft` | Lock type: hard or soft |
| `-t, --task <task>` |  | Task description |
| `-s, --session <session>` |  | Session ID (defaults to a new CLI session) |

An intent locks repository scopes. A scope naming a symbol outside the
repository, by its `external_reference:<uuid>` id, as `entity:<uuid>` or by
its bare uuid, is refused with the symbol named and `kin refs <id>` given as
the command that lists its callers, and nothing is locked. An
`external_reference` id the graph holds no symbol under is refused as naming
nothing. `kin traffic show` refuses the same scopes, since no intent can be
declared on one, and the `kin_register_intent` and `kin_check_traffic` MCP
tools refuse them with `external_symbol_not_served`.

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
| `<scope>` | yes | Scope to query (entity:&lt;uuid&gt;, contract:&lt;uuid&gt;, file:&lt;path&gt;, artifact:&lt;path&gt;, or an entity UUID) |

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
| `-s, --scope <scope>` |  | Scope to link (entity:&lt;uuid&gt;, contract:&lt;uuid&gt;, artifact:&lt;path&gt;, change:&lt;id&gt;, or an entity UUID) |
| `-p, --priority <priority>` |  | Priority: critical, high, medium, low, none |

Work is linked to repository scopes. A scope naming a symbol outside the
repository, by its `external_reference:<uuid>` id, as `entity:<uuid>` or by
its bare uuid, is refused with the symbol named and `kin refs <id>` given as
the command that lists its callers, and nothing is written. `kin work link`,
`kin work implement` and the `--scope` filter of `kin work list` refuse the
same scopes, and so do the `kin_work_*` MCP tools, with
`external_symbol_not_served`. An `external_reference` id the graph holds no
symbol under is refused as naming nothing.

#### `kin work list`

List work items

```
kin work list [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `-s, --status <status>` |  | Filter by status |
| `-k, --kind <kind>` |  | Filter by kind |
| `--scope <scope>` |  | Filter by scope (entity:&lt;uuid&gt;, contract:&lt;uuid&gt;, artifact:&lt;path&gt;, change:&lt;id&gt;, or an entity UUID) |

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
| `<target>` | yes | Target to annotate (entity:&lt;uuid&gt;, contract:&lt;uuid&gt;, artifact:&lt;path&gt;, change:&lt;id&gt;, work:&lt;uuid&gt;, or an entity UUID) |

| Flag | Default | Description |
| --- | --- | --- |
| `-k, --kind <kind>` |  | Annotation kind: comment, warning, instruction, reasoning |
| `-b, --body <body>` |  | Annotation body |

A note is anchored to what the graph holds. An entity id, given as
`entity:<uuid>` or bare, that the graph holds no entity under is refused and
nothing is written, with `kin locate` given as the way to find the id. A
symbol outside the repository, named by its `external_reference:<uuid>` id,
as an `entity:` target or by its bare uuid, is refused with the symbol named
and `kin refs <id>` given as the command that lists its callers, since a note
belongs on one of them. The `kin_annotation_add` MCP tool refuses the same
targets. `kin note list` refuses a target naming such a symbol too, since no
note can be anchored to one, rather than answering that it has none.

#### `kin note list`

List annotations for a semantic scope or work item

```
kin note list <target>
```

| Argument | Required | Description |
| --- | --- | --- |
| `<target>` | yes | Target to query (entity:&lt;uuid&gt;, contract:&lt;uuid&gt;, artifact:&lt;path&gt;, change:&lt;id&gt;, work:&lt;uuid&gt;, or an entity UUID) |

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
kin graph status [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--json` |  | Output machine-readable JSON: the rendered lines beside the structured reference-edge coverage, relation census, graph section and call-site shares |

Among its lines it counts every call site the graph's call-site ledgers hold, by
the state each reads as, with each state's share of that census, the callers no
current ledger describes yet, and the files holding them. The block is the one
the `kin_graph_status` MCP tool serves as `call_sites`, and `--json` carries it
under `call_sites` with `census`, `shares` (for every state its `sites` and its
`share` of the census, which add up to it), `callers_owed` and `owed_files`.
Callers no resolver can prove on this host now are counted apart, under
`callers_unproven_no_resolver` with their reasons in `no_resolver`, and are not
owed files, since no sweep will reach them until the host changes.

```
Call sites in the store: 1840 across 612 caller(s), 14 caller(s) owed
  by state: proven_target 1102 (60%), proven_external 431 (23%), proven_outside 229 (12%), unresolved 78 (4%)
  owed enrichment: src/cli/main.py (9 caller(s))
  owed enrichment: src/io/files.py (5 caller(s))
  not settled: call_sites_owed: 14 of the 612 callers in the store have call sites the graph has not settled yet because their derivation or enrichment is owed, so a call there is not accounted for
  not settled: call_sites_unresolved: 78 of the 1840 call sites in the store got an answer that proves no target
```

In `--json` a critical graph health issue still exits non-zero after the JSON
is printed.

#### `kin graph validate`

Structural integrity validation

```
kin graph validate
```

#### `kin graph owed`

Show the owed derivation ledger repository authority holds: each source body owed a parse, and the re-derivation that last paid the workspace, then the files whose callers are owed enrichment. Reads the local store only; starts no daemon, admits nothing, and migrates no earlier build's records

```
kin graph owed [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--json` |  | Output machine-readable JSON (`kin.graph.owed-derivations.v1`) |

It reports the owed derivation records persisted in repository authority, then the owed enrichment described below. For the ledger it reads the authority snapshot and its acknowledged journal, checks both against the digests the authority record names, replays the journal onto the snapshot's envelope and runs the ledger checks a full open runs. When that read cannot answer, it validates the store in full: the recovery, whole-history replay and body checks a full open runs. Either way the ledger it prints is one an open would accept.

It writes nothing to the store on either path. An open also records its history validation, and finishes what an interrupted write or promotion left behind, such as a superseded snapshot or a staged authority record; this command does neither, so every file in the store is as it found it, and a record an interrupted write left staged is refused until a daemon or another command finishes that write. It never contacts or starts a daemon, admits nothing and reads nothing from the working copy.

It can run while a daemon serves the repository. It reads under the repository authority lock, which a daemon also takes while it commits, and it waits up to 10 seconds in total for the store lock: while another process holds it, the command retries, holding nothing, and when the 10 seconds are spent it refuses with a message that another process held the repository authority lock. How long it then holds the lock depends on the path. The envelope read holds it only while it reads the snapshot and the journal and checks them against the authority record. The full validation, taken only when that read cannot answer, holds it through the whole recovery, history replay and body check until the ledger is printed, which on a large store can take much longer, and a daemon's commit waits for it. The owed enrichment below always takes the full validation, and holds the lock until the workspace graph is materialized.

It does not migrate legacy state. The `semantic-debt.json` and `unpublished-enrichment.json` files an earlier build kept beside the store are not ledger records: a daemon of this build judges them at its first start and carries what they still owe into repository authority with its next transaction, and until then this command does not show them. A workspace with no records therefore reads "no owed derivation records in repository authority", which says what the ledger holds and not that no semantic work is owed: an earlier build's record that has not migrated, or enrichment that is still incomplete, can remain.

Every workspace authority holds is listed with its records and, whenever authority records one, its last payment, even when no records remain. The JSON carries `schema`, `repository_id`, the logical `generation` the ledger was read at, and `workspaces`, each with `workspace_id`, `records` and `payment`. A record has `path` (its UTF-8 rendering, or `null` when the path has none), `path_hex` (the exact path bytes), `body` (the digest of the body the parse is owed for), `recorded_at` (the logical generation that recorded it) and `cause` (`publication`, or `legacy` for a record carried in from an earlier build's file). A payment has `paid_through` (the generation the paying commit was taken against), `operation_id` and `hydration_version`.

When authority cannot be read, for example a store layout newer than this build, damaged authority, a ledger that fails its checks, or a lock still held when its 10 seconds are spent, it prints nothing on stdout, names the cause on stderr, and exits non-zero.

After the ledger it reports owed enrichment for this store's own workspace: every file holding an entity with source text that no current call-site ledger describes, with how many such callers each holds. Until a language-server sweep writes a caller's ledger, its call sites are not accounted for, whatever the derivation ledger says. The workspace graph is derived state, so this half validates authority in full, still writing nothing and within the same 10-second lock budget, materializes the workspace graph from it, and releases the lock before it reads the graph. Each caller is read in the order every Kin surface reads it: an owed derivation, then no ledger, then a stale proof context, then the ledger. The line reads `owed enrichment in workspace <id>: <owed> of the <callers> callers with source text hold no current call-site ledger, in <n> file(s)`, followed by one `<path>: <n> caller(s)` line per file, or says every caller holds a current ledger or sits in a file the parser read no call in, which needs none. When the graph cannot be read, the line names why and says it was not read; the ledger above is still reported and the command still exits zero. The JSON carries it as `owed_enrichment`, with `workspace_id`, `callers`, `callers_owed`, `files` (each with `file` and `callers`) and, when the graph could not be read, `unavailable`.

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

An `external_reference:<uuid>` id, or its bare uuid, names a symbol outside the
repository, which has no entity record here. It is refused with the symbol
named and `kin refs <id>` given as the command that lists its callers.

#### `kin graph source`

Print the exact implementation body for an entity

```
kin graph source <entity> [options]
```

| Argument | Required | Description |
| --- | --- | --- |
| `<entity>` | yes | Entity name or ID. A name with twins can carry its pin: `Name@file`, `Name@file:line`, `Name#kind` |

| Flag | Default | Description |
| --- | --- | --- |
| `--file <file>` |  | Exact repo-relative file of the entity, when its name has twins |
| `--kind <kind>` |  | Exact entity kind (for example: function), when its name has twins |
| `--json` |  | Output machine-readable JSON |

[`kin source`](#kin-source) is the same command at the top level.

#### `kin graph body`

Alias for source: print the exact implementation body for an entity

```
kin graph body <entity> [options]
```

| Argument | Required | Description |
| --- | --- | --- |
| `<entity>` | yes | Entity name or ID. A name with twins can carry its pin: `Name@file`, `Name@file:line`, `Name#kind` |

| Flag | Default | Description |
| --- | --- | --- |
| `--file <file>` |  | Exact repo-relative file of the entity, when its name has twins |
| `--kind <kind>` |  | Exact entity kind (for example: function), when its name has twins |
| `--json` |  | Output machine-readable JSON |

#### `kin graph export`

Export the drawable projection of the live graph as JSON. Reads the daemon's live graph, projects it to nodes and links, and samples it server side so every consumer draws the same picture. The payload contract is `graph-export.schema.json` in `packages/boundary-contracts`; `docs/graph-feed.md` explains the sampling rule and how to pair an export with `kin graph watch`.

```
kin graph export [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--limit <N>` | `1400` | Cap the exported node count, sampled by degree with per-module quotas. `0` exports every entity |
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
| `--limit <N>` | `1400` | Cap the drawn node count, sampled by degree with per-module quotas. `0` draws every entity |

The page draws the same payload `kin graph export` prints, so it is capped and
sampled the same way, and it says which it is: a sampled canvas reads "showing
1,400 of 20,298 entities", and a complete one says so instead of going quiet.
The command refuses rather than serving a blank page when it cannot read the
graph, and the refusal names the storage namespace it looked at.

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

Create and restore complete native recovery carriers.

```
kin backup <subcommand>
```

Subcommands:

#### `kin backup create`

Create a complete current-format carrier outside `.kin`. The destination must
not exist. Without `--output`, a repository-specific backup directory outside
the working tree is used.

```
kin backup create [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `-t, --tag <tag>` |  | Optional tag to label the backup |
| `--output <path>` |  | Absent destination in an existing directory |

#### `kin backup list`

List available backups

```
kin backup list [--json] [--directory <path>]
```

Use `--directory` to list carriers after the original repository is lost.
Invalid or incomplete entries are reported without hiding healthy carriers.

#### `kin backup restore`

Restore native identity, history and metadata into a fresh location. The target
must be an absent `.kin` directory in an existing working directory at a different
path from the original repository. Existing
destinations are never replaced. Old daemon runtime endpoints are not restored.

```
kin backup restore --from <carrier> --target <working-directory>/.kin
```

Legacy named or `--latest` in-place graph restore is refused without changing
the repository or old backup. Corrupt, incomplete or unsupported carriers and
pending path-bound reconciliation journals also refuse safely.

#### `kin backup delete`

Permanently delete one complete carrier from the default backup directory.

```
kin backup delete <name>
```

| Argument | Required | Description |
| --- | --- | --- |
| `<name>` | yes | Exact carrier directory name; no partial matching |

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
| `--when-unused` |  | Stop only daemons nothing is using, and name the rest  A daemon with an attached client, a request in flight, a write it has not flushed, or enrichment or embedding still running is left up and says which, then exits on its own as soon as that ends. Without this flag the stop happens now, whatever is attached. |
| `--json` |  | Emit machine-readable JSON |

#### `kin daemon sweep`

Ask this repository's daemon for a language-server enrichment sweep

```
kin daemon sweep [options]
```

The sweep derives the cross-file reference, override and type-use edges a single-file parse cannot, and it skips files the graph already holds server evidence for. `kin init` runs one and every daemon start queues one, so this is the surface for the case those did not finish: a sweep killed with its daemon, a store converted before a language server was installed, or a repository whose sweeps the daemon has stopped queueing because the last three all died without enriching anything. It prints the daemon's own answer, waits for the sweep by default, and fails loudly when no daemon answers or when the daemon has no language server to enrich with. The wait lasts up to 900 seconds. When it runs out the command exits non-zero and says how far the sweep has reached, and the sweep keeps running in the daemon, which publishes it when it ends. The sweep commits its progress as it goes, so a sweep whose daemon is stopped before it ends resumes on the next daemon start, skipping the files already recorded as finished. A question the language server answers in a way Kin cannot prove, such as a call hierarchy prepared for a different entity, gets the same answer every time, so it is recorded as unprovable and the file still finishes; `/lsp/sweep/status` names those files under `unprovable_files`. Only a question that got no answer, a timeout or a server that stopped answering, leaves its file owed.

The record of finished files lives in the store's repository authority, and a store that holds one is written at authority snapshot format version 21 (22 when it carries a graph section) and journal frame version 6. The operation that recorded it stays in the store's operation log, so the store keeps those versions after its files are edited. A Kin build that reads at most snapshot version 20 and frame version 5 refuses such a store at the header with an `incompatible snapshot schema` or `unsupported authority frame version` error that names the version it needs, and no path back to such a build is promised for a store this build has swept.

When the language server answers that a call names a declaration outside the repository, in a standard library or an installed dependency, the sweep records the call as a proven call into that symbol. The symbol is named by the package that holds it, at the version the server loaded, and by the chain of declarations the server's own symbols give it, the way SCIP names symbols: `Array.map` in TypeScript 5.6.3 is `npm typescript 5.6.3` and `` `lib.es5.d.ts`/Array#map(). ``, and it is the same symbol in every repository on that version. Each such proof names the proof context it was made under: the language server, its version, and hashes of its configuration and of the environment it answered against. A later sweep under another context records each site it proves again under that context. A declaration outside the repository that the server's symbols do not name still retires the in-repository guesses at the call, and records no symbol. A store that holds these symbols or proof contexts is written at authority snapshot format version 23 (24 when it carries a graph section) and journal frame version 7, which a Kin build that reads at most snapshot version 22 and frame version 6 refuses at the header. Every store is swept once more after upgrading to this build, because files an earlier sweep finished recorded no such proofs.

Every entity with source text in a file the sweep finishes gets a call-site ledger: how many call expressions Kin's parser reads in its body, and one state for each of them, keyed by where its callee sits inside the entity. A site is proven (to a repository declaration, to a named external symbol, or outside the repository with no symbol to name), a call through a value binding that proves no target, in a file no build compiles, a site where the language server timed out, crashed or broke protocol, or unresolved, with the reason. An entity with no call gets a ledger that counts none, so an entity without a ledger is one whose enrichment is still owed. A file is recorded as finished only once every entity in it has a ledger, and an edit that changes an entity drops its ledger and the file's record together. A proven site is carried by a call edge whose evidence names the proof context. When a file is proven again after every pass over it finished, a proof its ledgers no longer hold, including one made under another context or under none, leaves its edge, and an edge left with no site is removed; a file whose passes failed keeps its proofs. A file whose language server repeatedly returns non-transient errors on the same bytes under the same proof context is recorded on its third attempt with the sites the server failed at, so the sweep stops asking about it. Timeouts and crashed server sessions remain owed. The sweep retries an interrupted file once within the pass, restarting a dead server, and the idle daemon queues another pass when persisted retry backoff expires. Repeated crashes without completing a file stop that language for the pass; completed files preserve progress and renew its restart allowance. A store that holds call-site ledgers is written at authority snapshot format version 25 (26 when it carries a graph section), journal frame version 8 and graph delta version 7, which a Kin build that reads at most snapshot version 24, frame version 7 and delta version 6 refuses at the header. Every store is swept once more after upgrading to this build, because files an earlier sweep finished have no ledgers.

| Flag | Default | Description |
| --- | --- | --- |
| `--no-wait` |  | Return as soon as the sweep is queued, instead of waiting for it |
| `--json` |  | Emit machine-readable JSON |
| `--verbose` |  | Print the daemon's answer and a line per file, not one live line |

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
| `--install-language-servers` |  | Install the missing language servers without asking: only for the languages the repository setup runs in uses, and for every language outside one. An install can write outside Kin's directory, and the run says so before it does, so an interactive run asks first and a scripted one needs this flag |
| `--resource-profile <profile>` |  | Record this machine's resource profile without the advanced prompt: proof, interactive, throughput, or ci |
| `--embedding-model <when>` | `later` | When the embedding model is fetched: `later`, or `never` on a machine that does not fetch it. Setup never downloads it either way |
| `--embedding-provider <where>` | `local` | Where vectors are computed: `local`, or `remote` for an OpenAI-compatible endpoint. `remote` collects no credential |
| `--skip-path` |  | Do not add `~/.kin/bin` to the shell profile. Only asked about for an npm or npx install, which cannot make the edit itself |
| `--tool-profile <profile>` |  | Tool profile to write into every AI client this run configures: agent-default, agent-query, agent-search, agent-routed or agent-routed-query. Without it each client gets its own default, and a profile set by hand is kept and pinned; with it the entry carries `KIN_MCP_TOOL_PROFILE_PINNED=1`, and later `kin setup` and `kin update` runs keep the profile |
| `--check` |  | Skip the wizard and only run the first-run health check |

The wizard opens with a hardware check. It reports the architecture, the
physical and logical core counts, the memory and the accelerator this machine
reports, all from the same `kin-infer` detection `kin resources inspect` reads,
then names the resource profile that follows from them and why.

`kin setup --intent advanced` can adjust that profile. A profile that budgets
past what the machine actually has can exceed safe memory and GPU thresholds and
crash the machine, so the detected figures are the ceiling and the prompt says
so. An adjustment is recorded in `~/.kin/config/setup.toml`; `kin` and
`kin-daemon` adopt it at their next start, and an exported
`KIN_RESOURCE_PROFILE` or a repository's `[resources]` config still outranks it.
Re-running the wizard and taking the recommendation clears the record.

The last two questions are asked on every intent, because `--intent` is how a
scripted run selects a plan and a decision reachable from only some plans is one
some installs never make. They are when the embedding model is fetched, which
defaults to later and never downloads during setup, and where vectors are
computed, which recommends local and states that a remote provider sends entity
text to the endpoint you configure.

A non-interactive run prints every decision it answered for you, the value it
took, and the command or flag that changes it later.

Run `kin setup` with no subcommand for the default behavior above, or one of:

#### `kin setup status`

Show what's installed

```
kin setup status [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--json` |  | Emit the machine-readable health report as JSON |
| `--verbose` |  | Print every check, including the ones that pass or do not apply |

On a terminal it prints only the checks that need something, and one line for the rest. A pipe, CI
and `--verbose` print the full table, unchanged.

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
| `--conversion-source <path>` |  | Report one file's persisted conversion coverage and its entity counts by kind |

`--conversion-source` is a conversion diagnostic for one repository-relative
path. It reports what conversion recorded for the file: whether an adapter
parsed it and how completely, the tier it is tracked at, whether its type is one
no adapter claims and why, whether its entity set can be certified as whole,
and how many entities of each kind it produced. It lists no entities, since you
work with entities through `kin locate` and the other graph commands. A path
the graph does not track is refused with a nonzero exit rather than reported as
empty. With `--json` it prints `path`, `file_coverage`, `counts_by_kind` and
`total`.

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
| `--set-policy <policy>` |  | Set how an available update should reach this machine and exit. `auto` (the default) installs unattended through the gated executor: it waits for a moment with no managed Kin daemon or VFS server, defers at most a bounded window, and runs the full stop-install-acknowledge chain. An open agent session does not hold it back. `prompt` notifies with the remedy attached and waits to be told. `manual` never notifies; checks still run. |
| `--apply` |  | Bring this machine current in one gesture: install the release, acknowledge the restart fence, and repair agent configs, in that order. This is what the update notification's button runs. |
| `--dry-run` |  | With --apply: print the ordered steps and change nothing. |
| `--unattended` |  | Run the unattended executor (what the update watchdog invokes on a stale install with policy auto): evaluate the machine-activity gates, and on proceed stop the managed daemon and VFS server cooperatively and run the full --apply chain. Agent MCP servers keep running; each picks up the new binary when its agent next starts it. Blocked runs persist a deferral clock instead of installing. The final stdout line is one JSON record (also appended to ~/.kin/update-ledger.jsonl) carrying the decision, reason, blocked_seconds, window_seconds, and how many releases the deferral has blocked across. |
| `--force-window` |  | With --unattended: apply despite the activity gates. For the watchdog once a deferred record shows blocked_seconds >= window_seconds, which starts at 24h and shortens as the installation falls further behind, to a floor of 6h. Never overrides a recorded prompt or manual policy, only the executor's own activity gates. |

### `kin upgrade`

Bring this store up to this build's replay semantics, keeping its history

```
kin upgrade [options]
```

| Flag | Default | Description |
| --- | --- | --- |
| `--json` |  | Output machine-readable JSON (`kin.store-upgrade.v1`): the state (`upgraded`, `requalified` or `already_current`), the versions it moved from and to, each head it re-derived, whether uncommitted work was re-derived, the source files parsed, whether binding history is checked afterwards, the elapsed time and any follow-up warnings. |

A store an older Kin build wrote serves the state that build derived, so every answer over it is qualified until it is re-derived. `kin status`, `kin graph status`, `kin doctor` and an MCP answer's trust reason name this command for it; through npm it is `npx -y @kinlab/kin@<version> upgrade`.

It re-derives the state every local branch head and a detached workspace base serve, from the exact trees and bodies the store keeps, and records each head's difference as one new native change on top of that head, with no file change. Uncommitted work is re-derived under the same build and stays pending. Every earlier change, branch, review, spec and history record is kept as it was, and history recorded before the upgrade keeps the replay version that authored it. The command stops this repository's daemon and holds the repository's runtime authority while it runs, so no daemon starts beside it, commits everything in one repository transaction, and writes the store's replay-semantics record last, so a run stopped before the commit changes nothing and a run stopped after it is finished by running it again.

The same transaction pays the workspace's owed derivation ledger (see [`kin graph owed`](#kin-graph-owed)) against the generation it was planned from, and only where its re-derivation verifier proves the workspace's committed graph is exactly this build's derivation of its tree. The payment says the owed parses were made, not that every file parsed completely: a file that does not parse keeps its incomplete coverage. A record a daemon's publication makes after the commit stays owed for the next commit, and one that lands before it makes the commit refuse. Once authority records the payment, the upgrade removes the owed-work files an earlier build kept beside the store.

It refuses, changing nothing, on a store a newer build recorded, a replay-semantics record this build cannot read, a store holding more than its own workspace, an open merge, a stash sealed on a head it would move, or while another process holds the repository's runtime authority. On a store already current it does nothing, unless the workspace's binding history is no longer checked; then it re-derives and checks it again without rewriting the record. It exits non-zero when a step after the commit did not complete, and names the step; running it again finishes it.

Kin 0.7.21 does not read the store formats owed derivation records need. While the ledger holds records, this build writes the authority snapshot at format version 19 (20 when it carries a graph section) and journal frames at version 5. Kin 0.7.21 reads snapshot versions 13 through 16 and frame versions 2 to 3, and its source (release commit `67a772ec0`, `crates/kin-db/src/storage/format.rs` and `crates/kin-db/src/storage/authority_frame.rs`) refuses such a store with `incompatible snapshot schema: on-disk snapshot format version 19 is newer than the range this binary supports (versions 13 through 16); this graph was written by a newer Kin; upgrade Kin to a build that supports this snapshot`, or with `unsupported authority frame version: 5 (this kin-db reads versions 2 to 3); a newer kin-db wrote it, so open this store with a kin built on a kin-db that reads frame version 5`. Those messages are from 0.7.21's source, not observed by running 0.7.21 against such a store, and no path back to 0.7.21 is promised for a store this build has written.

### `kin completions`

Generate shell completions for bash, zsh, or fish

```
kin completions <shell>
```

| Argument | Required | Description |
| --- | --- | --- |
| `<shell>` | yes | Shell to generate completions for |
