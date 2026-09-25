# kin

`kin` is the semantic system of record: repository format, CLI, daemon, MCP server, projections,
reconcile, review, provenance, execution, and the bundled crates and packages under `crates/` and
`packages/`. Work belongs here when it changes local semantic repository truth, projections or
reconcile, CLI, daemon or MCP behaviour, or provenance, review and execution semantics. Graph
storage and retrieval live in the bundled `crates/kin-db`. Hosted collaboration lives in `kinlab`.

## The graph is the authority

Runtime query paths answer from the graph. They never grep, walk or rank raw filesystem contents,
and `scripts/zero_file_search_guard.sh` enforces that. When the graph cannot produce an answer,
return an error or report the gap rather than falling back to raw file search. Ingestion, import,
reconcile, migration, projection, config and test IO may read files as explicit boundaries.

When the Kin MCP server is available, use it to read this repository. Find an entity with
`semantic_search` when you know its name or `semantic_locate` when you know only the behaviour,
then take `get_context_pack` on the best hit, and `find_references` or `impact_analysis` before
changing shared code. Read the `_kin` envelope on every answer, since an empty result is
trustworthy only when its `negative.safe_to_conclude_absent` says so.
[docs/gemini-extension-context.md](docs/gemini-extension-context.md) is the full tool guide, and
the Gemini CLI extension loads it as context.

## Checks

CI runs these, and `.github/workflows/ci.yml` holds the current flags and the jobs that apply to
a change:

```bash
cargo fmt -- --check
cargo clippy --all-targets --all-features -- <the allow list ci.yml assembles>
cargo nextest run --locked --partition count:<n>/3   # three shards
cargo test --doc --locked                            # nextest does not run doctests
python3 scripts/check-quarantine.py
bash scripts/zero_file_search_guard.sh
```

Run targeted crate tests for a behaviour change, and leave the full-workspace run to CI. Set
`KIN_EMBED_BACKEND=cpu` for any gate. The default, `auto`, batches on the host's single Metal
device, and concurrent gates that share it fail on host load rather than on their diff. CPU and
Metal differ in the last ULPs of every vector, so a citable release-clean result never sets it.

Keep every tracked path a regular file. The release image promotion archives this source, and
its bundle validator refuses any non-regular entry, including a symlink.

## Non-obvious behaviours

**Acceptance grades main, not your pull request.** The `Product Acceptance` job in
`.github/workflows/acceptance.yml` carries `if: ${{ github.event_name != 'pull_request' }}`, so
it reports `skipped` on every PR. Main's own push run is the only grader, and a red one stops any
release cut.

**The daemon's default port is 4219** (`crates/kin-daemon/src/bin/kin-daemon.rs`), and a running
daemon records the port it actually took in `<kin_root>/daemon.port`. A test that binds 4219
fails exactly like a real regression when a container or a stray daemon already holds the port,
so read `lsof -nP -iTCP:4219 -sTCP:LISTEN` before believing a bind failure.

**`kin init` exits 7 on a store that is fine.** `EXIT_ENRICHMENT_UNATTESTED` in
`crates/kin-cli/src/commands/init.rs` says the store is real, publishable and answering, and
only that nobody can attest its enrichment finished, because a daemon was killed on the way.
`exit_code_for` returns it whenever a daemon kill record exists for the store. Exit 8 is the same
shape for a reopen-acceleration section that did not persist. Neither is a failed conversion, and
neither is 1.

**Register the MCP server by absolute path, never as a bare `kin`.** The command is
`kin mcp start [--repo <path>]`, and the repository also resolves from `KIN_MCP_REPO`, then the
working directory, then the client's workspace roots. A bare `kin` resolves against the caller's
PATH, which inside a container carries neither `~/.kin/bin` nor an npm prefix.

**The release version lives in several files at once.** `scripts/release-intent.mjs` and
`scripts/check-release-version.mjs` keep them in lockstep. The `Release version gate` job runs
them on pull requests from `automation/release-next` or labelled `release:automated`, and an
ordinary pull request is not graded by it. Its `classifyPath` treats `.github/`, `docs/`,
`AGENTS.md`, any markdown, and anything under a test or fixture directory as non-release, so a
docs-only change needs no version bump.

## Landing

kin is a classic direct-merge repository. Its merge-queue ruleset was disabled on 2026-08-27 and
kept only for a one-step rollback. Seven required contexts on main, read from
`/repos/firelock-ai/kin/rules/branches/main`: `DCO Sign-off`, `PR text hygiene`, `cargo-deny`,
`gitleaks (full history)`, `Fast gate lint and policy`, `Fast gate build and tests` and
`MCP surface contract`. Commit with `git commit -s`, and keep assistant-session traces out of the
PR title and body, which `PR text hygiene` refuses.
