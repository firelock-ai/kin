# AGENTS.md

This repository (`kin`) is part of the Kin ecosystem. The canonical source of truth for cross-repo
thesis, boundaries, lane arbitration and commit hygiene is the umbrella workspace's
**`kin-ecosystem/AGENTS.md`** (also symlinked as `kin-ecosystem/CLAUDE.md`), and it is loaded
automatically when you work inside the umbrella. Read it before making architectural or process
decisions. `CLAUDE.md` at this repo's root is a regular file that imports this one, because Claude Code reads
that filename and this repository's source is archived into kin-infra's promotion bundle, whose
validator refuses any non-regular entry; a symlink there failed production image promotion of
v0.6.4 after the release was already public. Edit this file, never that one, and keep every
tracked path in this repository a regular file.

## This repo's role

`kin` is the semantic system of record: repo format, CLI, daemon, MCP server, projections,
reconcile, review, provenance, execution, and the bundled seam packages and crates under `crates/`
and `packages/`. Work belongs here when it changes local semantic repo truth, projections or
reconcile, CLI, daemon or MCP behaviour, or provenance, review and execution semantics. Graph
internals go in `kin-db`; hosted collaboration goes in `kinlab`.

The graph is the authority. Runtime query paths must not answer by grepping, walking or ranking raw
filesystem contents, and `scripts/zero_file_search_guard.sh` is the gate that enforces it. When a
graph-backed answer cannot be produced, fail loud or report the gap rather than hiding it behind
raw file search.

## The inner loop

Two commands, both run from the umbrella root, both printing the path, sha and branch they resolved
before they grade anything:

```bash
bin/kin-parity            # builds kin and kin-daemon here, runs the release's own acceptance
bin/kin-precheck kin      # runs the lint, policy and guard gates ci.yml grades on
```

`bin/kin-parity` takes no gpu and no daemon lock and uses a scratch `KIN_HOME`. `bin/kin-precheck`
enumerates the gate list out of this repo's own `.github/workflows/ci.yml` rather than a remembered
copy, and refuses with no tally when a gate could not run. Beside them run `cargo test -p <crate>`
for the crates you touched. Do not reproduce the full workspace suite locally; hosted CI is the gate
of record for that.

The two required CI gates run, in substance:

```bash
cargo fmt -- --check
cargo clippy --all-targets --all-features -- <the allow list ci.yml assembles>
cargo nextest run --locked --partition count:<n>/3   # three shards
cargo test --doc --locked                            # nextest does not run doctests
python3 scripts/check-quarantine.py
bash scripts/zero_file_search_guard.sh
```

Both legs matter, including the case where nextest is green and the separate doctest pass is not.
Set `KIN_EMBED_BACKEND=cpu` for any gate; `bin/kin-lane run` does it for a heavy command. The
default is `auto`, which batches on the host's one Metal device, and concurrent gates sharing it
fail on host load rather than on their diff. cpu and metal differ in the last ULPs of every vector,
so a citable release-clean result never sets it.

## Non-obvious behaviours

**Acceptance grades main, not your pull request.** The `Product Acceptance` job carries
`if: ${{ github.event_name != 'pull_request' }}` (`.github/workflows/acceptance.yml:106`), and kin
has no merge_group since the flip to classic landing, so it reports `skipped` on every PR. Main's
own push run is the only grader, and a red one stops any release cut.

**The daemon's default port is 4219** (`crates/kin-daemon/src/bin/kin-daemon.rs:64`, and the usage
text beside it), and a running daemon records the port it actually took in `<kin_root>/daemon.port`.
A test that binds 4219 fails exactly like a real regression when a container or a stray daemon
already holds it, so read `lsof -nP -iTCP:4219 -sTCP:LISTEN` before believing a bind failure.

**`kin init` exits 7 on a store that is fine.** `EXIT_ENRICHMENT_UNATTESTED = 7`
(`crates/kin-cli/src/commands/init.rs:204`) says the store is real, publishable and answering
questions, and only that nobody can attest its enrichment finished, because a daemon was killed on
the way. `exit_code_for` returns it whenever a daemon kill record exists for the store. 8 is the
same shape for a reopen-acceleration section that did not persist. Neither is a failed conversion,
and neither is 1.

**Register the MCP server by absolute path, never as a bare `kin`.** The command is
`kin mcp start [--repo <path>]`, and the repository also resolves from `KIN_MCP_REPO`, then the
working directory, then the client's workspace roots. A bare `kin` resolves against the caller's
PATH, which inside a container carries neither `~/.kin/bin` nor an npm prefix, and which in this
fleet's login shell hits a VFS wrapper function that shadows the product binary.

**The release version lives in several files at once,** and `scripts/release-intent.mjs` with
`scripts/check-release-version.mjs` are what hold them in lockstep; the `Release version gate` job
runs them on every PR. Its `classifyPath` treats `.github/`, `docs/`, `AGENTS.md`, `CLAUDE.md`, any
markdown, and anything under a test or fixture directory as non-release, so a docs-only change needs
no bump.

## Landing

kin is a classic direct-merge repo. Its merge-queue ruleset was disabled on 2026-08-27 under
FIR-2815 and preserved only for a one-step rollback. Seven required contexts on main, read from
`/repos/firelock-ai/kin/rules/branches/main`: `DCO Sign-off`, `PR text hygiene`, `cargo-deny`,
`gitleaks (full history)`, `Fast gate lint and policy`, `Fast gate build and tests` and
`MCP surface contract`. Commit with `git commit -s`, and keep assistant-session traces out of the
PR title and body, which
`PR text hygiene` refuses. From the umbrella root, `bin/kin-lane merge enqueue kin <lane> <pr>`
records the row and `bin/kin-lane merge land kin <lane> <pr>` merges once every check has concluded
with zero failures.
