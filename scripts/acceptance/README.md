# Product acceptance suites

Two falsifiable suites that ask whether the product still answers correctly.
`.github/workflows/acceptance.yml` runs both on every pull request against that
pull request's own build. Neither is release proof; both are regression gates.

Each suite prints one line per check:

```
CHECK <id> <ticket> PASS|FAIL|UNREADABLE <detail>
```

`UNREADABLE` is a third outcome and never a pass. It means the probe could not be
evaluated: no response, a payload that is not JSON, a focal entity that never
resolved, a field the fix has not defined yet. Exit status is 1 when any check
fails, 2 when none fail but some are unreadable, 3 on a setup error, and 0 only
when every selected check passes.

## What each suite proves

`magic_repro.py` covers the graph and MCP answer surfaces on small fixtures it
builds itself. Check 0 asserts the run stayed off the GPU. Checks 1 through 9
cover cross-file edges on the incremental commit path, absence authority on an
empty `find_references`, the completeness signal on a partial one, the
`dead-code` delete list against real references, call-edge precision against a
test double, `trace_data_flow` compact mode and localized truncation, JavaScript
entity kinds and edge density, virtual-environment admission and context-pack
byte arrays, and relation-graph completeness reporting. Every check names the
ticket it is about, so a failure is attributable without reading the code.

`brownfield_repro.py` covers reference enrichment on two pinned upstream trees,
`psf/requests` and `expressjs/express`, replayed as single-commit repositories
holding the exact pinned tree object. Check 0 asserts the run stayed off the GPU
and off every store but its own scratch `KIN_HOME`. Check 1 is the positive
control on JavaScript import specifiers. Checks 2 through 8 cover the two real
callers of `HTTPAdapter.send`, the `app.handle` walk in express, one verdict per
payload, `find_references` and `graph_neighborhood` agreeing on one entity, an
express export nothing may certify as unused, and `semantic_search` refusing to
certify a false absence.

The brownfield fixtures are one commit each, so its recall results are
one-commit-shape results. The suite prints that scope on every run and records it
in the JSON. History-shaped behavior, meaning conversion cost, provenance depth,
and commit peak memory, is not exercised here.

`brownfield_repro.py --self-test` exercises the verdict graders on fixed payloads
and needs no binary and no corpus. Each case is paired with its inverse, so a
grader that cannot tell its own cases apart fails rather than reporting a clean
product on a broken one.

## Running against a local build

```
cargo build --locked --bin kin --bin kin-daemon

python3 scripts/acceptance/magic_repro.py \
  --kin target/debug/kin --daemon target/debug/kin-daemon \
  --json acceptance/magic.json --verbose

python3 scripts/acceptance/brownfield_repro.py \
  --kin target/debug/kin --daemon target/debug/kin-daemon \
  --json acceptance/brownfield.json \
  --corpus-cache ~/.cache/kin-brownfield-repro --verbose
```

Both take `--only` to select check ids, `--workdir` to keep fixtures somewhere
known, `--keep` to leave them behind, and `--compare` a prior run's JSON so a
check that passed there and fails now reads REGRESSION rather than plain FAIL.
`brownfield_repro.py` also takes `--offline`, which refuses to fetch and requires
the corpus cache to already carry both pinned commits.

Two environment settings keep a run honest and both suites set them for
themselves: `KIN_DAEMON_AUTO_EMBED=0` keeps the run off inference, and
`KIN_VFS_DISABLE=1` keeps it off the filesystem projection. The workflow sets
`KIN_EMBED_BACKEND=cpu` as well. The brownfield suite's recall checks need a
language server on PATH; without one its enrichment sweep never runs and those
checks report UNREADABLE rather than a verdict. `scripts/ci-install-language-servers.sh`
is what provides one on a hosted runner.

## The umbrella copies

These two files were ported on 2026-08-21 from `bin/kin-magic-repro` and
`bin/kin-brownfield-repro` in the kin-ecosystem umbrella, and each carries a
header saying so. The umbrella copies still exist and are what the release
tooling calls: `bin/kin-release-preflight` copies `kin-magic-repro` into its run
root and runs it against the installed binaries on every install leg,
`bin/kin-shipped-gate` runs it against the binary npm actually served, and
`bin/kin-magic-at-scale` imports `kin-brownfield-repro` as a module to reuse its
checks 2 and 3 at real history depth.

Until those tools become wrappers around this directory, a change to either copy
has to be reconciled with the other. Three things are what make that
reconciliation mechanical and none of them should drift: the CHECK line format,
the exit codes, and the `kin-magic-repro:` and `kin-brownfield-repro:` prefixes on
the summary lines. `bin/kin-shipped-gate` parses two of those summary lines by
prefix, so renaming them breaks a release gate in another repository with nothing
in this one to catch it.
