# Product acceptance suites

Seven falsifiable suites that ask whether the product still answers correctly.
`.github/workflows/acceptance.yml` runs all seven on every pull request against
that pull request's own build. None is release proof; all are regression gates.

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
byte arrays, and relation-graph completeness reporting. Checks 10 and 11 cover
the pair FIR-2598 reports: a comment-only commit must keep every relation kind
it had, and the census must be able to see a kind that lost ground once one
does. Check 11 raises the recorded baseline by one edge over an unchanged entity
count rather than damaging the graph, because the loss that started the ticket
was 0.9% of its kind and no magnitude threshold was ever going to reach it.
Every check names the ticket it is about, so a failure is attributable without
reading the code.

`parse_hole_repro.py` covers what the others cannot see: a file the
repository admits that produced no entity at all. It builds a JavaScript library
of four modules that declare a function beside three that are valid source and
declare nothing, then asserts that `kin graph status` publishes the per-language
ratio and names the silent paths, and that `kin doctor` carries a
`parse_coverage` row that does the same. Each check runs the same probe against
a control repository whose files all produce entities and asserts that no file
is named there, so a surface that reported unconditionally fails here rather
than passing on the control alone.

It asserts no verdict, deliberately. A file that produced no entity is not on
its own evidence that anything failed: a side-effect script, a re-export and a
comment-only file each correctly produce nothing, and no graph-owned signal
separates those from a file an adapter could not read. The doctor row must stay
`healthy`, and this suite fails if it does not, because a row that went red on
the count would go red on most JavaScript repositories.

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

`response_budget_elisions.py` covers the one rule the response budget owes every
answer it shortens: a list it cut is never rendered as an empty one. An empty
array is the shape a reader takes for "the walk found none", and the v0.5.47
stranger read `"affected_tests": []` beside a `covering_tests: 16` twice in one
session and drew the wrong conclusion both times, with a sibling
`affected_tests_withheld` counter sitting in the same response. Check 0 cuts a
trace and asserts the chain keeps a step and publishes `elisions.chain`. Check 1
walks an entity with no callees and asserts the empty chain claims no elision, so
an empty array still means one thing. Check 2 reads `tools/list` and asserts every
advertised budget sits under what a real MCP client accepts. Check 3 runs one
query at the ceiling and again at the floor and asserts nothing full in the first
is empty in the second, which needs no counter to be true.

Check 4 covers the rule underneath that one: a response has to be counted before
it can be cut. `impact_analysis` reported `bounded: false` beside a
`chars_before_budget` of 50,354 against a 2,000-character ceiling and shipped all
50,354, because the budget's shape table named only the four `affected_*` buckets
and the bulk of an impact report is not in them (FIR-2602). The check runs one
impact query at the ceiling and again at the floor over every list the report can
carry, asserts none of them was emptied, and reads the response's own accounting:
`bounded: false` asserts the response fits, so it has to fit, and a response that
does not fit has to say so in `degradations`. A ceiling is not always reachable,
because every cut list keeps a floor entry, and that case is fine as long as it is
never quiet.

Checks 5 to 7 carry the same rule to the budget that cuts a context pack first
(FIR-2482). A pack is bounded twice: its own token budget refuses candidates
inside the builder, before the response budget sees the payload at all, and only
the second cut was ever disclosed. A dependency section trimmed from twelve rows
to six serialized six rows beside `returned: 6`, which is what a focal with six
dependencies serializes, and `kin context` printed "Dependencies: 6 entries" for
both. Check 5 packs one focal at a generous token budget and again at a tight
one, with one identical generous `max_chars` on both so the response budget
cannot be the cutter, and asserts every group that shrank publishes an elision
naming `token_budget` rather than `response_budget`, because a caller told the
wrong cause raises the wrong lever. Check 6 is the same defect one field down: a
row whose inline source the response budget took used to lose the key outright,
which is the shape of a `compact` call and of source the graph never had, so it
now keeps a null `body` beside a marker naming what went. Check 7 drives
`kin context`, whose rendered lines are the whole of what a reader of that
surface sees, and asserts the lines and `--json` report the same cut and name the
lever that recovers it.

`memory_pressure_refusal.py` covers the back-off Kin owes a machine it is
running on, and the disclosure it owes the person running it. A daemon that
quietly stopped sweeping would look identical to one that had finished, since
every counter on every surface keeps reporting the unenriched files as pending
work, so each check grades the refusal and the disclosure together and pairs
both with an unpressured control (FIR-2614).

`init_memory_repro.py` covers what a brownfield conversion holds while it runs.
A full-history `psf/requests` conversion measured 11.72 GiB of resident set
inside a 12 GiB container, because proving an import plan rebuilt the whole plan
from raw objects and compared the two, holding several whole histories at once
(FIR-2539). No functional test can see that class: a re-derivation that
materializes a second copy returns the same verdict as one that streams it. The
suite drives the live-heap guard in `crates/kin-core/tests/` and grades what
proof 1 adds to the running peak, through a counting allocator rather than
resident set, because RSS keeps counting freed pages and inside a memory-limited
container both a fixed and an unfixed build report the ceiling rather than their
demand.

`registry_home_isolation.py` covers the boundary `KIN_HOME` is supposed to draw.
The cross-repo registry is store state, and it used to sit outside that boundary
because the registry file's parent doubled as the machine-level supervisor
directory, so a daemon under a scratch home read the operator's registry and
pinned sibling authority for every repository on the box (FIR-2467). The suite
builds two homes, registers repositories into each, and asks `kin deps`, `kin
registry` and a scratch-home daemon's own log what they can see. Every check
carries the control that keeps it from passing for the wrong reason, including
one that requires an unbindable sibling in the scratch home to still draw the pin
warning, so a sealed reading is a sealed daemon and not a daemon that stopped
pinning anything. Check 3 asserts the other half: the registry moves with
`KIN_HOME` and the supervisor does not, because one supervisor holds daemons from
several managed homes and following `KIN_HOME` would hide from a pinned session
the daemons it shares the box with. Every probe leaves `KIN_REGISTRY_PATH` unset
on purpose, since an explicit pin wins on both sides of that fix and a probe that
kept one could not fail.

`brownfield_repro.py --self-test` and `response_budget_elisions.py --self-test`
exercise their verdict graders on fixed payloads and need no binary and no
corpus. Each case is paired with its inverse, so a grader that cannot tell its
own cases apart fails rather than reporting a clean product on a broken one. That
pairing has already earned its keep: one elision grader passed a deliberately
broken product because its fixture sat under the budget and never reached the
code the check was about.

## Running against a local build

```
cargo build --release --locked --bin kin --bin kin-daemon

python3 scripts/acceptance/magic_repro.py \
  --kin target/release/kin --daemon target/release/kin-daemon \
  --json acceptance/magic.json --verbose

python3 scripts/acceptance/brownfield_repro.py \
  --kin target/release/kin --daemon target/release/kin-daemon \
  --json acceptance/brownfield.json \
  --corpus-cache ~/.cache/kin-brownfield-repro --verbose

python3 scripts/acceptance/response_budget_elisions.py \
  --kin target/release/kin --daemon target/release/kin-daemon \
  --json acceptance/response_budget.json --verbose

python3 scripts/acceptance/registry_home_isolation.py \
  --kin target/release/kin --daemon target/release/kin-daemon \
  --json acceptance/registry_isolation.json --verbose
```

Release, not debug. Release is what ships, so it is what an acceptance answer
should be about, and the profile has already been shown to change an answer: on
the first CI run a debug build truncated a data-flow walk that a release build
walked whole (FIR-2593).

`magic_repro.py` and `brownfield_repro.py` take `--only` to select check ids,
`--workdir` to keep fixtures somewhere known, `--keep` to leave them behind, and
`--compare` a prior run's JSON so a check that passed there and fails now reads
REGRESSION rather than plain FAIL. `brownfield_repro.py` also takes `--offline`,
which refuses to fetch and requires the corpus cache to already carry both pinned
commits. `response_budget_elisions.py` builds its own fixture, fetches nothing,
and takes `--workdir` and `--verbose`. `registry_home_isolation.py` builds both
of its homes and all four of its repositories itself, fetches nothing, and takes
`--keep` and `--verbose`.

The magic suite's fixtures commit through kin, and kin refuses to invent an
author, so the machine running them needs a git identity. That refusal is
correct product behavior, not an obstacle: an invented author cannot be
corrected later without rewriting history, so kin declines rather than guessing.
A developer machine already has one; the workflow sets one explicitly, because a
hosted runner does not, and without it every fixture that commits through kin
fails to build and its checks report UNREADABLE.

Two environment settings keep a run honest and both suites set them for
themselves: `KIN_DAEMON_AUTO_EMBED=0` keeps the run off inference, and
`KIN_VFS_DISABLE=1` keeps it off the filesystem projection. The workflow sets
`KIN_EMBED_BACKEND=cpu` as well. The brownfield suite's recall checks need a
language server on PATH; without one its enrichment sweep never runs and those
checks report UNREADABLE rather than a verdict. `scripts/ci-install-language-servers.sh`
is what provides one on a hosted runner.

## The gate

`gate.py` decides the CI job. It reads the suites' JSON reports rather than their
exit codes, because an exit code is one lever with two settings, demand a clean
sweep or demand nothing, and neither is right while one check is blocked on
something outside the change under review.

A FAIL always fails the gate and no allowance can excuse it. An UNREADABLE fails
too unless `--allow-unreadable SUITE:CHECK=REASON` names it, the reason is
required, and every allowance prints on every run. Three rules keep that list
from becoming a way to stop enforcing: an allowance naming a check the report
does not carry is an error, because a pointer at nothing looks exactly like a
satisfied allowance; an allowance on a check that now passes is announced as
stale; and a missing or unparseable report is a failure, because a suite that
wrote nothing did not pass.

`gate.py --self-test` exercises every one of those rules against its inverse and
needs no reports. The workflow runs it before the build, alongside the brownfield
graders' self-test, so a gate that has stopped deciding is named in seconds.

An allowance is meant to be temporary and every one of them names the ticket that
will remove it. Check the workflow for the current list before assuming a green
job means every check passed.

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
