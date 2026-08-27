# Product acceptance suites

Falsifiable suites that ask whether the product still answers correctly, and one
that asks whether it still tells the truth before it answers anything.
`.github/workflows/acceptance.yml` runs them all on every pull request against
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
Checks 18 through 20 cover what FIR-2644 adds to the same commit: the caller set
must be unchanged including a caller composed through an override, every
reference line a caller reports must still carry the call when read against the
file on disk, and an answer taken over a graph short of its own census must
disclose that rather than presenting as clean. Each of the three runs its own
control, and they share one experiment because the experiment is destructive.
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

`hydration_semantics_repro.py` covers the durable replay-semantics version
recorded when a store is created. It builds one fresh repository and requires
the control to stay silent on `kin graph status`, report a healthy
`hydration_semantics` doctor row, and omit `hydration_semantics_stale` from the
stdio MCP envelope. It then plants stamps one version behind and ahead, removes
the stamp entirely, and plants an incompatible future-schema stamp. All four
gap arms must disclose on all three surfaces with direction-safe advice. The
current-store control is what prevents an always-warning comparator or a
missing writer from satisfying the suite.

`brownfield_repro.py` covers reference enrichment on two pinned upstream trees,
`psf/requests` and `expressjs/express`, replayed as single-commit repositories
holding the exact pinned tree object. Check 0 asserts the run stayed off the GPU
and off every store but its own scratch `KIN_HOME`. Check 1 is the positive
control on JavaScript import specifiers. Checks 2 through 8 cover the two real
callers of `HTTPAdapter.send`, the `app.handle` walk in express, one verdict per
payload, `find_references` and `graph_neighborhood` agreeing on one entity, an
express export nothing may certify as unused, and `semantic_search` refusing to
certify a false absence. Check 9 kills a `kin init` mid-conversion and asserts the
next command names the kill, the re-run says whether it resumes or restarts, and
nothing is orphaned silently. Check 10 replays the rc0550 brown stranger's task 3
verbatim, at that run's own budget, and requires the walk to reach the hop that
folds `verify` into the urllib3 pool key and every external node it touches to
name what it crosses into.

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
both with an unpressured control (FIR-2614). Checks 0 to 3 cover the host half
and 4 and 5 the daemon's own budget, including that a budget refusal blames the
budget rather than the machine.

Checks 6 to 9 carry the same rule to a daemon that did not back off in time and
was killed (FIR-2650). A daemon killed with SIGKILL is watched by nobody, so
until it recorded its own life it left no trace at all and every surface
downstream was free to call the silence an idle exit, which is what a measured
OOM on `psf/requests` was reported as. Check 6 kills a real daemon and asserts
the next start settles the death and that `kin graph status` and `kin doctor`
name it. Check 7 plants the record a kernel-attributed kill leaves and asserts
both surfaces quote the ceiling, because "the daemon died" invites a re-run and
"it hit the memory limit at 12.0 GiB" does not. Check 8 grades the sentence the
measured run actually printed, asking a lost request over a killed daemon, and
its control requires the ordinary idle-window explanation to survive where the
daemon really did retire. Check 9 grades the store's own enrichment line, which
read "completion not attested" over a killed daemon and was byte-identical to a
healthy store whose enrichment was merely uncertified.

Checks 10 and 11 cover the reading the back-off decides on (FIR-2653). Summing
resident sets across a process tree charges every shared page once per process,
so the v0.5.51 stranger read a daemon and thirteen children holding 25.3 GiB
inside a container hard-capped at 12, and background embedding refused on all
three of its stores. Check 10 grades the published figure against the kernel's
own proportional and resident readings for the same pid, taken here rather than
asked of kin, and against what the cgroup is charged wherever a cap binds the
daemon; where no cap does, it says so in its own line rather than reporting an
arm it never ran. Check 11 grades the whole tree the same way, since
"of which 23.1 GiB is in those child processes" is where the defect bit, and
then sets a budget just above the tree's summed resident set, where the pre-fix
reading sits at the refusal bar and the proportional one sits near two thirds;
that arm runs only where the two readings are at least 30% apart and says so
when they are not. Its control, a store under a one-byte budget, must still back
off, because a build that had stopped backing off at all would pass every arm
above it. Both checks are Linux, and both say so off it: the macOS reader
(`phys_footprint` through `proc_pid_rusage`) has unit coverage in
`kin-daemon-spawn` and no end-to-end arm here, because there is no second kernel
figure to grade it against without root.

Check 12 grades the TREE that reading was taken over (FIR-2823). Linux lists a
process's threads under `/proc/<pid>/task` and `sysinfo` returns them from
`processes()` beside real processes, each with its own tid as a pid and its
owning process as its parent, so a walk that does not exclude them counts one
daemon once per thread. Threads share an address space, so each reads back the
whole process's proportional set, and the v0.6.1 stranger was shown a 1.41 GiB
daemon published at 10.35 GiB with `child_count: 11` against zero child
processes. Check 11 could not catch it: when the published `child_count`
disagrees with the descendants it reads, it declines to grade on the reasoning
that the two readings are of different trees, and a daemon counting its threads
produces that disagreement on every run, so the arm skipped and the suite passed.
Check 12 grades that number, reading the descendant set before and after the
standing is published and grading only where the two agree, so a short-lived
child during init is an unreadable tree rather than a defect. Its control is the
reason it can fail at all and is asserted rather than assumed: a single-threaded
process counts its threads and its child processes to the same number, so a
one-thread daemon is reported UNREADABLE and never banked as a pass. Linux, and
it says so off it, for the same reason as the two above.

Checks 10 and 11 run twice in CI, and the second run is the one that can fail. A
runner has no memory cap, so check 10's cgroup arm has nothing to hold a
published figure under and check 11's derived budget is gigabytes; the workflow
therefore runs `--only 10 --only 11` again inside `docker run --memory=2g`, which
is the shape the defect was found in. Check 12 needs no cap, because a thread
count is not a budget, so it runs once with the rest. Against shipped 0.5.51 bytes in exactly that
setup both checks FAIL, quoting a daemon and twenty-three children published as
holding 1.45 GiB inside a container the kernel charged 283 MiB, and a rung of
`critical` against a derived budget of 1 GiB while the tree held 62 MiB.

Both also wait for a standing rather than reading one. A daemon publishes on a
pressure call, and those arrive from the enrichment sweep, which needs a
language server to exist, or from the ambient reconcile tick, which needs the
working copy to move. Reading the file the instant `graph status` returns read
an absent one and reported UNREADABLE twice against real bytes, so the suite
retires the old record, writes a file, asks for status, and waits.

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

`first_contact_honesty.py` covers the three surfaces a stranger meets before the
graph answers anything, all found by the npm0549 green stranger on shipped
0.5.49. Check 0 asserts `kin commit --help` carries the same sentence a commit
prints, that a Kin commit lands in Kin's own authority and `git status` stays
dirty until `kin eject` or a push, and asserts the CLI reference quotes it too
(FIR-2627). Check 1 packs `packages/kin`, makes a global npm prefix unwritable,
proves `npm install -g` is refused there exactly as it is in a container, then
runs the README's own leading shell block against that machine and requires it to
reach a working `kin --version` (FIR-2628). Check 2 points a real npm at a port
nothing listens on and requires the language-server install failure to name the
environment as the suspected cause, print the proxy variables that would route
it, name the offline route to a working server, and state that Kin runs
without the servers (FIR-2629).

Two limits it states rather than hides. Check 1 stubs the archive download with
`KIN_NO_PROVISION` and a seeded managed binary, so what it proves is that the
documented first path does not need the prefix that is refused, not that the
download works; the release install proof owns that half. And check 1 reports
UNREADABLE rather than PASS when the global install SUCCEEDS against the prefix
it made unwritable, which is what happens as root, because a probe that cannot
see its own wall has not passed.

Check 2's network error is npm's own, produced by a real npm against a closed
port, never a stub printing the words the classifier looks for. When the install
dies of something that is not the network, the check reports UNREADABLE and says
which reason it got, because a classifier that was never asked the question has
not answered it.

`eject_journal_repro.py` covers the eject archive round trip the rc0552n green
stranger lost on 0.5.52 (FIR-2664). A finished `kin eject` left its journal in
the archived `kin/` at the detach phase, `cp -r` of that archive back to `.kin`
carried the journal along under fresh inodes, and every `kin commit` after that
answered `HTTP 500 ... invalid identity-bound descriptor` until the store was
deleted. Check `archive` asserts a finished eject leaves no journal beside the
archived authority key. Check `copyback` copies the archived `kin/` back with
`cp -R` and requires the next commit to land. Check `carried` plants a journal
in the exact shape 0.5.52 wrote, keyed to the fixture's own authority key and
bound to the archived `kin/`, lets the copy carry it back, and requires the
commit to land and the carried copy to be retired while the archive's own is
untouched. Check `refusal` plants a journal bound to nothing the store can
verify and requires the refusal to name the file and the remedy in words, with
no `HTTP 500`, `Internal Server Error` or `Core error` in it, then removes the
file as the message says and requires the same store to commit. Check `hook`
covers the second half of the same run: `kin eject` builds its replacement Git
with gitoxide, whose template writes `.git/hooks/docs.url`, a URL Git never
runs, and `kin init` refused the ejected repository over it; the check requires
`kin init` to re-admit past it and, as its control, still to refuse an
executable `pre-commit` by name. Eject is Unix-only, and so is the suite.

`verdict_limits_repro.py` covers the one-verdict contract the rc0552s green
stranger caught 0.5.52 breaking (FIR-2672): `find_references` on a Python
function answered `verdict.state: certified`, `completeness.status: complete`,
`bound: exact` and "the counts here are the whole set" in the same `_kin` block
that recorded `classes.imports: absent` and `limits: [edge_coverage:imports_absent]`,
and the rename the stranger made on the certified sites broke on the import
sites Kin could never read. Every release since the one verdict existed (0.5.43)
certified that way, because the verdict weighed `calls` alone. Check `invariant`
queries a three-file Python package whose files reach one another through every
class the verdict reads (imports, calls, and a class used as an annotation and
read through its attributes, which a language server resolves into references)
with the default classes, and requires that no requested class read anything but
`present` while the verdict certifies: a short class must make the verdict
inconclusive, be named in the limiting factor and in `limits`, and turn
`status`, `bound` and `counted.exact` into a floor; with every class present the
verdict must certify. Check `inverse` is the control that keeps that from being
satisfied by refusing everything, and it prefers the genuine arm: on a build
whose linker produces entity-level import edges, the default query has every
requested class present and must certify with `limiting_factor: null` and an
exact count; on a build whose linker does not, it falls back to the same focal
over `calls` alone, a class the fixture proves present, and names which arm ran.
Check `unproduced` requires the import class to read `unproduced` (a build whose
linker emits no entity-level import edge) or `present` (one whose linker does),
never `absent`, on a source whose files import one another. Check `two_reasons`
runs the same query under the server's smallest response budget, which withholds
rows and refuses on its own, and requires every input the verdict records as
inconclusive to keep its clause in `limiting_factor`, each label once: the
budget's clause beside the class gap on a build that cannot produce the import
class, the budget's clause alone on one that can. The self-test feeds the
graders the exact 0.5.52 envelope, which must fail, beside the fixed shape and
the all-present shape, which must pass, and a factor that kept one clause and
dropped the rest, which must fail. Both worlds pass, and the shipped shape fails
in both.

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

python3 scripts/acceptance/first_contact_honesty.py \
  --kin target/release/kin --daemon target/release/kin-daemon \
  --json acceptance/first_contact.json --verbose

python3 scripts/acceptance/eject_journal_repro.py \
  --kin target/release/kin --daemon target/release/kin-daemon \
  --json acceptance/eject_journal.json --verbose

python3 scripts/acceptance/verdict_limits_repro.py \
  --kin target/release/kin --daemon target/release/kin-daemon \
  --json acceptance/verdict_limits.json --verbose
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
