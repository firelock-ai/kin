#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

"""Prove a budget-cut list never ships as an empty one, on the real binary.

FIR-2600. The v0.5.47 brownfield stranger read `"affected_tests": []` beside a
`covering_tests: 16` that contradicted it, twice in one session, and drew the
wrong conclusion both times. An empty array is the shape a reader takes for "the
walk found none", and no counter elsewhere in the response outranks it.

So this suite asserts both directions on one walk each, because either half alone
can be satisfied by a broken tool:

  0  a walk the budget cut keeps at least one step and publishes `elisions.chain`
     with a count and a reason that agree with `steps_omitted` and the chain
  1  a walk that reached nothing still answers with an empty chain and claims no
     elision, so an empty array means exactly one thing
  2  the budget the tool advertises is the budget it enforces, and its ceiling is
     one a real MCP client accepts
  3  no ranked list the budget cuts ships empty
  4  a response the budget could not bring under its ceiling says so, and one
     reporting `bounded: false` is one that fits
  5  a pack cut by its own token budget publishes what it cut, under that
     budget's name, and leaves no group empty
  6  a row whose inline source the budget took says so on the row
  7  `kin context` names the same cut in its lines and in its `--json`

FIR-2482 is checks 5 to 7, and it is the same rule reached through the OTHER
budget. A context pack is cut twice: its own token budget refuses candidates
inside the builder, before the response budget sees anything, and only the
second cut was ever disclosed. A dependency section trimmed from twelve rows to
six serialized `returned: 6` beside six rows, which is exactly what a focal with
six dependencies serializes, and `kin context` printed "Dependencies: 6 entries"
for both. The body case is the same defect one field down: a row that lost its
source to the budget lost the key outright, which is the shape of a `compact`
call and of source the graph never had.

FIR-2602 is check 4. `impact_analysis` reported `{"bounded": false,
"chars_before_budget": 50354, "max_chars": 2000}` and shipped all 50,354
characters, because the shape table named only the four `affected_*` buckets and
the bulk of an impact report is not in them. A bucket the table does not name is
a bucket the bounder cannot count, and nothing in the response said so.

Exit status is 0 when every check passed, 1 when one failed, 2 when one could not
be read, and 3 when the run could not be set up. `--self-test` exercises every
grader against its inverse and needs no binary, so a grader that cannot fail is
a failure here rather than a silent pass in CI.
"""
from __future__ import print_function

import argparse
import functools
import json
import os
import shutil
import subprocess
import sys
import tempfile

PASS = "PASS"
FAIL = "FAIL"
UNREADABLE = "UNREADABLE"

print = functools.partial(print, flush=True)

# The largest payload the v0.5.47 stranger run proved a real MCP client refuses.
# The ceiling this server advertises has to sit below it, or the tool is telling
# callers to ask for a result their client will throw away.
REFUSED_BY_A_REAL_CLIENT = 117313


# Every list an `impact_analysis` response carries, mirroring the shape table in
# crates/kin-mcp/src/budget.rs. Listed here so a key added to the response and
# not to the table is a check that grades nothing rather than a silent gap: the
# check reports UNREADABLE when it grades none of them.
IMPACT_LISTS = [
    "entity_impacts",
    "affected_callers",
    "affected_dependents",
    "affected_contract_consumers",
    "affected_tests",
    "unreviewed_agent_changes",
    "changed_ids",
    "actor_attribution",
    "affected_work_items",
    "affected_annotations",
    "cross_repo_impact",
    "active_traffic",
]

# The reason code a response still over its ceiling publishes.
OVER_BUDGET_REASON = "response_over_budget"

# Callees on the wide focal. Sized so the whole pack clears the pack token
# budget's 8,000 floor several times over while the serialized response stays
# well under the 60,000-character response ceiling, which is what lets check 5
# attribute a cut to one budget rather than to two.
WIDE_CALLEES = 35


class SetupError(Exception):
    """The run could not be set up. Never a pass, never a check failure."""


class Result(object):
    """One check's verdict, which starts unproven and can only be lowered."""

    def __init__(self, ident, ticket, title):
        self.id = ident
        self.ticket = ticket
        self.title = title
        self.notes = []
        self.failed = False
        self.unread = False

    def ok(self, detail):
        self.notes.append(detail)

    def bad(self, detail):
        self.failed = True
        self.notes.append(detail)

    def unknown(self, detail):
        self.unread = True
        self.notes.append(detail)

    @property
    def status(self):
        if self.failed:
            return FAIL
        if self.unread:
            return UNREADABLE
        return PASS

    @property
    def detail(self):
        return "; ".join(self.notes)

    def row(self):
        return {
            "id": self.id,
            "ticket": self.ticket,
            "title": self.title,
            "status": self.status,
            "detail": self.detail,
        }


def grade_cut_walk(payload):
    """Grade a walk the budget cut. Returns a list of complaints, empty on pass.

    Kept separate from the run so `--self-test` can hand it a payload carrying
    the exact defect and watch it fail.
    """
    problems = []
    chain = payload.get("chain")
    if not isinstance(chain, list):
        return ["the response carries no chain array"]
    omitted = payload.get("steps_omitted")
    if not isinstance(omitted, int) or omitted <= 0:
        return ["the walk was not cut, so this check proves nothing"]
    if not chain:
        problems.append(
            "the budget emptied a chain it cut: an empty array reads as "
            "'the walk found none' and %d steps were withheld" % omitted
        )
    elisions = payload.get("elisions")
    if not isinstance(elisions, dict) or "chain" not in elisions:
        problems.append("a cut chain published no elision under `elisions.chain`")
        return problems
    elision = elisions["chain"]
    if elision.get("elided") != omitted:
        problems.append(
            "elisions.chain.elided is %r and steps_omitted is %r"
            % (elision.get("elided"), omitted)
        )
    if elision.get("kept") != len(chain):
        problems.append(
            "elisions.chain.kept is %r and the chain carries %d"
            % (elision.get("kept"), len(chain))
        )
    if elision.get("total") != len(chain) + omitted:
        problems.append(
            "elisions.chain.total is %r and kept plus elided is %d"
            % (elision.get("total"), len(chain) + omitted)
        )
    if not elision.get("reason"):
        problems.append("elisions.chain names no reason")
    return problems


def grade_empty_walk(payload):
    """Grade a walk that genuinely reached nothing."""
    problems = []
    chain = payload.get("chain")
    if not isinstance(chain, list):
        return ["the response carries no chain array"]
    if chain:
        return ["the fixture reached %d steps, so this check proves nothing" % len(chain)]
    if payload.get("steps_omitted"):
        problems.append(
            "an untouched walk reports steps_omitted %r" % payload.get("steps_omitted")
        )
    elisions = payload.get("elisions") or {}
    if elisions:
        problems.append(
            "a walk that withheld nothing claims an elision: %s" % json.dumps(elisions)
        )
    return problems


def grade_advertised_budget(schema):
    """Grade one tool's advertised budget against what a client accepts."""
    problems = []
    ceiling = schema.get("maximum")
    default = schema.get("default")
    floor = schema.get("minimum")
    if not isinstance(ceiling, int):
        return ["the schema advertises no maximum"]
    if ceiling >= REFUSED_BY_A_REAL_CLIENT:
        problems.append(
            "the advertised ceiling %d is at or above the %d a real client refused"
            % (ceiling, REFUSED_BY_A_REAL_CLIENT)
        )
    if not isinstance(default, int) or not isinstance(floor, int):
        problems.append("the schema advertises no default or no minimum")
        return problems
    if not floor < default <= ceiling:
        problems.append(
            "the advertised default %d does not sit inside %d..%d"
            % (default, floor, ceiling)
        )
    return problems


def grade_budget_accounting(payload):
    """Grade one response's own account of what the budget did to it.

    Two claims, both readable off the response alone:

      * `bounded: false` asserts the response fits, so it has to fit. This is
        the FIR-2602 defect exactly: false beside a size 25 times the ceiling.
      * a response that does NOT fit says so in `degradations`, because every
        list keeps a floor entry and a ceiling is not always reachable. Rare and
        real is fine; quiet is not.
    """
    problems = []
    accounting = ((payload.get("_kin") or {}).get("response")) or {}
    if not accounting:
        return ["the response carries no `_kin.response` accounting"]
    max_chars = accounting.get("max_chars")
    before = accounting.get("chars_before_budget")
    after = accounting.get("chars_after_budget")
    if not isinstance(max_chars, int) or not isinstance(before, int):
        return ["the accounting names no max_chars or no chars_before_budget"]
    if not isinstance(after, int):
        return [
            "the accounting reports no chars_after_budget, so nothing in the response "
            "says what size it shipped at"
        ]
    bounded = accounting.get("bounded")
    if bounded is not True and bounded is not False:
        problems.append("the accounting reports bounded %r" % bounded)
    if bounded is False and after > max_chars:
        problems.append(
            "the accounting reports bounded false at %d characters against a %d ceiling"
            % (after, max_chars)
        )
    reasons = [
        entry.get("reason")
        for entry in (payload.get("degradations") or [])
        if isinstance(entry, dict)
    ]
    if after > max_chars and OVER_BUDGET_REASON not in reasons:
        problems.append(
            "the response measures %d against a %d ceiling and publishes no %s "
            "degradation" % (after, max_chars, OVER_BUDGET_REASON)
        )
    if after <= max_chars and OVER_BUDGET_REASON in reasons:
        problems.append(
            "the response fits at %d against a %d ceiling and claims it does not"
            % (after, max_chars)
        )
    return problems


# Groups a context pack's own token budget can cut, under the names both
# `kin context` and `get_context_pack` publish them by. Listed here so a group
# added to the pack and not to this list is a check that grades less rather than
# a silent gap: the check reports UNREADABLE when it grades none of them.
PACK_GROUPS = ["dependencies", "dependents", "transitive_deps", "tests", "contracts"]

# The reason code a row the pack's token budget refused carries. Distinct from
# `response_budget` on purpose: a caller raises one with `token_budget` and the
# other with `max_chars`, and being told the wrong lever costs a round trip that
# cannot help.
TOKEN_BUDGET_REASON = "token_budget"


def grade_pack_token_budget(whole, cut):
    """Grade a pack cut by its token budget against the pack that was not.

    The inference needs no counter: anything the walk found at the generous
    budget it still found at the tight one, so a group full at the ceiling and
    short at the floor was cut by the token budget and by nothing else. Two
    things would break that, and both are asserted rather than assumed. The
    caller pins one identical, generous `max_chars` on both calls, so the
    response budget cannot be the cutter; and the focal's section must ride
    dependency edges, so the same-file cap cannot be either.
    """
    problems = []
    graded = 0
    if not isinstance(whole, dict) or not isinstance(cut, dict):
        return ["a pack response was not an object"], 0
    source = (cut.get("dependency_selection") or {}).get("source")
    if source != "dependency_edges":
        problems.append(
            "the focal fell back to same-file neighbours (source %r), so the cap and the "
            "budget cannot be told apart on this fixture" % source
        )
    for key in PACK_GROUPS:
        before = whole.get(key)
        if not isinstance(before, list) or not before:
            continue
        after = cut.get(key)
        if not isinstance(after, list):
            problems.append(
                "`%s` held %d entries at the generous budget and is absent at the tight "
                "one, which reads as 'the graph found none'" % (key, len(before))
            )
            continue
        if not after:
            problems.append(
                "`%s` held %d entries at the generous budget and [] at the tight one, so "
                "the budget emptied it" % (key, len(before))
            )
        if len(after) >= len(before):
            continue
        graded += 1
        elision = (cut.get("elisions") or {}).get(key)
        if not elision:
            problems.append(
                "`%s` fell from %d to %d entries and published no elision"
                % (key, len(before), len(after))
            )
            continue
        if elision.get("kept") != len(after):
            problems.append(
                "elisions.%s.kept is %r and the array carries %d"
                % (key, elision.get("kept"), len(after))
            )
        if elision.get("total") != len(before):
            problems.append(
                "elisions.%s.total is %r and the generous budget returned %d"
                % (key, elision.get("total"), len(before))
            )
        if elision.get("elided") != len(before) - len(after):
            problems.append(
                "elisions.%s.elided is %r and %d entries went"
                % (key, elision.get("elided"), len(before) - len(after))
            )
        if TOKEN_BUDGET_REASON not in (elision.get("reason") or ""):
            problems.append(
                "elisions.%s names %r, so a caller reads this as the response budget and "
                "raises the wrong lever" % (key, elision.get("reason"))
            )
    # The other direction, and it is what gives an absent disclosure its
    # meaning: a group the tight call returned whole must claim no loss.
    for key in PACK_GROUPS:
        before, after = whole.get(key), cut.get(key)
        if not isinstance(before, list) or not isinstance(after, list):
            continue
        if len(after) < len(before):
            continue
        elision = (cut.get("elisions") or {}).get(key)
        if elision and TOKEN_BUDGET_REASON in (elision.get("reason") or ""):
            problems.append(
                "`%s` returned all %d entries and still claims %r withheld"
                % (key, len(before), elision.get("elided"))
            )
    return problems, graded


def grade_body_elisions(payload):
    """Grade a pack whose inline source the response budget took.

    A row that simply loses its `body` key is byte-identical to a row from a
    `compact` call and to one whose source the graph does not hold. Both
    readings are wrong about a row the budget cut, and a count elsewhere in the
    response does not correct either: the reader looks at the row.
    """
    problems = []
    rows = [row for row in (payload.get("dependencies") or []) if isinstance(row, dict)]
    focal = payload.get("focal_entity")
    if isinstance(focal, dict):
        rows.append(focal)
    if not rows:
        return ["the cut response carried no row to grade"], 0
    elision = (payload.get("elisions") or {}).get("body")
    marked = 0
    for row in rows:
        if row.get("body") not in (None, ""):
            continue
        if not row.get("body_elided") and not row.get("body_unavailable"):
            problems.append(
                "row %r carries no source and says nothing about why, which is the shape "
                "of `compact` and of a graph gap alike" % row.get("name")
            )
            continue
        if row.get("body_elided") and row.get("body_unavailable"):
            problems.append(
                "row %r claims the budget took its body AND that the graph never had it"
                % row.get("name")
            )
        if row.get("body_elided"):
            marked += 1
    if marked == 0:
        return problems, 0
    if not elision:
        problems.append("%d rows lost their body and no elision was published" % marked)
        return problems, marked
    if not elision.get("elided"):
        problems.append("elisions.body claims nothing was withheld beside %d marked rows" % marked)
    elif elision["elided"] < marked:
        problems.append(
            "elisions.body counts %r withheld and %d rows say they lost one"
            % (elision.get("elided"), marked)
        )
    if not elision.get("reason"):
        problems.append("elisions.body names no reason")
    return problems, marked


def pack_sections(doc):
    """Row counts per section of a `kin context --json` pack, by the same group
    names the MCP tool publishes."""
    pack = (doc or {}).get("pack") or {}
    selection = (doc or {}).get("dependency_selection") or {}
    dependents = selection.get("dependents_returned") or 0
    signatures = pack.get("dependency_signatures")
    counts = {}
    if isinstance(signatures, list):
        counts["dependencies"] = len(signatures) - dependents
        counts["dependents"] = dependents
    for key, field in (
        ("transitive_deps", "transitive_deps"),
        ("tests", "tests"),
        ("contracts", "contracts"),
    ):
        rows = pack.get(field)
        if isinstance(rows, list):
            counts[key] = len(rows)
    return counts


def grade_cli_context(whole, cut, text):
    """Grade `kin context`, whose rendered lines are the whole of what a reader
    of that surface sees. A cut those lines do not name is, to that reader, a
    cut that did not happen.

    Graded off the same differential check 5 uses rather than off the
    disclosure alone: a section full at a generous `--budget` and short at a
    tight one was cut, whatever the response says about it. Grading only what
    the disclosure claims would let a build that discloses nothing report that
    nothing was cut, which is the defect wearing the check's own costume.
    """
    problems = []
    elisions = (cut or {}).get("budget_elisions") or {}
    before, after = pack_sections(whole), pack_sections(cut)
    graded = 0
    for key, full in sorted(before.items()):
        if not full or after.get(key, 0) >= full:
            continue
        graded += 1
        kept = after.get(key, 0)
        if key not in elisions:
            problems.append(
                "`%s` fell from %d rows to %d and the response publishes no elision for it"
                % (key, full, kept)
            )
            continue
        if elisions[key].get("total") != full:
            problems.append(
                "budget_elisions.%s.total is %r and the generous budget returned %d"
                % (key, elisions[key].get("total"), full)
            )
        if elisions[key].get("kept") != kept:
            problems.append(
                "budget_elisions.%s.kept is %r and the pack carries %d"
                % (key, elisions[key].get("kept"), kept)
            )
    if graded == 0:
        return problems, 0
    for key, elision in sorted(elisions.items()):
        elided = elision.get("elided")
        if not elided:
            problems.append("budget_elisions.%s claims nothing withheld" % key)
            continue
        if elision.get("reason") != TOKEN_BUDGET_REASON:
            problems.append(
                "budget_elisions.%s names %r rather than the token budget"
                % (key, elision.get("reason"))
            )
        if elision.get("kept", 0) + elided != elision.get("total"):
            problems.append(
                "budget_elisions.%s: kept %r plus elided %r is not total %r"
                % (key, elision.get("kept"), elided, elision.get("total"))
            )
        if "%d withheld" % elided not in text:
            problems.append(
                "the rendering never names the %d entries withheld from `%s`" % (elided, key)
            )
    if graded and "--budget" not in text:
        problems.append("the rendering names no lever that recovers what was withheld")
    return problems, graded


class McpError(Exception):
    """One MCP call that could not be read. Unreadable is not absent."""


class Suite(object):
    """One fixture repository, answered over kin's stdio MCP server.

    The MCP path is the surface FIR-2600 is about: the stranger's client is what
    read `"affected_tests": []`, and the raw daemon route carries neither the
    `_kin` envelope nor the same wrapper, so probing it would answer a different
    question from the one asked.
    """

    def __init__(self, kin, workdir, verbose, daemon=None):
        self.kin = kin
        self.workdir = workdir
        self.verbose = verbose
        self.run_id = "r%d" % os.getpid()
        self.kin_home = os.path.join(workdir, "kin-home-" + self.run_id)
        if not os.path.isdir(self.kin_home):
            os.makedirs(self.kin_home)
        self.env = dict(os.environ)
        self.env["KIN_HOME"] = self.kin_home
        self.env["KIN_DAEMON_AUTO_EMBED"] = "0"
        self.env["KIN_VFS_DISABLE"] = "1"
        self.env["KIN_EMBED_BACKEND"] = "cpu"
        self.env.pop("KIN_MCP_REPO", None)
        if daemon:
            self.env["KIN_DAEMON_BIN"] = os.path.abspath(daemon)
        self.repo = None

    def run(self, args, cwd=None, timeout=900):
        proc = subprocess.run(
            args,
            cwd=cwd or self.repo,
            env=self.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        if self.verbose:
            print("$ %s -> %d" % (" ".join(args), proc.returncode))
        return proc

    def fixture(self):
        """A repository with one deep call chain, tests that cover its base, and
        one entity nothing calls.

        The chain is deep enough that a small budget has to cut it. The tests
        give `impact_analysis` a populated `affected_tests`, which is the bucket
        that shipped empty. The isolated entity is the subject of the other
        direction, where an empty answer is the true one.
        """
        repo = os.path.join(self.workdir, "fixture-" + self.run_id)
        if os.path.isdir(repo):
            shutil.rmtree(repo)
        os.makedirs(os.path.join(repo, "src"))
        os.makedirs(os.path.join(repo, "tests"))

        lines = ["def hop_0(value):", '    """The base of the chain."""', "    return value"]
        for index in range(1, 60):
            lines += [
                "",
                "",
                "def hop_%d(value):" % index,
                '    """A hop carrying enough text to cost the budget real characters."""',
                "    return hop_%d(value) + %d" % (index - 1, index),
            ]
        lines += [
            "",
            "",
            "def entry(value):",
            '    """The focal the deep walk starts from."""',
            "    return hop_59(value)",
            "",
            "",
            "def nothing_calls_this_and_it_calls_nothing():",
            '    """An island, so an empty answer here is the true one."""',
            "    return 0",
            "",
        ]
        with open(os.path.join(repo, "src", "chain.py"), "w") as handle:
            handle.write("\n".join(lines))

        # A second focal whose callees cost the pack's TOKEN budget without
        # costing its response budget much. Every parameter is `a<i>=0`, which
        # the pack's estimator counts as four tokens across roughly seven
        # characters, so these callees run to about 16,000 estimated tokens in
        # well under the 60,000-character response ceiling. That ratio is the
        # point: the token budget has to cut this pack at its 8,000 floor while
        # the response budget, pinned at its ceiling on both calls, has nothing
        # to do, and check 5 asserts that rather than assuming it. Nothing here
        # is named `hop`, so the locate-based checks above rank exactly what
        # they ranked before.
        params = ", ".join("a%d=0" % index for index in range(100))
        wide = []
        for index in range(WIDE_CALLEES):
            wide += [
                "def wide_dep_%02d(%s):" % (index, params),
                '    """A callee sized in tokens, not in characters."""',
                "    return a0",
                "",
                "",
            ]
        wide += ["def wide_entry(value):", '    """The focal the pack budget arm packs."""', "    return ("]
        for index in range(WIDE_CALLEES):
            wide.append(
                "        wide_dep_%02d()" % index
                + (" +" if index < WIDE_CALLEES - 1 else "")
            )
        wide += ["    )", ""]
        with open(os.path.join(repo, "src", "wide.py"), "w") as handle:
            handle.write("\n".join(wide))

        tests = ["from src.chain import hop_0", ""]
        for index in range(24):
            tests += [
                "",
                "def test_hop_0_case_%d():" % index,
                '    """One covering test, so affected_tests has something to lose."""',
                "    assert hop_0(%d) == %d" % (index, index),
            ]
        tests.append("")
        with open(os.path.join(repo, "tests", "test_chain.py"), "w") as handle:
            handle.write("\n".join(tests))

        # Every git call carries the fixture's own identity and no hooks. A
        # developer host's global hooks refuse an unsigned message, and a fixture
        # commit that a host policy blocks is a setup error wearing the costume
        # of a product failure.
        git = [
            "git",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "user.email=acceptance@firelock.invalid",
            "-c",
            "user.name=kin-response-budget-elisions",
        ]
        for args in (
            git + ["init", "--quiet"],
            git + ["add", "-A"],
            git + ["commit", "--quiet", "-s", "-m", "fixture"],
        ):
            proc = self.run(args, cwd=repo, timeout=120)
            if proc.returncode != 0:
                raise SetupError(
                    "%s failed: %s"
                    % (" ".join(args), proc.stderr.decode("utf-8", "replace")[-500:])
                )
        self.repo = repo
        proc = self.run([self.kin, "init"], cwd=repo, timeout=900)
        if proc.returncode != 0:
            raise SetupError("kin init failed: %s" % proc.stderr.decode("utf-8", "replace")[-1000:])
        return repo

    def mcp(self, method, params, timeout=600):
        """One MCP request against a fresh stdio server, returning its payload.

        `tools/list` returns the raw result. A `tools/call` pierces
        `content[0].text` first, because the outer frame is an envelope and
        reading payload keys off its top level comes back empty for every key.
        """
        env = dict(self.env)
        env["KIN_MCP_REPO"] = self.repo
        proc = subprocess.Popen(
            [self.kin, "mcp", "start", "--repo", self.repo],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=self.repo,
            env=env,
            text=True,
        )
        if method == "tools/list":
            call = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
        else:
            call = {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": method, "arguments": params},
            }
        frames = [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "kin-response-budget-elisions", "version": "1"},
                },
            },
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            call,
        ]
        try:
            out, err = proc.communicate(
                "".join(json.dumps(frame) + "\n" for frame in frames), timeout=timeout
            )
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            raise McpError("%s timed out after %ss" % (method, timeout))
        response = None
        for line in out.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                frame = json.loads(line)
            except ValueError:
                continue
            if frame.get("id") == 2:
                response = frame
        if response is None:
            raise McpError(
                "%s returned no id=2 frame (stderr tail: %s)"
                % (method, err[-300:].replace("\n", " "))
            )
        if "error" in response:
            raise McpError("%s error: %s" % (method, json.dumps(response["error"])[:300]))
        result = response.get("result") or {}
        if method == "tools/list":
            return result
        content = result.get("content") or []
        if not content or "text" not in content[0]:
            raise McpError("%s returned no text content" % method)
        try:
            return json.loads(content[0]["text"])
        except ValueError as exc:
            raise McpError("%s payload is not JSON (%s)" % (method, exc))


    def entity_id(self, name):
        """One entity id, resolved the way an agent resolves one.

        `get_context_pack` addresses its focal by id, so a check that drove a
        name-taking sibling instead would be probing a different surface from
        the one the claim is about.
        """
        payload = self.mcp("semantic_locate", {"query": name, "limit": 20})
        for row in payload.get("entities") or []:
            if row.get("name") == name:
                found = row.get("entity_id") or row.get("id")
                if found:
                    return found
        raise McpError("semantic_locate resolved no entity named %r" % name)

    def cli(self, args, timeout=600):
        """One `kin ...` invocation in the fixture, returning (rc, stdout)."""
        proc = self.run([self.kin] + args, timeout=timeout)
        return proc.returncode, proc.stdout.decode("utf-8", "replace")


def grade_buckets(payload, buckets):
    """Grade every named list on one payload against the never-empty rule."""
    problems = []
    graded = 0
    for key in buckets:
        rows = payload.get(key)
        if not isinstance(rows, list):
            continue
        withheld = payload.get(key + "_withheld")
        elision = (payload.get("elisions") or {}).get(key)
        if not withheld and not elision:
            continue
        graded += 1
        if not rows:
            problems.append(
                "`%s` was cut to an empty array, which reads as 'the walk found none'" % key
            )
        if not elision:
            problems.append("`%s` was cut and published no elision" % key)
            continue
        if elision.get("kept") != len(rows):
            problems.append(
                "elisions.%s.kept is %r and the array carries %d"
                % (key, elision.get("kept"), len(rows))
            )
        if withheld is not None and elision.get("elided") != withheld:
            problems.append(
                "elisions.%s.elided is %r and %s_withheld is %r"
                % (key, elision.get("elided"), key, withheld)
            )
        if elision.get("total") != len(rows) + (elision.get("elided") or 0):
            problems.append(
                "elisions.%s.total is %r and kept plus elided is %d"
                % (key, elision.get("total"), len(rows) + (elision.get("elided") or 0))
            )
        if not elision.get("reason"):
            problems.append("elisions.%s names no reason" % key)
    return problems, graded


def check_0(suite):
    res = Result("0", "FIR-2600", "a budget-cut chain is elided, never emptied")
    try:
        payload = suite.mcp(
            "trace_data_flow",
            {
                "focal": "entry",
                "depth": 8,
                "direction": "calls",
                "limit_per_step": 25,
                "include_body": False,
                "max_chars": 2000,
            },
        )
    except McpError as exc:
        res.unknown("cut walk unreadable: %s" % exc)
        return res
    problems = grade_cut_walk(payload)
    if problems:
        for problem in problems:
            res.bad(problem)
        return res
    res.ok(
        "the cut walk kept %d of %d steps and published elisions.chain %s"
        % (
            len(payload["chain"]),
            len(payload["chain"]) + payload["steps_omitted"],
            json.dumps(payload["elisions"]["chain"], sort_keys=True),
        )
    )
    return res


def check_1(suite):
    res = Result("1", "FIR-2600", "an empty chain still means the walk reached nothing")
    try:
        payload = suite.mcp(
            "trace_data_flow",
            {
                "focal": "nothing_calls_this_and_it_calls_nothing",
                "depth": 8,
                "direction": "calls",
                "include_body": False,
            },
        )
    except McpError as exc:
        res.unknown("empty walk unreadable: %s" % exc)
        return res
    problems = grade_empty_walk(payload)
    if problems:
        for problem in problems:
            res.bad(problem)
        return res
    res.ok("the untouched walk reported an empty chain and claimed no elision")
    return res


def check_2(suite):
    res = Result("2", "FIR-2600", "the advertised budget is one a client accepts")
    try:
        listing = suite.mcp("tools/list", {})
    except McpError as exc:
        res.unknown("tools/list unreadable: %s" % exc)
        return res
    tools = listing.get("tools")
    if not isinstance(tools, list) or not tools:
        res.unknown("the tool listing carried no tools")
        return res
    graded = 0
    for tool in tools:
        schema = tool.get("inputSchema") or tool.get("input_schema") or {}
        properties = schema.get("properties") or {}
        for key in ("max_chars", "max_response_chars"):
            if key not in properties:
                continue
            graded += 1
            for problem in grade_advertised_budget(properties[key]):
                res.bad("%s.%s: %s" % (tool.get("name"), key, problem))
    if graded == 0:
        res.unknown("no tool advertised a budget parameter, so nothing was graded")
        return res
    if not res.failed:
        res.ok("%d advertised budgets sit under what a real client accepts" % graded)
    return res


def check_3(suite):
    res = Result("3", "FIR-2600", "no ranked list the budget cuts ships empty")
    lists = ["entities", "files"]
    query = {"query": "hop", "limit": 60}
    try:
        whole = suite.mcp("semantic_locate", dict(query, max_chars=60000))
        cut = suite.mcp("semantic_locate", dict(query, max_chars=2000))
    except McpError as exc:
        res.unknown("semantic_locate unreadable: %s" % exc)
        return res

    # The same query at two budgets. Anything the walk found at the ceiling it
    # still found at the floor, so a list that is full in one and empty in the
    # other was emptied by the budget and by nothing else. This needs no counter
    # to be true, which is why it is the check.
    populated = [key for key in lists if whole.get(key)]
    if not populated:
        res.unknown("the ceiling call filled no list, so the rule was not exercised")
        return res
    for key in populated:
        rows = cut.get(key)
        if not isinstance(rows, list) or not rows:
            res.bad(
                "`%s` held %d entries at the ceiling and %r at the floor, so the budget "
                "emptied it" % (key, len(whole[key]), rows)
            )
    problems, graded = grade_buckets(cut, lists)
    for problem in problems:
        res.bad(problem)
    if graded == 0:
        res.unknown("the floor call cut nothing, so the elision rule was not exercised")
        return res
    if not res.failed:
        res.ok(
            "%d of %d lists were cut and every one kept an entry: %s"
            % (
                graded,
                len(populated),
                json.dumps(cut.get("elisions") or {}, sort_keys=True),
            )
        )
    return res


def check_4(suite):
    res = Result(
        "4",
        "FIR-2602",
        "an impact response is counted whole, and never reports a bound it did not hold",
    )
    target = {"files": ["src/chain.py"], "include_traffic": False}
    try:
        whole = suite.mcp("impact_analysis", dict(target, max_chars=60000))
        cut = suite.mcp("impact_analysis", dict(target, max_chars=2000))
    except McpError as exc:
        res.unknown("impact_analysis unreadable: %s" % exc)
        return res

    for label, payload in (("ceiling", whole), ("floor", cut)):
        for problem in grade_budget_accounting(payload):
            res.bad("%s call: %s" % (label, problem))

    # The bulk of this fixture's impact report is outside the four `affected_*`
    # buckets, which is the shape FIR-2602 was measured on. A list full at the
    # ceiling and empty at the floor was emptied by the budget and by nothing
    # else, and needs no counter to be true.
    populated = [key for key in IMPACT_LISTS if whole.get(key)]
    if not populated:
        res.unknown("the ceiling call filled no impact list, so the rule was not exercised")
        return res
    outside = [
        key
        for key in populated
        if not key.startswith("affected_") or key in ("affected_work_items", "affected_annotations")
    ]
    if not outside:
        res.unknown(
            "every populated list is a blast-radius bucket, so the FIR-2602 shape was "
            "not reproduced"
        )
        return res
    for key in populated:
        rows = cut.get(key)
        if not isinstance(rows, list) or not rows:
            res.bad(
                "`%s` held %d entries at the ceiling and %r at the floor, so the budget "
                "emptied it" % (key, len(whole[key]), rows)
            )

    problems, graded = grade_buckets(cut, IMPACT_LISTS)
    for problem in problems:
        res.bad(problem)
    if graded == 0:
        res.unknown("the floor call cut no impact list, so the elision rule was not exercised")
        return res

    if not res.failed:
        accounting = cut["_kin"]["response"]
        res.ok(
            "the report measured %d characters and was cut to %d against a %d ceiling; "
            "%d of %d lists were cut and every one kept an entry, %d of them outside the "
            "blast-radius buckets: %s"
            % (
                accounting["chars_before_budget"],
                accounting["chars_after_budget"],
                accounting["max_chars"],
                graded,
                len(populated),
                len(outside),
                json.dumps(cut.get("elisions") or {}, sort_keys=True),
            )
        )
    return res


def check_5(suite):
    res = Result(
        "5",
        "FIR-2482",
        "a pack cut by its own token budget says what it cut, and empties nothing",
    )
    try:
        focal = suite.entity_id("wide_entry")
        # One identical, generous `max_chars` on both calls, so the only budget
        # that differs between them is the pack's own. `compact` keeps inline
        # source out of the payload for the same reason: the arm is about rows
        # the token budget refused, and bodies would put the response budget
        # back in the picture on the generous call.
        target = {"entity_id": focal, "compact": True, "include_traffic": False}
        ceiling = dict(target, max_chars=60000, token_budget=200000)
        floor = dict(target, max_chars=60000, token_budget=8000)
        whole = suite.mcp("get_context_pack", ceiling)
        cut = suite.mcp("get_context_pack", floor)
    except McpError as exc:
        res.unknown("get_context_pack unreadable: %s" % exc)
        return res

    # If the response budget touched either call the differential is measuring
    # two cutters at once, which is exactly the confusion this check exists to
    # remove. Read off each response's own accounting rather than assumed.
    for label, payload in (("generous", whole), ("tight", cut)):
        accounting = ((payload.get("_kin") or {}).get("response")) or {}
        if accounting.get("bounded"):
            res.unknown(
                "the %s call was also cut by the response budget (%s), so the token "
                "budget cannot be isolated on this fixture"
                % (label, json.dumps(accounting, sort_keys=True))
            )
            return res

    problems, graded = grade_pack_token_budget(whole, cut)
    for problem in problems:
        res.bad(problem)
    if graded == 0:
        res.unknown("the tight budget cut no group, so the rule was not exercised")
        return res
    if not res.failed:
        res.ok(
            "%d of %d groups were cut by the token budget and every one kept an entry: %s"
            % (
                graded,
                len([key for key in PACK_GROUPS if whole.get(key)]),
                json.dumps(cut.get("elisions") or {}, sort_keys=True),
            )
        )
    return res


def check_6(suite):
    res = Result("6", "FIR-2482", "a row whose body the budget took says so on the row")
    try:
        focal = suite.entity_id("wide_entry")
        payload = suite.mcp(
            "get_context_pack",
            {
                "entity_id": focal,
                "compact": False,
                "include_traffic": False,
                "token_budget": 200000,
                "max_chars": 12000,
            },
        )
    except McpError as exc:
        res.unknown("get_context_pack unreadable: %s" % exc)
        return res

    problems, marked = grade_body_elisions(payload)
    for problem in problems:
        res.bad(problem)
    if marked == 0:
        res.unknown("the budget took no body, so the rule was not exercised")
        return res
    if not res.failed:
        res.ok(
            "%d rows name the budget that took their source, and elisions.body agrees: %s"
            % (marked, json.dumps((payload.get("elisions") or {}).get("body"), sort_keys=True))
        )
    return res


def check_7(suite):
    res = Result("7", "FIR-2482", "kin context names what its token budget withheld")
    # `kin context` takes any number, so unlike the MCP tool it can be driven
    # well below the 8k floor the tool's bucketing imposes. The generous call is
    # the control: a section full there and short here was cut by the token
    # budget, which is true whether or not the response admits it.
    rc_whole, raw_whole = suite.cli(
        ["context", "wide_entry", "--budget", "200000", "--json"]
    )
    rc_json, raw_cut = suite.cli(["context", "wide_entry", "--budget", "2000", "--json"])
    rc_text, text = suite.cli(["context", "wide_entry", "--budget", "2000"])
    if rc_whole != 0 or rc_json != 0 or rc_text != 0:
        res.unknown(
            "kin context exited %d (generous), %d (json), %d (text)"
            % (rc_whole, rc_json, rc_text)
        )
        return res
    try:
        whole, cut = json.loads(raw_whole), json.loads(raw_cut)
    except ValueError as exc:
        res.unknown("kin context --json is not JSON (%s)" % exc)
        return res

    problems, graded = grade_cli_context(whole, cut, text)
    for problem in problems:
        res.bad(problem)
    if graded == 0:
        res.unknown("the tight budget cut no section, so the rule was not exercised")
        return res
    if not res.failed:
        res.ok(
            "%d sections report the same cut in the lines and in the json: %s"
            % (graded, json.dumps(cut.get("budget_elisions") or {}, sort_keys=True))
        )
    return res


CHECKS = [
    ("0", check_0),
    ("1", check_1),
    ("2", check_2),
    ("3", check_3),
    ("4", check_4),
    ("5", check_5),
    ("6", check_6),
    ("7", check_7),
]


def self_test():
    """Exercise every grader against its inverse. No binary, no fixture."""
    problems = []

    def expect(label, got, want):
        if got != want:
            problems.append("%s: got %r, wanted %r" % (label, got, want))

    whole = {
        "chain": [{"step": 1}, {"step": 2}],
        "steps_omitted": 3,
        "elisions": {"chain": {"kept": 2, "elided": 3, "total": 5, "reason": "response_budget"}},
    }
    expect("a correct cut walk passes", grade_cut_walk(whole), [])

    emptied = dict(whole)
    emptied["chain"] = []
    emptied["elisions"] = {"chain": {"kept": 0, "elided": 3, "total": 3, "reason": "response_budget"}}
    expect("an emptied chain fails", len(grade_cut_walk(emptied)) >= 1, True)

    silent = {"chain": [{"step": 1}], "steps_omitted": 3}
    expect("a cut with no elision fails", len(grade_cut_walk(silent)) >= 1, True)

    mismatched = {
        "chain": [{"step": 1}],
        "steps_omitted": 3,
        "elisions": {"chain": {"kept": 9, "elided": 9, "total": 9, "reason": "response_budget"}},
    }
    expect("an elision that disagrees fails", len(grade_cut_walk(mismatched)) >= 1, True)

    reasonless = {
        "chain": [{"step": 1}],
        "steps_omitted": 3,
        "elisions": {"chain": {"kept": 1, "elided": 3, "total": 4}},
    }
    expect("an elision with no reason fails", len(grade_cut_walk(reasonless)) >= 1, True)

    uncut = {"chain": [{"step": 1}], "steps_omitted": 0}
    expect("an uncut walk proves nothing", len(grade_cut_walk(uncut)) >= 1, True)

    expect("a true empty walk passes", grade_empty_walk({"chain": []}), [])
    expect(
        "an empty walk claiming an elision fails",
        len(grade_empty_walk({"chain": [], "elisions": {"chain": {"elided": 4}}})) >= 1,
        True,
    )
    expect(
        "an empty walk reporting omissions fails",
        len(grade_empty_walk({"chain": [], "steps_omitted": 4})) >= 1,
        True,
    )
    expect(
        "a non-empty walk proves nothing here",
        len(grade_empty_walk({"chain": [{"step": 1}]})) >= 1,
        True,
    )

    expect(
        "an honest budget passes",
        grade_advertised_budget({"default": 45000, "minimum": 2000, "maximum": 60000}),
        [],
    )
    expect(
        "the ceiling that got a result refused fails",
        len(grade_advertised_budget({"default": 30000, "minimum": 2000, "maximum": 400000})) >= 1,
        True,
    )
    expect(
        "a default outside its own clamp fails",
        len(grade_advertised_budget({"default": 90000, "minimum": 2000, "maximum": 60000})) >= 1,
        True,
    )
    expect(
        "a schema with no maximum fails",
        len(grade_advertised_budget({"default": 45000, "minimum": 2000})) >= 1,
        True,
    )

    honest = {
        "affected_tests": [{"name": "test_a"}],
        "affected_tests_withheld": 15,
        "elisions": {
            "affected_tests": {"kept": 1, "elided": 15, "total": 16, "reason": "response_budget"}
        },
    }
    expect("an honest cut bucket passes", grade_buckets(honest, ["affected_tests"]), ([], 1))
    reported = dict(honest)
    reported["affected_tests"] = []
    reported["elisions"] = {
        "affected_tests": {"kept": 0, "elided": 15, "total": 15, "reason": "response_budget"}
    }
    expect(
        "the shipped defect fails",
        len(grade_buckets(reported, ["affected_tests"])[0]) >= 1,
        True,
    )
    quiet = {"affected_tests": [], "affected_tests_withheld": 15}
    expect(
        "a cut bucket with no elision fails",
        len(grade_buckets(quiet, ["affected_tests"])[0]) >= 1,
        True,
    )
    untouched = {"affected_tests": []}
    expect(
        "an untouched bucket is not graded",
        grade_buckets(untouched, ["affected_tests"]),
        ([], 0),
    )

    fitting = {
        "_kin": {
            "response": {
                "max_chars": 2000,
                "chars_before_budget": 50354,
                "chars_after_budget": 1840,
                "bounded": True,
            }
        }
    }
    expect("a response that fits passes", grade_budget_accounting(fitting), [])

    shipped = {
        "_kin": {
            "response": {
                "max_chars": 2000,
                "chars_before_budget": 50354,
                "chars_after_budget": 50354,
                "bounded": False,
            }
        }
    }
    expect(
        "the FIR-2602 shape fails",
        len(grade_budget_accounting(shipped)) >= 1,
        True,
    )

    silent = {
        "_kin": {
            "response": {
                "max_chars": 2000,
                "chars_before_budget": 50354,
                "chars_after_budget": 2574,
                "bounded": True,
            }
        }
    }
    expect(
        "a response still over its ceiling and saying nothing fails",
        len(grade_budget_accounting(silent)) >= 1,
        True,
    )
    disclosed = dict(silent)
    disclosed["degradations"] = [{"reason": OVER_BUDGET_REASON}]
    expect("the same response, disclosed, passes", grade_budget_accounting(disclosed), [])

    overclaimed = {
        "_kin": {
            "response": {
                "max_chars": 2000,
                "chars_before_budget": 50354,
                "chars_after_budget": 1840,
                "bounded": True,
            }
        },
        "degradations": [{"reason": OVER_BUDGET_REASON}],
    }
    expect(
        "a response that fits and claims it does not fails",
        len(grade_budget_accounting(overclaimed)) >= 1,
        True,
    )

    sizeless = {
        "_kin": {
            "response": {"max_chars": 2000, "chars_before_budget": 50354, "bounded": False}
        }
    }
    expect(
        "an accounting with no shipped size fails",
        len(grade_budget_accounting(sizeless)) >= 1,
        True,
    )
    expect(
        "a response with no accounting at all fails",
        len(grade_budget_accounting({"affected_tests": []})) >= 1,
        True,
    )

    # ── FIR-2482: the pack's own token budget ───────────────────────────

    def pack(deps, elisions=None, source="dependency_edges"):
        doc = {
            "dependencies": [{"name": "d%d" % index} for index in range(deps)],
            "dependents": [{"name": "u0"}],
            "dependency_selection": {"source": source},
        }
        if elisions:
            doc["elisions"] = elisions
        return doc

    whole_pack = pack(20)
    honest = pack(
        6,
        {"dependencies": {"kept": 6, "elided": 14, "total": 20, "reason": "token_budget"}},
    )
    expect("an honest pack cut passes", grade_pack_token_budget(whole_pack, honest)[0], [])
    expect("an honest pack cut grades one group", grade_pack_token_budget(whole_pack, honest)[1], 1)

    silent = pack(6)
    expect(
        "a pack cut with no elision fails",
        len(grade_pack_token_budget(whole_pack, silent)[0]) >= 1,
        True,
    )
    emptied = pack(
        0,
        {"dependencies": {"kept": 0, "elided": 20, "total": 20, "reason": "token_budget"}},
    )
    expect(
        "a pack group emptied by the budget fails",
        len(grade_pack_token_budget(whole_pack, emptied)[0]) >= 1,
        True,
    )
    absent = {"dependents": [{"name": "u0"}], "dependency_selection": {"source": "dependency_edges"}}
    expect(
        "a pack group that vanished entirely fails",
        len(grade_pack_token_budget(whole_pack, absent)[0]) >= 1,
        True,
    )
    miscounted = pack(
        6,
        {"dependencies": {"kept": 9, "elided": 14, "total": 20, "reason": "token_budget"}},
    )
    expect(
        "a pack elision that disagrees with its array fails",
        len(grade_pack_token_budget(whole_pack, miscounted)[0]) >= 1,
        True,
    )
    misattributed = pack(
        6,
        {"dependencies": {"kept": 6, "elided": 14, "total": 20, "reason": "response_budget"}},
    )
    expect(
        "a token-budget cut blamed on the response budget fails",
        len(grade_pack_token_budget(whole_pack, misattributed)[0]) >= 1,
        True,
    )
    phantom = pack(
        20,
        {"dependencies": {"kept": 20, "elided": 3, "total": 23, "reason": "token_budget"}},
    )
    expect(
        "a whole pack claiming a cut fails",
        len(grade_pack_token_budget(whole_pack, phantom)[0]) >= 1,
        True,
    )
    fallback = pack(
        6,
        {"dependencies": {"kept": 6, "elided": 14, "total": 20, "reason": "token_budget"}},
        source="same_file_fallback",
    )
    expect(
        "a pack whose section came from the cap is not gradeable here",
        len(grade_pack_token_budget(whole_pack, fallback)[0]) >= 1,
        True,
    )

    cut_bodies = {
        "dependencies": [
            {"name": "d0", "body": None, "body_elided": ["body"]},
            {"name": "d1", "body": None, "body_elided": ["body"]},
        ],
        "elisions": {"body": {"kept": 0, "elided": 2, "total": 2, "reason": "response_budget"}},
    }
    expect("marked bodies pass", grade_body_elisions(cut_bodies)[0], [])
    expect("marked bodies grade two rows", grade_body_elisions(cut_bodies)[1], 2)

    stripped = {
        "dependencies": [{"name": "d0"}, {"name": "d1"}],
        "elisions": {"body": {"kept": 0, "elided": 2, "total": 2, "reason": "response_budget"}},
    }
    expect(
        "a bodiless row that says nothing fails",
        len(grade_body_elisions(stripped)[0]) >= 1,
        True,
    )
    both = {
        "dependencies": [
            {"name": "d0", "body": None, "body_elided": ["body"], "body_unavailable": "gone"}
        ],
        "elisions": {"body": {"kept": 0, "elided": 1, "total": 1, "reason": "response_budget"}},
    }
    expect(
        "a row claiming a cut and a gap at once fails",
        len(grade_body_elisions(both)[0]) >= 1,
        True,
    )
    uncounted = {
        "dependencies": [{"name": "d0", "body": None, "body_elided": ["body"]}],
    }
    expect(
        "marked rows with no elision fail",
        len(grade_body_elisions(uncounted)[0]) >= 1,
        True,
    )
    undercounted = {
        "dependencies": [
            {"name": "d0", "body": None, "body_elided": ["body"]},
            {"name": "d1", "body": None, "body_elided": ["body"]},
        ],
        "elisions": {"body": {"kept": 0, "elided": 1, "total": 1, "reason": "response_budget"}},
    }
    expect(
        "an elision counting fewer than the rows say fails",
        len(grade_body_elisions(undercounted)[0]) >= 1,
        True,
    )
    gap_only = {"dependencies": [{"name": "d0", "body": None, "body_unavailable": "generated"}]}
    expect("a pure graph gap is not a budget cut", grade_body_elisions(gap_only)[1], 0)

    def cli_doc(rows, elisions=None):
        doc = {
            "pack": {"dependency_signatures": [{"entity_id": "e%d" % i} for i in range(rows)]},
            "dependency_selection": {"dependents_returned": 0},
        }
        if elisions:
            doc["budget_elisions"] = elisions
        return doc

    cli_whole = cli_doc(50)
    honest_cut = cli_doc(
        4, {"dependencies": {"kept": 4, "elided": 46, "total": 50, "reason": "token_budget"}}
    )
    cli_text = "  Dependencies: 4 entries (46 withheld by the 2000-token budget)\n  Raise --budget"
    expect(
        "a rendering that names its cut passes",
        grade_cli_context(cli_whole, honest_cut, cli_text)[0],
        [],
    )
    expect(
        "a rendering that names its cut grades one section",
        grade_cli_context(cli_whole, honest_cut, cli_text)[1],
        1,
    )
    expect(
        "a cut section disclosing nothing at all fails",
        len(grade_cli_context(cli_whole, cli_doc(4), "  Dependencies: 4 entries")[0]) >= 1,
        True,
    )
    expect(
        "a rendering that hides a cut it disclosed fails",
        len(grade_cli_context(cli_whole, honest_cut, "  Dependencies: 4 entries")[0]) >= 1,
        True,
    )
    expect(
        "a rendering with no lever fails",
        len(
            grade_cli_context(
                cli_whole, honest_cut, "  Dependencies: 4 entries (46 withheld)"
            )[0]
        )
        >= 1,
        True,
    )
    expect(
        "a cut blamed on the wrong budget fails",
        len(
            grade_cli_context(
                cli_whole,
                cli_doc(
                    4,
                    {
                        "dependencies": {
                            "kept": 4,
                            "elided": 46,
                            "total": 50,
                            "reason": "response_budget",
                        }
                    },
                ),
                cli_text,
            )[0]
        )
        >= 1,
        True,
    )
    expect(
        "an elision that disagrees with the generous run fails",
        len(
            grade_cli_context(
                cli_whole,
                cli_doc(
                    4,
                    {
                        "dependencies": {
                            "kept": 4,
                            "elided": 6,
                            "total": 10,
                            "reason": "token_budget",
                        }
                    },
                ),
                cli_text,
            )[0]
        )
        >= 1,
        True,
    )
    expect(
        "a whole pack grades nothing here",
        grade_cli_context(cli_whole, cli_doc(50), "  Dependencies: 50 entries")[1],
        0,
    )

    for line in problems:
        print("SELF-TEST FAIL %s" % line)
    print(
        "response budget elisions: self-test %s"
        % ("FAILED (%d)" % len(problems) if problems else "passed")
    )
    return 1 if problems else 0


def main(argv):
    parser = argparse.ArgumentParser(
        add_help=True,
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--kin", default=os.environ.get("KIN_BIN"), help="path to the kin binary")
    parser.add_argument(
        "--daemon",
        default=os.environ.get("KIN_DAEMON_BIN"),
        help="path to the kin-daemon binary the server should spawn",
    )
    parser.add_argument("--workdir", default=None, help="where to build the fixture")
    parser.add_argument("--json", default=None, help="write the report here")
    parser.add_argument("--label", default="", help="label recorded in the report")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    opts = parser.parse_args(argv)

    if opts.self_test:
        return self_test()

    if not opts.kin:
        sys.stderr.write("no kin binary: pass --kin PATH or set KIN_BIN\n")
        return 3
    kin = os.path.abspath(opts.kin)
    if not os.path.isfile(kin) or not os.access(kin, os.X_OK):
        sys.stderr.write("kin binary %s is missing or not executable\n" % kin)
        return 3

    workdir = opts.workdir or tempfile.mkdtemp(prefix="kin-budget-elisions-")
    if not os.path.isdir(workdir):
        os.makedirs(workdir)
    suite = Suite(kin, os.path.abspath(workdir), opts.verbose, opts.daemon)
    try:
        suite.fixture()
    except (SetupError, subprocess.TimeoutExpired) as exc:
        sys.stderr.write("setup failed: %s\n" % exc)
        return 3

    results = []
    for ident, check in CHECKS:
        try:
            res = check(suite)
        except subprocess.TimeoutExpired as exc:
            res = Result(ident, "FIR-2600", "check %s" % ident)
            res.unknown("timed out: %s" % exc)
        marker = res.status
        print("CHECK %s %s %s %s" % (res.id, res.ticket, marker, res.detail))
        results.append(res)

    failed = [r for r in results if r.status == FAIL]
    unread = [r for r in results if r.status == UNREADABLE]
    print(
        "response budget elisions: %d PASS, %d FAIL, %d UNREADABLE"
        % (len(results) - len(failed) - len(unread), len(failed), len(unread))
    )
    if opts.json:
        directory = os.path.dirname(os.path.abspath(opts.json))
        if directory and not os.path.isdir(directory):
            os.makedirs(directory)
        with open(opts.json, "w") as handle:
            json.dump(
                {"label": opts.label, "results": [r.row() for r in results]},
                handle,
                indent=2,
                sort_keys=True,
            )
            handle.write("\n")
    if failed:
        return 1
    if unread:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
