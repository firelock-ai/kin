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

        for args in (
            ["git", "init", "--quiet"],
            ["git", "-c", "core.hooksPath=/dev/null", "config", "user.email", "acceptance@firelock.invalid"],
            ["git", "config", "user.name", "kin-response-budget-elisions"],
            ["git", "add", "-A"],
            ["git", "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "fixture"],
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
    res = Result("3", "FIR-2600", "no impact bucket the budget cuts ships empty")
    buckets = [
        "affected_callers",
        "affected_dependents",
        "affected_contract_consumers",
        "affected_tests",
    ]
    try:
        payload = suite.mcp(
            "impact_analysis",
            {"files": ["src/chain.py", "tests/test_chain.py"], "max_chars": 2500},
        )
    except McpError as exc:
        res.unknown("impact_analysis unreadable: %s" % exc)
        return res
    problems, graded = grade_buckets(payload, buckets)
    if problems:
        for problem in problems:
            res.bad(problem)
        return res
    if graded == 0:
        res.unknown(
            "the budget cut no bucket on this fixture, so the rule was not exercised"
        )
        return res
    res.ok(
        "%d cut buckets kept an entry and published an elision: %s"
        % (graded, json.dumps(payload.get("elisions") or {}, sort_keys=True))
    )
    return res


CHECKS = [("0", check_0), ("1", check_1), ("2", check_2), ("3", check_3)]


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
