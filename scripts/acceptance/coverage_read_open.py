#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
"""NON-CITABLE acceptance suite for the coverage read's durable comparison (FIR-2964).

`kin graph status` computes artifact coverage against durable truth, and to get
it the shipped daemon opens the repository authority. That open decodes the
whole snapshot and re-verifies every persisted body; on a converted repository
about nineteen twentieths of those bytes are the change map, and this read
touches no change, no entity and no relation. Several designs are in flight to
serve it cheaply, the one landing being an envelope read that decodes the
snapshot while skipping the change-map domains.

**This suite is the gate any of them has to pass, and it is written to be blind
to which one is in the tree.** It names no lever, no cache and no log line from
any particular design, because a gate that knew the implementation would have to
be rewritten by the next one and would grade nothing in between.

What it grades is the property every cheap path can break in the same way. The
tempting shortcut is to hand the read the tree the daemon already holds, which
is the one its query graph was built from. The read's first act is asking
whether the graph's tree and the authority's agree, so serving the graph's own
tree makes that the graph against itself, and the answer is coherence on every
store whatever is on disk. That defect passes any check run only on a clean
repository, which is every fixture anyone writes by hand.

So the two arms are a pair and neither is sufficient:

``clean`` requires a freshly converted store to report its trees IN SYNC. It is
the control. Without it a path that reported divergence unconditionally would
satisfy the arm below.

``diverged`` makes the graph and durable truth actually differ and requires the
read to say so. It is the one that catches the substitution. When the divergence
cannot be arranged on this host it returns UNREADABLE rather than PASS, because
an arm that never reached its own condition has graded nothing, and the
substitution it exists for reports in-sync too.

``instrument`` guards the attribution itself, at BOTH depths. Every authority
open logs the caller that asked for it, and an instrument that silently stopped
logging is worse than none because the count it feeds keeps being quoted. Both
depths are required because they cover different populations: instrumenting only
kin-cli's wrapper attributed two of twenty-six opens on a measured run, so a
suite happy with the wrapper alone would certify an attribution covering an
unknown and small fraction.

Each check prints:

    CHECK <id> <ticket> PASS|FAIL|UNREADABLE <detail>

Exit status is 1 when any check fails, 2 when none fail but some are unreadable,
3 on setup failure, and 0 only when every check passes. ``--self-test`` drives
every grader against its inverse without building a repository.
"""

from __future__ import print_function

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile


PASS = "PASS"
FAIL = "FAIL"
UNREADABLE = "UNREADABLE"
TICKET = "FIR-2964"

# The field the whole suite turns on: whether the derived graph and the durable
# authority carry the same tree.
IN_SYNC = "repository_tree_in_sync"

# What an authority open logs about itself. Matched as substrings, because the
# line carries a repository id, a caller and a count that all vary.
#
# TWO lines, at two depths, and both are required. The wrapper line comes from
# kin-cli's `ActiveRepositoryAuthority::open`; the funnel line comes from
# `kin_core::open_persisted_local_repository_authority`, which every path into
# kin-db's recovery reaches. Measured on a converted store, the wrapper
# attributed two of twenty-six opens in one run, so a suite asserting only the
# wrapper would pass a build whose funnel instrument had been removed and would
# certify an attribution covering a small fraction of the opens.
OPEN_LINE = "opening repository authority"
FUNNEL_LINE = "opening persisted repository authority"
OPEN_CALLER_FIELD = "caller="


def tail(text, limit=600):
    text = (text or "").strip()
    return text if len(text) <= limit else "..." + text[-limit:]


def run(cmd, cwd=None, env=None, timeout=900):
    proc = subprocess.run(
        cmd,
        cwd=cwd,
        env=env,
        timeout=timeout,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return proc.returncode, proc.stdout


class Result(object):
    def __init__(self, check_id, title):
        self.id = check_id
        self.title = title
        self.asserts = []

    def ok(self, detail):
        self.asserts.append({"status": PASS, "detail": detail})

    def bad(self, detail):
        self.asserts.append({"status": FAIL, "detail": detail})

    def unknown(self, detail):
        self.asserts.append({"status": UNREADABLE, "detail": detail})

    @property
    def status(self):
        if any(row["status"] == FAIL for row in self.asserts):
            return FAIL
        if any(row["status"] == UNREADABLE for row in self.asserts):
            return UNREADABLE
        return PASS if self.asserts else UNREADABLE

    @property
    def detail(self):
        for wanted in (FAIL, UNREADABLE):
            for row in self.asserts:
                if row["status"] == wanted:
                    return row["detail"]
        passed = [row["detail"] for row in self.asserts if row["status"] == PASS]
        return "; ".join(passed) if passed else "no assertion was reached"


def strip_ansi(text):
    """Daemon logs carry escapes between a field name and its value."""
    out = []
    skipping = False
    for char in text or "":
        if char == "\x1b":
            skipping = True
            continue
        if skipping:
            if char.isalpha():
                skipping = False
            continue
        out.append(char)
    return "".join(out)


def coverage_of(report):
    """The artifact-coverage block, or ``None`` when it cannot be read.

    ``None`` rather than an empty dict on purpose: an absent block compared
    against an absent block agrees perfectly, and a suite that let that count as
    agreement would pass on a report shape it never understood.
    """
    if not isinstance(report, dict):
        return None
    coverage = report.get("artifact_coverage")
    if isinstance(coverage, dict) and IN_SYNC in coverage:
        return coverage
    if IN_SYNC in report:
        return report
    return None


def sync_problems(coverage, expect_in_sync):
    """Problems in one coverage reading's in-sync verdict.

    One grader for both arms, so they cannot drift into disagreeing about what
    the field means.
    """
    if coverage is None:
        return None
    value = coverage.get(IN_SYNC)
    if value is not True and value is not False:
        return None
    if expect_in_sync and value is False:
        return [
            "a freshly converted store reported its trees out of sync, so this suite's "
            "control does not hold and its other arm proves nothing"
        ]
    if not expect_in_sync and value is True:
        return [
            "the graph and durable truth differ and the read reported them in sync, which "
            "is what serving the graph's own tree as durable truth looks like"
        ]
    return []


def instrument_problems(log_text):
    """Problems in what the daemon logged about its own authority opens."""
    if log_text is None:
        return None
    clean = strip_ansi(log_text)
    # The funnel line contains the wrapper line's text as a substring, so it has
    # to be separated before either is counted, or every funnel open would be
    # scored as a wrapper open and the two-depth check would collapse to one.
    funnel = [line for line in clean.splitlines() if FUNNEL_LINE in line]
    wrapper = [
        line
        for line in clean.splitlines()
        if OPEN_LINE in line and FUNNEL_LINE not in line
    ]
    problems = []
    if not funnel:
        problems.append(
            "no persisted-authority open was logged at all, so this build carries no funnel "
            "instrument and any attribution from it would cover an unknown fraction"
        )
    if not funnel and not wrapper:
        return [
            "no authority open of either depth was logged, so the count these lines feed "
            "cannot be attributed to any caller"
        ]
    for label, lines in (("funnel", funnel), ("wrapper", wrapper)):
        bare = [line for line in lines if OPEN_CALLER_FIELD not in line]
        if bare:
            problems.append(
                "%d of %d %s opens logged no caller, so they cannot be attributed"
                % (len(bare), len(lines), label)
            )
    return problems


class Suite(object):
    def __init__(self, kin, workdir, daemon=None, verbose=False):
        self.kin = kin
        self.daemon = daemon
        self.workdir = workdir
        self.verbose = verbose
        self.env = dict(os.environ)
        self.env["KIN_HOME"] = os.path.join(workdir, "kin-home")
        self.env["KIN_DAEMON_AUTO_EMBED"] = "0"
        self.env["KIN_EMBED_BACKEND"] = "cpu"
        self.env["KIN_VFS_DISABLE"] = "1"
        self.env["RUST_LOG"] = "kin_cli=info,kin_daemon=info,kin_db=info"
        self.env.pop("KIN_MCP_REPO", None)
        self.env.pop("KIN_DIR", None)
        if daemon:
            self.env["KIN_DAEMON_BIN"] = daemon
        os.makedirs(self.env["KIN_HOME"], exist_ok=True)
        self.repo = None

    def log(self, line):
        if self.verbose:
            print("  " + line, flush=True)

    def git(self, args):
        base = ["git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false"]
        rc, out = run(base + args, cwd=self.repo, env=self.env)
        if rc != 0:
            raise RuntimeError("git %s failed: %s" % (" ".join(args), tail(out)))

    def kin_run(self, args, timeout=900):
        rc, out = run([self.kin] + args, cwd=self.repo, env=self.env, timeout=timeout)
        self.log("kin %s -> %d" % (" ".join(args), rc))
        return rc, out

    def build_fixture(self):
        repo = os.path.join(self.workdir, "fixture")
        os.makedirs(os.path.join(repo, "src"))
        self.repo = repo
        self.git(["init", "--initial-branch=main"])
        self.git(["config", "user.name", "Kin Acceptance"])
        self.git(["config", "user.email", "acceptance@firelock.ai"])
        for index in range(4):
            with open(os.path.join(repo, "src", "mod_%d.py" % index), "w") as handle:
                handle.write("def fn_%d():\n    return %d\n" % (index, index))
        # A structured artifact, so the body-reading half of the coverage read
        # is exercised rather than skipped. Without one, no body is ever fetched
        # and a path that could not fetch bodies at all would still pass.
        with open(os.path.join(repo, "pyproject.toml"), "w") as handle:
            handle.write('[project]\nname = "fixture"\nversion = "0.1.0"\n')
        self.git(["add", "-A"])
        self.git(["commit", "-m", "fixture"])
        rc, out = self.kin_run(["init", "--no-enrich"])
        if rc != 0:
            raise RuntimeError("kin init exited %d: %s" % (rc, tail(out)))
        return repo

    def daemon_log(self):
        path = os.path.join(self.repo, ".kin", "daemon.log")
        if not os.path.isfile(path):
            return None
        with open(path, "r", errors="replace") as handle:
            return handle.read()

    def status(self):
        rc, out = self.kin_run(["graph", "status", "--json"])
        if rc != 0:
            return None, out
        try:
            start = out.find("{")
            end = out.rfind("}")
            return json.loads(out[start : end + 1]), out
        except (ValueError, IndexError):
            return None, out


def check_clean(suite):
    result = Result(0, "a freshly converted store reports its trees in sync")
    report, out = suite.status()
    coverage = coverage_of(report)
    if coverage is None:
        result.unknown("artifact coverage was not readable: %s" % tail(out))
        return result
    problems = sync_problems(coverage, expect_in_sync=True)
    if problems is None:
        result.unknown("the in-sync field carried neither true nor false")
        return result
    if problems:
        result.bad("; ".join(problems))
        return result
    result.ok("the control holds: a clean store reads in sync")
    return result


def check_diverged(suite):
    result = Result(1, "a store whose trees differ is reported out of sync")
    # Change a tracked file after admission, so the graph the daemon carries and
    # the tree the authority holds are no longer the same.
    with open(os.path.join(suite.repo, "src", "mod_0.py"), "w") as handle:
        handle.write("def fn_0():\n    return 99\n\ndef added_after_admission():\n    pass\n")
    report, out = suite.status()
    coverage = coverage_of(report)
    if coverage is None:
        result.unknown("artifact coverage was not readable: %s" % tail(out))
        return result
    if coverage.get(IN_SYNC) is True:
        # Two things produce this: a read serving the graph's own tree, and a
        # divergence that never took. They are not separable from here, so this
        # is UNREADABLE rather than a FAIL, and a green suite never rests on it.
        result.unknown(
            "the trees still read in sync after the worktree changed, so either the "
            "divergence did not take on this host or the read is comparing the graph "
            "against itself; this arm cannot separate those and does not guess"
        )
        return result
    problems = sync_problems(coverage, expect_in_sync=False)
    if problems is None:
        result.unknown("the in-sync field carried neither true nor false")
        return result
    if problems:
        result.bad("; ".join(problems))
        return result
    result.ok("the read compared against durable truth and reported the divergence")
    return result


def check_instrument(suite):
    result = Result(2, "every authority open names the caller that asked for it")
    problems = instrument_problems(suite.daemon_log())
    if problems is None:
        result.unknown("the daemon log could not be read")
        return result
    if problems:
        result.bad("; ".join(problems))
        return result
    result.ok("every logged authority open carries its caller")
    return result


def self_test():
    asserts = 0

    def expect(condition, label):
        nonlocal asserts
        asserts += 1
        if not condition:
            print("SELFTEST FAIL %s" % label)
            sys.exit(1)

    expect(sync_problems({IN_SYNC: True}, True) == [], "in sync passes the clean arm")
    expect(sync_problems({IN_SYNC: False}, True) != [], "out of sync fails the clean arm")
    expect(sync_problems({IN_SYNC: False}, False) == [], "out of sync passes the diverged arm")
    expect(sync_problems({IN_SYNC: True}, False) != [], "in sync fails the diverged arm")
    expect(sync_problems({}, True) is None, "a missing field is unknown, never agreement")
    expect(sync_problems({IN_SYNC: "yes"}, True) is None, "a non-boolean is unknown")
    expect(sync_problems(None, True) is None, "an unreadable coverage block is unknown")

    expect(coverage_of({"artifact_coverage": {IN_SYNC: True}}) is not None, "nested block reads")
    expect(coverage_of({IN_SYNC: True}) is not None, "a flat block reads")
    expect(coverage_of({"artifact_coverage": {}}) is None, "a block without the field is unknown")
    expect(coverage_of("not a report") is None, "a non-dict is unknown")

    good = "INFO %s repository=r caller=graph_health.rs:201 opens_on_this_thread=1" % OPEN_LINE
    bare = "INFO %s repository=r opens_on_this_thread=1" % OPEN_LINE
    funnel = "INFO %s repository=r caller=state.rs:4676" % FUNNEL_LINE
    bare_funnel = "INFO %s repository=r" % FUNNEL_LINE
    both = funnel + "\n" + good
    expect(instrument_problems(both) == [], "both depths attributed passes")
    expect(
        instrument_problems(good) != [],
        "the wrapper alone fails, because a build with no funnel instrument attributes an "
        "unknown fraction",
    )
    expect(instrument_problems(funnel) == [], "the funnel alone passes")
    expect(instrument_problems(funnel + "\n" + bare) != [], "a bare wrapper open fails")
    expect(instrument_problems(bare_funnel) != [], "a bare funnel open fails")
    expect(instrument_problems("nothing here") != [], "no open logged at all fails")
    expect(instrument_problems(None) is None, "an unreadable log is unknown")
    expect(
        instrument_problems("\x1b[32m" + both + "\x1b[0m") == [],
        "ANSI escapes do not hide the caller",
    )
    expect(
        instrument_problems(funnel) == [] and instrument_problems(funnel + "\n" + good) == [],
        "the funnel line is not miscounted as a wrapper open despite containing its text",
    )

    print("SELFTEST PASS %d assertions over 3 graders" % asserts)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kin", default=os.environ.get("KIN_BIN"))
    parser.add_argument("--daemon", default=os.environ.get("KIN_DAEMON_BIN"))
    parser.add_argument("--json", dest="json_path", default=None)
    parser.add_argument("--label", default=os.environ.get("KIN_ACCEPTANCE_LABEL"))
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        return self_test()
    if not args.kin:
        print("setup error: --kin or KIN_BIN must name the binary under test", file=sys.stderr)
        return 3
    if not os.path.isfile(args.kin) or not os.access(args.kin, os.X_OK):
        print("setup error: %s is not an executable file" % args.kin, file=sys.stderr)
        return 3

    workdir = tempfile.mkdtemp(prefix="kin-coverage-read-")
    results = []
    try:
        suite = Suite(args.kin, workdir, daemon=args.daemon, verbose=args.verbose)
        suite.build_fixture()
        # The clean control runs FIRST and against an untouched store, because
        # the arm below mutates the worktree and cannot be undone cheaply.
        results.append(check_clean(suite))
        results.append(check_diverged(suite))
        results.append(check_instrument(suite))
    except Exception as error:  # noqa: BLE001 - a setup failure is its own exit code
        print("setup error: %s" % error, file=sys.stderr)
        return 3
    finally:
        if not args.keep:
            shutil.rmtree(workdir, ignore_errors=True)

    for result in results:
        print("CHECK %d %s %s %s" % (result.id, TICKET, result.status, result.detail), flush=True)

    if args.json_path:
        with open(args.json_path, "w") as handle:
            json.dump(
                {
                    "label": args.label,
                    "ticket": TICKET,
                    "checks": [
                        {
                            "id": r.id,
                            "title": r.title,
                            "status": r.status,
                            "detail": r.detail,
                            "asserts": r.asserts,
                        }
                        for r in results
                    ],
                },
                handle,
                indent=2,
            )

    if any(r.status == FAIL for r in results):
        return 1
    if any(r.status == UNREADABLE for r in results):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
