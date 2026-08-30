#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
"""NON-CITABLE acceptance suite for the coverage read's authority open (FIR-2964).

`kin graph status` computes artifact coverage against durable truth. It used to
get that by opening the repository authority, which reads the authoritative
snapshot into memory and decodes it; on a converted repository about
nineteen twentieths of those bytes are the change map, and this read touches no
change, no entity and no relation. It needs the durable workspace tree and a few
bodies by content address. The daemon now retains the tree at startup and serves
the bodies from the backend it already pins, so a coverage read opens nothing.

This suite grades the SUBSTITUTION, not the memory. It asserts that the fast
path runs, that the slow path still exists and still works, and above all that
the two answer the same thing. It asserts no resident set: a fixture small enough
to run in CI cannot exhibit the transient this change removes, and a check that
claimed to measure it would be measuring nothing. The numbers belong in the
lane report against a real corpus.

Three checks, and the third is the one that matters.

``paths`` proves each arm took the path it claims, by reading the daemon's own
log. Without it the other two grade one observation twice: if the retention
silently stopped applying, both arms would run the slow path, agree perfectly,
and pass.

``agreement`` runs both arms over one store and requires identical coverage.

``divergence`` is the arm that catches the substitution worth catching. The
obvious way to serve a durable tree cheaply is to hand over the tree the daemon
already has, which is the one its query graph was built from. That passes
``agreement`` on any clean store, because comparing the graph to itself always
reports coherence. So this check makes the graph and durable truth actually
differ and requires BOTH arms to say so. If divergence cannot be established on
this host it reports UNREADABLE rather than passing, because an arm that never
reached its own condition has graded nothing.

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
import time


PASS = "PASS"
FAIL = "FAIL"
UNREADABLE = "UNREADABLE"
TICKET = "FIR-2964"

# The lever that turns the retention off. Registered in kin-core's env registry.
NO_TREE_ENV = "KIN_DAEMON_NO_COVERAGE_TREE"

# The daemon's own words for which path a coverage read took. Matched as
# substrings of a log line, because the lines carry a repository id and a count
# that vary; the phrases are the claim, which does not.
FAST_PATH_LINE = "coverage read served from the retained workspace tree"
SLOW_PATH_LINE = "opens this repository's authority"

# The coverage fields both arms must agree on. Named explicitly rather than
# compared as whole JSON, because the report also carries timings and counters
# that legitimately differ between two runs, and a whole-object comparison would
# fail on those and teach nothing.
COVERAGE_FIELDS = (
    "repository_tree_in_sync",
    "issue_paths",
    "covered_artifacts",
    "authority_artifacts",
)


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


def path_problems(log_text, expect_fast):
    """Problems in which path one daemon's log says a coverage read took.

    One grader for both arms, so they cannot drift into disagreeing about what
    the log means.
    """
    if log_text is None:
        return None
    clean = strip_ansi(log_text)
    fast = FAST_PATH_LINE in clean
    slow = SLOW_PATH_LINE in clean
    if expect_fast:
        problems = []
        if not fast:
            problems.append("the daemon never logged serving a coverage read from a retained tree")
        if slow:
            problems.append("the daemon logged opening the authority for a coverage read anyway")
        return problems
    problems = []
    if not slow:
        problems.append("the daemon never logged opening the authority for a coverage read")
    if fast:
        problems.append("the daemon served from a retained tree with the lever set")
    return problems


def coverage_of(report):
    """The coverage fields, or ``None`` when the report cannot be read."""
    if not isinstance(report, dict):
        return None
    coverage = report.get("artifact_coverage")
    if not isinstance(coverage, dict):
        # Older or narrower shapes put the fields at the top level. Read either,
        # and report unreadable rather than inventing zeros, because a missing
        # field compared against a missing field agrees perfectly.
        coverage = report
    found = {}
    for field in COVERAGE_FIELDS:
        if field in coverage:
            found[field] = coverage[field]
    return found or None


def agreement_problems(fast, slow):
    """Problems in two arms' coverage readings."""
    if fast is None or slow is None:
        return None
    if not fast or not slow:
        return None
    shared = sorted(set(fast) & set(slow))
    if not shared:
        return None
    problems = []
    for field in shared:
        if fast[field] != slow[field]:
            problems.append("%s: fast=%r slow=%r" % (field, fast[field], slow[field]))
    return problems


def divergence_problems(fast, slow):
    """Both arms must report a repository whose trees differ as out of sync."""
    if fast is None or slow is None:
        return None
    key = "repository_tree_in_sync"
    if key not in fast or key not in slow:
        return None
    if fast[key] is not False and slow[key] is not False:
        # Neither arm saw divergence, so nothing was graded. Not a pass: the
        # substitution this check exists for reports in-sync too.
        return None
    problems = []
    if fast[key] is not False:
        problems.append(
            "the slow path saw the trees diverge and the fast path reported them in sync, "
            "which is what serving the graph's own tree as durable truth looks like"
        )
    if slow[key] is not False:
        problems.append("the fast path saw the trees diverge and the slow path did not")
    return problems


class Suite(object):
    def __init__(self, kin, workdir, daemon=None, verbose=False):
        self.kin = kin
        self.daemon = daemon
        self.workdir = workdir
        self.verbose = verbose
        self.base_env = dict(os.environ)
        self.base_env["KIN_HOME"] = os.path.join(workdir, "kin-home")
        self.base_env["KIN_DAEMON_AUTO_EMBED"] = "0"
        self.base_env["KIN_EMBED_BACKEND"] = "cpu"
        self.base_env["KIN_VFS_DISABLE"] = "1"
        self.base_env.pop("KIN_MCP_REPO", None)
        self.base_env.pop("KIN_DIR", None)
        self.base_env.pop(NO_TREE_ENV, None)
        if daemon:
            self.base_env["KIN_DAEMON_BIN"] = daemon
        os.makedirs(self.base_env["KIN_HOME"], exist_ok=True)
        self.repo = None

    def log(self, line):
        if self.verbose:
            print("  " + line, flush=True)

    def env(self, no_tree=False):
        env = dict(self.base_env)
        if no_tree:
            env[NO_TREE_ENV] = "1"
        else:
            env.pop(NO_TREE_ENV, None)
        return env

    def git(self, args):
        base = ["git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false"]
        rc, out = run(base + args, cwd=self.repo, env=self.base_env)
        if rc != 0:
            raise RuntimeError("git %s failed: %s" % (" ".join(args), tail(out)))

    def kin_run(self, args, no_tree=False, timeout=900):
        rc, out = run([self.kin] + args, cwd=self.repo, env=self.env(no_tree), timeout=timeout)
        self.log("kin %s (no_tree=%s) -> %d" % (" ".join(args), no_tree, rc))
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
        # A structured artifact, so the body-reading arm of the coverage read is
        # actually exercised. Without one, `read_body` never fires and the
        # backend path this change adds is never taken.
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

    def restart_daemon(self, no_tree):
        """A fresh daemon, so its startup decides the retention under this arm.

        The lever is read at process start, so a command reaching an
        already-running daemon cannot change it. Stopping first is what makes
        the two arms two arms rather than one.
        """
        self.kin_run(["daemon", "stop"], no_tree=no_tree, timeout=180)
        log = os.path.join(self.repo, ".kin", "daemon.log")
        if os.path.isfile(log):
            os.remove(log)
        time.sleep(1)

    def status(self, no_tree):
        """One `kin graph status --json` from a freshly started daemon."""
        self.restart_daemon(no_tree)
        rc, out = self.kin_run(["graph", "status", "--json"], no_tree=no_tree)
        if rc != 0:
            return None, out, self.daemon_log()
        try:
            start = out.find("{")
            end = out.rfind("}")
            report = json.loads(out[start : end + 1])
        except (ValueError, IndexError):
            return None, out, self.daemon_log()
        return report, out, self.daemon_log()


def check_paths(suite, fast_log, slow_log):
    result = Result(0, "each arm takes the path it claims")
    problems = path_problems(fast_log, expect_fast=True)
    if problems is None:
        result.unknown("the default arm's daemon log could not be read")
        return result
    if problems:
        result.bad("; ".join(problems))
        return result
    result.ok("the default arm served the coverage read from the retained tree")

    problems = path_problems(slow_log, expect_fast=False)
    if problems is None:
        result.unknown("the %s arm's daemon log could not be read" % NO_TREE_ENV)
        return result
    if problems:
        result.bad("; ".join(problems))
        return result
    result.ok("and %s=1 put it back on the authority open" % NO_TREE_ENV)
    return result


def check_agreement(suite, fast, slow):
    result = Result(1, "both paths report the same coverage")
    problems = agreement_problems(fast, slow)
    if problems is None:
        result.unknown("coverage fields were not readable from both arms")
        return result
    if problems:
        result.bad("the two paths disagree: " + "; ".join(problems))
        return result
    result.ok("both paths agree on %d coverage field(s)" % len(set(fast) & set(slow)))
    return result


def check_divergence(suite, fast, slow, established):
    result = Result(2, "both paths still see a repository out of sync")
    if not established:
        result.unknown(
            "no divergence between the graph and durable truth could be arranged on this host, "
            "so neither arm reached the condition this check grades"
        )
        return result
    problems = divergence_problems(fast, slow)
    if problems is None:
        result.unknown(
            "neither arm reported the trees out of sync, so the divergence did not take and "
            "nothing was graded"
        )
        return result
    if problems:
        result.bad("; ".join(problems))
        return result
    result.ok(
        "both paths reported the trees out of sync, so the fast path is reading durable truth "
        "and not the graph's own tree"
    )
    return result


def self_test():
    asserts = 0

    def expect(condition, label):
        nonlocal asserts
        asserts += 1
        if not condition:
            print("SELFTEST FAIL %s" % label)
            sys.exit(1)

    fast_log = "... %s workspace_artifacts=5" % FAST_PATH_LINE
    slow_log = "... no retained workspace tree describes this publication, so the coverage read %s" % SLOW_PATH_LINE
    expect(path_problems(fast_log, True) == [], "a fast log passes the fast arm")
    expect(path_problems(fast_log, False) != [], "a fast log fails the slow arm")
    expect(path_problems(slow_log, False) == [], "a slow log passes the slow arm")
    expect(path_problems(slow_log, True) != [], "a slow log fails the fast arm")
    expect(path_problems("", True) != [], "an empty log fails the fast arm")
    expect(path_problems("", False) != [], "an empty log fails the slow arm")
    expect(path_problems(None, True) is None, "an unreadable log is unknown")
    expect(
        path_problems(fast_log + "\n" + slow_log, True) != [],
        "a log carrying both lines fails rather than passing on the first",
    )
    expect(
        path_problems("\x1b[32m" + FAST_PATH_LINE + "\x1b[0m", True) == [],
        "ANSI escapes do not hide the line",
    )

    good = {"repository_tree_in_sync": True, "issue_paths": [], "covered_artifacts": 5}
    expect(agreement_problems(good, dict(good)) == [], "identical readings agree")
    drift = dict(good)
    drift["covered_artifacts"] = 4
    expect(agreement_problems(good, drift) != [], "a differing field is caught")
    expect(agreement_problems(good, None) is None, "an unreadable arm is unknown")
    expect(agreement_problems({}, good) is None, "an empty reading is unknown, not agreement")

    out = {"repository_tree_in_sync": False}
    insync = {"repository_tree_in_sync": True}
    expect(divergence_problems(out, dict(out)) == [], "both out of sync passes")
    expect(divergence_problems(insync, out) != [], "fast in sync while slow diverged fails")
    expect(divergence_problems(out, insync) != [], "slow in sync while fast diverged fails")
    expect(
        divergence_problems(insync, dict(insync)) is None,
        "neither seeing divergence is unknown, never a pass",
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

        fast, _, fast_log = suite.status(no_tree=False)
        slow, _, slow_log = suite.status(no_tree=True)
        results.append(check_paths(suite, fast_log, slow_log))
        results.append(check_agreement(suite, coverage_of(fast), coverage_of(slow)))

        # Make durable truth and the graph differ, then ask both arms again.
        with open(os.path.join(suite.repo, "src", "mod_0.py"), "w") as handle:
            handle.write("def fn_0():\n    return 99\n\ndef added_after_admission():\n    pass\n")
        diverged_fast, _, _ = suite.status(no_tree=False)
        diverged_slow, _, _ = suite.status(no_tree=True)
        fast_cov = coverage_of(diverged_fast)
        slow_cov = coverage_of(diverged_slow)
        established = bool(
            (fast_cov and fast_cov.get("repository_tree_in_sync") is False)
            or (slow_cov and slow_cov.get("repository_tree_in_sync") is False)
        )
        results.append(check_divergence(suite, fast_cov, slow_cov, established))
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
