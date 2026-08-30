#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
"""NON-CITABLE acceptance suite for bounded Git history admission (FIR-2041).

`kin init --history-limit N` takes in the newest N commits of HEAD's
first-parent history instead of all of it, so a repository whose whole history
does not fit a machine can still be converted. This suite proves the flag cuts
what it says it cuts, records where it stopped, and says so on the surface a
reader would otherwise misread.

The default arm is the load-bearing one and it runs FIRST. A bound that fails to
cut is a visible defect: the conversion is as expensive as it always was and the
operator finds out immediately. A default that silently cuts is not visible at
all. The store is internally consistent, every proof passes, the counts agree
with each other, and the only evidence is history that is not there. So check 0
converts the same fixture with no flag and requires every commit, and check 1's
pass means nothing without it.

Check 2 grades the boundary as a JOIN rather than against a fixed expectation.
It takes the commit ids the product published as unadmitted and requires the
SOURCE repository to hold every one of them, and requires the oldest admitted
commit to be a commit the source holds too. An expectation that the list is
merely non-empty passes on a list of fabricated ids, and a boundary naming
commits that do not exist is exactly what an off-by-one in the window selection
would produce.

Check 3 is the false-boundary control. A limit larger than the repository's own
history admits all of it and must record NO boundary, because reporting one
would tell an operator their history is incomplete at the moment all of it was
admitted. Without this arm, a boundary written unconditionally satisfies every
assertion in check 1.

What this suite does NOT grade, said here so nobody later reads it as more: it
grades the admitted window, the durable record and the reported sentence. It
grades no resident set and no conversion peak. Whether a bounded conversion
actually fits a smaller machine is a measurement, not a check, and FIR-2955 owns
the memory it is a workaround for.

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
import subprocess
import sys
import tempfile


PASS = "PASS"
FAIL = "FAIL"
UNREADABLE = "UNREADABLE"
TICKET = "FIR-2041"

# Commits on the fixture's mainline before the side branch merges in.
TRUNK_COMMITS = 8

# The bound the bounded arm asks for. Small enough that real history falls
# outside the window on a fixture this size, and large enough that the window
# still contains more than one commit.
LIMIT = 3

# Fragments of the sentence a bounded repository prints at the end of its log.
# Graded as a set of required fragments rather than by equality, because the
# sentence carries a commit id and two counts that vary with the fixture; the
# fragments are the CLAIMS, which do not.
BOUNDARY_CLAIMS = (
    "admitted history starts at",
    "are not in the semantic graph",
)

# The claim the sentence must never make. `kin log` reaching the oldest admitted
# change is the exact moment a reader concludes the repository began there, and
# the whole point of the record is that it did not.
FORBIDDEN_CLAIM = "repository began"


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


def boundary_problems(manifest, expect_bounded, requested=None, admitted=None):
    """Problems in one manifest's recorded boundary.

    One grader for both directions, so the bounded and unbounded arms cannot
    drift into disagreeing about what the record means.
    """
    if not isinstance(manifest, dict):
        return None
    recorded = manifest.get("history_boundary")
    if not expect_bounded:
        if recorded is None:
            return []
        return ["a conversion that cut nothing recorded a boundary: %r" % (recorded,)]
    if recorded is None:
        return ["a conversion that cut history recorded no boundary"]
    problems = []
    if requested is not None and recorded.get("requested_limit") != requested:
        problems.append(
            "recorded requested_limit %r, asked for %r"
            % (recorded.get("requested_limit"), requested)
        )
    if admitted is not None and recorded.get("admitted_commits") != admitted:
        problems.append(
            "recorded admitted_commits %r, admitted %r"
            % (recorded.get("admitted_commits"), admitted)
        )
    if not recorded.get("oldest_admitted_commit"):
        problems.append("the boundary names no oldest admitted commit")
    if not recorded.get("unadmitted_parents"):
        problems.append("the boundary names no unadmitted parent")
    return problems


def log_problems(text, expect_bounded):
    """Problems in one ``kin log`` rendering's boundary sentence."""
    body = text or ""
    hits = [line for line in body.splitlines() if BOUNDARY_CLAIMS[0] in line]
    if not expect_bounded:
        return [] if not hits else ["a whole-history repository printed %r" % hits]
    if len(hits) != 1:
        return ["expected one boundary sentence, got %d" % len(hits)]
    line = hits[0]
    problems = []
    for claim in BOUNDARY_CLAIMS:
        if claim not in line:
            problems.append("the sentence omits %r" % claim)
    if FORBIDDEN_CLAIM in line:
        problems.append("the sentence claims the %r there" % FORBIDDEN_CLAIM)
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
        self.env.pop("KIN_MCP_REPO", None)
        self.env.pop("KIN_DIR", None)
        if daemon:
            self.env["KIN_DAEMON_BIN"] = daemon
        os.makedirs(self.env["KIN_HOME"], exist_ok=True)
        self.total_commits = None

    def log(self, line):
        if self.verbose:
            print("  " + line, flush=True)

    def git(self, repo, args, check=True):
        base = ["git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false"]
        rc, out = run(base + args, cwd=repo, env=self.env)
        if check and rc != 0:
            raise RuntimeError("git %s failed: %s" % (" ".join(args), tail(out)))
        return rc, out

    def kin_run(self, repo, args, timeout=900):
        rc, out = run([self.kin] + args, cwd=repo, env=self.env, timeout=timeout)
        self.log("kin %s -> %d" % (" ".join(args), rc))
        return rc, out

    def build_fixture(self, name):
        """A fresh copy of the same history, one per arm.

        Copied rather than shared, because `kin init` writes into the
        repository it converts and two arms sharing one directory would make the
        second arm's result depend on the first.
        """
        repo = os.path.join(self.workdir, name)
        os.makedirs(os.path.join(repo, "src"))
        self.git(repo, ["init", "--initial-branch=main"])
        self.git(repo, ["config", "user.name", "Kin Acceptance"])
        self.git(repo, ["config", "user.email", "acceptance@firelock.ai"])

        def commit(label, body):
            with open(os.path.join(repo, "src", "%s.py" % label), "w") as handle:
                handle.write(body)
            self.git(repo, ["add", "-A"])
            self.git(repo, ["commit", "-m", "add %s" % label])

        for index in range(TRUNK_COMMITS):
            commit("trunk_%d" % index, "def trunk_%d():\n    return %d\n" % (index, index))
        self.git(repo, ["checkout", "-b", "side"])
        commit("side_one", "def side_one():\n    return 1\n")
        self.git(repo, ["checkout", "main"])
        self.git(repo, ["merge", "--no-ff", "-m", "merge side", "side"])
        commit("after_merge", "def after_merge():\n    return 0\n")

        _, out = self.git(repo, ["rev-list", "--all", "--count"])
        total = int(out.strip())
        if self.total_commits is None:
            self.total_commits = total
        elif self.total_commits != total:
            raise RuntimeError("fixture builds are not identical across arms")
        return repo

    def manifest(self, repo):
        path = os.path.join(repo, ".kin", "manifest.json")
        if not os.path.isfile(path):
            return None
        with open(path) as handle:
            return json.load(handle)

    def change_count(self, repo):
        """Git-origin changes in the store, read from `kin log --json`.

        A window wider than the fixture is requested so the walk reaches the
        bottom; the count is what the report actually returned rather than what
        was asked for.
        """
        rc, out = self.kin_run(repo, ["log", "-n", "10000", "--json"])
        if rc != 0:
            return None, out
        try:
            start = out.find("{")
            end = out.rfind("}")
            report = json.loads(out[start : end + 1])
        except (ValueError, IndexError):
            return None, out
        return len(report.get("entries", [])), out

    def convert(self, repo, limit=None):
        args = ["init", "--no-enrich"]
        if limit is not None:
            args += ["--history-limit", str(limit)]
        return self.kin_run(repo, args)


def check_default_is_whole(suite):
    """CHECK 0: a conversion that says nothing takes in every commit."""
    result = Result(0, "the default admits whole history")
    repo = suite.build_fixture("default-arm")
    rc, out = suite.convert(repo)
    if rc != 0:
        result.unknown("`kin init` with no flag exited %d: %s" % (rc, tail(out)))
        return result, None
    count, log_out = suite.change_count(repo)
    if count is None:
        result.unknown("`kin log --json` was not readable: %s" % tail(log_out))
        return result, None
    if count != suite.total_commits:
        result.bad(
            "the default admitted %d of the fixture's %d commits, so it bounded history "
            "nobody asked to bound" % (count, suite.total_commits)
        )
        return result, repo
    result.ok("the default admitted all %d commits" % count)

    problems = boundary_problems(suite.manifest(repo), expect_bounded=False)
    if problems is None:
        result.unknown("the manifest was not readable")
        return result, repo
    if problems:
        result.bad("; ".join(problems))
        return result, repo
    result.ok("and recorded no boundary")

    problems = log_problems(log_out, expect_bounded=False)
    if problems:
        result.bad("; ".join(problems))
        return result, repo
    result.ok("and `kin log` said nothing about an admitted-history edge")
    return result, repo


def check_bound_cuts_and_records(suite):
    """CHECK 1: a bound admits its window and records where it stopped."""
    result = Result(1, "a bound admits its window")
    repo = suite.build_fixture("bounded-arm")
    rc, out = suite.convert(repo, limit=LIMIT)
    if rc != 0:
        result.unknown("`kin init --history-limit %d` exited %d: %s" % (LIMIT, rc, tail(out)))
        return result, None
    count, log_out = suite.change_count(repo)
    if count is None:
        result.unknown("`kin log --json` was not readable: %s" % tail(log_out))
        return result, None
    if count != LIMIT:
        result.bad(
            "`--history-limit %d` admitted %d changes; a first-parent window of N admits "
            "exactly N" % (LIMIT, count)
        )
        return result, repo
    result.ok("`--history-limit %d` admitted exactly %d changes" % (LIMIT, LIMIT))

    problems = boundary_problems(
        suite.manifest(repo), expect_bounded=True, requested=LIMIT, admitted=LIMIT
    )
    if problems is None:
        result.unknown("the manifest was not readable")
        return result, repo
    if problems:
        result.bad("; ".join(problems))
        return result, repo
    result.ok("the manifest records the requested limit, the admitted count and the edge")

    problems = log_problems(log_out, expect_bounded=True)
    if problems:
        result.bad("; ".join(problems))
        return result, repo
    result.ok("and `kin log` reports where admitted history starts")
    return result, repo


def check_boundary_names_real_commits(suite, repo):
    """CHECK 2: every commit the boundary names is one the source repository holds."""
    result = Result(2, "the boundary names real Git commits")
    if repo is None:
        result.unknown("the bounded arm produced no repository to read")
        return result
    manifest = suite.manifest(repo)
    recorded = (manifest or {}).get("history_boundary")
    if not recorded:
        result.unknown("the bounded arm recorded no boundary to grade")
        return result

    named = list(recorded.get("unadmitted_parents") or [])
    oldest = recorded.get("oldest_admitted_commit")
    if oldest:
        named.append(oldest)
    if not named:
        result.unknown("the boundary named no commits at all")
        return result

    missing = []
    for oid in named:
        rc, _ = suite.git(repo, ["cat-file", "-e", "%s^{commit}" % oid], check=False)
        if rc != 0:
            missing.append(oid)
    if missing:
        result.bad(
            "the boundary names %d commit(s) this repository does not hold: %s"
            % (len(missing), ", ".join(missing[:4]))
        )
        return result
    result.ok("all %d commit(s) the boundary names exist in the repository" % len(named))

    # The must-miss control. Without it, a `cat-file -e` that answered 0 for
    # everything would pass the arm above on any list at all.
    fabricated = "0" * 40
    rc, _ = suite.git(repo, ["cat-file", "-e", "%s^{commit}" % fabricated], check=False)
    if rc == 0:
        result.unknown("the existence probe accepts a fabricated commit id, so it proves nothing")
        return result
    result.ok("and a fabricated id is rejected by the same probe")
    return result


def check_a_limit_that_binds_nothing_records_nothing(suite):
    """CHECK 3: asking for more history than there is records no boundary."""
    result = Result(3, "a limit nothing binds records nothing")
    repo = suite.build_fixture("roomy-arm")
    limit = (suite.total_commits or TRUNK_COMMITS) * 10
    rc, out = suite.convert(repo, limit=limit)
    if rc != 0:
        result.unknown("`kin init --history-limit %d` exited %d: %s" % (limit, rc, tail(out)))
        return result
    count, log_out = suite.change_count(repo)
    if count is None:
        result.unknown("`kin log --json` was not readable: %s" % tail(log_out))
        return result
    if count != suite.total_commits:
        result.bad(
            "a limit of %d over %d commits admitted only %d"
            % (limit, suite.total_commits, count)
        )
        return result
    result.ok("a limit of %d admitted all %d commits" % (limit, count))

    problems = boundary_problems(suite.manifest(repo), expect_bounded=False)
    if problems is None:
        result.unknown("the manifest was not readable")
        return result
    if problems:
        result.bad("; ".join(problems))
        return result
    result.ok("and recorded no boundary, so no reader is told history is incomplete")

    problems = log_problems(log_out, expect_bounded=False)
    if problems:
        result.bad("; ".join(problems))
        return result
    result.ok("and `kin log` stayed silent")
    return result


def self_test():
    """Drive every grader against its inverse, with no repository."""
    checks = 0
    asserts = 0

    def expect(condition, label):
        nonlocal asserts
        asserts += 1
        if not condition:
            print("SELFTEST FAIL %s" % label)
            sys.exit(1)

    checks += 1
    expect(boundary_problems({"history_boundary": None}, False) == [], "unbounded accepts absent")
    expect(
        boundary_problems({"history_boundary": {"requested_limit": 3}}, False) != [],
        "unbounded rejects a recorded boundary",
    )
    expect(
        boundary_problems({"history_boundary": None}, True) != [],
        "bounded rejects an absent boundary",
    )

    checks += 1
    good = {
        "history_boundary": {
            "requested_limit": 3,
            "admitted_commits": 3,
            "oldest_admitted_commit": "a" * 40,
            "unadmitted_parents": ["b" * 40],
        }
    }
    expect(boundary_problems(good, True, 3, 3) == [], "bounded accepts a complete record")
    expect(
        boundary_problems(good, True, 4, 3) != [],
        "bounded rejects a record whose requested limit is not the one asked for",
    )
    expect(
        boundary_problems(good, True, 3, 4) != [],
        "bounded rejects a record whose admitted count is not the one admitted",
    )
    for field in ("oldest_admitted_commit", "unadmitted_parents"):
        broken = {"history_boundary": dict(good["history_boundary"])}
        broken["history_boundary"][field] = "" if field.endswith("commit") else []
        expect(
            boundary_problems(broken, True, 3, 3) != [],
            "bounded rejects a record missing %s" % field,
        )
    expect(boundary_problems("not a manifest", True) is None, "an unreadable manifest is unknown")

    checks += 1
    sentence = (
        "admitted history starts at Git commit abc, the oldest of 3 commit(s) admitted under "
        "`--history-limit 3`; 2 older or side-branch Git commit(s) are in this store as Git "
        "objects and are not in the semantic graph"
    )
    expect(log_problems("change x\n\n" + sentence, True) == [], "a full sentence passes")
    expect(log_problems("change x", True) != [], "a missing sentence fails the bounded arm")
    expect(log_problems("change x", False) == [], "silence passes the unbounded arm")
    expect(
        log_problems("change x\n\n" + sentence, False) != [],
        "a sentence on a whole-history repository fails",
    )
    expect(
        log_problems("change x\n\nadmitted history starts at commit abc", True) != [],
        "a sentence that omits what was left out fails",
    )
    expect(
        log_problems(
            "change x\n\n" + sentence + " and the repository began here", True
        )
        != [],
        "a sentence claiming the repository began at the edge fails",
    )
    expect(
        log_problems("change x\n\n" + sentence + "\n" + sentence, True) != [],
        "two sentences fail rather than passing on the first",
    )

    print("SELFTEST PASS %d assertions over %d graders" % (asserts, checks))
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

    workdir = tempfile.mkdtemp(prefix="kin-history-limit-")
    results = []
    try:
        suite = Suite(args.kin, workdir, daemon=args.daemon, verbose=args.verbose)
        # The unbounded control runs first on purpose: check 1 proves nothing
        # about a product whose default already bounds.
        default_result, _ = check_default_is_whole(suite)
        results.append(default_result)
        bounded_result, bounded_repo = check_bound_cuts_and_records(suite)
        results.append(bounded_result)
        results.append(check_boundary_names_real_commits(suite, bounded_repo))
        results.append(check_a_limit_that_binds_nothing_records_nothing(suite))
    except Exception as error:  # noqa: BLE001 - a setup failure is its own exit code
        print("setup error: %s" % error, file=sys.stderr)
        return 3
    finally:
        if not args.keep:
            import shutil

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
                            "id": result.id,
                            "title": result.title,
                            "status": result.status,
                            "detail": result.detail,
                            "asserts": result.asserts,
                        }
                        for result in results
                    ],
                },
                handle,
                indent=2,
            )

    if any(result.status == FAIL for result in results):
        return 1
    if any(result.status == UNREADABLE for result in results):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
