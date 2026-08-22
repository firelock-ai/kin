#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
"""NON-CITABLE acceptance suite for parse-hole honesty (FIR-2599).

Its output is a regression gate, never proof, never investor-facing and never a
released claim. It shares the CHECK line format, the exit codes and the
`--self-test` discipline of its siblings in this directory, so a reader who
knows one knows all of them.

What it is for
--------------
The rc0547b brownfield stranger measured expressjs/express on v0.5.47 and found
75 of 141 admitted files producing no entity, with `lib/express.js` among them.
Every surface a person or an agent reads said the store was fine: `kin graph
status` printed `No issues detected.`, `kin doctor` agreed, and `kin dead-code`
printed zeros over the hole. This suite reproduces that shape against a LOCAL
kin build in seconds and asserts the three surfaces now say so.

Every check is paired with its own control on a repository of the same shape
with no hole, because a surface that reported a hole unconditionally would pass
the first half of each check and is the failure this suite exists to catch.

    CHECK <id> <ticket> PASS|FAIL|UNREADABLE <detail>

UNREADABLE is a distinct outcome from FAIL and is never reported as a pass: it
means the probe could not be evaluated (no output, a non-JSON payload, a field
this build does not define). A crashed probe is UNREADABLE, never a verdict.
Exit status is 1 when any check FAILs, 2 when none fail but some are UNREADABLE,
0 only when every check passes, 3 on a setup error.

The binary under test
---------------------
    cargo build --release --locked --bin kin --bin kin-daemon
    python3 scripts/acceptance/parse_hole_repro.py --kin target/release/kin

`--kin` may also come from KIN_BIN. The kin-daemon beside it is used when one
exists. No binary is built by this script.
"""

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
TICKET = "FIR-2599"

# Four modules an adapter reads, and three files it cannot, all admitted under a
# .js extension. Three is the express shape in miniature: it clears the file
# floor the threshold carries, and 3 of 7 is well past its share.
READABLE = 4
UNREADABLE_FILES = 3


def run(cmd, cwd=None, env=None, timeout=600):
    proc = subprocess.run(
        cmd, cwd=cwd, env=env, timeout=timeout,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
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
        graded = [a for a in self.asserts if a["status"] in (PASS, FAIL, UNREADABLE)]
        if any(a["status"] == FAIL for a in graded):
            return FAIL
        if any(a["status"] == UNREADABLE for a in graded):
            return UNREADABLE
        if not graded:
            return UNREADABLE
        return PASS

    @property
    def detail(self):
        for wanted in (FAIL, UNREADABLE):
            for a in self.asserts:
                if a["status"] == wanted:
                    return a["detail"]
        # Every passing assertion, not the last one. Each check here grades a
        # fixture WITH the hole and its control without, and a line naming only
        # the control would read as a pass for a suite that never probed the
        # case it exists for.
        graded = [a["detail"] for a in self.asserts if a["status"] == PASS]
        return "; ".join(graded) if graded else "no assertion was reached"


# ------------------------------------------------------------------- graders

def status_withholds_all_clear(text):
    """Whether `kin graph status` output declines to report a clean store.

    Both halves are required. A page that dropped the all-clear and said nothing
    about why is not the fix; a page that named the hole under a `✓` is not
    either.
    """
    named = "parse coverage is incomplete" in text and "produced no entity" in text
    return named and "No issues detected." not in text


def doctor_row_reports_a_hole(report):
    """Whether the doctor report's parse row needs attention and names a file.

    Reads the structured report rather than the rendered table, because the
    table's column widths are presentation and the row's status is the verdict.
    Returns None when the row is absent, which is UNREADABLE rather than a
    verdict about the store.
    """
    rows = [row for row in report.get("checks", []) if row.get("id") == "parse_coverage"]
    if not rows:
        return None
    row = rows[0]
    return row.get("status") != "healthy" and ".js" in (row.get("detail") or "")


def dead_code_refuses(text):
    """Whether `kin dead-code` declined to answer rather than printing a zero."""
    return "REFUSED" in text and "No dead code found." not in text


GRADERS = {
    "status_withholds_all_clear": status_withholds_all_clear,
    "dead_code_refuses": dead_code_refuses,
}


# ------------------------------------------------------------------- fixtures

class Suite(object):
    def __init__(self, kin, workdir, daemon=None, verbose=False):
        self.kin = kin
        self.workdir = workdir
        self.verbose = verbose
        self.kin_home = os.path.join(workdir, "kin-home-%d" % os.getpid())
        os.makedirs(self.kin_home, exist_ok=True)
        self.env = dict(os.environ)
        # A scratch KIN_HOME keeps this run off the fleet's stores and the
        # auto-embed opt-out keeps it off the GPU. Neither is a nicety: this
        # suite is meant to run on every pull request beside other work.
        self.env["KIN_HOME"] = self.kin_home
        self.env["KIN_DAEMON_AUTO_EMBED"] = "0"
        self.env["KIN_EMBED_BACKEND"] = "cpu"
        self.env["KIN_VFS_DISABLE"] = "1"
        self.env.pop("KIN_MCP_REPO", None)
        self.env.pop("KIN_DIR", None)
        if daemon:
            self.env["KIN_DAEMON_BIN"] = daemon
        self.repos = {}

    def git(self, args, cwd):
        base = ["git",
                "-c", "core.hooksPath=/dev/null",
                "-c", "user.email=repro@example.invalid",
                "-c", "user.name=kin-parse-hole-repro",
                "-c", "commit.gpgsign=false"]
        return run(base + args, cwd=cwd, env=self.env)

    def kin_run(self, args, repo, timeout=600):
        return run([self.kin] + args, cwd=repo, env=self.env, timeout=timeout)

    def fixture(self, name, unreadable):
        """A JavaScript library of `READABLE` modules plus `unreadable` files an
        adapter is registered for and produces nothing from.

        Admitted through `kin init`, the boundary a user crosses, so the census
        reads the same tree and entity table the product does.
        """
        if name in self.repos:
            return self.repos[name]
        repo = os.path.join(self.workdir, name)
        os.makedirs(os.path.join(repo, "lib"), exist_ok=True)
        rc, out = self.git(["init", "--initial-branch=main"], repo)
        if rc != 0:
            raise RuntimeError("git init failed: %s" % out)
        # Every readable module requires the next one round a cycle, so each has
        # an inbound edge and the scan lists nothing. The empty answer is the one
        # the ticket is about: a bare "No dead code found." over a hole reads as
        # a licence to act.
        for index in range(READABLE):
            following = (index + 1) % READABLE
            with open(os.path.join(repo, "lib", "module%d.js" % index), "w") as handle:
                handle.write(
                    "const next = require('./module%d');\n"
                    "function handler%d() {\n  return next;\n}\n"
                    "module.exports = handler%d;\n" % (following, index, index)
                )
        for index in range(unreadable):
            # Bytes no adapter produces an entity from, under an extension that
            # admits the file as a full-adapter input. The extension is what
            # puts it in the denominator; the content is what leaves it out of
            # the entity table.
            with open(os.path.join(repo, "lib", "unreadable%d.js" % index), "wb") as handle:
                handle.write(bytes(range(8)))
        self.git(["add", "--all"], repo)
        rc, out = self.git(["commit", "-m", "a javascript library"], repo)
        if rc != 0:
            raise RuntimeError("git commit failed: %s" % out)
        rc, out = self.kin_run(["init"], repo, timeout=900)
        if rc != 0:
            raise RuntimeError("kin init failed in %s: %s" % (repo, out))
        self.repos[name] = repo
        return repo


# --------------------------------------------------------------------- checks

def check_status(suite):
    """`kin graph status` withholds its all-clear over a parse hole.

    The express page printed "Supported inputs: 141" beside "Files: 66" and then
    `✓ No issues detected.`, so it held every number a reader needed and drew the
    one conclusion those numbers refute.
    """
    result = Result("status", "graph status names a parse hole and withholds the all-clear")
    for name, unreadable, want in (("holed", UNREADABLE_FILES, True), ("whole", 0, False)):
        repo = suite.fixture(name, unreadable)
        rc, out = suite.kin_run(["graph", "status"], repo)
        if not out.strip():
            result.unknown("%s: `kin graph status` produced no output (rc=%d)" % (name, rc))
            continue
        got = status_withholds_all_clear(out)
        if got == want:
            result.ok("%s: withholds=%s as expected" % (name, got))
        else:
            result.bad("%s: withholds=%s, wanted %s. Output: %s"
                       % (name, got, want, out.strip()[:600]))
    return result


def check_doctor(suite):
    """`kin doctor` carries a parse-coverage row that needs attention."""
    result = Result("doctor", "doctor reports a parse-coverage row naming the hole")
    for name, unreadable, want in (("holed", UNREADABLE_FILES, True), ("whole", 0, False)):
        repo = suite.fixture(name, unreadable)
        # The row reads the run's one `graph status`, which needs a daemon, and
        # `kin init` leaves none running. Without this the row reports
        # "no daemon is serving this repository" and the check grades a fact
        # about the fixture as a fact about the product.
        suite.kin_run(["graph", "status"], repo)
        rc, out = suite.kin_run(["doctor", "--json"], repo)
        try:
            report = json.loads(out[out.index("{"):out.rindex("}") + 1])
        except (ValueError, json.JSONDecodeError):
            result.unknown("%s: `kin doctor --json` payload was not JSON (rc=%d): %s"
                           % (name, rc, out.strip()[:400]))
            continue
        got = doctor_row_reports_a_hole(report)
        if got is None:
            result.unknown("%s: this build's doctor report carries no `parse_coverage` row" % name)
        elif got == want:
            result.ok("%s: row reports a hole=%s as expected" % (name, got))
        else:
            rows = [r for r in report.get("checks", []) if r.get("id") == "parse_coverage"]
            result.bad("%s: row reports a hole=%s, wanted %s. Row: %s"
                       % (name, got, want, json.dumps(rows)))
    return result


def check_dead_code(suite):
    """`kin dead-code` refuses rather than printing a zero over the hole.

    The stranger's words: 0 is a number while the caveat is a paragraph. An
    empty result over a parse hole is the one answer in that command that reads
    as a licence to act.
    """
    result = Result("dead_code", "dead-code refuses over a parse hole and answers without one")
    for name, unreadable, want in (("holed", UNREADABLE_FILES, True), ("whole", 0, False)):
        repo = suite.fixture(name, unreadable)
        rc, out = suite.kin_run(["dead-code"], repo)
        if not out.strip():
            result.unknown("%s: `kin dead-code` produced no output (rc=%d)" % (name, rc))
            continue
        got = dead_code_refuses(out)
        if got == want:
            result.ok("%s: refuses=%s as expected" % (name, got))
        else:
            result.bad("%s: refuses=%s, wanted %s. Output: %s"
                       % (name, got, want, out.strip()[:600]))
    return result


CHECKS = [check_status, check_doctor, check_dead_code]


# ------------------------------------------------------------------ self-test

def self_test():
    """Falsify every grader against its own inverse.

    A grader that cannot tell its two cases apart reports a clean product on a
    broken one, so each case here is paired with the input that must produce the
    opposite verdict. This runs before any build in CI, so a broken grader is
    named in seconds rather than after three minutes of compiling.
    """
    cases = [
        ("status_withholds_all_clear", True,
         "javascript parse coverage is incomplete: 3 of 7 admitted files produced no entity"),
        ("status_withholds_all_clear", False, "✓ No issues detected."),
        # Named AND all-clear is the sabotage that matters: a page that grew the
        # sentence and kept the tick has not withheld anything.
        ("status_withholds_all_clear", False,
         "parse coverage is incomplete: produced no entity\n✓ No issues detected."),
        # A page that dropped the tick and said nothing is not the fix either.
        ("status_withholds_all_clear", False, "Entities: 4  |  Files: 4"),
        ("dead_code_refuses", True, "REFUSED: this scan cannot say whether anything is unreferenced"),
        ("dead_code_refuses", False, "No dead code found."),
        ("dead_code_refuses", False, "REFUSED\nNo dead code found."),
    ]
    failures = []
    for name, want, text in cases:
        got = GRADERS[name](text)
        if got != want:
            failures.append("%s(%r) = %s, wanted %s" % (name, text, got, want))

    # The doctor grader reads a structure rather than a string.
    doctor_cases = [
        (True, {"checks": [{"id": "parse_coverage", "status": "stale",
                            "detail": "3 of 7 admitted files, including lib/unreadable0.js"}]}),
        (False, {"checks": [{"id": "parse_coverage", "status": "healthy",
                             "detail": "javascript 7/7"}]}),
        # A row that needs attention and names no file is not a usable report,
        # and neither is one whose detail is missing entirely.
        (False, {"checks": [{"id": "parse_coverage", "status": "stale", "detail": "incomplete"}]}),
        (False, {"checks": [{"id": "parse_coverage", "status": "stale"}]}),
        # An absent row is UNREADABLE, never a verdict about the store.
        (None, {"checks": [{"id": "relation_census", "status": "healthy"}]}),
        (None, {"checks": []}),
    ]
    for want, report in doctor_cases:
        got = doctor_row_reports_a_hole(report)
        if got != want:
            failures.append("doctor_row_reports_a_hole(%s) = %s, wanted %s"
                            % (json.dumps(report), got, want))

    # Result.status must never grade a FAIL or an ungraded run as a pass.
    grade_cases = [
        (PASS, [(PASS, "a")]),
        (FAIL, [(PASS, "a"), (FAIL, "b")]),
        (UNREADABLE, [(PASS, "a"), (UNREADABLE, "b")]),
        (FAIL, [(UNREADABLE, "a"), (FAIL, "b")]),
        (UNREADABLE, []),
    ]
    for want, entries in grade_cases:
        result = Result("t", "t")
        for status, detail in entries:
            result.asserts.append({"status": status, "detail": detail})
        if result.status != want:
            failures.append("Result.status(%s) = %s, wanted %s"
                            % (entries, result.status, want))

    for failure in failures:
        print("SELFTEST FAIL %s" % failure)
    total = len(cases) + len(doctor_cases) + len(grade_cases)
    print("kin-parse-hole-repro: self-test %d/%d cases"
          % (total - len(failures), total))
    return 1 if failures else 0


# ----------------------------------------------------------------------- main

def main(argv):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--kin", default=os.environ.get("KIN_BIN"),
                        help="the kin binary under test")
    parser.add_argument("--daemon", default=os.environ.get("KIN_DAEMON_BIN"),
                        help="the kin-daemon beside it")
    parser.add_argument("--keep", action="store_true", help="keep the fixtures")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--self-test", action="store_true",
                        help="falsify this suite's graders and exit")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    if not args.kin:
        print("kin-parse-hole-repro: no kin binary. Pass --kin or set KIN_BIN.")
        return 3
    kin = os.path.abspath(args.kin)
    if not os.path.isfile(kin) or not os.access(kin, os.X_OK):
        print("kin-parse-hole-repro: %s is not an executable file" % kin)
        return 3
    daemon = args.daemon
    if not daemon:
        beside = os.path.join(os.path.dirname(kin), "kin-daemon")
        daemon = beside if os.path.isfile(beside) else None

    workdir = tempfile.mkdtemp(prefix="kin-parse-hole-repro-")
    try:
        suite = Suite(kin, workdir, daemon=daemon, verbose=args.verbose)
        results = []
        for check in CHECKS:
            try:
                results.append(check(suite))
            except Exception as error:  # noqa: BLE001 - a crashed probe is UNREADABLE
                result = Result(getattr(check, "__name__", "check"), "probe crashed")
                result.unknown("%s: %s" % (type(error).__name__, error))
                results.append(result)
        for result in results:
            print("CHECK %s %s %s %s" % (result.id, TICKET, result.status, result.detail))
        failed = [r for r in results if r.status == FAIL]
        unreadable = [r for r in results if r.status == UNREADABLE]
        print("kin-parse-hole-repro: %d checks, %d pass, %d FAIL, %d UNREADABLE"
              % (len(results), len(results) - len(failed) - len(unreadable),
                 len(failed), len(unreadable)))
        if failed:
            return 1
        if unreadable:
            return 2
        return 0
    finally:
        if not args.keep:
            shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
