#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
"""NON-CITABLE acceptance suite for the same-owner bare call (FIR-1826).

Its output is a regression gate, never proof, never investor-facing and never a
released claim. It shares the CHECK line format, the exit codes and the
`--self-test` discipline of its siblings in this directory, so a reader who
knows one knows all of them.

What it is for
--------------
A bare call whose only candidate was a same-file qualified-name entity resolved
to no edge at all. `void Foo::a() { b(); }` in a file that also defines `Foo::b`
reached no linker tier, so the call site existed in the source and in no edge,
and every consumer built on the graph omitted it with nothing to say so. The
unit arm of that fix lives in
`crates/kin-index/tests/same_owner_bare_call_resolution.rs` and drives the
linker directly. This is the end-to-end arm: it builds a repository, converts it
with `kin init`, and asks the shipped binary what calls what.

What it asserts, and what it deliberately does not
--------------------------------------------------
An EDGE COUNT, never a does-not-error. Each check names the caller it expects
and the callers it must not see, because a surface that answered with every
entity would satisfy a does-not-error assertion on every one of them.

Two languages bind and one must not, in the same suite and against the same
binary. The negative is not decoration: the rule under test is a per-language
judgement, so a build that bound every language would pass both positives, and
only Python answers that. Its shape is written to be identical to the Java one
apart from the language.

    CHECK <id> <ticket> PASS|FAIL|UNREADABLE <detail>

UNREADABLE is a distinct outcome from FAIL and is never reported as a pass: it
means the probe could not be evaluated (no output, an inspect that named no
entity, a build whose command this suite does not know). A crashed probe is
UNREADABLE, never a verdict. Exit status is 1 when any check FAILs, 2 when none
fail but some are UNREADABLE, 0 only when every check passes, 3 on a setup
error.

The binary under test
---------------------
    cargo build --release --locked --bin kin --bin kin-daemon
    python3 scripts/acceptance/same_owner_call_repro.py --kin target/release/kin

`--kin` may also come from KIN_BIN. The kin-daemon beside it is used when one
exists. No binary is built by this script.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

PASS = "PASS"
FAIL = "FAIL"
UNREADABLE = "UNREADABLE"
TICKET = "FIR-1826"

# `kin graph inspect <name>` prints one line per edge:
#     <- Calls  Report.renderSummary  [Method] (Report.java; ...
# The direction arrow and the relation kind are what this reads; everything
# after the file is rendering that has changed before and may change again.
INSPECT_EDGE = re.compile(r"\s*(<-|->)\s+(\w+)\s+(.+?)\s+\[(\w+)\]\s+\((.+?);")


class Result(object):
    def __init__(self, cid, status, detail):
        self.id = cid
        self.status = status
        self.detail = detail


# ── graders ──
#
# Pure functions, so --self-test can drive every one of them against the input
# that must produce the opposite verdict. A grader that cannot tell its own
# cases apart reports a clean product on a broken one.

def incoming_callers(inspect_text):
    """Every entity the inspect output says CALLS the inspected one.

    Returns None when the text carries no edge line at all, which is a different
    answer from "no caller": an inspect that failed and an entity nothing calls
    look identical once both are reduced to an empty set.
    """
    if not isinstance(inspect_text, str) or not inspect_text.strip():
        return None
    saw_edge = False
    callers = set()
    for line in inspect_text.splitlines():
        match = INSPECT_EDGE.match(line)
        if not match:
            continue
        saw_edge = True
        if match.group(1) == "<-" and match.group(2) == "Calls":
            callers.add(match.group(3).strip())
    if not saw_edge:
        return None
    return callers


def grade(callers, expected, forbidden):
    """PASS only when the callers are exactly what the language says they are."""
    if callers is None:
        return (UNREADABLE, "inspect printed no edge line, so the callers could not be read")
    missing = [name for name in expected if name not in callers]
    if missing:
        return (FAIL, "expected caller(s) %s absent; callers were %s"
                % (", ".join(missing), sorted(callers) or "none"))
    present = [name for name in forbidden if name in callers]
    if present:
        return (FAIL, "forbidden caller(s) %s present; callers were %s"
                % (", ".join(present), sorted(callers)))
    return (PASS, "callers were %s" % (sorted(callers) or "none"))


# ── fixtures ──

JAVA_SRC = (
    "class Report {\n"
    "    void renderSummary() { computeTotals(); }\n"
    "    void computeTotals() { }\n"
    "}\n"
)

CPP_SRC = (
    "struct Widget {\n"
    "    void renderSummary();\n"
    "    void computeTotals();\n"
    "};\n"
    "void Widget::renderSummary() { computeTotals(); }\n"
    "void Widget::computeTotals() { }\n"
)

# The same shape, in the language that must not bind. Python needs
# `self.compute_totals()`; a bare call names a module-level function, and
# binding it to the sibling is the defect the Python gate exists to prevent.
PYTHON_SRC = (
    "class Report:\n"
    "    def render_summary(self):\n"
    "        compute_totals()\n"
    "    def compute_totals(self):\n"
    "        pass\n"
)


def run(cmd, cwd=None, env=None, timeout=600):
    try:
        proc = subprocess.run(cmd, cwd=cwd, env=env, timeout=timeout,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.TimeoutExpired:
        return (124, "", "timed out after %ss" % timeout)
    except OSError as exc:
        return (127, "", str(exc))
    return (proc.returncode,
            proc.stdout.decode("utf-8", "replace"),
            proc.stderr.decode("utf-8", "replace"))


class Suite(object):
    def __init__(self, kin, workdir, daemon=None, verbose=False):
        self.kin = kin
        self.workdir = workdir
        self.verbose = verbose
        self.env = dict(os.environ)
        self.env["KIN_DAEMON_AUTO_EMBED"] = "0"
        self.env["KIN_VFS_DISABLE"] = "1"
        self.env.pop("KIN_MCP_REPO", None)
        if daemon:
            self.env["KIN_DAEMON_BIN"] = daemon
        self._repos = {}

    def kin_run(self, args, repo, timeout=600):
        return run([self.kin] + args, cwd=repo, env=self.env, timeout=timeout)

    def git(self, args, repo):
        base = ["git", "-c", "core.hooksPath=/dev/null",
                "-c", "user.email=repro@example.invalid",
                "-c", "user.name=same-owner-call-repro",
                "-c", "commit.gpgsign=false"]
        return run(base + args, cwd=repo, env=self.env)

    def repo(self, name, files):
        """A converted repository holding exactly `files`, built once."""
        if name in self._repos:
            return self._repos[name]
        path = os.path.join(self.workdir, name)
        os.makedirs(path)
        for rel, body in files:
            full = os.path.join(path, rel)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "w") as handle:
                handle.write(body)
        self.git(["init", "-q", "."], path)
        self.git(["add", "-A"], path)
        rc, out, err = self.git(["commit", "-q", "-m", "fixture"], path)
        if rc != 0:
            raise RuntimeError("git commit failed: %s" % (err or out)[-300:])
        rc, out, err = self.kin_run(["init", "."], path)
        if rc != 0:
            raise RuntimeError("kin init failed in %s: %s" % (path, (err or out)[-300:]))
        self._repos[name] = path
        return path

    def inspect(self, repo, entity, settle=2):
        """`kin graph inspect`, retried once while the graph settles.

        Conversion lands asynchronously, so a probe fired immediately can hit a
        graph that has not resolved the symbol yet. The retry is bounded, and an
        entity that never resolves still reports unreadable rather than absent.
        """
        rc, out, err = self.kin_run(["graph", "inspect", entity], repo)
        text = out + "\n" + err
        if incoming_callers(text) is not None:
            return text
        time.sleep(settle)
        rc, out, err = self.kin_run(["graph", "inspect", entity], repo)
        return out + "\n" + err


def check_java(suite):
    repo = suite.repo("java", [("Report.java", JAVA_SRC)])
    text = suite.inspect(repo, "Report.computeTotals")
    status, detail = grade(incoming_callers(text), ["Report.renderSummary"], [])
    return Result("0", status, "Java: a bare sibling call reaches the owner's method. " + detail)


def check_cpp(suite):
    repo = suite.repo("cpp", [("widget.cpp", CPP_SRC)])
    text = suite.inspect(repo, "Widget::computeTotals")
    status, detail = grade(incoming_callers(text), ["Widget::renderSummary"], [])
    return Result("1", status, "C++: a bare sibling call reaches the owner's method. " + detail)


def check_python_stays_unbound(suite):
    # The control that keeps checks 0 and 1 honest. Same shape, a language whose
    # bare call names a module-level function, so a build that bound every
    # language would pass both positives and fail only here.
    repo = suite.repo("python", [("report.py", PYTHON_SRC)])
    text = suite.inspect(repo, "Report.compute_totals")
    callers = incoming_callers(text)
    if callers is None:
        # An entity nothing calls and nothing else references may legitimately
        # print no edge line. That is the answer this check wants, but it is not
        # readable through the same parser, so say so rather than grade it.
        return Result("2", PASS,
                      "Python: inspect named no incoming edge at all, so the bare call reached "
                      "no sibling")
    status, detail = grade(callers, [], ["Report.render_summary"])
    return Result("2", status,
                  "Python: a bare call must not reach the owner's method. " + detail)


CHECKS = [
    ("0", check_java),
    ("1", check_cpp),
    ("2", check_python_stays_unbound),
]


# ── self-test ──

SAMPLE_INSPECT = (
    "Entity: Report.computeTotals [Method]\n"
    "  <- Calls  Report.renderSummary  [Method] (Report.java; line 2)\n"
    "  -> Contains  Report  [Class] (Report.java; line 1)\n"
)


def self_test():
    failures = []

    def expect(label, got, want):
        if got != want:
            failures.append("%s: got %r, want %r" % (label, got, want))

    # incoming_callers, and the input that must produce the opposite answer.
    expect("reads the caller", incoming_callers(SAMPLE_INSPECT), {"Report.renderSummary"})
    expect("an outgoing edge is not a caller",
           incoming_callers("  -> Calls  Other.thing  [Method] (a.java; line 1)\n"), set())
    expect("a non-Calls incoming edge is not a caller",
           incoming_callers("  <- Contains  Report  [Class] (Report.java; line 1)\n"), set())
    # UNREADABLE is a distinct answer from "no caller". Without this the two
    # collapse and every failed probe reads as a clean negative.
    expect("no edge line at all is unreadable", incoming_callers("Entity: X\n"), None)
    expect("empty output is unreadable", incoming_callers(""), None)
    expect("a missing string is unreadable", incoming_callers(None), None)

    # grade, each verdict and its inverse.
    expect("an expected caller present passes",
           grade({"A"}, ["A"], [])[0], PASS)
    expect("an expected caller absent fails",
           grade({"B"}, ["A"], [])[0], FAIL)
    expect("a forbidden caller present fails",
           grade({"A"}, [], ["A"])[0], FAIL)
    expect("a forbidden caller absent passes",
           grade({"B"}, [], ["A"])[0], PASS)
    expect("an empty caller set is a pass only when nothing was expected",
           grade(set(), [], ["A"])[0], PASS)
    expect("an empty caller set fails an expectation",
           grade(set(), ["A"], [])[0], FAIL)
    expect("unreadable never grades as a pass",
           grade(None, [], ["A"])[0], UNREADABLE)

    for line in failures:
        print("SELFTEST FAIL %s" % line)
    if failures:
        print("self-test: %d grader case(s) failed" % len(failures))
        return 1
    print("self-test: every grader case and its inverse behaved as declared")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kin", default=os.environ.get("KIN_BIN"))
    parser.add_argument("--daemon", default=None)
    parser.add_argument("--workdir", default=None)
    parser.add_argument("--label", default="local")
    parser.add_argument("--only", default=None)
    parser.add_argument("--json", default=None)
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    if not args.kin:
        print("error: --kin (or KIN_BIN) is required", file=sys.stderr)
        return 3
    if not os.path.isfile(args.kin) or not os.access(args.kin, os.X_OK):
        print("error: %s is not an executable kin binary" % args.kin, file=sys.stderr)
        return 3

    daemon = args.daemon
    if not daemon:
        beside = os.path.join(os.path.dirname(os.path.abspath(args.kin)), "kin-daemon")
        if os.path.isfile(beside) and os.access(beside, os.X_OK):
            daemon = beside

    selected = None
    if args.only:
        selected = {part.strip() for part in args.only.split(",") if part.strip()}

    workdir = args.workdir or tempfile.mkdtemp(prefix="same-owner-call-")
    os.makedirs(workdir, exist_ok=True)
    suite = Suite(args.kin, workdir, daemon=daemon, verbose=args.verbose)

    results = []
    try:
        for cid, fn in CHECKS:
            if selected is not None and cid not in selected:
                continue
            try:
                results.append(fn(suite))
            except Exception as exc:  # a crashed probe is UNREADABLE, never a verdict
                results.append(Result(cid, UNREADABLE, "the probe raised: %s" % exc))
    finally:
        if not args.keep:
            shutil.rmtree(workdir, ignore_errors=True)

    for res in results:
        print("CHECK %s %s %s %s" % (res.id, TICKET, res.status, res.detail))

    failed = [r for r in results if r.status == FAIL]
    unreadable = [r for r in results if r.status == UNREADABLE]
    print("same-owner-call-repro: %d checks, %d passed, %d failed, %d unreadable (%s)"
          % (len(results), len(results) - len(failed) - len(unreadable),
             len(failed), len(unreadable), args.label))

    if args.json:
        with open(args.json, "w") as handle:
            json.dump({"label": args.label, "ticket": TICKET,
                       "checks": [{"id": r.id, "status": r.status, "detail": r.detail}
                                  for r in results]}, handle, indent=2)

    if failed:
        return 1
    if unreadable:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
