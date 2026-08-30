#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

"""Decide the acceptance job from the suites' own JSON reports.

The suites exit 1 on any FAIL, 2 when none fail but some are UNREADABLE, and 3
on a setup error. Gating on that number alone gives one lever with two settings:
demand a clean sweep, or demand nothing. Neither is right while a single check is
blocked on something outside the change under review.

So the gate reads the reports instead. A FAIL is never tolerated and has no
allowance. An UNREADABLE fails too, unless it is named in an allowance that
carries a reason, and every allowance is printed on every run so a suppressed
check is never quiet.

Three rules keep the allowance list from becoming a way to stop enforcing:

  * An allowance naming a check the report does not carry is an error. A pointer
    at nothing looks exactly like a satisfied allowance, so a renamed or deleted
    check must break the gate rather than silently widen it.
  * An allowance on a check that now passes is reported loudly as stale. It does
    not fail the run, because a check that recovers should not turn the fleet red
    on the next unrelated pull request, but it is on the summary until removed.
  * A missing or unreadable report is a failure. A suite that wrote nothing did
    not pass, and an absent file and a clean file are different facts.

Usage:
    python3 scripts/acceptance/gate.py \\
        --report magic=acceptance/magic.json \\
        --report brownfield=acceptance/brownfield.json \\
        --allow-unreadable 'brownfield:4=reason the check is blocked'

Exit status is 0 when the gate passes and 1 when it does not. `--self-test`
exercises every rule above against its inverse and needs no reports.
"""

from __future__ import print_function

import argparse
import contextlib
import functools
import io
import json
import os
import shutil
import sys
import tempfile

PASS = "PASS"
FAIL = "FAIL"
UNREADABLE = "UNREADABLE"

print = functools.partial(print, flush=True)


class GateError(Exception):
    """A gate that could not be decided. Always a failure, never a pass."""


def parse_pair(text, what):
    if "=" not in text:
        raise GateError("%s must be NAME=VALUE, got %r" % (what, text))
    name, value = text.split("=", 1)
    name = name.strip()
    if not name:
        raise GateError("%s carries an empty name: %r" % (what, text))
    return name, value


def parse_allowance(text):
    name, reason = parse_pair(text, "--allow-unreadable")
    if ":" not in name:
        raise GateError(
            "--allow-unreadable must be SUITE:CHECK=REASON, got %r" % text)
    suite, check = name.split(":", 1)
    suite = suite.strip()
    check = check.strip()
    reason = reason.strip()
    if not suite or not check:
        raise GateError("--allow-unreadable names an empty suite or check: %r" % text)
    if not reason:
        raise GateError(
            "--allow-unreadable %s:%s carries no reason; an allowance without one "
            "is a suppression nobody can review" % (suite, check))
    return (suite, check), reason


def load_report(path):
    """The report's results, or a GateError naming why it could not be read."""

    if not os.path.exists(path):
        raise GateError("no report at %s; a suite that wrote nothing did not pass"
                        % path)
    try:
        with open(path) as handle:
            payload = json.load(handle)
    except ValueError as exc:
        raise GateError("report %s is not JSON: %s" % (path, exc))
    results = payload.get("results")
    if not isinstance(results, list):
        # Name the remedy in the failing log rather than in a sibling file. Four
        # suites have now shipped their rows under `checks`: same_owner_call
        # first, working_copy_freshness second (kin#1205's squash printed four
        # CHECK lines over a report this loader could not read), init_budget
        # third under FIR-2929, and vcs_read_surfaces fourth under FIR-2985. Each
        # author had to rediscover the key from this message, which said only
        # what was missing and never what to do about it.
        if isinstance(payload.get("checks"), list):
            raise GateError(
                "report %s carries its rows under `checks`; this gate reads "
                "`results`. Rename the top-level key in that suite's "
                "`report_payload`, then add the self-test row that loads the "
                "written report back through this loader, which is what stops "
                "it drifting again; "
                "`scripts/acceptance/working_copy_freshness_repro.py`'s "
                "`report_payload` docstring prescribes both and records the "
                "earlier occurrences" % path)
        raise GateError("report %s carries no results list" % path)
    if not results:
        raise GateError("report %s carries an empty results list; a suite that "
                        "graded nothing did not pass" % path)
    rows = {}
    for row in results:
        if not isinstance(row, dict) or "id" not in row:
            raise GateError("report %s carries a result with no id" % path)
        rows[str(row["id"])] = row
    return rows


def decide(reports, allowances):
    """Return (failures, notes) for one already-loaded set of reports."""

    failures = []
    notes = []
    for (suite, check), reason in sorted(allowances.items()):
        if suite not in reports:
            failures.append(
                "allowance %s:%s names a suite this gate did not run" % (suite, check))
            continue
        if check not in reports[suite]:
            failures.append(
                "allowance %s:%s names a check the report does not carry; an "
                "allowance pointing at nothing reads exactly like a satisfied one"
                % (suite, check))
            continue
        status = reports[suite][check].get("status")
        if status == PASS:
            notes.append(
                "STALE ALLOWANCE %s:%s now passes, so its allowance can go (%s)"
                % (suite, check, reason))
        elif status == UNREADABLE:
            notes.append("ALLOWED %s:%s is %s (%s)" % (suite, check, status, reason))
    for suite in sorted(reports):
        for check in sorted(reports[suite], key=lambda k: (len(k), k)):
            row = reports[suite][check]
            status = row.get("status")
            detail = str(row.get("detail") or "")[:300]
            if status == FAIL:
                failures.append("%s:%s FAIL %s" % (suite, check, detail))
            elif status == UNREADABLE:
                if (suite, check) in allowances:
                    continue
                failures.append("%s:%s UNREADABLE %s" % (suite, check, detail))
            elif status != PASS:
                failures.append(
                    "%s:%s carries status %r, which this gate does not recognize"
                    % (suite, check, status))
    return failures, notes


def annotate(kind, message):
    print("::%s::%s" % (kind, message))


def run(report_args, allowance_args):
    allowances = {}
    for text in allowance_args:
        key, reason = parse_allowance(text)
        allowances[key] = reason
    reports = {}
    failures = []
    for text in report_args:
        name, path = parse_pair(text, "--report")
        try:
            reports[name] = load_report(path)
        except GateError as exc:
            failures.append("%s: %s" % (name, exc))
    if reports:
        found, notes = decide(reports, allowances)
        failures += found
        for note in notes:
            print(note)
            if note.startswith("STALE"):
                annotate("warning", note)
    for name in sorted(reports):
        counts = {}
        for row in reports[name].values():
            counts[row.get("status")] = counts.get(row.get("status"), 0) + 1
        print("%s: %s" % (name, ", ".join("%s %s" % (counts[k], k)
                                          for k in sorted(counts))))
    if failures:
        for line in failures:
            annotate("error", line)
        print("acceptance gate FAILED on %d finding(s)" % len(failures))
        return 1
    print("acceptance gate passed")
    return 0


def self_test():
    """Exercise every rule against its inverse. No reports, no binary."""

    problems = []

    def expect(label, got, want):
        if got != want:
            problems.append("%s: got %r, wanted %r" % (label, got, want))

    clean = {"magic": {"0": {"status": PASS, "detail": "fine"}}}
    expect("a clean report passes", decide(clean, {})[0], [])

    failing = {"magic": {"0": {"status": FAIL, "detail": "broken"}}}
    expect("a FAIL fails", len(decide(failing, {})[0]), 1)
    expect("a FAIL has no allowance",
           len(decide(failing, {("magic", "0"): "please"})[0]), 1)

    unread = {"magic": {"0": {"status": UNREADABLE, "detail": "no answer"}}}
    expect("an UNREADABLE fails by default", len(decide(unread, {})[0]), 1)
    expect("an allowed UNREADABLE passes",
           decide(unread, {("magic", "0"): "blocked on X"})[0], [])
    expect("an allowed UNREADABLE is announced",
           decide(unread, {("magic", "0"): "blocked on X"})[1][0].startswith("ALLOWED"),
           True)

    expect("an allowance pointing at nothing fails",
           len(decide(clean, {("magic", "9"): "gone"})[0]), 1)
    expect("an allowance on an unrun suite fails",
           len(decide(clean, {("other", "0"): "gone"})[0]), 1)
    stale_failures, stale_notes = decide(clean, {("magic", "0"): "recovered"})
    expect("a stale allowance does not fail", stale_failures, [])
    expect("a stale allowance is announced",
           stale_notes[0].startswith("STALE ALLOWANCE"), True)

    weird = {"magic": {"0": {"status": "SKIPPED", "detail": ""}}}
    expect("an unrecognized status fails", len(decide(weird, {})[0]), 1)

    for text, label in (
            ("magic:4", "an allowance with no reason"),
            ("magic=only a reason", "an allowance with no check"),
            ("magic:4=", "an allowance with an empty reason"),
            (":4=reason", "an allowance with an empty suite")):
        try:
            parse_allowance(text)
            problems.append("%s was accepted: %r" % (label, text))
        except GateError:
            pass
    expect("a well formed allowance parses",
           parse_allowance("brownfield:4=blocked on FIR-1"),
           (("brownfield", "4"), "blocked on FIR-1"))

    missing = "/nonexistent/acceptance-gate-self-test.json"
    try:
        load_report(missing)
        problems.append("a missing report was accepted")
    except GateError:
        pass

    # Exercise the actual run boundary, not only decide(). A missing report must
    # return a process-failing status and emit a GitHub error annotation. This is
    # what makes an unneutralized workflow invocation authoritative.
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        missing_run_rc = run(
            ["missing=/nonexistent/acceptance-gate-self-test-run.json"], []
        )
    missing_run_output = output.getvalue()
    expect("a failing run returns 1", missing_run_rc, 1)
    expect(
        "a failing run emits a GitHub error annotation",
        "::error::missing: no report at " in missing_run_output,
        True,
    )
    expect(
        "a failing run names the failed verdict",
        "acceptance gate FAILED on 1 finding(s)" in missing_run_output,
        True,
    )

    # The `checks`-key branch and the no-key branch both refuse, and a field-level
    # assertion cannot tell them apart, so each arm is asserted on its exact
    # MESSAGE. A mutation that merely redirects between the two branches leaves
    # both refusing and would survive a check that only asked whether it raised.
    scratch = tempfile.mkdtemp(prefix="acceptance-gate-self-test-")
    try:
        def write(name, payload):
            target = os.path.join(scratch, name)
            with open(target, "w") as handle:
                json.dump(payload, handle)
            return target

        rows = [{"id": "one", "status": PASS, "detail": "self-test"}]

        checks_keyed = write("checks.json", {"ticket": "FIR-0", "checks": rows})
        try:
            load_report(checks_keyed)
            problems.append("a `checks`-keyed report was accepted")
        except GateError as exc:
            expect("a `checks`-keyed report names the remedy",
                   "Rename the top-level key" in str(exc), True)
            expect("a `checks`-keyed report names the prescribing docstring",
                   "working_copy_freshness_repro.py" in str(exc), True)

        neither = write("neither.json", {"ticket": "FIR-0", "rows": rows})
        try:
            load_report(neither)
            problems.append("a report with neither key was accepted")
        except GateError as exc:
            expect("a report with neither key keeps the plain message",
                   str(exc).endswith("carries no results list"), True)
            expect("CONTROL the plain message does NOT name the remedy",
                   "Rename the top-level key" in str(exc), False)

        good = write("good.json", {"ticket": "FIR-0", "results": rows})
        expect("CONTROL a `results`-keyed report is still accepted",
               sorted(load_report(good)), ["one"])
    finally:
        shutil.rmtree(scratch, ignore_errors=True)

    for line in problems:
        print("SELF-TEST FAIL %s" % line)
    print("acceptance gate: self-test %s"
          % ("FAILED (%d)" % len(problems) if problems else "passed"))
    return 1 if problems else 0


def main(argv):
    parser = argparse.ArgumentParser(
        add_help=True, description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--report", action="append", default=[],
                        metavar="NAME=PATH",
                        help="a suite's JSON report, repeatable")
    parser.add_argument("--allow-unreadable", action="append", default=[],
                        metavar="SUITE:CHECK=REASON",
                        help="tolerate one UNREADABLE check, repeatable; the "
                             "reason is required and is printed on every run")
    parser.add_argument("--self-test", action="store_true",
                        help="exercise every rule against its inverse and exit")
    opts = parser.parse_args(argv)

    if opts.self_test:
        return self_test()
    if not opts.report:
        sys.stderr.write("no reports: pass at least one --report NAME=PATH\n")
        return 1
    try:
        return run(opts.report, opts.allow_unreadable)
    except GateError as exc:
        annotate("error", "acceptance gate could not be decided: %s" % exc)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
