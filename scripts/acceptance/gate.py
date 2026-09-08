#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

"""Decide the acceptance job from the suites' own JSON reports.

The suites exit 1 on any FAIL, 2 when none fail but some are UNREADABLE, and 3
on a setup error. Gating on that number alone gives one lever with two settings:
demand a clean sweep, or demand nothing. Neither is right while a single check is
blocked on something outside the change under review.

So the gate reads the reports instead. An UNREADABLE fails unless it is named in
an allowance that carries a reason. A FAIL fails unless it is named in a stricter
allowance that carries a ticket AND the substring the failing detail must contain,
and every allowance is printed on every run so a suppressed check is never quiet.

The FAIL allowance is the newer and the narrower of the two, and it exists because
`bin/kin-parity` already tolerated one FAIL under a ticket while this gate could
not, so the two graders of the same suites disagreed on the same report. Its extra
demands are what keep it from becoming a way to stop enforcing: a check has more
than one way to go red, so an allowance keyed on the check id alone would tolerate
every one of them, including the next regression. Keyed on the failure's own words
it tolerates one, and a FAIL that does not carry them is reported with a warning
saying the allowance was considered and did not match.

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
        --allow-unreadable 'brownfield:4=reason the check is blocked' \\
        --allow-fail 'brownfield:4=FIR-1|the words the failure carries|why it is tolerated'

Exit status is 0 when the gate passes and 1 when it does not. `--self-test`
exercises every rule above against its inverse and needs no reports.
"""

from __future__ import print_function

import argparse
import collections
import contextlib
import functools
import io
import json
import os
import re
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


FailAllowance = collections.namedtuple("FailAllowance", "ticket needle why")

# A ticket id, not a sentence about one. `FIR-2464` passes, `see the ticket` does
# not, and neither does an empty field, which is the shape a forgotten ticket
# actually takes.
TICKET_ID = re.compile(r"^[A-Z][A-Z0-9]*-[0-9]+$")


def parse_fail_allowance(text):
    """One tolerated FAIL, keyed on its ticket AND on the failure's own words.

    Grammar: SUITE:CHECK=TICKET|SUBSTRING THE FAILURE MUST CARRY|WHY

    Keyed on the check id alone this would be a check that cannot fail. A check
    has more than one way to go red: brownfield:4 can fail on a fabricated callee,
    on a witness that came back truncated, or on the absent hand-off its ticket
    tracks, and only the last of those is being tolerated. So the substring is
    required, it is matched against every failing assertion rather than against
    the row's summary line, and a FAIL that does not carry it is reported with a
    warning saying the allowance was considered and did not match.
    """
    name, value = parse_pair(text, "--allow-fail")
    if ":" not in name:
        raise GateError(
            "--allow-fail must be SUITE:CHECK=TICKET|SUBSTRING|WHY, got %r" % text)
    suite, check = name.split(":", 1)
    suite = suite.strip()
    check = check.strip()
    if not suite or not check:
        raise GateError("--allow-fail names an empty suite or check: %r" % text)
    if "," in check or "*" in check:
        raise GateError(
            "--allow-fail %s:%s names more than one check; one allowance tolerates "
            "one check, so that removing it is one decision about one defect"
            % (suite, check))
    parts = value.split("|", 2)
    if len(parts) != 3:
        raise GateError(
            "--allow-fail %s:%s must be TICKET|SUBSTRING|WHY, got %r"
            % (suite, check, value))
    ticket, needle, why = (part.strip() for part in parts)
    if not TICKET_ID.match(ticket):
        raise GateError(
            "--allow-fail %s:%s carries no ticket id (%r); a tolerated FAIL that "
            "nobody is tracking is a defect nobody is fixing" % (suite, check, ticket))
    if not needle:
        raise GateError(
            "--allow-fail %s:%s carries no substring; without one it would tolerate "
            "every way this check can fail, including the next regression"
            % (suite, check))
    if not why:
        raise GateError(
            "--allow-fail %s:%s carries no reason; an allowance without one is a "
            "suppression nobody can review" % (suite, check))
    return (suite, check), FailAllowance(ticket, needle, why)


def failure_matches(row, needle):
    """Whether EVERY failing assertion in this row is the tolerated one.

    The row's `detail` is only its first failing assertion, so a check that grew
    a second, unrelated failure would still present the tolerated sentence and be
    waved through. Reading the assertions instead means a new failure alongside
    the tolerated one refuses the allowance. Rows from suites that publish no
    assertion list fall back to the summary line, which is all they offer.
    """
    asserts = row.get("asserts")
    if not isinstance(asserts, list):
        return needle in str(row.get("detail") or "")
    failing = [a for a in asserts
               if isinstance(a, dict) and a.get("status") == FAIL]
    if not failing:
        return False
    return all(needle in str(a.get("detail") or "") for a in failing)


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


def decide(reports, allowances, fail_allowances=None):
    """Return (failures, notes) for one already-loaded set of reports."""

    fail_allowances = fail_allowances or {}
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
    for (suite, check), spec in sorted(fail_allowances.items()):
        if suite not in reports:
            failures.append(
                "fail allowance %s:%s names a suite this gate did not run"
                % (suite, check))
            continue
        if check not in reports[suite]:
            failures.append(
                "fail allowance %s:%s names a check the report does not carry; an "
                "allowance pointing at nothing reads exactly like a satisfied one"
                % (suite, check))
            continue
        if reports[suite][check].get("status") == PASS:
            notes.append(
                "STALE ALLOWANCE %s:%s now passes, so its %s FAIL allowance can go (%s)"
                % (suite, check, spec.ticket, spec.why))
    for suite in sorted(reports):
        for check in sorted(reports[suite], key=lambda k: (len(k), k)):
            row = reports[suite][check]
            status = row.get("status")
            detail = str(row.get("detail") or "")[:300]
            if status == FAIL:
                spec = fail_allowances.get((suite, check))
                if spec is not None and failure_matches(row, spec.needle):
                    notes.append(
                        "ALLOWED FAIL %s:%s, tracked as %s (%s); every failing "
                        "assertion carries %r"
                        % (suite, check, spec.ticket, spec.why, spec.needle))
                    continue
                if spec is not None:
                    notes.append(
                        "UNMATCHED ALLOWANCE %s:%s carries a %s FAIL allowance, but "
                        "this failure does not carry %r in every failing assertion, "
                        "so it stands" % (suite, check, spec.ticket, spec.needle))
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


def run(report_args, allowance_args, fail_allowance_args=()):
    allowances = {}
    for text in allowance_args:
        key, reason = parse_allowance(text)
        allowances[key] = reason
    fail_allowances = {}
    for text in fail_allowance_args:
        key, spec = parse_fail_allowance(text)
        fail_allowances[key] = spec
    reports = {}
    failures = []
    for text in report_args:
        name, path = parse_pair(text, "--report")
        try:
            reports[name] = load_report(path)
        except GateError as exc:
            failures.append("%s: %s" % (name, exc))
    if reports:
        found, notes = decide(reports, allowances, fail_allowances)
        failures += found
        for note in notes:
            print(note)
            # A tolerated FAIL is the loudest thing this gate can do without
            # failing, so it reaches the run summary as an annotation rather than
            # only the log. STALE and UNMATCHED are warnings for the same reason:
            # each names an allowance that is no longer describing reality.
            if note.startswith("STALE") or note.startswith("UNMATCHED"):
                annotate("warning", note)
            elif note.startswith("ALLOWED FAIL"):
                annotate("notice", note)
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
    expect("an UNREADABLE allowance does not cover a FAIL",
           len(decide(failing, {("magic", "0"): "please"})[0]), 1)

    # The FAIL allowance and the ways it must refuse. The tolerated failure is
    # brownfield:4's real one, carried in an assertion list rather than only in
    # the summary line, because that is the shape the suites actually write.
    hand_off = ("the hand-off this.router.handle at lib/application.js:177, the "
                "last line of app.handle and the edge the question is about, is "
                "absent from the walk")
    fabricated = "counted steps include fabricated callees req.get"

    def brownfield_row(*failing_details):
        return {"brownfield": {"4": {
            "status": FAIL, "detail": failing_details[0],
            "asserts": ([{"status": PASS, "detail": "a complete witness receipt"}]
                        + [{"status": FAIL, "detail": d} for d in failing_details])}}}

    tracked = {("brownfield", "4"): FailAllowance("FIR-2464", hand_off, "tracked")}
    allowed_failures, allowed_notes = decide(brownfield_row(hand_off), {}, tracked)
    expect("the tracked FAIL is allowed", allowed_failures, [])
    expect("the tracked FAIL is announced with its ticket",
           any(n.startswith("ALLOWED FAIL brownfield:4, tracked as FIR-2464")
               for n in allowed_notes), True)
    other_failures, other_notes = decide(brownfield_row(fabricated), {}, tracked)
    expect("a different FAIL on the same check still fails", len(other_failures), 1)
    expect("a different FAIL says the allowance was considered and did not match",
           any(n.startswith("UNMATCHED ALLOWANCE brownfield:4") for n in other_notes),
           True)
    expect("a second failure beside the tracked one refuses the allowance",
           len(decide(brownfield_row(hand_off, fabricated), {}, tracked)[0]), 1)
    expect("CONTROL a row with no assertion list falls back to its summary line",
           failure_matches({"detail": hand_off}, hand_off), True)
    expect("a row whose assertion list carries no failure does not match",
           failure_matches({"detail": hand_off,
                            "asserts": [{"status": PASS, "detail": hand_off}]},
                           hand_off), False)

    recovered = {"brownfield": {"4": {"status": PASS, "detail": "the hand-off is present"}}}
    stale_fail_failures, stale_fail_notes = decide(recovered, {}, tracked)
    expect("a stale FAIL allowance does not fail", stale_fail_failures, [])
    expect("a stale FAIL allowance is announced",
           stale_fail_notes[0].startswith("STALE ALLOWANCE brownfield:4"), True)
    expect("a FAIL allowance pointing at nothing fails",
           len(decide(recovered, {},
                      {("brownfield", "9"): tracked[("brownfield", "4")]})[0]), 1)
    expect("a FAIL allowance on an unrun suite fails",
           len(decide(recovered, {},
                      {("other", "4"): tracked[("brownfield", "4")]})[0]), 1)

    for text, label in (
            ("brownfield:4=|needle|why", "a fail allowance with no ticket"),
            ("brownfield:4=see the ticket|needle|why",
             "a fail allowance whose ticket is a sentence"),
            ("brownfield:4=FIR-1||why", "a fail allowance with no substring"),
            ("brownfield:4=FIR-1|needle|", "a fail allowance with no reason"),
            ("brownfield:4=FIR-1|needle", "a fail allowance with two fields"),
            ("brownfield:4=FIR-1", "a fail allowance with one field"),
            ("brownfield=FIR-1|needle|why", "a fail allowance with no check"),
            ("brownfield:4", "a fail allowance with no value"),
            ("brownfield:4,5=FIR-1|needle|why", "a fail allowance naming two checks"),
            ("brownfield:*=FIR-1|needle|why", "a fail allowance naming a glob")):
        try:
            parse_fail_allowance(text)
            problems.append("%s was accepted: %r" % (label, text))
        except GateError:
            pass
    expect("a well formed fail allowance parses",
           parse_fail_allowance("brownfield:4=FIR-2464|the hand-off|why it stands"),
           (("brownfield", "4"),
            FailAllowance("FIR-2464", "the hand-off", "why it stands")))

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

        # The FAIL allowance at the run boundary, not only inside decide(). A
        # tolerated FAIL has to reach the run summary as an annotation, because
        # a line that exists only in a log nobody opens is how a suppression
        # goes quiet, and quiet is the whole thing this gate is built against.
        tolerated = write("brownfield.json", {"ticket": "FIR-0", "results": [
            {"id": "4", "status": FAIL, "detail": hand_off,
             "asserts": [{"status": FAIL, "detail": hand_off}]}]})
        spec = "brownfield:4=FIR-2464|%s|the callee lives outside the graph" % hand_off
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            tolerated_rc = run(["brownfield=%s" % tolerated], [], [spec])
        tolerated_output = output.getvalue()
        expect("an allowed FAIL passes the run boundary", tolerated_rc, 0)
        expect("an allowed FAIL reaches the run summary as a notice",
               "::notice::ALLOWED FAIL brownfield:4, tracked as FIR-2464"
               in tolerated_output, True)
        expect("CONTROL an allowed FAIL raises no error annotation",
               "::error::" in tolerated_output, False)

        untolerated = write("other.json", {"ticket": "FIR-0", "results": [
            {"id": "4", "status": FAIL, "detail": fabricated,
             "asserts": [{"status": FAIL, "detail": fabricated}]}]})
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            untolerated_rc = run(["brownfield=%s" % untolerated], [], [spec])
        untolerated_output = output.getvalue()
        expect("CONTROL the same allowance fails a different failure",
               untolerated_rc, 1)
        expect("CONTROL that refusal names the unmatched allowance",
               "::warning::UNMATCHED ALLOWANCE brownfield:4" in untolerated_output,
               True)

        # Through main(), not run(), because run() raises and main() is what the
        # workflow calls: a malformed allowance has to become a failing exit code
        # and an error annotation rather than a traceback the log swallows.
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            ticketless_rc = main(["--report", "brownfield=%s" % tolerated,
                                  "--allow-fail", "brownfield:4=|%s|no ticket" % hand_off])
        ticketless_output = output.getvalue()
        expect("a fail allowance with no ticket is refused at the run boundary",
               ticketless_rc, 1)
        expect("that refusal names the missing ticket",
               "carries no ticket id" in ticketless_output, True)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            ticketed_rc = main(["--report", "brownfield=%s" % tolerated,
                                "--allow-fail", spec])
        expect("CONTROL the same invocation with a ticket passes", ticketed_rc, 0)
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
    parser.add_argument("--allow-fail", action="append", default=[],
                        metavar="SUITE:CHECK=TICKET|SUBSTRING|WHY",
                        help="tolerate one FAIL whose every failing assertion "
                             "carries SUBSTRING, repeatable; the ticket, the "
                             "substring and the reason are all required and all "
                             "are printed on every run")
    parser.add_argument("--self-test", action="store_true",
                        help="exercise every rule against its inverse and exit")
    opts = parser.parse_args(argv)

    if opts.self_test:
        return self_test()
    if not opts.report:
        sys.stderr.write("no reports: pass at least one --report NAME=PATH\n")
        return 1
    try:
        return run(opts.report, opts.allow_unreadable, opts.allow_fail)
    except GateError as exc:
        annotate("error", "acceptance gate could not be decided: %s" % exc)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
