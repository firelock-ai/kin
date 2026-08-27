#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
"""Refuse a flake quarantine that has become a graveyard.

`.config/nextest.toml` buys a quarantined test two retries so a flake costs
seconds instead of a merge-queue ejection. The cost of that is obvious and it is
the reason this guard exists: a quarantine with no clock is a place to park a
real bug where nobody has to look at it again. Every rule below is a way of
saying the same thing, that a row has to keep earning its place.

## What it refuses

  no-ticket       an override with no `ticket=FIR-NNNN` in its quarantine
                  comment. A row nobody has to close is a row nobody closes.
  no-date         no `since=`, or a `since` that is not a date. The clock is
                  the point, so a row without one is not a quarantine row.
  expired         `since` older than QUARANTINE_MAX_DAYS. Fourteen days is long
                  enough to fix a flake and short enough that forgetting shows.
  too-many        more than QUARANTINE_MAX_ROWS rows. A cap turns "one more
                  test is misbehaving" into a decision instead of a habit.
  stale-row       a row naming a test that is no longer there, or a row whose
                  comment and filter disagree about which test it is.
  loose-filter    a filter with no `binary_id(=...)`. A bare `test(=name)`
                  matches that name in EVERY binary, so a row meant for one
                  test can silently buy retries for a namesake elsewhere.
  no-retries      an override with no `retries`, or `retries = 0`. Measured:
                  with retries at 0 a failing test is a plain FAIL, so such a
                  row is quarantine bookkeeping over a test nothing retries.

And one thing it only warns about, because it is good news:

  promotion       `last-flake` older than QUARANTINE_PROMOTION_DAYS. The test
                  has not needed a retry in a week and is a candidate to leave.

## The division of labour with nextest, measured rather than assumed

cargo-nextest 0.9.140 was run against each shape before this guard was written:

  binary_id(=...) matching no binary  -> config parse ERROR, exit 96
  test(=...) matching no test         -> accepted silently, exit 0
  an unknown key anywhere in the file -> a warning, exit 0

So nextest already owns the binary half of "this row still applies to
something", loudly, on every run. The test-name half is unowned, which is the
half this guard covers, and it covers it by reading the source file the row
names rather than by grepping the config, because a config the tool never
matched is a lie about coverage a text search cannot see.

The unknown-key result is why the bookkeeping is a comment. Extra fields in the
override table would be dropped with a warning nobody reads, and the row would
still look complete.

## What `cargo nextest show-config` does not do

Its help says it "shows configuration information about nextest, including
overrides applied to individual tests". On 0.9.140 it has exactly two
subcommands, `version` and `test-groups`, and `show-config version` accepts a
config carrying a malformed filter expression and exits 0. It is not a
validator, and there is no subcommand that dumps resolved per-test overrides.
Reading the help and stopping there would have produced a check that cannot
fail. Measured, and recorded here so the next reader does not pay for it twice.

## The controls, and why these ones

`run_controls()` runs before a single repository file is read, against carried
fixtures rather than against the tree, because a control drawn from the file
under test only proves self-consistency.

Every refusal has its own mutation and each is asserted to fire BY NAME. A
mutation that turns the guard red for the wrong reason is a guard with an arm
nothing reaches, which is how two assertions come to hide each other's absence.
The clean fixture is the negative control and must stay silent. The absent
needle is assembled from parts so this file cannot be what satisfies it.

## Usage

  python3 scripts/check-quarantine.py [root]
  python3 scripts/check-quarantine.py --report-junit <path> [root]

The second mode is the reporting verdict. `.config/nextest.toml` grades a
quarantined flake as passing so it blocks nothing, and writes a JUnit file that
records the retry either way. This mode reads that file and reports what the
same execution would have been graded under `--flaky-result fail`, so the
retries stay visible instead of going quiet. A missing or empty JUnit file is
UNREADABLE and refuses; it is not zero flakes.
"""

from __future__ import annotations

import re
import sys
import tomllib
import xml.etree.ElementTree as ElementTree
from datetime import date, timedelta
from pathlib import Path

CONFIG = Path(".config") / "nextest.toml"

QUARANTINE_MAX_DAYS = 14
QUARANTINE_MAX_ROWS = 5
QUARANTINE_PROMOTION_DAYS = 7

# The bookkeeping comment that must sit above every override. Keys are matched
# individually rather than as one line pattern, so a row missing exactly one of
# them is refused by the arm that owns that key instead of by a shapeless
# "malformed comment".
#
# The colon is load-bearing and was bought by this guard's first run against the
# real file. With the marker written as `# quarantine ` a line of ordinary prose
# reading "# quarantine row is not a licence to weaken an assertion" satisfied
# it, the walk-back stopped there, and a correctly filled row was reported as
# having no ticket. A marker also has to fail to match the prose around it, so
# the walk-back below keeps going unless the line it stops on carries keys.
COMMENT_MARKER = "# quarantine:"
KEY = re.compile(r"\b(ticket|since|last-flake|source)=(\S+)")
TICKET = re.compile(r"^FIR-[0-9]+$")
ISO_DATE = re.compile(r"^([0-9]{4})-([0-9]{2})-([0-9]{2})$")

BINARY_ID = re.compile(r"binary_id\(=([^)]+)\)")
TEST_NAME = re.compile(r"test\(=([^)]+)\)")


class Row:
    """One override plus the comment block immediately above it."""

    def __init__(self, index, line, filter_expr, retries, meta):
        self.index = index
        self.line = line
        self.filter_expr = filter_expr
        self.retries = retries
        self.meta = meta

    def label(self):
        return f"row {self.index} (line {self.line})"


def parse_rows(text):
    """Pair each `[[profile.default.overrides]]` with the comment above it.

    Textual on purpose. tomllib discards comments, and the comment is where the
    bookkeeping lives, so a TOML-only read would report every row as having no
    ticket. tomllib still runs, in `load_config`, to prove the file is valid
    TOML and to read the values; this pass only supplies what tomllib throws
    away.
    """

    rows = []
    lines = text.splitlines()
    index = 0
    for number, line in enumerate(lines, start=1):
        if line.strip() != "[[profile.default.overrides]]":
            continue
        meta = {}
        # Walk back over the contiguous comment block above the table header.
        for above in range(number - 2, -1, -1):
            candidate = lines[above]
            if not candidate.startswith("#"):
                break
            if candidate.startswith(COMMENT_MARKER):
                found = dict(KEY.findall(candidate))
                if found:
                    meta = found
                    break
        filter_expr = None
        retries = None
        for below in range(number, len(lines)):
            body = lines[below]
            if body.startswith("[") or body.strip() == "[[profile.default.overrides]]":
                break
            stripped = body.strip()
            if stripped.startswith("filter"):
                filter_expr = stripped.split("=", 1)[1].strip().strip("'\"")
            elif stripped.startswith("retries"):
                retries = stripped.split("=", 1)[1].strip()
        rows.append(Row(index, number, filter_expr, retries, meta))
        index += 1
    return rows


def load_config(path):
    """Prove the file is TOML before anything reads meaning out of it."""

    raw = path.read_bytes()
    try:
        tomllib.loads(raw.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as error:
        raise AssertionError(f"{path} is not readable as TOML: {error}")
    return raw.decode("utf-8")


def parse_date(value):
    match = ISO_DATE.match(value or "")
    if not match:
        return None
    try:
        return date(int(match.group(1)), int(match.group(2)), int(match.group(3)))
    except ValueError:
        return None


def check_rows(rows, root, today):
    """Return (findings, warnings). A finding is a refusal; a warning is news."""

    findings = []
    warnings = []

    if len(rows) > QUARANTINE_MAX_ROWS:
        findings.append(
            f"too-many: {len(rows)} quarantine rows, the cap is "
            f"{QUARANTINE_MAX_ROWS}. Fix one before adding another, or say on "
            "the record why the cap should move"
        )

    for row in rows:
        meta = row.meta
        where = row.label()

        ticket = meta.get("ticket")
        if not ticket or not TICKET.match(ticket):
            findings.append(
                f"no-ticket: {where} carries no `ticket=FIR-NNNN`. A row nobody "
                "has to close is a row nobody closes"
            )

        since = parse_date(meta.get("since"))
        if since is None:
            findings.append(
                f"no-date: {where} carries no readable `since=YYYY-MM-DD`. The "
                "clock is what separates a quarantine from a hiding place"
            )
        else:
            age = (today - since).days
            if age > QUARANTINE_MAX_DAYS:
                findings.append(
                    f"expired: {where} has been quarantined {age} days, the "
                    f"limit is {QUARANTINE_MAX_DAYS}. Fix the test and delete "
                    "the row, naming the run where it passed without retries"
                )

        last_flake = parse_date(meta.get("last-flake"))
        if last_flake is None:
            findings.append(
                f"no-date: {where} carries no readable `last-flake=YYYY-MM-DD`. "
                "Without it nothing can tell a live flake from a fixed one"
            )
        elif (today - last_flake).days >= QUARANTINE_PROMOTION_DAYS:
            warnings.append(
                f"promotion: {where} has not needed a retry in "
                f"{(today - last_flake).days} days. Delete the row and let the "
                "test stand on its own, or record a newer flake"
            )

        if row.retries is None or row.retries.strip() in ("0", ""):
            findings.append(
                f"no-retries: {where} sets no `retries` above zero, so nothing "
                "retries this test and the row buys it nothing. Measured: at "
                "retries 0 a failing test is a plain FAIL, never flaky"
            )

        findings.extend(check_filter_join(row, root, where))

    return findings, warnings


def check_filter_join(row, root, where):
    """Join the filter, the comment's source path, and the file on disk.

    Three facts that must agree. Asserting any one of them alone is the shape
    where two checks each hold and jointly guarantee nothing: the filter can
    name a test the file no longer defines, and the comment can name a file the
    filter is not about.
    """

    findings = []
    expr = row.filter_expr or ""

    binary = BINARY_ID.search(expr)
    if not binary:
        findings.append(
            f"loose-filter: {where} has no `binary_id(=...)`, so `test(=...)` "
            "matches that name in every binary in the workspace. Scope it"
        )

    test = TEST_NAME.search(expr)
    if not test:
        findings.append(
            f"stale-row: {where} has no `test(=...)`, so it names no test at all"
        )
        return findings

    source = row.meta.get("source")
    if not source:
        findings.append(
            f"stale-row: {where} carries no `source=<path>`, so nothing can "
            "check that the test it names still exists"
        )
        return findings

    path = root / source
    if not path.is_file():
        findings.append(
            f"stale-row: {where} names source {source}, which is not a file. "
            "The test moved or went; delete the row or repoint it"
        )
        return findings

    function = test.group(1).rsplit("::", 1)[-1]
    body = path.read_text(encoding="utf-8", errors="replace")
    if not re.search(rf"\bfn\s+{re.escape(function)}\s*\(", body):
        findings.append(
            f"stale-row: {where} names test {function}, which {source} no "
            "longer defines. A row that applies to nothing is a row claiming "
            "coverage it does not have"
        )

    if binary:
        target = binary.group(1).rsplit("::", 1)[-1]
        if path.stem != target:
            findings.append(
                f"stale-row: {where} filters binary target {target} while its "
                f"source is {source}. The comment and the filter disagree "
                "about which test this row is for"
            )

    return findings


# ─── The reporting verdict ──────────────────────────────────────────────────


def report_junit(junit_path, quarantined):
    """Grade one execution the other way, out of its own JUnit record.

    `.config/nextest.toml` grades a quarantined flake as passing. That is what
    keeps it off the critical path, and it is also how quarantine goes quiet, so
    the same run is read here for what `--flaky-result fail` would have said.
    """

    if not junit_path.is_file():
        raise AssertionError(
            f"UNREADABLE: no JUnit file at {junit_path}. That is a fact about "
            "this read, not about the run: absent is not zero flakes"
        )
    raw = junit_path.read_text(encoding="utf-8", errors="replace")
    # nextest writes this file on the same runner that just ran the tests, so it
    # is not foreign input. Refusing a DOCTYPE anyway costs one line and removes
    # the entity-expansion class outright, which is cheaper than taking a
    # third-party parser as a dependency for one guard.
    if "<!DOCTYPE" in raw or "<!ENTITY" in raw:
        raise AssertionError(
            f"UNREADABLE: {junit_path} declares a DTD. nextest writes none, so "
            "this file did not come from the run it claims to describe"
        )
    try:
        tree = ElementTree.fromstring(raw)
    except ElementTree.ParseError as error:
        raise AssertionError(f"UNREADABLE: {junit_path} did not parse: {error}")

    cases = tree.iter("testcase")
    total = 0
    flaky = []
    for case in cases:
        total += 1
        retried = list(case.iter("flakyFailure")) + list(case.iter("flakyError"))
        if retried:
            name = f"{case.get('classname', '?')} {case.get('name', '?')}"
            flaky.append((name, len(retried)))

    if total == 0:
        raise AssertionError(
            f"UNREADABLE: {junit_path} records no test case at all, so it is "
            "evidence about nothing. A run that graded zero tests is a finding"
        )

    if not flaky:
        print(f"{total} test(s) recorded, none needed a retry")
        return 0

    unquarantined = []
    for name, tries in flaky:
        print(f"::notice title=Quarantined flake::{name} needed {tries} retry(ies)")
        print(f"flaky under --flaky-result fail: {name}, {tries} retry(ies)")
        if not any(test in name for test in quarantined):
            unquarantined.append(name)

    if unquarantined:
        print(
            "these tests were retried and no quarantine row names them: "
            + ", ".join(unquarantined)
        )
        print(
            "A retry nobody declared is a flake nobody ticketed. Add the row "
            "with its evidence, or find out why something is retrying it."
        )
        return 1

    print(
        f"{len(flaky)} quarantined test(s) needed a retry. The run passed under "
        "the blocking verdict and this is the reporting one; update `last-flake` "
        "on the rows above"
    )
    return 0


# ─── Controls ───────────────────────────────────────────────────────────────

CLEAN_FIXTURE = """
[profile.default]
flaky-result = "pass"

# quarantine: ticket=FIR-1 since={since} last-flake={flake} source={source}
[[profile.default.overrides]]
filter = 'binary_id(=pkg::target) & test(=a_test_that_is_defined)'
retries = 2
"""

EXTRA_ROW = """
# quarantine: ticket=FIR-2 since={since} last-flake={flake} source=target.rs
[[profile.default.overrides]]
filter = 'binary_id(=pkg::target) & test(=a_test_that_is_defined)'
retries = 2
"""

# Assembled rather than written out, so this file cannot be the thing that
# satisfies a search for it. The guard's own source sits in the tree it reads.
ABSENT_FUNCTION = "a_function_" + "no_fixture_defines"

FIXTURE_SOURCE = """
#[test]
fn a_test_that_is_defined() { assert!(true); }
"""


def run_controls():
    """Every arm, one mutation each, asserted by NAME.

    Asserting only that the guard went red would let one arm cover another's
    absence. The clean fixture is the negative control: if it ever produces a
    finding, every mutation below is red for a reason that has nothing to do
    with what it mutated.
    """

    import tempfile

    today = date(2026, 8, 27)
    fresh = (today - timedelta(days=1)).isoformat()

    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        (tmp / "target.rs").write_text(FIXTURE_SOURCE, encoding="utf-8")

        def grade(text):
            findings, warnings = check_rows(parse_rows(text), tmp, today)
            return findings, warnings

        clean = CLEAN_FIXTURE.format(since=fresh, flake=fresh, source="target.rs")
        findings, warnings = grade(clean)
        if findings or warnings:
            raise AssertionError(
                "control failed: the clean fixture produced "
                f"{findings + warnings}, so every mutation below would be red "
                "for the wrong reason"
            )

        mutations = {
            "no-ticket": clean.replace("ticket=FIR-1 ", ""),
            "no-date": clean.replace(f"since={fresh} ", ""),
            "expired": clean.replace(
                f"since={fresh}",
                "since=" + (today - timedelta(days=QUARANTINE_MAX_DAYS + 1)).isoformat(),
            ),
            "too-many": clean + EXTRA_ROW.format(since=fresh, flake=fresh)
            * QUARANTINE_MAX_ROWS,
            "stale-row": clean.replace(
                "test(=a_test_that_is_defined)", f"test(={ABSENT_FUNCTION})"
            ),
            "loose-filter": clean.replace("binary_id(=pkg::target) & ", ""),
            "no-retries": clean.replace("retries = 2", "retries = 0"),
        }

        for arm, text in mutations.items():
            findings, _ = grade(text)
            if not findings:
                raise AssertionError(
                    f"control failed: the {arm} mutation produced no finding, "
                    "so that refusal cannot fire"
                )
            if not any(finding.startswith(arm + ":") for finding in findings):
                raise AssertionError(
                    f"control failed: the {arm} mutation was caught by "
                    f"{[f.split(':', 1)[0] for f in findings]} rather than by "
                    f"{arm}. A mutation caught by the wrong arm proves the "
                    "wrong arm works and says nothing about this one"
                )

        # The promotion arm is a warning, not a refusal, so it needs its own
        # assertion in both directions: it must fire, and it must not refuse.
        aged = clean.replace(
            f"last-flake={fresh}",
            "last-flake="
            + (today - timedelta(days=QUARANTINE_PROMOTION_DAYS)).isoformat(),
        )
        findings, warnings = grade(aged)
        if findings:
            raise AssertionError(
                f"control failed: an old last-flake refused ({findings}); it is "
                "good news and must warn rather than block a landing"
            )
        if not any(warning.startswith("promotion:") for warning in warnings):
            raise AssertionError(
                "control failed: an old last-flake produced no promotion warning"
            )

        # The stale-row arm must also catch a source path that no longer exists,
        # which is a different producer of the same finding.
        missing = clean.replace("source=target.rs", "source=gone.rs")
        findings, _ = grade(missing)
        if not any(finding.startswith("stale-row:") for finding in findings):
            raise AssertionError(
                "control failed: a row naming a missing source file was not "
                "caught as stale-row"
            )


def run_junit_controls():
    """The reporting verdict, both directions, on carried XML."""

    import contextlib
    import io
    import tempfile

    quiet = """<testsuites><testsuite name="s">
      <testcase name="a" classname="pkg::t"/>
    </testsuite></testsuites>"""
    noisy = """<testsuites><testsuite name="s">
      <testcase name="a" classname="pkg::t"><flakyFailure/></testcase>
    </testsuite></testsuites>"""
    empty = """<testsuites></testsuites>"""

    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        for name, body in (("quiet", quiet), ("noisy", noisy), ("empty", empty)):
            (tmp / f"{name}.xml").write_text(body, encoding="utf-8")

        def graded(path, quarantined):
            with contextlib.redirect_stdout(io.StringIO()):
                return report_junit(path, quarantined)

        if graded(tmp / "quiet.xml", ["a"]) != 0:
            raise AssertionError("control failed: a clean JUnit file refused")
        if graded(tmp / "noisy.xml", ["a"]) != 0:
            raise AssertionError(
                "control failed: a declared quarantined flake refused; it is "
                "reported, not blocked"
            )
        if graded(tmp / "noisy.xml", ["something_else"]) != 1:
            raise AssertionError(
                "control failed: a flake no quarantine row names was accepted"
            )
        for name in ("empty", "absent"):
            try:
                graded(tmp / f"{name}.xml", [])
            except AssertionError:
                continue
            raise AssertionError(
                f"control failed: an {name} JUnit file read as zero flakes "
                "rather than as UNREADABLE"
            )


def main(argv):
    argv = list(argv[1:])
    junit = None
    if argv and argv[0] == "--report-junit":
        if len(argv) < 2:
            raise AssertionError("--report-junit needs a path")
        junit = Path(argv[1])
        argv = argv[2:]
    root = Path(argv[0]) if argv else Path.cwd()

    run_controls()
    run_junit_controls()

    config = root / CONFIG
    if not config.is_file():
        if junit is not None:
            raise AssertionError(
                f"no {CONFIG} under {root}, so nothing declares which retries "
                "are expected; this read cannot grade the run"
            )
        print(f"no {CONFIG}: nothing is quarantined, which is the goal state")
        return 0

    text = load_config(config)
    rows = parse_rows(text)

    if junit is not None:
        quarantined = []
        for row in rows:
            named = TEST_NAME.search(row.filter_expr or "")
            if named:
                quarantined.append(named.group(1).rsplit("::", 1)[-1])
        return report_junit(junit, quarantined)

    findings, warnings = check_rows(rows, root, date.today())

    for warning in warnings:
        print(f"::warning title=Quarantine promotion candidate::{warning}")
        print(warning)

    if findings:
        for finding in findings:
            print(finding)
        print(
            f"\n{len(findings)} quarantine finding(s). A quarantine row is a "
            "promise to fix a test, with a clock on it. Fix the test and delete "
            "the row, or correct the row."
        )
        return 1

    print(
        f"{len(rows)} quarantine row(s), every one ticketed, dated, inside "
        f"{QUARANTINE_MAX_DAYS} days, and naming a test that still exists"
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except AssertionError as error:
        sys.exit(f"check-quarantine: {error}")
