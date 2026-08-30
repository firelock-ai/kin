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
import re
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
# `kin status`'s basis clause, the FIR-2820 shape. It lives in the TEXT surface
# only: `kin status --json` carries no admission field and neither does
# `kin support --json`, both measured on 2026-08-30. So the invariant check below
# reads text for the basis and JSON for the counts, deliberately.
ADMITTED_BASIS = re.compile(r"as admitted \d+[smhd]* ago")
UNMEASURED_BASIS = "not measured against the working copy"

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
    # The surface that actually carries it. `kin support --json` nests the block
    # under `health`, measured against a live store on 2026-08-30.
    health = report.get("health")
    if isinstance(health, dict):
        nested = health.get("repository_artifact_coverage")
        if isinstance(nested, dict) and IN_SYNC in nested:
            return nested
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


def basis_clause(text):
    """The basis clause out of a `kin status` tree line, for a failure detail.

    Quoted rather than paraphrased so a failure shows what the product said.
    """
    for line in text.splitlines():
        if line.startswith("Tree:") and ("admitted" in line or UNMEASURED_BASIS in line):
            return line.strip()
    return tail(text, 160)


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
        # `kin_core` is load-bearing and was missing, which is why check 2 failed.
        # The funnel line this suite counts is emitted by
        # `kin-core/src/repository_authority.rs:367`, and a filter that does not
        # name kin_core silently drops it. Measured on 2026-08-30 with everything
        # else held fixed: 0 funnel lines with the old filter, 8 with kin_core
        # added, 8 with RUST_LOG unset entirely.
        #
        # The failure was legible only as "this build carries no funnel
        # instrument", which is a claim about the BINARY made by a filter in the
        # harness. A log filter that omits the module under test cannot be told
        # apart from the instrument being absent.
        self.env["RUST_LOG"] = "kin_cli=info,kin_daemon=info,kin_db=info,kin_core=info"
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

    def daemon_log_path(self):
        """Where the daemon writes for THIS store, resolved not assumed."""
        return os.path.join(self.repo, ".kin", "daemon.log")

    def daemon_log(self):
        """The daemon log, or a (None, path) pair naming what was tried.

        Returns the text, or ``None`` beside the path so a caller can fail LOUDLY
        with the location rather than reporting an unattributed UNREADABLE. The
        old shape returned a bare ``None`` and the check said only "the daemon log
        could not be read", which is true of a wrong path and of a daemon that
        never started, and those need different fixes.
        """
        path = self.daemon_log_path()
        if not os.path.isfile(path):
            return None, path
        with open(path, "r", errors="replace") as handle:
            return handle.read(), path

    def status(self):
        """The artifact-coverage report, from the surface that carries it.

        `kin support --json` at `health.repository_artifact_coverage`.

        This suite previously called `kin graph status --json`. **That flag never
        existed.** Searched across all 334 commits touching
        `crates/kin-cli/src/main.rs`, `GraphAction::Status` took an argument in
        zero of the 275 that carry the enum, while the control (`Inspect` taking
        arguments) held in all 275. So the suite was written against a surface
        the product never shipped, every call exited 2 on a clap usage error, and
        both checks below reported UNREADABLE from the moment it was wired in.

        The usage error is also why the third check failed: clap rejects the
        argument before the command runs, so nothing ever started the daemon
        whose log that check reads. One wrong flag produced all three findings.
        """
        rc, out = self.kin_run(["support", "--json"])
        if rc != 0:
            return None, out
        try:
            start = out.find("{")
            end = out.rfind("}")
            return json.loads(out[start : end + 1]), out
        except (ValueError, IndexError):
            return None, out

    def status_text(self):
        """`kin status`'s text output, which is where the basis clause lives.

        Not `--json`: neither `kin status --json` nor `kin support --json`
        carries an admission field, measured on 2026-08-30. The FIR-2820 basis is
        a text-surface property, so the invariant check reads it there.
        """
        rc, out = self.kin_run(["status"])
        return out


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
    """The read admits before it answers, so the two trees cannot be seen apart.

    **This arm used to assert the opposite and it measured a pre-kin#1258 state.**
    It edited a tracked file and required `repository_tree_in_sync` to read False,
    on the theory that the graph the daemon carries and the tree the authority
    holds would then differ. Since read-after-admit landed, every read surface
    admits the working tree before it reports, so they cannot be observed
    diverged through the CLI at all.

    Measured on 2026-08-30 against a binary carrying kin#1258, every route:

        start:                       in_sync=True  authority=1 graph_tree=1
        after edit:                  in_sync=True  authority=1 graph_tree=1
        after kin admit:             in_sync=True  authority=1 graph_tree=1
        daemon stop + edit + admit:  in_sync=True  authority=1 graph_tree=1

    `authority_artifact_count` and `graph_tree_artifact_count` move together in
    every one. **The divergence route is unreachable and that is the thesis
    working**, graph truth taking the working tree on read, not a gap. Do not
    resurrect the old arm; see kin#1258 and FIR-2964.

    So this asserts the invariant the runtime now guarantees instead, and it is a
    stronger check than the one it replaces because a stale reading fails it:

    1. after an edit, the trees read in sync AND the basis names the admission
       the read just performed, rather than reporting sync off a stale reading;
    2. with no daemon able to run, the same read names the gap and never claims
       it measured the working copy.

    Assertion 2 is what stops assertion 1 passing vacuously. A surface that
    always said "in sync, as admitted 0s ago" would satisfy 1 forever, and only
    the arm where nothing can admit can tell that apart from a real answer.
    """
    result = Result(1, "the read admits before it answers, and says so")
    with open(os.path.join(suite.repo, "src", "mod_0.py"), "w") as handle:
        handle.write("def fn_0():\n    return 99\n\ndef added_after_admission():\n    pass\n")

    report, out = suite.status()
    coverage = coverage_of(report)
    if coverage is None:
        result.unknown("artifact coverage was not readable: %s" % tail(out))
        return result
    if coverage.get(IN_SYNC) is not True:
        result.bad(
            "the trees read out of sync after an edit, but every read admits "
            "before it answers since kin#1258, so nothing should be able to "
            "observe them apart: %r" % coverage.get(IN_SYNC)
        )
        return result

    text = suite.status_text()
    if ADMITTED_BASIS.search(text):
        result.ok("the read admitted the edit and dated it: %s" % basis_clause(text))
    elif UNMEASURED_BASIS in text:
        result.bad(
            "the trees read in sync while the basis says the working copy was "
            "never measured, which is the FIR-2820 defect: a sync verdict resting "
            "on a reading nothing refreshed"
        )
        return result
    else:
        result.unknown(
            "the status text carried neither an admitted-ago clause nor the "
            "unmeasured one, so this arm cannot tell a fresh answer from a stale "
            "one: %s" % tail(text, 200)
        )
        return result

    # The control. Nothing can bring a daemon up, so nothing can admit, and the
    # read must say so rather than repeat the verdict above.
    #
    # A real executable that REFUSES, never a missing path: an absent binary
    # tests "the binary is absent" and this arm is about "no daemon can run".
    # And stopping the daemon is not enough, because `kin admit` starts one.
    refusing = os.path.join(suite.workdir, "kin-daemon-that-refuses")
    with open(refusing, "w") as handle:
        handle.write("#!/bin/sh\necho 'stub daemon refuses' >&2\nexit 1\n")
    os.chmod(refusing, 0o755)
    if not os.access(refusing, os.X_OK):
        result.unknown("the refusing-daemon stub is not executable, so the "
                       "control would test an absent binary instead")
        return result
    suite.kin_run(["daemon", "stop"])
    restore = suite.env.get("KIN_DAEMON_BIN")
    suite.env["KIN_DAEMON_BIN"] = refusing
    try:
        blind = suite.status_text()
    finally:
        if restore is None:
            suite.env.pop("KIN_DAEMON_BIN", None)
        else:
            suite.env["KIN_DAEMON_BIN"] = restore
    if ADMITTED_BASIS.search(blind):
        result.bad(
            "with no daemon able to run, the read still claimed a fresh "
            "admission, so the dated clause above proves nothing: %s"
            % basis_clause(blind)
        )
        return result
    if UNMEASURED_BASIS not in blind:
        result.unknown(
            "with no daemon able to run, the read named neither an admission nor "
            "the gap, so the control cannot grade: %s" % tail(blind, 200)
        )
        return result
    result.ok("and with no daemon able to run it names the gap instead of a verdict")
    return result


def check_instrument(suite):
    """Every authority open names its caller, read from the daemon's own log.

    Fails LOUDLY with the path it tried when the log is absent. The old shape
    said only "the daemon log could not be read", which is equally true of a
    wrong path and of a daemon that never started, and those need opposite fixes.

    That distinction was not academic here. This check reported UNREADABLE on
    every main run, and the cause was neither: `kin graph status --json` above it
    was rejected by clap before the command ran, so nothing ever started a daemon
    and no log was ever written. A finding that named the path would have said so.
    """
    result = Result(2, "every authority open names the caller that asked for it")
    log_text, log_path = suite.daemon_log()
    if log_text is None:
        result.bad(
            "no daemon log at %s, so no authority open can be attributed; either "
            "nothing started a daemon for this store or the log moved" % log_path
        )
        return result
    problems = instrument_problems(log_text)
    if problems is None:
        result.unknown("the daemon log at %s could not be read" % log_path)
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

    # The report this suite writes, read back through the gate's OWN loader.
    # Every earlier occurrence of this bug shipped a suite whose graders were all
    # correct and whose report the verdict step could not read, so no grader
    # assertion could ever have caught it. This loads the real file with the real
    # loader.
    import importlib.util
    import tempfile as _selftest_tempfile

    gate_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gate.py")
    spec = importlib.util.spec_from_file_location("acceptance_gate", gate_path)
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    scratch = _selftest_tempfile.mkdtemp(prefix="coverage-read-selftest-")

    sample = Result(1, "a sample check")
    sample.ok("the shape this suite writes")
    written = os.path.join(scratch, "report.json")
    with open(written, "w") as handle:
        json.dump(report_payload([sample], None), handle)
    loaded = None
    try:
        loaded = gate.load_report(written)
    except Exception as error:  # noqa: BLE001 - the point is that it must not raise
        print("SELFTEST FAIL gate loader refused this suite's own report: %s" % error)
        sys.exit(1)
    expect(bool(loaded), "the gate loader reads the report this suite writes")

    # The control. A report keyed the old way must still be refused, or the row
    # above would pass for a loader that accepts anything.
    wrong = os.path.join(scratch, "wrong.json")
    with open(wrong, "w") as handle:
        json.dump({"ticket": TICKET, "checks": [{"id": 1, "status": PASS}]}, handle)
    refused = False
    try:
        gate.load_report(wrong)
    except Exception:  # noqa: BLE001 - refusing is the expected outcome
        refused = True
    expect(refused, "the gate loader still refuses a report keyed `checks`")
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

    # The real shape, from `kin support --json`. Measured against a live store on
    # 2026-08-30: the block is nested under `health`, and reading only the two
    # older shapes is what made every call return None even once the command was
    # right. Both halves were broken and fixing one would have looked like no fix.
    expect(
        coverage_of({"health": {"repository_artifact_coverage": {IN_SYNC: True}}}) is not None,
        "the health-nested block `kin support --json` actually emits reads",
    )
    expect(
        coverage_of({"health": {"repository_artifact_coverage": {}}}) is None,
        "a health-nested block without the field is unknown, never agreement",
    )
    expect(
        coverage_of({"health": {}}) is None,
        "an empty health block is unknown",
    )
    expect(
        coverage_of({"health": "not a dict"}) is None,
        "a non-dict health value is unknown rather than an exception",
    )

    # The basis clause, which decides the invariant arm. It lives in the TEXT
    # surface only, so these are the exact strings the product prints.
    FRESH = ("Kin repository-v6 status\n"
             "Tree: 4cdf1b66 (1 artifacts, ahead of its base change as admitted 0s ago)\n")
    STALE = ("Kin repository-v6 status\n"
             "Tree: 9c117d6c (1 artifacts, ahead of its base change as last admitted, not "
             "measured against the working copy: no daemon is running for this repository)\n")
    BARE = "Kin repository-v6 status\nTree: 9c117d6c (1 artifacts, ahead of its base change)\n"
    expect(bool(ADMITTED_BASIS.search(FRESH)), "a dated admission is recognised")
    expect(not ADMITTED_BASIS.search(STALE), "an unmeasured basis is NOT read as an admission")
    expect(not ADMITTED_BASIS.search(BARE), "a bare verdict is NOT read as an admission")
    expect(UNMEASURED_BASIS in STALE, "the unmeasured clause is recognised")
    expect(UNMEASURED_BASIS not in FRESH, "a fresh answer carries no unmeasured clause")
    # The trap this pair exists for: the two clauses share the word "admitted",
    # so a needle keyed on that word alone would score STALE as fresh.
    expect("admitted" in STALE, "the stale clause DOES contain the word admitted")
    expect(basis_clause(FRESH).startswith("Tree:"), "the failure detail quotes the tree line")
    expect(basis_clause("no tree line here") != "", "an unparseable text still yields a detail")

    # The daemon-log resolver returns a PAIR now, so a caller can name the path.
    class _NoLog(object):
        workdir = "/nonexistent-selftest"
        repo = "/nonexistent-selftest/repo"
        daemon_log_path = Suite.daemon_log_path
        daemon_log = Suite.daemon_log
    text, path = _NoLog().daemon_log()
    expect(text is None, "an absent daemon log reads as None")
    expect("nonexistent-selftest" in path, "and it names the path it tried")

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


def report_payload(results, label):
    """The report shape `scripts/acceptance/gate.py` reads.

    The key is `results` and not `checks`. That is not a style choice: the gate
    calls `payload.get("results")` and refuses anything else, and its own refusal
    text records four suites that shipped the wrong key before this one, which
    would have made this the fifth.

    Extracted from `main` rather than left inline, because a shape built inside
    `main` cannot be exercised without running the whole suite, and that is
    precisely how four earlier occurrences reached main with every grader
    correct. The self-test loads what this returns back through the gate's own
    loader.
    """
    return {
        "label": label,
        "ticket": TICKET,
        "results": [
            {
                "id": r.id,
                "title": r.title,
                "status": r.status,
                "detail": r.detail,
                "asserts": r.asserts,
            }
            for r in results
        ],
    }


def absolute_binary(path):
    """Resolve a binary path before anything changes directory.

    Every suite in this job is invoked with `--kin target/release/kin`, a
    RELATIVE path, and every one of them runs that binary with `cwd=` set to a
    `mkdtemp` fixture. A relative path survives the existence check at the
    repository root and then resolves against the fixture, where nothing of that
    name exists.

    That is what happened on main's Acceptance run 33295001248:
    `setup error: [Errno 2] No such file or directory: 'target/release/kin'`,
    exit 3 swallowed by the step's `|| rc=$?`, and the gate then failing on a
    report that was never written. The siblings did not fail because they
    resolve first; `vcs_read_surfaces_repro.py` and
    `working_copy_freshness_repro.py` both carry this function. This suite was
    the only one in the job without it.

    Returns the path unchanged when it does not exist, so the caller's refusal
    names what the operator actually typed.
    """
    if not path:
        return None
    resolved = os.path.abspath(path)
    return resolved if os.path.exists(resolved) else path


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
    # Resolved BEFORE the check, so the refusal names the path actually looked
    # for, and before any fixture changes directory under it.
    args.kin = absolute_binary(args.kin)
    args.daemon = absolute_binary(args.daemon)
    if not os.path.isfile(args.kin) or not os.access(args.kin, os.X_OK):
        print(
            "setup error: %s is not an executable file (resolved from the invocation's "
            "working directory, %s)" % (args.kin, os.getcwd()),
            file=sys.stderr,
        )
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
            json.dump(report_payload(results, args.label), handle, indent=2)

    if any(r.status == FAIL for r in results):
        return 1
    if any(r.status == UNREADABLE for r in results):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
