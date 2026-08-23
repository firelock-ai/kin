#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
"""NON-CITABLE acceptance suite for host memory-pressure refusals (FIR-2614).

Its output is a regression gate, never proof, never investor-facing and never a
released claim. It shares the CHECK line format, the exit codes and the
`--self-test` discipline of its siblings in this directory, so a reader who
knows one knows all of them.

What it is for
--------------
Kin must never do to a user's machine what heavy tooling did to the box it was
built on. It measures host memory pressure, caps and streams its own work, backs
off before the host swaps, and says so, rather than pushing on until something
is killed. Two measured failures are why: a full-history `kin init` was
OOM-killed at a 12 GiB container cap, and the language-server cold sweep peaked
at 18.2 GB on a one-gigabyte store.

This suite proves the back-off exists and, just as importantly, that it is
disclosed. A daemon that quietly stopped sweeping would look identical to one
that had finished, since every counter on every surface keeps reporting the
unenriched files as pending work.

Two constraints, both covered
-----------------------------
A daemon backs off for two different reasons and the remedies point in opposite
directions. The host can be out of room, which is the user's to fix, and the
daemon can be over its own footprint budget, which is Kin's. Checks 0 to 3 cover
the host half; checks 4 and 5 cover the budget half, including that a budget
refusal blames the budget and not the machine.

Why both levers are pinned rather than produced
-----------------------------------------------
A test that has to exhaust a machine's memory to prove Kin backs off is a test
that takes the machine down to run, on the shared runner, beside every other
job. `KIN_MEMORY_PRESSURE` pins the level the daemon judges its work against and
`KIN_DAEMON_MEMORY_BUDGET_BYTES` names the budget outright, and both are the
same seams the product reads, so what is proven here is the shipped decision
rather than a stand-in for it. A one-byte budget puts any real daemon over the
line on its first look, which is the shortest path to the decision under test
and needs no memory at all.

What it deliberately does NOT assert
------------------------------------
That any particular machine is under pressure, or that the probe grades this
runner correctly. Those are properties of the host, not of the change, and a
suite that asserted them would be red on a busy runner and green on an idle one
for reasons having nothing to do with the code. The reading itself is unit
tested in `kin_core::memory_pressure`, against readings supplied as inputs.

Every check is paired with its control, because a build that had simply broken
the sweep would pass the refusal half of every one of them.

The control pins `nominal` rather than leaving the host unpinned, and that is
not tidiness. The first run of the budget checks was on a development box the
fleet had filled: 98.9 GiB of 128 in use with 41.5 GiB of 42 GiB swap gone, so
Kin's own unforced reading was critical and it was refusing background embedding
exactly as designed. Every unpinned control failed, and it failed for a fact
about the machine rather than about the build. A control that assumes the host
is healthy is no control at all on a machine that is genuinely full, which is
precisely the machine this product exists for. Both axes are therefore pinned in
every arm, so each check moves one lever and the other stays where the check
needs it.

    CHECK <id> <ticket> PASS|FAIL|UNREADABLE <detail>

UNREADABLE is a distinct outcome from FAIL and is never reported as a pass: it
means the probe could not be evaluated (no output, a non-JSON payload, a field
this build does not define). A crashed probe is UNREADABLE, never a verdict.
Exit status is 1 when any check FAILs, 2 when none fail but some are UNREADABLE,
0 only when every check passes, 3 on a setup error.

The binary under test
---------------------
    cargo build --release --locked --bin kin --bin kin-daemon
    python3 scripts/acceptance/memory_pressure_refusal.py --kin target/release/kin

`--kin` may also come from KIN_BIN. The kin-daemon beside it is used when one
exists. No binary is built by this script.
"""

import argparse
import json
import os
import signal
import shutil
import subprocess
import sys
import tempfile
import time

PASS = "PASS"
FAIL = "FAIL"
UNREADABLE = "UNREADABLE"
TICKET = "FIR-2614"

# The doctor row and the durable record this suite is about.
ROW_ID = "host_memory_pressure"
RECORD_NAME = "memory-pressure"
FOOTPRINT_NAME = "daemon-footprint"

# The derived budget's own floor, so a published standing can be told from a
# leftover with a one-byte operator budget in it.
GIB = 1024 * 1024 * 1024


def tail(text, limit=400):
    """The END of a command's output, which is where its error is."""
    text = (text or "").strip()
    return text if len(text) <= limit else "..." + text[-limit:]


def run(cmd, cwd=None, env=None, timeout=600):
    proc = subprocess.run(
        cmd, cwd=cwd, env=env, timeout=timeout,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    return proc.returncode, proc.stdout


class Result(object):
    def __init__(self, check_id, ticket, title):
        self.id = check_id
        self.ticket = ticket
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
        # Every passing assertion, not the last one. Each check grades the
        # pressured case AND its control, and a line naming only the control
        # would read as a pass for a suite that never probed the case it exists
        # for.
        graded = [a["detail"] for a in self.asserts if a["status"] == PASS]
        return "; ".join(graded) if graded else "no assertion was reached"


# ------------------------------------------------------------------- graders

def doctor_row(report):
    """The pressure row out of a `kin doctor --json` report, or None.

    None is UNREADABLE rather than a verdict: a build that does not carry the
    row cannot be graded by a suite that is about the row.
    """
    for row in report.get("checks", []):
        if row.get("id") == ROW_ID:
            return row
    return None


def row_reports_a_refusal(row):
    """Whether the row reports work held back for want of memory.

    Both halves are required. `degraded` alone would be satisfied by a row that
    went red for any reason, and the detail is what a reader acts on.
    """
    if not row:
        return False
    detail = row.get("detail") or ""
    return row.get("status") == "degraded" and "memory pressure" in detail


# The two statuses `kin doctor` treats as blocking. Mirrored from
# `blocks_readiness` in crates/kin-cli/src/commands/health.rs, whose third case
# is `stale` on the one id `semantic_query_readiness` and cannot apply to this
# row. A row of any other status is advisory and changes no verdict.
BLOCKING_STATUSES = ("missing", "misconfigured")


def row_blocks_readiness(row):
    """Whether this row's own status would withhold the page's all-clear.

    This is the half that could break a release rather than a store: the
    install proof gates on `kin doctor`'s aggregate, so a pressure row that
    withheld it would fail a release over a busy machine rather than over a
    defective install.

    Asked of the ROW rather than of the report, because a report is also
    unhealthy on any machine that has no VFS driver or no configured MCP
    client, which is most development machines and none of what this suite is
    about. The report-level property is the A/B below: forcing pressure must
    not change the verdict at all.
    """
    return bool(row) and row.get("status") in BLOCKING_STATUSES


def reason_names_the_budget(reason):
    """Whether a refusal blames this daemon's own budget rather than the host.

    The two constraints fail in different situations and the remedies point in
    opposite directions, so a refusal that named the wrong one would send a
    reader to buy memory they already have. Both halves are required: the budget
    sentence, and the absence of the host sentence.
    """
    reason = reason or ""
    return "it is allowed" in reason and "host memory pressure" not in reason


def status_publishes_the_standing(text):
    """Whether `kin status` printed what the daemon holds and may hold.

    The child figure is required. A line without it cannot tell a daemon with no
    language servers from a reading that never looked for them, which is the
    blindness this whole pass exists to end.
    """
    return "Daemon memory:" in text and "it is allowed" in text and "child processes" in text


def names_a_death(text):
    """Whether the text says the daemon died, rather than offering the idle window.

    Both halves are required and the second is the point. The measured sentence
    named an idle window and told the reader to re-run, which is advice that
    cannot terminate when the cause is an OOM at that repository size. A text
    that names a death AND still leads with the idle window has not fixed
    anything.
    """
    text = text or ""
    # The phrases the product actually produces for a daemon that died, from
    # `daemon_loss_explanation` and the kill record's own summary. Listed rather
    # than guessed at, because a grader matching a phrase nothing emits passes
    # every build.
    return any(phrase in text for phrase in (
        "is gone",
        "was terminated",
        "killed",
        "stopped beating",
    ))


def names_memory_with_a_figure(text):
    """Whether the text names an out-of-memory kill and quotes a ceiling.

    "The daemon died" invites a re-run. "It ran out of memory at 12.0 GiB" does
    not, and the figure is what makes the difference actionable, so a mention
    with no number does not count.
    """
    text = text or ""
    named = "out-of-memory" in text or "out of memory" in text or "memory limit" in text
    has_figure = "GiB" in text or "MiB" in text
    return named and has_figure


def status_discloses_the_refusal(text):
    """Whether `kin graph status` printed the refusal beside its counters.

    The page is where a reader already is when they ask why the numbers are not
    moving, and the refusal is invisible in every counter on it.
    """
    return "memory pressure" in text and "⚠" in text


GRADERS = {
    "names_a_death": names_a_death,
    "names_memory_with_a_figure": names_memory_with_a_figure,
    "row_reports_a_refusal": row_reports_a_refusal,
    "row_blocks_readiness": row_blocks_readiness,
    "status_discloses_the_refusal": status_discloses_the_refusal,
    "reason_names_the_budget": reason_names_the_budget,
    "status_publishes_the_standing": status_publishes_the_standing,
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
        # Inherited pressure would decide this suite's control runs for it. The
        # runner's own state is never an input here.
        self.env.pop("KIN_MEMORY_PRESSURE", None)
        self.env.pop("KIN_DAEMON_MEMORY_BUDGET_BYTES", None)
        if daemon:
            self.env["KIN_DAEMON_BIN"] = daemon
        self.repos = {}

    def git(self, args, cwd):
        base = ["git",
                "-c", "core.hooksPath=/dev/null",
                "-c", "user.email=repro@example.invalid",
                "-c", "user.name=kin-memory-pressure-repro",
                "-c", "commit.gpgsign=false"]
        return run(base + args, cwd=cwd, env=self.env)

    def kin_run(self, args, repo, pressure=None, budget=None, timeout=600):
        """One `kin` command, optionally under a pinned pressure level.

        The level reaches the daemon only through the command that STARTS one:
        a repo worker captures its environment at process start and a later
        command talking to it over HTTP cannot change what it holds. Every
        pressured probe below therefore stops the daemon first.
        """
        env = dict(self.env)
        if pressure is None:
            env.pop("KIN_MEMORY_PRESSURE", None)
        else:
            env["KIN_MEMORY_PRESSURE"] = pressure
        if budget is None:
            env.pop("KIN_DAEMON_MEMORY_BUDGET_BYTES", None)
        else:
            env["KIN_DAEMON_MEMORY_BUDGET_BYTES"] = str(budget)
        return run([self.kin] + args, cwd=repo, env=env, timeout=timeout)

    def restart_daemon(self, repo, pressure=None, budget=None):
        """Stop whatever daemon is serving `repo` and start one under `pressure`.

        Returns the (rc, output) of the command that started the new one, so a
        caller can report a failure to start rather than grading its absence.
        """
        run([self.kin, "daemon", "stop"], cwd=repo, env=self.env, timeout=180)
        return self.kin_run(["graph", "status"], repo, pressure=pressure, budget=budget)

    def record_path(self, repo):
        return os.path.join(repo, ".kin", RECORD_NAME)

    def pid_path(self, repo):
        return os.path.join(repo, ".kin", "daemon.pid")

    def kill_record_path(self, repo):
        return os.path.join(repo, ".kin", "daemon.kills.json")

    def daemon_pid(self, repo):
        """The pid this store publishes, or None."""
        try:
            with open(self.pid_path(repo)) as handle:
                return int(handle.read().strip().splitlines()[0])
        except (IOError, OSError, ValueError, IndexError):
            return None

    def read_kill_record(self, repo):
        """The kill record this store carries, or None."""
        try:
            with open(self.kill_record_path(repo)) as handle:
                return json.load(handle)
        except (IOError, OSError, ValueError):
            return None

    def footprint_path(self, repo):
        return os.path.join(repo, ".kin", FOOTPRINT_NAME)

    def read_published_footprint(self, repo):
        """The standing this store's daemon published, or None."""
        try:
            with open(self.footprint_path(repo)) as handle:
                return json.load(handle)
        except (IOError, OSError, ValueError):
            return None

    def read_record(self, repo):
        """The refusal this store records, or None.

        A record that will not parse is None, matching the product's own rule:
        a record that exists to report a degradation must never become one.
        """
        try:
            with open(self.record_path(repo)) as handle:
                return json.load(handle)
        except (IOError, OSError, ValueError):
            return None

    def fixture(self, name):
        """A small Python library, admitted through `kin init`.

        Initialized with no pressure forced, so every check starts from a store
        that converged normally and the refusals below are the only difference
        between the two arms.
        """
        if name in self.repos:
            return self.repos[name]
        repo = os.path.join(self.workdir, name)
        os.makedirs(os.path.join(repo, "pkg"), exist_ok=True)
        rc, out = self.git(["init", "--initial-branch=main"], repo)
        if rc != 0:
            raise RuntimeError("git init failed: %s" % out)
        for index in range(3):
            with open(os.path.join(repo, "pkg", "module%d.py" % index), "w") as handle:
                handle.write(
                    "def handler%d(payload):\n"
                    "    \"\"\"Return the payload unchanged.\"\"\"\n"
                    "    return payload\n" % index
                )
        self.git(["add", "--all"], repo)
        rc, out = self.git(["commit", "-m", "a python library"], repo)
        if rc != 0:
            raise RuntimeError("git commit failed: %s" % out)
        rc, out = self.kin_run(["init"], repo, timeout=900)
        if rc != 0:
            raise RuntimeError("kin init failed in %s: %s" % (repo, out))
        self.repos[name] = repo
        return repo


# --------------------------------------------------------------------- checks

def check_0(suite):
    """A critical machine holds heavy work back and the store records why.

    The record is the whole disclosure mechanism: the daemon that decided is a
    process nobody is watching, and every surface that has to say what happened
    runs later and in another process.
    """
    result = Result(
        "0", TICKET,
        "a critical machine holds heavy work back, and a machine with room does not",
    )
    repo = suite.fixture("pressured")
    rc, out = suite.restart_daemon(repo, pressure="critical")
    if rc != 0:
        result.unknown("could not start a daemon under pressure, exit %d: %s" % (rc, tail(out)))
        return result
    record = suite.read_record(repo)
    if record is None:
        result.bad(
            "a daemon started on a machine pinned critical recorded no refusal at %s; "
            "either it did not hold anything back or it held it back in silence"
            % suite.record_path(repo)
        )
    elif record.get("level") != "critical" or not record.get("reason"):
        result.bad("the recorded refusal names no level or no reason: %s" % json.dumps(record))
    else:
        result.ok("the store records a %s refusal of %s" % (record.get("level"), record.get("work")))

    control = suite.fixture("control")
    rc, out = suite.restart_daemon(control, pressure="nominal")
    if rc != 0:
        result.unknown("could not start a control daemon, exit %d: %s" % (rc, tail(out)))
        return result
    stale = suite.read_record(control)
    if stale is not None:
        result.bad(
            "a store on an unpressured machine recorded a refusal, so this suite's other "
            "half proves nothing: %s" % json.dumps(stale)
        )
    else:
        result.ok("a machine with room records nothing")
    return result


def check_1(suite):
    """`kin doctor` reports the refusal, heals, and changes no verdict.

    Three assertions that pull in different directions and all matter. The row
    has to be there under pressure, because a refusal nobody can see is the
    defect this ticket is about. It has to go away once the work runs, or a
    surface reporting last week's refusal reads exactly like one reporting this
    second's. And forcing pressure must not move the page's verdict, because the
    install proof gates on that verdict and a busy machine is not a broken
    install.

    Both arms run against ONE store on ONE machine, so the only difference
    between the two reports is the pressure. Comparing two stores would fold in
    every row that describes the host, and on a development machine several of
    those are unhealthy for reasons this suite is not about.
    """
    result = Result(
        "1", TICKET,
        "the doctor row reports a refusal, heals when the work runs, and changes no verdict",
    )
    repo = suite.fixture("pressured")
    reports = {}
    for arm, pressure in (("pressured", "critical"), ("healed", "nominal")):
        rc, out = suite.restart_daemon(repo, pressure=pressure)
        if rc != 0:
            result.unknown("%s: could not start a daemon, exit %d: %s" % (arm, rc, tail(out)))
            return result
        rc, out = suite.kin_run(["doctor", "--json"], repo, pressure=pressure)
        try:
            reports[arm] = json.loads(out[out.index("{"):out.rindex("}") + 1])
        except (ValueError, json.JSONDecodeError):
            result.unknown("%s: `kin doctor --json` payload was not JSON (rc=%d): %s"
                           % (arm, rc, tail(out)))
            return result

    under = doctor_row(reports["pressured"])
    healed = doctor_row(reports["healed"])
    if under is None or healed is None:
        result.unknown("this build's doctor report carries no `%s` row" % ROW_ID)
        return result

    if not row_reports_a_refusal(under):
        result.bad("under pressure the row read %s, which reports nothing a reader can act "
                   "on. Row: %s" % (under.get("status"), json.dumps(under)))
    else:
        result.ok("under pressure the row reports the refusal")

    if row_reports_a_refusal(healed):
        result.bad("the row still reports a refusal after the work ran, so it reports the "
                   "past rather than the present. Row: %s" % json.dumps(healed))
    else:
        result.ok("the row heals to %s once the work runs" % healed.get("status"))

    if row_blocks_readiness(under) or row_blocks_readiness(healed):
        result.bad("the row's own status withholds the page's all-clear, so it would fail "
                   "the install proof over a busy machine: %s" % json.dumps(under))
    elif reports["pressured"].get("healthy") != reports["healed"].get("healthy"):
        result.bad(
            "forcing pressure moved the page's verdict from %s to %s, so this row decides a "
            "gate it must not touch"
            % (reports["healed"].get("healthy"), reports["pressured"].get("healthy"))
        )
    else:
        result.ok("the verdict is %s either way" % reports["healed"].get("healthy"))
    return result


def check_2(suite):
    """`kin graph status` prints the refusal beside the counters it explains."""
    result = Result(
        "2", TICKET,
        "graph status discloses a refusal and says nothing on a machine with room",
    )
    for name, pressure, wanted in (
        ("pressured", "critical", True),
        ("control", "nominal", False),
    ):
        repo = suite.fixture(name)
        rc, out = suite.restart_daemon(repo, pressure=pressure)
        if rc != 0:
            result.unknown("%s: could not start a daemon, exit %d: %s" % (name, rc, tail(out)))
            continue
        disclosed = status_discloses_the_refusal(out)
        if disclosed != wanted:
            result.bad("%s: disclosed=%s, wanted %s. Output: %s"
                       % (name, disclosed, wanted, tail(out, 900)))
        else:
            result.ok("%s: disclosed=%s as expected" % (name, disclosed))
    return result


def check_3(suite):
    """An unreadable machine proceeds exactly as one with room.

    Absence of evidence is not pressure. A host whose accounting cannot be read
    has said nothing, and a Kin that stopped working over it would have invented
    a limit nobody measured. `KIN_MEMORY_PRESSURE=unknown` is exactly that host.
    """
    result = Result(
        "3", TICKET,
        "an unreadable machine keeps working and discloses nothing",
    )
    repo = suite.fixture("unreadable")
    rc, out = suite.restart_daemon(repo, pressure="unknown")
    if rc != 0:
        result.unknown("could not start a daemon on an unreadable host, exit %d: %s"
                       % (rc, tail(out)))
        return result
    record = suite.read_record(repo)
    if record is not None:
        result.bad("an unreadable machine produced a refusal, which is a limit nobody "
                   "measured: %s" % json.dumps(record))
    elif status_discloses_the_refusal(out):
        result.bad("an unreadable machine disclosed a refusal it never made: %s" % tail(out, 700))
    else:
        result.ok("an unreadable machine keeps working and says nothing")
    rc, out = suite.kin_run(["doctor", "--json"], repo, pressure="unknown")
    try:
        report = json.loads(out[out.index("{"):out.rindex("}") + 1])
    except (ValueError, json.JSONDecodeError):
        result.unknown("`kin doctor --json` payload was not JSON (rc=%d): %s" % (rc, tail(out)))
        return result
    row = doctor_row(report)
    if row is None:
        result.unknown("this build's doctor report carries no `%s` row" % ROW_ID)
    elif row_reports_a_refusal(row):
        result.bad("the doctor row reports a refusal on an unreadable host: %s" % json.dumps(row))
    else:
        result.ok("the doctor row reads %s" % row.get("status"))
    return result


def check_4(suite):
    """A daemon over its own budget backs off and blames the budget, not the host.

    Driven by naming a one-byte budget rather than by allocating gigabytes, for
    the same reason the pressure level is pinned rather than produced: a test
    that has to fill a machine to prove Kin backs off is a test that takes the
    machine down to run. An operator budget is honoured exactly as given, so one
    byte puts any real daemon over it on its first look, which is the shortest
    path to the decision under test.

    The control is the same store with no budget named, where the derived budget
    is gigabytes and nothing backs off.
    """
    result = Result(
        "4", TICKET,
        "a daemon over its footprint budget refuses, and names the budget rather than the host",
    )
    repo = suite.fixture("budgeted")
    rc, out = suite.restart_daemon(repo, pressure="nominal", budget=1)
    if rc != 0:
        result.unknown("could not start a daemon under a one-byte budget, exit %d: %s"
                       % (rc, tail(out)))
        return result
    record = suite.read_record(repo)
    if record is None:
        result.bad("a daemon whose tree is over its budget recorded no refusal at %s"
                   % suite.record_path(repo))
    elif not reason_names_the_budget(record.get("reason")):
        result.bad("the refusal blames the wrong constraint, which sends the reader to buy "
                   "memory they already have: %s" % json.dumps(record))
    else:
        result.ok("the store records a budget refusal of %s" % record.get("work"))

    rc, out = suite.restart_daemon(repo, pressure="nominal", budget=None)
    if rc != 0:
        result.unknown("could not start a control daemon, exit %d: %s" % (rc, tail(out)))
        return result
    stale = suite.read_record(repo)
    if stale is not None:
        result.bad("the derived budget is gigabytes, yet this store still records a refusal, "
                   "so check 4's other half proves nothing: %s" % json.dumps(stale))
    else:
        result.ok("a daemon inside its derived budget records nothing")
    return result


def check_5(suite):
    """`kin status` publishes what the daemon holds, including its children.

    The child figure is the point. Every per-pid view of the daemon that died
    was blind to the 1.93 GiB its language server held, and a status line
    without a child figure cannot tell a daemon with no servers from a reading
    that never looked for them.
    """
    result = Result(
        "5", TICKET,
        "kin status publishes the daemon's footprint against its budget, children named",
    )
    # Its own store, never one another check has published into. Sharing the
    # budgeted fixture let this check pass on the record check 4's one-byte arm
    # had left behind, which is a check that cannot fail for the reason it names.
    repo = suite.fixture("published")
    rc, out = suite.restart_daemon(repo, pressure="nominal", budget=None)
    if rc != 0:
        result.unknown("could not start a daemon, exit %d: %s" % (rc, tail(out)))
        return result
    rc, out = suite.kin_run(["status"], repo, pressure="nominal")
    if rc != 0:
        result.unknown("`kin status` exited %d: %s" % (rc, tail(out)))
        return result
    if not status_publishes_the_standing(out):
        result.bad("kin status published no daemon footprint line, so a reader has no way to "
                   "ask what Kin thinks it is holding. Output: %s" % tail(out, 900))
    else:
        result.ok("kin status names the footprint, the budget and the children")

    # And the number behind the line is this run's derived budget, not a
    # leftover. A published standing whose budget is a byte is the shape the
    # stale record had, and it would satisfy the text grader above.
    published = suite.read_published_footprint(repo)
    if published is None:
        result.bad("no standing was published at %s, so the line above came from somewhere "
                   "this check did not write" % suite.footprint_path(repo))
    elif not published.get("budget_is_derived") or published.get("budget_bytes", 0) < GIB:
        result.bad("the published budget is not this run's derived one: %s"
                   % json.dumps(published))
    else:
        result.ok("the published budget is derived and is %d bytes"
                  % published.get("budget_bytes"))
    return result


def check_6(suite):
    """FIR-2650: a daemon that was killed must not be reported as an idle exit.

    Measured by the liaison on the kin-db 0.7.51 pin, psf/requests at full
    history inside a 12 GiB container. `kin init` completed, exit 0, and the
    daemon was then OOM-killed inside its post-init enrichment commit: its log
    ends mid-commit with no shutdown line, the cgroup recorded `oom_kill 1`, and
    `docker inspect` read `OOMKilled=true`. Kin reported that death as

        the kin daemon at http://... stopped answering while the lsp sweep
        status request was in flight; it exits after its idle window, so re-run
        the command and kin will start a fresh one

    That sentence is built from the endpoint and the request name alone and asks
    nothing about whether the daemon is alive. The truth was on two independent
    surfaces and Kin used neither.

    It matters past the wording. An idle exit is a normal event and its advice
    is to re-run; an OOM kill at that repository size recurs on every attempt,
    so the reader is sent around a loop that cannot terminate.

    This arm kills a real daemon with SIGKILL, which is the signal the OOM
    killer sends, and then asks Kin something. The answer must say the daemon
    died. It must not offer the idle window as the explanation.
    """
    result = Result(
        "6", TICKET,
        "a killed daemon is reported as a death, not as an idle-window exit",
    )
    repo = suite.fixture("killed")
    rc, out = suite.restart_daemon(repo, pressure="nominal")
    if rc != 0:
        result.unknown("could not start a daemon, exit %d: %s" % (rc, tail(out)))
        return result
    pid = suite.daemon_pid(repo)
    if pid is None:
        result.unknown("no daemon pid was published at %s" % suite.pid_path(repo))
        return result
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError as error:
        result.unknown("could not kill the daemon at pid %s: %s" % (pid, error))
        return result
    # The reaper in the process that spawned it records the death. Give it the
    # moment that takes; a bounded wait separates "not yet" from "never".
    for _ in range(40):
        time.sleep(0.25)
        if suite.read_kill_record(repo) is not None:
            break

    record = suite.read_kill_record(repo)
    if record is None:
        result.bad("a daemon killed with SIGKILL left no record at %s, so no surface can "
                   "name the death and every one of them is free to call it an idle exit"
                   % suite.kill_record_path(repo))
        return result
    result.ok("the store records the kill (kills=%s last_cause=%s)"
              % (record.get("kills"), list((record.get("last_cause") or {}).keys())[:1]))

    rc, out = suite.kin_run(["graph", "status"], repo, pressure="nominal")
    if names_a_death(out):
        result.ok("kin graph status names the death rather than an idle window")
    else:
        result.bad("kin graph status says nothing about a daemon this store recorded as "
                   "killed. Output: %s" % tail(out, 700))

    rc, out = suite.kin_run(["doctor", "--json"], repo, pressure="nominal")
    row = None
    try:
        report = json.loads(out[out.index("{"):out.rindex("}") + 1])
        row = next((r for r in report.get("checks", [])
                    if r.get("id") == "daemon_kill_record"), None)
    except (ValueError, json.JSONDecodeError):
        result.unknown("`kin doctor --json` payload was not JSON: %s" % tail(out))
        return result
    if row is None:
        result.unknown("this build's doctor report carries no `daemon_kill_record` row")
    elif row.get("status") == "healthy":
        result.bad("the doctor row reads healthy on a store whose daemon was killed: %s"
                   % json.dumps(row))
    else:
        result.ok("the doctor row reports the kill (status=%s)" % row.get("status"))
    return result


def check_7(suite):
    """FIR-2650: an OOM kill is named as one, with the figure, on every surface.

    Check 6 proves a death is not called an idle exit. This proves the other
    half: when the kernel's own counter attributed the kill to memory, every
    surface says so and quotes the ceiling, because "the daemon died" invites a
    re-run while "it ran out of memory at 12.0 GiB" does not.

    The evidence is planted rather than produced. Attributing a kill to memory
    needs a cgroup counter that moved, which no macOS host has and no CI runner
    reliably offers, so this writes the record a real OOM leaves and asks the
    surfaces to read it. That is the half FIR-2650 is about: on the measured run
    the truth was already on two surfaces and Kin used neither. What it does not
    prove is the recording, which check 6 covers on the killing side and which a
    capped container covers end to end.
    """
    result = Result(
        "7", TICKET,
        "a kill the kernel attributed to memory is named as one, with the ceiling",
    )
    repo = suite.fixture("oomnamed")
    rc, out = suite.restart_daemon(repo, pressure="nominal")
    if rc != 0:
        result.unknown("could not start a daemon, exit %d: %s" % (rc, tail(out)))
        return result
    run([suite.kin, "daemon", "stop"], cwd=repo, env=suite.env, timeout=180)

    twelve_gib = 12 * 1024 * 1024 * 1024
    planted = {
        "kills": 1,
        "memory_kills": 1,
        "first_unix": 1787000000,
        "last_unix": 1787000000,
        "last_pid": 4103,
        "last_cause": {"MemoryLimit": {"kernel_oom_kills": 1}},
        "limit_bytes": twelve_gib,
        "last_rss_bytes": twelve_gib - 5 * 1024 * 1024,
    }
    with open(suite.kill_record_path(repo), "w") as handle:
        json.dump(planted, handle)

    rc, out = suite.kin_run(["graph", "status"], repo, pressure="nominal")
    if names_memory_with_a_figure(out):
        result.ok("kin graph status names the memory kill and quotes the ceiling")
    else:
        result.bad("kin graph status does not name an out-of-memory kill with its figure on "
                   "a store whose record carries the kernel's own attribution. Output: %s"
                   % tail(out, 700))

    rc, out = suite.kin_run(["doctor", "--json"], repo, pressure="nominal")
    try:
        report = json.loads(out[out.index("{"):out.rindex("}") + 1])
    except (ValueError, json.JSONDecodeError):
        result.unknown("`kin doctor --json` payload was not JSON: %s" % tail(out))
        return result
    row = next((r for r in report.get("checks", [])
                if r.get("id") == "daemon_kill_record"), None)
    if row is None:
        result.unknown("this build's doctor report carries no `daemon_kill_record` row")
    elif names_memory_with_a_figure(row.get("detail") or ""):
        result.ok("the doctor row names the memory kill and quotes the ceiling")
    else:
        result.bad("the doctor row does not name an out-of-memory kill with its figure: %s"
                   % json.dumps(row))
    return result


CHECKS = [("0", check_0), ("1", check_1), ("2", check_2), ("3", check_3),
          ("4", check_4), ("5", check_5), ("6", check_6), ("7", check_7)]


# ------------------------------------------------------------------ self-test

def self_test():
    """Falsify every grader against its own inverse.

    A grader that cannot tell its two cases apart reports a clean product on a
    broken one, so each case here is paired with the input that must produce the
    opposite verdict. This runs before any build in CI, so a broken grader is
    named in seconds rather than after three minutes of compiling.
    """
    failures = []

    row_cases = [
        (True, {"id": ROW_ID, "status": "degraded",
                "detail": "host memory pressure is critical: 11.5 GiB of the 12.0 GiB this "
                          "container allows is in use, so the language-server enrichment "
                          "sweep did not start."}),
        # A row that is degraded for some other reason is not this disclosure.
        (False, {"id": ROW_ID, "status": "degraded", "detail": "the daemon was killed"}),
        # A healthy row naming the subject is the quiet case, not the reported one.
        (False, {"id": ROW_ID, "status": "healthy",
                 "detail": "no work has been held back on this store for want of memory"}),
        (False, {"id": ROW_ID, "status": "unsupported", "detail": "memory pressure"}),
        (False, None),
    ]
    for want, row in row_cases:
        got = row_reports_a_refusal(row)
        if got != want:
            failures.append("row_reports_a_refusal(%s) = %s, wanted %s"
                            % (json.dumps(row), got, want))

    healthy_cases = [
        # The two statuses that withhold the page's all-clear.
        (True, {"id": ROW_ID, "status": "missing"}),
        (True, {"id": ROW_ID, "status": "misconfigured"}),
        # And the four that do not, which is what this row is allowed to be.
        (False, {"id": ROW_ID, "status": "degraded"}),
        (False, {"id": ROW_ID, "status": "healthy"}),
        (False, {"id": ROW_ID, "status": "unsupported"}),
        (False, {"id": ROW_ID, "status": "pending"}),
        (False, None),
    ]
    for want, row in healthy_cases:
        got = row_blocks_readiness(row)
        if got != want:
            failures.append("row_blocks_readiness(%s) = %s, wanted %s"
                            % (json.dumps(row), got, want))

    status_cases = [
        (True, "Entities: 12  |  Files: 3\n\n⚠ host memory pressure is critical, so the "
               "language-server enrichment sweep did not start."),
        # The clean page must not read as a disclosure.
        (False, "Entities: 12  |  Files: 3\n\n✓ No issues detected."),
        # A warning about something else is not this one.
        (False, "⚠ language-server enrichment is suspended for this store"),
        # And the words alone, with no warning marker, are the help text on a
        # page that is otherwise clean.
        (False, "notes: set KIN_MEMORY_PRESSURE to pin the memory pressure level"),
    ]
    for want, text in status_cases:
        got = status_discloses_the_refusal(text)
        if got != want:
            failures.append("status_discloses_the_refusal(%r) = %s, wanted %s"
                            % (text, got, want))

    budget_cases = [
        (True, "this repository's daemon and the 1 process(es) it started hold 8.4 GiB of the "
               "8.0 GiB it is allowed (derived from the memory available here), of which "
               "1.9 GiB is in those child processes, so the language-server enrichment sweep "
               "did not start."),
        # The host sentence is the other constraint and must not read as this one.
        (False, "host memory pressure is critical: 11.5 GiB of the 12.0 GiB this container "
                "allows is in use, so the language-server enrichment sweep did not start."),
        # A sentence carrying both blames the host, which is the ambiguity the
        # grader exists to refuse.
        (False, "host memory pressure is critical and it is allowed less than that"),
        (False, None),
        (False, ""),
    ]
    for want, reason in budget_cases:
        got = reason_names_the_budget(reason)
        if got != want:
            failures.append("reason_names_the_budget(%r) = %s, wanted %s" % (reason, got, want))

    standing_cases = [
        (True, "Store size: 12 MiB\nDaemon memory: this repository's daemon and the 1 "
               "process(es) it started hold 2.5 GiB of the 8.0 GiB it is allowed (derived from "
               "the memory available here), of which 512 MiB is in those child processes"),
        # A line with no child figure cannot tell a daemon with no servers from
        # a reading that never looked.
        (False, "Daemon memory: holds 2.5 GiB of the 8.0 GiB it is allowed"),
        # And the label alone is not the disclosure.
        (False, "Daemon memory: not measured"),
        (False, "Store size: 12 MiB"),
    ]
    for want, text in standing_cases:
        got = status_publishes_the_standing(text)
        if got != want:
            failures.append("status_publishes_the_standing(%r) = %s, wanted %s"
                            % (text, got, want))

    death_cases = [
        (True, "the daemon serving this repository (pid 41) is gone; it was committing"),
        (True, "a daemon serving this store was killed 1 time(s)"),
        (True, "the daemon serving this repository was terminated while the request was in flight"),
        # The measured sentence, which is the thing this grader must reject.
        (False, "the kin daemon at http://127.0.0.1:39767 stopped answering while the lsp "
                "sweep status request was in flight; it exits after its idle window, so "
                "re-run the command and kin will start a fresh one"),
        (False, "Semantic enrichment: present (1058 entities; completion not attested)"),
        (False, ""),
        (False, None),
    ]
    for want, text in death_cases:
        got = names_a_death(text)
        if got != want:
            failures.append("names_a_death(%r) = %s, wanted %s" % (text, got, want))

    memory_cases = [
        (True, "this machine's kernel recorded 1 out-of-memory kill(s) against the 12.0 GiB "
               "available here"),
        (True, "killed by the memory limit; 512 MiB resident at its last beat"),
        # Named without a figure is not actionable, and a figure without the
        # cause is not this defect either.
        (False, "the daemon ran out of memory"),
        (False, "the daemon was terminated; 12.0 GiB available here"),
        (False, ""),
    ]
    for want, text in memory_cases:
        got = names_memory_with_a_figure(text)
        if got != want:
            failures.append("names_memory_with_a_figure(%r) = %s, wanted %s" % (text, got, want))

    # `tail` must keep the END of an output, which is where the error is.
    tail_cases = [
        ("short", "short"),
        ("WARN noise " * 60 + "Error: the real cause", None),
    ]
    for text, exact in tail_cases:
        got = tail(text, 40)
        if exact is not None and got != exact:
            failures.append("tail(%r) = %r, wanted %r" % (text, got, exact))
        if exact is None and not got.endswith("Error: the real cause"):
            failures.append("tail dropped the end of the output: %r" % got)

    # Result.status must never grade a FAIL or an ungraded run as a pass.
    grade_cases = [
        (PASS, [(PASS, "a")]),
        (FAIL, [(PASS, "a"), (FAIL, "b")]),
        (UNREADABLE, [(PASS, "a"), (UNREADABLE, "b")]),
        (FAIL, [(UNREADABLE, "a"), (FAIL, "b")]),
        (UNREADABLE, []),
    ]
    for want, entries in grade_cases:
        result = Result("t", TICKET, "t")
        for status, detail in entries:
            result.asserts.append({"status": status, "detail": detail})
        if result.status != want:
            failures.append("Result.status(%s) = %s, wanted %s"
                            % (entries, result.status, want))

    for failure in failures:
        print("SELFTEST FAIL %s" % failure)
    total = (len(row_cases) + len(healthy_cases) + len(status_cases)
             + len(budget_cases) + len(standing_cases) + len(death_cases)
             + len(memory_cases) + len(tail_cases) + len(grade_cases))
    print("kin-memory-pressure-repro: self-test %d/%d cases"
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
    parser.add_argument("--json", dest="json_path", default=None,
                        help="write the machine-readable report here, for scripts/acceptance/gate.py")
    parser.add_argument("--label", default=os.environ.get("KIN_ACCEPTANCE_LABEL"),
                        help="an opaque run label recorded in the report")
    parser.add_argument("--keep", action="store_true", help="keep the fixtures")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--self-test", action="store_true",
                        help="falsify this suite's graders and exit")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    if not args.kin:
        print("kin-memory-pressure-repro: no kin binary. Pass --kin or set KIN_BIN.")
        return 3
    # Absolute, because every command below runs with cwd inside a fixture in a
    # temp directory, and a relative path would resolve against that fixture
    # rather than against the checkout.
    kin = os.path.abspath(os.path.expanduser(args.kin))
    if not os.path.isfile(kin) or not os.access(kin, os.X_OK):
        print("kin-memory-pressure-repro: %s is not an executable file" % kin)
        return 3
    daemon = args.daemon and os.path.abspath(os.path.expanduser(args.daemon))
    if not daemon:
        beside = os.path.join(os.path.dirname(kin), "kin-daemon")
        daemon = beside if os.path.isfile(beside) else None

    workdir = tempfile.mkdtemp(prefix="kin-memory-pressure-repro-")
    try:
        suite = Suite(kin, workdir, daemon=daemon, verbose=args.verbose)
        results = []
        for check_id, check in CHECKS:
            try:
                results.append(check(suite))
            except Exception as error:  # noqa: BLE001 - a crashed probe is UNREADABLE
                result = Result(check_id, TICKET, "probe crashed")
                result.unknown("%s: %s" % (type(error).__name__, error))
                results.append(result)
        for result in results:
            print("CHECK %s %s %s %s" % (result.id, result.ticket, result.status, result.detail))
        failed = [r for r in results if r.status == FAIL]
        unreadable = [r for r in results if r.status == UNREADABLE]
        print("kin-memory-pressure-repro: %d checks, %d pass, %d FAIL, %d UNREADABLE"
              % (len(results), len(results) - len(failed) - len(unreadable),
                 len(failed), len(unreadable)))
        # Every daemon this suite started, stopped. A worker left running holds
        # a store open for whatever runs next in the same job.
        for repo in suite.repos.values():
            run([kin, "daemon", "stop"], cwd=repo, env=suite.env, timeout=180)
        if args.json_path:
            # The gate reads this rather than the exit code, because an exit
            # status is one lever with two settings and a check blocked on
            # something outside the change under review needs a third.
            payload = {
                "suite": "memory_pressure_refusal",
                "ticket": TICKET,
                "label": args.label,
                "kin": kin,
                "results": [
                    {"id": r.id, "ticket": r.ticket, "title": r.title,
                     "status": r.status, "detail": r.detail, "asserts": r.asserts}
                    for r in results
                ],
            }
            directory = os.path.dirname(os.path.abspath(args.json_path))
            if directory:
                os.makedirs(directory, exist_ok=True)
            with open(args.json_path, "w") as handle:
                json.dump(payload, handle, indent=2, sort_keys=True)
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
