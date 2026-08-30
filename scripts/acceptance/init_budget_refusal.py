#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
"""NON-CITABLE acceptance suite for what `kin init` says before and after it runs.

Its output is a regression gate, never proof, never investor-facing and never a
released claim. It shares the CHECK line format, the exit codes and the
`--self-test` discipline of its siblings in this directory, so a reader who
knows one knows all of them.

What it is for
--------------
Two measured failures, both of which a script or an agent reads as success.

The first is silence. On `prometheus/prometheus` at 18,514 commits over 1,676
tracked files, inside an 8 GiB container, `kin init .` was killed by the kernel
at phase 4 of 17 and printed nothing: `SIGKILL` runs no destructor, so the
operator saw four phase lines and a shell that said `Killed`. Measured twice on
the shipped 0.6.0, exit 137 both times, `memory.peak` equal to the cap exactly
and `oom_kill` moving 0 to 1 to 2. The post-mortem Kin writes for that death is
excellent and arrives one run too late, because it is read off disk by the NEXT
command, and most people do not run a command twice after it dies for no stated
reason.

The second is a zero. On `pallets/flask` the same command exited 0 after 473 s
with a store whose summary said "completion not attested, and a daemon serving
this store was killed". The words were right and the exit code was not, and the
exit code is what a scripted setup reads.

What it measures, and what it does not
--------------------------------------
Checks 0 to 3 drive the up-front refusal through the real binary against a real
Git repository, with the ceiling pinned by `KIN_INIT_MEMORY_CEILING_BYTES`
rather than by exhausting a machine. Pinning is deliberate and is the same seam
`memory_pressure_refusal.py` uses for the same reason: a test that has to fill a
machine's memory to prove Kin refuses is a test that takes the machine down to
run, beside every other job on the runner.

Check 4 drives the exit code by putting the store into the state an unwatched
kill leaves, which is what `peek_unwatched_daemon_death` grades: a serving record
beside a pid that is gone. It prefers the real route, reading the pid out of the
store's own `daemon.serving` file and signalling THAT pid, never a pattern, since
`pkill -f` matches an agent's whole command line and has taken sessions down on
this fleet. Where init publishes a store and no daemon ever records itself as
serving it, which is what a host with no language server does, it writes the same
record naming a pid confirmed not to be running. Either route exercises the
product's own grading path; neither fabricates a verdict.

Check 5 grades the band the release measurement opened. `kin init` does not end
when the conversion ends: it starts a repository daemon on the store it just
wrote, and that daemon has its own share of the same machine. A forecast that
fits the ceiling but exceeds that share is the band where the conversion
succeeds and the daemon it starts cannot, which on psf/requests inside a 12 GiB
container meant seventeen completed phases, a 1.2 GB store, and four OOM kills,
with nothing said before the run. It pins the daemon's share with
`KIN_DAEMON_MEMORY_BUDGET_BYTES` for the same reason checks 0 to 3 pin the
ceiling, and it carries a silent arm, because a band that fired on everything
would satisfy every assertion in its loud arm.

It does NOT measure how much memory a conversion really needs, and nothing here
should be read as calibrating the forecast. Check 5 in particular grades the
decision and its wording, never a resident set: what a daemon holds is
FIR-2955's structural half and no check in this workspace gates it. The forecast's coefficient was fitted
to sampled cgroup readings from full conversions of real repositories and that
measurement lives in the lane report, not here. What this asserts is that the
decision is made, disclosed and acted on.

Each check prints one line:

    CHECK <id> <ticket> PASS|FAIL|UNREADABLE <detail>

UNREADABLE is a distinct outcome from FAIL and is never reported as a pass: it
means the probe could not be evaluated. A measurement that cannot be taken is not
a measurement that passed. Exit status is 1 when any check FAILs, 2 when none
fail but some are UNREADABLE, 0 only when every check passes, 3 on a setup error.

The binary under test
---------------------
    cargo build --release --locked --bin kin --bin kin-daemon
    python3 scripts/acceptance/init_budget_refusal.py --kin target/release/kin

`--kin` may also come from KIN_BIN.
"""

from __future__ import print_function

import argparse
import functools
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time

print = functools.partial(print, flush=True)

PASS = "PASS"
FAIL = "FAIL"
UNREADABLE = "UNREADABLE"

TICKET_SILENCE = "FIR-2639"
TICKET_EXIT = "FIR-2650"
TICKET_REPORT = "FIR-2929"
TICKET_DAEMON = "FIR-2955"

# What a seeded row says before its check answers. Named once, because the
# self-test reads it back to prove `main` replaced the row rather than shipping
# the placeholder, and a second spelling is how that assertion goes quietly
# blind.
PENDING_MARKER = "did not answer"

CEILING_ENV = "KIN_INIT_MEMORY_CEILING_BYTES"
# The daemon's own share, which `kin init` forecasts against because the daemon
# it starts at the end runs under it. Pinned rather than produced, for the same
# reason every other limit here is: a test that fills a machine to prove Kin
# noticed takes the runner down beside every other job.
DAEMON_BUDGET_ENV = "KIN_DAEMON_MEMORY_BUDGET_BYTES"

# A ceiling no conversion of anything can fit under, so the refusal is decided by
# the comparison rather than by the fixture's size. One byte rather than zero,
# because zero is the value the product refuses as unreadable and check 3 owns
# that case.
TINY_CEILING = "1"
# Room for any fixture this suite builds, so check 2's silence is the product
# choosing to say nothing rather than the check failing to look.
ROOMY_CEILING = str(512 * 1024 * 1024 * 1024)
# A daemon share smaller than any fixture this suite builds will produce, so
# check 5's band is entered by the comparison rather than by the fixture's size.
# The four-commit fixture forecasts 4,800,000 bytes, one BYTES_PER_COMMIT term
# per commit, so anything well under that works and this is two orders below.
TIGHT_DAEMON_BUDGET = str(64 * 1024)
# And a share no fixture can exceed, for the silent control.
ROOMY_DAEMON_BUDGET = str(512 * 1024 * 1024 * 1024)

# What the daemon-allowance band owes a reader. It is a different sentence from
# the Tight one on purpose: Tight says the conversion might not finish, and this
# says the conversion will finish and the thing that serves it afterward may not
# start. A reader told the first when the second is true goes looking in the
# wrong place.
REQUIRED_DAEMON_BAND_PHRASES = [
    # Unique to this band's sentence. Checked by grepping the tree: it occurs
    # exactly once across kin-core and kin-daemon, in the sentence this check
    # exists to grade.
    "is a different matter",
    "repository daemon",
    "answers nothing",
    "convert a repository with less history",
]
# `is allowed` was in this list and has been removed, because it is not this
# band's phrase. `memory_pressure.rs` uses "it is allowed" four times in the
# daemon's own footprint warning, which a run under a tight pinned budget prints
# anyway, so the assertion was satisfied by a DIFFERENT message than the one it
# named. It was caught on a Linux run whose FAIL detail listed three missing
# phrases and not four: the daemon's own warning had supplied the fourth. The
# check still went red, because the other three are genuinely this band's, and
# an assertion that passes on someone else's output is a passing assertion for
# the wrong reason whether or not its neighbours cover for it.

# Every phrase the refusal owes an operator. A refusal that fires and does not
# say what to do next leaves the reader exactly where the silence did.
REQUIRED_REFUSAL_PHRASES = [
    "needs more memory",
    "commits over",
    "tracked files",
    "give it more than",
    "convert a repository with less history",
    "git clone --depth",
    CEILING_ENV,
]

# What a conversion with room must NOT say. The forecast is a floor and the
# advisory band is narrow, so an ordinary conversion of an ordinary repository
# has to be silent about memory or the line that matters gets skipped.
FORBIDDEN_QUIET_PHRASES = [
    "needs more memory",
    "is expected to hold about",
]


def tail(text, limit=400):
    text = (text or "").strip()
    return text if len(text) <= limit else "..." + text[-limit:]


def _a_pid_that_is_not_running():
    """A process id this host is not currently using.

    Searched rather than invented, because a pid that happens to be live would
    make the store read as SERVED rather than as killed, which is the one
    outcome that would make this check quietly grade nothing. `None` when no
    free id could be confirmed, which the caller reports as unreadable rather
    than guessing.
    """
    for candidate in range(4_194_300, 4_194_000, -1):
        try:
            os.kill(candidate, 0)
        except ProcessLookupError:
            return candidate
        except OSError:
            continue
    return None


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
        graded = [a["detail"] for a in self.asserts if a["status"] == PASS]
        return "; ".join(graded) if graded else "no assertion was reached"


# ------------------------------------------------------------------ reporting


def report_payload(rows, label, kin):
    """The report shape `scripts/acceptance/gate.py` reads.

    The key is `results` and not `checks`. That is not a style choice: the gate
    calls `payload.get("results")` at `gate.py:98` and refuses anything else
    with "carries no results list". This suite shipped keyed `checks`, which is
    the third time that key has broken this gate; `same_owner_call_repro.py`
    records the first and `working_copy_freshness_repro.py` the second.

    What the third instance cost is worth writing down, because the failure is
    quiet. Every acceptance run on main from kin#1232's squash `5088b0e4c`
    onward carried this finding, while the suite itself printed five green
    CHECK lines and exited 0. The step read fine, the log read fine, and the
    only red surface said a report was unreadable. The run that opened FIR-2929
    was read as a runner OOM, because the log carried `daemon exited during
    startup with status signal: 9 (SIGKILL)`, which is the OOM signature; it
    was check 4 signalling the daemon on purpose, which is the whole of what
    check 4 does, and the daemon's own record beside it read `memory_kills=0`.

    Written once here and read back through the gate's own loader by
    `--self-test`, over rows this file's own writer produced, so a rename on
    either side of that boundary fails here rather than on main.
    """
    return {
        "suite": "init_budget_refusal",
        "label": label,
        "kin": kin,
        "results": [{"id": r.id, "ticket": r.ticket, "title": r.title,
                     "status": r.status, "detail": r.detail} for r in rows],
    }


def pending_row(check_id):
    """The row a check that has not answered yet leaves in the report.

    The gate's other refusal is an absent file, and the shape that produces one
    is a report written once at the end: a suite the runner kills, or one that
    returns early, leaves nothing, and "no report at acceptance/init_budget.json"
    is an absence that reads exactly like every other absence. So every selected
    check has a row from the moment the report path is known, and each is
    replaced as its check answers.

    UNREADABLE rather than FAIL, because a check that never ran did not fail;
    the gate treats both as red and only one of them is true.
    """
    row = Result(check_id, TICKET_REPORT, "check %s has not answered" % check_id)
    row.unknown("check %s %s: this suite was interrupted before it graded, so "
                "the report carries the row and not the verdict"
                % (check_id, PENDING_MARKER))
    return row


class Reporter(object):
    """Keeps `--json` on disk and current, rather than writing it once at exit.

    Rewritten in full after every check, because a partial report the gate can
    read is worth more than a complete one it never receives. The write is
    atomic through a sibling temp file so a kill mid-write cannot leave the
    gate half a JSON document, which is the one failure that would read as
    "not JSON" rather than as an interrupted run.
    """

    def __init__(self, path, label, kin):
        self.path = path
        self.label = label
        self.kin = kin
        self.rows = []

    def seed(self, check_ids):
        self.rows = [pending_row(cid) for cid in check_ids]
        self.flush()

    def setup_error(self, detail):
        """The row a run that never reached a check leaves behind.

        A setup failure used to return before the report was written, so the
        gate said the file was missing and named nothing. One FAIL row saying
        what went wrong is strictly more than that.
        """
        row = Result("setup", TICKET_REPORT, "the suite could not start")
        row.bad(detail)
        self.rows = [row]
        self.flush()

    def record(self, result):
        for index, row in enumerate(self.rows):
            if row.id == result.id:
                self.rows[index] = result
                break
        else:
            self.rows.append(result)
        self.flush()

    def flush(self):
        if not self.path:
            return
        payload = report_payload(self.rows, self.label, self.kin)
        tmp = "%s.partial" % self.path
        with open(tmp, "w") as handle:
            json.dump(payload, handle, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, self.path)


# ------------------------------------------------------------------- grading
#
# Pure over text, so `--self-test` can grade them against their own inverse
# without a binary, a repository or a machine of any particular size.


def missing_refusal_phrases(text):
    """Phrases the refusal owes an operator and did not print."""
    body = text or ""
    return [phrase for phrase in REQUIRED_REFUSAL_PHRASES if phrase not in body]


def memory_chatter(text):
    """Phrases a conversion with room must not print."""
    body = text or ""
    return [phrase for phrase in FORBIDDEN_QUIET_PHRASES if phrase in body]


class Suite(object):
    def __init__(self, kin, workdir, verbose=False):
        self.kin = kin
        self.workdir = workdir
        self.verbose = verbose
        self.home = os.path.join(workdir, "home")
        os.makedirs(self.home, exist_ok=True)
        self.env = dict(os.environ)
        # A scratch KIN_HOME so nothing here touches the machine's real store
        # registry, and so a daemon this suite starts is never the fleet's.
        self.env["KIN_HOME"] = self.home
        self.env["HOME"] = self.home
        self.env["GIT_CONFIG_NOSYSTEM"] = "1"
        self.env.pop(CEILING_ENV, None)
        # Same reason as the line above. A machine that already exports a daemon
        # share would decide check 5's control arm instead of the check doing it.
        self.env.pop(DAEMON_BUDGET_ENV, None)
        self.repos = {}

    def git(self, args, cwd):
        proc = subprocess.run(
            ["git"] + args, cwd=cwd, env=self.env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        return proc.returncode, proc.stdout

    def kin_run(self, args, cwd, ceiling=None, timeout=1800, extra_env=None):
        """One real `kin` invocation. The exit code is read directly, never
        through a pipe: `$?` after `kin init | tail` is tail's code, which is
        how a killed run was first read as a clean one."""
        env = dict(self.env)
        if ceiling is not None:
            env[CEILING_ENV] = ceiling
        if extra_env:
            env.update(extra_env)
        proc = subprocess.run(
            [self.kin] + args, cwd=cwd, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            timeout=timeout,
        )
        if self.verbose:
            print("--- kin %s (rc=%d)\n%s" % (" ".join(args), proc.returncode, proc.stdout))
        return proc.returncode, proc.stdout

    def fixture(self, name, commits=4):
        """A tiny Git repository with real history, built once per name."""
        if name in self.repos:
            return self.repos[name]
        repo = os.path.join(self.workdir, name)
        os.makedirs(os.path.join(repo, "pkg"), exist_ok=True)
        rc, out = self.git(["init", "--initial-branch=main"], repo)
        if rc != 0:
            raise RuntimeError("git init failed: %s" % out)
        self.git(["config", "user.email", "kin@example.invalid"], repo)
        self.git(["config", "user.name", "Kin"], repo)
        for index in range(commits):
            path = os.path.join(repo, "pkg", "module%d.py" % index)
            with open(path, "w") as handle:
                handle.write(
                    "def handler%d(payload):\n"
                    "    \"\"\"Return the payload unchanged.\"\"\"\n"
                    "    return payload\n" % index
                )
            self.git(["add", "--all"], repo)
            rc, out = self.git(["commit", "-m", "revision %d" % index], repo)
            if rc != 0:
                raise RuntimeError("git commit failed: %s" % out)
        self.repos[name] = repo
        return repo

    def commit_count(self, repo):
        """Commits reachable from HEAD, or None when git will not say.

        None rather than 0, because a failed count and an empty repository are
        different facts and only one of them is a measurement.
        """
        rc, out = self.git(["rev-list", "--count", "HEAD"], repo)
        if rc != 0:
            return None
        try:
            return int(out.strip().splitlines()[-1])
        except (ValueError, IndexError):
            return None

    def store_exists(self, repo):
        return os.path.isdir(os.path.join(repo, ".kin"))


# --------------------------------------------------------------------- checks


def check_0(suite):
    """A conversion that cannot fit refuses up front instead of dying silently.

    The pre-fix baseline is not a different message, it is no message: the run
    reaches phase 4 and the kernel ends it. So this grades three things at once,
    because any one of them alone would pass on a build that merely crashed
    differently: a non-zero exit, refusal prose on the way out, and no store and
    no staging left behind.
    """
    result = Result("0", TICKET_SILENCE, "an unaffordable conversion refuses before it starts")
    repo = suite.fixture("refused")
    try:
        rc, out = suite.kin_run(["init", "."], repo, ceiling=TINY_CEILING)
    except subprocess.TimeoutExpired:
        result.unknown("`kin init` did not finish inside the timeout")
        return result

    if rc == 0:
        result.bad("`kin init` exited 0 under a %s-byte ceiling, so nothing refused: %s"
                   % (TINY_CEILING, tail(out)))
    else:
        result.ok("`kin init` exited %d rather than converting" % rc)

    if "needs more memory" not in out:
        result.bad("the refusal printed no memory sentence, which is the silence this "
                   "check exists for: %s" % tail(out))
    else:
        result.ok("the refusal says the conversion needs more memory than the ceiling")

    if suite.store_exists(repo):
        result.bad("a refused conversion left a store at %s/.kin behind" % repo)
    else:
        result.ok("no store was written")

    stranded = [name for name in os.listdir(suite.workdir)
                if name.startswith(".kin-git-capture-")]
    if stranded:
        result.bad("a refused conversion stranded staging: %s" % ", ".join(sorted(stranded)))
    else:
        result.ok("no capture staging was stranded")
    return result


def check_1(suite):
    """The refusal names the numbers and every way forward.

    A refusal that says only "no" reproduces the dead end the walk found: the
    obvious workaround, `git clone --depth 1`, is refused by admission, so a
    reader told to "convert a repository with less history" and nothing else is
    told to do the one thing that does not work.
    """
    result = Result("1", TICKET_SILENCE, "the refusal carries the numbers and both remedies")
    repo = suite.fixture("refused")
    try:
        rc, out = suite.kin_run(["init", "."], repo, ceiling=TINY_CEILING)
    except subprocess.TimeoutExpired:
        result.unknown("`kin init` did not finish inside the timeout")
        return result
    if rc == 0:
        result.unknown("nothing refused, so there is no refusal to read: %s" % tail(out))
        return result

    missing = missing_refusal_phrases(out)
    if missing:
        result.bad("the refusal omits %s; it printed: %s"
                   % (", ".join(repr(p) for p in missing), tail(out, 900)))
    else:
        result.ok("the refusal names the counts, the ceiling, both remedies, the shallow "
                  "dead end and the override")
    return result


def check_2(suite):
    """A conversion with room converts and says nothing about memory.

    The control, and the half that can fail silently. A refusal wired to fire on
    everything would pass every assertion in check 0 and make Kin unusable, and a
    forecast that narrates itself on an ordinary repository trains a reader to
    skip the line that matters.
    """
    result = Result("2", TICKET_SILENCE, "a conversion with room is silent and succeeds")
    repo = suite.fixture("admitted")
    try:
        rc, out = suite.kin_run(["init", "."], repo, ceiling=ROOMY_CEILING)
    except subprocess.TimeoutExpired:
        result.unknown("`kin init` did not finish inside the timeout")
        return result

    if rc != 0:
        result.bad("`kin init` exited %d with room to spare: %s" % (rc, tail(out, 900)))
        return result
    result.ok("`kin init` exited 0")

    if not suite.store_exists(repo):
        result.bad("`kin init` exited 0 and wrote no store")
    else:
        result.ok("a store was written")

    chatter = memory_chatter(out)
    if chatter:
        result.bad("a conversion with room narrated its memory: %s" % ", ".join(chatter))
    else:
        result.ok("nothing was said about memory")
    return result


def check_3(suite):
    """A ceiling override Kin cannot read refuses rather than disarming the check.

    The failure being guarded is a typo that turns the guard off. Treating an
    unparseable value as absent would fall back to the measured ceiling, which is
    the one outcome an operator who set the variable will not expect, and the
    conversion that follows would be killed with no warning again.
    """
    result = Result("3", TICKET_SILENCE, "an unreadable ceiling override is refused, not ignored")
    repo = suite.fixture("badceiling")
    try:
        rc, out = suite.kin_run(["init", "."], repo, ceiling="eight gigabytes")
    except subprocess.TimeoutExpired:
        result.unknown("`kin init` did not finish inside the timeout")
        return result

    if rc == 0:
        result.bad("an unreadable %s was ignored and the conversion ran: %s"
                   % (CEILING_ENV, tail(out)))
    else:
        result.ok("`kin init` exited %d rather than converting under a ceiling nobody set" % rc)

    if CEILING_ENV not in out or "not a positive whole number" not in out:
        result.bad("the refusal does not name the variable and what is wrong with it: %s"
                   % tail(out, 700))
    else:
        result.ok("the refusal names the variable and why it was rejected")

    if suite.store_exists(repo):
        result.bad("a refused conversion left a store behind at %s/.kin" % repo)
    else:
        result.ok("no store was written")
    return result


def check_4(suite):
    """A daemon killed during a conversion makes `kin init` exit non-zero.

    The measured shape: `kin init` finished, exit 0, and its own summary said
    "completion not attested, and a daemon serving this store was killed". The
    words were already right; the exit code was the surface a scripted setup
    reads and it said the run was fine.

    Driven by killing the real daemon rather than by planting a record. The pid
    comes from the store's own `daemon.serving` file and the signal goes to that
    pid alone: matching a pattern would reach this fleet's agent sessions, which
    carry their whole prompt in argv.
    """
    result = Result("4", TICKET_EXIT, "a killed daemon yields a non-zero init exit")
    repo = suite.fixture("killed")
    serving = os.path.join(repo, ".kin", "daemon.serving")
    killed = {"pid": None, "error": None, "route": None}
    stop = threading.Event()

    def reaper():
        """Put this store into the state an unwatched kill leaves.

        Two routes to one state, because a check that depends on a daemon
        happening to appear inside the window is a check that reports
        UNREADABLE on any host where it does not. The first route is the real
        one: read the pid out of the store's own serving record and signal THAT
        pid. The second is used only when init publishes a store and no daemon
        ever records itself as serving it, and it writes the same record a
        killed daemon leaves behind, naming a pid that is not running.

        Either way what is exercised is the product's own grading path,
        `peek_unwatched_daemon_death`, which is defined as a serving record
        beside a pid that is gone.
        """
        store = os.path.dirname(serving)
        dead = _a_pid_that_is_not_running()
        # Runs until the conversion returns, not until it has acted once. A
        # planted record can be replaced by a real daemon publishing its own a
        # moment later, and the reading that decides the exit code is taken at
        # the very end, so the last write before then is the one that counts.
        while not stop.is_set():
            try:
                with open(serving) as handle:
                    pid = json.load(handle).get("pid")
            except (IOError, OSError, ValueError):
                pid = None
            if isinstance(pid, int) and pid > 1 and pid != dead:
                try:
                    os.kill(pid, signal.SIGKILL)
                    killed["pid"] = pid
                    killed["route"] = "signalled the real daemon this store recorded"
                except ProcessLookupError:
                    # Already gone, and its record survived it. That is exactly
                    # the state under test, arrived at without any help.
                    killed["pid"] = pid
                    killed["route"] = "found a serving record beside a pid already gone"
                except OSError as error:
                    killed["error"] = str(error)
                return
            if os.path.isdir(store) and dead is not None:
                try:
                    with open(serving, "w") as handle:
                        json.dump({"pid": dead, "oom_kills_at_start": None,
                                   "at_unix": int(time.time())}, handle)
                    killed["pid"] = dead
                    killed["route"] = "planted the record a killed daemon leaves"
                except (IOError, OSError) as error:
                    killed["error"] = str(error)
            time.sleep(0.05)

    watcher = threading.Thread(target=reaper, daemon=True)
    watcher.start()
    try:
        rc, out = suite.kin_run(["init", "."], repo, ceiling=ROOMY_CEILING)
    except subprocess.TimeoutExpired:
        stop.set()
        result.unknown("`kin init` did not finish inside the timeout")
        return result
    finally:
        stop.set()
    watcher.join(timeout=5)

    if killed["pid"] is None:
        result.unknown("this conversion never reached a state a kill could be induced in, so "
                       "nothing was graded%s"
                       % ("" if killed["error"] is None else " (%s)" % killed["error"]))
        return result
    result.ok("%s (pid %d)" % (killed.get("route", "induced a kill"), killed["pid"]))

    if not suite.store_exists(repo):
        result.unknown("the conversion wrote no store, so this is not the case under test")
        return result

    says_killed = "a daemon serving this store was killed" in out
    if rc == 0:
        result.bad("`kin init` exited 0 after its daemon was killed, which is the zero a "
                   "scripted setup reads as done (summary named the kill: %s)" % says_killed)
    else:
        result.ok("`kin init` exited %d" % rc)

    # The two surfaces have to agree. A non-zero exit whose summary says nothing,
    # or a summary that names a kill beside a zero, is the same defect wearing
    # the other face.
    if says_killed and rc == 0:
        result.bad("the summary names the kill and the exit code says success")
    elif rc != 0 and not says_killed:
        result.bad("`kin init` exited %d but its summary never names a killed daemon: %s"
                   % (rc, tail(out, 700)))
    elif says_killed and rc != 0:
        result.ok("the summary and the exit code agree that a daemon was killed")
    return result


def check_5(suite):
    """A conversion that fits the machine but not the daemon's share says so.

    The stranger finding this exists for, measured on the v0.6.2 candidate on
    2026-08-29. psf/requests at 6493 commits inside a 12 GiB container: the
    forecast was 7.3 GB, which is 0.61 of the ceiling and under TIGHT_FRACTION,
    so `kin init` printed nothing about memory at all. All seventeen phases then
    completed, a 1.2 GB store was written, and the repository daemon the same
    command starts was OOM-killed. Four kills across that init and three
    `kin graph status` attempts. The user is left with a store that reports
    success and answers nothing.

    Per-process sampling separated the two: the conversion peaked at 5.518 GiB
    and the daemon at 8.351 GiB, sequentially, so the daemon is the larger of
    the two and it was the one nothing forecast. The forecast is a conversion
    forecast by its own constants and had no daemon term.

    WHAT THIS GRADES, and what it does not. It grades the DECISION and its
    wording, not the memory. Nothing here measures what a daemon holds, and a
    green run says only that a conversion whose store exceeds the daemon's
    share is told so before it starts. The resident-set cost itself is
    FIR-2955's structural half and no check in this workspace gates it.

    Both levers are pinned, which is this suite's standing pattern: the ceiling
    so the conversion has room, the daemon share so the band is entered by the
    comparison rather than by the fixture's size. The silent arm is the half
    that can fail quietly, because a band wired to fire on everything would
    satisfy every assertion above it and make an ordinary conversion narrate
    itself.
    """
    result = Result("5", TICKET_DAEMON,
                    "a conversion that fits the machine but not the daemon's share says so")

    # The silent control first, so a band that fires on everything is caught
    # before its own arm can pass.
    quiet_repo = suite.fixture("daemonroom")
    try:
        rc, out = suite.kin_run(["init", "."], quiet_repo, ceiling=ROOMY_CEILING,
                                extra_env={DAEMON_BUDGET_ENV: ROOMY_DAEMON_BUDGET})
    except subprocess.TimeoutExpired:
        result.unknown("the silent control's `kin init` did not finish inside the timeout")
        return result
    if rc != 0:
        result.bad("the silent control exited %d: %s" % (rc, tail(out, 900)))
        return result
    chatter = memory_chatter(out)
    if chatter:
        result.bad("a conversion with room in both budgets narrated its memory: %s"
                   % ", ".join(chatter))
    else:
        result.ok("a conversion with room in both budgets said nothing")

    # And the band itself.
    repo = suite.fixture("daemontight")
    try:
        rc, out = suite.kin_run(["init", "."], repo, ceiling=ROOMY_CEILING,
                                extra_env={DAEMON_BUDGET_ENV: TIGHT_DAEMON_BUDGET})
    except subprocess.TimeoutExpired:
        result.unknown("`kin init` did not finish inside the timeout")
        return result

    # This band warns. A refusal here would cost a user a conversion that does
    # complete, which is the opposite error and a worse one.
    if rc != 0:
        result.bad("a conversion that fits the machine was stopped, exit %d: %s"
                   % (rc, tail(out, 900)))
    else:
        result.ok("`kin init` exited 0, so the band warns rather than refusing")

    if not suite.store_exists(repo):
        result.bad("the conversion was allowed to proceed and wrote no store")
    else:
        result.ok("a store was written")

    # A "no band at all" outcome is graded FAIL here, deliberately, and an
    # earlier draft of this check got that wrong in a way worth recording.
    #
    # That draft treated silence as UNREADABLE on the theory that a pin which
    # failed to apply would produce it. It does. So does the defect: an
    # unpatched binary has no band to print. The two are indistinguishable from
    # the output, so the guard excused the exact behaviour this check exists to
    # catch, and against the shipped v0.6.2 candidate it reported UNREADABLE
    # where it had previously reported FAIL. A guard that cannot separate its
    # two causes is worse than no guard, because it renames a defect as an
    # environment problem.
    #
    # What actually rules the runner out is source, not output. `ceiling()`
    # returns the pinned value before consulting the host at all, and
    # `FootprintBudget::resolve` returns an operator value unclamped and
    # unconditionally. Neither reads this machine when the variable is set. And
    # checks 0 and 2 already prove the ceiling pin applies wherever this suite
    # runs: one refuses under a tiny ceiling and one is silent under a roomy
    # one, on every host that has ever run them.
    missing = [p for p in REQUIRED_DAEMON_BAND_PHRASES if p not in out]
    if missing:
        result.bad("the line does not say %s: %s" % (", ".join(missing), tail(out, 900)))
    else:
        result.ok("the line names the daemon, its allowance and what a reader can do")

    # And prove the line is about THIS fixture rather than some other forecast,
    # by requiring the survey it was computed from. Only this repository's
    # commit count produces this number.
    commits = suite.commit_count(repo)
    if commits is None:
        result.unknown("could not count the fixture's commits, so the line's survey is unchecked")
    elif ("%d commits" % commits) not in out:
        result.bad("the line does not name this fixture's %d commits, so it is reporting a "
                   "forecast for something else: %s" % (commits, tail(out, 700)))
    else:
        result.ok("the line names this fixture's own %d commits" % commits)

    # The Tight sentence claims the CONVERSION might not finish. Borrowing it
    # here would send a reader to watch the wrong half of the command.
    if "It will probably finish. If the kernel stops it" in out:
        result.bad("the daemon band printed the Tight sentence, whose claim is about the "
                   "conversion rather than about what runs after it: %s" % tail(out, 700))
    else:
        result.ok("the daemon band does not borrow the Tight wording")
    return result


CHECKS = [("0", check_0), ("1", check_1), ("2", check_2), ("3", check_3), ("4", check_4),
          ("5", check_5)]


# ------------------------------------------------------------------ self test


def self_test():
    """Grade this suite's own graders against their inverse.

    Every helper below decides a check's verdict, so a helper that cannot fail
    is a check that cannot fail. Each is driven once with input it must accept
    and once with input it must reject.
    """
    failures = []

    # Counted rather than remembered. The tally this used to print was a
    # hardcoded 14 against twelve assertions, and a number nobody measures is a
    # number that drifts the moment an assertion is added or dropped.
    def expect(condition, message):
        expect.count += 1
        if not condition:
            failures.append(message)

    expect.count = 0

    complete = (
        "this conversion needs more memory than this container has: about 108.9 GB against 8.0 GB\n"
        "  18514 commits over 1676 tracked files is what drives it\n"
        "  give it more than 108.9 GB, on a larger machine\n"
        "  or convert a repository with less history. Note that a shallow clone is not that "
        "repository: `git clone --depth` leaves a boundary Kin refuses\n"
        "  if this container really has more memory, set %s to the true ceiling\n" % CEILING_ENV
    )
    expect(missing_refusal_phrases(complete) == [],
           "a complete refusal was reported as missing %s" % missing_refusal_phrases(complete))
    expect(missing_refusal_phrases("") == REQUIRED_REFUSAL_PHRASES,
           "an empty refusal was not reported as missing every phrase")

    # The mutation that matters: a refusal that fires, states its numbers, and
    # never says what to do. It must be caught, or the dead end survives.
    no_remedy = (
        "this conversion needs more memory than this container has: about 108.9 GB against 8.0 GB\n"
        "  18514 commits over 1676 tracked files is what drives it\n"
    )
    missing = missing_refusal_phrases(no_remedy)
    expect("give it more than" in missing and "git clone --depth" in missing,
           "a refusal with no remedy was accepted as complete")

    expect(memory_chatter("Initialized Kin repository authority at /tmp/x\n") == [],
           "an ordinary summary was reported as narrating memory")
    expect(memory_chatter("  this conversion is expected to hold about 5.0 GB of the 8.0 GB") != [],
           "a narrated forecast was not detected")
    expect(memory_chatter("this conversion needs more memory than this machine has") != [],
           "a refusal leaking into the quiet path was not detected")

    # The Result roll-up. A check that reaches no assertion is UNREADABLE, never
    # a pass, which is what stops a suite that graded nothing reporting green.
    empty = Result("x", "T", "t")
    expect(empty.status == UNREADABLE, "a check with no assertion did not read UNREADABLE")
    mixed = Result("x", "T", "t")
    mixed.ok("fine")
    mixed.unknown("could not read")
    expect(mixed.status == UNREADABLE, "a pass beside an unreadable did not read UNREADABLE")
    mixed.bad("wrong")
    expect(mixed.status == FAIL, "a failure did not win the roll-up")
    passing = Result("x", "T", "t")
    passing.ok("one")
    passing.ok("two")
    expect(passing.status == PASS, "two passes did not read PASS")
    expect("one" in passing.detail and "two" in passing.detail,
           "a passing detail dropped one of its assertions")

    expect(len(CHECKS) == len({check_id for check_id, _ in CHECKS}),
           "two checks share an id, so one of them cannot be selected")

    failures += grade_report_shape(expect)

    for failure in failures:
        print("SELFTEST FAIL %s" % failure)
    if failures:
        return 1
    print("SELFTEST PASS %d assertions over %d checks" % (expect.count, len(CHECKS)))
    return 0


def load_gate():
    """`scripts/acceptance/gate.py`, imported from beside this file.

    Imported rather than reimplemented. A copy of the gate's rules in this file
    would pass on the day the gate's rules changed, which is the whole failure
    being guarded against, one level up.
    """
    import importlib.util

    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gate.py")
    if not os.path.exists(path):
        return None
    spec = importlib.util.spec_from_file_location("acceptance_gate", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def grade_report_shape(expect):
    """Drive this suite's own report through the gate's own loader.

    The defect this exists for grades nothing in the suite: every check passed,
    every CHECK line printed, the process exited 0, and the verdict step could
    not read the file. A self-test that only grades graders cannot see that, and
    for three suites in this directory it did not.

    So the assertions here are about the join between two files rather than
    about either one. `Reporter` is what `main` writes with, `gate.load_report`
    is what the workflow reads with, and neither key is spelled a second time
    here: the ids come from CHECKS, and the statuses come back off the loaded
    rows. Renaming the key on either side turns this red.

    Three arms:

      * the writer `main` uses produces rows the gate reads, with the ids and
        the statuses intact;
      * CONTROL, the `checks`-keyed shape that shipped is still refused, or the
        first arm would pass over any payload at all;
      * `main` is wired to that writer, proven by running this file as a
        subprocess down a path that returns before any check and requiring a
        readable report to exist afterwards. Deleting the `reporter` calls from
        `main` leaves the first two arms green, measured.
    """
    problems = []
    gate = load_gate()
    if gate is None:
        return ["gate.py is not beside this file, so the report shape went unchecked"]

    scratch = tempfile.mkdtemp(prefix="kin-init-budget-selftest-")
    try:
        # Arm 1. The writer main uses, over one row per real check.
        written = os.path.join(scratch, "report.json")
        reporter = Reporter(written, "selftest", "/nonexistent/kin")
        reporter.seed([check_id for check_id, _ in CHECKS])
        graded = Result(CHECKS[0][0], TICKET_REPORT, "a check that answered")
        graded.ok("this row was graded")
        reporter.record(graded)
        try:
            rows = gate.load_report(written)
        except Exception as error:  # noqa: BLE001 - the refusal is the finding
            problems.append("the gate refused this suite's own report: %s" % error)
            rows = {}
        expect(sorted(rows) == sorted(check_id for check_id, _ in CHECKS),
               "the gate read %s out of this suite's report, not %s"
               % (sorted(rows), sorted(check_id for check_id, _ in CHECKS)))
        # Against the GATE's vocabulary, never this file's. `PASS` here and the
        # `PASS` that produced the row are one module global, so comparing them
        # is comparing a constant to itself and a rename of this suite's three
        # status names sails through. Measured: renamed to PASSED/FAILED/UNKNOWN
        # with gate.py untouched, this self-test stayed green at 18 assertions
        # while the real gate reported "carries status 'PASSED', which this gate
        # does not recognize" five times. That is this PR's own defect one field
        # over.
        expect(rows.get(CHECKS[0][0], {}).get("status") == gate.PASS,
               "the gate did not read a graded row's status back as its own %s"
               % gate.PASS)
        expect(rows.get(CHECKS[-1][0], {}).get("status") == gate.UNREADABLE,
               "the gate did not read an unanswered row back as its own %s"
               % gate.UNREADABLE)

        # And through `decide`, which is where the vocabulary is actually
        # enforced. `load_report` accepts any status string; only `decide` says
        # "carries status %r, which this gate does not recognize". A report whose
        # every row passed must produce no findings, or this suite is writing
        # words the gate will refuse on a run where nothing is wrong.
        all_pass = os.path.join(scratch, "all-pass.json")
        passing = Reporter(all_pass, "selftest", "/nonexistent/kin")
        rows_out = []
        for check_id, _ in CHECKS:
            row = Result(check_id, TICKET_REPORT, "a check that answered")
            row.ok("graded")
            rows_out.append(row)
        passing.rows = rows_out
        passing.flush()
        try:
            findings, _notes = gate.decide({"init_budget": gate.load_report(all_pass)}, {})
        except Exception as error:  # noqa: BLE001 - a refusal is the finding
            findings = ["the gate could not decide this suite's report: %s" % error]
        expect(findings == [],
               "the gate does not recognize what this suite writes on a clean "
               "run: %s" % "; ".join(findings)[:300])

        # Arm 2, the control. The shape that shipped must still be refused, or
        # arm 1 proves only that the gate accepts something.
        shipped = os.path.join(scratch, "shipped.json")
        with open(shipped, "w") as handle:
            json.dump({"suite": "init_budget_refusal",
                       "checks": [{"id": check_id, "status": PASS, "detail": "green"}
                                  for check_id, _ in CHECKS]}, handle)
        try:
            gate.load_report(shipped)
            refused = None
        except Exception as error:  # noqa: BLE001 - the refusal is what is wanted
            refused = str(error)
        # Matched on the key this suite owns, not on the gate's sentence. A
        # reword of `gate.py`'s message that still refuses would otherwise turn
        # this red under a CONTROL label saying the gate stopped refusing, which
        # points the next reader at the wrong file.
        expect(refused is not None and "results" in refused,
               "CONTROL the gate no longer refuses the `checks`-keyed shape that "
               "broke every acceptance run on main, so arm 1 grades nothing")

        # Arm 3. That main writes through that writer at all, which neither arm
        # above can see. `--only` naming no real check returns 3 before any
        # fixture is built, so this costs a process and no binary.
        from_main = os.path.join(scratch, "from-main.json")
        proc = subprocess.run(
            [sys.executable, os.path.abspath(__file__),
             "--kin", sys.executable, "--json", from_main,
             "--only", "no-such-check-id"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
        expect(proc.returncode == 3,
               "a run selecting no checks exited %d, not 3" % proc.returncode)
        if not os.path.exists(from_main):
            problems.append("main returned before writing a report, so the gate would "
                            "see an absent file and name nothing about why")
        else:
            try:
                setup_rows = gate.load_report(from_main)
            except Exception as error:  # noqa: BLE001
                problems.append("the gate could not read the report main wrote on a "
                                "setup error: %s" % error)
                setup_rows = {}
            expect(any(row.get("status") == gate.FAIL for row in setup_rows.values()),
                   "main's setup-error report carries no FAIL row, so a suite that "
                   "never started would read as one that graded nothing")

        # Arm 4. That a check which ANSWERS replaces its seeded row. Arm 3 only
        # ever reaches `setup_error`, so deleting `reporter.record` from the
        # check loop leaves every arm above green while the report ships the
        # pending placeholders: five green CHECK lines, exit 0, and five
        # UNREADABLE rows to the gate. Measured, and it is the same shape as the
        # defect this file exists to fix.
        #
        # A stub `kin` rather than a real one, because the question is whether
        # the row was replaced, not what it was replaced with. Check 0 grades the
        # stub's silence as a FAIL and that is a graded row.
        stub = os.path.join(scratch, "kin-stub")
        with open(stub, "w") as handle:
            handle.write("#!/bin/sh\nexit 9\n")
        os.chmod(stub, 0o755)
        answered_path = os.path.join(scratch, "answered.json")
        subprocess.run(
            [sys.executable, os.path.abspath(__file__),
             "--kin", stub, "--json", answered_path, "--only", CHECKS[0][0]],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=300)
        if not os.path.exists(answered_path):
            problems.append("a run of check %s wrote no report at all" % CHECKS[0][0])
        else:
            try:
                answered = gate.load_report(answered_path)
            except Exception as error:  # noqa: BLE001
                problems.append("the gate could not read the report a graded run "
                                "wrote: %s" % error)
                answered = {}
            row = answered.get(CHECKS[0][0], {})
            expect(bool(row) and PENDING_MARKER not in str(row.get("detail", "")),
                   "check %s ran and the report still carries its seeded placeholder, "
                   "so main graded a check and never recorded it: %s"
                   % (CHECKS[0][0], str(row.get("detail"))[:160]))
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    return problems


# ----------------------------------------------------------------------- main


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kin", default=os.environ.get("KIN_BIN"),
                        help="path to the kin binary under test (or KIN_BIN)")
    parser.add_argument("--json", dest="json_path", default=None,
                        help="write the machine-readable report here")
    parser.add_argument("--label", default=os.environ.get("KIN_ACCEPTANCE_LABEL"),
                        help="label recorded in the report")
    parser.add_argument("--keep", action="store_true", help="keep the fixtures")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--only", action="append", default=None,
                        help="run only these check ids")
    parser.add_argument("--self-test", action="store_true",
                        help="grade this suite's own graders and exit")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    # The report exists from here on, whatever happens next. A suite that
    # returns early, raises, or is signalled used to leave the gate an absent
    # file, and "no report at acceptance/init_budget.json" names nothing about
    # why. Every path below writes rows instead.
    reporter = Reporter(args.json_path, args.label,
                        os.path.abspath(args.kin) if args.kin else None)

    if not args.kin:
        detail = "no kin binary given; pass --kin or set KIN_BIN"
        print("setup: %s" % detail)
        reporter.setup_error(detail)
        return 3
    kin = os.path.abspath(args.kin)
    if not os.path.isfile(kin) or not os.access(kin, os.X_OK):
        detail = "%s is not an executable file" % kin
        print("setup: %s" % detail)
        reporter.setup_error(detail)
        return 3

    selected = [(cid, fn) for cid, fn in CHECKS if not args.only or cid in args.only]
    if not selected:
        detail = ("--only selected no checks out of %s"
                  % ", ".join(cid for cid, _ in CHECKS))
        print("setup: %s" % detail)
        reporter.setup_error(detail)
        return 3

    reporter.seed([cid for cid, _ in selected])
    workdir = tempfile.mkdtemp(prefix="kin-init-budget-")

    # A cancelled or timed-out job sends SIGTERM, and the rows already on disk
    # are the last thing worth saving. SIGKILL cannot be caught by anything and
    # is not claimed to be: what the seeded rows buy against a SIGKILL is that
    # the report is already there, carrying UNREADABLE rows for whatever had
    # not answered.
    #
    # Installed after the workdir exists so it can remove it. `os._exit` runs no
    # `finally`, so a handler that did not clean up here would strand a fixture
    # tree on every interrupted run, which the plain KeyboardInterrupt this
    # replaces did not.
    def _flush_and_die(signum, _frame):
        reporter.flush()
        if not args.keep:
            shutil.rmtree(workdir, ignore_errors=True)
        print("CHECK - %s %s the suite was signalled (%d) before every check answered"
              % (TICKET_REPORT, UNREADABLE, signum))
        os._exit(2)

    for signame in ("SIGTERM", "SIGINT"):
        if hasattr(signal, signame):
            try:
                signal.signal(getattr(signal, signame), _flush_and_die)
            except (ValueError, OSError):
                pass  # not the main thread, or a platform without it

    results = []
    try:
        suite = Suite(kin, workdir, verbose=args.verbose)
        for check_id, check in selected:
            try:
                result = check(suite)
            except Exception as error:  # a check that threw graded nothing
                result = Result(check_id, TICKET_SILENCE, "check %s raised" % check_id)
                result.unknown("check %s raised %s: %s"
                               % (check_id, type(error).__name__, error))
            results.append(result)
            reporter.record(result)
    finally:
        # The fixture tree goes first. A flush that raised ahead of the rmtree
        # would strand the tree and swallow the CHECK-line loop below, and the
        # old `finally` held only the rmtree.
        if not args.keep:
            shutil.rmtree(workdir, ignore_errors=True)
        reporter.flush()

    for result in results:
        print("CHECK %s %s %s %s" % (result.id, result.ticket, result.status, result.detail))

    # The ids that answered must be the ids that were asked for. A suite that
    # graded fewer checks than it was given prints a clean tally otherwise. The
    # mismatch is a row in the report as well as a line on stdout, because this
    # used to return before the report was written and the gate then said the
    # file was missing rather than that the suite graded the wrong things.
    asked = [cid for cid, _ in selected]
    answered = [result.id for result in results]
    if asked != answered:
        detail = ("asked for %s and %s answered"
                  % (",".join(asked), ",".join(answered)))
        print("CHECK - - %s %s" % (UNREADABLE, detail))
        mismatch = Result("asked", TICKET_REPORT, "the ids asked for are the ids that answered")
        mismatch.unknown(detail)
        reporter.record(mismatch)
        return 2

    if any(result.status == FAIL for result in results):
        return 1
    if any(result.status == UNREADABLE for result in results):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
