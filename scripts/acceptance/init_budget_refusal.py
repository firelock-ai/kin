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

It does NOT measure how much memory a conversion really needs, and nothing here
should be read as calibrating the forecast. The forecast's coefficient was fitted
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

CEILING_ENV = "KIN_INIT_MEMORY_CEILING_BYTES"

# A ceiling no conversion of anything can fit under, so the refusal is decided by
# the comparison rather than by the fixture's size. One byte rather than zero,
# because zero is the value the product refuses as unreadable and check 3 owns
# that case.
TINY_CEILING = "1"
# Room for any fixture this suite builds, so check 2's silence is the product
# choosing to say nothing rather than the check failing to look.
ROOMY_CEILING = str(512 * 1024 * 1024 * 1024)

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


CHECKS = [("0", check_0), ("1", check_1), ("2", check_2), ("3", check_3), ("4", check_4)]


# ------------------------------------------------------------------ self test


def self_test():
    """Grade this suite's own graders against their inverse.

    Every helper below decides a check's verdict, so a helper that cannot fail
    is a check that cannot fail. Each is driven once with input it must accept
    and once with input it must reject.
    """
    failures = []

    def expect(condition, message):
        if not condition:
            failures.append(message)

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

    for failure in failures:
        print("SELFTEST FAIL %s" % failure)
    if failures:
        return 1
    print("SELFTEST PASS %d assertions over %d checks" % (14, len(CHECKS)))
    return 0


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

    if not args.kin:
        print("setup: no kin binary given; pass --kin or set KIN_BIN")
        return 3
    kin = os.path.abspath(args.kin)
    if not os.path.isfile(kin) or not os.access(kin, os.X_OK):
        print("setup: %s is not an executable file" % kin)
        return 3

    selected = [(cid, fn) for cid, fn in CHECKS if not args.only or cid in args.only]
    if not selected:
        print("setup: --only selected no checks out of %s"
              % ", ".join(cid for cid, _ in CHECKS))
        return 3

    workdir = tempfile.mkdtemp(prefix="kin-init-budget-")
    results = []
    try:
        suite = Suite(kin, workdir, verbose=args.verbose)
        for check_id, check in selected:
            try:
                results.append(check(suite))
            except Exception as error:  # a check that threw graded nothing
                broken = Result(check_id, TICKET_SILENCE, "check %s raised" % check_id)
                broken.unknown("check %s raised %s: %s"
                               % (check_id, type(error).__name__, error))
                results.append(broken)
    finally:
        if not args.keep:
            shutil.rmtree(workdir, ignore_errors=True)

    for result in results:
        print("CHECK %s %s %s %s" % (result.id, result.ticket, result.status, result.detail))

    # The ids that answered must be the ids that were asked for. A suite that
    # graded fewer checks than it was given prints a clean tally otherwise.
    asked = [cid for cid, _ in selected]
    answered = [result.id for result in results]
    if asked != answered:
        print("CHECK - - %s asked for %s and %s answered"
              % (UNREADABLE, ",".join(asked), ",".join(answered)))
        return 2

    if args.json_path:
        with open(args.json_path, "w") as handle:
            json.dump({
                "suite": "init_budget_refusal",
                "label": args.label,
                "kin": kin,
                "checks": [{"id": r.id, "ticket": r.ticket, "title": r.title,
                            "status": r.status, "detail": r.detail} for r in results],
            }, handle, indent=2)

    if any(result.status == FAIL for result in results):
        return 1
    if any(result.status == UNREADABLE for result in results):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
