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

A third failure, and the sharpest
---------------------------------
The back-off can be right about a number that is impossible. The v0.5.51
stranger read `graph status` claiming this repository's daemon and its thirteen
children held 25.3 GiB inside a container hard-capped at 12, and background
embedding refused on all three of its stores, so every vector answer came from
an empty index on a box that had room. Summing resident sets across a process
tree charges every shared page once per process that maps it, so the total
tracked how many descendants there were rather than any memory anyone held.
Checks 10 and 11 cover that (FIR-2653): 10 grades the published figure against
the kernel's own two readings for the same processes, and against what the
cgroup is charged where a cap exists; 11 proves a tree the pre-fix arithmetic
would have refused is admitted, with the control that a tree genuinely over its
budget still backs off.

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
# The daemon-death checks are a distinct ticket in the same class, and a CHECK
# line is the whole of what a reader sees when one fails. Labelling them with
# the suite's ticket sent that reader to the wrong issue.
TICKET_DEATH = "FIR-2650"
# The footprint READING is a third ticket in the same class: the back-off was
# right and the number it read was impossible.
TICKET_FOOTPRINT = "FIR-2653"

# The doctor row and the durable record this suite is about.
ROW_ID = "host_memory_pressure"
RECORD_NAME = "memory-pressure"
FOOTPRINT_NAME = "daemon-footprint"

# The derived budget's own floor, so a published standing can be told from a
# leftover with a one-byte operator budget in it.
GIB = 1024 * 1024 * 1024

# An endpoint nothing can be listening on, for the arms that need a dispatch to
# fail rather than a daemon to answer. Port 1 is privileged and unused, so a
# connection there refuses immediately and deterministically instead of hanging.
DEAD_ENDPOINT = "http://127.0.0.1:1"


def tail(text, limit=400):
    """The END of a command's output, which is where its error is."""
    text = (text or "").strip()
    return text if len(text) <= limit else "..." + text[-limit:]


def _is_zombie(pid):
    """Whether `pid` names a process that has exited and not been reaped.

    Linux only, through `/proc`. Everywhere else this is False, which is
    correct rather than a gap: the caller pairs it with `os.kill(pid, 0)`, and
    on a host with no `/proc` an unreaped child still answers that call, so the
    wait falls back to its timeout instead of reporting a wrong state.
    """
    try:
        with open("/proc/%d/stat" % pid) as handle:
            fields = handle.read().rsplit(")", 1)[-1].split()
        return bool(fields) and fields[0] == "Z"
    except (IOError, OSError, IndexError):
        return False


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


# ----------------------------------------------------- the kernel's own view
#
# Every reader below asks the kernel directly rather than asking kin, which is
# the whole point: a check that took its comparison figure from the product
# could never disagree with it. They are Linux-only and each returns None off
# Linux or when the file is not there, so a caller can say "not measurable
# here" instead of grading a zero.

def _sum_kb_field(body, name):
    """Every `Name:  <value> kB` line in a smaps-shaped body, summed, in kB."""
    total = None
    for line in body.splitlines():
        if not line.startswith(name + ":"):
            continue
        parts = line.split(":", 1)[1].split()
        if not parts:
            continue
        try:
            total = (total or 0) + int(parts[0])
        except ValueError:
            continue
    return total


def proportional_bytes(pid):
    """This process's PSS, in bytes, out of `/proc/<pid>/smaps_rollup`.

    PSS divides every shared page by the number of processes mapping it, so a
    sum of PSS across a tree counts each page once. This is the figure the
    product is supposed to be publishing.
    """
    try:
        with open("/proc/%d/smaps_rollup" % pid) as handle:
            kb = _sum_kb_field(handle.read(), "Pss")
    except (IOError, OSError):
        return None
    return None if kb is None else kb * 1024


def resident_bytes(pid):
    """This process's resident set, in bytes, out of `/proc/<pid>/statm`.

    The figure the pre-fix build summed. Kept as the comparison because it is
    what makes the check able to fail: a published figure at or above this one
    is a resident set wearing a footprint's name.
    """
    try:
        with open("/proc/%d/statm" % pid) as handle:
            fields = handle.read().split()
        return int(fields[1]) * os.sysconf("SC_PAGE_SIZE")
    except (IOError, OSError, ValueError, IndexError):
        return None


def descendants_of(pid):
    """Every descendant pid of `pid`, at any depth, out of `/proc`."""
    parents = {}
    try:
        entries = os.listdir("/proc")
    except (IOError, OSError):
        return []
    for entry in entries:
        if not entry.isdigit():
            continue
        try:
            with open("/proc/%s/stat" % entry) as handle:
                fields = handle.read().rsplit(")", 1)[-1].split()
            parents[int(entry)] = int(fields[1])
        except (IOError, OSError, ValueError, IndexError):
            continue
    found, frontier = set(), [pid]
    while frontier:
        current = frontier.pop()
        for child, parent in parents.items():
            if parent == current and child not in found:
                found.add(child)
                frontier.append(child)
    return sorted(found)


def binding_cgroup_dir(pid):
    """The cgroup v2 directory whose `memory.max` binds `pid`, or None.

    The same walk the product does, written again here on purpose: this is the
    independent reading the product's own figure is graded against, and taking
    it from kin would make the comparison a tautology. Leaf to root, smallest
    finite cap wins, because a limit on an ancestor binds just as hard.
    """
    try:
        with open("/proc/%d/cgroup" % pid) as handle:
            body = handle.read()
    except (IOError, OSError):
        return None
    relative = None
    for line in body.splitlines():
        parts = line.split(":", 2)
        if len(parts) == 3 and parts[0] == "0" and parts[1] == "":
            relative = parts[2].strip().lstrip("/")
            break
    segments = [s for s in (relative or "").split("/") if s]
    binding = None
    while True:
        directory = "/".join(["/sys/fs/cgroup"] + segments)
        try:
            with open(os.path.join(directory, "memory.max")) as handle:
                raw = handle.read().strip()
            if raw != "max":
                limit = int(raw)
                if binding is None or limit < binding[0]:
                    binding = (limit, directory)
        except (IOError, OSError, ValueError):
            pass
        if not segments:
            break
        segments.pop()
    return binding and {"dir": binding[1], "limit_bytes": binding[0]}


def cgroup_charge_bytes(directory):
    """What the kernel says this cgroup is charged right now, in bytes."""
    try:
        with open(os.path.join(directory, "memory.current")) as handle:
            return int(handle.read().strip())
    except (IOError, OSError, ValueError):
        return None


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


def reading_is_proportional(own_bytes, pss_bytes, rss_bytes):
    """Whether a published own-figure is a proportional reading of that process.

    Two ways to fail and they catch different builds. A figure at or above the
    resident set IS the resident set, which is the pre-fix reading exactly. A
    figure comfortably below the resident set but well above the proportional
    one is a partial fix, or a resident set on a process that happens to share
    little, and would slip past the first test alone.

    The 25% allowance is for sampling drift between the daemon's own sample and
    this probe's read, and for nothing else: an overcount across a process tree
    is a factor, not a percentage.
    """
    if not all(isinstance(v, int) and v > 0 for v in (own_bytes, pss_bytes, rss_bytes)):
        return False
    return own_bytes < rss_bytes and own_bytes <= int(pss_bytes * 1.25)


def total_fits_the_kernel_charge(total_bytes, charged_bytes, cap_bytes):
    """Whether a published tree total is one its cgroup could actually hold.

    A process tree cannot hold more than the kernel charges the cgroup it runs
    in, and the cgroup cannot be charged more than its cap. Both are asserted,
    because a build whose clamp read the cap instead of the charge would satisfy
    the second and not the first.

    The same 5% is drift between two instants, not room for an overcount.
    """
    if not all(isinstance(v, int) and v > 0 for v in (charged_bytes, cap_bytes)):
        return False
    if not isinstance(total_bytes, int) or total_bytes < 0:
        return False
    return total_bytes <= int(charged_bytes * 1.05) and total_bytes <= cap_bytes


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


def offers_the_idle_window(text):
    """Whether the text explains a lost daemon as an idle-window exit.

    The exact advice the measured run gave for an OOM kill, and the reason
    FIR-2650 is a defect rather than a wording preference: re-running is a
    terminating fix for a daemon that retired, and a loop that cannot terminate
    for one the kernel killed at this repository's size.

    Graded in both directions on purpose. A build that simply deleted the
    sentence would pass a one-sided check while telling every ordinary reader
    nothing, so the control arm requires this to be TRUE where the daemon really
    did retire.
    """
    text = text or ""
    return "idle window" in text and "re-run" in text


def row_reports_a_kill(row):
    """Whether the doctor row reports a killed daemon, rather than merely not
    reporting a healthy one.

    Written as "reports a kill" and not as "is not healthy" on purpose. A row
    that reads `unsupported`, which is what this build emits outside a Kin
    repository, is not healthy either, so a check written the negative way
    passes on a probe that never found a store at all. Both halves are required:
    the status the row's own contract gives a kill, and a detail that names one.
    """
    if not row:
        return False
    return row.get("status") == "degraded" and names_a_death(row.get("detail"))


def enrichment_warning(text):
    """The enrichment kill warning out of `kin status`, or None.

    Isolated from the rest of the page so the remedy is graded on the line that
    names the kill. Asking whether the whole output contains "To recover:" would
    pass on a page where some other row happened to carry those words.
    """
    for line in (text or "").splitlines():
        if line.lstrip().startswith("⚠") and names_a_death(line):
            return line
    return None


def enrichment_line(text):
    """The durable enrichment line out of `kin status`, or None.

    None is UNREADABLE rather than a verdict: a build whose status page carries
    no such line cannot be graded by a check that is about that line.
    """
    for line in (text or "").splitlines():
        if line.startswith("Durable semantic enrichment:"):
            return line
    return None


def enrichment_names_a_kill(line):
    """Whether the enrichment line says a daemon serving this store was killed.

    "Completion not attested" is true of every store, which is exactly why it
    hid this one: the counts, the presence and the caveat were identical to a
    store whose enrichment simply had not been certified yet. Both halves are
    required, because the caveat alone is what the defect looked like.
    """
    line = line or ""
    return "completion not attested" in line and "killed" in line


GRADERS = {
    "names_a_death": names_a_death,
    "names_memory_with_a_figure": names_memory_with_a_figure,
    "row_reports_a_refusal": row_reports_a_refusal,
    "row_blocks_readiness": row_blocks_readiness,
    "status_discloses_the_refusal": status_discloses_the_refusal,
    "reason_names_the_budget": reason_names_the_budget,
    "status_publishes_the_standing": status_publishes_the_standing,
    "offers_the_idle_window": offers_the_idle_window,
    "enrichment_names_a_kill": enrichment_names_a_kill,
    "row_reports_a_kill": row_reports_a_kill,
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
        # An inherited endpoint would decide every probe below for it, and the
        # lost-request checks would then be grading whatever daemon the operator
        # happened to have running.
        self.env.pop("KIN_DAEMON_URL", None)
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

    def kin_run(self, args, repo, pressure=None, budget=None, timeout=600,
                daemon_url=None):
        """One `kin` command, optionally under a pinned pressure level.

        The level reaches the daemon only through the command that STARTS one:
        a repo worker captures its environment at process start and a later
        command talking to it over HTTP cannot change what it holds. Every
        pressured probe below therefore stops the daemon first.

        `daemon_url` pins the endpoint the command dispatches to, which is how
        the checks about a LOST request stay deterministic. Without it the CLI
        resolves an endpoint and starts a replacement daemon when it finds
        none, so a probe meant to grade a failed dispatch would race a respawn
        and usually lose.
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
        if daemon_url is None:
            env.pop("KIN_DAEMON_URL", None)
        else:
            env["KIN_DAEMON_URL"] = daemon_url
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

    def wait_for_exit(self, pid, seconds=30):
        """Wait until `pid` is no longer a live process. True if it went.

        `os.kill` returns before the kernel has finished tearing a process down,
        and until it has, the pid still answers as alive. The two hosts show
        that window differently: on macOS the killed daemon's port already
        refuses a connection, while on a Linux runner the socket stayed open
        long enough to accept one and reset it, `Connection reset by peer (os
        error 104)`. A check about a request lost to a daemon that is ALREADY
        dead has to establish that rather than assume it, or it grades a
        different state on one host than on the other, which is exactly what
        happened.

        A zombie counts as gone. `os.kill(pid, 0)` succeeds on one, so a wait
        that only asked that question would spin until it timed out on any host
        whose parent had not reaped the child yet.
        """
        deadline = time.time() + seconds
        while time.time() < deadline:
            try:
                os.kill(pid, 0)
            except OSError:
                return True
            if _is_zombie(pid):
                return True
            time.sleep(0.2)
        return False

    def daemon_endpoint(self, repo):
        """The endpoint this store's daemon published, or None.

        Read from the store rather than parsed out of a log, because it is the
        same file the CLI resolves an endpoint from, so a check pinning it sends
        its request exactly where the CLI would have sent it.
        """
        try:
            with open(os.path.join(repo, ".kin", "daemon.port")) as handle:
                port = int(handle.read().strip().splitlines()[0])
        except (IOError, OSError, ValueError, IndexError):
            return None
        return "http://127.0.0.1:%d" % port

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

    def publish_standing(self, repo, pressure="nominal", seconds=60):
        """Make this store's daemon publish what it is holding, and return it.

        A standing is written by a pressure call, and those run on the daemon's
        own cadence rather than inside the request that started it. Which call
        arrives first depends on the host: the enrichment sweep publishes at
        start, but only where a language server exists for it to run, and the
        ambient reconcile tick publishes when the working copy moves. A probe
        that read the file the instant `graph status` returned therefore read an
        absent one on a machine with no language servers, which is what real
        0.5.51 bytes did in a container here, twice, reported as UNREADABLE.

        So this provokes the tick it can provoke: it writes a file into the
        working copy and asks for status, then waits. The written file is
        ordinary content in this check's own fixture and changes nothing else.

        It retires the existing record first, so what comes back is a reading
        taken just now rather than one this daemon published during `kin init`,
        when it held two dozen short-lived children. A check that graded a stale
        record against a live kernel would be comparing two different machines.
        """
        try:
            os.remove(self.footprint_path(repo))
        except (IOError, OSError):
            pass
        self.kin_run(["status"], repo, pressure=pressure)
        marker = os.path.join(repo, "pkg", "tick_%d.py" % int(time.time() * 1000 % 1000000))
        try:
            with open(marker, "w") as handle:
                handle.write("def tick():\n    return None\n")
        except (IOError, OSError):
            pass
        self.kin_run(["status"], repo, pressure=pressure)
        return self.wait_for_published_footprint(repo, seconds=seconds)

    def wait_for_record(self, repo, seconds=60):
        """The refusal this store records, waited for. None if it never appears.

        Same reason as `wait_for_published_footprint`: a refusal is written by
        the pressure call that made it, and those run on the daemon's own
        cadence rather than in the request that started it.
        """
        deadline = time.time() + seconds
        while time.time() < deadline:
            record = self.read_record(repo)
            if record is not None:
                return record
            time.sleep(0.5)
        return None

    def wait_for_published_footprint(self, repo, seconds=60):
        """The standing this store's daemon publishes, waited for. None if it never does.

        A daemon publishes its standing on its first pressure call, and those
        come from the reconcile tick and the sweep and embed decisions rather
        than from answering a request, so a probe that reads the file the
        instant `graph status` returns reads an absent one. That is not a
        product finding and it is easy to record as one: the first version of
        checks 10 and 11 reported UNREADABLE against real 0.5.51 bytes in a
        container for exactly this reason.

        Freshness comes from `publish_standing` retiring the old record before
        provoking a new one, not from matching a pid: a daemon can be replaced
        between a probe reading its pid and reading its record, and a wait keyed
        on the pid would then time out over a record that is perfectly current.
        """
        deadline = time.time() + seconds
        while time.time() < deadline:
            published = self.read_published_footprint(repo)
            if published is not None:
                return published
            time.sleep(0.5)
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

    It asserts the contract the product actually offers, which is that the NEXT
    start settles what an unwatched death left behind, not that the kill is
    accounted for at the instant it happens. Nothing is watching at that
    instant, which is the whole defect; a check demanding otherwise would be
    demanding a promise nobody makes and would stay red against a correct fix.
    """
    result = Result(
        "6", TICKET_DEATH,
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
    # Nothing settles the death at the moment of the kill, and asserting that it
    # does would be asserting a contract the product does not offer. A daemon
    # killed with nothing watching leaves a record of having been alive, and the
    # NEXT start reads what the survival of that record means, in the same order
    # a killed sweep is settled. So this asks Kin for something, which starts a
    # daemon, and then asks what the store now says.
    rc, out = suite.restart_daemon(repo, pressure="nominal")
    if rc != 0:
        result.unknown("could not start a successor daemon, exit %d: %s" % (rc, tail(out)))
        return result

    record = suite.read_kill_record(repo)
    if record is None:
        result.bad("a daemon killed with SIGKILL left no record at %s, so no surface can "
                   "name the death and every one of them is free to call it an idle exit"
                   % suite.kill_record_path(repo))
        return result
    result.ok("the successor settled the death this store never had a watcher for "
              "(kills=%s cause=%s)"
              % (record.get("kills"), (record.get("last_cause") or {}).get("kind")))

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
        "7", TICKET_DEATH,
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
        # Internally tagged: `#[serde(tag = "kind", rename_all = "snake_case")]`
        # on DaemonKillCause. The externally-tagged shape this first carried did
        # not deserialize, the reader returned None, and the surface correctly
        # said nothing, which read exactly like the product failing to name an
        # OOM. A planted fixture that cannot be loaded is a check that fails for
        # its own reason.
        "last_cause": {"kind": "memory_limit", "kernel_oom_kills": 1},
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


def check_8(suite):
    """FIR-2650: the sentence a lost request ends with stops asserting the idle window.

    Checks 6 and 7 prove the store RECORDS a death and that `kin graph status`
    and `kin doctor` read it. This is the surface the measured sentence actually
    came from, and it was still wrong after them:

        the kin daemon at http://127.0.0.1:39767 stopped answering while the lsp
        sweep status request was in flight; it exits after its idle window, so
        re-run the command and kin will start a fresh one

    That is built from the endpoint and the request name alone. It asks nothing
    about whether the daemon is alive, so it says "idle window" for a daemon the
    kernel OOM-killed fourteen seconds earlier, and its advice is to re-run,
    which at that repository size is a loop that cannot terminate.

    Both arms run against real daemons and a real SIGKILL, which is the signal
    the OOM killer sends. The difference between them is one file: the serving
    record a killed daemon leaves behind and a retiring one takes with it.

    The control is not decoration. A build that deleted the idle-window sentence
    outright would pass the killed arm and would have told every ordinary reader
    nothing, so the control REQUIRES the old sentence where the daemon really
    did retire.
    """
    result = Result(
        "8", TICKET_DEATH,
        "a request lost to a killed daemon is not explained as an idle-window exit",
    )

    # The control arm. A daemon that stops on its own terms retires its serving
    # record with its endpoint, so this store can prove no death, and the
    # ordinary explanation is the right one.
    quiet = suite.fixture("retired")
    rc, out = suite.restart_daemon(quiet, pressure="nominal")
    if rc != 0:
        result.unknown("could not start a daemon, exit %d: %s" % (rc, tail(out)))
        return result
    run([suite.kin, "daemon", "stop"], cwd=quiet, env=suite.env, timeout=180)
    rc, out = suite.kin_run(["graph", "status"], quiet, pressure="nominal",
                            daemon_url=DEAD_ENDPOINT)
    if offers_the_idle_window(out):
        result.ok("a store whose daemon retired still reads as an idle-window exit")
    else:
        result.bad("the idle-window explanation is gone from a store that has lost no "
                   "daemon, so every ordinary reader now gets nothing. Output: %s"
                   % tail(out, 700))

    # The measured arm.
    repo = suite.fixture("lostrequest")
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
    # This arm is about a request lost to a daemon that is ALREADY dead, so the
    # death is established rather than assumed. Without this wait the arm graded
    # a different state on each host: macOS refused the connection outright,
    # while a Linux runner accepted it and reset it with the pid still alive,
    # which is a real product state and a different one, covered by its own
    # unit test rather than here.
    if not suite.wait_for_exit(pid):
        result.unknown("pid %s was still present 30s after SIGKILL, so nothing here graded "
                       "a request lost to a daemon that had already died" % pid)
        return result

    # Pinned at the endpoint that daemon published, so the request goes where
    # the measured one went and fails the way it failed. Pinning also keeps the
    # CLI from starting a replacement, which is what makes this deterministic
    # rather than a race against a respawn.
    endpoint = suite.daemon_endpoint(repo) or DEAD_ENDPOINT
    rc, out = suite.kin_run(["graph", "status"], repo, pressure="nominal",
                            daemon_url=endpoint)
    if rc == 0:
        result.unknown("the request to %s succeeded after the daemon was killed, so nothing "
                       "here graded a lost request" % endpoint)
        return result
    if offers_the_idle_window(out):
        result.bad("kin explained a SIGKILLed daemon as an idle-window exit and advised a "
                   "re-run, which is the advice that cannot terminate when the cause "
                   "recurs. Output: %s" % tail(out, 900))
    elif names_a_death(out):
        result.ok("the lost request names the death instead of the idle window")
    else:
        result.bad("kin named neither an idle window nor a death for a daemon it had just "
                   "lost, so the reader is left with a socket error. Output: %s"
                   % tail(out, 900))

    # The window check 6 cannot see. Check 6 starts a successor before asking,
    # which settles the death into the store's tally, so it proves the tally is
    # read and says nothing about the moment before one exists. A reader who
    # runs `kin doctor` right after watching a command die has started no
    # successor, and that reader used to be told no daemon serving this store
    # had ever been killed.
    #
    # The absent tally file is what makes this arm discriminating: with no tally
    # to read, a row that reports the kill can only have read the unsettled
    # death, and a build without that reading is left saying "healthy".
    if os.path.exists(suite.kill_record_path(repo)):
        result.unknown("something settled the death into %s before this arm ran, so a "
                       "reported kill no longer proves the unsettled reading"
                       % suite.kill_record_path(repo))
        return result
    rc, out = suite.kin_run(["doctor", "--json"], repo, pressure="nominal",
                            daemon_url=endpoint)
    try:
        report = json.loads(out[out.index("{"):out.rindex("}") + 1])
    except (ValueError, json.JSONDecodeError):
        result.unknown("`kin doctor --json` payload was not JSON: %s" % tail(out))
        return result
    row = next((r for r in report.get("checks", [])
                if r.get("id") == "daemon_kill_record"), None)
    if row is None:
        result.unknown("this build's doctor report carries no `daemon_kill_record` row")
    elif row_reports_a_kill(row):
        result.ok("the doctor row reports a kill nothing has settled yet (status=%s)"
                  % row.get("status"))
    else:
        result.bad("the doctor row does not report the kill on a store whose daemon was "
                   "killed and whose death nothing has settled yet, which is the state a "
                   "reader is in the moment a command dies: %s" % json.dumps(row))
    return result


def check_9(suite):
    """FIR-2650: an enrichment nobody attested says whether a daemon was killed.

    The other half of the measured report. `kin init` exited 0 over a 1.1 GB
    store and summarized the enrichment as

        present (1058 entities, 2016 relations, 6731 changes in durable
        authority generation 1; completion not attested)

    while the daemon that would have finished it lay OOM-killed. Every word of
    that is true of a perfectly healthy store whose enrichment simply has not
    been certified yet, so the two are byte-identical on this surface and the
    reader has no signal at all.

    The claim the fix may make is joint and not causal: this store's enrichment
    is unattested AND a daemon serving it was killed. Whether that kill is what
    stopped the enrichment is not something the record establishes, so the check
    does not ask for it.

    `kin status` is the surface probed because it is the durable one and it can
    be asked again. `kin init` renders the same clause from the same function
    and prints it once per repository, which no scripted check can re-ask; its
    rendering is covered by unit test in `commands/init.rs` instead.
    """
    result = Result(
        "9", TICKET_DEATH,
        "an unattested enrichment names the daemon kill behind it, or names none",
    )

    # The control first, so a build that named a kill unconditionally fails here
    # rather than passing on the killed arm alone.
    quiet = suite.fixture("attested")
    rc, out = suite.kin_run(["status"], quiet, pressure="nominal")
    line = enrichment_line(out)
    if line is None:
        result.unknown("this build's `kin status` carries no durable enrichment line: %s"
                       % tail(out, 700))
        return result
    if enrichment_names_a_kill(line):
        result.bad("a store that has lost no daemon reports one anyway: %s" % line)
    else:
        result.ok("a store that has lost no daemon names no kill")

    repo = suite.fixture("killedenrich")
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
    if not suite.wait_for_exit(pid):
        result.unknown("pid %s was still present 30s after SIGKILL, so the store had no "
                       "death to report yet" % pid)
        return result

    rc, out = suite.kin_run(["status"], repo, pressure="nominal")
    line = enrichment_line(out)
    if line is None:
        result.unknown("this build's `kin status` carries no durable enrichment line after "
                       "the kill: %s" % tail(out, 700))
        return result
    if enrichment_names_a_kill(line):
        result.ok("the enrichment line names the kill beside its counts")
    else:
        result.bad("the enrichment of a store whose daemon was killed reads exactly like one "
                   "that was merely never certified: %s" % line)

    # The cause and the remedy belong on the page too. A line that says a daemon
    # was killed and stops there tells a reader something happened and nothing
    # about what to do, which is most of the way back to the parenthetical.
    #
    # Graded on the warning line itself rather than on the whole page, because
    # a page-wide search for the remedy would pass on a build where some other
    # row happened to carry those words and this line carried none.
    warning = enrichment_warning(out)
    if warning is None:
        result.bad("the enrichment counts name a kill and no warning line states its cause, "
                   "so the reader is told something happened and nothing about what. "
                   "Output: %s" % tail(out, 900))
    elif "To recover:" in warning:
        result.ok("the warning line carries the cause and the remedy together")
    else:
        result.bad("the warning names a kill and offers no way out of it: %s" % warning)
    return result


def _published_own_bytes(published):
    """`own_bytes` out of a published standing, or None when it carries none."""
    footprint = (published or {}).get("footprint") or {}
    value = footprint.get("own_bytes")
    return value if isinstance(value, int) else None


def check_10(suite):
    """FIR-2653: the published footprint is a proportional reading, held under
    what the kernel charges.

    The v0.5.51 stranger read `graph status` claiming this repository's daemon
    and its thirteen children held 25.3 GiB inside a container hard-capped at 12
    GiB, whose own peak was 9.99 GiB and whose `memory.events` said the cap was
    never reached. Not merely wrong: impossible. The cause was in the doc comment
    of the type that carried it, `children_bytes` documented as "Every
    descendant's resident set, summed", and a resident set counts every shared
    page once per process that maps it.

    So this grades the number against the kernel's own two figures for the same
    processes, read here rather than asked of kin, because a check that took its
    comparison from the product could never disagree with it.

    Arm A runs wherever `/proc` does and grades the daemon's own row. It is the
    weaker of the two on purpose, and worth saying why: a LONE process shares
    almost nothing, so its proportional set sits within a percent of its
    resident set and no comparison between them can be evidence. Against
    shipped 0.5.51 bytes in a container this arm passed, at 60,432,384 published
    against 60,014,592 proportional and 63,598,592 resident. It fires where a
    daemon does share, which is every machine with a supervisor beside it.

    Arm B is the container half, it needs a memory cap to exist, and it is what
    caught the shipped defect: the same run published 1,450,377,216 bytes for
    the daemon and twenty-three children while the kernel charged that container
    283,222,016. The double-count needs siblings to appear at all, which is why
    the arm that sees it is the one that compares against a whole-cgroup figure.
    It runs when this process is already inside a cap, which is how the release
    stranger runs and how `acceptance.yml` runs these two checks a second time.
    Where there is no cap there is nothing for a footprint to be held under, and
    the check says so in its own detail rather than reporting an arm it never
    ran.

    Off Linux this is UNREADABLE and says why. `phys_footprint` is what macOS
    publishes and there is no second kernel figure to grade it against without
    root; the macOS reader has unit coverage in `kin-daemon-spawn` instead, and
    what that proves is narrower.
    """
    result = Result(
        "10", TICKET_FOOTPRINT,
        "the published daemon footprint is proportional, and never above what the kernel charges",
    )
    if not sys.platform.startswith("linux"):
        result.unknown(
            "no /proc on %s, so the published figure has no independent kernel reading to be "
            "graded against here. The macOS path (phys_footprint via proc_pid_rusage) is "
            "covered by kin-daemon-spawn's unit tests, which prove the reader answers and "
            "that the fold counts a shared page once; they do not prove this end to end"
            % sys.platform
        )
        return result

    repo = suite.fixture("proportional")
    rc, out = suite.restart_daemon(repo, pressure="nominal")
    if rc != 0:
        result.unknown("could not start a daemon, exit %d: %s" % (rc, tail(out)))
        return result
    published = suite.publish_standing(repo)
    # After the provocation, because it takes two commands and a daemon can be
    # replaced between them; the pid this reads is the one the readings below
    # are about.
    pid = suite.daemon_pid(repo)
    if pid is None:
        result.unknown("this store published no daemon pid at %s" % suite.pid_path(repo))
        return result
    own = _published_own_bytes(published)
    # Read immediately after the record, so the two figures are as close in time
    # as this probe can make them.
    pss = proportional_bytes(pid)
    rss = resident_bytes(pid)
    if own is None:
        result.unknown("this daemon (pid %d) published no standing at %s: %s"
                       % (pid, suite.footprint_path(repo), json.dumps(published)))
        return result
    if pss is None or rss is None or pss <= 0 or rss <= 0:
        result.unknown("could not read pid %d from /proc (pss=%s rss=%s)" % (pid, pss, rss))
        return result

    if not reading_is_proportional(own, pss, rss):
        result.bad(
            "the daemon publishes %d bytes for itself, against %d proportional and %d resident "
            "for pid %d. A figure at or above the resident set is a resident set, and summing "
            "those across a tree is what read 25.3 GiB inside a 12 GiB container"
            % (own, pss, rss, pid)
        )
    else:
        result.ok(
            "the daemon's own figure is %d bytes, against %d proportional and %d resident for "
            "pid %d" % (own, pss, rss, pid)
        )

    binding = binding_cgroup_dir(pid)
    if binding is None:
        result.ok(
            "cgroup arm: not run, because no memory cap binds pid %d, so there is no kernel "
            "charge for a footprint to be held under. Run this suite inside a container with "
            "--memory to exercise it" % pid
        )
        return result
    charged = cgroup_charge_bytes(binding["dir"])
    if charged is None:
        result.unknown("cgroup %s carries a cap of %d and no readable memory.current"
                       % (binding["dir"], binding["limit_bytes"]))
        return result
    total = own + ((published.get("footprint") or {}).get("children_bytes") or 0)
    # Five percent, for the same reason the two figures above are read back to
    # back: the daemon sampled its tree at one instant and this reads the cgroup
    # at another. It is not slack for an overcount, which is a factor, not a
    # percentage.
    if not total_fits_the_kernel_charge(total, charged, binding["limit_bytes"]):
        result.bad(
            "the daemon and its %d child process(es) are published as holding %d bytes while "
            "the kernel charges cgroup %s just %d, under a cap of %d. A process tree cannot "
            "hold more than its container is charged"
            % ((published.get("footprint") or {}).get("child_count", 0), total,
               binding["dir"], charged, binding["limit_bytes"])
        )
    else:
        result.ok(
            "cgroup arm: the published tree holds %d bytes, the kernel charges %d, the cap is "
            "%d" % (total, charged, binding["limit_bytes"])
        )
    return result


def check_11(suite):
    """FIR-2653: the whole TREE is published proportionally, and a daemon inside
    its budget is admitted.

    Check 10 grades the daemon's own row. This grades the sum, which is where
    the defect actually bit: the stranger's line read "of which 23.1 GiB is in
    those child processes", thirteen processes averaging 1.8 GiB each, which is
    what per-process resident sets summed over children that map the same pages
    look like. Background embedding then did not start on any of the three
    stores, so every vector answer that release candidate could give came from
    an empty index: psf/requests finished 0 of 2,116, expressjs/express 0 of 742.

    The comparison is a distance rather than a threshold, so it needs no
    tolerance constant: the published total has to be at least as close to the
    tree's proportional sum as to its summed resident set. A pre-fix build
    publishes the second of those exactly.

    Then the consequence, on the surface it had one. No budget is named: the
    daemon runs under the one it derives from its own ceiling, which is what a
    user runs under, and inside a container that ceiling is the cap. A tree read
    proportionally sits far inside that budget and stays nominal; the same tree
    summed resident does not, which is how three stranger stores finished with
    nothing in their vector index.

    The control is its own store under a one-byte budget, where any real daemon
    is over, and it grades the published RUNG rather than a refusal record.
    Which piece of heavy work reaches a consultation depends on what is
    installed beside the daemon, since the enrichment sweep records a refusal
    only where a language server exists for it to run, and the rung is published
    either way. Without the control a build that had stopped grading its budget
    at all would pass every arm above it.

    What it does NOT prove: that a vector was computed. The suite runs with
    `KIN_DAEMON_AUTO_EMBED=0` and loads no model, deliberately, so what is
    graded is the admission decision and the rung the embed gate reads. That
    gate takes its verdict from this same standing through the same
    `pressure_verdict`; the Rust tests in `kin_core::memory_pressure` and
    `kin_daemon::daemon` carry the other half by name.
    """
    result = Result(
        "11", TICKET_FOOTPRINT,
        "the published tree total is proportional, and a daemon inside its budget is admitted",
    )
    if not sys.platform.startswith("linux"):
        result.unknown(
            "no /proc on %s, so the tree's two readings cannot be taken here. The same "
            "opposition is asserted as a unit test over a synthetic process table in "
            "kin_daemon::daemon, where thirteen children map one image" % sys.platform
        )
        return result

    repo = suite.fixture("proportional-admitted")
    rc, out = suite.restart_daemon(repo, pressure="nominal")
    if rc != 0:
        result.unknown("could not start a daemon, exit %d: %s" % (rc, tail(out)))
        return result
    published = suite.publish_standing(repo)
    pid = suite.daemon_pid(repo)
    own = _published_own_bytes(published)
    if pid is None or own is None:
        result.unknown("no pid or no published standing for %s: pid=%s standing=%s"
                       % (repo, pid, json.dumps(published)))
        return result
    footprint = published.get("footprint") or {}
    total = own + (footprint.get("children_bytes") or 0)
    tree = [pid] + descendants_of(pid)
    proportional_sum, resident_sum = 0, 0
    for member in tree:
        proportional_sum += proportional_bytes(member) or 0
        resident_sum += resident_bytes(member) or 0
    if proportional_sum <= 0 or resident_sum <= 0:
        result.unknown("could not read the %d-process tree from /proc (proportional=%d "
                       "resident=%d)" % (len(tree), proportional_sum, resident_sum))
        return result

    # The record names the tree it measured. A daemon holds two dozen
    # short-lived children during `kin init` and none once it settles, so a
    # record describing a different tree from the one this reads is two
    # different machines being compared and grades nothing.
    if footprint.get("child_count") != len(tree) - 1:
        result.ok(
            "tree arm: not run, because the daemon published a standing over %s child "
            "process(es) and this read finds %d, so the two readings are of different trees"
            % (footprint.get("child_count"), len(tree) - 1)
        )
    elif abs(total - proportional_sum) > abs(total - resident_sum):
        result.bad(
            "the daemon publishes %d bytes for its %d-process tree, which is closer to that "
            "tree's summed resident set of %d than to its proportional sum of %d. Summing "
            "resident sets charges every shared page once per process, and is what read 25.3 "
            "GiB inside a 12 GiB container"
            % (total, len(tree), resident_sum, proportional_sum)
        )
    else:
        result.ok(
            "the published %d bytes for %d process(es) sits with the proportional sum of %d, "
            "not the summed resident set of %d"
            % (total, len(tree), proportional_sum, resident_sum)
        )

    # What the impossible number cost, on the surface it cost it. Nothing is
    # named here: the budget is the one this daemon derives from its own
    # ceiling, which is what a user runs under, and a tree read proportionally
    # sits far inside it while the same tree summed resident does not. That is
    # the whole finding, in one assertion: background embedding refused on all
    # three stranger stores under exactly this shape.
    derived_refusal = suite.read_record(repo)
    if derived_refusal is not None:
        result.bad(
            "this daemon, inside its own derived budget, recorded a refusal: %s. Every "
            "vector answer a store gives in this state comes from an index nothing is "
            "filling" % json.dumps(derived_refusal)
        )
    elif (published.get("level") or "") != "nominal":
        result.bad(
            "this daemon publishes rung %r under its derived budget of %s bytes while holding "
            "%d, so heavy work is judged against a figure the tree is not holding: %s"
            % (published.get("level"), published.get("budget_bytes"), total,
               json.dumps(published))
        )
    else:
        result.ok(
            "under its derived budget of %s bytes the daemon holds %d and stays nominal, so "
            "background embedding is admitted"
            % (published.get("budget_bytes"), total)
        )

    # Its own store, never the one above, so the control cannot pass on a record
    # the first arm left behind or fail on one it cleared. It grades the RUNG
    # rather than a refusal record, because which piece of heavy work reaches a
    # consultation depends on what is installed beside the daemon: the
    # enrichment sweep records a refusal only where a language server exists for
    # it to run, and the rung is published either way.
    control = suite.fixture("proportional-refused")
    rc, out = suite.restart_daemon(control, pressure="nominal", budget=1)
    if rc != 0:
        result.unknown("could not start the control daemon, exit %d: %s" % (rc, tail(out)))
        return result
    control_standing = suite.publish_standing(control)
    if control_standing is None:
        result.unknown("the control daemon published no standing at %s"
                       % suite.footprint_path(control))
        return result
    if control_standing.get("level") != "critical":
        result.bad(
            "a daemon under a ONE-BYTE budget publishes rung %r, so the arms above prove "
            "nothing: a build that had stopped grading its budget at all would pass them: %s"
            % (control_standing.get("level"), json.dumps(control_standing))
        )
    else:
        result.ok("the control, at a one-byte budget, publishes critical")
    control_record = suite.read_record(control)
    if control_record is not None and not reason_names_the_budget(control_record.get("reason")):
        result.bad("the control's refusal blames the wrong constraint: %s"
                   % json.dumps(control_record))
    return result


CHECKS = [("0", check_0), ("1", check_1), ("2", check_2), ("3", check_3),
          ("4", check_4), ("5", check_5), ("6", check_6), ("7", check_7),
          ("8", check_8), ("9", check_9), ("10", check_10), ("11", check_11)]


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

    idle_cases = [
        # The measured sentence, verbatim. This grader exists to recognize it.
        (True, "the kin daemon at http://127.0.0.1:39767 stopped answering while the lsp "
               "sweep status request was in flight; it exits after its idle window, so "
               "re-run the command and kin will start a fresh one"),
        # The fixed sentence, which names the window only to say it was not the
        # cause and offers no re-run. A grader that matched "idle window" alone
        # would call this the defect and stay red on the fix forever.
        (False, "the kin daemon at http://127.0.0.1:39767 stopped answering while the lsp "
                "sweep status request was in flight, and it did not exit its idle window: "
                "The daemon for this store was killed by the memory limit 1 time(s)"),
        (False, "daemon graph command failed: connection refused"),
        (False, ""),
        (False, None),
    ]
    for want, text in idle_cases:
        got = offers_the_idle_window(text)
        if got != want:
            failures.append("offers_the_idle_window(%r) = %s, wanted %s" % (text, got, want))

    enrichment_cases = [
        (True, "Durable semantic enrichment: present (1058 entities, 2016 relations, 6731 "
               "changes at authority generation 1, workspace generation 1; completion not "
               "attested, and a daemon serving this store was killed)"),
        # The measured line, which is the one this grader must reject.
        (False, "Durable semantic enrichment: present (1058 entities, 2016 relations, 6731 "
                "changes at authority generation 1, workspace generation 1; completion not "
                "attested)"),
        # A line that dropped the caveat is not a fix either: the counts are
        # still unattested, and a reader told only about a kill loses that.
        (False, "Durable semantic enrichment: present (1058 entities; a daemon serving this "
                "store was killed)"),
        (False, ""),
        (False, None),
    ]
    for want, line in enrichment_cases:
        got = enrichment_names_a_kill(line)
        if got != want:
            failures.append("enrichment_names_a_kill(%r) = %s, wanted %s" % (line, got, want))

    kill_row_cases = [
        (True, {"status": "degraded",
                "detail": "the daemon for this store was killed 1 time(s) since 04:20Z"}),
        # The hole a "not healthy" test leaves. Outside a Kin repository the row
        # reads unsupported, which is not healthy either, so a check written the
        # negative way passes on a probe that never found a store.
        (False, {"status": "unsupported",
                 "detail": "not in a Kin repository, so there is no store whose daemons "
                           "could have been killed"}),
        (False, {"status": "healthy",
                 "detail": "no daemon serving this store has been killed"}),
        # Degraded for some other reason is not this report.
        (False, {"status": "degraded", "detail": "the sweep circuit is open"}),
        (False, None),
    ]
    for want, row in kill_row_cases:
        got = row_reports_a_kill(row)
        if got != want:
            failures.append("row_reports_a_kill(%r) = %s, wanted %s" % (row, got, want))

    warning_cases = [
        ("Refs: 1\n⚠ The daemon for this store was killed 1 time(s). To recover: ...\nX: 2",
         "⚠ The daemon for this store was killed 1 time(s). To recover: ..."),
        ("  ⚠ a daemon serving this store was killed", "  ⚠ a daemon serving this store was killed"),
        # A warning about something else is not this line, and picking it would
        # grade the remedy of an unrelated row.
        ("⚠ reconcile loop degraded", None),
        # The counts line names a kill but is not the warning.
        ("Durable semantic enrichment: present (1; completion not attested, and a daemon "
         "serving this store was killed)", None),
        ("", None),
        (None, None),
    ]
    for text, exact in warning_cases:
        got = enrichment_warning(text)
        if got != exact:
            failures.append("enrichment_warning(%r) = %r, wanted %r" % (text, got, exact))

    # The line extractor must find the durable line and only that line.
    line_cases = [
        ("Kin repository-v6 status\nDurable semantic enrichment: present (1)\nRefs: 1",
         "Durable semantic enrichment: present (1)"),
        # The live line names enrichment too, and picking it would grade the
        # wrong sentence.
        ("Live graph enrichment: see `kin graph status`", None),
        ("", None),
        (None, None),
    ]
    for text, exact in line_cases:
        got = enrichment_line(text)
        if got != exact:
            failures.append("enrichment_line(%r) = %r, wanted %r" % (text, got, exact))

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
    # FIR-2653. The two figures the footprint checks decide on, each paired with
    # the reading that must produce the opposite verdict. The pre-fix build's
    # own numbers are in here as cases, so a grader that cannot see them fails
    # in seconds rather than passing a build that publishes 25.3 GiB.
    proportional_cases = [
        # own well under both: a proportional reading.
        (True, (700 * 1024 * 1024, 720 * 1024 * 1024, 980 * 1024 * 1024)),
        # own EQUAL to the resident set: the pre-fix reading exactly.
        (False, (980 * 1024 * 1024, 720 * 1024 * 1024, 980 * 1024 * 1024)),
        # own above the resident set: worse still.
        (False, (1200 * 1024 * 1024, 720 * 1024 * 1024, 980 * 1024 * 1024)),
        # under the resident set but far above PSS: a partial fix the first
        # comparison alone would pass.
        (False, (900 * 1024 * 1024, 300 * 1024 * 1024, 980 * 1024 * 1024)),
        # just inside the drift allowance, which must still pass.
        (True, (int(300 * 1024 * 1024 * 1.2), 300 * 1024 * 1024, 980 * 1024 * 1024)),
        # an unread figure is not a passing one.
        (False, (None, 720 * 1024 * 1024, 980 * 1024 * 1024)),
        (False, (0, 720 * 1024 * 1024, 980 * 1024 * 1024)),
    ]
    for want, (own, pss, rss) in proportional_cases:
        if reading_is_proportional(own, pss, rss) != want:
            failures.append("reading_is_proportional(%s, %s, %s) != %s" % (own, pss, rss, want))

    charge_cases = [
        # the measured healthy shape: 754 MB across a tree in a container
        # charged 2.15 GiB under a 12 GiB cap.
        (True, (754 * 1024 * 1024, 2313310208, 12884901888)),
        # the measured defect: 25.3 GiB published against the same container.
        (False, (int(25.3 * 1024 * 1024 * 1024), 2313310208, 12884901888)),
        # and the greenfield one, 14.6 GiB against a container that peaked at
        # 2.15 GiB, which is under the cap and still impossible.
        (False, (int(14.6 * 1024 * 1024 * 1024), 2313310208, 12884901888)),
        # a build whose clamp read the CAP rather than the charge: inside the
        # cap, above what the kernel is charged, and it must still fail.
        (False, (11 * 1024 * 1024 * 1024, 2313310208, 12884901888)),
        # equal to the charge is inside it.
        (True, (2313310208, 2313310208, 12884901888)),
        # an unreadable charge is not a passing comparison.
        (False, (754 * 1024 * 1024, None, 12884901888)),
    ]
    for want, (total, charged, cap) in charge_cases:
        if total_fits_the_kernel_charge(total, charged, cap) != want:
            failures.append("total_fits_the_kernel_charge(%s, %s, %s) != %s"
                            % (total, charged, cap, want))

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
             + len(memory_cases) + len(idle_cases) + len(enrichment_cases)
             + len(kill_row_cases) + len(warning_cases) + len(line_cases)
             + len(tail_cases) + len(grade_cases)
             + len(proportional_cases) + len(charge_cases))
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
    parser.add_argument("--only", action="append", default=None,
                        help="run only these check ids (repeatable)")
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
        selected = [(cid, fn) for cid, fn in CHECKS
                    if args.only is None or cid in args.only]
        if not selected:
            print("kin-memory-pressure-repro: --only %s matched no check" % args.only)
            return 3
        for check_id, check in selected:
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
