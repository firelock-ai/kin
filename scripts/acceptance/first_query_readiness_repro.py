#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

"""The first query after `kin init`, on a surface nothing else in the estate can see.

Every other acceptance suite here exports `KIN_DAEMON_AUTO_EMBED=0`, and for a
good reason: they run on shared CI and on a dev host with one Metal device, and
the fleet's own doctrine puts gates on the CPU so a concurrent run fails on its
diff rather than on host load. The consequence is exact. Nothing in the estate
runs the path where the embedding backfill exists, so nothing can observe what
happens on the other side of it.

This suite runs with auto-embed ON and grades two different defects that have
been wearing one ticket's name.

**Late.** A cold daemon answers `tools/list` and `initialize` long before it can
answer a query. `kin init` stops the daemon it started unless it borrowed a live
one, so the next MCP call spawns a cold daemon, and the first query waits behind
the repository-authority open and the spine build. Both finish AFTER the
endpoint publishes and after the still-starting window closes, so a user sees a
call that simply takes a long time with no line anywhere saying why. What is
owed is not speed, it is disclosure, and `check_postinit` grades exactly that.

**Thin.** This is the one that needs auto-embed on, and it is the reason this
suite exists rather than a unit test. The LSP cold sweep is ordered behind the
embedding backfill on first boot, so until the sweep publishes, cross-file edges
are missing and `find_references` answers with fewer upstreams than the
repository contains. It answers promptly, it answers successfully, and it
answers wrong. Nothing about a thin answer looks like a failure, which is why a
suite that grades elapsed time cannot see it and why `check_disclosed` grades
`total_upstream` instead.

A correction this suite is built on, because it decides what the checks read.
The embedding backlog does not make a query late: no query path takes
`embedding_work`. Its only blocking holders are the embed worker
(`daemon.rs:232`), a `#[cfg(test)]` helper (`daemon.rs:274`) and the explicit
`/embed` handler (`api.rs:6644`); everything else is a `try_lock` on a status
path. Embedding gates the SWEEP, and the sweep is what makes an answer thin.

    CHECK <id> <ticket> PASS|FAIL|UNREADABLE <detail>

Exit codes match the siblings: 0 when every check graded, 3 when the suite could
not start. The verdict belongs to `scripts/acceptance/gate.py`, which reads the
`--json` report rather than the exit code, because an exit status is one lever
with two settings and a check blocked on something outside the change under
review needs a third.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

TICKET = "FIR-1926"
PASS = "PASS"
FAIL = "FAIL"
UNREADABLE = "UNREADABLE"

# The disclosure the MCP server owes a caller whose daemon is still starting.
# Formatted by `starting_report` in crates/kin-mcp/src/startup_binding.rs; the
# grace that decides when it is emitted is TOOLS_CALL_STARTUP_BIND_GRACE in
# crates/kin-mcp/src/server.rs. Matched on the two invariant halves rather than
# the whole sentence, so a reworded middle does not silently stop matching while
# a deleted disclosure still does.
STILL_STARTING_OPENING = re.compile(
    r"cannot answer '(?P<tool>[^']+)' yet: the repo daemon is still starting"
)
STILL_STARTING_DETAIL = re.compile(r"\((?P<phase>[^;)]+); (?P<elapsed>\d+)s so far\)")
STILL_STARTING_ADVICE = "This is startup latency, not a failure"

# The daemon-side fault injection this suite consumes. Registered in
# crates/kin-core/src/env_registry.rs at Diagnostic sensitivity, off by default,
# captured at daemon start like every other behaviour lever. They exist because
# nothing in the acceptance estate can otherwise reach the states graded below,
# and they ship with this consumer so neither is a branch nothing exercises.
STARTUP_HOLD_ENV = "KIN_DAEMON_TEST_STARTUP_HOLD_SECS"
HOLD_SWEEP_ENV = "KIN_DAEMON_TEST_HOLD_ENRICHMENT_SWEEP"
# Comfortably past TOOLS_CALL_STARTUP_BIND_GRACE (10s), and comfortably inside
# FIRST_QUERY_BOUND_SECONDS, so the disclosure is reached and the run is short.
STARTUP_HOLD_SECONDS = 20

# How long the first query may take before silence stops being defensible. The
# disclosure is what makes any wait acceptable, so this bounds the case where
# NEITHER an answer nor a disclosure arrives.
FIRST_QUERY_BOUND_SECONDS = 120

# This suite deliberately asserts NO expected upstream count.
#
# It used to, as a thin-answer check, and that check could not fail. Three
# fixtures were tried against a provably-refused enrichment sweep and all three
# answered completely: Python with the sweep held returned every reference while
# the refusal line appeared twice in the fixture's own daemon.log against a
# control of 91 lines, and JavaScript returned total_upstream=2 held and unheld
# alike. Kin's own parser resolves simple cross-file references without
# enrichment, so a synthetic fixture cannot observe a thin first answer at all;
# that needs a reference class only enrichment produces, which on the evidence
# means a real corpus. Tracked separately rather than shipped as a check that
# passes for the wrong reason. The count is still REPORTED below, because a
# number in a detail line is evidence; it is simply never asserted on.


ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def strip_ansi(text):
    return ANSI.sub("", text or "")


def tail(text, limit=400):
    text = strip_ansi(text or "").strip()
    return text if len(text) <= limit else "..." + text[-limit:]


# ------------------------------------------------------------------- graders
#
# Pure, so `--self-test` can falsify each one without a daemon, a repository or
# a binary. Every grader below is called from `self_test` with an input that
# must pass and an input that must fail.


def reads_as_still_starting(text):
    """Is this the startup disclosure rather than an answer or an error?

    Requires the opening AND the advice line. The opening alone would match a
    log line quoting it, and the advice alone would match a doc comment; a
    caller has to see both to know it should retry rather than remediate.
    """
    if not text:
        return False
    return bool(STILL_STARTING_OPENING.search(text)) and STILL_STARTING_ADVICE in text


def disclosure_names_phase_and_elapsed(text):
    """Return (phase, elapsed_seconds) from the disclosure, or None.

    A disclosure that says only "still starting" is not the contract. The
    contract is that it names WHICH phase and HOW LONG, because those are the
    two facts that tell a waiting user this is progress rather than a hang.
    """
    if not reads_as_still_starting(text):
        return None
    found = STILL_STARTING_DETAIL.search(text)
    if not found:
        return None
    phase = found.group("phase").strip()
    if not phase:
        return None
    return (phase, int(found.group("elapsed")))


def upstream_total(payload):
    """The upstream count a find_references payload reports, or None.

    None is not zero. A payload that does not carry the key at all cannot be
    graded, and reporting it as zero would turn an unreadable answer into a
    confident finding of thinness.
    """
    if not isinstance(payload, dict):
        return None
    total = payload.get("total_upstream")
    if isinstance(total, bool) or not isinstance(total, int):
        return None
    return total


def focal_entity_resolved(payload):
    """Did the query resolve to an entity at all?

    An unresolved symbol and a symbol with no references are different facts,
    and only the second is thinness. Without this, a resolution failure reports
    as `total_upstream=0` and the suite files a confident finding of thinness
    against a query that never named anything.
    """
    if not isinstance(payload, dict):
        return False
    focal = payload.get("focal_entity")
    return isinstance(focal, dict) and bool(focal.get("id"))


# ------------------------------------------------------------------- results


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
        # Every passing assertion, not the last. A line naming only the hot
        # control would read as a pass for a suite that never probed the cold
        # first query it exists for.
        graded = [a["detail"] for a in self.asserts if a["status"] == PASS]
        return "; ".join(graded) if graded else "no assertion was reached"


class ProbeError(RuntimeError):
    """The probe could not produce a reading. UNREADABLE, never FAIL."""


# ------------------------------------------------------------------- fixture

# One definition, imported and called from two other modules.
#
# JavaScript on purpose, and this is the whole reason the thin arm can fail.
# The first version of this fixture was Python, and kin's own parser resolved
# every reference in it without the LSP sweep, so holding the sweep changed
# nothing and `disclosed` passed with a complete answer while the sweep was
# provably refused. The brownfield suite records why: on JavaScript, import
# references resolve 0 of 305 without enrichment. So a JavaScript import is a
# reference class that EXISTS only once the cross-file sweep publishes, which
# is exactly the state the thin arm grades.
#
# Small on purpose otherwise: this suite grades a readiness contract and an
# edge count, not ingestion.
FIXTURE = {
    "core.js": "export function widen(value) {\n  return value * 2;\n}\n",
    "alpha.js": "import { widen } from './core.js';\n\nexport function runAlpha(x) {\n  return widen(x) + 1;\n}\n",
    "beta.js": "import { widen } from './core.js';\n\nexport function runBeta(x) {\n  return widen(x) - 1;\n}\n",
}


class Suite(object):
    def __init__(self, kin, workdir, daemon=None, verbose=False):
        self.kin = kin
        self.workdir = workdir
        self.daemon = daemon
        self.verbose = verbose
        self.repo = os.path.join(workdir, "repo")
        self.env = dict(os.environ)
        self.env["KIN_HOME"] = os.path.join(workdir, "kin-home")
        self.env["HOME"] = os.path.join(workdir, "home")
        # The whole point of this suite. Every sibling sets this to 0, which is
        # why nothing in the estate can observe the sweep queued behind the
        # backfill. Set explicitly rather than left to the default, so a change
        # in the default cannot silently turn this suite into another blind one.
        self.env["KIN_DAEMON_AUTO_EMBED"] = "1"
        # On the CPU, not the one Metal device. A gate that embeds on the shared
        # GPU fails on host load rather than on its diff, and the fleet holds
        # the gpu lock for anything that wants the device.
        self.env.setdefault("KIN_EMBED_BACKEND", "cpu")
        # Arm the startup hold, and this is the line that makes the suite worth
        # running. A three-file fixture opens in under a second, so without it
        # the first query always answers inside the bound, `postinit` always
        # takes its trivial branch, and the disclosure contract this suite
        # exists to grade is never reached. Measured: the first run of this
        # suite passed 2 of 2 with zero occurrences of the disclosure in its
        # own log. Held longer than TOOLS_CALL_STARTUP_BIND_GRACE, which is 10s
        # in crates/kin-mcp/src/server.rs, or the call settles before the grace
        # matters and nothing changes. A caller-set value wins, so a
        # falsification run can disarm it without editing this file.
        self.env.setdefault(STARTUP_HOLD_ENV, str(STARTUP_HOLD_SECONDS))
        # KIN_DAEMON_TEST_HOLD_ENRICHMENT_SWEEP is deliberately NOT set here.
        # Armed, it creates the thin-answer state, which is what `disclosed`
        # must go red on; the default run has to be the healthy one or the
        # control grades nothing.
        if daemon:
            self.env["KIN_DAEMON_BIN"] = daemon
        for path in (self.env["KIN_HOME"], self.env["HOME"], self.repo):
            os.makedirs(path, exist_ok=True)
        self._ready = None
        self._setup_error = None

    def run(self, args, cwd=None, timeout=900):
        proc = subprocess.run(
            args,
            cwd=cwd or self.repo,
            env=self.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            text=True,
        )
        if self.verbose:
            sys.stderr.write("$ %s\n%s\n" % (" ".join(args), tail(proc.stdout, 2000)))
        return proc.returncode, strip_ansi(proc.stdout)

    def git(self, args):
        base = ["git", "-c", "user.email=first-query@example.invalid",
                "-c", "user.name=kin-first-query-repro",
                "-c", "commit.gpgsign=false",
                "-c", "core.fsmonitor=false"]
        return self.run(base + args)

    def build_fixture(self):
        for name, body in FIXTURE.items():
            with open(os.path.join(self.repo, name), "w") as handle:
                handle.write(body)
        rc, out = self.git(["init", "--quiet", "--initial-branch=main"])
        if rc != 0:
            raise ProbeError("git init failed: %s" % tail(out))
        rc, out = self.git(["add", "-A"])
        if rc != 0:
            raise ProbeError("git add failed: %s" % tail(out))
        rc, out = self.git(["commit", "--quiet", "-m", "fixture"])
        if rc != 0:
            raise ProbeError("git commit failed: %s" % tail(out))

    def init(self):
        """`kin init`, which stops the daemon it started unless it borrowed one.

        That is what makes the next MCP call spawn a cold daemon, which is the
        state this whole suite is about. If a future `kin init` starts leaving a
        live daemon behind, `check_postinit` will pass trivially, so the daemon
        state is reported in the detail line rather than assumed.
        """
        rc, out = self.run([self.kin, "init"])
        if rc != 0:
            raise ProbeError("kin init exited %d: %s" % (rc, tail(out)))
        return out

    def mcp(self, tool, args, timeout=FIRST_QUERY_BOUND_SECONDS):
        """One tools/call, returning the raw text as well as any JSON.

        Deliberately unlike the sibling drivers, which raise when the payload is
        not JSON. The still-starting disclosure is plain prose, and a driver
        that treats it as a probe error could never grade the case this suite
        exists for. The real payload lives inside content[0].text; reading
        fields off the outer result object returns empty for every one of them.
        """
        env = dict(self.env)
        env["KIN_MCP_REPO"] = self.repo
        proc = subprocess.Popen(
            [self.kin, "mcp", "start", "--repo", self.repo],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=self.repo,
            env=env,
            text=True,
        )
        msgs = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                        "clientInfo": {"name": "kin-first-query-repro",
                                       "version": "1"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
             "params": {"name": tool, "arguments": args}},
        ]
        payload = "".join(json.dumps(m) + "\n" for m in msgs)
        began = time.time()
        try:
            out, err = proc.communicate(payload, timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            # Not an error. Silence past the bound is the defect this suite
            # grades, so it is a reading like any other.
            return {"raw": None, "json": None, "elapsed": time.time() - began,
                    "timed_out": True, "stderr": ""}
        elapsed = time.time() - began
        resp = None
        for line in out.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            if obj.get("id") == 2:
                resp = obj
        if resp is None:
            raise ProbeError("no id=2 frame for %s (stderr tail: %s)"
                             % (tool, tail(err, 200).replace("\n", " ")))
        if "error" in resp:
            raise ProbeError("%s returned a protocol error: %s"
                             % (tool, json.dumps(resp["error"])[:200]))
        content = (resp.get("result") or {}).get("content") or []
        if not content or "text" not in content[0]:
            raise ProbeError("%s returned no text content" % tool)
        text = content[0]["text"]
        try:
            body = json.loads(text)
        except ValueError:
            body = None
        return {"raw": text, "json": body if isinstance(body, dict) else None,
                "elapsed": elapsed, "timed_out": False,
                "stderr": tail(err, 200)}

    def ready(self):
        """Build and init once, for whichever check runs first.

        Setup used to live inside `check_postinit`, which made `check_disclosed`
        depend on a sibling having run and having succeeded. Reorder the CHECKS
        list, or let init fail, and the control would grade a repository that
        was never built while reporting it as a control-query problem. Both
        checks call this, it runs once, and a setup failure raises the same
        error into both so neither can report a misleading cause.
        """
        if self._ready is None:
            try:
                self.build_fixture()
                self.init()
                self._ready = True
            except Exception as error:  # noqa: BLE001 - any setup failure is UNREADABLE
                # Deliberately wider than ProbeError. `kin init` can fail with a
                # raw OSError before it ever produces output, and catching only
                # ProbeError let that escape, skip the memo, and run setup a
                # second time for the second check, so both reported a raw
                # exception instead of the one honest cause.
                self._setup_error = "%s: %s" % (type(error).__name__, error)
                self._ready = False
        if not self._ready:
            raise ProbeError("the fixture never reached a queryable state, so "
                             "nothing about readiness can be read: %s"
                             % self._setup_error)

    def find_references(self, timeout=FIRST_QUERY_BOUND_SECONDS):
        # `query`, not a symbol/file pair. Read off the handler and confirmed
        # against how brownfield_repro.py calls the same tool; a guessed
        # argument name returns a protocol error, which this suite would report
        # as UNREADABLE and which would look like a daemon problem.
        return self.mcp("find_references", {"query": "widen"}, timeout=timeout)


# -------------------------------------------------------------------- checks


def check_postinit(suite):
    """The first query after `kin init` answers, or says why it cannot.

    Grades the readiness contract, not speed. A cold daemon is allowed to take
    minutes; what it is not allowed to do is take them in silence. So this
    passes on an answer inside the bound, and it passes on the still-starting
    disclosure provided the disclosure names the phase and the elapsed seconds,
    because those two facts are what separate progress from a hang.
    """
    result = Result("postinit", "the first query after init answers or discloses")
    suite.ready()

    probe = suite.find_references()
    if probe["timed_out"]:
        result.bad(
            "the first query neither answered nor disclosed within %ds; a user "
            "sees a call that hangs with nothing saying why"
            % FIRST_QUERY_BOUND_SECONDS)
        return result

    disclosure = disclosure_names_phase_and_elapsed(probe["raw"])
    if disclosure:
        phase, elapsed = disclosure
        result.ok("the first query disclosed rather than hung: phase %r, %ds "
                  "elapsed, returned after %.1fs" % (phase, elapsed, probe["elapsed"]))
        return result

    if reads_as_still_starting(probe["raw"]):
        result.bad(
            "the still-starting answer arrived but named no phase and no "
            "elapsed seconds, so it cannot tell a waiting user this is "
            "progress: %s" % tail(probe["raw"], 240))
        return result

    if probe["json"] is None:
        result.unknown("the first query returned neither JSON nor the "
                       "still-starting disclosure: %s" % tail(probe["raw"], 240))
        return result

    armed = suite.env.get(STARTUP_HOLD_ENV, "0")
    result.ok("the first query answered in %.1fs with total_upstream=%s "
              "(no disclosure was owed; %s=%s)"
              % (probe["elapsed"], upstream_total(probe["json"]),
                 STARTUP_HOLD_ENV, armed))
    return result


def check_disclosed(suite):
    """A hot daemon answers, resolves, and says nothing about starting.

    The control for `check_postinit`, and it grades two things that can fail. A
    daemon still emitting the still-starting text here means readiness never
    settled, so the disclosure the first query got was a permanent state rather
    than a transient one. And a query that resolves no focal entity means the
    fixture has nothing to find, which would let `postinit` pass on an empty
    repository having proven nothing.

    It does NOT assert an upstream count. See the note above the fixture: that
    assertion could not fail, and shipping it would have been a check named for
    a defect it cannot observe.
    """
    result = Result("disclosed", "a hot daemon answers completely and says nothing about starting")
    suite.ready()

    probe = None
    deadline = time.time() + FIRST_QUERY_BOUND_SECONDS * 4
    while time.time() < deadline:
        probe = suite.find_references()
        if probe["timed_out"]:
            continue
        if not reads_as_still_starting(probe["raw"]):
            break
        time.sleep(5)

    if probe is None or probe["timed_out"]:
        result.unknown("the daemon never answered a control query, so nothing "
                       "about completeness can be read from this run")
        return result

    if reads_as_still_starting(probe["raw"]):
        result.bad("the daemon was still disclosing a pending start after %ds; "
                   "readiness never settled, so a first query is not merely slow"
                   % (FIRST_QUERY_BOUND_SECONDS * 4))
        return result

    if probe["json"] is None:
        result.unknown("the control query returned no JSON payload: %s"
                       % tail(probe["raw"], 240))
        return result

    if not focal_entity_resolved(probe["json"]):
        result.unknown("the control query resolved no focal entity, so nothing "
                       "about completeness can be read: an unresolved symbol "
                       "and a symbol with no references are different facts and "
                       "only the second is thinness")
        return result

    total = upstream_total(probe["json"])
    if total is None:
        result.unknown("the control payload carried no total_upstream key, so "
                       "completeness cannot be graded either way")
        return result

    result.ok("a hot daemon answered in %.1fs with a resolved focal entity, "
              "total_upstream=%d, and no still-starting text"
              % (probe["elapsed"], total))
    return result


CHECKS = [check_postinit, check_disclosed]


# ----------------------------------------------------------------- self-test


def self_test():
    """Falsify every grader. A grader nobody has watched fail proves nothing."""

    real = (
        "kin-mcp cannot answer 'find_references' yet: the repo daemon is still "
        "starting (phase: opening durable state; 42s so far). The MCP transport "
        "is up and `initialize` and `tools/list` are served; retry this call "
        "once the daemon is ready. Large repositories can take minutes on a "
        "fully cold start. This is startup latency, not a failure: do not "
        "restart the MCP server or re-run `kin init`."
    )
    failures = []

    def want(label, condition):
        if not condition:
            failures.append(label)

    want("the real disclosure is recognised", reads_as_still_starting(real))
    want("a real answer is not mistaken for the disclosure",
         not reads_as_still_starting('{"total_upstream": 2}'))
    want("an empty response is not mistaken for the disclosure",
         not reads_as_still_starting(""))
    # The opening alone is a log line quoting it; the advice alone is a doc
    # comment. Neither is a disclosure a caller can act on.
    want("the opening without the advice is refused",
         not reads_as_still_starting(real.split("The MCP transport")[0]))
    want("the advice without the opening is refused",
         not reads_as_still_starting(STILL_STARTING_ADVICE))

    want("phase and elapsed are read from the real disclosure",
         disclosure_names_phase_and_elapsed(real)
         == ("phase: opening durable state", 42))
    # This is the mutation the ticket names: the disclosure survives but stops
    # carrying what makes it useful.
    want("a disclosure naming no phase or elapsed is refused",
         disclosure_names_phase_and_elapsed(
             real.replace("(phase: opening durable state; 42s so far)", "")) is None)
    want("a disclosure with an empty phase is refused",
         disclosure_names_phase_and_elapsed(
             real.replace("phase: opening durable state", "")) is None)

    want("a payload with no count is unreadable, not zero",
         upstream_total({"upstream": []}) is None)
    want("a resolved focal entity is recognised",
         focal_entity_resolved({"focal_entity": {"id": "e1"}, "total_upstream": 2}))
    want("an unresolved query is not mistaken for a thin answer",
         not focal_entity_resolved({"focal_entity": None, "total_upstream": 0}))
    want("a focal entity with no id is unresolved",
         not focal_entity_resolved({"focal_entity": {}, "total_upstream": 0}))
    want("a payload with no focal entity at all is unresolved",
         not focal_entity_resolved({"total_upstream": 0}))
    want("a boolean is not a count", upstream_total({"total_upstream": True}) is None)
    want("a non-object payload is unreadable", upstream_total("2") is None)

    # The Result grader itself: a check with no assertion must not read as a
    # pass, and one FAIL must outrank any number of passes.
    empty = Result("x", "x")
    want("a check that graded nothing is UNREADABLE", empty.status == UNREADABLE)
    mixed = Result("x", "x")
    mixed.ok("fine")
    mixed.bad("not fine")
    want("one FAIL outranks a pass", mixed.status == FAIL)
    unreadable = Result("x", "x")
    unreadable.ok("fine")
    unreadable.unknown("could not read")
    want("UNREADABLE outranks a pass", unreadable.status == UNREADABLE)

    if failures:
        print("kin-first-query-readiness-repro: SELF-TEST FAILED")
        for label in failures:
            print("  - %s" % label)
        return 1
    print("kin-first-query-readiness-repro: self-test passed, "
          "every grader refused the input it must refuse")
    return 0


# ---------------------------------------------------------------------- main


def main(argv):
    parser = argparse.ArgumentParser(
        description=__doc__,
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
        print("kin-first-query-readiness-repro: no kin binary. Pass --kin or set KIN_BIN.")
        return 3
    # Absolute, because every command below runs with cwd inside a fixture in a
    # temp directory. A relative --daemon, which is what the CI step passes,
    # resolves against that fixture rather than the checkout, and kin then
    # refuses with "explicit KIN_DAEMON_BIN does not exist".
    kin = os.path.abspath(os.path.expanduser(args.kin))
    if not os.path.isfile(kin) or not os.access(kin, os.X_OK):
        print("kin-first-query-readiness-repro: %s is not an executable file" % kin)
        return 3
    daemon = args.daemon and os.path.abspath(os.path.expanduser(args.daemon))
    if not daemon:
        beside = os.path.join(os.path.dirname(kin), "kin-daemon")
        daemon = beside if os.path.isfile(beside) else None

    workdir = tempfile.mkdtemp(prefix="kin-first-query-readiness-repro-")
    try:
        suite = Suite(kin, workdir, daemon=daemon, verbose=args.verbose)
        results = []
        for check in CHECKS:
            try:
                results.append(check(suite))
            except ProbeError as error:
                result = Result(getattr(check, "__name__", "check"), "probe could not read")
                result.unknown(str(error))
                results.append(result)
            except Exception as error:  # noqa: BLE001 - a crashed probe is UNREADABLE
                result = Result(getattr(check, "__name__", "check"), "probe crashed")
                result.unknown("%s: %s" % (type(error).__name__, error))
                results.append(result)
        for result in results:
            print("CHECK %s %s %s %s" % (result.id, TICKET, result.status, result.detail))
        failed = [r for r in results if r.status == FAIL]
        unreadable = [r for r in results if r.status == UNREADABLE]
        print("kin-first-query-readiness-repro: %d checks, %d pass, %d FAIL, %d UNREADABLE"
              % (len(results), len(results) - len(failed) - len(unreadable),
                 len(failed), len(unreadable)))
        if args.json_path:
            # The gate reads this rather than the exit code, because an exit
            # status is one lever with two settings and a check blocked on
            # something outside the change under review needs a third.
            payload = {
                "suite": "first_query_readiness_repro",
                "ticket": TICKET,
                "label": args.label,
                "kin": kin,
                "results": [
                    {"id": r.id, "ticket": TICKET, "title": r.title,
                     "status": r.status, "detail": r.detail, "asserts": r.asserts}
                    for r in results
                ],
            }
            directory = os.path.dirname(os.path.abspath(args.json_path))
            if directory:
                os.makedirs(directory, exist_ok=True)
            with open(args.json_path, "w") as handle:
                json.dump(payload, handle, indent=2)
                handle.write("\n")
        return 0
    finally:
        if args.keep:
            print("kin-first-query-readiness-repro: fixtures kept at %s" % workdir)
        else:
            shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
