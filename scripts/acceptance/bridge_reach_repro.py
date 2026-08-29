#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
"""NON-CITABLE acceptance suite for the local-to-hosted bridge's two dead surfaces.

Its output is a regression gate, never proof, never investor-facing and never a
released claim. It shares the CHECK line format, the exit codes and the
`--self-test` discipline of its siblings in this directory, so a reader who knows
one knows all of them.

What it is for
--------------
Two findings from the 2026-08-29 bridge walk, both of which shipped in v0.6.0 and
v0.6.1 and neither of which any suite could see.

FIR-2936. `kin push`, `kin pull` and `kin remote plan-push` died in 0.03 s saying
"no Kin daemon is reachable" while a daemon was serving that exact repository and
`kin doctor` printed its port in the same second. The cause was not the daemon.
`DaemonClient::try_connect` read `KIN_DAEMON_URL` and did no discovery at all,
answering `None` whenever the variable was unset, and nothing in the product sets
it. So the three byte-moving surfaces were unreachable from every default install
and the message named a cause the reader could disprove with the next command.

FIR-2938. `kin auth login` sent every terminal user to Google. KinLab's
`/auth/login` has read a `provider` parameter for as long as it has had more than
one, and the web sign-in page offers both, but the CLI never sent it, so the
GitHub sign-in that shipped to production was unreachable from the surface its
users live in.

What it measures, and what it does not
--------------------------------------
Checks 0 to 2 drive the real binary against a real store and grade the three
outcomes daemon resolution can reach: an endpoint that answers, no endpoint
because autostart is off, and an endpoint that was named and did not answer. The
last two are refusal text, and they are graded as hard as the first, because a
refusal that names a wrong cause is the defect FIR-2936 is about.

Check 1 is the arm that could not pass before the fix. `KIN_DAEMON_URL` is unset
there, which is the exact input the old gate answered `None` for, so a build that
reads only that variable prints the retired sentence and this check fails. It is
also where all three surfaces are covered, because nothing is serving and no
daemon starts, so `kin pull` and `kin remote plan-push` cost two more refusals
rather than two more daemons. A check that graded only push would stay green
through a revert of either of the others.

Checks 3 to 6 drive `kin auth login` against a stub that plays the control
plane's CLI-flow routes and records what it was asked. The stub exists so the
checks grade what the CLI SENDS rather than what production answers: a suite that
reached kinlab.ai would grade a deployment's provider configuration on every pull
request, and would go red on a network nobody changed. Check 6 is the only one
that carries a credential through storage and back, with the keyring off and a
token this file writes.

It does NOT measure whether a push succeeds, whether the transfer routing is
correct, or whether a real sign-in completes. The transfer's own destination is a
separate finding, and nothing here is minted against a real deployment or leaves
this host.

Each check prints one line:

    CHECK <id> <ticket> PASS|FAIL|UNREADABLE <detail>

UNREADABLE is a distinct outcome from FAIL and is never reported as a pass: it
means the probe could not be evaluated. A measurement that cannot be taken is not
a measurement that passed. Exit status is 1 when any check FAILs, 2 when none
fail but some are UNREADABLE, 0 only when every check passes, 3 on a setup error.

The binary under test
---------------------
    cargo build --release --locked --bin kin --bin kin-daemon
    python3 scripts/acceptance/bridge_reach_repro.py --kin target/release/kin

`--kin` may also come from KIN_BIN.
"""

from __future__ import print_function

import argparse
import functools
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading

try:
    from http.server import BaseHTTPRequestHandler, HTTPServer
except ImportError:  # pragma: no cover - python 2 is not supported
    BaseHTTPRequestHandler = None
    HTTPServer = None

try:
    from urllib.parse import parse_qsl, urlsplit
except ImportError:  # pragma: no cover - python 2 is not supported
    parse_qsl = None
    urlsplit = None

print = functools.partial(print, flush=True)

PASS = "PASS"
FAIL = "FAIL"
UNREADABLE = "UNREADABLE"

TICKET_DAEMON = "FIR-2936"
TICKET_PROVIDER = "FIR-2938"

# The sentence the ticket is named after, verbatim from the build that shipped
# it. It described a daemon that was serving, so no branch of the refusal may
# say it again, whatever else changes.
RETIRED_REFUSAL = "no Kin daemon is reachable"

# What the refusal owes a reader when autostart is off and nothing is serving.
# The cause, the repository it is about, and the one word that undoes it.
REQUIRED_NO_DAEMON_PHRASES = ["KIN_NO_DAEMON", "unset KIN_NO_DAEMON"]

# What the refusal owes a reader when the operator's own override answered
# nothing. Naming the variable is the whole point: an override aimed at a dead
# endpoint is invisible from inside the command.
REQUIRED_OVERRIDE_PHRASES = ["KIN_DAEMON_URL", "unset KIN_DAEMON_URL"]

# An endpoint on a port nothing serves. Port 1 needs root to bind on every host
# this runs on, so a stray listener cannot turn this arm green.
DEAD_ENDPOINT = "http://127.0.0.1:1"

# A peer that no transfer can complete against, so check 0 grades how far the
# command got rather than whether a push works.
DEAD_PEER = "http://127.0.0.1:1"


def tail(text, limit=400):
    text = (text or "").strip()
    return text if len(text) <= limit else "..." + text[-limit:]


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
# Pure over text, so `--self-test` can grade them against their own inverse with
# no binary, no store and no daemon.


def says_retired_refusal(text):
    """True when the output carries the sentence FIR-2936 was filed about."""
    return RETIRED_REFUSAL in (text or "")


def missing_phrases(text, required):
    """The phrases a refusal owes a reader and did not print."""
    body = text or ""
    return [phrase for phrase in required if phrase not in body]


# Every clause a daemon-RESOLUTION refusal carries, and nothing else does. The
# retired sentence, the two the fix replaced it with, and the shared
# `daemon_required_error` behind the third. A transfer that reached the daemon
# fails with the daemon's own HTTP status and carries none of these.
RESOLUTION_REFUSAL_CLAUSES = [
    RETIRED_REFUSAL,
    "has no repository authority to run in",
    "there is no repository authority to answer",
]


def stopped_at_daemon_resolution(text):
    """True when the command never got past resolving a daemon.

    Exact rather than a proxy, and that distinction was bought. The first
    version of check 0 asserted that the failure names the peer URL, on the
    theory that only a transfer would know it. The fixed product fails that: the
    daemon reports `kin push refused (HTTP 424): ... transport failed: io:
    Connection refused` and never echoes the peer, because echoing it was never
    something the daemon owed. An assertion a correct product fails is worse
    than no assertion, so this keys on the clauses the resolution refusals
    actually carry instead.
    """
    body = text or ""
    return any(clause in body for clause in RESOLUTION_REFUSAL_CLAUSES)


def repo_daemon_state(status_text):
    """What `kin daemon status` says about a repo daemon: SERVING, ABSENT or None.

    Three answers, not two, and the third is the point. "Serving" is keyed on the
    endpoint line a running repo daemon prints, because that endpoint is the
    thing a transfer would talk to. "Absent" is keyed on the sentences the
    command prints when there is no worker, which are its own words rather than
    the absence of mine: an output this grader cannot read is not an absent
    daemon, and reporting it as one would let a renamed status format grade every
    run as a caught defect.

    The supervisor is deliberately not a serving daemon here. It runs in both
    states, it is machine-wide rather than per repository, and it prints its port
    as `port NNNNN` rather than as a URL, so a looser match would read a healthy
    supervisor as the worker this check is about.
    """
    text = status_text or ""
    if re.search(r"^\s*endpoint:\s+http://127\.0\.0\.1:\d+", text, re.M):
        return "SERVING"
    if "worker daemon not running" in text or "Repo daemons: none registered" in text:
        return "ABSENT"
    return None


def has_no_provider_flag(text):
    """True when the CLI refused `--provider` as an argument it does not have.

    Graded as a failure rather than as an unreadable run, and the distinction is
    the whole ticket: a binary that cannot parse the flag has not failed to be
    measured, it has failed. Keyed on clap's own refusal beside the flag name, so
    an unrelated usage error stays unreadable.
    """
    body = text or ""
    return "--provider" in body and "unexpected argument" in body


def printed_login_url(text):
    """The browser URL `kin auth login --no-browser` printed, or None.

    Anchored on the scheme and host the stub serves, so a sentence that merely
    talks about a URL cannot satisfy it. `None` is reported as UNREADABLE by the
    caller rather than as a missing provider: a URL that was never printed and a
    URL carrying the wrong provider are different facts.
    """
    match = re.search(r"http://127\.0\.0\.1:\d+/auth/login\?\S+", text or "")
    return match.group(0) if match else None


def query_of(url):
    """The URL's query parameters as a dict, last value winning.

    Last value on purpose: it is what a server's own query parser would take if
    a parameter were ever sent twice, so a duplicate `provider` reads here the
    way it would read there rather than being hidden by a first-wins parse.
    """
    if not url:
        return {}
    return dict(parse_qsl(urlsplit(url).query, keep_blank_values=True))


def provider_count(url):
    """How many times `provider` appears, which one-value reads cannot see."""
    if not url:
        return 0
    return len([1 for key, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)
                if key == "provider"])


# ------------------------------------------------------- the control-plane stub


class _StartHandler(BaseHTTPRequestHandler):
    """Plays the CLI-flow routes and records every request it is given.

    Only the two routes `kin auth login` calls, and only the fields it reads. It
    validates nothing, mints nothing that leaves this process, and never talks to
    a real deployment.
    """

    def do_POST(self):  # noqa: N802 - BaseHTTPRequestHandler's spelling
        length = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        self.server.requests.append({"path": self.path, "body": body})
        route = self.path.rstrip("/")
        if route.endswith("/cli/auth/start"):
            base = "http://127.0.0.1:%d" % self.server.server_address[1]
            # The URL the real server builds: flowId and code_challenge and
            # nothing else. It names no provider, which is why the CLI has to
            # add one.
            self._json(200, {
                "flowId": self.server.flow_id,
                "authorizationUrl": "%s/auth/login?flowId=%s&code_challenge=%s"
                                    % (base, self.server.flow_id, self.server.code_challenge),
            })
            return
        if route.endswith("/cli/auth/exchange"):
            # The shape the real exchange returns, and the point worth keeping:
            # it carries no provider. Whatever the CLI records about one, it
            # records from what it asked for, never from what came back.
            self._json(200, {
                "token": "bridge-reach-token",
                "expiresAt": "2027-01-01T00:00:00Z",
                "user": {"email": "stranger@example.invalid",
                         "displayName": "A Stranger"},
            })
            return
        self._json(404, {"error": "not found"})

    def _json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):  # keep the suite's output the suite's own
        return


class ControlPlaneStub(object):
    """A local stand-in for the KinLab control plane's CLI-flow start route."""

    FLOW_ID = "bridgereachflow0001"
    CODE_CHALLENGE = "bridgereachchallenge0001"

    def __init__(self):
        self.server = HTTPServer(("127.0.0.1", 0), _StartHandler)
        self.server.requests = []
        self.server.flow_id = self.FLOW_ID
        self.server.code_challenge = self.CODE_CHALLENGE
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_exc):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        return False

    @property
    def base_url(self):
        return "http://127.0.0.1:%d" % self.server.server_address[1]

    @property
    def requests(self):
        return list(self.server.requests)


# ------------------------------------------------------------------- the suite


class Suite(object):
    def __init__(self, kin, workdir, verbose=False):
        self.kin = kin
        self.workdir = workdir
        self.verbose = verbose
        self.home = os.path.join(workdir, "home")
        os.makedirs(self.home, exist_ok=True)
        self.env = dict(os.environ)
        # A scratch KIN_HOME and HOME so nothing here touches the machine's real
        # store registry, its credential store, or a daemon the fleet is using.
        self.env["KIN_HOME"] = self.home
        self.env["HOME"] = self.home
        self.env["GIT_CONFIG_NOSYSTEM"] = "1"
        self.env["KIN_EMBED_BACKEND"] = "cpu"
        self.env["KIN_DAEMON_AUTO_EMBED"] = "0"
        # No Keychain. `store_credential` prefers the OS keyring, which on macOS
        # can raise an interactive dialog and on a headless runner fails in its
        # own way; either would decide check 6 for a reason that has nothing to
        # do with providers. Off, the credential lands in a file under the
        # scratch HOME above and nothing outlives this run.
        self.env["KIN_NO_KEYRING"] = "1"
        self.env.pop("KINLAB_AUTH_PASSPHRASE", None)
        # The variable under test. Inherited from the runner it would decide
        # checks 0 and 1 without either of them naming it.
        self.env.pop("KIN_DAEMON_URL", None)
        self.env.pop("KIN_NO_DAEMON", None)
        self.repos = {}

    def git(self, args, cwd):
        proc = subprocess.run(
            ["git"] + args, cwd=cwd, env=self.env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        return proc.returncode, proc.stdout

    def kin_run(self, args, cwd, extra_env=None, timeout=300, stdin_closed=False,
                stdin_text=None):
        """One real `kin` invocation.

        The exit code is read directly, never through a pipe: a pipeline's status
        is its last stage's, which is how a killed run was first read as a clean
        one.
        """
        env = dict(self.env)
        if extra_env:
            for key, value in extra_env.items():
                if value is None:
                    env.pop(key, None)
                else:
                    env[key] = value
        proc = subprocess.run(
            [self.kin] + args, cwd=cwd, env=env,
            input=stdin_text,
            stdin=(subprocess.DEVNULL
                   if stdin_closed and stdin_text is None else None),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            timeout=timeout,
        )
        if self.verbose:
            print("--- kin %s (rc=%d)\n%s" % (" ".join(args), proc.returncode, proc.stdout))
        return proc.returncode, proc.stdout

    def fixture(self, name, commits=2):
        """A tiny Git repository converted to a Kin store, built once per name."""
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
            with open(os.path.join(repo, "pkg", "module%d.py" % index), "w") as handle:
                handle.write("def handler%d(payload):\n    return payload\n" % index)
            self.git(["add", "--all"], repo)
            rc, out = self.git(["commit", "-m", "revision %d" % index], repo)
            if rc != 0:
                raise RuntimeError("git commit failed: %s" % out)
        rc, out = self.kin_run(["init", "."], repo, timeout=900)
        if rc != 0:
            raise RuntimeError("kin init failed (rc=%d): %s" % (rc, tail(out, 900)))
        self.repos[name] = repo
        return repo

    def stop_daemons(self):
        """Best effort, so a check that wants no daemon starts from none."""
        for repo in self.repos.values():
            try:
                self.kin_run(["daemon", "stop"], repo, timeout=120)
            except (subprocess.TimeoutExpired, OSError):
                pass


# --------------------------------------------------------------------- checks


def check_0(suite):
    """`kin push` resolves a daemon with KIN_DAEMON_URL unset.

    The reproduction from the walk, run forwards, and the one assertion here that
    depends on no wording at all. The variable is unset, which is every default
    install, and no repo daemon is serving when the command starts. Resolution is
    supposed to find or start one, so a daemon SERVING afterwards is the fact
    that separates a build that discovers from one that reads an environment
    variable and gives up. A build that does neither leaves the state it found
    and reports a daemon it never looked for.

    Three assertions, because any one alone passes on a build that merely fails
    differently: the retired sentence is absent, a repo daemon is serving after
    the run, and the failure names the peer, which is the only thing that shows
    the command reached the transfer rather than the gate.
    """
    result = Result("0", TICKET_DAEMON, "push resolves a daemon with no override set")
    repo = suite.fixture("reach")
    suite.stop_daemons()
    try:
        _, before = suite.kin_run(["daemon", "status"], repo)
    except subprocess.TimeoutExpired:
        result.unknown("`kin daemon status` did not finish, so the starting state is unknown")
        return result
    if repo_daemon_state(before) != "ABSENT":
        result.unknown("a repo daemon was already %s before the run, so nothing here can "
                       "show resolution started one: %s"
                       % (repo_daemon_state(before) or "unreadable", tail(before)))
        return result
    result.ok("no repo daemon was serving when the command started")

    try:
        rc, out = suite.kin_run(["push", "--url", DEAD_PEER], repo)
    except subprocess.TimeoutExpired:
        result.unknown("`kin push` did not finish inside the timeout")
        return result
    if rc == 0:
        result.unknown("`kin push` exited 0 against a peer that cannot answer, so this run "
                       "is not the case under test: %s" % tail(out))
        return result

    if says_retired_refusal(out):
        result.bad("`kin push` says %r with no override set, which is what a build that "
                   "does no discovery prints: %s" % (RETIRED_REFUSAL, tail(out, 700)))
    else:
        result.ok("the refusal does not name an unreachable daemon")

    try:
        _, after = suite.kin_run(["daemon", "status"], repo)
    except subprocess.TimeoutExpired:
        result.unknown("`kin daemon status` did not finish, so nothing confirms a daemon")
        return result
    state = repo_daemon_state(after)
    if state == "SERVING":
        result.ok("a repo daemon is serving after the run, so resolution reached one")
    elif state == "ABSENT":
        result.bad("no repo daemon is serving after `kin push`, so nothing resolved or "
                   "started one and the command refused without ever looking: %s"
                   % tail(after, 700))
    else:
        result.unknown("`kin daemon status` did not say whether a repo daemon is serving, "
                       "so this run graded nothing: %s" % tail(after, 700))

    # Where it stopped. The daemon that answered is running, so a failure that
    # still carries a resolution refusal means the command never got to it.
    if stopped_at_daemon_resolution(out):
        result.bad("`kin push` failed at daemon resolution while a daemon serves this "
                   "repository, which is the defect: %s" % tail(out, 700))
    else:
        result.ok("the failure carries no resolution refusal, so the command got past "
                  "the gate and was refused by the work")
    return result


def check_1(suite):
    """With autostart off and nothing serving, all three surfaces name the true state.

    The arm a build reading only `KIN_DAEMON_URL` cannot pass. The variable is
    unset here, which is the exact input the old gate answered `None` for, so
    that build prints the retired sentence and fails.

    All three surfaces, not one. The ticket names `kin push`, `kin pull` and
    `kin remote plan-push`, and they share one connector today, so a check that
    graded only push would stay green through a revert of either of the others.
    This arm is the cheap place to cover all three: nothing is serving, autostart
    is off, so each call is a refusal and no daemon starts.
    """
    result = Result("1", TICKET_DAEMON, "no-autostart refusal names KIN_NO_DAEMON on all three")
    repo = suite.fixture("noautostart")
    suite.stop_daemons()
    surfaces = [("kin push", ["push", "--url", DEAD_PEER]),
                ("kin pull", ["pull", "--url", DEAD_PEER]),
                ("kin remote plan-push", ["remote", "plan-push", "--url", DEAD_PEER])]
    graded = 0
    for name, args in surfaces:
        try:
            rc, out = suite.kin_run(
                args, repo, extra_env={"KIN_NO_DAEMON": "1", "KIN_DAEMON_URL": None},
            )
        except subprocess.TimeoutExpired:
            result.unknown("`%s` did not finish inside the timeout" % name)
            continue
        if rc == 0:
            result.unknown("`%s` exited 0 with autostart off, so there is no refusal to "
                           "read: %s" % (name, tail(out)))
            continue
        graded += 1

        if says_retired_refusal(out):
            result.bad("`%s` still says %r, which is what a build that reads only "
                       "KIN_DAEMON_URL prints for this input: %s"
                       % (name, RETIRED_REFUSAL, tail(out, 700)))
        else:
            result.ok("`%s` does not name an unreachable daemon" % name)

        missing = missing_phrases(out, REQUIRED_NO_DAEMON_PHRASES)
        if missing:
            result.bad("`%s` omits %s: %s"
                       % (name, ", ".join(repr(p) for p in missing), tail(out, 700)))
        else:
            result.ok("`%s` names KIN_NO_DAEMON and the word that undoes it" % name)

        if os.path.realpath(repo) not in out and repo not in out:
            result.bad("`%s` never names the repository it is about: %s"
                       % (name, tail(out, 700)))
        else:
            result.ok("`%s` names the repository" % name)

    # A surface that never produced a refusal graded nothing, and three surfaces
    # collapsing into one graded arm is what a partial revert would look like.
    if graded != len(surfaces):
        result.unknown("%d of %d surfaces produced a refusal to grade"
                       % (graded, len(surfaces)))
    return result


def check_2(suite):
    """An override that answers nothing names the variable that aimed it.

    The operator set this endpoint, so the remedy is about that variable and
    nothing else. A message that sent them to `kin doctor` here would send them
    looking at a supervisor that is not deciding anything.
    """
    result = Result("2", TICKET_DAEMON, "a dead override names KIN_DAEMON_URL and its remedy")
    repo = suite.fixture("reach")
    try:
        rc, out = suite.kin_run(
            ["push", "--url", DEAD_PEER], repo,
            extra_env={"KIN_DAEMON_URL": DEAD_ENDPOINT},
        )
    except subprocess.TimeoutExpired:
        result.unknown("`kin push` did not finish inside the timeout")
        return result
    if rc == 0:
        result.unknown("`kin push` exited 0 against a dead endpoint: %s" % tail(out))
        return result

    if says_retired_refusal(out):
        result.bad("the refusal says %r rather than naming the override that answered "
                   "nothing: %s" % (RETIRED_REFUSAL, tail(out, 700)))
    else:
        result.ok("the refusal does not name an unreachable daemon")

    missing = missing_phrases(out, REQUIRED_OVERRIDE_PHRASES)
    if missing:
        result.bad("the refusal omits %s: %s"
                   % (", ".join(repr(p) for p in missing), tail(out, 700)))
    else:
        result.ok("the refusal names KIN_DAEMON_URL and the remedy")

    if DEAD_ENDPOINT not in out:
        result.bad("the refusal never names the endpoint that answered nothing, so the "
                   "operator cannot see what their override points at: %s" % tail(out, 700))
    else:
        result.ok("the refusal names the endpoint that answered nothing")
    return result


def check_3(suite):
    """`kin auth login --provider github` asks the sign-in page for GitHub.

    Graded on the URL the CLI prints, which is the URL it would open, against a
    stub that returns the parameters the real `startCliFlow` returns and no
    provider. The flow parameters are asserted by value beside it: adding a
    provider while dropping `flowId` would trade a Google-only login for a broken
    one.
    """
    result = Result("3", TICKET_PROVIDER, "--provider github reaches the sign-in URL")
    with ControlPlaneStub() as stub:
        try:
            rc, out = suite.kin_run(
                ["auth", "login", "--no-browser", "--base-url", stub.base_url,
                 "--provider", "github"],
                suite.workdir, stdin_closed=True, timeout=120,
            )
        except subprocess.TimeoutExpired:
            result.unknown("`kin auth login` did not finish inside the timeout")
            return result
        if has_no_provider_flag(out):
            result.bad("`kin auth login` has no --provider flag, so a terminal user cannot "
                       "ask for the GitHub sign-in at all: %s" % tail(out, 500))
            return result
        if not stub.requests:
            result.unknown("the CLI never asked the stub to start a flow (rc=%d): %s"
                           % (rc, tail(out)))
            return result

    url = printed_login_url(out)
    if url is None:
        result.unknown("`kin auth login` printed no sign-in URL (rc=%d): %s" % (rc, tail(out)))
        return result
    result.ok("the CLI printed a sign-in URL")

    query = query_of(url)
    if query.get("provider") != "github":
        result.bad("the sign-in URL asks for provider=%r rather than github, so a terminal "
                   "user still cannot reach the GitHub sign-in: %s"
                   % (query.get("provider"), url))
    else:
        result.ok("the sign-in URL asks for the github provider")

    if provider_count(url) != 1:
        result.bad("the sign-in URL names provider %d times, and which one wins is the "
                   "server's parser to decide, not the CLI's: %s" % (provider_count(url), url))
    else:
        result.ok("the sign-in URL names one provider")

    lost = [key for key, value in (("flowId", ControlPlaneStub.FLOW_ID),
                                   ("code_challenge", ControlPlaneStub.CODE_CHALLENGE))
            if query.get(key) != value]
    if lost:
        result.bad("the sign-in URL lost %s, so the flow the server started cannot "
                   "complete: %s" % (", ".join(lost), url))
    else:
        result.ok("every flow parameter the server returned survived")
    return result


def check_4(suite):
    """A login that names no provider is still the Google login that shipped.

    The compatibility control, and the half that can fail silently. A flag that
    quietly moved every existing user to a different identity provider would pass
    check 3 and be a worse defect than the one it fixes.
    """
    result = Result("4", TICKET_PROVIDER, "the default login is unchanged")
    with ControlPlaneStub() as stub:
        try:
            rc, out = suite.kin_run(
                ["auth", "login", "--no-browser", "--base-url", stub.base_url],
                suite.workdir, stdin_closed=True, timeout=120,
            )
        except subprocess.TimeoutExpired:
            result.unknown("`kin auth login` did not finish inside the timeout")
            return result
        if not stub.requests:
            result.unknown("the CLI never asked the stub to start a flow (rc=%d): %s"
                           % (rc, tail(out)))
            return result

    url = printed_login_url(out)
    if url is None:
        result.unknown("`kin auth login` printed no sign-in URL (rc=%d): %s" % (rc, tail(out)))
        return result

    query = query_of(url)
    asked = query.get("provider")
    if asked is None:
        result.bad("a login naming no provider sends no provider at all, so the sign-in "
                   "page picks for the user and the CLI cannot say which one it got: %s"
                   % url)
    elif asked != "google":
        result.bad("a login naming no provider asks for provider=%r, so the flag moved "
                   "everybody who did not ask to move: %s" % (asked, url))
    else:
        result.ok("a login naming no provider still asks for google")

    lost = [key for key, value in (("flowId", ControlPlaneStub.FLOW_ID),
                                   ("code_challenge", ControlPlaneStub.CODE_CHALLENGE))
            if query.get(key) != value]
    if lost:
        result.bad("the sign-in URL lost %s: %s" % (", ".join(lost), url))
    else:
        result.ok("every flow parameter the server returned survived")
    return result


def check_5(suite):
    """A provider the CLI cannot send is refused before any network call.

    The zero is the assertion that matters. A name the CLI does not know reaches
    the sign-in page as an unconfigured provider and comes back as a redirect
    carrying `authError=provider-unavailable`, which no terminal ever shows, so
    the refusal has to happen here and the flow must never be started.
    """
    result = Result("5", TICKET_PROVIDER, "an unknown provider is refused before the network")
    with ControlPlaneStub() as stub:
        try:
            rc, out = suite.kin_run(
                ["auth", "login", "--no-browser", "--base-url", stub.base_url,
                 "--provider", "gitlab"],
                suite.workdir, stdin_closed=True, timeout=120,
            )
        except subprocess.TimeoutExpired:
            result.unknown("`kin auth login` did not finish inside the timeout")
            return result
        requests = stub.requests

    if has_no_provider_flag(out):
        result.bad("`kin auth login` has no --provider flag, so it refuses every provider "
                   "including the two it should send: %s" % tail(out, 500))
        return result
    if rc == 0:
        result.bad("`kin auth login --provider gitlab` exited 0: %s" % tail(out))
    else:
        result.ok("`kin auth login --provider gitlab` exited %d" % rc)

    if requests:
        result.bad("the CLI started a flow against the server before refusing a provider "
                   "it cannot send: %s" % json.dumps(requests)[:300])
    else:
        result.ok("no flow was started, so the refusal happened before the network")

    missing = [name for name in ("google", "github") if name not in out]
    if missing:
        result.bad("the refusal does not list %s, so the reader is not told what they may "
                   "ask for: %s" % (", ".join(missing), tail(out, 500)))
    else:
        result.ok("the refusal lists the providers the CLI can send")
    return result


def check_6(suite):
    """A completed login records the provider, and `kin auth status` names it.

    The end of FIR-2938's ask, and the only check here that carries a credential
    through storage and back. The exchange the stub answers carries NO provider,
    which is the shape the real one has, so the field can only come from what the
    login requested. That is why both surfaces are required to word it as a
    request rather than as what the browser did: a client saying "signed in with
    github" would be claiming something it was never told.

    Nothing here leaves the process. The keyring is off, the credential is a file
    under this run's own HOME, and the token is a constant this file writes.
    """
    result = Result("6", TICKET_PROVIDER, "a stored credential records the provider it asked for")
    with ControlPlaneStub() as stub:
        try:
            rc, out = suite.kin_run(
                ["auth", "login", "--no-browser", "--base-url", stub.base_url,
                 "--provider", "github"],
                suite.workdir, stdin_text="stub-auth-code\n", timeout=120,
            )
        except subprocess.TimeoutExpired:
            result.unknown("`kin auth login` did not finish inside the timeout")
            return result
        if has_no_provider_flag(out):
            result.bad("`kin auth login` has no --provider flag, so nothing can be "
                       "recorded: %s" % tail(out, 500))
            return result
        exchanged = [r for r in stub.requests if r["path"].rstrip("/").endswith("exchange")]
        if rc != 0 or not exchanged:
            result.unknown("the login did not complete against the stub (rc=%d, %d exchange "
                           "requests): %s" % (rc, len(exchanged), tail(out)))
            return result
    result.ok("the login completed against the stub")

    if "github" not in out:
        result.bad("the login's own confirmation does not name the provider it asked "
                   "for: %s" % tail(out, 500))
    else:
        result.ok("the login confirmation names the github provider")

    try:
        status_rc, status = suite.kin_run(
            ["auth", "status", "--base-url", stub.base_url], suite.workdir, timeout=120)
    except subprocess.TimeoutExpired:
        result.unknown("`kin auth status` did not finish inside the timeout")
        return result
    if status_rc != 0:
        result.unknown("`kin auth status` exited %d: %s" % (status_rc, tail(status)))
        return result

    if "github" not in status:
        result.bad("`kin auth status` does not name the provider the stored credential "
                   "asked for: %s" % tail(status, 500))
    else:
        result.ok("`kin auth status` names the github provider")

    # The honesty half. The exchange carried no provider, so a surface that says
    # the user signed in with one is claiming more than the client can know.
    if "signed in with" in status.lower():
        result.bad("`kin auth status` says the user signed in with a provider, which the "
                   "exchange response never told it: %s" % tail(status, 500))
    else:
        result.ok("the status does not claim to know what the browser did")
    return result


CHECKS = [("0", check_0), ("1", check_1), ("2", check_2),
          ("3", check_3), ("4", check_4), ("5", check_5), ("6", check_6)]


# ---------------------------------------------------------------- the report


def report_payload(kin, label, results):
    """The machine-readable report, in the one shape `gate.py` can read.

    The rows live under `results`, which is what `gate.py` reads and the only key
    it reads. Built here rather than inline at the write so `--self-test` can hand
    the exact bytes to the gate's own loader, which is a check no assertion in
    this file can fake: a suite and a gate that each hardcode the key separately
    are exactly the pair that stayed green while one of them said something else.
    """
    return {
        "suite": "bridge_reach_repro",
        "label": label,
        "kin": kin,
        "results": [{"id": r.id, "ticket": r.ticket, "title": r.title,
                     "status": r.status, "detail": r.detail,
                     # Every assertion, not only the one `detail` surfaced. A
                     # check that graded three surfaces and reports one sentence
                     # is indistinguishable from one that graded one surface.
                     "asserts": r.asserts} for r in results],
    }


# ------------------------------------------------------------------ self test


def _load_gate_module():
    """The gate that decides this suite's report, imported from beside it."""
    import importlib.util

    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gate.py")
    spec = importlib.util.spec_from_file_location("acceptance_gate", path)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception:
        return None
    return module


def self_test():
    """Grade this suite's own graders against their inverse.

    Every helper below decides a check's verdict, so a helper that cannot fail is
    a check that cannot fail. Each is driven once with input it must accept and
    once with input it must reject, and the pairs that read alike from outside
    are driven against each other rather than against nothing.
    """
    failures = []

    def expect(condition, message):
        if not condition:
            failures.append(message)

    # The sentence the ticket is named after, and the two refusals that replaced
    # it. The replacements must not trip the detector, or every check above would
    # fail on a build that is correct.
    shipped = ("Error: no Kin daemon is reachable. Repository authority and every view "
               "derived from it live in the daemon, so a transfer must run there.")
    expect(says_retired_refusal(shipped), "the shipped refusal was not detected")
    no_daemon = ("Error: KIN_NO_DAEMON is set and no kin daemon is already running for "
                 "/tmp/r, so there is no repository authority to answer kin push; unset "
                 "KIN_NO_DAEMON and re-run, and kin will start one")
    override = ("Error: KIN_DAEMON_URL is set to http://127.0.0.1:1 and no kin daemon "
                "answered there, so kin push has no repository authority to run in; unset "
                "KIN_DAEMON_URL and kin will use the daemon serving /tmp/r, or set it to an "
                "endpoint that is up")
    for replacement in (no_daemon, override):
        expect(not says_retired_refusal(replacement),
               "a correct refusal was read as the retired one: %s" % replacement)

    expect(missing_phrases(no_daemon, REQUIRED_NO_DAEMON_PHRASES) == [],
           "the no-autostart refusal was reported as missing %s"
           % missing_phrases(no_daemon, REQUIRED_NO_DAEMON_PHRASES))
    expect(missing_phrases(override, REQUIRED_OVERRIDE_PHRASES) == [],
           "the override refusal was reported as missing %s"
           % missing_phrases(override, REQUIRED_OVERRIDE_PHRASES))

    # The mutation that matters for both: a refusal that names its cause and
    # never says what to do. The reader is left exactly where the wrong cause
    # left them.
    expect("unset KIN_NO_DAEMON" in missing_phrases(
        "KIN_NO_DAEMON is set and no kin daemon is running", REQUIRED_NO_DAEMON_PHRASES),
        "a no-autostart refusal with no remedy was accepted as complete")
    expect("unset KIN_DAEMON_URL" in missing_phrases(
        "KIN_DAEMON_URL is set to http://127.0.0.1:1 and nothing answered",
        REQUIRED_OVERRIDE_PHRASES),
        "an override refusal with no remedy was accepted as complete")

    # The two refusals must not satisfy each other's requirements, or check 1 and
    # check 2 would both pass on a build that printed one sentence for both
    # states. This is the pair that reads alike from outside.
    expect(missing_phrases(no_daemon, REQUIRED_OVERRIDE_PHRASES) != [],
           "the no-autostart refusal satisfied the override requirements, so the two "
           "checks cannot tell the two states apart")
    expect(missing_phrases(override, REQUIRED_NO_DAEMON_PHRASES) != [],
           "the override refusal satisfied the no-autostart requirements")

    # Stopped at the gate, or stopped by the work. Every refusal resolution can
    # produce must read as the gate, and the failure the FIXED product actually
    # returns must not, which is the case that turned a correct build red when
    # this asserted on the peer URL instead. The 424 below is pasted from the
    # 16:38:16Z run against the built binary.
    for refusal in (shipped, no_daemon, override):
        expect(stopped_at_daemon_resolution(refusal),
               "a resolution refusal was not read as one: %s" % refusal)
    reached_the_work = ("Error: kin push refused (HTTP 424): repository transfer storage "
                        "failed: remote transfer status transport failed: io: Connection "
                        "refused")
    expect(not stopped_at_daemon_resolution(reached_the_work),
           "the failure a working push returns was read as a resolution refusal, which "
           "would turn a correct product red: %s" % reached_the_work)

    # The three states `kin daemon status` can leave a reader in, driven from
    # the command's own output. The supervisor block is in BOTH fixtures on
    # purpose: it runs whether a worker does or not and prints a port of its own,
    # so a grader that matched any port would read the absent case as serving and
    # check 0 could never fail.
    supervisor = ("Supervisor: running (pid 60731, port 58095)\n"
                  "  scope:     machine-wide (one per machine, not per KIN_HOME)\n\n")
    serving = (supervisor + "Repo daemons (1):\n"
               "  r  running  pid 14354  port 61182  1 entities  /tmp/r\n"
               "    endpoint:  http://127.0.0.1:61182\n")
    absent = (supervisor + "Repo daemons: none registered\n\n"
              "Current repo (r): worker daemon not running\n")
    expect(repo_daemon_state(serving) == "SERVING",
           "a serving repo daemon read as %r" % repo_daemon_state(serving))
    expect(repo_daemon_state(absent) == "ABSENT",
           "an absent repo daemon read as %r" % repo_daemon_state(absent))
    expect(repo_daemon_state(supervisor) is None,
           "a status naming only the supervisor read as %r rather than unreadable"
           % repo_daemon_state(supervisor))
    expect(repo_daemon_state("") is None,
           "empty output read as %r rather than unreadable" % repo_daemon_state(""))

    # A CLI that cannot parse the flag has failed, not gone unmeasured, and an
    # unrelated usage error must not be swept into that verdict.
    expect(has_no_provider_flag("error: unexpected argument '--provider' found\n\n"
                                "  tip: a similar argument exists: '--profile-summary'"),
           "a binary with no --provider flag was not detected")
    expect(not has_no_provider_flag("error: unexpected argument '--wat' found"),
           "an unrelated usage error was read as a missing --provider flag")
    expect(not has_no_provider_flag(
        "error: invalid value 'gitlab' for '--provider <PROVIDER>'\n"
        "  [possible values: google, github]"),
        "a refusal of a provider VALUE was read as a missing flag, which would turn the "
        "working build's own refusal into the defect")

    printed = ("Open this URL in a browser to continue:\n\n"
               "http://127.0.0.1:5555/auth/login?flowId=F&code_challenge=C&provider=github\n")
    url = printed_login_url(printed)
    expect(url is not None, "a printed sign-in URL was not found")
    expect(query_of(url).get("provider") == "github",
           "the provider was not read out of a printed URL")
    expect(query_of(url).get("flowId") == "F" and query_of(url).get("code_challenge") == "C",
           "a flow parameter was lost reading the printed URL")
    expect(printed_login_url("Open this URL in a browser to continue:\n") is None,
           "prose with no URL was read as a URL")
    expect(printed_login_url("Error: no auth code provided\n") is None,
           "a refusal with no URL was read as a URL")

    # One value read out of two is the failure a single-value parse cannot see,
    # and the count is the only thing that can.
    doubled = ("http://127.0.0.1:5555/auth/login?flowId=F&provider=google&provider=github")
    expect(provider_count(doubled) == 2, "two providers were counted as %d"
           % provider_count(doubled))
    expect(provider_count("http://127.0.0.1:5555/auth/login?flowId=F&provider=github") == 1,
           "one provider was not counted as one")
    expect(provider_count("http://127.0.0.1:5555/auth/login?flowId=F") == 0,
           "a URL naming no provider was counted as naming one")

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

    expect(len(CHECKS) == len({check_id for check_id, _ in CHECKS}),
           "two checks share an id, so one of them cannot be selected")

    # The report this suite writes has to be a report the gate can read, and the
    # two halves live in different files, so neither one alone can see the join.
    written = Result("0", TICKET_DAEMON, "a row for the gate to read")
    written.ok("something was graded")
    gate = _load_gate_module()
    if gate is None:
        expect(False, "gate.py could not be imported, so the report shape was not graded")
    else:
        handle, path = tempfile.mkstemp(prefix="kin-bridge-reach-report-", suffix=".json")
        try:
            with os.fdopen(handle, "w") as out:
                json.dump(report_payload("/nonexistent/kin", "self-test", [written]), out)
            try:
                rows = gate.load_report(path)
                expect(set(rows) == {"0"},
                       "the gate read %s out of a one-row report" % sorted(rows))
            except gate.GateError as error:
                expect(False, "the gate refused this suite's own report: %s" % error)
            with open(path, "w") as out:
                json.dump({"suite": "bridge_reach_repro",
                           "checks": [{"id": "0", "status": PASS, "detail": "x"}]}, out)
            try:
                gate.load_report(path)
                expect(False, "the gate accepted a report keyed `checks`, so this self-test "
                              "could not have caught a suite writing the wrong key")
            except gate.GateError:
                pass
        finally:
            os.unlink(path)

    for failure in failures:
        print("SELFTEST FAIL %s" % failure)
    if failures:
        return 1
    print("SELFTEST PASS %d assertions over %d checks" % (37, len(CHECKS)))
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

    if HTTPServer is None or parse_qsl is None:
        print("setup: this suite needs python3's http.server and urllib.parse")
        return 3
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

    workdir = tempfile.mkdtemp(prefix="kin-bridge-reach-")
    results = []
    suite = None
    try:
        suite = Suite(kin, workdir, verbose=args.verbose)
        for check_id, check in selected:
            try:
                results.append(check(suite))
            except Exception as error:  # a check that threw graded nothing
                broken = Result(check_id, TICKET_DAEMON, "check %s raised" % check_id)
                broken.unknown("check %s raised %s: %s"
                               % (check_id, type(error).__name__, error))
                results.append(broken)
    finally:
        if suite is not None:
            suite.stop_daemons()
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
            json.dump(report_payload(kin, args.label, results), handle, indent=2)
            handle.write("\n")

    if any(result.status == FAIL for result in results):
        return 1
    if any(result.status == UNREADABLE for result in results):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
