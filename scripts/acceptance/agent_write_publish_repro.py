#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
"""Prove an agent's write reaches graph authority, and a refused one leaves nothing behind.

FIR-3550. In run 3 of the local-model demo a 27B model under `kin agent run` read a
function, called the agent's own `edit_file` to put a doc comment above it, and Kin
refused the commit: "tracked working-copy path ... differs from prior workspace source
(the file content changed)". The harness had written the file before it staged and
committed, and the commit held every tracked path to the prior tree, so the agent's own
bytes read as drift. The edit stayed on disk and the graph kept the old text.

Two hermetic test suites were green the whole time. kin-agent's runs against a scripted
MCP server that projected whatever it was sent, and kin-daemon's commit tests staged
without writing first, so neither could see the composition. This suite runs the real
binaries end to end: `kin init`, `kin agent run` against a scripted chat endpoint, and a
direct `kin mcp start` session to read the result back.

Six checks, one repository, run in order:

  edit_lands            an `edit_file` on a tracked function commits: the run exits 0,
                        the file holds the new text, `get_entity_source` answers with the
                        new body, and the durability block reads `recorded`
  refused_edit_is_clean an edit authority refuses (an unterminated comment that hides a
                        declaration, which the planner rejects) leaves the file exactly as
                        it was, the run exits 6, and the model is told it did not land
  create_lands          a `write_file` of a new module commits, the file exists with the
                        body, and the graph lists its function
  refused_create_is_clean
                        a `write_file` over a tracked path is refused, the tracked file
                        keeps its text, and the refused content comes back to the model
  pure_kin_mutate_lands the same binary under `KIN_AGENT_PURE_KIN`, whose belt carries no
                        `edit_file` and no `write_file` at all: one `kin_mutate` naming the
                        ENTITY commits, the file and `get_entity_source` carry it,
                        durability reads `recorded`, the run records
                        `entities_changed` and no file, the call went out under a session
                        the harness supplied (the model never sees `kin_session_start`),
                        and `kin log` carries the agent's own summary rather than the bare
                        transaction line
  edit_survives_a_daemon_restart
                        the repository's daemon is stopped after the agent's session opens
                        and before its first edit, as an unattended update did in the
                        demo's real-model run. Sessions live in the daemon, so begin is
                        refused for a session that no longer exists; the harness must open
                        a new one and commit through it. The run exits 0, the file and
                        `get_entity_source` carry the edit, durability reads `recorded`,
                        and no edit is written outside a transaction

What it is blind to: it drives one agent, one repository and one scripted conversation. It
does not grade the cost of a commit, the delegate's retry on a slow one, or a real model.

Each check prints one line:

    CHECK <id> <ticket> PASS|FAIL|UNREADABLE <detail>

Exit status is 0 when every check passed, 1 when one failed, 2 when one could not be
read, and 3 when the run could not be set up. `--self-test` drives every grader against
an input that must pass and one that must fail, and needs no binary.
"""
from __future__ import print_function

import argparse
import functools
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

try:
    from http.server import BaseHTTPRequestHandler, HTTPServer
except ImportError:  # pragma: no cover - python 2 is not supported by this suite
    raise SystemExit("python 3 is required")

PASS = "PASS"
FAIL = "FAIL"
UNREADABLE = "UNREADABLE"

TICKET = "FIR-3550"

print = functools.partial(print, flush=True)

LIB_RS = "pub fn value() -> u8 {\n    1\n}\n"
OTHER_RS = "pub fn other() -> u8 {\n    4\n}\n\npub fn kept() -> u8 {\n    5\n}\n"
README = "# agent write fixture\n"

EDIT_FIND = "pub fn value() -> u8 {\n    1\n}"
EDIT_REPLACE = "/// The value this module reports.\npub fn value() -> u8 {\n    0x2a\n}"
EDIT_MARKER = "0x2a"

# An unterminated block comment swallows `kept`, so the new text parses incomplete and the
# planner refuses to publish a deletion it cannot verify. Deterministic, and independent
# of the daemon's reconcile timing, which a drift-based refusal would race.
REFUSED_FIND = "pub fn kept() -> u8 {"
REFUSED_REPLACE = "/* pub fn kept() -> u8 {"

CREATED_PATH = "src/added.rs"
CREATED_BODY = "pub fn added() -> u8 {\n    3\n}\n"
OVERWRITE_BODY = "# replaced wholesale\n"

# The edit made after the daemon is restarted, on a function no earlier check changes.
RESTART_FIND = "pub fn other() -> u8 {\n    4\n}"
RESTART_REPLACE = "/// The other value.\npub fn other() -> u8 {\n    0x2b\n}"
RESTART_MARKER = "0x2b"

# The pure-Kin check's own file and entity. Its own, and not one of the four
# above, because the checks run in order against one repository and an entity a
# neighbour has already moved cannot tell a failure of this path from a failure
# of that one.
MUTABLE_RS = "pub fn mutable() -> u8 {\n    7\n}\n"
MUTATE_BODY = "/// Set through Kin by an agent with no file tools.\npub fn mutable() -> u8 {\n    0x2c\n}"
MUTATE_MARKER = "0x2c"
# The sentence the agent names for its own change. Distinctive, because the
# assertion is that history carries THIS and not the bare transaction line.
MUTATE_SUMMARY = "Raise mutable to 0x2c"


def run(cmd, cwd=None, env=None, timeout=600):
    proc = subprocess.Popen(cmd, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            universal_newlines=True)
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
        return 124, out, err
    return proc.returncode, out, err


# ── graders ────────────────────────────────────────────────────────────────
#
# Every grader takes what a run produced and returns (status, detail). Kept apart from
# the run so `--self-test` can hand each one an input that must pass and one that must
# fail, with no binary anywhere.


def durability_state(payload):
    if not isinstance(payload, dict):
        return None
    block = (payload.get("_kin") or {}).get("durability")
    if isinstance(block, dict):
        return block.get("state")
    return None


def mentions(payload, needle):
    if isinstance(payload, str):
        return needle in payload
    if isinstance(payload, list):
        return any(mentions(item, needle) for item in payload)
    if isinstance(payload, dict):
        return any(mentions(value, needle) for value in payload.values())
    return False


def grade_edit_lands(rc, disk, source_payload, status_payload):
    if rc is None or disk is None or source_payload is None or status_payload is None:
        return UNREADABLE, "the run or its read-back produced nothing to grade"
    problems = []
    if rc != 0:
        problems.append("kin agent run exited %s, not 0" % rc)
    if EDIT_MARKER not in disk:
        problems.append("the file on disk does not carry the edit")
    if not mentions(source_payload, EDIT_MARKER):
        problems.append("get_entity_source still answers with the old body")
    state = durability_state(status_payload)
    if state != "recorded":
        problems.append("durability reads %r, not 'recorded'" % state)
    if problems:
        return FAIL, "; ".join(problems)
    return PASS, "the edit committed: disk, get_entity_source and durability agree"


def mutate_rows(trace):
    """Every `kin_mutate` call the run made, as the trace recorded it."""
    return [row for row in (trace or []) if row.get("tool") == "kin_mutate"]


def grade_pure_kin_mutate_lands(rc, disk, source_payload, status_payload, trace, result,
                                messages):
    """A belt with no file tools commits by naming the entity, and says what it did.

    Five things have to be true together, and each one has been separately true
    while the composition was broken. The change reaches disk and the graph, the
    way any commit must. The run records the ENTITY it changed and no file,
    because on this belt there is no file tool to record. The mutate call
    carries a session_id the model never saw, since kin_session_start is
    harness-owned and a call without one is refused by a daemon that owns
    sessions. And history carries the agent's own sentence rather than the bare
    transaction line.

    The session assertion is the one this check exists for. Two hermetic suites
    covered the halves: kin-agent's tests run against a scripted MCP server that
    has no daemon and no session authority, and kin-mcp's run in-process where
    its own registry IS the authority. Neither could see that the fallback
    between them invents an id the daemon has never heard of.
    """
    if rc is None or disk is None or source_payload is None or status_payload is None:
        return UNREADABLE, "the run or its read-back produced nothing to grade"
    if trace is None or result is None or messages is None:
        return UNREADABLE, "the run's trace, result record or change log was unreadable"
    problems = []
    if rc != 0:
        problems.append("kin agent run exited %s, not 0" % rc)
    if MUTATE_MARKER not in disk:
        problems.append("the file on disk does not carry the mutation")
    if not mentions(source_payload, MUTATE_MARKER):
        problems.append("get_entity_source still answers with the old body")
    state = durability_state(status_payload)
    if state != "recorded":
        problems.append("durability reads %r, not 'recorded'" % state)

    calls = mutate_rows(trace)
    if not calls:
        problems.append("the run made no kin_mutate call at all")
    else:
        errored = [row for row in calls if row.get("is_error")]
        if errored:
            problems.append("kin_mutate came back an error: %s"
                            % json.dumps(errored[0])[:300])
        unsessioned = [row for row in calls
                       if not ((row.get("args") or {}).get("session_id") or "").strip()]
        if unsessioned:
            problems.append("a kin_mutate went out with no session_id, which a daemon that "
                            "owns sessions refuses; the harness must supply its own")

    agent = (result.get("kin_agent") or {})
    if agent.get("entities_changed") != ["mutable"]:
        problems.append("the run recorded entities_changed=%r, not ['mutable']"
                        % (agent.get("entities_changed"),))
    if agent.get("files_changed"):
        problems.append("a belt with no file tools recorded files_changed=%r"
                        % (agent.get("files_changed"),))

    # Read for the sentence anywhere in the message, not only as its first line.
    # A commit that folds admitted working-tree content puts the fold in the
    # subject and the caller's words in the body, and whether earlier checks in
    # this suite left anything pending is not what this check is about.
    if not any(message and MUTATE_SUMMARY in message for message in messages):
        problems.append("no recorded change message carries %r; the newest are %r"
                        % (MUTATE_SUMMARY, messages[:2]))

    if problems:
        return FAIL, "; ".join(problems)
    return PASS, ("a Kin-only belt committed by naming the entity, under a session the harness "
                  "supplied, and history carries the agent's own sentence")


def grade_refused_edit_is_clean(rc, disk_before, disk_after, tool_result):
    if rc is None or disk_after is None or tool_result is None:
        return UNREADABLE, "the run produced nothing to grade"
    problems = []
    if rc != 6:
        problems.append("kin agent run exited %s, not 6 (changes_unpublished)" % rc)
    if disk_after != disk_before:
        problems.append("the refused edit changed the file on disk")
    if "did not land" not in tool_result or "unchanged" not in tool_result:
        problems.append("the model was not told the edit did not land and the file is unchanged")
    if problems:
        return FAIL, "; ".join(problems)
    return PASS, "the refused edit left the file untouched and the model was told"


def grade_create_lands(rc, disk, listed_payload):
    if rc is None or listed_payload is None:
        return UNREADABLE, "the run or its read-back produced nothing to grade"
    problems = []
    if rc != 0:
        problems.append("kin agent run exited %s, not 0" % rc)
    if disk != CREATED_BODY:
        problems.append("the created file is missing or holds other bytes")
    if not mentions(listed_payload, "added"):
        problems.append("the graph does not list the created function")
    if problems:
        return FAIL, "; ".join(problems)
    return PASS, "the created module committed and the graph lists its function"


def grade_refused_create_is_clean(rc, disk_before, disk_after, tool_result):
    if rc is None or disk_after is None or tool_result is None:
        return UNREADABLE, "the run produced nothing to grade"
    problems = []
    if rc != 6:
        problems.append("kin agent run exited %s, not 6 (changes_unpublished)" % rc)
    if disk_after != disk_before:
        problems.append("the refused write changed the tracked file")
    if OVERWRITE_BODY.strip() not in tool_result:
        problems.append("the refused content did not come back to the model")
    if problems:
        return FAIL, "; ".join(problems)
    return PASS, "the refused write left the tracked file alone and handed the content back"


def grade_edit_survives_a_daemon_restart(stop, rc, disk, source_payload, status_payload, trace):
    """`stop` is the restart's (rc, detail); `trace` is the run's kin-trace rows."""
    if not stop or stop[0] != 0:
        return UNREADABLE, "no restart was exercised: %s" % (
            stop[1] if stop else "the model endpoint was never asked for its first answer")
    if rc is None or disk is None or source_payload is None or status_payload is None \
            or trace is None:
        return UNREADABLE, "the run or its read-back produced nothing to grade"
    problems = []
    if rc != 0:
        problems.append("kin agent run exited %s, not 0" % rc)
    if RESTART_MARKER not in disk:
        problems.append("the file on disk does not carry the edit")
    if not mentions(source_payload, RESTART_MARKER):
        problems.append("get_entity_source still answers with the old body")
    state = durability_state(status_payload)
    if state != "recorded":
        problems.append("durability reads %r, not 'recorded'" % state)
    edits = [row for row in trace if row.get("surface") == "local"
             and row.get("tool") in ("edit_file", "write_file")]
    if not edits:
        problems.append("the trace records no edit")
    for row in edits:
        provenance = row.get("provenance") or {}
        if provenance.get("closed_with") != "kin_transaction_commit" \
                or provenance.get("closed_cleanly") is not True:
            problems.append("the edit did not commit through a transaction (%s)" % (
                provenance.get("reason") or provenance.get("detail") or "no reason recorded"))
    if problems:
        return FAIL, "; ".join(problems)
    refused = any(row.get("tool") == "kin_transaction_begin" and row.get("is_error")
                  and "Session not found" in str(row.get("detail") or "") for row in trace)
    sessions = sum(1 for row in trace if row.get("tool") == "kin_session_start")
    how = ("begin was refused for the gone session and the harness opened a new one"
           if refused and sessions >= 2 else "no begin was refused after the restart")
    return PASS, "the edit committed through Kin after a daemon restart; %s" % how


# ── the scripted chat endpoint ─────────────────────────────────────────────


def completion(text, tool=None, arguments=None):
    message = {"role": "assistant", "content": text}
    finish = "stop"
    if tool:
        message["tool_calls"] = [{"id": "call_1", "type": "function",
                                  "function": {"name": tool,
                                               "arguments": json.dumps(arguments)}}]
        finish = "tool_calls"
    return {"id": "chatcmpl-acceptance", "object": "chat.completion",
            "choices": [{"index": 0, "message": message, "finish_reason": finish}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5}}


class Endpoint(object):
    """One scripted conversation: each request pops the next answer.

    `before_first`, when given, runs once before the first answer goes back, while the
    agent waits on its model, which is where a real model spends its long turns.
    """

    def __init__(self, script, before_first=None):
        answers = list(script)
        pending = [before_first] if before_first else []
        lock = threading.Lock()

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def _send(self, payload):
                body = json.dumps(payload).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                self._send({"object": "list", "data": [{"id": "scripted", "object": "model"}]})

            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length", "0")))
                with lock:
                    while pending:
                        pending.pop(0)()
                    answer = answers.pop(0) if answers else completion("Done.")
                self._send(answer)

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()
        self.base_url = "http://127.0.0.1:%d/v1" % self.server.server_address[1]

    def close(self):
        self.server.shutdown()
        self.server.server_close()


# ── the product under test ─────────────────────────────────────────────────


class Mcp(object):
    """A minimal newline-delimited JSON-RPC client over `kin mcp start`."""

    def __init__(self, argv, env, cwd):
        self.proc = subprocess.Popen(argv, env=env, cwd=cwd, stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     universal_newlines=True)
        self.next_id = 1
        self.request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                    "clientInfo": {"name": "agent-write-acceptance",
                                                   "version": "0"}})
        self.proc.stdin.write(json.dumps({"jsonrpc": "2.0",
                                          "method": "notifications/initialized",
                                          "params": {}}) + "\n")
        self.proc.stdin.flush()

    def request(self, method, params):
        rid = self.next_id
        self.next_id += 1
        self.proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": rid, "method": method,
                                          "params": params}) + "\n")
        self.proc.stdin.flush()
        while True:
            line = self.proc.stdout.readline()
            if not line:
                raise RuntimeError("kin mcp start closed during %s" % method)
            message = json.loads(line)
            if message.get("id") == rid:
                return message

    def call(self, name, arguments):
        result = self.request("tools/call", {"name": name, "arguments": arguments})
        blocks = (result.get("result") or {}).get("content") or []
        text = "".join(block.get("text", "") for block in blocks)
        try:
            return json.loads(text)
        except ValueError:
            return None

    def close(self):
        try:
            self.proc.stdin.close()
            self.proc.wait(timeout=30)
        except Exception:  # noqa: BLE001 - teardown only
            self.proc.kill()


class Suite(object):
    def __init__(self, kin, workdir, daemon=None, verbose=False):
        self.kin = kin
        self.workdir = workdir
        self.verbose = verbose
        self.env = dict(os.environ)
        self.env["KIN_HOME"] = os.path.join(workdir, "home")
        # KIN_HOME does not move the supervisor. It lives beside an explicit
        # KIN_REGISTRY_PATH, or else in the real home's `.kin`, where a daemon started
        # here would take the machine-wide supervisor with the build under test.
        self.env["KIN_REGISTRY_PATH"] = os.path.join(workdir, "home", "registry.toml")
        self.env.pop("KIN_MCP_REPO", None)
        if daemon:
            self.env["KIN_DAEMON_BIN"] = daemon
        self._repo = None
        self._setup_error = None
        self._runs = 0
        self.last_trace = None
        self.last_result = None

    def git(self, cwd, args):
        # The caller's global and system git config stay out of the fixture: a hooks
        # path or a commit-message policy there is the machine's, not the product's.
        env = dict(self.env, GIT_AUTHOR_NAME="Acceptance", GIT_AUTHOR_EMAIL="acceptance@example.invalid",
                   GIT_COMMITTER_NAME="Acceptance", GIT_COMMITTER_EMAIL="acceptance@example.invalid",
                   GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        rc, out, err = run(["git"] + args, cwd=cwd, env=env, timeout=120)
        if rc != 0:
            raise RuntimeError("git %s failed: %s" % (" ".join(args), err.strip()))
        return out

    def repo(self):
        """The initialised fixture, built once.

        A fixture that failed to build is never handed out half made: every later check
        gets the same setup error, so it reads UNREADABLE rather than grading an agent
        run against a directory Kin was never initialised in.
        """
        if self._repo:
            return self._repo
        if self._setup_error:
            raise RuntimeError(self._setup_error)
        path = os.path.join(self.workdir, "repo")
        try:
            os.makedirs(os.path.join(path, "src"))
            for relative, body in (("src/lib.rs", LIB_RS), ("src/other.rs", OTHER_RS),
                                   ("src/mutable.rs", MUTABLE_RS),
                                   ("README.md", README),
                                   ("Cargo.toml", '[package]\nname = "agentwrite"\n'
                                                  'version = "0.1.0"\nedition = "2021"\n')):
                with open(os.path.join(path, relative), "w") as handle:
                    handle.write(body)
            self.git(path, ["init", "-q", "-b", "main"])
            self.git(path, ["add", "."])
            self.git(path, ["commit", "-q", "-m", "Add the agent write fixture"])
            rc, out, err = run([self.kin, "init"], cwd=path, env=self.env, timeout=900)
            if rc not in (0, 7, 8):
                raise RuntimeError("kin init exited %s: %s" % (rc, err.strip()[-600:]))
        except Exception as error:  # noqa: BLE001 - recorded once, raised for every check
            self._setup_error = "fixture setup failed: %s" % error
            raise RuntimeError(self._setup_error)
        self._repo = path
        return path

    def read(self, relative):
        path = os.path.join(self.repo(), relative)
        if not os.path.exists(path):
            return None
        with open(path) as handle:
            return handle.read()

    def agent(self, script, before_first=None, env_extra=None):
        """Run `kin agent run` through one scripted conversation.

        Returns the exit code and the last tool result the model was sent, and keeps the
        run's kin-trace rows on `last_trace` and its result record on `last_result`.

        `env_extra` is what lets one check run the same binary with a different
        belt: `KIN_AGENT_PURE_KIN` decides whether edit_file and write_file exist
        at all, and it is read per process, so the only way to grade both belts
        is to run the binary twice.
        """
        self._runs += 1
        out = os.path.join(self.workdir, "run-%d" % self._runs)
        endpoint = Endpoint(script, before_first=before_first)
        env = dict(self.env, **(env_extra or {}))
        try:
            rc, stdout, stderr = run([self.kin, "agent", "run", "--task",
                                      "Make the change the conversation asks for.",
                                      "--model", "scripted", "--base-url", endpoint.base_url,
                                      "--repo", self.repo(), "--out", out,
                                      "--max-tool-calls", "4", "--deadline", "600"],
                                     cwd=self.workdir, env=env, timeout=900)
        finally:
            endpoint.close()
        if self.verbose:
            print("kin agent run rc=%s\n%s" % (rc, stderr[-2000:]))
        tool_result = None
        transcript = os.path.join(out, "transcript.jsonl")
        if os.path.exists(transcript):
            with open(transcript) as handle:
                for line in handle:
                    record = json.loads(line)
                    for block in (record.get("message") or {}).get("content") or []:
                        if isinstance(block, dict) and block.get("type") == "tool_result":
                            tool_result = block.get("content")
        self.last_trace = None
        trace = os.path.join(out, "kin-trace.jsonl")
        if os.path.exists(trace):
            with open(trace) as handle:
                self.last_trace = [json.loads(line) for line in handle if line.strip()]
        self.last_result = None
        result = os.path.join(out, "result.json")
        if os.path.exists(result):
            with open(result) as handle:
                self.last_result = json.load(handle)
        return rc, tool_result

    def change_messages(self, count=3):
        """The subjects of the most recent changes, newest first.

        Read with `kin log`, which resolves its repository from the working
        directory, because the recorded message is the one thing an agent's own
        run record cannot tell you: it is written by the daemon on the far side
        of the commit.
        """
        rc, out, err = run([self.kin, "log", "-n", str(count), "--json"],
                           cwd=self.repo(), env=self.env, timeout=180)
        if rc != 0:
            return None
        try:
            payload = json.loads(out)
        except ValueError:
            return None
        # `LogReport` keys its rows `entries` and each carries `message`
        # (crates/kin-cli/src/commands/log.rs), and that shape is held by a
        # crate test of its own. Read it outright rather than guessing among
        # alternatives, so a report that changed shape reads as unreadable here
        # instead of as an absent message.
        entries = payload.get("entries")
        if not isinstance(entries, list):
            return None
        return [entry.get("message") for entry in entries if isinstance(entry, dict)]

    def mcp(self):
        return Mcp([self.kin, "mcp", "start", "--repo", self.repo()], self.env, self.workdir)

    def stop_daemon(self):
        """Stop this fixture's daemon with `kin daemon stop` and wait for its port to close.

        Returns (rc, detail). The port is read first, because a stopped daemon removes its
        endpoint files.
        """
        port = None
        port_file = os.path.join(self.repo(), ".kin", "daemon.port")
        if os.path.exists(port_file):
            with open(port_file) as handle:
                text = handle.read().strip()
            port = int(text) if text.isdigit() else None
        if port is None:
            return 1, "no daemon was serving the fixture when the restart was due"
        rc, _, err = run([self.kin, "daemon", "stop"], cwd=self.repo(), env=self.env,
                         timeout=180)
        if rc != 0:
            return rc, "kin daemon stop exited %s: %s" % (rc, err.strip()[-300:])
        deadline = time.time() + 60
        while time.time() < deadline:
            probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            probe.settimeout(1)
            try:
                probe.connect(("127.0.0.1", port))
            except OSError:
                return 0, "the daemon on port %d stopped" % port
            finally:
                probe.close()
            time.sleep(0.5)
        return 1, "the daemon on port %d still answered 60 s after kin daemon stop" % port


class Result(object):
    def __init__(self, ident, status, detail):
        self.ident = ident
        self.status = status
        self.detail = detail


def entity_id(listed, name):
    stack = [listed]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            if node.get("name") == name and (node.get("id") or node.get("entity_id")):
                return node.get("id") or node.get("entity_id")
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return None


def check_edit_lands(suite):
    rc, _ = suite.agent([completion("Documenting value.", "edit_file",
                                    {"path": "src/lib.rs", "find": EDIT_FIND,
                                     "replace": EDIT_REPLACE}),
                         completion("value is documented.")])
    session = suite.mcp()
    try:
        listed = session.call("list_file_entities", {"path": "src/lib.rs", "limit": 50})
        focal = entity_id(listed, "value")
        source = session.call("get_entity_source", {"entity_id": focal}) if focal else None
        status = session.call("kin_graph_status", {})
    finally:
        session.close()
    verdict, detail = grade_edit_lands(rc, suite.read("src/lib.rs"), source, status)
    return Result("edit_lands", verdict, "%s %s" % (TICKET, detail))


def check_refused_edit_is_clean(suite):
    before = suite.read("src/other.rs")
    rc, tool_result = suite.agent([completion("Commenting out kept.", "edit_file",
                                              {"path": "src/other.rs", "find": REFUSED_FIND,
                                               "replace": REFUSED_REPLACE}),
                                   completion("kept is commented out.")])
    verdict, detail = grade_refused_edit_is_clean(rc, before, suite.read("src/other.rs"),
                                                  tool_result)
    return Result("refused_edit_is_clean", verdict, "%s %s" % (TICKET, detail))


def check_create_lands(suite):
    rc, _ = suite.agent([completion("Adding a module.", "write_file",
                                    {"path": CREATED_PATH, "content": CREATED_BODY}),
                         completion("src/added.rs holds added.")])
    session = suite.mcp()
    try:
        listed = session.call("list_file_entities", {"path": CREATED_PATH, "limit": 50})
    finally:
        session.close()
    verdict, detail = grade_create_lands(rc, suite.read(CREATED_PATH), listed)
    return Result("create_lands", verdict, "%s %s" % (TICKET, detail))


def check_refused_create_is_clean(suite):
    before = suite.read("README.md")
    rc, tool_result = suite.agent([completion("Rewriting the readme.", "write_file",
                                              {"path": "README.md", "content": OVERWRITE_BODY}),
                                   completion("README.md rewritten.")])
    verdict, detail = grade_refused_create_is_clean(rc, before, suite.read("README.md"),
                                                    tool_result)
    return Result("refused_create_is_clean", verdict, "%s %s" % (TICKET, detail))


def check_pure_kin_mutate_lands(suite):
    """Drive the belt the founder asked for: Kin tools, and nothing else.

    `KIN_AGENT_PURE_KIN` is read per process, so this is the same binary run a
    second time rather than a flag on the call. The scripted model calls
    `mcp__kin__kin_mutate` by the name the belt exposes, names the entity rather
    than a path, and passes the change message as `summary`.
    """
    rc, _ = suite.agent(
        [completion("Raising mutable through Kin.", "mcp__kin__kin_mutate",
                    {"operations": [{"verb": "update", "target": "mutable",
                                     "body": MUTATE_BODY,
                                     "description": "raise mutable to 0x2c"}],
                     "summary": MUTATE_SUMMARY}),
         completion("mutable now returns 0x2c.")],
        env_extra={"KIN_AGENT_PURE_KIN": "1"})
    trace, result = suite.last_trace, suite.last_result
    messages = suite.change_messages()
    session = suite.mcp()
    try:
        listed = session.call("list_file_entities", {"path": "src/mutable.rs", "limit": 50})
        focal = entity_id(listed, "mutable")
        source = session.call("get_entity_source", {"entity_id": focal}) if focal else None
        status = session.call("kin_graph_status", {})
    finally:
        session.close()
    verdict, detail = grade_pure_kin_mutate_lands(rc, suite.read("src/mutable.rs"), source,
                                                  status, trace, result, messages)
    return Result("pure_kin_mutate_lands", verdict, "%s %s" % (TICKET, detail))


def check_edit_survives_a_daemon_restart(suite):
    stop = []
    rc, _ = suite.agent([completion("Documenting other.", "edit_file",
                                    {"path": "src/other.rs", "find": RESTART_FIND,
                                     "replace": RESTART_REPLACE}),
                         completion("other is documented.")],
                        before_first=lambda: stop.append(suite.stop_daemon()))
    session = suite.mcp()
    try:
        listed = session.call("list_file_entities", {"path": "src/other.rs", "limit": 50})
        focal = entity_id(listed, "other")
        source = session.call("get_entity_source", {"entity_id": focal}) if focal else None
        status = session.call("kin_graph_status", {})
    finally:
        session.close()
    verdict, detail = grade_edit_survives_a_daemon_restart(
        stop[0] if stop else None, rc, suite.read("src/other.rs"), source, status,
        suite.last_trace)
    return Result("edit_survives_a_daemon_restart", verdict, "%s %s" % (TICKET, detail))


CHECKS = [
    ("edit_lands", check_edit_lands),
    ("refused_edit_is_clean", check_refused_edit_is_clean),
    ("create_lands", check_create_lands),
    ("refused_create_is_clean", check_refused_create_is_clean),
    ("pure_kin_mutate_lands", check_pure_kin_mutate_lands),
    # Last, because it stops the daemon every earlier check ran against.
    ("edit_survives_a_daemon_restart", check_edit_survives_a_daemon_restart),
]


def report_payload(results):
    """The report shape `scripts/acceptance/gate.py` reads: keyed `results`, not `checks`."""
    return {"suite": "agent_write_publish", "ticket": TICKET,
            "results": [{"id": r.ident, "ticket": TICKET, "status": r.status,
                         "detail": r.detail} for r in results]}


def absolute_binary(path):
    """A binary path the fixtures can still find after they change directory."""
    return path and os.path.abspath(os.path.expanduser(path))


def self_test():
    failures = []
    checked = []

    def expect(what, got, want):
        checked.append(what)
        if got != want:
            failures.append("%s: got %s, want %s" % (what, got, want))

    recorded = {"_kin": {"durability": {"state": "recorded"}}}
    uncommitted = {"_kin": {"durability": {"state": "live_uncommitted"}}}
    new_source = {"source": "pub fn value() -> u8 {\n    0x2a\n}", "_kin": {}}
    old_source = {"source": "pub fn value() -> u8 {\n    1\n}", "_kin": {}}
    edited = EDIT_REPLACE + "\n"

    expect("edit lands",
           grade_edit_lands(0, edited, new_source, recorded)[0], PASS)
    expect("edit refused by the commit",
           grade_edit_lands(6, edited, old_source, uncommitted)[0], FAIL)
    expect("edit lands on disk only",
           grade_edit_lands(0, edited, old_source, recorded)[0], FAIL)
    expect("edit with no read-back",
           grade_edit_lands(0, edited, None, recorded)[0], UNREADABLE)

    told = ("The edit of `src/other.rs` did not land: repository authority did not publish "
            "it: ... Nothing was written, so `src/other.rs` is unchanged on disk and in the graph.")
    expect("refused edit, clean",
           grade_refused_edit_is_clean(6, OTHER_RS, OTHER_RS, told)[0], PASS)
    expect("refused edit left on disk",
           grade_refused_edit_is_clean(6, OTHER_RS, OTHER_RS.replace("pub fn kept", "/* pub fn kept"),
                                       told)[0], FAIL)
    expect("refused edit reported as a success",
           grade_refused_edit_is_clean(0, OTHER_RS, OTHER_RS, "Edited `src/other.rs`.")[0], FAIL)

    listed = {"entities": [{"name": "added", "id": "e1"}]}
    expect("create lands", grade_create_lands(0, CREATED_BODY, listed)[0], PASS)
    expect("create left no file", grade_create_lands(0, None, listed)[0], FAIL)
    expect("create not in the graph", grade_create_lands(0, CREATED_BODY, {"entities": []})[0],
           FAIL)

    handed_back = "`README.md` was not created: ... The 21 bytes you sent follow ...\n" + OVERWRITE_BODY
    expect("refused create, clean",
           grade_refused_create_is_clean(6, README, README, handed_back)[0], PASS)
    expect("refused create written anyway",
           grade_refused_create_is_clean(6, README, OVERWRITE_BODY, handed_back)[0], FAIL)
    expect("refused create without its content",
           grade_refused_create_is_clean(6, README, README, "did not publish it")[0], FAIL)

    mutated = MUTATE_BODY + "\n"
    mutated_source = {"source": MUTATE_BODY, "_kin": {}}
    stale_source = {"source": MUTABLE_RS, "_kin": {}}
    sessioned = [{"tool": "kin_mutate", "is_error": False,
                  "args": {"session_id": "s1", "summary": MUTATE_SUMMARY,
                           "operations": [{"verb": "update", "target": "mutable"}]}}]
    unsessioned = [{"tool": "kin_mutate", "is_error": False,
                    "args": {"summary": MUTATE_SUMMARY,
                             "operations": [{"verb": "update", "target": "mutable"}]}}]
    kin_only = {"kin_agent": {"entities_changed": ["mutable"], "files_changed": []}}
    said_it = [MUTATE_SUMMARY + "\n\nMCP transaction 0000", "MCP transaction 0001"]
    # The same sentence where a commit that folded pending working-tree content
    # puts it: the subject declares the fold and the caller's words open the
    # body. Whether an earlier check in this suite left anything pending is not
    # what this check is about, so both shapes have to read as "it said it".
    said_it_under_a_fold = ["MCP transaction 0000 (also admitted 1 pending working-tree file)"
                            "\n\n" + MUTATE_SUMMARY + "\n\nThe workspace already held ..."]
    said_nothing = ["MCP transaction 0000", "MCP transaction 0001"]

    expect("pure-kin mutate lands",
           grade_pure_kin_mutate_lands(0, mutated, mutated_source, recorded, sessioned,
                                       kin_only, said_it)[0], PASS)
    # The one this check exists for: the halves were green while the
    # composition was not, so a mutate that goes out unsessioned must be a
    # failure here and not merely a note.
    expect("pure-kin mutate went out with no session",
           grade_pure_kin_mutate_lands(0, mutated, mutated_source, recorded, unsessioned,
                                       kin_only, said_it)[0], FAIL)
    expect("pure-kin mutate said it under a fold",
           grade_pure_kin_mutate_lands(0, mutated, mutated_source, recorded, sessioned,
                                       kin_only, said_it_under_a_fold)[0], PASS)
    expect("pure-kin mutate recorded only the transaction line",
           grade_pure_kin_mutate_lands(0, mutated, mutated_source, recorded, sessioned,
                                       kin_only, said_nothing)[0], FAIL)
    expect("pure-kin mutate changed nothing in the graph",
           grade_pure_kin_mutate_lands(0, mutated, stale_source, recorded, sessioned,
                                       kin_only, said_it)[0], FAIL)
    expect("pure-kin run recorded a file it has no tool to change",
           grade_pure_kin_mutate_lands(0, mutated, mutated_source, recorded, sessioned,
                                       {"kin_agent": {"entities_changed": ["mutable"],
                                                      "files_changed": ["src/mutable.rs"]}},
                                       said_it)[0], FAIL)
    expect("pure-kin mutate made no mutate call",
           grade_pure_kin_mutate_lands(0, mutated, mutated_source, recorded, [],
                                       kin_only, said_it)[0], FAIL)
    expect("pure-kin mutate with no log to read",
           grade_pure_kin_mutate_lands(0, mutated, mutated_source, recorded, sessioned,
                                       kin_only, None)[0], UNREADABLE)

    stopped = (0, "the daemon on port 1 stopped")
    other_edited = OTHER_RS.replace(RESTART_FIND, RESTART_REPLACE)
    new_other = {"source": RESTART_REPLACE, "_kin": {}}
    old_other = {"source": RESTART_FIND, "_kin": {}}
    committed = {"surface": "local", "tool": "edit_file",
                 "provenance": {"bracketed": True, "closed_with": "kin_transaction_commit",
                                "closed_cleanly": True}}
    reopened = [{"tool": "kin_session_start"},
                {"tool": "kin_transaction_begin", "is_error": True,
                 "detail": "Session not found: s1. It was ended or expired after its idle "
                           "timeout."},
                {"tool": "kin_session_start"}, {"tool": "kin_transaction_begin"},
                {"tool": "kin_transaction_stage"}, {"tool": "kin_transaction_commit"},
                committed]
    written_locally = [{"tool": "kin_session_start"},
                       {"tool": "kin_transaction_begin", "is_error": True,
                        "detail": "Session not found: s1."},
                       {"surface": "local", "tool": "edit_file",
                        "provenance": {"bracketed": False, "reason": "Session not found: s1."}}]
    expect("edit survives a restart",
           grade_edit_survives_a_daemon_restart(stopped, 0, other_edited, new_other, recorded,
                                                reopened)[0], PASS)
    expect("restart ends in a local write",
           grade_edit_survives_a_daemon_restart(stopped, 0, other_edited, old_other,
                                                uncommitted, written_locally)[0], FAIL)
    expect("restart ends in a refusal",
           grade_edit_survives_a_daemon_restart(stopped, 6, OTHER_RS, old_other, recorded,
                                                written_locally)[0], FAIL)
    expect("restart's local write picked up only by the reconcile loop",
           grade_edit_survives_a_daemon_restart(stopped, 0, other_edited, new_other, recorded,
                                                written_locally)[0], FAIL)
    expect("restart never happened",
           grade_edit_survives_a_daemon_restart((1, "kin daemon stop exited 1"), 0,
                                                other_edited, new_other, recorded,
                                                reopened)[0], UNREADABLE)

    report = report_payload([Result("edit_lands", PASS, "x")])
    expect("report keyed results", sorted(report), ["results", "suite", "ticket"])
    expect("report row id", report["results"][0]["id"], "edit_lands")

    for failure in failures:
        print("SELF-TEST FAIL %s" % failure)
    print("SELF-TEST %s (%d expectations)" % ("FAIL" if failures else "PASS", len(checked)))
    return 1 if failures else 0


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kin", default=os.environ.get("KIN_BIN") or shutil.which("kin"))
    parser.add_argument("--daemon", default=os.environ.get("KIN_DAEMON_BIN"))
    parser.add_argument("--json", dest="json_path")
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    opts = parser.parse_args(argv)

    if opts.self_test:
        return self_test()

    if not opts.kin:
        print("SETUP no kin binary: pass --kin or set KIN_BIN")
        return 3
    opts.kin = absolute_binary(opts.kin)
    opts.daemon = absolute_binary(opts.daemon)

    workdir = tempfile.mkdtemp(prefix="agent-write-publish-")
    suite = Suite(opts.kin, workdir, daemon=opts.daemon, verbose=opts.verbose)
    try:
        results = []
        for ident, check in CHECKS:
            try:
                results.append(check(suite))
            except Exception as error:  # noqa: BLE001 - a setup failure is not a verdict
                results.append(Result(ident, UNREADABLE, "%s check raised: %s" % (TICKET, error)))
        for result in results:
            print("CHECK %s %s %s %s" % (result.ident, TICKET, result.status, result.detail))
        if opts.json_path:
            directory = os.path.dirname(os.path.abspath(opts.json_path))
            if directory and not os.path.isdir(directory):
                os.makedirs(directory)
            with open(opts.json_path, "w") as handle:
                json.dump(report_payload(results), handle, indent=2)
        if [r.ident for r in results] != [ident for ident, _ in CHECKS]:
            print("SETUP the checks asked and the checks answered differ")
            return 3
        if any(result.status == FAIL for result in results):
            return 1
        if any(result.status == UNREADABLE for result in results):
            return 2
        return 0
    finally:
        try:
            if suite._repo:
                run([opts.kin, "daemon", "stop"], cwd=suite._repo, env=suite.env, timeout=180)
        except Exception:  # noqa: BLE001 - teardown must not change the verdict
            pass
        if not opts.keep:
            shutil.rmtree(workdir, ignore_errors=True)
        else:
            print("kept fixtures under %s" % workdir)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
