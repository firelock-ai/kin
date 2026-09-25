#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
"""Prove an agent's change reaches graph authority, and a refused one leaves nothing behind.

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

The agent's file tools have since been retired. It changes code only through `kin_mutate`,
naming the entity it changes, so every check drives an entity operation. The suite reads
each target's entity id and `source_base` over its own `kin mcp start` session and scripts
the model to send them back, as a model that had just read the entity would.

Six checks, one repository, run in order:

  edit_lands            an anchored `EntitySourcePatch` on a tracked function commits: the
                        run exits 0, the file holds the new text, `get_entity_source`
                        answers with the new body, the durability block reads `recorded`,
                        and the change went out as a `kin_mutate` patch with no file tool
  refused_edit_is_clean a patch authority refuses (an unterminated comment that hides a
                        declaration, which the planner rejects) leaves the file and the
                        entity exactly as they were, the model is told it did not land, and
                        the run records no entity changed. The run exits 0: a refused
                        change is an error result the model reads, and the run ends on the
                        model's own answer
  create_lands          an `EntityCreate` that puts a new function in a new source unit
                        beside a Python anchor commits: the unit holds the declaration, the
                        graph lists the function, `get_entity_source` serves it, and
                        durability reads `recorded`
  refused_create_is_clean
                        an `EntityCreate` whose generated source unit a tracked file already
                        holds is refused: the tracked file keeps its text, the function
                        never reaches the graph, the model is told why, and the declaration
                        it sent stays in the conversation it goes on with
  pure_kin_mutate_lands one `kin_mutate` naming the ENTITY by its UUID, with the
                        `source_base` a read returned for it, commits: the file and
                        `get_entity_source` carry it, durability reads `recorded`, the run
                        records that entity in `entities_changed` and no file, the call went
                        out under a session the harness supplied (the model never sees
                        `kin_session_start`), and `kin log` carries the agent's own summary
                        rather than the bare transaction line
  edit_survives_a_daemon_restart
                        the repository's daemon is stopped after the agent's session opens
                        and before its first change, as an unattended update did in the
                        demo's real-model run. Sessions live in the daemon, so the session
                        the harness opened is gone, and the change must commit through Kin
                        anyway. A whole-body `update` guarded by the entity's `source_base`
                        is sent; the run exits 0, the file and `get_entity_source` carry it,
                        durability reads `recorded`, the last `kin_mutate` came back clean,
                        and no file tool was used

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
import re
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

# A Python module beside the crate, because a new source unit is created next to a
# Python or Go anchor. Rust has no module-owner creation yet, so a new Rust function can
# only be placed beside an existing one.
PY_GREET = "def greet():\n    return 1\n"
PY_TAKEN = "def keep_me():\n    return 9\n"

# The anchored patch `edit_lands` sends, and the body it leaves.
EDIT_FIND = "pub fn value() -> u8 {\n    1\n}"
EDIT_EDITS = [{"old_text": "pub fn value", "new_text": "/// The value this module reports.\npub fn value"},
              {"old_text": "    1\n", "new_text": "    0x2a\n"}]
EDIT_REPLACE = "/// The value this module reports.\npub fn value() -> u8 {\n    0x2a\n}"
EDIT_MARKER = "0x2a"

# An unterminated block comment swallows `kept`, so the new text parses incomplete and the
# planner refuses to publish a deletion it cannot verify. Deterministic, and independent
# of the daemon's reconcile timing, which a drift-based refusal would race.
REFUSED_FIND = "pub fn kept() -> u8 {"
REFUSED_REPLACE = "/* pub fn kept() -> u8 {"

# A new function in a new source unit, which Kin places beside its Python anchor.
CREATED_NAME = "added"
CREATED_PATH = "py/added.py"
CREATED_DECLARATION = "def added():\n    return 3"
CREATED_BODY = CREATED_DECLARATION + "\n"
# A new source unit whose generated path a tracked file already holds, so creating it
# would overwrite that file. Kin refuses it and overwrites nothing.
TAKEN_NAME = "taken"
TAKEN_PATH = "py/taken.py"
TAKEN_DECLARATION = "def taken():\n    return 8"

# The edit made after the daemon is restarted, on a function no earlier check changes. It
# is a whole-body update guarded by the source base the suite read before the run.
RESTART_FIND = "pub fn other() -> u8 {\n    4\n}"
RESTART_REPLACE = "/// The other value.\npub fn other() -> u8 {\n    0x2b\n}"
RESTART_MARKER = "0x2b"

# How a run ends when Kin refuses its change. The refusal is an error result the model
# reads, and the run then ends on the model's own answer, so the process exits 0; the
# record is what says nothing landed: an errored kin_mutate and no entity changed.
REFUSED_CHANGE_EXIT = 0

# What Kin tells the model when it refuses to overwrite a tracked source unit: "the
# generated source unit is already occupied; no existing artifact was overwritten".
CREATE_REFUSAL = "already occupied"

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


def received(value, limit=240):
    """What a grader was actually handed, short enough for one CHECK line.

    Every mismatch names this rather than a fixed phrase, so a refusal, an ambiguity list
    or an unreadable reply can never read as "the old body".
    """
    text = value if isinstance(value, str) else json.dumps(value, sort_keys=True)
    text = " ".join(text.split())
    return text if len(text) <= limit else text[:limit] + "..."


def mutate_rows(trace):
    """Every `kin_mutate` call the run made, as the trace recorded it."""
    return [row for row in (trace or []) if row.get("tool") == "kin_mutate"]


def entity_change_problems(trace, verb, lands=True):
    """What is wrong with how a run sent its change.

    A change goes out as a `kin_mutate` operation with this verb and nothing else: a row
    for a file tool, or for the local surface file tools used to take, is a change made
    outside the graph. A change that lands ends on a clean `kin_mutate`; a refused one
    comes back an error on every call that carried it.
    """
    problems = []
    if any(row.get("tool") in ("edit_file", "write_file") or row.get("surface") == "local"
           for row in trace):
        problems.append("the run used a file tool")
    calls = mutate_rows(trace)
    carried = [row for row in calls
               if any(op.get("verb") == verb
                      for op in ((row.get("args") or {}).get("operations") or []))]
    if not carried:
        problems.append("no kin_mutate call carried a %r operation" % verb)
    elif lands and carried[-1].get("is_error"):
        problems.append("the %s came back an error: %s" % (verb, received(carried[-1])))
    elif not lands and not all(row.get("is_error") for row in carried):
        problems.append("a kin_mutate carrying the refused %s came back clean" % verb)
    return problems


def says_it_did_not_land(tool_result, tool_error):
    """Whether the model was told its change did not land.

    Kin answers a refused `kin_mutate` with an error result that carries its reason, and
    one that landed with a receipt naming what it applied. The model is told the change
    failed when it reads the error flag and a reason; a result that reads as a receipt
    told it the opposite.
    """
    if not tool_error or not (tool_result or "").strip():
        return False
    try:
        payload = json.loads(tool_result)
    except ValueError:
        return True
    return not (isinstance(payload, dict)
                and ("ops_applied" in payload or payload.get("committed") is True))


def recorded_changes(result):
    """The entities a run says it changed, or None when its record is unreadable."""
    agent = (result or {}).get("kin_agent")
    if not isinstance(agent, dict):
        return None
    return agent.get("entities_changed")


def conversation_carries(request, needle):
    """Whether a request the model sent still holds `needle` in a call it made earlier.

    The model keeps its own work in its conversation: every later request carries the
    tool calls it already made, arguments included. Arguments travel as a JSON string, so
    they are decoded before they are searched.
    """
    for message in (request or {}).get("messages") or []:
        for call in message.get("tool_calls") or []:
            arguments = (call.get("function") or {}).get("arguments")
            try:
                decoded = json.loads(arguments) if isinstance(arguments, str) else arguments
            except ValueError:
                decoded = arguments
            if mentions(decoded, needle):
                return True
    return False


def grade_edit_lands(rc, disk, source_payload, status_payload, trace):
    if rc is None or disk is None or source_payload is None or status_payload is None \
            or trace is None:
        return UNREADABLE, "the run or its read-back produced nothing to grade"
    problems = []
    if rc != 0:
        problems.append("kin agent run exited %s, not 0" % rc)
    if EDIT_MARKER not in disk:
        problems.append("the file on disk does not carry the edit: %s" % received(disk))
    if not mentions(source_payload, EDIT_MARKER):
        problems.append("get_entity_source answered without the edit: %s"
                        % received(source_payload))
    state = durability_state(status_payload)
    if state != "recorded":
        problems.append("durability reads %r, not 'recorded'" % state)
    problems.extend(entity_change_problems(trace, "patch"))
    if problems:
        return FAIL, "; ".join(problems)
    return PASS, "the entity patch committed: disk, get_entity_source and durability agree"


def grade_pure_kin_mutate_lands(rc, disk, source_payload, status_payload, trace, result,
                                messages, entity):
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
        problems.append("the file on disk does not carry the mutation: %s" % received(disk))
    if not mentions(source_payload, MUTATE_MARKER):
        problems.append("get_entity_source answered without the mutation: %s"
                        % received(source_payload))
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

    # The run records the entity as the agent named it, which is its UUID.
    agent = (result.get("kin_agent") or {})
    if agent.get("entities_changed") != [entity]:
        problems.append("the run recorded entities_changed=%r, not [%r] (mutable)"
                        % (agent.get("entities_changed"), entity))
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


def grade_refused_edit_is_clean(rc, disk_before, disk_after, source_before, source_after,
                                tool_result, tool_error, trace, result):
    if rc is None or disk_after is None or tool_result is None or source_before is None \
            or source_after is None or trace is None or result is None:
        return UNREADABLE, "the run produced nothing to grade"
    problems = []
    if rc != REFUSED_CHANGE_EXIT:
        problems.append("kin agent run exited %s, not %s" % (rc, REFUSED_CHANGE_EXIT))
    if disk_after != disk_before:
        problems.append("the refused edit changed the file on disk: %s" % received(disk_after))
    if (source_after or {}).get("body") != (source_before or {}).get("body") \
            or mentions(source_after, REFUSED_REPLACE):
        problems.append("the refused edit changed the entity in the graph: %s"
                        % received(source_after))
    if not says_it_did_not_land(tool_result, tool_error):
        problems.append("the model was not told the edit did not land (is_error=%s): %s"
                        % (tool_error, received(tool_result)))
    problems.extend(entity_change_problems(trace, "patch", lands=False))
    if recorded_changes(result) != []:
        problems.append("the run recorded the refused entity as changed: %r"
                        % (recorded_changes(result),))
    if problems:
        return FAIL, "; ".join(problems)
    return PASS, ("the refused entity patch left the file and the graph untouched and the model "
                  "was told")


def grade_create_lands(rc, disk, listed_payload, source_payload, status_payload, trace):
    if rc is None or listed_payload is None or source_payload is None \
            or status_payload is None or trace is None:
        return UNREADABLE, "the run or its read-back produced nothing to grade"
    problems = []
    if rc != 0:
        problems.append("kin agent run exited %s, not 0" % rc)
    if disk != CREATED_BODY:
        problems.append("the created source unit is missing or holds other bytes: %s"
                        % received(disk))
    if not functions_named(listed_payload, CREATED_NAME, CREATED_PATH):
        problems.append("the graph does not list the created function: %s"
                        % received(listed_payload))
    if not mentions(source_payload, CREATED_DECLARATION):
        problems.append("get_entity_source did not answer with the created declaration: %s"
                        % received(source_payload))
    state = durability_state(status_payload)
    if state != "recorded":
        problems.append("durability reads %r, not 'recorded'" % state)
    problems.extend(entity_change_problems(trace, "create"))
    if problems:
        return FAIL, "; ".join(problems)
    return PASS, ("the created function committed in a new source unit: disk, the graph and "
                  "durability agree")


def grade_refused_create_is_clean(rc, disk_before, disk_after, listed_after, tool_result,
                                  tool_error, next_request, trace, result):
    if rc is None or disk_after is None or tool_result is None or listed_after is None \
            or next_request is None or trace is None or result is None:
        return UNREADABLE, "the run produced nothing to grade"
    problems = []
    if rc != REFUSED_CHANGE_EXIT:
        problems.append("kin agent run exited %s, not %s" % (rc, REFUSED_CHANGE_EXIT))
    if disk_after != disk_before:
        problems.append("the refused create changed the tracked file: %s" % received(disk_after))
    if functions_named(listed_after, TAKEN_NAME):
        problems.append("the refused function reached the graph: %s" % received(listed_after))
    if not tool_error or CREATE_REFUSAL not in tool_result:
        problems.append("the refusal did not come back to the model (is_error=%s): %s"
                        % (tool_error, received(tool_result)))
    if not conversation_carries(next_request, TAKEN_DECLARATION):
        problems.append("the refused declaration is not in the conversation the model went on "
                        "with")
    problems.extend(entity_change_problems(trace, "create", lands=False))
    if recorded_changes(result) != []:
        problems.append("the run recorded the refused function as changed: %r"
                        % (recorded_changes(result),))
    if problems:
        return FAIL, "; ".join(problems)
    return PASS, ("the refused create left the tracked file and the graph alone, and the model "
                  "kept its declaration and was told why")


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
        problems.append("the file on disk does not carry the edit: %s" % received(disk))
    if not mentions(source_payload, RESTART_MARKER):
        problems.append("get_entity_source answered without the edit: %s"
                        % received(source_payload))
    state = durability_state(status_payload)
    if state != "recorded":
        problems.append("durability reads %r, not 'recorded'" % state)
    # A `kin_mutate` is one transaction, begun and committed by the server, so a clean one
    # is the edit committed through a transaction and an errored one is not.
    problems.extend(entity_change_problems(trace, "update"))
    if problems:
        return FAIL, "; ".join(problems)
    sessions = sum(1 for row in trace if row.get("tool") == "kin_session_start")
    how = ("the harness opened a new session after the restart" if sessions >= 2
           else "the session outlived the restart")
    return PASS, "the entity update committed through Kin after a daemon restart; %s" % how


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
        # Every request the agent sent, in order, so a check can read what the model
        # still held when it asked for its next answer.
        self.requests = requests = []

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
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                with lock:
                    try:
                        requests.append(json.loads(body.decode() or "null"))
                    except ValueError:
                        requests.append(None)
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

    def lookup(self, name):
        """`get_entity_source` given a name, the strict name resolution Kin serves.

        One exact name answers with that entity. A name several entities carry answers
        `ambiguous_focal` with every candidate and no body. A refusal arrives as prose, bare
        or inside the envelope's `message`, and two of them are answers rather than
        failures: a name nothing carries, read as `{"not_found": true}`, and a name only a
        whole-file module node carries (a file's module shares its stem), read as
        `{"module_node": {"id": ..., "name": ...}}`. None means the reply could not be read.
        """
        result = self.request("tools/call", {"name": "get_entity_source",
                                             "arguments": {"entity_id": name}})
        answer = result.get("result") or {}
        text = "".join(block.get("text", "") for block in answer.get("content") or [])
        try:
            payload = json.loads(text)
        except ValueError:
            payload = None
        if not answer.get("isError"):
            return payload
        message = payload.get("message") if isinstance(payload, dict) else text
        return refusal_answer(message, name)

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
        self.last_requests = None
        self.last_tool_error = None

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
            os.makedirs(os.path.join(path, "py"))
            for relative, body in (("src/lib.rs", LIB_RS), ("src/other.rs", OTHER_RS),
                                   ("src/mutable.rs", MUTABLE_RS),
                                   ("py/greet.py", PY_GREET), (TAKEN_PATH, PY_TAKEN),
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

        Returns the exit code and the last tool result the model was sent. Keeps the run's
        kin-trace rows on `last_trace`, its result record on `last_result`, whether that
        last tool result was an error on `last_tool_error`, and every request the agent
        sent its model on `last_requests`.

        `env_extra` sets environment for this one run, which is how a check names a
        setting the agent reads per process.
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
        self.last_requests = endpoint.requests
        tool_result = None
        self.last_tool_error = None
        transcript = os.path.join(out, "transcript.jsonl")
        if os.path.exists(transcript):
            with open(transcript) as handle:
                for line in handle:
                    record = json.loads(line)
                    for block in (record.get("message") or {}).get("content") or []:
                        if isinstance(block, dict) and block.get("type") == "tool_result":
                            tool_result = block.get("content")
                            self.last_tool_error = bool(block.get("is_error"))
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


# How Kin words the two refusals a strict name lookup can answer with. An absence is
# "no entity found matching '<name>'. ..." from the daemon, or exactly
# "Entity not found: <name>" from the in-process handler; either names what was asked.
NOT_FOUND_MATCHING = "no entity found matching '%s'"
NOT_FOUND_EXACT = "Entity not found: %s"
MODULE_NODE_REFUSAL = re.compile(
    r"^entity '(?P<name>[^']*)' \((?P<id>[0-9a-fA-F-]{36})\) exists in the graph but has no "
    r"retrievable source: .* is an import/module relationship node for a whole file")


def refusal_answer(message, name):
    """What a refused name lookup says about `name`: absent, a module node, or unreadable.

    Only a refusal about exactly `name` counts, so another entity's words cannot stand in
    for this one.
    """
    if not isinstance(message, str):
        return None
    if message.startswith(NOT_FOUND_MATCHING % name) \
            or message.strip() == NOT_FOUND_EXACT % name:
        return {"not_found": True}
    match = MODULE_NODE_REFUSAL.match(message)
    if match and match.group("name") == name:
        return {"module_node": {"id": match.group("id"), "name": name}}
    return None


def entity_rows(reply):
    """The entities a strict name lookup reached, one row each: id, name, kind and file.

    An exact answer is one row; an `ambiguous_focal` answer is every candidate it lists.
    A caller picks among them by name, kind and file, never by rank, so a name two
    entities share cannot stand for the wrong one. [] is a name nothing carries. None is
    a reply that could not be read, including a candidate list cut short.
    """
    if not isinstance(reply, dict):
        return None
    if reply.get("not_found"):
        return []
    if reply.get("module_node"):
        node = reply["module_node"]
        return [{"id": node.get("id"), "name": node.get("name"), "kind": "module",
                 "file_path": None}]
    if reply.get("ambiguous_focal"):
        candidates = reply.get("candidates") or []
        if reply.get("candidate_count") != len(candidates):
            return None
        return [{"id": row.get("entity_id"), "name": row.get("name"), "kind": row.get("kind"),
                 "file_path": row.get("file_path")} for row in candidates]
    if reply.get("id"):
        return [{"id": reply.get("id"), "name": reply.get("name"), "kind": reply.get("kind"),
                 "file_path": reply.get("file_path")}]
    return None


def functions_named(rows, name, path=None):
    """The rows that are a function named exactly `name`, in `path` when one is named."""
    return [row for row in rows or []
            if row.get("name") == name and str(row.get("kind", "")).lower() == "function"
            and (path is None or row.get("file_path") == path)]


# The name the agent's belt gives Kin's one write tool.
MUTATE = "mcp__kin__kin_mutate"


def read_back(suite, path, name, status=True):
    """Find the function `name` in `path`, read it, and read the graph status, over one
    session.

    Returns the rows the exact-name lookup reached, the function's entity id, its
    `get_entity_source` answer by that id (which carries the `source_base` a guarded
    change names) and the status, each None when Kin did not answer it. The id is set
    only when exactly one function of that name lives in `path`.
    """
    session = suite.mcp()
    try:
        rows = entity_rows(session.lookup(name))
        matches = functions_named(rows, name, path)
        focal = matches[0]["id"] if len(matches) == 1 else None
        source = session.call("get_entity_source", {"entity_id": focal}) if focal else None
        state = session.call("kin_graph_status", {}) if status else None
    finally:
        session.close()
    return rows, focal, source, state


def mutate_call(text, operation, summary):
    """A scripted turn that sends one entity operation through `kin_mutate`."""
    return completion(text, MUTATE, {"operations": [operation], "summary": summary})


def unreadable_base(ident, name):
    return Result(ident, UNREADABLE, "%s the suite could not read %s's entity id and source base"
                  % (TICKET, name))


def check_edit_lands(suite):
    _, focal, before, _ = read_back(suite, "src/lib.rs", "value", status=False)
    base = (before or {}).get("source_base")
    if not focal or not base:
        return unreadable_base("edit_lands", "value")
    rc, _ = suite.agent([mutate_call("Documenting value.",
                                     {"verb": "patch", "target": focal,
                                      "payload": {"EntitySourcePatch": {"source_base": base,
                                                                        "edits": EDIT_EDITS}},
                                      "description": "document value and raise it to 0x2a"},
                                     "Document value and raise it to 0x2a"),
                         completion("value is documented.")])
    trace = suite.last_trace
    _, _, source, status = read_back(suite, "src/lib.rs", "value")
    verdict, detail = grade_edit_lands(rc, suite.read("src/lib.rs"), source, status, trace)
    return Result("edit_lands", verdict, "%s %s" % (TICKET, detail))


def check_refused_edit_is_clean(suite):
    before = suite.read("src/other.rs")
    _, focal, source_before, _ = read_back(suite, "src/other.rs", "kept", status=False)
    base = (source_before or {}).get("source_base")
    if not focal or not base:
        return unreadable_base("refused_edit_is_clean", "kept")
    rc, tool_result = suite.agent([mutate_call("Commenting out kept.",
                                               {"verb": "patch", "target": focal,
                                                "payload": {"EntitySourcePatch": {
                                                    "source_base": base,
                                                    "edits": [{"old_text": REFUSED_FIND,
                                                               "new_text": REFUSED_REPLACE}]}},
                                                "description": "comment out kept"},
                                               "Comment out kept"),
                                   completion("kept is commented out.")])
    tool_error, trace, result = suite.last_tool_error, suite.last_trace, suite.last_result
    _, _, source_after, _ = read_back(suite, "src/other.rs", "kept", status=False)
    verdict, detail = grade_refused_edit_is_clean(rc, before, suite.read("src/other.rs"),
                                                  source_before, source_after, tool_result,
                                                  tool_error, trace, result)
    return Result("refused_edit_is_clean", verdict, "%s %s" % (TICKET, detail))


def check_create_lands(suite):
    _, anchor, anchor_source, _ = read_back(suite, "py/greet.py", "greet", status=False)
    base = (anchor_source or {}).get("source_base")
    if not anchor or not base:
        return unreadable_base("create_lands", "greet")
    rc, _ = suite.agent([mutate_call("Adding a module.",
                                     {"verb": "create", "target": anchor,
                                      "payload": {"EntityCreate": {
                                          "source_base": base, "name": CREATED_NAME,
                                          "kind": "function", "body": CREATED_DECLARATION,
                                          "placement": "new_source_unit"}},
                                      "description": "add added in its own source unit"},
                                     "Add added in its own source unit"),
                         completion("py/added.py holds added.")])
    trace = suite.last_trace
    listed, _, created, status = read_back(suite, CREATED_PATH, CREATED_NAME)
    verdict, detail = grade_create_lands(rc, suite.read(CREATED_PATH), listed, created, status,
                                         trace)
    return Result("create_lands", verdict, "%s %s" % (TICKET, detail))


def check_refused_create_is_clean(suite):
    before = suite.read(TAKEN_PATH)
    _, anchor, anchor_source, _ = read_back(suite, "py/greet.py", "greet", status=False)
    base = (anchor_source or {}).get("source_base")
    if not anchor or not base:
        return unreadable_base("refused_create_is_clean", "greet")
    rc, tool_result = suite.agent([mutate_call("Adding taken.",
                                               {"verb": "create", "target": anchor,
                                                "payload": {"EntityCreate": {
                                                    "source_base": base, "name": TAKEN_NAME,
                                                    "kind": "function",
                                                    "body": TAKEN_DECLARATION,
                                                    "placement": "new_source_unit"}},
                                                "description": "add taken in its own source unit"},
                                               "Add taken in its own source unit"),
                                   completion("py/taken.py holds taken.")])
    tool_error, trace, result = suite.last_tool_error, suite.last_trace, suite.last_result
    # The request after the refusal is the conversation the model went on with.
    requests = suite.last_requests or []
    next_request = requests[1] if len(requests) > 1 else None
    listed, _, _, _ = read_back(suite, TAKEN_PATH, TAKEN_NAME, status=False)
    verdict, detail = grade_refused_create_is_clean(rc, before, suite.read(TAKEN_PATH), listed,
                                                    tool_result, tool_error, next_request,
                                                    trace, result)
    return Result("refused_create_is_clean", verdict, "%s %s" % (TICKET, detail))


def check_pure_kin_mutate_lands(suite):
    """Drive the belt the founder asked for: Kin tools, and nothing else.

    `KIN_AGENT_PURE_KIN` is read per process, so this is the same binary run a
    second time rather than a flag on the call. The scripted model calls
    `mcp__kin__kin_mutate` by the name the belt exposes, names the entity by its
    UUID with the `source_base` a read returned for it rather than a path, and
    passes the change message as `summary`.
    """
    _, focal, before, _ = read_back(suite, "src/mutable.rs", "mutable", status=False)
    base = (before or {}).get("source_base")
    if not focal or not base:
        return unreadable_base("pure_kin_mutate_lands", "mutable")
    rc, _ = suite.agent(
        [completion("Raising mutable through Kin.", "mcp__kin__kin_mutate",
                    {"operations": [{"verb": "update", "target": focal,
                                     "payload": {"EntitySourceBase": base},
                                     "body": MUTATE_BODY,
                                     "description": "raise mutable to 0x2c"}],
                     "summary": MUTATE_SUMMARY}),
         completion("mutable now returns 0x2c.")],
        env_extra={"KIN_AGENT_PURE_KIN": "1"})
    trace, result = suite.last_trace, suite.last_result
    messages = suite.change_messages()
    _, _, source, status = read_back(suite, "src/mutable.rs", "mutable")
    verdict, detail = grade_pure_kin_mutate_lands(rc, suite.read("src/mutable.rs"), source,
                                                  status, trace, result, messages, focal)
    return Result("pure_kin_mutate_lands", verdict, "%s %s" % (TICKET, detail))


def check_edit_survives_a_daemon_restart(suite):
    _, focal, before, _ = read_back(suite, "src/other.rs", "other", status=False)
    base = (before or {}).get("source_base")
    if not focal or not base:
        return unreadable_base("edit_survives_a_daemon_restart", "other")
    stop = []
    rc, _ = suite.agent([mutate_call("Documenting other.",
                                     {"verb": "update", "target": focal,
                                      "payload": {"EntitySourceBase": base},
                                      "body": RESTART_REPLACE,
                                      "description": "document other and raise it to 0x2b"},
                                     "Document other and raise it to 0x2b"),
                         completion("other is documented.")],
                        before_first=lambda: stop.append(suite.stop_daemon()))
    trace = suite.last_trace
    _, _, source, status = read_back(suite, "src/other.rs", "other")
    verdict, detail = grade_edit_survives_a_daemon_restart(
        stop[0] if stop else None, rc, suite.read("src/other.rs"), source, status, trace)
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

    def mutation(verb, is_error=False):
        return {"tool": "kin_mutate", "surface": "kin", "is_error": is_error,
                "args": {"session_id": "s1", "operations": [{"verb": verb, "target": "e1"}]}}

    session = {"tool": "kin_session_start"}
    patched = [session, mutation("patch")]
    patch_refused = [session, mutation("patch", is_error=True)]
    by_edit_file = patched + [{"surface": "local", "tool": "edit_file"}]

    expect("edit lands",
           grade_edit_lands(0, edited, new_source, recorded, patched)[0], PASS)
    expect("edit refused by the commit",
           grade_edit_lands(6, edited, old_source, uncommitted, patch_refused)[0], FAIL)
    expect("edit lands on disk only",
           grade_edit_lands(0, edited, old_source, recorded, patched)[0], FAIL)
    expect("edit with no read-back",
           grade_edit_lands(0, edited, None, recorded, patched)[0], UNREADABLE)
    expect("edit with no trace",
           grade_edit_lands(0, edited, new_source, recorded, None)[0], UNREADABLE)
    expect("edit that also went through a file tool",
           grade_edit_lands(0, edited, new_source, recorded, by_edit_file)[0], FAIL)
    expect("edit sent as no entity patch",
           grade_edit_lands(0, edited, new_source, recorded, [session, mutation("update")])[0],
           FAIL)
    expect("edit whose patch came back an error",
           grade_edit_lands(0, edited, new_source, recorded, patch_refused)[0], FAIL)

    kept = {"body": "pub fn kept() -> u8 {\n    5\n}", "_kin": {}}
    commented = {"body": REFUSED_REPLACE + "\n    5\n}", "_kin": {}}
    refusal = ("reparsed exact bytes did not preserve existing entity 00000000-0000-4000-8000-"
               "000000000001")
    receipt = json.dumps({"transaction_id": "t1", "ops_applied": 1})
    nothing_changed = {"kin_agent": {"entities_changed": []}}
    kept_changed = {"kin_agent": {"entities_changed": ["kept"]}}
    commented_out = OTHER_RS.replace("pub fn kept", "/* pub fn kept")

    def refused_edit(**changes):
        args = dict(rc=REFUSED_CHANGE_EXIT, disk_before=OTHER_RS, disk_after=OTHER_RS,
                    source_before=kept, source_after=kept, tool_result=refusal,
                    tool_error=True, trace=patch_refused, result=nothing_changed)
        args.update(changes)
        return grade_refused_edit_is_clean(**args)[0]

    expect("refused edit, clean", refused_edit(), PASS)
    expect("refused edit left on disk", refused_edit(disk_after=commented_out), FAIL)
    expect("refused edit reached the graph", refused_edit(source_after=commented), FAIL)
    expect("refused edit reported without the error flag", refused_edit(tool_error=False), FAIL)
    expect("refused edit reported as a receipt", refused_edit(tool_result=receipt), FAIL)
    expect("refused edit with an empty answer", refused_edit(tool_result="  "), FAIL)
    expect("refused edit recorded as a change", refused_edit(result=kept_changed), FAIL)
    expect("refused patch came back clean", refused_edit(trace=patched), FAIL)
    expect("refused edit through a file tool", refused_edit(trace=by_edit_file), FAIL)
    expect("refused edit run that crashed", refused_edit(rc=1), FAIL)
    expect("refused edit with no read-back", refused_edit(source_after=None), UNREADABLE)

    created_listed = [{"id": "m2", "name": CREATED_NAME, "kind": "Module",
                       "file_path": CREATED_PATH},
                      {"id": "e2", "name": CREATED_NAME, "kind": "Function",
                       "file_path": CREATED_PATH}]
    created_source = {"body": CREATED_DECLARATION, "_kin": {}}
    created = [session, mutation("create")]
    create_refused = [session, mutation("create", is_error=True)]
    by_write_file = created + [{"surface": "local", "tool": "write_file"}]

    def create(**changes):
        args = dict(rc=0, disk=CREATED_BODY, listed_payload=created_listed,
                    source_payload=created_source, status_payload=recorded, trace=created)
        args.update(changes)
        return grade_create_lands(**args)[0]

    expect("create lands", create(), PASS)
    expect("create left no file", create(disk=None), FAIL)
    expect("create wrote other bytes", create(disk="def added():\n    pass\n"), FAIL)
    expect("create not in the graph", create(listed_payload=[]), FAIL)
    expect("create reached only as its source unit's module",
           create(listed_payload=created_listed[:1]), FAIL)
    expect("create listed in another unit",
           create(listed_payload=[dict(created_listed[1], file_path="py/greet.py")]), FAIL)
    expect("create not served by get_entity_source",
           create(source_payload={"body": "", "_kin": {}}), FAIL)
    expect("create not durable", create(status_payload=uncommitted), FAIL)
    expect("create through a file tool", create(trace=by_write_file), FAIL)
    expect("create refused", create(rc=0, trace=create_refused), FAIL)
    expect("create run that crashed", create(rc=1), FAIL)
    expect("create with no read-back", create(source_payload=None), UNREADABLE)

    occupied = ("the generated source unit is already occupied; no existing artifact was "
                "overwritten")
    # The tracked unit's module is named for its file, so the lookup reaches it. It is
    # not the function the refused create named, and a lookup that reaches only it is
    # clean.
    kept_listed = [{"id": "m1", "name": TAKEN_NAME, "kind": "Module", "file_path": TAKEN_PATH}]
    reached_listed = kept_listed + [{"id": "e4", "name": TAKEN_NAME, "kind": "Function",
                                     "file_path": TAKEN_PATH}]
    sent = json.dumps({"operations": [{"verb": "create", "payload": {"EntityCreate": {
        "name": TAKEN_NAME, "body": TAKEN_DECLARATION}}}]})
    went_on = {"messages": [{"role": "assistant", "content": "Adding taken.",
                             "tool_calls": [{"id": "c1", "type": "function",
                                             "function": {"name": MUTATE, "arguments": sent}}]},
                            {"role": "tool", "tool_call_id": "c1", "content": occupied}]}
    forgot = {"messages": [{"role": "user", "content": "Make the change."}]}
    taken_changed = {"kin_agent": {"entities_changed": [TAKEN_NAME]}}

    def refused_create(**changes):
        args = dict(rc=REFUSED_CHANGE_EXIT, disk_before=PY_TAKEN, disk_after=PY_TAKEN,
                    listed_after=kept_listed, tool_result=occupied, tool_error=True,
                    next_request=went_on, trace=create_refused, result=nothing_changed)
        args.update(changes)
        return grade_refused_create_is_clean(**args)[0]

    expect("refused create, clean", refused_create(), PASS)
    expect("refused create written anyway",
           refused_create(disk_after=TAKEN_DECLARATION + "\n"), FAIL)
    expect("refused create reached the graph", refused_create(listed_after=reached_listed),
           FAIL)
    expect("refused create without its reason", refused_create(tool_result="did not publish it"),
           FAIL)
    expect("refused create reported without the error flag", refused_create(tool_error=False),
           FAIL)
    expect("refused create whose declaration the model lost", refused_create(next_request=forgot),
           FAIL)
    expect("refused create recorded as a change", refused_create(result=taken_changed), FAIL)
    expect("refused create came back clean", refused_create(trace=created), FAIL)
    expect("refused create through a file tool", refused_create(trace=by_write_file), FAIL)
    expect("refused create run that crashed", refused_create(rc=1), FAIL)
    expect("refused create with no next request", refused_create(next_request=None),
           UNREADABLE)

    mutated = MUTATE_BODY + "\n"
    mutated_source = {"source": MUTATE_BODY, "_kin": {}}
    stale_source = {"source": MUTABLE_RS, "_kin": {}}
    mutable_id = "00000000-0000-4000-8000-000000000042"
    sessioned = [{"tool": "kin_mutate", "is_error": False,
                  "args": {"session_id": "s1", "summary": MUTATE_SUMMARY,
                           "operations": [{"verb": "update", "target": mutable_id}]}}]
    unsessioned = [{"tool": "kin_mutate", "is_error": False,
                    "args": {"summary": MUTATE_SUMMARY,
                             "operations": [{"verb": "update", "target": mutable_id}]}}]
    kin_only = {"kin_agent": {"entities_changed": [mutable_id], "files_changed": []}}
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
                                       kin_only, said_it, mutable_id)[0], PASS)
    # The one this check exists for: the halves were green while the
    # composition was not, so a mutate that goes out unsessioned must be a
    # failure here and not merely a note.
    expect("pure-kin mutate went out with no session",
           grade_pure_kin_mutate_lands(0, mutated, mutated_source, recorded, unsessioned,
                                       kin_only, said_it, mutable_id)[0], FAIL)
    expect("pure-kin mutate said it under a fold",
           grade_pure_kin_mutate_lands(0, mutated, mutated_source, recorded, sessioned,
                                       kin_only, said_it_under_a_fold, mutable_id)[0], PASS)
    expect("pure-kin mutate recorded only the transaction line",
           grade_pure_kin_mutate_lands(0, mutated, mutated_source, recorded, sessioned,
                                       kin_only, said_nothing, mutable_id)[0], FAIL)
    expect("pure-kin mutate changed nothing in the graph",
           grade_pure_kin_mutate_lands(0, mutated, stale_source, recorded, sessioned,
                                       kin_only, said_it, mutable_id)[0], FAIL)
    expect("pure-kin run recorded a file it has no tool to change",
           grade_pure_kin_mutate_lands(0, mutated, mutated_source, recorded, sessioned,
                                       {"kin_agent": {"entities_changed": [mutable_id],
                                                      "files_changed": ["src/mutable.rs"]}},
                                       said_it, mutable_id)[0], FAIL)
    expect("pure-kin mutate made no mutate call",
           grade_pure_kin_mutate_lands(0, mutated, mutated_source, recorded, [],
                                       kin_only, said_it, mutable_id)[0], FAIL)
    expect("pure-kin run recorded an entity other than the one it named",
           grade_pure_kin_mutate_lands(0, mutated, mutated_source, recorded, sessioned,
                                       {"kin_agent": {"entities_changed": ["mutable"],
                                                      "files_changed": []}},
                                       said_it, mutable_id)[0], FAIL)
    expect("pure-kin mutate with no log to read",
           grade_pure_kin_mutate_lands(0, mutated, mutated_source, recorded, sessioned,
                                       kin_only, None, mutable_id)[0], UNREADABLE)

    stopped = (0, "the daemon on port 1 stopped")
    other_edited = OTHER_RS.replace(RESTART_FIND, RESTART_REPLACE)
    new_other = {"source": RESTART_REPLACE, "_kin": {}}
    old_other = {"source": RESTART_FIND, "_kin": {}}
    reopened = [session, session, mutation("update")]
    retried = [session, mutation("update", is_error=True), session, mutation("update")]
    update_refused = [session, mutation("update", is_error=True)]
    written_locally = [session, {"surface": "local", "tool": "edit_file"}]
    expect("edit survives a restart",
           grade_edit_survives_a_daemon_restart(stopped, 0, other_edited, new_other, recorded,
                                                reopened)[0], PASS)
    expect("edit survives a restart after one refused attempt",
           grade_edit_survives_a_daemon_restart(stopped, 0, other_edited, new_other, recorded,
                                                retried)[0], PASS)
    expect("restart ends in a local write",
           grade_edit_survives_a_daemon_restart(stopped, 0, other_edited, old_other,
                                                uncommitted, written_locally)[0], FAIL)
    expect("restart ends in a refusal",
           grade_edit_survives_a_daemon_restart(stopped, 0, OTHER_RS, old_other, recorded,
                                                update_refused)[0], FAIL)
    expect("restart's local write picked up only by the reconcile loop",
           grade_edit_survives_a_daemon_restart(stopped, 0, other_edited, new_other, recorded,
                                                written_locally)[0], FAIL)
    expect("restart whose last update came back an error",
           grade_edit_survives_a_daemon_restart(stopped, 0, other_edited, new_other, recorded,
                                                reopened + [mutation("update", True)])[0], FAIL)
    expect("restart never happened",
           grade_edit_survives_a_daemon_restart((1, "kin daemon stop exited 1"), 0,
                                                other_edited, new_other, recorded,
                                                reopened)[0], UNREADABLE)

    # The exact-name lookup. A name a module and a function share, or two functions in
    # two files share, answers with candidates; the harness takes the one function in the
    # named file and nothing else.
    twins = {"ambiguous_focal": True, "query": "other", "candidate_count": 3, "candidates": [
        {"entity_id": "m9", "name": "other", "kind": "Module", "file_path": "src/other.rs"},
        {"entity_id": "f9", "name": "other", "kind": "Function", "file_path": "src/other.rs"},
        {"entity_id": "g9", "name": "other", "kind": "Function", "file_path": "src/lib.rs"}]}
    rows = entity_rows(twins)
    expect("lookup picks the function in its file",
           [row["id"] for row in functions_named(rows, "other", "src/other.rs")], ["f9"])
    expect("lookup never picks by rank across files",
           len(functions_named(rows, "other")), 2)
    expect("lookup of a cut-short candidate list",
           entity_rows(dict(twins, candidate_count=30)), None)
    expect("lookup of a name nothing carries", entity_rows({"not_found": True}), [])
    expect("lookup of an unreadable reply", entity_rows(None), None)
    # The refusals as a Kin server words them inside the envelope's message.
    absent = ("no entity found matching 'taken'. Use semantic_search or semantic_locate to "
              "find the entity, then call get_entity_source with the ID it returns.")
    module = ("entity 'taken' (821e4f27-4ea4-491f-81af-b5488fc27eeb) exists in the graph but "
              "has no retrievable source: taken is an import/module relationship node for a "
              "whole file, not an independently readable or editable declaration.")
    expect("refused lookup of a name nothing carries",
           entity_rows(refusal_answer(absent, "taken")), [])
    expect("refused lookup of a name only a file's module carries",
           entity_rows(refusal_answer(module, "taken")),
           [{"id": "821e4f27-4ea4-491f-81af-b5488fc27eeb", "name": "taken", "kind": "module",
             "file_path": None}])
    expect("a module node is no function of that name",
           functions_named(entity_rows(refusal_answer(module, "taken")), "taken"), [])
    expect("a refusal about another name says nothing about this one",
           refusal_answer(module, "kept"), None)
    expect("an absence about another name says nothing about this one",
           refusal_answer(absent, "kept"), None)
    expect("any other refusal is unreadable",
           refusal_answer("daemon unavailable", "taken"), None)
    expect("a refusal with no message is unreadable", refusal_answer(None, "taken"), None)
    expect("the in-process absence for exactly this name",
           refusal_answer("Entity not found: taken", "taken"), {"not_found": True})
    expect("an in-process absence about another name says nothing about this one",
           refusal_answer("Entity not found: kept", "taken"), None)
    expect("an in-process absence about a longer name says nothing about this one",
           refusal_answer("Entity not found: taken_too", "taken"), None)
    expect("an absence that names nothing is unreadable",
           refusal_answer("Entity not found", "taken"), None)
    expect("a daemon absence about a longer name says nothing about this one",
           refusal_answer("no entity found matching 'taken_too'.", "taken"), None)
    exact = {"id": "f8", "name": "value", "kind": "Function", "file_path": "src/lib.rs",
             "source_base": {}}
    expect("lookup of an exact answer",
           [row["id"] for row in functions_named(entity_rows(exact), "value", "src/lib.rs")],
           ["f8"])
    expect("lookup that reached a member under another name",
           functions_named(entity_rows(dict(exact, name="Owner::value")), "value"), [])

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
