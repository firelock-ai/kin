#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
"""Grade the served `agent-default` MCP surface, per pull request.

Five assertions in this repository read the served MCP surface and every one of
them runs only on `main`'s push:

  * `.github/workflows/install-proof.yml`, "Graph query and MCP tool-call
    proof", throws `MCP tools/list omitted semantic_search` and then calls that
    tool through `tools/call` twice
  * `scripts/prove-windows-npm-first-run.mjs` asserts
    `toolNames.includes('semantic_search')` for both npm entrypoints, then calls
    it and requires the committed entity back
  * `scripts/acceptance/magic_repro.py` `check_6` requires `include_body` or
    `compact` on the served `trace_data_flow`
  * the same file's `check_14`, arm 3, requires the literal
    `last_settled_selected_graph` in the served `kin_graph_status` description
  * `scripts/acceptance/response_budget_elisions.py` `check_2` grades every
    advertised `max_chars` or `max_response_chars`, and reports UNREADABLE when
    it finds none

On 2026-09-02 all five were `skipped` across 44 of 44 check runs on the pull
request that moved the surface, and all five went red on `main` for four
landings while every pull request read green. This suite is those assertions on
one server against one small fixture, so the move fails on the pull request that
makes it.

It reuses the graders rather than restating them.
`response_budget_elisions.grade_advertised_budget` is imported and called on the
served schemas; `magic_repro.trace_shape_knob` and
`magic_repro.graph_status_description` are the same readers `check_6` and
`check_14` use. A rule edited in either file moves here in the same commit,
which is the only way a per-pull-request gate and `main`'s gate stay one gate.

Check 0 is the positive control and every other check depends on it. The server
prints which tool profile it resolved, and a run that graded `full` would pass
every assertion below while saying nothing about the surface an agent is served.

Checks 13 and 14 run last, because they edit the fixture. Check 13 drives the
write path on both write surfaces, `agent-default`'s named tools and
`agent-routed`'s `session` and `mutate` commands: a session opened under the
caller's own UUID, one committed entity edit, the exact body read back with no
line offsets, and a mutate under an unopened session refused by `kin_mutate`
itself. Check 14 reads the same entity on `agent-routed-query`, which numbers
body lines as `+N`, and has every write refused with the sentence naming
`agent-routed`.

Exit status is 0 when every check passed, 1 when one failed, 2 when one could
not be read, and 3 when the run could not be set up. `--self-test` drives every
grader against its inverse and needs no binary, so a grader that cannot fail is
a failure here rather than a silent pass in CI.
"""

from __future__ import print_function

import argparse
import json
import os
import shutil
import re
import subprocess
import sys
import tempfile
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from magic_repro import (  # noqa: E402
    AS_OF_EARLIER_SAMPLING,
    graph_status_description,
    trace_shape_knob,
)
from response_budget_elisions import grade_advertised_budget  # noqa: E402

PASS = "PASS"
FAIL = "FAIL"
UNREADABLE = "UNREADABLE"

# The profile `kin setup` writes into every agent's MCP entry, and the one the
# five graders above are served. Named rather than left to the binary's default:
# a default that moves would otherwise quietly re-point this whole suite.
AGENT_DEFAULT_PROFILE = "agent-default"

# The query profile and the exact names it serves, read out of
# crates/kin-mcp/src/tools.rs::agent_query_tool_names on 2026-09-02, with
# lexical_lookup joining the profile when the literal lookup over the graph's
# text index landed on 2026-09-19. Written out rather than derived: the served
# set is a public surface, and a check that derived it from the binary under
# test would agree with any surface that binary happened to serve.
AGENT_QUERY_PROFILE = "agent-query"
AGENT_QUERY_NAMES = (
    "find_references",
    "get_context_pack",
    "get_entity_source",
    "graph_neighborhood",
    "impact_analysis",
    "kin_graph_status",
    "kin_provenance_query",
    "lexical_lookup",
    "semantic_locate",
    "semantic_search",
    "trace_data_flow",
    "trace_path",
)

# The share of agent-default's tools/list the query profile may cost.
#
# Native tool calling re-sends the whole tools array on every turn, so this is a
# per-turn cost. Measured on 2026-09-02 by the demo's MCP executor against a
# real `kin mcp start`: agent-default's tools/list was 30,194 bytes and 8,627
# tokens on google/gemma-4-e4b, 36 percent of that run's 24,000-token ceiling
# before the model had asked anything (FIR-3107). The assertion is in BYTES,
# because bytes are what this process can measure; the demo measured 3.5 bytes
# per token on that model, so the ratio held here is the ratio of the token cost
# on it too.
AGENT_QUERY_LIST_CEILING_PERCENT = 65

# The tool-search profile and the exact always-on set it serves, read out of
# crates/kin-mcp/src/tools.rs::agent_search_tool_names on 2026-09-03. Written
# out for the same reason AGENT_QUERY_NAMES is: a check that derived the set
# from the binary under test would agree with any surface that binary served.
AGENT_SEARCH_PROFILE = "agent-search"
AGENT_SEARCH_NAMES = (
    "kin_tool_call",
    "get_context_pack",
    "kin_graph_status",
    "kin_tool_search",
    "semantic_locate",
    "trace_data_flow",
)

# The name of the tool that reaches everything the profile withholds.
TOOL_SEARCH_NAME = "kin_tool_search"

# Four tools the 2026-09-03 measurement moved behind the search: impact_analysis
# was offered 24 times and called none, get_entity_source 24 and once,
# find_references five calls of which four came from the one arm with no flow
# walker, and no arm reached for a transaction tool at all. Named here so the
# exact-set assertion above has a second, independently written control.
WITHHELD_BY_DESIGN = (
    "impact_analysis",
    "find_references",
    "get_entity_source",
    "kin_transaction_commit",
)

# The most bytes agent-search's tools/list may cost, measured on the profile AS
# SERVED. Mirrors kin_mcp::tools::AGENT_SEARCH_LIST_CEILING_BYTES, which holds
# the same ceiling as a crate test; this one holds it on the wire, where a
# spawned server resolves the profile and writes the listing a client reads.
#
# Grounded in a measurement. The three retrieval tools measured 4,928 bytes on
# kin-mcp 0.6.4, so this leaves the search tool's schema, kin_graph_status and
# normal prose growth inside a ceiling that is still a third of agent-query's
# 15,345 bytes.
AGENT_SEARCH_LIST_CEILING_BYTES = 8_000

# The routed profile: one tool whose commands reach the query belt, for a client
# that loads every tool it is handed and re-sends them all with every request.
# Read out of crates/kin-mcp/src/routed.rs on 2026-09-22, where the same ceiling
# is ROUTED_LIST_CEILING_BYTES and a crate test holds it; this holds it on the
# wire, and grades that a routed command reaches its named tool through a real
# daemon.
AGENT_ROUTED_PROFILE = "agent-routed"
ROUTED_TOOL_NAME = "kin"
ROUTED_LIST_CEILING_BYTES = 3_200
AGENT_ROUTED_QUERY_PROFILE = "agent-routed-query"
# The refusal a write gets on the read-only routed surface names the profile
# that carries it (crates/kin-mcp/src/routed.rs, `refused_read_only`).
ROUTED_WRITE_REFUSAL = "The agent-routed profile carries Kin's writes."
# The note beside a numbered body (crates/kin-mcp/src/entity_lines.rs).
NUMBERING_KEY = "about_body"
NUMBERED_LINE = re.compile(r"^\+(\d+)\t")
# What kin_mutate answers for a session it never registered: the handler's own
# refusal, which a routed call must reach rather than a routing one.
UNKNOWN_SESSION = "Session not found"

# The tool names the two shipped proofs assert literally. Read out of
# .github/workflows/install-proof.yml and scripts/prove-windows-npm-first-run.mjs
# on 2026-09-02; both assert this one name and no other. Adding a name to either
# file adds it here.
PROOF_ASSERTED_NAMES = ("semantic_search",)

# The budget parameter names response_budget_elisions.check_2 grades.
BUDGET_KEYS = ("max_chars", "max_response_chars")


# BEGIN failure evidence excerpt
# Every suite carries this block byte for byte, because a suite is also copied
# out and run as a single file. test_failure_excerpt.py keeps the copies equal.
EVIDENCE_LIMIT = 4000
EVIDENCE_LINE_LIMIT = 600
EVIDENCE_PANICS = ("panicked at", "has overflowed its stack")
EVIDENCE_ESCAPES = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
EVIDENCE_ERROR = re.compile(r"^(?:[\w./-]+:\s*)?(?:error|fatal)\b", re.IGNORECASE)
EVIDENCE_LOG_ERROR = re.compile(r"\sERROR\s")


def failure_excerpt(text, limit=EVIDENCE_LIMIT):
    """Bounded evidence from a command's output that still says why it failed.

    Output that fits is returned whole. Longer output keeps its opening and its
    end, and between them every line that carries a Rust panic, with the
    message line under it, and the last error line, wherever they fall. A
    warning printed around the error cannot push it out, and a long log cannot
    cut the panic out. `limit` only ever raises the bound, never lowers it.
    """
    text = (text or "").strip()
    limit = max(int(limit), EVIDENCE_LIMIT)
    if len(text) <= limit:
        return text
    head_end = limit // 4
    tail_start = len(text) - limit // 2
    lines = text.split("\n")
    starts, offset = [], 0
    panics, errors = [], []
    for index, line in enumerate(lines):
        starts.append(offset)
        offset += len(line) + 1
        plain = EVIDENCE_ESCAPES.sub("", line).strip()
        if any(marker in plain for marker in EVIDENCE_PANICS):
            panics.extend((index, index + 1))
        if EVIDENCE_ERROR.match(plain) or EVIDENCE_LOG_ERROR.search(plain):
            errors.append(index)
    # The first panic and its message, then the last error line, then any
    # later panics, for as long as the middle's share of the bound lasts.
    order = panics[:2] + errors[-1:] + panics[2:]
    budget, kept = limit // 4, set()
    for index in order:
        if index >= len(lines) or index in kept:
            continue
        start, end = starts[index], starts[index] + len(lines[index])
        if end <= head_end or start >= tail_start:
            continue
        cost = min(len(lines[index]), EVIDENCE_LINE_LIMIT) + 1
        if cost > budget:
            continue
        kept.add(index)
        budget -= cost
    middle = [lines[index][:EVIDENCE_LINE_LIMIT] for index in sorted(kept)]
    parts = [text[:head_end], "[...]"] + middle + (["[...]"] if middle else [])
    return "\n".join(parts + [text[tail_start:]])
# END failure evidence excerpt


class McpError(Exception):
    pass


class SetupError(Exception):
    pass


class Result(object):
    """One check's verdict, in the CHECK-line shape the sibling suites print."""

    def __init__(self, ident, source, title):
        self.id = ident
        self.source = source
        self.title = title
        self.status = PASS
        self.detail = title
        self.notes = []

    def ok(self, detail):
        self.notes.append("ok: " + detail)
        if self.status == PASS:
            self.detail = detail

    def bad(self, detail):
        self.notes.append("FAIL: " + detail)
        self.status = FAIL
        self.detail = detail

    def unknown(self, detail):
        self.notes.append("UNREADABLE: " + detail)
        if self.status != FAIL:
            self.status = UNREADABLE
            self.detail = detail

    def row(self):
        return {
            "id": self.id,
            "source": self.source,
            "title": self.title,
            "status": self.status,
            "detail": self.detail,
            "notes": self.notes,
        }


# ── the graders ─────────────────────────────────────────────────────────────
#
# Each takes plain payloads and returns a list of problems, so `--self-test` can
# drive every one of them against a doctored listing with no binary and no
# fixture. A grader that only runs behind a live server is a grader nobody has
# ever seen fail.


def grade_profile_notice(stderr):
    """The control: the server said which profile it resolved, and it is ours."""
    for line in (stderr or "").splitlines():
        if "tool profile" not in line:
            continue
        if "'%s'" % AGENT_DEFAULT_PROFILE in line:
            return []
        return ["the server resolved a profile this suite does not grade: %s" % line.strip()]
    return ["the server printed no tool-profile notice, so which surface was graded is unknown"]


def grade_proof_asserted_names(listing):
    """install-proof.yml and prove-windows-npm-first-run.mjs, by name."""
    tools = listing.get("tools")
    if not isinstance(tools, list) or not tools:
        return ["tools/list carried no tools"]
    served = [tool.get("name") for tool in tools]
    return [
        "the shipped proofs call %s by name and agent-default serves %s"
        % (name, sorted(entry for entry in served if entry))
        for name in PROOF_ASSERTED_NAMES
        if name not in served
    ]


def grade_served_names_are_registered(listing, registry):
    """A served name the registry does not carry is a public rename by any route."""
    registered = {tool.get("name") for tool in registry.get("tools") or []}
    if not registered:
        return ["the full profile listed no tools, so nothing graded the served names"]
    unregistered = sorted(
        name
        for name in (tool.get("name") for tool in listing.get("tools") or [])
        if name and name not in registered
    )
    if unregistered:
        return [
            "agent-default serves %s under a name the registry does not carry" % unregistered
        ]
    return []


def listing_bytes(listing):
    """The bytes a client reads off the pipe.

    Compact, the way serde writes it, with no separators of Python's own.
    `json.dumps` defaults insert `", "` and `": "` and read 4.5 percent high on
    this listing: 34,470 against the 32,976 the wire carries.
    """
    return len(json.dumps(listing, separators=(",", ":"), sort_keys=True))


def grade_query_profile(query, default):
    """The query profile serves its exact set, no write tool, and far fewer bytes."""
    tools = query.get("tools")
    if not isinstance(tools, list) or not tools:
        return ["the agent-query profile listed no tools"]
    served = sorted(name for name in (tool.get("name") for tool in tools) if name)
    problems = []
    for name in ("kin_artifact_read", "kin_artifact_list", "list_file_entities"):
        if name in served:
            problems.append("retired file-oriented tool is exposed: %s" % name)
    if served != sorted(AGENT_QUERY_NAMES):
        problems.append(
            "agent-query serves %s, not the set this suite grades (%s)"
            % (served, sorted(AGENT_QUERY_NAMES))
        )
    write_side = [
        name
        for name in served
        if name.startswith("kin_session_") or name.startswith("kin_transaction_")
    ]
    if write_side:
        problems.append("agent-query serves the write tools %s" % write_side)

    baseline = default.get("tools")
    if not isinstance(baseline, list) or not baseline:
        problems.append("agent-default listed no tools, so there is nothing to measure against")
        return problems
    query_bytes = listing_bytes(query)
    default_bytes = listing_bytes(default)
    if query_bytes * 100 > default_bytes * AGENT_QUERY_LIST_CEILING_PERCENT:
        problems.append(
            "agent-query's tools/list is %d bytes against agent-default's %d (%d%%), over "
            "the %d%% ceiling the profile exists to buy"
            % (
                query_bytes,
                default_bytes,
                query_bytes * 100 // max(default_bytes, 1),
                AGENT_QUERY_LIST_CEILING_PERCENT,
            )
        )
    return problems


def grade_search_call(payload):
    """install-proof's validateSearch and the Windows proof's four assertions.

    Both require the same three things of one real `tools/call`: no RPC error,
    no `isError`, and the seeded entity and its file named in the rendered
    result. The fixture's entity is `hello` in `probe.py`, which is what
    install-proof seeds and asserts.
    """
    if payload is None:
        return ["semantic_search returned no result frame"]
    if payload.get("error"):
        return ["semantic_search returned an RPC error: %s" % json.dumps(payload["error"])[:200]]
    result = payload.get("result")
    if not isinstance(result, dict):
        return ["semantic_search returned no result object"]
    if result.get("isError") is True:
        return ["semantic_search returned isError: %s" % json.dumps(result)[:200]]
    rendered = json.dumps(result)
    missing = [needle for needle in ("hello", "probe.py") if needle not in rendered]
    if missing:
        return ["semantic_search did not return the seeded entity: %s absent" % ", ".join(missing)]
    return []


def grade_discovered_query(listing, lookup, frames):
    """A discovered hidden query works without opening direct calls or writes."""
    if len(frames) != 3:
        return ["discovered query controls returned fewer than three frames"]
    problems = grade_search_call(frames[0])
    names = {tool.get("name") for tool in listing.get("tools") or []}
    if "semantic_search" in names or "kin_tool_call" not in names:
        problems.append("the query was not hidden behind the served dispatcher")
    invocation = (lookup or {}).get("invocation") or {}
    if (invocation.get("profile_enabled") or {}).get("semantic_search") is not False:
        problems.append("discovery did not mark the hidden query directly disabled")
    if (invocation.get("callable_via_dispatcher") or {}).get("semantic_search") is not True:
        problems.append("discovery did not mark the hidden query callable through the dispatcher")
    for label, frame, reason in (
        ("direct hidden query", frames[1], "not enabled"),
        ("wrapped mutation", frames[2], "read-only"),
    ):
        result = (frame or {}).get("result") or {}
        refused = bool((frame or {}).get("error")) or result.get("isError") is True
        if not refused or reason not in json.dumps(frame):
            problems.append("%s was not refused for its expected boundary" % label)
    return problems


def search_payload(frame):
    """The JSON one `kin_tool_search` call returned, or None when it did not.

    None is never a pass here: every grader that reads a lookup reports the
    unreadable one by name, because a search that answered nothing and a search
    that answered wrongly are the same failure to an agent.
    """
    if frame is None or frame.get("error"):
        return None
    result = frame.get("result")
    if not isinstance(result, dict) or result.get("isError") is True:
        return None
    for block in result.get("content") or []:
        text = block.get("text") if isinstance(block, dict) else None
        if not isinstance(text, str):
            continue
        try:
            return json.loads(text)
        except ValueError:
            return None
    return None


def canonical(value):
    """One serialization for both sides of a byte-for-byte comparison.

    The wire pretty-prints a tool-call payload and writes tools/list compact, so
    a raw byte compare would report a formatting difference as a schema change.
    Both sides are re-serialized the same way here, which is the claim that
    matters: the schema search returns IS the schema `full` serves.
    """
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def grade_search_profile(search):
    """Assertion 1: the always-on set is static, so grade it exactly."""
    tools = search.get("tools")
    if not isinstance(tools, list) or not tools:
        return ["the agent-search profile listed no tools"]
    served = sorted(name for name in (tool.get("name") for tool in tools) if name)
    problems = []
    if served != sorted(AGENT_SEARCH_NAMES):
        problems.append(
            "agent-search serves %s, not the always-on set this suite grades (%s)"
            % (served, sorted(AGENT_SEARCH_NAMES))
        )
    if TOOL_SEARCH_NAME not in served:
        problems.append(
            "agent-search serves no %s, so every withheld tool is unreachable from it"
            % TOOL_SEARCH_NAME
        )
    search_bytes = listing_bytes(search)
    if search_bytes > AGENT_SEARCH_LIST_CEILING_BYTES:
        problems.append(
            "agent-search's tools/list is %d bytes, over the %d-byte ceiling"
            % (search_bytes, AGENT_SEARCH_LIST_CEILING_BYTES)
        )
    # A second, independently written statement of the same intent. The equality
    # above is one line, and a future edit that "fixes" a failure by rewriting
    # AGENT_SEARCH_NAMES to whatever is served would pass it. These four are the
    # tools the measurement moved behind the search; they are reachable through
    # it and must not be served beside it.
    still_served = [name for name in WITHHELD_BY_DESIGN if name in served]
    if still_served:
        problems.append(
            "agent-search serves %s, which the measurement moved behind the search"
            % still_served
        )
    return problems


def grade_tool_reachability(registry, lookups):
    """Assertion 2: every tool in the registry is findable through the search.

    The new silent failure this surface makes possible. A tool that no profile
    serves and no search finds is gone from the product with no line of code
    saying so, and nothing else in this suite would catch it.
    """
    registered = sorted(
        name for name in (tool.get("name") for tool in registry.get("tools") or []) if name
    )
    if not registered:
        return ["the full profile listed no tools, so nothing graded reachability"]
    problems = []
    for name in registered:
        payload = lookups.get(name)
        if payload is None:
            problems.append(
                "%s: the served search returned no readable answer for its own name" % name
            )
            continue
        named = payload.get("matched_names")
        if not isinstance(named, list) or name not in named:
            problems.append(
                "%s is registered and the served search does not find it, so it is unreachable"
                % name
            )
    return problems


def grade_schema_fidelity(registry, lookups):
    """Assertion 3: the schema search returns equals the one `full` serves.

    This closes the drift reachability would otherwise hide. A search that
    returned a summary, a trimmed schema, or a belt short form would satisfy
    reachability while handing an agent a definition it cannot call from.
    """
    served = {
        tool.get("name"): tool
        for tool in registry.get("tools") or []
        if isinstance(tool, dict) and tool.get("name")
    }
    if not served:
        return ["the full profile listed no tools, so there was no schema to compare against"]
    problems = []
    for name, definition in sorted(served.items()):
        payload = lookups.get(name)
        if payload is None:
            problems.append("%s: the served search returned no readable answer" % name)
            continue
        matches = payload.get("matches")
        found = None
        if isinstance(matches, list):
            found = next(
                (
                    match
                    for match in matches
                    if isinstance(match, dict) and match.get("name") == name
                ),
                None,
            )
        if found is None:
            problems.append(
                "%s was named by the search but its full definition was not returned, so a "
                "found tool is not callable" % name
            )
            continue
        if canonical(found) != canonical(definition):
            problems.append(
                "%s: the schema the search returns is not the schema the full profile serves"
                % name
            )
    return problems


# Every profile `kin mcp start` accepts, for the portability sweep. `benchmark`
# and `context-bench` are served tools/list only: their bytes feed citable
# results, and the sweep reads them rather than calling anything.
ALL_PROFILES = [
    "agent-default", "agent-query", "agent-search", "agent-routed", "agent-routed-query",
    "benchmark", "context-bench", "full",
]

# The JSON-schema keywords a provider tool API refuses at the top of a tool's
# input schema. A client loading tools for such an API drops the tool without a
# word: Claude Code listed 19 of agent-default's 22 tools while three opened with
# `anyOf` (crates/kin-mcp/src/input_contract.rs).
TOP_LEVEL_COMBINATORS = ("oneOf", "anyOf", "allOf", "not", "if", "then", "else")


def grade_portable_schemas(listings):
    """Every tool on every profile serves a plain `type: object` input schema."""
    problems = []
    if not listings:
        return ["no profile listing was read"]
    for profile, listing in sorted(listings.items()):
        tools = listing.get("tools")
        if not isinstance(tools, list) or not tools:
            problems.append("%s served no tools" % profile)
            continue
        for tool in tools:
            schema = tool.get("inputSchema") or {}
            found = [keyword for keyword in TOP_LEVEL_COMBINATORS if keyword in schema]
            if found:
                problems.append("%s/%s opens its input schema with %s"
                                % (profile, tool.get("name"), ", ".join(found)))
            if schema.get("type") != "object":
                problems.append("%s/%s serves an input schema of type %r, not object"
                                % (profile, tool.get("name"), schema.get("type")))
    return problems


def grade_routed_profile(listing, search_frame, describe_frame):
    """The routed profile serves one tool, under its ceiling, that reaches the belt.

    The search goes through the routed tool to `semantic_search` and must bring
    back the seeded entity, graded by the same reader the install proof's
    search is. `describe` must hand back the command's schemas.
    """
    tools = listing.get("tools")
    if not isinstance(tools, list) or not tools:
        return ["the agent-routed profile listed no tools"]
    problems = []
    served = [tool.get("name") for tool in tools]
    if served != [ROUTED_TOOL_NAME]:
        problems.append("agent-routed serves %s, not the one routed tool" % served)
    routed_bytes = listing_bytes(listing)
    if routed_bytes > ROUTED_LIST_CEILING_BYTES:
        problems.append(
            "agent-routed's tools/list is %d bytes, over the %d-byte ceiling"
            % (routed_bytes, ROUTED_LIST_CEILING_BYTES)
        )
    problems.extend("routed search: %s" % problem for problem in grade_search_call(search_frame))
    described = search_payload(describe_frame)
    variants = (described or {}).get("variants")
    if not isinstance(variants, list) or not all(
        isinstance(variant, dict) and isinstance(variant.get("args_schema"), dict)
        for variant in variants or [None]
    ):
        problems.append("routed describe did not return the command's schemas")
    return problems


def entity_id_named(payload, name):
    """The id of the first entity called `name` anywhere in a tool's answer."""
    stack = [payload]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            if node.get("name") == name and (node.get("id") or node.get("entity_id")):
                return node.get("id") or node.get("entity_id")
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
    return None


def refusal_text(frame):
    """The text of a refused call, or None when the call was not refused."""
    if frame is None:
        return None
    if frame.get("error"):
        return json.dumps(frame["error"])
    result = frame.get("result")
    if not isinstance(result, dict) or result.get("isError") is not True:
        return None
    return json.dumps(result)


def grade_write_family(label, frames, session_id, body, disk):
    """One write surface, end to end: session, commit, exact read-back, refusal.

    `frames` answer, in order: a session opened under the caller's own UUID, a
    `kin_mutate` of one entity under it, that entity's source, and a mutate
    under a UUID no session was opened for. The body read back must be the
    committed text byte for byte, with no `+N` offsets, because an agent on a
    write surface restates what it reads into its next edit.
    """
    if len(frames) != 4 or any(frame is None for frame in frames):
        return ["%s: the server answered %d of the 4 calls" % (
            label, len([frame for frame in frames if frame is not None]))]
    problems = []
    opened = search_payload(frames[0])
    if opened is None:
        problems.append("%s: the session did not open: %s" % (label, (refusal_text(frames[0]) or "")[:300]))
    elif opened.get("session_id") != session_id:
        problems.append("%s: the session opened as %r, not the caller's %r"
                        % (label, opened.get("session_id"), session_id))
    committed = search_payload(frames[1])
    if committed is None:
        problems.append("%s: the mutate was refused: %s" % (label, (refusal_text(frames[1]) or "")[:300]))
    elif committed.get("status") != "committed":
        problems.append("%s: the mutate answered status %r, not committed"
                        % (label, committed.get("status")))
    source = search_payload(frames[2])
    if source is None:
        problems.append("%s: the source read answered nothing" % label)
    else:
        if source.get("body") != body:
            problems.append("%s: the body read back is not the committed text: %r"
                            % (label, (source.get("body") or "")[:200]))
        if NUMBERING_KEY in source:
            problems.append("%s: a write surface served numbered lines" % label)
    if disk is None or body not in disk:
        problems.append("%s: the file on disk does not carry the committed body" % label)
    refused = refusal_text(frames[3])
    if refused is None or UNKNOWN_SESSION not in refused:
        problems.append("%s: a mutate under an unopened session was not refused by kin_mutate "
                        "itself: %s" % (label, (refused or json.dumps(frames[3]))[:300]))
    return problems


def grade_read_only_routed(frames, body, disk_before, disk_after):
    """The read-only routed surface: numbered bodies, and every write refused.

    `frames` answer, in order: an entity's source, a `mutate`, a `session`, and
    a `call` of `kin_mutate`. The source must number every line as `+N` and a
    tab, carry the note that says so, and strip back to the committed body. The
    three writes must each be refused with the sentence naming the profile that
    carries writes, and the file must be byte-identical afterwards.
    """
    if len(frames) != 4 or any(frame is None for frame in frames):
        return ["the server answered %d of the 4 calls" % len(
            [frame for frame in frames if frame is not None])]
    problems = []
    source = search_payload(frames[0])
    if source is None:
        problems.append("the source read answered nothing")
    else:
        lines = (source.get("body") or "").split("\n")
        offsets = [NUMBERED_LINE.match(line) for line in lines]
        if not lines or not all(offsets) or [int(m.group(1)) for m in offsets] != list(
            range(len(lines))
        ):
            problems.append("the body is not numbered +0, +1, ... line by line: %r"
                            % (source.get("body") or "")[:200])
        elif "\n".join(NUMBERED_LINE.sub("", line) for line in lines) != body:
            problems.append("the numbered body does not strip back to the committed text")
        if not source.get(NUMBERING_KEY):
            problems.append("the numbered body came without its %s note" % NUMBERING_KEY)
    for label, frame in (("mutate", frames[1]), ("session", frames[2]), ("call kin_mutate", frames[3])):
        refused = refusal_text(frame)
        if refused is None or ROUTED_WRITE_REFUSAL not in refused:
            problems.append("%s was not refused with the profile that carries writes: %s"
                            % (label, (refused or json.dumps(frame))[:300]))
    if disk_before is None or disk_before != disk_after:
        problems.append("the file changed on the read-only surface")
    return problems


def grade_trace_shape_knob(listing):
    """magic_repro.py check_6, through check_6's own reader."""
    knob, keys = trace_shape_knob(listing)
    if keys is None:
        return ["trace_data_flow is absent from tools/list, which magic_repro check_6 reads"]
    if knob is None:
        return [
            "trace_data_flow advertises neither include_body nor compact, which "
            "magic_repro.py check_6 requires: %s" % keys
        ]
    return []


def grade_graph_status_description(listing):
    """magic_repro.py check_14 arm 3, through check_14's own reader."""
    description = graph_status_description(listing)
    if not description:
        return ["tools/list carries no kin_graph_status description, which magic_repro check_14 reads"]
    if AS_OF_EARLIER_SAMPLING not in description:
        return [
            "the served kin_graph_status description does not name %r, so an agent cannot "
            "know to read `stale`, and magic_repro.py check_14 arm 3 fails on main"
            % AS_OF_EARLIER_SAMPLING
        ]
    return []


def _budget_properties(listing, name):
    for tool in listing.get("tools") or []:
        if tool.get("name") == name:
            schema = tool.get("inputSchema") or tool.get("input_schema") or {}
            return schema.get("properties") or {}
    return {}


def grade_advertised_budgets(listing, registry):
    """response_budget_elisions.py check_2, through that file's own grader.

    Two halves, because either alone passes a broken surface. Every budget the
    served profile advertises is graded by the imported grader, which is the
    check itself. And every tool that REGISTERS a budget has to advertise one,
    because check_2 counts what it graded and reports UNREADABLE at zero: a
    profile that trimmed every budget would take check_2 to UNREADABLE on main
    rather than to a pass, and UNREADABLE is not a pass.
    """
    problems = []
    graded = 0
    for tool in listing.get("tools") or []:
        properties = _budget_properties(listing, tool.get("name"))
        for key in BUDGET_KEYS:
            if key not in properties:
                continue
            graded += 1
            problems.extend(
                "%s.%s: %s" % (tool.get("name"), key, problem)
                for problem in grade_advertised_budget(properties[key])
            )
        registered = _budget_properties(registry, tool.get("name"))
        if any(key in registered for key in BUDGET_KEYS) and not any(
            key in properties for key in BUDGET_KEYS
        ):
            problems.append(
                "%s registers a budget parameter and agent-default advertises none, so "
                "response_budget_elisions.py check_2 grades a smaller set than it did"
                % tool.get("name")
            )
    if graded == 0:
        problems.append(
            "no served tool advertised a budget parameter, so check_2 would report "
            "UNREADABLE on main and grade nothing"
        )
    return problems


# ── the fixture and the server ──────────────────────────────────────────────

PROBE_PY = '''\
def hello(name):
    """Greet by name. The entity the shipped install proof seeds and asserts."""
    return "hello " + name


def caller(name):
    """Calls hello, so a shape query has a chain to walk."""
    return hello(name)
'''

MAIN_RS = '''\
/// The Rust half, so the served surface is graded against more than one adapter.
pub fn greet(name: &str) -> String {
    format!("hello {name}")
}
'''

GIT = [
    "git",
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "commit.gpgsign=false",
    "-c",
    "user.email=acceptance@firelock.invalid",
    "-c",
    "user.name=kin-mcp-surface-contract",
]


class Suite(object):
    """One small fixture repository, served over kin's stdio MCP server.

    The MCP path is the surface every one of the five graders reads: the daemon
    route serves no tool listing at all, and the library route is what the
    kin-mcp unit tests already hold. What is left to a job like this one is the
    wire: the profile a spawned server actually resolves and the listing it
    actually writes to a client's stdin.
    """

    def __init__(self, kin, workdir, verbose=False, daemon=None):
        self.kin = kin
        self.daemon = daemon
        self.workdir = workdir
        self.verbose = verbose
        self.repo = None
        self.env = dict(os.environ)
        self.env["KIN_HOME"] = os.path.join(workdir, "kin-home")
        self.env["KIN_DAEMON_AUTO_EMBED"] = "0"
        self.env["KIN_VFS_DISABLE"] = "1"
        self.env["KIN_EMBED_BACKEND"] = "cpu"
        self.env.pop("KIN_MCP_REPO", None)
        if daemon:
            self.env["KIN_DAEMON_BIN"] = os.path.abspath(daemon)
        if not os.path.isdir(self.env["KIN_HOME"]):
            os.makedirs(self.env["KIN_HOME"])

    def run(self, args, cwd, timeout=900):
        proc = subprocess.run(
            args, cwd=cwd, env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout,
        )
        if self.verbose:
            print("$ %s -> %d" % (" ".join(args), proc.returncode))
        return proc

    def fixture(self):
        repo = os.path.join(self.workdir, "fixture")
        if os.path.isdir(repo):
            shutil.rmtree(repo)
        os.makedirs(os.path.join(repo, "src"))
        with open(os.path.join(repo, "src", "probe.py"), "w") as handle:
            handle.write(PROBE_PY)
        with open(os.path.join(repo, "src", "main.rs"), "w") as handle:
            handle.write(MAIN_RS)
        for args in (
            GIT + ["init", "--quiet"],
            GIT + ["add", "-A"],
            GIT + ["commit", "--quiet", "-s", "-m", "fixture"],
        ):
            proc = self.run(args, repo, timeout=120)
            if proc.returncode != 0:
                raise SetupError(
                    "%s failed: %s" % (" ".join(args), failure_excerpt(proc.stderr.decode("utf-8", "replace")))
                )
        proc = self.run([self.kin, "init"], repo, timeout=900)
        if proc.returncode != 0:
            raise SetupError("kin init failed: %s" % failure_excerpt(proc.stderr.decode("utf-8", "replace")))
        self.repo = repo
        return repo

    def serve(self, profile, calls, timeout=600):
        """One server, one initialize, one tools/list, and the calls asked for.

        One process rather than one per request, because each spawn pays the
        daemon handshake and this job sits on a pull request's clock. The frames
        are written in one write and the server answers them in order, which is
        the same sequence the install proof drives.

        `KIN_MCP_TOOL_PROFILE` is set rather than left to the binary's default,
        because it is what `kin setup` writes into every agent's MCP entry
        (crates/kin-cli/src/commands/setup.rs) and because a default that moved
        would otherwise silently re-point every grader here.
        """
        env = dict(self.env)
        env["KIN_MCP_REPO"] = self.repo
        env["KIN_MCP_TOOL_PROFILE"] = profile
        frames = [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "kin-mcp-surface-contract", "version": "1"},
                },
            },
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        ]
        for index, (name, arguments) in enumerate(calls):
            frames.append(
                {
                    "jsonrpc": "2.0",
                    "id": 3 + index,
                    "method": "tools/call",
                    "params": {"name": name, "arguments": arguments},
                }
            )
        proc = subprocess.Popen(
            [self.kin, "mcp", "start", "--repo", self.repo],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=self.repo, env=env, text=True,
        )
        try:
            out, err = proc.communicate(
                "".join(json.dumps(frame) + "\n" for frame in frames), timeout=timeout
            )
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            raise McpError("the %s server did not answer within %ss" % (profile, timeout))
        by_id = {}
        for line in out.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                frame = json.loads(line)
            except ValueError:
                continue
            if frame.get("id") is not None:
                by_id[frame["id"]] = frame
        if 1 not in by_id:
            raise McpError(
                "the %s server answered no initialize (stderr tail: %s)"
                % (profile, failure_excerpt(err).replace("\n", " "))
            )
        listing = by_id.get(2)
        if listing is None or "error" in listing:
            raise McpError(
                "the %s server answered no tools/list: %s"
                % (profile, json.dumps(listing)[:300] if listing else "no frame")
            )
        return (listing.get("result") or {}), [by_id.get(3 + i) for i in range(len(calls))], err


# ── the checks ──────────────────────────────────────────────────────────────


def run_checks(suite, verbose=False):
    results = []

    def record(ident, source, title, problems, good):
        res = Result(ident, source, title)
        if problems is None:
            res.unknown(good)
        elif problems:
            for problem in problems:
                res.bad(problem)
        else:
            res.ok(good)
        results.append(res)
        return res

    try:
        served, calls, stderr = suite.serve(
            AGENT_DEFAULT_PROFILE,
            [("semantic_search", {"query": "hello", "compact": True, "limit": 5})],
        )
    except McpError as error:
        for ident, source, title in CHECK_TITLES:
            res = Result(ident, source, title)
            res.unknown("the agent-default server was unreadable: %s" % error)
            results.append(res)
        return results

    control = record(
        "0", "control", "the graded surface is the profile kin setup registers",
        grade_profile_notice(stderr),
        "the server resolved the %r profile and served %d tools"
        % (AGENT_DEFAULT_PROFILE, len(served.get("tools") or [])),
    )
    if control.status != PASS:
        # Every check below reads `served`. Grading it against an unknown
        # profile would report a surface nobody is served.
        for ident, source, title in CHECK_TITLES[1:]:
            res = Result(ident, source, title)
            res.unknown("the profile control did not pass, so this reads an unknown surface")
            results.append(res)
        return results

    record(
        "1", "install-proof + windows-npm",
        "every tool name the shipped proofs assert is served under that name",
        grade_proof_asserted_names(served),
        "agent-default serves %s" % ", ".join(PROOF_ASSERTED_NAMES),
    )

    record(
        "2", "install-proof + windows-npm",
        "a real tools/call returns the seeded entity",
        grade_search_call(calls[0]),
        "semantic_search returned the seeded hello entity from probe.py",
    )

    record(
        "3", "magic:6", "trace_data_flow advertises its shape knob",
        grade_trace_shape_knob(served),
        "trace_data_flow advertises %r" % (trace_shape_knob(served)[0],),
    )

    record(
        "4", "magic:14", "the kin_graph_status description names the as-of-earlier shape",
        grade_graph_status_description(served),
        "the served description names %r" % AS_OF_EARLIER_SAMPLING,
    )

    try:
        registry, _, _ = suite.serve("full", [])
    except McpError as error:
        registry = None
        for ident, source, title in [entry for entry in CHECK_TITLES if entry[0] in ("5", "6")]:
            res = Result(ident, source, title)
            res.unknown("the full profile was unreadable, so the registry is unknown: %s" % error)
            results.append(res)

    if registry is not None:
        record(
            "5", "response_budget:2", "every advertised budget is one a client accepts",
            grade_advertised_budgets(served, registry),
            "the served budgets sit under what a real client accepts, and every tool "
            "that registers one advertises one",
        )
        record(
            "6", "the general form",
            "no name is served that the registry does not carry",
            grade_served_names_are_registered(served, registry),
            "every served name is a registered name across %d served and %d registered tools"
            % (len(served.get("tools") or []), len(registry.get("tools") or [])),
        )

    try:
        query, _, query_stderr = suite.serve(AGENT_QUERY_PROFILE, [])
    except McpError as error:
        query, query_stderr, query_error = None, "", error
    if query is None:
        res = Result(*[entry for entry in CHECK_TITLES if entry[0] == "7"][0])
        res.unknown(
            "the agent-query profile was unreadable, so its surface is unknown: %s" % query_error
        )
        results.append(res)
    else:
        record(
            "7", "FIR-3107", "the query profile serves its exact set and costs far fewer bytes",
            grade_query_profile(query, served),
            "agent-query served %d tools in %d bytes against agent-default's %d in %d"
            % (
                len(query.get("tools") or []),
                listing_bytes(query),
                len(served.get("tools") or []),
                listing_bytes(served),
            ),
        )
        if AGENT_QUERY_PROFILE not in (query_stderr or ""):
            results[-1].unknown(
                "the server printed no notice naming %r, so which surface was measured is "
                "unknown" % AGENT_QUERY_PROFILE
            )

    # The tool-search surface. One server, one tools/list and one tools/call per
    # registered tool, because reachability and fidelity are claims about EVERY
    # tool and a sample would pass while one fell out of the index. The calls
    # read no graph, so they cost a frame each.
    registered_names = sorted(
        name for name in (tool.get("name") for tool in (registry or {}).get("tools") or []) if name
    )
    search_ids = ("8", "9", "10", "11")
    try:
        search, lookup_frames, search_stderr = suite.serve(
            AGENT_SEARCH_PROFILE,
            [(TOOL_SEARCH_NAME, {"need": name}) for name in registered_names]
            + [
                ("kin_tool_call", {"tool": "semantic_search", "arguments": {
                    "query": "hello", "compact": True, "limit": 5,
                }}),
                ("semantic_search", {"query": "hello"}),
                ("kin_tool_call", {"tool": "kin_mutate", "arguments": {}}),
            ],
        )
    except McpError as error:
        search, search_stderr, lookup_frames = None, "", []
        for ident, source, title in [e for e in CHECK_TITLES if e[0] in search_ids]:
            res = Result(ident, source, title)
            res.unknown("the agent-search profile was unreadable: %s" % error)
            results.append(res)

    if search is not None:
        record(
            "8", "FIR-3112", "the always-on profile serves its exact set under its byte ceiling",
            grade_search_profile(search),
            "agent-search served %d tools in %d bytes, under the %d-byte ceiling"
            % (
                len(search.get("tools") or []),
                listing_bytes(search),
                AGENT_SEARCH_LIST_CEILING_BYTES,
            ),
        )
        if AGENT_SEARCH_PROFILE not in (search_stderr or ""):
            results[-1].unknown(
                "the server printed no notice naming %r, so which surface was measured is "
                "unknown" % AGENT_SEARCH_PROFILE
            )

        lookups = {
            name: search_payload(frame)
            for name, frame in zip(registered_names, lookup_frames)
        }
        record(
            "11", "discovered query invocation",
            "a hidden query executes while direct profile and write boundaries stay closed",
            grade_discovered_query(
                search, lookups.get("semantic_search"), lookup_frames[len(registered_names):]
            ),
            "the discovered query returned hello from probe.py; direct hidden calls and "
            "wrapped writes were refused",
        )
        if registry is None or not registered_names:
            for ident, source, title in [e for e in CHECK_TITLES if e[0] in ("9", "10")]:
                res = Result(ident, source, title)
                res.unknown(
                    "the registry was unreadable, so reachability and fidelity graded nothing"
                )
                results.append(res)
        else:
            record(
                "9", "FIR-3112", "every registered tool is findable through the served search",
                grade_tool_reachability(registry, lookups),
                "all %d registered tools came back from the served search by name"
                % len(registered_names),
            )
            record(
                "10", "FIR-3112",
                "the schema the search returns is the schema the full profile serves",
                grade_schema_fidelity(registry, lookups),
                "all %d schemas matched the full profile's byte for byte"
                % len(registered_names),
            )

    try:
        routed, routed_frames, routed_stderr = suite.serve(
            AGENT_ROUTED_PROFILE,
            [
                (ROUTED_TOOL_NAME, {"command": "search", "args": {"query": "hello", "limit": 5}}),
                (ROUTED_TOOL_NAME, {"command": "describe", "args": {"command": "search"}}),
            ],
        )
    except McpError as error:
        res = Result(*[entry for entry in CHECK_TITLES if entry[0] == "12"][0])
        res.unknown("the agent-routed profile was unreadable: %s" % error)
        results.append(res)
    else:
        record(
            "12", "routed profile",
            "the routed profile serves one tool under its ceiling and reaches the belt",
            grade_routed_profile(routed, routed_frames[0], routed_frames[1]),
            "agent-routed served %s in %d bytes, under the %d-byte ceiling, and its routed "
            "search returned hello from probe.py"
            % (ROUTED_TOOL_NAME, listing_bytes(routed), ROUTED_LIST_CEILING_BYTES),
        )
        if AGENT_ROUTED_PROFILE not in (routed_stderr or ""):
            results[-1].unknown(
                "the server printed no notice naming %r, so which surface was measured is "
                "unknown" % AGENT_ROUTED_PROFILE
            )

    listings = {}
    unreadable = []
    for profile in ALL_PROFILES:
        try:
            listings[profile], _, _ = suite.serve(profile, [])
        except McpError as error:
            unreadable.append("%s: %s" % (profile, error))
    if unreadable:
        res = Result(*[entry for entry in CHECK_TITLES if entry[0] == "15"][0])
        res.unknown("profiles were unreadable: %s" % "; ".join(unreadable))
        results.append(res)
    else:
        record(
            "15", "portable schemas",
            "no tool on any profile opens its input schema with a combinator",
            grade_portable_schemas(listings),
            "every tool on all %d profiles serves a plain object schema; tools/list bytes: %s"
            % (len(listings), ", ".join(
                "%s %d" % (profile, listing_bytes(listing))
                for profile, listing in sorted(listings.items())
            )),
        )

    # The write path, last, because it edits the fixture every check above reads.
    # Entity ids are stable across an edit, so the id check 2 found serves every
    # call below.
    focal = entity_id_named(search_payload(calls[0]), "hello")
    probe = os.path.join(suite.repo, "src", "probe.py")

    def disk():
        try:
            with open(probe) as handle:
                return handle.read()
        except OSError:
            return None

    def guarded(body, base, description):
        """A whole-entity replacement carrying the source base it was written against."""
        return {"verb": "update", "target": focal, "body": body,
                "payload": {"EntitySourceBase": base}, "description": description}

    committed_body = None
    last_base = None
    write_problems = [] if focal else ["check 2's search named no id for hello"]
    for family, profile, wrap in (
        ("named", AGENT_DEFAULT_PROFILE, lambda tool, command, args: (tool, args)),
        ("routed", AGENT_ROUTED_PROFILE,
         lambda tool, command, args: (ROUTED_TOOL_NAME, {"command": command, "args": args})),
    ):
        if not focal:
            break
        session_id = str(uuid.uuid4())
        body = (
            'def hello(name):\n    """Greet by name. The entity the shipped install proof '
            'seeds and asserts."""\n    return "hello from the %s write path, " + name' % family
        )
        # A replacement names the version it replaces, and the frames below are
        # written before any answer comes back, so the base is read first, per
        # family: the named family's commit moves the one the routed family needs.
        try:
            _, based, _ = suite.serve(profile, [
                wrap("get_entity_source", "source", {"entity_id": focal}),
            ])
        except McpError as error:
            write_problems = None
            write_unread = "the %s server was unreadable: %s" % (profile, error)
            break
        base = (search_payload(based[0]) or {}).get("source_base") if based else None
        if not isinstance(base, dict):
            write_problems.append("%s: get_entity_source served no source_base for hello: %s" % (
                family, (refusal_text(based[0]) if based else None) or json.dumps(based)[:300]))
            continue
        last_base = base
        try:
            _, frames, _ = suite.serve(profile, [
                wrap("kin_session_start", "session", {
                    "vendor": "acceptance", "client_name": "kin-mcp-surface-contract",
                    "cwd": suite.repo, "session_id": session_id,
                }),
                wrap("kin_mutate", "mutate", {
                    "session_id": session_id,
                    "operations": [guarded(body, base, "the %s write path" % family)],
                    "summary": "mcp surface contract: the %s write path" % family,
                }),
                wrap("get_entity_source", "source", {"entity_id": focal}),
                # Guarded as well, so it reaches the session check this frame grades
                # instead of the refusal of an unguarded replacement.
                wrap("kin_mutate", "mutate", {
                    "session_id": str(uuid.uuid4()),
                    "operations": [guarded(body, base, "never opened")],
                    "summary": "never opened",
                }),
            ])
        except McpError as error:
            write_problems = None
            write_unread = "the %s server was unreadable: %s" % (profile, error)
            break
        write_problems.extend(grade_write_family(family, frames, session_id, body, disk()))
        committed_body = body
    if write_problems is None:
        res = Result(*[entry for entry in CHECK_TITLES if entry[0] == "13"][0])
        res.unknown(write_unread)
        results.append(res)
    else:
        record(
            "13", "write surfaces",
            "each write surface opens a session, commits an edit and reads back its exact body",
            write_problems,
            "agent-default's named tools and agent-routed's session and mutate commands each "
            "committed an edit to hello under the caller's own session id, read the exact body "
            "back, and refused a mutate under an unopened session",
        )

    before = disk()
    read_only = None
    if focal and committed_body:
        try:
            _, read_only, read_only_stderr = suite.serve(AGENT_ROUTED_QUERY_PROFILE, [
                (ROUTED_TOOL_NAME, {"command": "source", "args": {"entity_id": focal}}),
                # Guarded, so the profile's own refusal is what answers it.
                (ROUTED_TOOL_NAME, {"command": "mutate", "args": {
                    "session_id": str(uuid.uuid4()),
                    "operations": [guarded("x", last_base or {}, "refused")],
                }}),
                (ROUTED_TOOL_NAME, {"command": "session", "args": {
                    "vendor": "acceptance", "client_name": "kin-mcp-surface-contract",
                    "cwd": suite.repo,
                }}),
                (ROUTED_TOOL_NAME, {"command": "call", "args": {
                    "tool": "kin_mutate", "arguments": {"session_id": str(uuid.uuid4())},
                }}),
            ])
        except McpError as error:
            read_only_error = str(error)
    if read_only is None:
        res = Result(*[entry for entry in CHECK_TITLES if entry[0] == "14"][0])
        res.unknown(
            "the %s profile was not graded: %s" % (
                AGENT_ROUTED_QUERY_PROFILE,
                read_only_error if focal and committed_body else "check 13 committed nothing to read",
            )
        )
        results.append(res)
    else:
        record(
            "14", "read-only routed profile",
            "the read-only routed profile numbers bodies and refuses every write",
            grade_read_only_routed(read_only, committed_body, before, disk()),
            "agent-routed-query numbered hello's body as +N lines that strip back to the "
            "committed text, and refused mutate, session and a call of kin_mutate by naming "
            "agent-routed",
        )
        if AGENT_ROUTED_QUERY_PROFILE not in (read_only_stderr or ""):
            results[-1].unknown(
                "the server printed no notice naming %r, so which surface was measured is "
                "unknown" % AGENT_ROUTED_QUERY_PROFILE
            )

    if verbose:
        for res in results:
            for note in res.notes:
                print("    %s %s" % (res.id, note))
    return results


CHECK_TITLES = [
    ("0", "control", "the graded surface is the profile kin setup registers"),
    ("1", "install-proof + windows-npm",
     "every tool name the shipped proofs assert is served under that name"),
    ("2", "install-proof + windows-npm", "a real tools/call returns the seeded entity"),
    ("3", "magic:6", "trace_data_flow advertises its shape knob"),
    ("4", "magic:14", "the kin_graph_status description names the as-of-earlier shape"),
    ("5", "response_budget:2", "every advertised budget is one a client accepts"),
    ("6", "the general form", "no name is served that the registry does not carry"),
    ("7", "FIR-3107", "the query profile serves its exact set and costs far fewer bytes"),
    ("8", "FIR-3112", "the always-on profile serves its exact set under its byte ceiling"),
    ("9", "FIR-3112", "every registered tool is findable through the served search"),
    ("10", "FIR-3112", "the schema the search returns is the schema the full profile serves"),
    ("11", "discovered query invocation",
     "a hidden query executes while direct profile and write boundaries stay closed"),
    ("12", "routed profile",
     "the routed profile serves one tool under its ceiling and reaches the belt"),
    ("13", "write surfaces",
     "each write surface opens a session, commits an edit and reads back its exact body"),
    ("14", "read-only routed profile",
     "the read-only routed profile numbers bodies and refuses every write"),
    ("15", "portable schemas",
     "no tool on any profile opens its input schema with a combinator"),
]


# ── falsification ───────────────────────────────────────────────────────────


def self_test():
    """Drive every grader against a correct surface and against each break.

    The correct case first, because a grader that fails everything catches the
    regressions and every clean tree with them. Then one break per grader, each
    of which is a thing that actually happened on 2026-09-02.
    """
    problems = []

    def expect(label, got, want_problems):
        if bool(got) != want_problems:
            problems.append(
                "%s: %s, wanted %s"
                % (label, "problems %r" % (got,) if got else "no problems",
                   "problems" if want_problems else "none")
            )

    def listing(**over):
        tools = [
            {
                "name": "semantic_search",
                "description": "Find code declarations.",
                "inputSchema": {"properties": {"query": {}}},
            },
            {
                "name": "trace_data_flow",
                "description": "Walk a chain.",
                "inputSchema": {
                    "properties": {
                        "focal": {},
                        "include_body": {},
                        "max_chars": {"minimum": 500, "default": 25000, "maximum": 60000},
                    }
                },
            },
            {
                "name": "kin_graph_status",
                "description": "Reports health, and may answer with a "
                               "last_settled_selected_graph reading.",
                "inputSchema": {"properties": {}},
            },
        ]
        for name, mutate in over.items():
            for tool in tools:
                if tool["name"] == name.replace("__", "_"):
                    mutate(tool)
        return {"tools": tools}

    registry = {
        "tools": [
            {"name": "semantic_search", "inputSchema": {"properties": {"query": {}}}},
            {
                "name": "trace_data_flow",
                "inputSchema": {
                    "properties": {"max_chars": {"minimum": 500, "default": 25000, "maximum": 60000}}
                },
            },
            {"name": "kin_graph_status", "inputSchema": {"properties": {}}},
        ]
    }

    good = listing()

    # The correct surface: every grader is quiet.
    expect("control on a good notice",
           grade_profile_notice("Kin MCP: serving the default 'agent-default' tool profile (21 tools)."),
           False)
    expect("names on a good listing", grade_proof_asserted_names(good), False)
    expect("knob on a good listing", grade_trace_shape_knob(good), False)
    expect("description on a good listing", grade_graph_status_description(good), False)
    expect("budgets on a good listing", grade_advertised_budgets(good, registry), False)
    expect("registration on a good listing", grade_served_names_are_registered(good, registry), False)
    expect("call on a good result",
           grade_search_call({"result": {"content": [{"text": "hello in probe.py"}]}}), False)
    portable = json.loads(json.dumps(good))
    for tool in portable["tools"]:
        tool["inputSchema"]["type"] = "object"
    expect("portable schemas on a good listing",
           grade_portable_schemas({"agent-default": portable}), False)
    expect("portable schemas on an untyped schema",
           grade_portable_schemas({"agent-default": good}), True)
    combinator = json.loads(json.dumps(portable))
    combinator["tools"][0]["inputSchema"]["anyOf"] = [{"required": ["query"]}, {"required": ["cursor"]}]
    expect("portable schemas on a top-level anyOf",
           grade_portable_schemas({"agent-default": combinator}), True)
    conditional = json.loads(json.dumps(portable))
    conditional["tools"][0]["inputSchema"]["allOf"] = [{"if": {"required": ["request_id"]}}]
    expect("portable schemas on a top-level allOf",
           grade_portable_schemas({"full": conditional}), True)
    expect("portable schemas on no listing", grade_portable_schemas({}), True)

    def profile_listing(names, padding=0):
        return {
            "tools": [
                {
                    "name": name,
                    "description": "d" * (40 + padding),
                    "inputSchema": {"properties": {"query": {}}},
                }
                for name in names
            ]
        }

    default_listing = profile_listing(
        list(AGENT_QUERY_NAMES)
        + [
            "kin_session_start",
            "kin_session_heartbeat",
            "kin_session_end",
            "kin_transaction_begin",
            "kin_transaction_stage",
            "kin_transaction_commit",
            "kin_transaction_abort",
        ],
        padding=400,
    )
    expect("query profile on a good pair",
           grade_query_profile(profile_listing(AGENT_QUERY_NAMES), default_listing), False)

    for retired in ("kin_artifact_read", "kin_artifact_list", "list_file_entities"):
        expect("query profile exposes retired %s" % retired,
               grade_query_profile(profile_listing(list(AGENT_QUERY_NAMES) + [retired]),
                                   default_listing), True)

    # And one break per grader.
    expect("control on the full profile",
           grade_profile_notice("Kin MCP: serving the 'full' tool profile (67 tools) from --tool-profile."),
           True)
    expect("control on no notice at all", grade_profile_notice(""), True)

    renamed = listing()
    renamed["tools"][0]["name"] = "find_declarations"
    expect("names when the served name moved", grade_proof_asserted_names(renamed), True)
    expect("registration when the served name moved",
           grade_served_names_are_registered(renamed, registry), True)

    trimmed_knob = listing()
    del trimmed_knob["tools"][1]["inputSchema"]["properties"]["include_body"]
    expect("knob when the schema was trimmed", grade_trace_shape_knob(trimmed_knob), True)

    trimmed_desc = listing()
    trimmed_desc["tools"][2]["description"] = "Reports health."
    expect("description when the sentence was trimmed",
           grade_graph_status_description(trimmed_desc), True)

    trimmed_budget = listing()
    del trimmed_budget["tools"][1]["inputSchema"]["properties"]["max_chars"]
    expect("budgets when the profile trimmed every one",
           grade_advertised_budgets(trimmed_budget, registry), True)

    over_ceiling = listing()
    over_ceiling["tools"][1]["inputSchema"]["properties"]["max_chars"]["maximum"] = 10_000_000
    expect("budgets when the ceiling is one a client refuses",
           grade_advertised_budgets(over_ceiling, registry), True)

    expect("call on an RPC error", grade_search_call({"error": {"code": -32602}}), True)
    expect("call on isError",
           grade_search_call({"result": {"isError": True, "content": []}}), True)
    expect("call on a result missing the seeded entity",
           grade_search_call({"result": {"content": [{"text": "nothing here"}]}}), True)
    expect("call on no frame at all", grade_search_call(None), True)

    moved = profile_listing(AGENT_QUERY_NAMES)
    moved["tools"][0]["name"] = "find_declarations"
    expect("query profile when a served name moved",
           grade_query_profile(moved, default_listing), True)

    writeful = profile_listing(list(AGENT_QUERY_NAMES) + ["kin_transaction_commit"])
    expect("query profile when a write tool joined it",
           grade_query_profile(writeful, default_listing), True)

    # The whole point of the profile, and the break that would make it
    # pointless: a query listing that costs what the default costs.
    equal_cost = profile_listing(AGENT_QUERY_NAMES)
    equal_cost["tools"][0]["description"] += "d" * (
        listing_bytes(default_listing) - listing_bytes(equal_cost)
    )
    expect("query profile when it saves nothing",
           grade_query_profile(equal_cost, default_listing), True)

    # ── the tool-search surface ─────────────────────────────────────────────
    #
    # A registry of three, a served profile, and the lookups a correct search
    # would return for each name. Small enough to read, and every break below is
    # a thing this design can actually do.
    def definition(name, prop="query"):
        return {
            "name": name,
            "description": "What %s does." % name,
            "annotations": {"title": name, "readOnlyHint": True},
            "inputSchema": {"type": "object", "properties": {prop: {"type": "string"}}},
        }

    search_registry = {
        "tools": [
            definition("semantic_locate"),
            definition("trace_data_flow", "focal"),
            definition("impact_analysis", "entity_ids"),
        ]
    }

    def lookup(name, matches=None, named=None):
        """The payload a correct search returns when asked for one name."""
        found = (
            [tool for tool in search_registry["tools"] if tool["name"] == name]
            if matches is None
            else matches
        )
        return {
            "need": name,
            "matches": found,
            "matched_names": [name] if named is None else named,
            "matches_withheld": 0,
            "registry": {"tools": len(search_registry["tools"])},
        }

    good_lookups = {tool["name"]: lookup(tool["name"]) for tool in search_registry["tools"]}
    good_search = profile_listing(AGENT_SEARCH_NAMES)

    expect("search profile on a good listing", grade_search_profile(good_search), False)
    expect("reachability on good lookups",
           grade_tool_reachability(search_registry, good_lookups), False)
    expect("fidelity on good lookups",
           grade_schema_fidelity(search_registry, good_lookups), False)
    if search_payload(
        {"result": {"content": [{"type": "text", "text": "{\"a\": 1}"}]}}
    ) != {"a": 1}:
        problems.append("payload reader did not read a well-formed tool result")

    # The always-on set moved.
    grown = profile_listing(list(AGENT_SEARCH_NAMES) + ["impact_analysis"])
    expect("search profile when a withheld tool joined it",
           grade_search_profile(grown), True)
    shrunk = profile_listing([n for n in AGENT_SEARCH_NAMES if n != TOOL_SEARCH_NAME])
    expect("search profile when the search tool itself went missing",
           grade_search_profile(shrunk), True)
    renamed_search = profile_listing(AGENT_SEARCH_NAMES)
    renamed_search["tools"][0]["name"] = "context_pack"
    expect("search profile when a served name moved",
           grade_search_profile(renamed_search), True)
    # The ceiling, which is the whole point of the profile.
    expect("search profile when the listing outgrew its ceiling",
           grade_search_profile(profile_listing(AGENT_SEARCH_NAMES, padding=3_000)), True)
    expect("search profile on an empty listing", grade_search_profile({"tools": []}), True)

    # A tool the search stopped finding: the new silent failure.
    lost = dict(good_lookups)
    lost["impact_analysis"] = lookup("impact_analysis", matches=[], named=[])
    expect("reachability when a tool falls out of the index",
           grade_tool_reachability(search_registry, lost), True)
    unanswered = dict(good_lookups)
    unanswered["impact_analysis"] = None
    expect("reachability when the search did not answer",
           grade_tool_reachability(search_registry, unanswered), True)
    expect("reachability when a tool was never looked up",
           grade_tool_reachability(search_registry, {}), True)
    expect("reachability on an empty registry",
           grade_tool_reachability({"tools": []}, good_lookups), True)

    # A schema that drifted from what `full` serves, which reachability alone
    # would pass: the tool is found, and the definition cannot be called from.
    drifted = dict(good_lookups)
    trimmed = json.loads(json.dumps(definition("impact_analysis", "entity_ids")))
    trimmed["inputSchema"]["properties"] = {}
    drifted["impact_analysis"] = lookup("impact_analysis", matches=[trimmed], named=["impact_analysis"])
    expect("fidelity when the returned schema was trimmed",
           grade_schema_fidelity(search_registry, drifted), True)
    summarized = dict(good_lookups)
    short = json.loads(json.dumps(definition("impact_analysis", "entity_ids")))
    short["description"] = "Impact."
    summarized["impact_analysis"] = lookup(
        "impact_analysis", matches=[short], named=["impact_analysis"]
    )
    expect("fidelity when the search returned a short form",
           grade_schema_fidelity(search_registry, summarized), True)
    named_only = dict(good_lookups)
    named_only["impact_analysis"] = lookup(
        "impact_analysis", matches=[], named=["impact_analysis"]
    )
    expect("fidelity when a match was named but not returned",
           grade_schema_fidelity(search_registry, named_only), True)
    expect("fidelity when the search did not answer",
           grade_schema_fidelity(search_registry, unanswered), True)
    expect("fidelity on an empty registry",
           grade_schema_fidelity({"tools": []}, good_lookups), True)

    dispatch_listing = {"tools": [{"name": "kin_tool_call"}]}
    dispatch_lookup = {"invocation": {
        "profile_enabled": {"semantic_search": False},
        "callable_via_dispatcher": {"semantic_search": True},
    }}
    dispatch_frames = [
        {"result": {"content": [{"type": "text", "text": "hello probe.py"}]}},
        {"error": {"message": "tool is not enabled in this MCP profile"}},
        {"error": {"message": "kin_tool_call is read-only"}},
    ]
    expect("discovered query and closed boundaries",
           grade_discovered_query(dispatch_listing, dispatch_lookup, dispatch_frames), False)
    for index in range(3):
        broken = list(dispatch_frames)
        broken[index] = {"result": {"content": []}}
        expect("discovered query broken control %d" % index,
               grade_discovered_query(dispatch_listing, dispatch_lookup, broken), True)
    expect("discovered query missing invocation metadata",
           grade_discovered_query(dispatch_listing, {}, dispatch_frames), True)
    expect("discovered query missing frame",
           grade_discovered_query(dispatch_listing, dispatch_lookup, dispatch_frames[:2]), True)

    # The reader itself: an error frame, an isError result and a body that is
    # not JSON must all read as "no answer" rather than as an empty one.
    for label, frame in (
        ("an RPC error", {"error": {"code": -32602}}),
        ("an isError result", {"result": {"isError": True, "content": []}}),
        ("a body that is not JSON", {"result": {"content": [{"type": "text", "text": "nope"}]}}),
        ("no frame at all", None),
    ):
        if search_payload(frame) is not None:
            problems.append("payload reader read %s as an answer" % label)

    # ── the routed surface ──────────────────────────────────────────────────
    routed_listing = {"tools": [{"name": ROUTED_TOOL_NAME, "description": "d" * 400,
                                 "inputSchema": {"properties": {"command": {}, "args": {}}}}]}
    routed_search = {"result": {"content": [{"type": "text", "text": "hello in probe.py"}]}}
    routed_describe = {"result": {"content": [{"type": "text", "text": json.dumps(
        {"command": "search", "variants": [{"args_schema": {"type": "object"}}]})}]}}
    expect("routed profile on a good surface",
           grade_routed_profile(routed_listing, routed_search, routed_describe), False)
    two_tools = {"tools": routed_listing["tools"] + [{"name": "semantic_locate"}]}
    expect("routed profile when a second tool rides beside the router",
           grade_routed_profile(two_tools, routed_search, routed_describe), True)
    heavy = {"tools": [dict(routed_listing["tools"][0], description="d" * 4_000)]}
    expect("routed profile over its ceiling",
           grade_routed_profile(heavy, routed_search, routed_describe), True)
    expect("routed profile when the routed search failed",
           grade_routed_profile(routed_listing, {"error": {"code": -32602}}, routed_describe),
           True)
    expect("routed profile when describe answered nothing",
           grade_routed_profile(routed_listing, routed_search, None), True)
    expect("routed profile on an empty listing",
           grade_routed_profile({"tools": []}, routed_search, routed_describe), True)

    # ── the write surfaces ──────────────────────────────────────────────────
    def answer(payload, is_error=False):
        result = {"content": [{"type": "text", "text": json.dumps(payload)}]}
        if is_error:
            result["isError"] = True
        return {"result": result}

    session = "3f0c7a52-1111-4222-8333-944445555666"
    body = 'def hello(name):\n    return "hi " + name'
    write_frames = [
        answer({"session_id": session, "status": "active"}),
        answer({"status": "committed"}),
        answer({"name": "hello", "body": body}),
        answer({"message": "Session not found: 1. It was ended."}, is_error=True),
    ]
    disk_text = "x\n" + body + "\n"
    expect("write family on a good run",
           grade_write_family("routed", write_frames, session, body, disk_text), False)
    for label, index, frame in (
        ("a refused session", 0, answer({"message": "no"}, is_error=True)),
        ("a session under another id", 0, answer({"session_id": "other"})),
        ("a refused mutate", 1, answer({"message": "no"}, is_error=True)),
        ("a staged but uncommitted mutate", 1, answer({"status": "staged"})),
        ("a numbered body on a write surface", 2,
         answer({"body": "+0\tdef hello(name):\n+1\t    return \"hi \" + name",
                 "about_body": "note"})),
        ("an old body", 2, answer({"body": "def hello(name):\n    return 1"})),
        ("an unopened session that was accepted", 3, answer({"status": "committed"})),
        ("an unopened session refused by routing", 3,
         answer({"message": "Commands: locate, search."}, is_error=True)),
    ):
        broken = list(write_frames)
        broken[index] = frame
        expect("write family on %s" % label,
               grade_write_family("routed", broken, session, body, disk_text), True)
    expect("write family when the file kept the old text",
           grade_write_family("routed", write_frames, session, body, "x\n"), True)
    expect("write family on a missing frame",
           grade_write_family("routed", write_frames[:3], session, body, disk_text), True)

    refusal = answer({"message": "mutate writes, and this connection serves the read-only "
                                 "agent-routed-query profile. " + ROUTED_WRITE_REFUSAL},
                     is_error=True)
    numbered = "\n".join("+%d\t%s" % (index, line) for index, line in enumerate(body.split("\n")))
    read_only_frames = [
        answer({"body": numbered, NUMBERING_KEY: "Each body line starts with +N."}),
        refusal, refusal, refusal,
    ]
    expect("read-only routed on a good run",
           grade_read_only_routed(read_only_frames, body, disk_text, disk_text), False)
    for label, index, frame in (
        ("an unnumbered body", 0, answer({"body": body, NUMBERING_KEY: "note"})),
        ("a body with no note", 0, answer({"body": numbered})),
        ("offsets out of order", 0,
         answer({"body": numbered.replace("+1\t", "+2\t"), NUMBERING_KEY: "note"})),
        ("a numbered body of other text", 0,
         answer({"body": "+0\tdef other():", NUMBERING_KEY: "note"})),
        ("an accepted mutate", 1, answer({"status": "committed"})),
        ("a session refused without naming the write profile", 2,
         answer({"message": "refused"}, is_error=True)),
        ("an accepted call of kin_mutate", 3, answer({"status": "committed"})),
    ):
        broken = list(read_only_frames)
        broken[index] = frame
        expect("read-only routed on %s" % label,
               grade_read_only_routed(broken, body, disk_text, disk_text), True)
    expect("read-only routed when the file changed",
           grade_read_only_routed(read_only_frames, body, disk_text, disk_text + "y"), True)
    if entity_id_named({"results": [{"name": "hello", "entity_id": "e1"}]}, "hello") != "e1":
        problems.append("the id reader missed a named entity")
    if entity_id_named({"results": [{"name": "caller", "entity_id": "e2"}]}, "hello") is not None:
        problems.append("the id reader returned an entity of another name")

    # An empty listing must never read as a clean surface.
    expect("names on an empty listing", grade_proof_asserted_names({"tools": []}), True)
    expect("knob on an empty listing", grade_trace_shape_knob({"tools": []}), True)
    expect("description on an empty listing", grade_graph_status_description({"tools": []}), True)
    expect("budgets on an empty listing", grade_advertised_budgets({"tools": []}, registry), True)
    expect("query profile on an empty listing",
           grade_query_profile({"tools": []}, default_listing), True)

    for problem in problems:
        print("SELF-TEST FAIL %s" % problem)
    if problems:
        return 1
    print("mcp-surface-contract self-test: every grader passed its correct case "
          "and failed each break")
    return 0


def main(argv):
    parser = argparse.ArgumentParser(
        add_help=True, description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--kin", default=os.environ.get("KIN_BIN"), help="the kin binary under test")
    parser.add_argument("--daemon", default=os.environ.get("KIN_DAEMON_BIN"),
                        help="the kin-daemon binary the server should spawn")
    parser.add_argument("--workdir", default=None, help="where to build the fixture")
    parser.add_argument("--json", default=None, help="write the report here")
    parser.add_argument("--label", default="", help="label recorded in the report")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    opts = parser.parse_args(argv)

    if opts.self_test:
        return self_test()

    if not opts.kin:
        sys.stderr.write("no kin binary: pass --kin PATH or set KIN_BIN\n")
        return 3
    kin = os.path.abspath(opts.kin)
    if not os.path.isfile(kin) or not os.access(kin, os.X_OK):
        sys.stderr.write("kin binary %s is missing or not executable\n" % kin)
        return 3

    workdir = opts.workdir or tempfile.mkdtemp(prefix="kin-mcp-surface-")
    if not os.path.isdir(workdir):
        os.makedirs(workdir)
    suite = Suite(kin, os.path.abspath(workdir), opts.verbose, opts.daemon)
    try:
        suite.fixture()
    except (SetupError, subprocess.TimeoutExpired) as error:
        sys.stderr.write("setup failed: %s\n" % error)
        return 3

    results = run_checks(suite, opts.verbose)
    for res in results:
        print("CHECK %s %s %s %s" % (res.id, res.source, res.status, res.detail))
    # A run that graded fewer checks than this file declares reported a green
    # summary for coverage it never had, which is the shape every check in here
    # exists to refuse. It is its own outcome rather than a pass with a warning.
    if len(results) != len(CHECK_TITLES):
        print(
            "mcp surface contract: graded %d of %d checks, so this run says nothing "
            "about the ones it skipped" % (len(results), len(CHECK_TITLES))
        )
        return 2
    failed = [res for res in results if res.status == FAIL]
    unread = [res for res in results if res.status == UNREADABLE]
    print(
        "mcp surface contract: %d PASS, %d FAIL, %d UNREADABLE"
        % (len(results) - len(failed) - len(unread), len(failed), len(unread))
    )
    if opts.json:
        directory = os.path.dirname(os.path.abspath(opts.json))
        if directory and not os.path.isdir(directory):
            os.makedirs(directory)
        with open(opts.json, "w") as handle:
            json.dump(
                {"label": opts.label, "results": [res.row() for res in results]},
                handle, indent=2, sort_keys=True,
            )
            handle.write("\n")
    if failed:
        return 1
    if unread:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
