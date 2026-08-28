#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

"""Prove trace cuts preserve and explain the branch the caller asked for.

FIR-2781 established checks 0 through 3. The v0.6.0 stranger run walked `Session.send` on a converted
`psf/requests` with `limit_per_step: 4` and got a chain that stops two hops
short of where `verify` goes. The per-step cap had discarded eleven of fifteen
callees, `HTTPAdapter.send` among them, and the response said so only as a count
in `clipped_steps`. Their words: "If I had trusted it, I would have written that
`verify` ends at `Session.send`."

The cap did not discard at random. `trace_fanout_score` ranks a candidate in the
expanded node's own file above one in any other file, as a hard tier above
declaration kind and above confidence, so a node with more same-file neighbors
than the cap allows never leaves its module. That is a proximity term, and no
question is an input to it.

The class this suite pins is not "a hop was dropped". A cap has to drop
something. It is that a chain missing its point reads exactly like a complete
one, because the honest label the tool already carried ("treat this as a lower
bound") is the same label a complete walk carries.

The extension adds checks 4 through 7. A target that steers discovery must also
survive both response-budget decisions, and each surviving step must carry the
exact graph-owned call-site lines that make the hop actionable.

Eight checks, on one seeded repository:

  0  a walk the cap cut BENEATH a node it then continued through says so in
     words, naming the node, the parameter and the count, and saying that an
     absence in this chain proves nothing
  1  that disclosure separates module-crossing losses from same-file breadth, so
     a reader can tell which class of hop went
  2  naming a `target` puts the module-crossing hop in the chain at the same cap
     that loses it unnamed, with the unnamed walk asserted beside it, because
     either half alone is satisfiable by a broken tool
  3  a walk no cap cut publishes none of this, and the keys are ABSENT rather
     than zero, so machinery for incomplete answers never qualifies a complete one
  4  a wide walk proves `cert_verify` was discovered, then a response-budget
     cut with that target keeps it and proves the budget actually bit
  5  the same response budget without a target drops `cert_verify`, beside the
     targeted arm, so the named question rather than the fixture delivers it
  6  callee steps carry the exact 1-based call sites from their parent files,
     including the cross-module hop and the next step beyond it
  7  the cross-file `send_via_adapter` edge walked backwards reports `send` as
     a caller and carries that caller's exact site from `sessions.py`

Exit status is 0 when every check passed, 1 when one failed, 2 when one could not
be read, and 3 when the run could not be set up. `--self-test` exercises every
grader against its inverse and needs no binary, so a grader that cannot fail is a
failure here rather than a silent pass in CI.
"""
from __future__ import print_function

import argparse
import functools
import json
import os
import shutil
import subprocess
import sys
import tempfile

PASS = "PASS"
FAIL = "FAIL"
UNREADABLE = "UNREADABLE"

print = functools.partial(print, flush=True)

# The wording a caller has to be unable to read as a mere lower bound. Asserted
# as a substring of the walker's own disclosure, because the number beside it
# (`spine_clipped_steps`) is what a machine reads and this is what a person does.
REFUSAL_PHRASE = "absence proves nothing"

# One module whose entry point calls many neighbours in its own file and exactly
# one function in another module. That is the measured shape: the cap fills on
# same-file callees and the hop that leaves the module is the one the question is
# about.
SESSIONS_SRC = '''"""Session layer."""

from adapters import send_via_adapter


def record_adapter(url):
    return url


def normalize_adapter(url):
    return record_adapter(url)


def get_adapter(url):
    return normalize_adapter(url)


def prepare_request(request):
    return request


def resolve_redirects(response):
    return response


def rebuild_auth(request):
    return request


def rebuild_proxies(request):
    return request


def rebuild_method(request):
    return request


def merge_settings(request):
    return request


def should_strip_auth(old, new):
    return old != new


def close_session(state):
    return state


def send(request, verify=True):
    """The focal. Nine same-file callees and one that leaves the module."""
    adapter = get_adapter(request)
    prepared = prepare_request(request)
    prepared = rebuild_auth(prepared)
    prepared = rebuild_proxies(prepared)
    prepared = rebuild_method(prepared)
    prepared = merge_settings(prepared)
    should_strip_auth(request, prepared)
    response = send_via_adapter(adapter, prepared, verify)
    resolve_redirects(response)
    close_session(response)
    return response
'''

ADAPTERS_SRC = '''"""Adapter layer: where verify leaves the session."""


def cert_verify(conn, verify):
    conn["cert_reqs"] = "CERT_REQUIRED" if verify else "CERT_NONE"
    return conn


def send_via_adapter(adapter, request, verify):
    """The hop the question is about."""
    return cert_verify({"adapter": adapter, "request": request}, verify)
'''

CROSSING_HOP = "send_via_adapter"
ELISION_TARGET = "cert_verify"
CALLER_ENTITY = "send"
SESSIONS_FILE = "sessions.py"
ADAPTERS_FILE = "adapters.py"
# Small enough to force branch narrowing on this body-free fixture, while still
# leaving room for the protected two-hop branch plus the bounder's disclosure.
RESPONSE_BUDGET = 4000
WIDE_RESPONSE_BUDGET = 60000
ELISION_DEPTH = 3
ELISION_LIMIT = 25


def fixture_line(source, needle):
    matches = [
        number for number, line in enumerate(source.splitlines(), 1)
        if needle in line
    ]
    if len(matches) != 1:
        raise AssertionError("fixture line %r matched %d times" % (needle, len(matches)))
    return matches[0]


SESSION_ADAPTER_CALL_LINE = fixture_line(SESSIONS_SRC, "response = send_via_adapter(")
ADAPTER_CERT_CALL_LINE = fixture_line(ADAPTERS_SRC, "return cert_verify(")


def run(cmd, cwd=None, env=None, timeout=600):
    proc = subprocess.Popen(
        cmd, cwd=cwd, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        universal_newlines=True,
    )
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
        return 124, out, err
    return proc.returncode, out, err


# ── graders ────────────────────────────────────────────────────────────────
#
# Every grader takes a parsed payload and returns (status, detail). Kept apart
# from the run so `--self-test` can hand each one a payload that must pass and a
# payload that must fail, with no binary anywhere.


def spine_disclosure(payload):
    """The `fanout_cap` / `spine_clipped` degradation, or None."""
    if not isinstance(payload, dict):
        return None
    for entry in payload.get("degradations") or []:
        if not isinstance(entry, dict):
            continue
        if entry.get("component") == "fanout_cap" and entry.get("reason") == "spine_clipped":
            return entry
    return None


def grade_says_the_absence_proves_nothing(payload):
    steps = payload.get("spine_clipped_steps")
    if steps is None:
        return UNREADABLE, "no spine_clipped_steps key on a walk that should carry one"
    if steps < 1:
        return FAIL, "spine_clipped_steps is %r on a walk the cap cut beneath" % (steps,)
    disclosure = spine_disclosure(payload)
    if disclosure is None:
        return FAIL, "spine_clipped_steps is %r and nothing in degradations says so" % (steps,)
    detail = disclosure.get("detail") or ""
    missing = [
        name for name, present in (
            ("limit_per_step", "limit_per_step" in detail),
            ("the refusal phrase", REFUSAL_PHRASE in detail),
            ("a clipped node name", "'" in detail),
        ) if not present
    ]
    if missing:
        return FAIL, "the disclosure omits %s: %r" % (", ".join(missing), detail[:220])
    remediation = disclosure.get("remediation") or ""
    if "target" not in remediation:
        return FAIL, "the disclosure names no lever: %r" % (remediation[:180],)
    return PASS, "spine_clipped_steps=%r and the disclosure names the node, the cap and the lever" % (steps,)


def grade_separates_the_class_of_loss(payload):
    clips = payload.get("clipped_steps")
    if not isinstance(clips, list) or not clips:
        return UNREADABLE, "no clipped_steps array to read a class of loss from"
    on_spine = [clip for clip in clips if isinstance(clip, dict) and clip.get("continued_below")]
    if not on_spine:
        return FAIL, "no clip reports continued_below, so no loss is attributable to the spine"
    crossing = sum(clip.get("dropped_crossing_file") or 0 for clip in on_spine)
    dropped = sum(
        (clip.get("dropped_callees") or 0) + (clip.get("dropped_callers") or 0)
        for clip in on_spine
    )
    if dropped < 1:
        return FAIL, "a clip on the spine dropped nothing, which is not a clip"
    if crossing < 1:
        return FAIL, (
            "the spine dropped %d neighbour(s) and none is reported as module-crossing, so the "
            "class of hop the question is about is indistinguishable from same-file breadth"
            % (dropped,)
        )
    if payload.get("spine_dropped_crossing_file") != crossing:
        return FAIL, (
            "the top-level spine_dropped_crossing_file (%r) disagrees with the clips (%d)"
            % (payload.get("spine_dropped_crossing_file"), crossing)
        )
    return PASS, "%d of %d spine losses are reported as module-crossing" % (crossing, dropped)


def chain_names(payload):
    chain = payload.get("chain")
    if not isinstance(chain, list):
        return None
    return [
        step.get("entity_name")
        for step in chain
        if isinstance(step, dict)
    ]


def grade_the_target_is_what_delivers_the_hop(untargeted, targeted):
    """Both arms, because either alone is satisfiable by a broken tool.

    A tool that ignored the cap entirely would pass the targeted half. A tool
    that returned an empty chain would pass the untargeted half. Only the pair
    says the question is what moved the answer.
    """
    without = chain_names(untargeted)
    with_target = chain_names(targeted)
    if without is None or with_target is None:
        return UNREADABLE, "one of the two walks returned no readable chain"
    if CROSSING_HOP in without:
        return FAIL, (
            "the untargeted walk already contains %s, so this fixture no longer reproduces the "
            "loss and the targeted half proves nothing: %r" % (CROSSING_HOP, without)
        )
    if CROSSING_HOP not in with_target:
        return FAIL, (
            "naming %s as the target did not put it in the chain: %r" % (CROSSING_HOP, with_target)
        )
    if targeted.get("target_name") != CROSSING_HOP:
        return FAIL, (
            "the response does not echo the question it was given: target_name=%r"
            % (targeted.get("target_name"),)
        )
    return PASS, "%s is absent unnamed and present when named" % (CROSSING_HOP,)


def grade_a_complete_walk_is_not_qualified(payload):
    if spine_disclosure(payload) is not None:
        return FAIL, "a walk no cap cut carries a spine_clipped disclosure"
    present = [
        key for key in ("spine_clipped_steps", "spine_dropped_crossing_file", "clipped_steps")
        if key in payload
    ]
    if present:
        return FAIL, (
            "a walk no cap cut carries %s; these keys must be absent, not zero, or a reader "
            "cannot tell an unaffected walk from one that reported nothing"
            % (", ".join(present),)
        )
    if not chain_names(payload):
        return UNREADABLE, "the control walk returned no chain, so it grades nothing"
    return PASS, "no clip, no spine key, no disclosure on a walk the cap never cut"


def response_budget_degradations(payload, reason):
    return [
        item for item in payload.get("degradations") or []
        if isinstance(item, dict)
        and item.get("component") == "response_budget"
        and item.get("reason") == reason
    ]


def graph_bounds_problem(payload, budget):
    expected = {
        "depth": ELISION_DEPTH,
        "direction": "calls",
        "limit_per_step": ELISION_LIMIT,
        "max_response_chars": budget,
        "bodies_included": False,
    }
    mismatches = [
        "%s=%r (wanted %r)" % (key, payload.get(key), value)
        for key, value in expected.items()
        if payload.get(key) != value
    ]
    return ", ".join(mismatches) if mismatches else None


def pretty_serialized_bytes(payload):
    """Match serde_json::to_string_pretty(...).len() for the ASCII fixture."""
    return len(json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8"))


def fanout_clip_problem(payload):
    clips = payload.get("clipped_steps")
    if clips:
        return "clipped_steps is nonempty, so per-step fanout loss can masquerade as response elision"
    if payload.get("spine_clipped_steps"):
        return "spine_clipped_steps is nonzero, so the walk itself was clipped"
    chain = payload.get("chain") or []
    truncated = [
        step.get("entity_name")
        for step in chain
        if isinstance(step, dict) and step.get("fanout_truncated")
    ]
    if truncated:
        return "chain rows report fanout_truncated: %r" % (truncated,)
    return None


def parentage_problem(payload, require_target):
    chain = payload.get("chain")
    if not isinstance(chain, list):
        return "the response carries no chain array"
    rows = [step for step in chain if isinstance(step, dict)]
    if len(rows) != len(chain):
        return "the chain carries a non-object step"
    by_step = {}
    for row in rows:
        step = row.get("step")
        parent = row.get("parent_step")
        if not isinstance(step, int) or not isinstance(parent, int):
            return "a chain row carries a non-integer step or parent_step"
        if step in by_step:
            return "step %r appears more than once" % (step,)
        by_step[step] = row
    for row in rows:
        parent = row["parent_step"]
        if parent != 0 and parent not in by_step:
            return "%s points at missing parent step %r" % (
                row.get("entity_name"), parent,
            )
    if not require_target:
        return None
    hops = [row for row in rows if row.get("entity_name") == CROSSING_HOP]
    targets = [row for row in rows if row.get("entity_name") == ELISION_TARGET]
    if len(hops) != 1 or len(targets) != 1:
        return "the target path needs exactly one %s and one %s, found %d and %d" % (
            CROSSING_HOP, ELISION_TARGET, len(hops), len(targets),
        )
    if targets[0]["parent_step"] != hops[0]["step"]:
        return "%s parent_step=%r does not name surviving %s step=%r" % (
            ELISION_TARGET, targets[0]["parent_step"], CROSSING_HOP, hops[0]["step"],
        )
    return None


def indexed_chain(payload, label):
    """Index one chain by local step and canonical entity identity."""
    chain = payload.get("chain")
    if not isinstance(chain, list):
        return None, "%s response carries no chain array" % label
    by_step = {}
    by_identity = {}
    for row in chain:
        if not isinstance(row, dict):
            return None, "%s chain carries a non-object step" % label
        step = row.get("step")
        identity = row.get("entity_id")
        name = row.get("entity_name")
        if not isinstance(step, int):
            return None, "%s row carries non-integer step=%r" % (label, step)
        if not isinstance(identity, str) or not identity:
            return None, "%s step %r carries no canonical entity_id" % (label, step)
        if not isinstance(name, str) or not name:
            return None, "%s entity %s carries no entity_name" % (label, identity)
        if step in by_step:
            return None, "%s step %r appears more than once" % (label, step)
        if identity in by_identity:
            return None, "%s entity_id %s appears more than once" % (label, identity)
        by_step[step] = row
        by_identity[identity] = row
    return (by_step, by_identity), None


def bounded_subset_problem(payload, wide):
    """Every bounded row and parent edge must come from the wide discovery."""
    wide_index, problem = indexed_chain(wide, "wide")
    if problem:
        return problem
    bounded_index, problem = indexed_chain(payload, "bounded")
    if problem:
        return problem
    wide_by_step, wide_by_identity = wide_index
    bounded_by_step, bounded_by_identity = bounded_index

    def parent_identity(row, by_step, label):
        parent = row.get("parent_step")
        if parent == 0:
            return "<focal>", None
        parent_row = by_step.get(parent)
        if parent_row is None:
            return None, "%s step %r points at missing parent step %r" % (
                label, row.get("step"), parent,
            )
        return parent_row.get("entity_id"), None

    for identity, row in bounded_by_identity.items():
        source = wide_by_identity.get(identity)
        if source is None:
            return "bounded entity_id %s was not discovered by the wide arm" % identity
        for key in ("entity_name", "role"):
            if row.get(key) != source.get(key):
                return "bounded entity %s changed %s from %r to %r" % (
                    identity, key, source.get(key), row.get(key),
                )
        bounded_parent, problem = parent_identity(row, bounded_by_step, "bounded")
        if problem:
            return problem
        wide_parent, problem = parent_identity(source, wide_by_step, "wide")
        if problem:
            return problem
        if bounded_parent != wide_parent:
            return "bounded edge into %s changed parent identity from %r to %r" % (
                identity, wide_parent, bounded_parent,
            )
    return None


def wide_premise_problem(payload):
    bounds = graph_bounds_problem(payload, WIDE_RESPONSE_BUDGET)
    if bounds:
        return "wide bounds drifted: " + bounds
    rendered_chars = pretty_serialized_bytes(payload)
    if rendered_chars > WIDE_RESPONSE_BUDGET:
        return "the wide response serializes to %d bytes, above its %d-byte budget" % (
            rendered_chars, WIDE_RESPONSE_BUDGET,
        )
    clips = fanout_clip_problem(payload)
    if clips:
        return clips
    if payload.get("steps_omitted") or payload.get("fanout_narrowed") \
            or payload.get("chain_withheld"):
        return "the wide premise reports response step loss"
    if (payload.get("elisions") or {}).get("chain"):
        return "the wide premise carries an elisions.chain cut"
    if response_budget_degradations(payload, "steps_omitted") \
            or response_budget_degradations(payload, "response_bounded"):
        return "the wide premise carries a response-budget step-loss degradation"
    chain = payload.get("chain")
    if isinstance(chain, list) and payload.get("total_steps") != len(chain):
        return "wide total_steps=%r disagrees with chain length %d" % (
            payload.get("total_steps"), len(chain),
        )
    problem = parentage_problem(payload, require_target=True)
    if problem:
        return problem
    _, problem = indexed_chain(payload, "wide")
    return problem


def bounded_elision_problem(payload, wide):
    bounds = graph_bounds_problem(payload, RESPONSE_BUDGET)
    if bounds:
        return "bounded bounds drifted: " + bounds
    rendered_chars = pretty_serialized_bytes(payload)
    if rendered_chars > RESPONSE_BUDGET:
        return "the bounded response serializes to %d bytes, above its %d-byte budget" % (
            rendered_chars, RESPONSE_BUDGET,
        )
    clips = fanout_clip_problem(payload)
    if clips:
        return clips
    chain = payload.get("chain")
    if not isinstance(chain, list):
        return "the response carries no chain array"
    wide_chain = wide.get("chain")
    if not isinstance(wide_chain, list):
        return "the wide response carries no chain array"
    if len(chain) >= len(wide_chain):
        return "the bounded chain kept %d of %d steps, so the budget cut nothing" % (
            len(chain), len(wide_chain),
        )
    omitted = payload.get("steps_omitted")
    narrowed = payload.get("fanout_narrowed")
    if not isinstance(omitted, int) or omitted <= 0:
        return "steps_omitted=%r does not prove a response cut" % (omitted,)
    if not isinstance(narrowed, int) or narrowed <= 0 or narrowed > omitted:
        return "fanout_narrowed=%r is not a positive subset of steps_omitted=%r" % (
            narrowed, omitted,
        )
    if len(chain) + omitted != len(wide_chain):
        return "bounded kept plus omitted is %d, but the wide premise discovered %d steps" % (
            len(chain) + omitted, len(wide_chain),
        )
    if payload.get("total_steps") != len(chain):
        return "total_steps=%r disagrees with bounded chain length %d" % (
            payload.get("total_steps"), len(chain),
        )
    elision = (payload.get("elisions") or {}).get("chain")
    if not isinstance(elision, dict):
        return "the cut carries no elisions.chain object"
    expected = {
        "kept": len(chain),
        "elided": omitted,
        "total": len(wide_chain),
        "reason": "response_budget",
    }
    mismatches = [
        "%s=%r (wanted %r)" % (key, elision.get(key), value)
        for key, value in expected.items()
        if elision.get(key) != value
    ]
    if mismatches:
        return "elisions.chain disagrees: " + ", ".join(mismatches)
    if len(response_budget_degradations(payload, "steps_omitted")) != 1:
        return "the cut needs exactly one response_budget/steps_omitted degradation"
    problem = parentage_problem(payload, require_target=False)
    if problem:
        return problem
    return bounded_subset_problem(payload, wide)


def grade_named_target_survives_response_budget(wide, bounded):
    if not isinstance(wide, dict) or not isinstance(bounded, dict):
        return UNREADABLE, "the wide or bounded response is not an object"
    if not isinstance(wide.get("chain"), list) or not isinstance(bounded.get("chain"), list):
        return UNREADABLE, "the wide or bounded response carries no readable chain"
    problem = wide_premise_problem(wide)
    if problem:
        return FAIL, "the wide discovery premise is not sound: " + problem
    problem = bounded_elision_problem(bounded, wide)
    if problem:
        return FAIL, "the targeted bounded arm is not a coherent response cut: " + problem
    if bounded.get("target_name") != ELISION_TARGET:
        return FAIL, "the bounded response does not echo target_name=%s" % (ELISION_TARGET,)
    problem = parentage_problem(bounded, require_target=True)
    if problem:
        return FAIL, "the named target path did not survive intact: " + problem
    return PASS, "%s and its %s parent survived; steps_omitted=%d, fanout_narrowed=%d" % (
        ELISION_TARGET,
        CROSSING_HOP,
        bounded["steps_omitted"],
        bounded["fanout_narrowed"],
    )


def grade_unnamed_response_budget_drops_the_target(wide, targeted, unnamed):
    if not all(isinstance(payload, dict) for payload in (wide, targeted, unnamed)):
        return UNREADABLE, "one of the three response arms is not an object"
    if not all(isinstance(payload.get("chain"), list) for payload in (wide, targeted, unnamed)):
        return UNREADABLE, "one of the three response arms carries no readable chain"
    target_status, target_detail = grade_named_target_survives_response_budget(wide, targeted)
    if target_status != PASS:
        return FAIL, "the paired targeted arm is not a valid control: " + target_detail
    problem = bounded_elision_problem(unnamed, wide)
    if problem:
        return FAIL, "the unnamed bounded arm is not a coherent response cut: " + problem
    names = chain_names(unnamed)
    if ELISION_TARGET in names:
        return FAIL, "the unnamed arm still contains %s: %r" % (ELISION_TARGET, names)
    if unnamed.get("target_name") is not None:
        return FAIL, "the unnamed arm reports target_name=%r" % (unnamed.get("target_name"),)
    for entry in unnamed.get("degradations") or []:
        if isinstance(entry, dict) and "named target" in (entry.get("detail") or ""):
            return FAIL, "the unnamed arm claims a named target branch was kept"
    return PASS, "%s survives only in the paired targeted cut; unnamed steps_omitted=%d" % (
        ELISION_TARGET, unnamed["steps_omitted"],
    )


def reference_line_contract_problem(payload):
    chain = payload.get("chain")
    if not isinstance(chain, list):
        return "the response carries no chain array"
    for index, step in enumerate(chain):
        if not isinstance(step, dict):
            return "chain row %d is not an object" % index
        for key in ("reference_lines", "reference_lines_absent_reason"):
            if key not in step:
                return "%s omits required key %s" % (step.get("entity_name"), key)
        lines = step["reference_lines"]
        reason = step["reference_lines_absent_reason"]
        if not isinstance(lines, list) or any(
                not isinstance(line, int) or line < 1 for line in lines):
            return "%s carries invalid 1-based reference_lines=%r" % (
                step.get("entity_name"), lines,
            )
        if lines != sorted(set(lines)):
            return "%s reference_lines are not sorted and deduplicated: %r" % (
                step.get("entity_name"), lines,
            )
        if lines and reason is not None:
            return "%s has site lines but also absent reason %r" % (
                step.get("entity_name"), reason,
            )
        if not lines and (not isinstance(reason, str) or not reason):
            return "%s has no site lines and no explicit absent reason" % (
                step.get("entity_name"),
            )
        allowed_reasons = {
            "no_evidence_span",
            "span_outside_caller_file",
            "federated_xref",
            "unreported_by_daemon",
        }
        if not lines and reason not in allowed_reasons:
            return "%s has unknown reference_lines_absent_reason=%r" % (
                step.get("entity_name"), reason,
            )
    return None


def one_step(payload, name):
    matches = [
        step for step in payload.get("chain") or []
        if isinstance(step, dict) and step.get("entity_name") == name
    ]
    if len(matches) != 1:
        return None, "%s appears %d times" % (name, len(matches))
    return matches[0], None


def grade_callee_call_sites(payload):
    if not isinstance(payload, dict) or not isinstance(payload.get("chain"), list):
        return UNREADABLE, "the callee walk carries no readable chain"
    problem = wide_premise_problem(payload)
    if problem:
        return FAIL, "the callee walk is not a complete wide premise: " + problem
    problem = reference_line_contract_problem(payload)
    if problem:
        return FAIL, problem
    expected = (
        (CROSSING_HOP, SESSION_ADAPTER_CALL_LINE),
        (ELISION_TARGET, ADAPTER_CERT_CALL_LINE),
    )
    for name, line in expected:
        step, problem = one_step(payload, name)
        if problem:
            return FAIL, problem
        if step.get("role") != "callee":
            return FAIL, "%s role=%r, wanted callee" % (name, step.get("role"))
        if step["reference_lines"] != [line]:
            return FAIL, "%s reference_lines=%r, wanted [%d]" % (
                name, step["reference_lines"], line,
            )
        if step["reference_lines_absent_reason"] is not None:
            return FAIL, "%s carries an absent reason beside a known site" % name
    return PASS, "%s line %d and %s line %d come from their parent files" % (
        CROSSING_HOP,
        SESSION_ADAPTER_CALL_LINE,
        ELISION_TARGET,
        ADAPTER_CERT_CALL_LINE,
    )


def grade_caller_call_site(payload):
    if not isinstance(payload, dict) or not isinstance(payload.get("chain"), list):
        return UNREADABLE, "the caller walk carries no readable chain"
    expected_bounds = {
        "depth": 1,
        "direction": "callers",
        "limit_per_step": ELISION_LIMIT,
        "max_response_chars": WIDE_RESPONSE_BUDGET,
        "bodies_included": False,
    }
    mismatches = [
        "%s=%r (wanted %r)" % (key, payload.get(key), value)
        for key, value in expected_bounds.items()
        if payload.get(key) != value
    ]
    if mismatches:
        return FAIL, "caller bounds drifted: " + ", ".join(mismatches)
    problem = fanout_clip_problem(payload)
    if problem:
        return FAIL, problem
    if payload.get("steps_omitted") or payload.get("fanout_narrowed") \
            or payload.get("chain_withheld") or (payload.get("elisions") or {}).get("chain"):
        return FAIL, "the caller walk was response-bounded, so it is not a complete premise"
    if payload.get("total_steps") != len(payload["chain"]):
        return FAIL, "caller total_steps disagrees with its chain length"
    problem = parentage_problem(payload, require_target=False)
    if problem:
        return FAIL, problem
    problem = reference_line_contract_problem(payload)
    if problem:
        return FAIL, problem
    step, problem = one_step(payload, CALLER_ENTITY)
    if problem:
        return FAIL, problem
    if step.get("role") != "caller":
        return FAIL, "%s role=%r, wanted caller" % (CALLER_ENTITY, step.get("role"))
    if payload.get("focal_file") != ADAPTERS_FILE:
        return FAIL, "caller focal_file=%r, wanted %s" % (
            payload.get("focal_file"), ADAPTERS_FILE,
        )
    if step.get("entity_file") != SESSIONS_FILE:
        return FAIL, "%s entity_file=%r, wanted %s" % (
            CALLER_ENTITY, step.get("entity_file"), SESSIONS_FILE,
        )
    if step.get("entity_file") == payload.get("focal_file"):
        return FAIL, "the caller and focal are in one file, so role-based file selection is untested"
    if step["reference_lines"] != [SESSION_ADAPTER_CALL_LINE]:
        return FAIL, "%s caller reference_lines=%r, wanted [%d]" % (
            CALLER_ENTITY, step["reference_lines"], SESSION_ADAPTER_CALL_LINE,
        )
    if step["reference_lines_absent_reason"] is not None:
        return FAIL, "%s carries an absent reason beside a known caller site" % CALLER_ENTITY
    return PASS, "%s walked as caller reports sessions.py line %d from a different file" % (
        CALLER_ENTITY, SESSION_ADAPTER_CALL_LINE,
    )


# ── the run ────────────────────────────────────────────────────────────────


class Suite(object):
    def __init__(self, kin, workdir, daemon=None, verbose=False):
        self.kin = kin
        self.workdir = workdir
        self.verbose = verbose
        self.env = dict(os.environ)
        self.env["KIN_HOME"] = os.path.join(workdir, "kin-home")
        self.env["KIN_DAEMON_AUTO_EMBED"] = "0"
        self.env["KIN_EMBED_BACKEND"] = "cpu"
        self.env["KIN_VFS_DISABLE"] = "1"
        self.env.pop("KIN_MCP_REPO", None)
        if daemon:
            self.env["KIN_DAEMON_BIN"] = daemon
        os.makedirs(self.env["KIN_HOME"])
        self._repo = None
        self._elision_arms = None
        self._caller_trace = None

    def git(self, args, repo):
        base = ["git", "-c", "core.hooksPath=/dev/null",
                "-c", "user.email=repro@example.invalid",
                "-c", "user.name=trace-spine-clipping-repro",
                "-c", "commit.gpgsign=false"]
        return run(base + args, cwd=repo, env=self.env)

    def repo(self):
        if self._repo:
            return self._repo
        path = os.path.join(self.workdir, "sessions")
        os.makedirs(path)
        for rel, body in (("sessions.py", SESSIONS_SRC), ("adapters.py", ADAPTERS_SRC)):
            with open(os.path.join(path, rel), "w") as handle:
                handle.write(body)
        self.git(["init", "-q", "."], path)
        self.git(["add", "-A"], path)
        rc, out, err = self.git(["commit", "-q", "-m", "fixture"], path)
        if rc != 0:
            raise RuntimeError("git commit failed: %s" % (err or out)[-300:])
        rc, out, err = self.kin_run(["init", "."], path)
        if rc != 0:
            raise RuntimeError("kin init failed: %s" % (err or out)[-300:])
        self._repo = path
        return path

    def kin_run(self, args, repo, timeout=600):
        return run([self.kin] + args, cwd=repo, env=self.env, timeout=timeout)

    def trace(
            self, limit, target=None, max_response_chars=None, depth=2,
            focal="send", direction="calls"):
        """One `kin trace-data-flow`, parsed, or None when it could not be read."""
        repo = self.repo()
        args = ["trace-data-flow", "--focal", focal, "--direction", direction,
                "--depth", str(depth), "--limit-per-step", str(limit), "--no-bodies"]
        if target:
            args += ["--target", target]
        if max_response_chars:
            args += ["--max-response-chars", str(max_response_chars)]
        rc, out, err = self.kin_run(args, repo)
        if self.verbose:
            print("  $ kin %s -> rc=%s" % (" ".join(args[1:]), rc))
        if rc != 0:
            return None
        try:
            return json.loads(out)
        except ValueError:
            return None

    def elision_arms(self):
        """One wide premise and a paired target/no-target response cut."""
        if self._elision_arms is None:
            wide = self.trace(
                limit=ELISION_LIMIT,
                max_response_chars=WIDE_RESPONSE_BUDGET,
                depth=ELISION_DEPTH,
            )
            targeted = self.trace(
                limit=ELISION_LIMIT,
                target=ELISION_TARGET,
                max_response_chars=RESPONSE_BUDGET,
                depth=ELISION_DEPTH,
            )
            unnamed = self.trace(
                limit=ELISION_LIMIT,
                max_response_chars=RESPONSE_BUDGET,
                depth=ELISION_DEPTH,
            )
            self._elision_arms = (wide, targeted, unnamed)
        return self._elision_arms

    def caller_trace(self):
        if self._caller_trace is None:
            self._caller_trace = self.trace(
                limit=ELISION_LIMIT,
                max_response_chars=WIDE_RESPONSE_BUDGET,
                depth=1,
                focal=CROSSING_HOP,
                direction="callers",
            )
        return self._caller_trace

    def close(self):
        if self._repo is None:
            return
        rc, out, err = self.kin_run(["daemon", "stop", "--json"], self._repo, timeout=60)
        if self.verbose and rc != 0:
            print("  daemon stop returned rc=%s: %s" % (rc, (err or out)[-300:]))


class Result(object):
    def __init__(self, ident, status, detail):
        self.ident = ident
        self.status = status
        self.detail = detail

    def row(self):
        return {
            "id": self.ident,
            "ticket": "FIR-2824",
            "status": self.status,
            "detail": self.detail,
        }


def check_says_the_absence_proves_nothing(suite):
    payload = suite.trace(limit=3)
    if payload is None:
        return Result("0", UNREADABLE, "the narrow walk returned nothing readable")
    status, detail = grade_says_the_absence_proves_nothing(payload)
    return Result("0", status, "A clipped spine refuses to be read as an absence. " + detail)


def check_separates_the_class_of_loss(suite):
    payload = suite.trace(limit=3)
    if payload is None:
        return Result("1", UNREADABLE, "the narrow walk returned nothing readable")
    status, detail = grade_separates_the_class_of_loss(payload)
    return Result("1", status, "The disclosure separates module-crossing loss from breadth. " + detail)


def check_the_target_is_what_delivers_the_hop(suite):
    untargeted = suite.trace(limit=3)
    targeted = suite.trace(limit=3, target=CROSSING_HOP)
    if untargeted is None or targeted is None:
        return Result("2", UNREADABLE, "one of the two walks returned nothing readable")
    status, detail = grade_the_target_is_what_delivers_the_hop(untargeted, targeted)
    return Result("2", status, "Naming the target is what puts the hop in the chain. " + detail)


def check_a_complete_walk_is_not_qualified(suite):
    payload = suite.trace(limit=25)
    if payload is None:
        return Result("3", UNREADABLE, "the wide walk returned nothing readable")
    status, detail = grade_a_complete_walk_is_not_qualified(payload)
    return Result("3", status, "A walk no cap cut carries none of this. " + detail)


def check_the_named_target_survives_response_elision(suite):
    wide, targeted, _ = suite.elision_arms()
    if wide is None or targeted is None:
        return Result("4", UNREADABLE, "the wide or targeted bounded walk returned nothing readable")
    status, detail = grade_named_target_survives_response_budget(wide, targeted)
    return Result("4", status, "The named branch survives response elision. " + detail)


def check_the_unnamed_budget_drops_the_same_target(suite):
    wide, targeted, unnamed = suite.elision_arms()
    if wide is None or targeted is None or unnamed is None:
        return Result("5", UNREADABLE, "one of the three response-budget arms returned nothing readable")
    status, detail = grade_unnamed_response_budget_drops_the_target(wide, targeted, unnamed)
    return Result("5", status, "The unnamed control loses the same branch. " + detail)


def check_callee_steps_carry_their_parent_file_sites(suite):
    wide, _, _ = suite.elision_arms()
    if wide is None:
        return Result("6", UNREADABLE, "the wide callee walk returned nothing readable")
    status, detail = grade_callee_call_sites(wide)
    return Result("6", status, "Callee steps carry their parent-file call sites. " + detail)


def check_caller_steps_carry_their_own_file_sites(suite):
    payload = suite.caller_trace()
    if payload is None:
        return Result("7", UNREADABLE, "the caller walk returned nothing readable")
    status, detail = grade_caller_call_site(payload)
    return Result("7", status, "Caller steps carry their own-file call sites. " + detail)


CHECKS = [
    ("0", check_says_the_absence_proves_nothing),
    ("1", check_separates_the_class_of_loss),
    ("2", check_the_target_is_what_delivers_the_hop),
    ("3", check_a_complete_walk_is_not_qualified),
    ("4", check_the_named_target_survives_response_elision),
    ("5", check_the_unnamed_budget_drops_the_same_target),
    ("6", check_callee_steps_carry_their_parent_file_sites),
    ("7", check_caller_steps_carry_their_own_file_sites),
]


# ── self-test ──────────────────────────────────────────────────────────────
#
# Each grader is handed a payload it must pass and one it must fail. A grader
# that answers PASS to both cannot fail in CI, which is the failure this suite
# exists to prevent in the tool it grades.

CLIPPED = {
    "chain": [{"entity_name": "get_adapter", "parent_step": 0}],
    "spine_clipped_steps": 1,
    "spine_dropped_crossing_file": 1,
    "clipped_steps": [{
        "step": 0, "entity_name": "send", "dropped_callees": 7, "dropped_callers": 0,
        "dropped_crossing_file": 1, "continued_below": True, "limit_per_step": 3,
    }],
    "degradations": [{
        "component": "fanout_cap", "reason": "spine_clipped",
        "detail": "the walk continued beneath 1 node(s) whose fan-out limit_per_step 3 had "
                  "already cut ... the widest was 'send' ... its absence proves nothing",
        "remediation": "name the symbol you are looking for as `target` ...",
    }],
}

CLEAN = {"chain": [{"entity_name": "get_adapter", "parent_step": 0}], "degradations": []}
WIDE_ELISION = {
    "depth": ELISION_DEPTH,
    "direction": "calls",
    "limit_per_step": ELISION_LIMIT,
    "max_response_chars": WIDE_RESPONSE_BUDGET,
    "bodies_included": False,
    "chain": [
        {"step": 1, "parent_step": 0, "entity_id": "entity-get-adapter",
         "entity_name": "get_adapter", "role": "callee",
         "reference_lines": [1], "reference_lines_absent_reason": None},
        {"step": 2, "parent_step": 0, "entity_id": "entity-send-via-adapter",
         "entity_name": CROSSING_HOP, "role": "callee",
         "reference_lines": [SESSION_ADAPTER_CALL_LINE], "reference_lines_absent_reason": None},
        {"step": 3, "parent_step": 1, "entity_id": "entity-normalize-adapter",
         "entity_name": "normalize_adapter", "role": "callee",
         "reference_lines": [2], "reference_lines_absent_reason": None},
        {"step": 4, "parent_step": 2, "entity_id": "entity-cert-verify",
         "entity_name": ELISION_TARGET, "role": "callee",
         "reference_lines": [ADAPTER_CERT_CALL_LINE], "reference_lines_absent_reason": None},
        {"step": 5, "parent_step": 3, "entity_id": "entity-record-adapter",
         "entity_name": "record_adapter", "role": "callee",
         "reference_lines": [3], "reference_lines_absent_reason": None},
    ],
    "total_steps": 5,
    "degradations": [],
}
TARGETED_ELISION = {
    "depth": ELISION_DEPTH,
    "direction": "calls",
    "limit_per_step": ELISION_LIMIT,
    "max_response_chars": RESPONSE_BUDGET,
    "bodies_included": False,
    "chain": [
        {"step": 2, "parent_step": 0, "entity_id": "entity-send-via-adapter",
         "entity_name": CROSSING_HOP, "role": "callee"},
        {"step": 4, "parent_step": 2, "entity_id": "entity-cert-verify",
         "entity_name": ELISION_TARGET, "role": "callee"},
    ],
    "total_steps": 2,
    "target_name": ELISION_TARGET,
    "steps_omitted": 3,
    "fanout_narrowed": 3,
    "elisions": {
        "chain": {"kept": 2, "elided": 3, "total": 5, "reason": "response_budget"},
    },
    "degradations": [
        {"component": "response_budget", "reason": "steps_omitted", "detail": "cut"},
    ],
}
UNNAMED_ELISION = {
    "depth": ELISION_DEPTH,
    "direction": "calls",
    "limit_per_step": ELISION_LIMIT,
    "max_response_chars": RESPONSE_BUDGET,
    "bodies_included": False,
    "chain": [
        {"step": 1, "parent_step": 0, "entity_id": "entity-get-adapter",
         "entity_name": "get_adapter", "role": "callee"},
        {"step": 3, "parent_step": 1, "entity_id": "entity-normalize-adapter",
         "entity_name": "normalize_adapter", "role": "callee"},
        {"step": 5, "parent_step": 3, "entity_id": "entity-record-adapter",
         "entity_name": "record_adapter", "role": "callee"},
    ],
    "total_steps": 3,
    "steps_omitted": 2,
    "fanout_narrowed": 2,
    "elisions": {
        "chain": {"kept": 3, "elided": 2, "total": 5, "reason": "response_budget"},
    },
    "degradations": [
        {"component": "response_budget", "reason": "steps_omitted", "detail": "cut"},
    ],
}
CALLER_SITE = {
    "depth": 1,
    "direction": "callers",
    "limit_per_step": ELISION_LIMIT,
    "max_response_chars": WIDE_RESPONSE_BUDGET,
    "bodies_included": False,
    "focal_file": ADAPTERS_FILE,
    "chain": [
        {
            "step": 1,
            "parent_step": 0,
            "entity_id": "entity-send",
            "entity_name": CALLER_ENTITY,
            "entity_file": SESSIONS_FILE,
            "role": "caller",
            "reference_lines": [SESSION_ADAPTER_CALL_LINE],
            "reference_lines_absent_reason": None,
        },
    ],
    "total_steps": 1,
    "degradations": [],
}


def _without(payload, *path):
    import copy
    clone = copy.deepcopy(payload)
    cursor = clone
    for key in path[:-1]:
        cursor = cursor[key]
    cursor.pop(path[-1], None)
    return clone


def self_test():
    failures = []
    graded = []

    def expect(label, got, want):
        graded.append(label)
        status = got[0]
        if status != want:
            failures.append("%s: expected %s, got %s (%s)" % (label, want, status, got[1]))

    expect("0 passes an honest clipped walk",
           grade_says_the_absence_proves_nothing(CLIPPED), PASS)
    expect("0 fails a walk that counts the clip and never says it",
           grade_says_the_absence_proves_nothing(_without(CLIPPED, "degradations")), FAIL)
    silent = json.loads(json.dumps(CLIPPED))
    silent["degradations"][0]["detail"] = "the walk continued beneath 1 node(s), limit_per_step 3, 'send'"
    expect("0 fails a disclosure missing the refusal phrase",
           grade_says_the_absence_proves_nothing(silent), FAIL)
    leverless = json.loads(json.dumps(CLIPPED))
    leverless["degradations"][0]["remediation"] = "re-query 'send' with a wider cap"
    expect("0 fails a disclosure that names no lever",
           grade_says_the_absence_proves_nothing(leverless), FAIL)
    expect("0 cannot read a walk with no spine key",
           grade_says_the_absence_proves_nothing(CLEAN), UNREADABLE)

    expect("1 passes a clip that separates the class",
           grade_separates_the_class_of_loss(CLIPPED), PASS)
    blind = json.loads(json.dumps(CLIPPED))
    blind["clipped_steps"][0]["dropped_crossing_file"] = 0
    blind["spine_dropped_crossing_file"] = 0
    expect("1 fails a clip that reports no module-crossing loss",
           grade_separates_the_class_of_loss(blind), FAIL)
    offspine = json.loads(json.dumps(CLIPPED))
    offspine["clipped_steps"][0]["continued_below"] = False
    expect("1 fails when no clip is attributable to the spine",
           grade_separates_the_class_of_loss(offspine), FAIL)
    disagreeing = json.loads(json.dumps(CLIPPED))
    disagreeing["spine_dropped_crossing_file"] = 9
    expect("1 fails when the top-level total disagrees with the clips",
           grade_separates_the_class_of_loss(disagreeing), FAIL)

    without = {"chain": [{"entity_name": "get_adapter"}]}
    with_hop = {"chain": [{"entity_name": CROSSING_HOP}], "target_name": CROSSING_HOP}
    expect("2 passes absent-unnamed and present-named",
           grade_the_target_is_what_delivers_the_hop(without, with_hop), PASS)
    expect("2 fails when the unnamed walk already had it",
           grade_the_target_is_what_delivers_the_hop(with_hop, with_hop), FAIL)
    expect("2 fails when naming it changed nothing",
           grade_the_target_is_what_delivers_the_hop(without, without), FAIL)
    unechoed = {"chain": [{"entity_name": CROSSING_HOP}]}
    expect("2 fails when the response does not echo the question",
           grade_the_target_is_what_delivers_the_hop(without, unechoed), FAIL)

    expect("3 passes an unaffected walk",
           grade_a_complete_walk_is_not_qualified(CLEAN), PASS)
    expect("3 fails a walk carrying the disclosure anyway",
           grade_a_complete_walk_is_not_qualified(CLIPPED), FAIL)
    zeroed = {"chain": [{"entity_name": "get_adapter"}], "degradations": [],
              "spine_clipped_steps": 0}
    expect("3 fails a walk that writes the key as zero rather than omitting it",
           grade_a_complete_walk_is_not_qualified(zeroed), FAIL)
    expect("3 cannot read a walk with no chain",
           grade_a_complete_walk_is_not_qualified({"degradations": []}), UNREADABLE)

    expect("4 passes a discovered named branch that survives a real cut",
           grade_named_target_survives_response_budget(WIDE_ELISION, TARGETED_ELISION), PASS)
    renumbered_targeted = json.loads(json.dumps(TARGETED_ELISION))
    renumbered_targeted["chain"][0]["step"] = 20
    renumbered_targeted["chain"][1]["step"] = 40
    renumbered_targeted["chain"][1]["parent_step"] = 20
    expect("4 accepts renumbering when canonical entity and parent identities are unchanged",
           grade_named_target_survives_response_budget(
               WIDE_ELISION, renumbered_targeted), PASS)
    no_cut_targeted = json.loads(json.dumps(TARGETED_ELISION))
    no_cut_targeted["steps_omitted"] = 0
    expect("4 fails a targeted arm whose response budget never bit",
           grade_named_target_survives_response_budget(WIDE_ELISION, no_cut_targeted), FAIL)
    lost_targeted = json.loads(json.dumps(TARGETED_ELISION))
    lost_targeted["chain"][1]["entity_name"] = "other_target"
    expect("4 fails when the named branch was still elided",
           grade_named_target_survives_response_budget(WIDE_ELISION, lost_targeted), FAIL)
    unechoed_targeted = json.loads(json.dumps(TARGETED_ELISION))
    unechoed_targeted.pop("target_name")
    expect("4 fails when the bounded arm does not echo the target",
           grade_named_target_survives_response_budget(WIDE_ELISION, unechoed_targeted), FAIL)
    wide_without_target = json.loads(json.dumps(WIDE_ELISION))
    wide_without_target["chain"] = [
        row for row in wide_without_target["chain"]
        if row["entity_name"] not in (CROSSING_HOP, ELISION_TARGET)
    ]
    wide_without_target["total_steps"] = len(wide_without_target["chain"])
    expect("4 fails a readable wide premise that never discovered the target",
           grade_named_target_survives_response_budget(wide_without_target, TARGETED_ELISION), FAIL)
    missing_parent = json.loads(json.dumps(TARGETED_ELISION))
    missing_parent["chain"][1]["parent_step"] = 0
    expect("4 fails a target row attached to the surviving wrong parent",
           grade_named_target_survives_response_budget(WIDE_ELISION, missing_parent), FAIL)
    orphaned_target = json.loads(json.dumps(TARGETED_ELISION))
    orphaned_target["chain"][1]["parent_step"] = 99
    expect("4 fails a target row that points at a missing parent step",
           grade_named_target_survives_response_budget(WIDE_ELISION, orphaned_target), FAIL)
    evidence_free = _without(TARGETED_ELISION, "elisions")
    expect("4 fails a cut with no elisions accounting",
           grade_named_target_survives_response_budget(WIDE_ELISION, evidence_free), FAIL)
    no_disclosure = _without(TARGETED_ELISION, "degradations")
    expect("4 fails a cut with no response-budget degradation",
           grade_named_target_survives_response_budget(WIDE_ELISION, no_disclosure), FAIL)
    cut_wide = json.loads(json.dumps(WIDE_ELISION))
    cut_wide["steps_omitted"] = 1
    expect("4 fails when the wide discovery premise was already cut",
           grade_named_target_survives_response_budget(cut_wide, TARGETED_ELISION), FAIL)
    oversized_wide = json.loads(json.dumps(WIDE_ELISION))
    oversized_wide["untrimmed_payload"] = "x" * WIDE_RESPONSE_BUDGET
    expect("4 fails a wide premise whose shipped JSON exceeds its budget",
           grade_named_target_survives_response_budget(
               oversized_wide, TARGETED_ELISION), FAIL)
    clipped_targeted = json.loads(json.dumps(TARGETED_ELISION))
    clipped_targeted["clipped_steps"] = [{"step": 2}]
    expect("4 fails when fanout clipping can explain the loss",
           grade_named_target_survives_response_budget(WIDE_ELISION, clipped_targeted), FAIL)
    wrong_budget = json.loads(json.dumps(TARGETED_ELISION))
    wrong_budget["max_response_chars"] = RESPONSE_BUDGET + 1
    expect("4 fails a bounded arm that echoes a different budget",
           grade_named_target_survives_response_budget(WIDE_ELISION, wrong_budget), FAIL)
    oversized_targeted = json.loads(json.dumps(TARGETED_ELISION))
    oversized_targeted["untrimmed_payload"] = "x" * RESPONSE_BUDGET
    expect("4 fails a response whose shipped JSON exceeds the echoed budget",
           grade_named_target_survives_response_budget(
               WIDE_ELISION, oversized_targeted), FAIL)
    short_targeted_universe = json.loads(json.dumps(TARGETED_ELISION))
    short_targeted_universe["steps_omitted"] = 2
    short_targeted_universe["fanout_narrowed"] = 2
    short_targeted_universe["elisions"]["chain"] = {
        "kept": 2,
        "elided": 2,
        "total": 4,
        "reason": "response_budget",
    }
    expect("4 fails internally coherent accounting for a smaller source universe",
           grade_named_target_survives_response_budget(
               WIDE_ELISION, short_targeted_universe), FAIL)
    invented_target_identity = json.loads(json.dumps(TARGETED_ELISION))
    invented_target_identity["chain"][1]["entity_id"] = "entity-not-in-wide"
    expect("4 fails a coherent target row the wide discovery never returned",
           grade_named_target_survives_response_budget(
               WIDE_ELISION, invented_target_identity), FAIL)

    expect("5 passes when the unnamed cut loses the widely discovered target",
           grade_unnamed_response_budget_drops_the_target(
               WIDE_ELISION, TARGETED_ELISION, UNNAMED_ELISION), PASS)
    no_cut_unnamed = json.loads(json.dumps(UNNAMED_ELISION))
    no_cut_unnamed["steps_omitted"] = 0
    expect("5 fails an unnamed arm whose response budget never bit",
           grade_unnamed_response_budget_drops_the_target(
               WIDE_ELISION, TARGETED_ELISION, no_cut_unnamed), FAIL)
    kept_unnamed = json.loads(json.dumps(UNNAMED_ELISION))
    kept_unnamed["chain"][-1]["entity_name"] = ELISION_TARGET
    expect("5 fails when the unnamed arm already keeps the target",
           grade_unnamed_response_budget_drops_the_target(
               WIDE_ELISION, TARGETED_ELISION, kept_unnamed), FAIL)
    lost_target_control = json.loads(json.dumps(TARGETED_ELISION))
    lost_target_control["chain"][1]["entity_name"] = "other_target"
    expect("5 fails when both bounded arms lose the target",
           grade_unnamed_response_budget_drops_the_target(
               WIDE_ELISION, lost_target_control, UNNAMED_ELISION), FAIL)
    named_unnamed = json.loads(json.dumps(UNNAMED_ELISION))
    named_unnamed["target_name"] = ELISION_TARGET
    expect("5 fails when the unnamed arm claims a target",
           grade_unnamed_response_budget_drops_the_target(
               WIDE_ELISION, TARGETED_ELISION, named_unnamed), FAIL)
    claiming_unnamed = json.loads(json.dumps(UNNAMED_ELISION))
    claiming_unnamed["degradations"][0]["detail"] = (
        "cut as whole branches, keeping the branch that reaches the named target"
    )
    expect("5 fails when the unnamed disclosure claims it kept a named target",
           grade_unnamed_response_budget_drops_the_target(
               WIDE_ELISION, TARGETED_ELISION, claiming_unnamed), FAIL)
    clipped_unnamed = json.loads(json.dumps(UNNAMED_ELISION))
    clipped_unnamed["chain"][0]["fanout_truncated"] = True
    expect("5 fails when the unnamed arm has a per-step fanout cut",
           grade_unnamed_response_budget_drops_the_target(
               WIDE_ELISION, TARGETED_ELISION, clipped_unnamed), FAIL)
    short_unnamed_universe = json.loads(json.dumps(UNNAMED_ELISION))
    short_unnamed_universe["steps_omitted"] = 1
    short_unnamed_universe["fanout_narrowed"] = 1
    short_unnamed_universe["elisions"]["chain"] = {
        "kept": 3,
        "elided": 1,
        "total": 4,
        "reason": "response_budget",
    }
    expect("5 fails internally coherent accounting for a smaller source universe",
           grade_unnamed_response_budget_drops_the_target(
               WIDE_ELISION, TARGETED_ELISION, short_unnamed_universe), FAIL)
    invented_unnamed = json.loads(json.dumps(UNNAMED_ELISION))
    for index, row in enumerate(invented_unnamed["chain"]):
        row["entity_name"] = "invented_%d" % index
    expect("5 fails bounded rows whose identities changed from the wide discovery",
           grade_unnamed_response_budget_drops_the_target(
               WIDE_ELISION, TARGETED_ELISION, invented_unnamed), FAIL)
    expect("5 cannot read a non-object response arm",
           grade_unnamed_response_budget_drops_the_target(
               WIDE_ELISION, TARGETED_ELISION, None), UNREADABLE)

    expect("6 passes exact callee sites from both parent files",
           grade_callee_call_sites(WIDE_ELISION), PASS)
    wrong_callee_line = json.loads(json.dumps(WIDE_ELISION))
    wrong_callee_line["chain"][1]["reference_lines"] = [SESSION_ADAPTER_CALL_LINE + 1]
    expect("6 fails a callee line from the wrong source row",
           grade_callee_call_sites(wrong_callee_line), FAIL)
    wrong_callee_role = json.loads(json.dumps(WIDE_ELISION))
    wrong_callee_role["chain"][3]["role"] = "caller"
    expect("6 fails when the forward step reports the wrong role",
           grade_callee_call_sites(wrong_callee_role), FAIL)
    unexplained_step = json.loads(json.dumps(WIDE_ELISION))
    unexplained_step["chain"][0]["reference_lines"] = []
    expect("6 fails any step with no lines and no absent reason",
           grade_callee_call_sites(unexplained_step), FAIL)
    invented_reason = json.loads(json.dumps(WIDE_ELISION))
    invented_reason["chain"][0]["reference_lines"] = []
    invented_reason["chain"][0]["reference_lines_absent_reason"] = "made_up_reason"
    expect("6 fails an empty-line row with an unknown absent-reason value",
           grade_callee_call_sites(invented_reason), FAIL)
    missing_line_key = json.loads(json.dumps(WIDE_ELISION))
    missing_line_key["chain"][0].pop("reference_lines_absent_reason")
    expect("6 fails a chain row that omits one uniform site key",
           grade_callee_call_sites(missing_line_key), FAIL)

    expect("7 passes the exact caller site in the caller's own file",
           grade_caller_call_site(CALLER_SITE), PASS)
    wrong_caller_line = json.loads(json.dumps(CALLER_SITE))
    wrong_caller_line["chain"][0]["reference_lines"] = [ADAPTER_CERT_CALL_LINE]
    expect("7 fails when the caller receives a line from the focal file",
           grade_caller_call_site(wrong_caller_line), FAIL)
    same_file_caller = json.loads(json.dumps(CALLER_SITE))
    same_file_caller["chain"][0]["entity_file"] = ADAPTERS_FILE
    expect("7 fails a fixture whose caller does not cross away from the focal file",
           grade_caller_call_site(same_file_caller), FAIL)
    wrong_caller_role = json.loads(json.dumps(CALLER_SITE))
    wrong_caller_role["chain"][0]["role"] = "callee"
    expect("7 fails when the reverse step reports the wrong role",
           grade_caller_call_site(wrong_caller_role), FAIL)
    reason_beside_line = json.loads(json.dumps(CALLER_SITE))
    reason_beside_line["chain"][0]["reference_lines_absent_reason"] = "no_evidence_span"
    expect("7 fails an absent reason beside a known caller site",
           grade_caller_call_site(reason_beside_line), FAIL)
    expect("7 cannot read a non-object caller response",
           grade_caller_call_site(None), UNREADABLE)

    for line in failures:
        print("SELFTEST FAIL %s" % line)
    # Counted, never written out. A hardcoded total is a number that drifts from
    # the assertions it claims to describe, and it drifts silently downward.
    print("self-test: %d grader assertions, %d failed" % (len(graded), len(failures)))
    if len(graded) != len(set(graded)):
        print("SELFTEST FAIL duplicate assertion labels, so one shadowed another")
        return 1
    if not graded:
        print("SELFTEST FAIL no grader assertion ran")
        return 1
    return 1 if failures else 0


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kin", default=os.environ.get("KIN_BIN") or shutil.which("kin"))
    parser.add_argument("--daemon", default=os.environ.get("KIN_DAEMON_BIN"))
    parser.add_argument("--json", default=None, help="write the machine-readable report here")
    parser.add_argument("--label", default=os.environ.get("KIN_ACCEPTANCE_LABEL") or "")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    opts = parser.parse_args(argv)

    if opts.self_test:
        return self_test()

    if not opts.kin:
        print("SETUP no kin binary: pass --kin or set KIN_BIN")
        return 3
    kin = os.path.abspath(os.path.expanduser(opts.kin))
    if not os.path.isfile(kin) or not os.access(kin, os.X_OK):
        print("SETUP kin binary is missing or not executable: %s" % kin)
        return 3
    daemon = opts.daemon and os.path.abspath(os.path.expanduser(opts.daemon))
    if daemon is None:
        sibling = os.path.join(os.path.dirname(kin), "kin-daemon")
        daemon = sibling if os.path.isfile(sibling) else None
    if daemon is not None and (not os.path.isfile(daemon) or not os.access(daemon, os.X_OK)):
        print("SETUP kin-daemon binary is missing or not executable: %s" % daemon)
        return 3

    workdir = tempfile.mkdtemp(prefix="trace-spine-clipping-")
    suite = None
    try:
        suite = Suite(kin, workdir, daemon=daemon, verbose=opts.verbose)
        results = []
        for ident, check in CHECKS:
            try:
                results.append(check(suite))
            except Exception as error:  # noqa: BLE001 - a setup failure is not a verdict
                results.append(Result(ident, UNREADABLE, "check raised: %s" % (error,)))
        for result in results:
            print("CHECK %s %s %s" % (result.ident, result.status, result.detail))
        asked = [ident for ident, _ in CHECKS]
        answered = [result.ident for result in results]
        if answered != asked:
            print("SETUP asked for %r and %r answered" % (asked, answered))
            return 3
        if opts.json:
            report_path = os.path.abspath(opts.json)
            directory = os.path.dirname(report_path)
            if directory and not os.path.isdir(directory):
                os.makedirs(directory)
            with open(report_path, "w") as handle:
                json.dump(
                    {
                        "suite": "trace_spine_clipping_repro",
                        "ticket": "FIR-2824",
                        "label": opts.label,
                        "kin": kin,
                        "results": [result.row() for result in results],
                    },
                    handle,
                    indent=2,
                    sort_keys=True,
                )
                handle.write("\n")
        if any(result.status == FAIL for result in results):
            return 1
        if any(result.status == UNREADABLE for result in results):
            return 2
        return 0
    finally:
        if suite is not None:
            suite.close()
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
