#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

"""Prove a narrow trace says it may be missing the hop you asked about.

FIR-2781. The v0.6.0 stranger run walked `Session.send` on a converted
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

Four checks, on one seeded repository:

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


def get_adapter(url):
    return url


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


# ── the run ────────────────────────────────────────────────────────────────


class Suite(object):
    def __init__(self, kin, workdir, daemon=None, verbose=False):
        self.kin = kin
        self.workdir = workdir
        self.verbose = verbose
        self.env = dict(os.environ)
        self.env["KIN_DAEMON_AUTO_EMBED"] = "0"
        self.env["KIN_VFS_DISABLE"] = "1"
        self.env.pop("KIN_MCP_REPO", None)
        if daemon:
            self.env["KIN_DAEMON_BIN"] = daemon
        self._repo = None

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

    def trace(self, limit, target=None):
        """One `kin trace-data-flow`, parsed, or None when it could not be read."""
        repo = self.repo()
        args = ["trace-data-flow", "--focal", "send", "--direction", "calls",
                "--depth", "2", "--limit-per-step", str(limit), "--no-bodies"]
        if target:
            args += ["--target", target]
        rc, out, err = self.kin_run(args, repo)
        if self.verbose:
            print("  $ kin %s -> rc=%s" % (" ".join(args[1:]), rc))
        if rc != 0:
            return None
        try:
            return json.loads(out)
        except ValueError:
            return None


class Result(object):
    def __init__(self, ident, status, detail):
        self.ident = ident
        self.status = status
        self.detail = detail


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


CHECKS = [
    ("0", check_says_the_absence_proves_nothing),
    ("1", check_separates_the_class_of_loss),
    ("2", check_the_target_is_what_delivers_the_hop),
    ("3", check_a_complete_walk_is_not_qualified),
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
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    opts = parser.parse_args(argv)

    if opts.self_test:
        return self_test()

    if not opts.kin:
        print("SETUP no kin binary: pass --kin or set KIN_BIN")
        return 3

    workdir = tempfile.mkdtemp(prefix="trace-spine-clipping-")
    try:
        suite = Suite(opts.kin, workdir, daemon=opts.daemon, verbose=opts.verbose)
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
        if any(result.status == FAIL for result in results):
            return 1
        if any(result.status == UNREADABLE for result in results):
            return 2
        return 0
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
