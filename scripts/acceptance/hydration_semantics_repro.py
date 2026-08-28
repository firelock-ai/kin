#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
"""NON-CITABLE acceptance suite for hydration-semantics disclosure (FIR-2829).

This suite proves one current control and all four gap standings against a store
built by the binary under test. A fresh store must carry the creation-time stamp
and stay silent on ``kin graph status`` and the MCP degraded map while ``kin
doctor`` reports a healthy row. Stores recorded behind or ahead, a store with no
stamp, and a store with an incompatible future-schema stamp must all disclose on
all three surfaces with direction-safe advice.

The control is load-bearing. A writer that silently stopped writing would make
every new store look unverified, and a comparator that always reported a gap
would make all four gap arms green. Requiring the fresh store to stay silent
catches both defects.

Three checks beyond the three surfaces, each closing a way the surfaces could be
right and the product still wrong:

``verdict`` drives a real negative-capable retrieval call rather than the
graph-status flag. ``kin_graph_status`` is not in the negative registry, so
nothing about its output constrains ``negative`` or ``_kin.verdict``, and a break
between the degraded flag and the retrieval verdict would leave this suite green
while the answer an agent acts on still certified.

``creation_doors`` builds a store through every creation door the shipped
binaries expose and reads the published record back. One door proved nothing
about the others, and a future creation path can leave the one staging boundary
while a suite that only ever built one store stays green.

``native_transfer`` moves real history between two replicas and reads the
receiver afterwards. The transfer protocol carries no authoring version, so a
receiver that kept its own creation stamp would certify replay semantics for
deltas authored on another host by another build. Its control is a pull that
admits nothing, which must leave the record alone.

Advice is compared against the canonical remedy exactly, not by prefix or
substring. A prefix check accepts correct advice followed by advice that
destroys the store.

Each check prints:

    CHECK <id> <ticket> PASS|FAIL|UNREADABLE <detail>

Exit status is 1 when any check fails, 2 when none fail but some are unreadable,
3 on setup failure, and 0 only when every check passes. ``--self-test`` drives
every grader against its inverse without building a repository.
"""

from __future__ import print_function

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import uuid


PASS = "PASS"
FAIL = "FAIL"
UNREADABLE = "UNREADABLE"
TICKET = "FIR-2829"
STAMP_REL = os.path.join(".kin", "kindb", "hydration-semantics")
FLAG = "hydration_semantics_stale"
OBSERVATION = "hydration_semantics"

# The exact strings `HydrationStanding::remedy` returns, one copy for the whole
# suite. Graded by equality rather than by prefix or substring, because a prefix
# match accepts correct advice followed by advice that destroys the store: an
# ahead arm can say "upgrade this build" and then "re-ingest with the older
# binary and replace the original", and every substring check in the world still
# passes it.
#
# A banned-word check would be wrong here and is deliberately not used. The
# correct ahead remedy contains "rather than re-ingesting" and the correct
# unknown-direction remedy permits re-ingest into a SEPARATE store, so a naive
# scan for "re-ingest" rejects the safe text and teaches nothing.
REMEDY_BEHIND = (
    "re-ingest the repository with `kin init` into a fresh store recorded under this build's "
    "replay semantics"
)
REMEDY_AHEAD = (
    "upgrade this Kin build to at least the one that created the store, rather than re-ingesting "
    "with the older replay version"
)
REMEDY_UNKNOWN = (
    "upgrade Kin before changing this store; if the newest build still cannot read the record, "
    "re-ingest the repository into a separate fresh store rather than replacing this one"
)
CANONICAL_REMEDY = {
    "current": None,
    "behind": REMEDY_BEHIND,
    "ahead": REMEDY_AHEAD,
    "absent": REMEDY_UNKNOWN,
    "unreadable": REMEDY_UNKNOWN,
}

# The suite's arm names are not the wire labels. "absent" describes the mutation
# this script performs; `unstamped` is what `HydrationStanding::label` publishes.
WIRE_STANDING = {
    "current": "current",
    "behind": "behind",
    "ahead": "ahead",
    "absent": "unstamped",
    "unreadable": "unreadable",
}


def tail(text, limit=500):
    text = (text or "").strip()
    return text if len(text) <= limit else "..." + text[-limit:]


def run(cmd, cwd=None, env=None, timeout=600):
    proc = subprocess.run(
        cmd,
        cwd=cwd,
        env=env,
        timeout=timeout,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return proc.returncode, proc.stdout


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
        if any(row["status"] == FAIL for row in self.asserts):
            return FAIL
        if any(row["status"] == UNREADABLE for row in self.asserts):
            return UNREADABLE
        return PASS if self.asserts else UNREADABLE

    @property
    def detail(self):
        for wanted in (FAIL, UNREADABLE):
            for row in self.asserts:
                if row["status"] == wanted:
                    return row["detail"]
        passed = [row["detail"] for row in self.asserts if row["status"] == PASS]
        return "; ".join(passed) if passed else "no assertion was reached"


def rendered_remedy(line):
    """The remedy `kin graph status` actually printed, or ``None``.

    The renderer appends exactly `" Remedy: <remedy>."`. Only that one trailing
    period is the renderer's, so anything after it belongs to the text under
    test and has to survive into the comparison. That is the whole mechanism
    that catches safe advice followed by unsafe advice.
    """
    marker = " Remedy: "
    at = line.find(marker)
    if at < 0:
        return None
    printed = line[at + len(marker) :].strip()
    if not printed.endswith("."):
        return None
    return printed[:-1]


def status_problems(text, standing, created_under=None, derives=None):
    """Return problems in one ``kin graph status`` rendering."""
    lines = [line.strip() for line in (text or "").splitlines()]
    hits = [line for line in lines if "hydration semantics:" in line.lower()]
    if standing == "current":
        return [] if not hits else ["a current store printed %r" % hits]
    if len(hits) != 1:
        return ["expected one hydration-semantics warning, got %d" % len(hits)]
    line = hits[0]
    problems = []
    if standing == "absent":
        if "records no hydration semantics version" not in line:
            problems.append("an unstamped store is not named as unstamped")
    elif standing == "unreadable":
        if "hydration semantics record could not be read" not in line:
            problems.append("an unreadable record is not named as unreadable")
    else:
        if "records hydration semantics version %d at creation" % created_under not in line:
            problems.append("the warning does not name recorded version %d" % created_under)
        if standing == "behind" and "cannot certify" not in line:
            problems.append("a behind store does not disclose the certification gap")
        if standing == "ahead" and "this binary predates the store's recorded semantics" not in line:
            problems.append("an ahead store does not say the binary predates it")
    if derives is not None and str(derives) not in line:
        problems.append("the warning does not name binary version %d" % derives)

    expected = CANONICAL_REMEDY[standing]
    printed = rendered_remedy(line)
    if printed is None:
        problems.append("the warning carries no remedy")
    elif printed != expected:
        problems.append(
            "the remedy is not the canonical %s advice; printed %r, wanted %r"
            % (standing, printed, expected)
        )
    return problems


def doctor_problems(report, standing, created_under=None, derives=None):
    """Return problems in the ``hydration_semantics`` doctor row."""
    rows = [
        row
        for row in (report or {}).get("checks", [])
        if row.get("id") == "hydration_semantics"
    ]
    if len(rows) != 1:
        return ["expected one hydration_semantics row, got %d" % len(rows)]
    row = rows[0]
    gap = standing != "current"
    wanted = "stale" if gap else "healthy"
    problems = []
    if row.get("status") != wanted:
        problems.append("status is %r, wanted %r" % (row.get("status"), wanted))
    detail = row.get("detail") or ""
    fix = row.get("manual_fix")
    if standing == "absent":
        if "records no hydration semantics version" not in detail:
            problems.append("an unstamped row is not named as unstamped")
    elif standing == "unreadable":
        if "record could not be read" not in detail:
            problems.append("an unreadable row is not named as unreadable")
    elif standing != "current":
        if created_under is None or str(created_under) not in detail:
            problems.append("detail does not name recorded version %r" % created_under)
        elif "records hydration semantics version %d at creation" % created_under not in detail:
            problems.append("detail does not identify the number as a creation-time record")
        if standing == "behind" and "cannot certify" not in detail:
            problems.append("a behind row does not disclose the certification gap")
        if standing == "ahead" and "predates" not in detail:
            problems.append("an ahead row does not say the binary predates the record")
    if derives is not None and str(derives) not in detail:
        problems.append("detail does not name binary version %d" % derives)

    expected = CANONICAL_REMEDY[standing]
    if expected is None:
        if fix is not None:
            problems.append("a current row manufactured a manual_fix: %r" % (fix,))
    elif not isinstance(fix, str):
        problems.append("a stale row carries no manual_fix")
    elif fix != expected:
        problems.append(
            "manual_fix is not the canonical %s advice; got %r, wanted %r"
            % (standing, fix, expected)
        )
    return problems


def envelope_problems(payload, standing, created_under=None, derives=None):
    """Return problems in the stdio MCP response envelope.

    Grades the structured observation, not only the compatibility boolean. A
    boolean named `stale` is wrong for three of the four gaps: an ahead store was
    made by a NEWER build, and an absent or unreadable record is unknown rather
    than proven stale, so an agent keying on the flag alone is told to re-ingest
    in exactly the cases where re-ingesting destroys the store.
    """
    envelope = (payload or {}).get("_kin")
    if not isinstance(envelope, dict):
        return ["the MCP payload carries no _kin envelope"]
    degraded = envelope.get("degraded")
    if not isinstance(degraded, dict):
        return ["the _kin envelope carries no degraded object"]
    gap = standing != "current"
    problems = []
    if gap and degraded.get(FLAG) is not True:
        problems.append("%s is not true" % FLAG)
    if not gap and FLAG in degraded:
        problems.append("a current store serialized %s" % FLAG)

    observation = envelope.get(OBSERVATION)
    if not isinstance(observation, dict):
        return problems + [
            "the _kin envelope carries no %s observation, so an agent is told a gap exists "
            "with no direction and no safe action" % OBSERVATION
        ]
    wire = WIRE_STANDING[standing]
    if observation.get("standing") != wire:
        problems.append("standing is %r, wanted %r" % (observation.get("standing"), wire))
    if derives is not None and observation.get("derives") != derives:
        problems.append(
            "derives is %r, wanted %r" % (observation.get("derives"), derives)
        )
    if created_under is None:
        if "created_under" in observation:
            problems.append(
                "an unknown creation version was published as %r"
                % (observation.get("created_under"),)
            )
    elif observation.get("created_under") != created_under:
        problems.append(
            "created_under is %r, wanted %r"
            % (observation.get("created_under"), created_under)
        )
    if standing == "unreadable":
        reason = observation.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            problems.append("an unreadable record published no read failure")
    elif "reason" in observation:
        problems.append("a %s standing published a reason: %r" % (standing, observation["reason"]))
    expected = CANONICAL_REMEDY[standing]
    if expected is None:
        if "remedy" in observation:
            problems.append("a current store published a remedy: %r" % (observation["remedy"],))
    elif observation.get("remedy") != expected:
        problems.append(
            "the %s remedy is not canonical; got %r, wanted %r"
            % (standing, observation.get("remedy"), expected)
        )
    return problems


def verdict_problems(payload, gap):
    """Return problems in one negative-capable retrieval answer.

    `kin_graph_status` is not in the negative registry, so grading its degraded
    flag cannot show that a successful absence stops being authoritative. This
    grades the one verdict a reader acts on, from a call that really does
    produce `negative` and `_kin.verdict`.

    The answer is deliberately POPULATED. A populated answer keeps
    `absence_claim: not_applicable` in both arms, so the discriminating field is
    `negative.trust`, and using a real answer avoids conflating hydration
    behaviour with an independently fragile empty-absence setup.
    """
    envelope = (payload or {}).get("_kin")
    if not isinstance(envelope, dict):
        return ["the retrieval payload carries no _kin envelope"]
    references = payload.get("references")
    if not isinstance(references, list) or not references:
        return ["find_references returned no rows, so this arm graded nothing"]
    # `negative` is a sibling of `_kin` at the payload's top level while
    # `verdict` and `completeness` live inside it. Reading `negative` off `_kin`
    # returns nothing and reads exactly like a tool that published no negative
    # block at all, which is the envelope-piercing mistake in the trap
    # catalogue. `verdict_limits_repro.py` is the proven reader this follows.
    negative = (payload or {}).get("negative")
    verdict = envelope.get("verdict")
    completeness = envelope.get("completeness")
    if not isinstance(negative, dict):
        return ["the answer carries no negative block"]
    if not isinstance(verdict, dict):
        return ["the answer carries no verdict"]
    if not isinstance(completeness, dict):
        return ["the answer carries no completeness block"]

    problems = []
    if negative.get("interpretation") != "qualified_answer":
        problems.append(
            "negative.interpretation is %r, wanted 'qualified_answer'"
            % (negative.get("interpretation"),)
        )
    if verdict.get("absence_claim") != "not_applicable":
        problems.append(
            "a populated answer must claim no absence, got %r"
            % (verdict.get("absence_claim"),)
        )
    counted = completeness.get("counted")
    counted_exact = counted.get("exact") if isinstance(counted, dict) else None
    limits = completeness.get("limits")
    limits = limits if isinstance(limits, list) else []
    signals = negative.get("degraded_signals")
    signals = signals if isinstance(signals, list) else []
    factor = verdict.get("limiting_factor")

    if gap:
        if (envelope.get("degraded") or {}).get(FLAG) is not True:
            problems.append("the gap did not reach the envelope's degraded map")
        if negative.get("trust") != "inconclusive":
            problems.append(
                "negative.trust is %r, wanted 'inconclusive'" % (negative.get("trust"),)
            )
        if negative.get("safe_to_conclude_absent") is not False:
            problems.append(
                "negative.safe_to_conclude_absent is %r, wanted False"
                % (negative.get("safe_to_conclude_absent"),)
            )
        if FLAG not in signals:
            problems.append("%s is missing from negative.degraded_signals: %r" % (FLAG, signals))
        if verdict.get("state") != "inconclusive":
            problems.append("verdict.state is %r, wanted 'inconclusive'" % (verdict.get("state"),))
        if verdict.get("safe_to_conclude_absent") is not False:
            problems.append(
                "verdict.safe_to_conclude_absent is %r, wanted False"
                % (verdict.get("safe_to_conclude_absent"),)
            )
        inputs = verdict.get("inputs")
        gate = inputs.get("absence_gate") if isinstance(inputs, dict) else None
        if gate != "inconclusive":
            problems.append("verdict.inputs.absence_gate is %r, wanted 'inconclusive'" % (gate,))
        # "degraded" only, and that is a fact about the producer rather than a
        # concession. `Envelope::negative_trust` returns one fixed sentence for
        # every degraded signal, "degraded: the daemon reported a degraded
        # signal, so the index may not reflect current truth", and never names
        # which flag; naming them is `Degraded::active_labels`, which is what
        # reaches `negative.degraded_signals` and `completeness.limits`. Both are
        # asserted above, so the flag-specific evidence is still required, from
        # the two fields that actually carry it.
        if not isinstance(factor, str) or "degraded" not in factor:
            problems.append(
                "verdict.limiting_factor does not blame a degraded signal: %r" % (factor,)
            )
        if completeness.get("bound") != "at_least":
            problems.append(
                "completeness.bound is %r, wanted 'at_least'" % (completeness.get("bound"),)
            )
        if counted_exact is not False:
            problems.append("completeness.counted.exact is %r, wanted False" % (counted_exact,))
        if "degraded:%s" % FLAG not in limits:
            problems.append("completeness.limits does not name the hydration gap: %r" % (limits,))
        if "verdict_inconclusive" not in limits:
            problems.append("completeness.limits does not carry verdict_inconclusive: %r" % (limits,))
        return problems

    if FLAG in (envelope.get("degraded") or {}):
        problems.append("a current store reached the degraded map")
    if negative.get("trust") != "authoritative":
        problems.append(
            "negative.trust is %r, wanted 'authoritative'" % (negative.get("trust"),)
        )
    if FLAG in signals:
        problems.append("a current store named itself a degraded signal: %r" % (signals,))
    if verdict.get("state") != "certified":
        problems.append("verdict.state is %r, wanted 'certified'" % (verdict.get("state"),))
    if factor is not None:
        problems.append("a certified answer named a limiting factor: %r" % (factor,))
    if completeness.get("bound") != "exact":
        problems.append("completeness.bound is %r, wanted 'exact'" % (completeness.get("bound"),))
    if counted_exact is not True:
        problems.append("completeness.counted.exact is %r, wanted True" % (counted_exact,))
    classes = completeness.get("classes")
    calls = classes.get("calls") if isinstance(classes, dict) else None
    if calls != "present":
        problems.append("completeness.classes.calls is %r, wanted 'present'" % (calls,))
    return problems


# Three files that reach one another, so `find_references` has a real cross-file
# `calls` set to answer from. Borrowed in shape from `verdict_limits_repro.py`,
# which already proves this fixture can certify an exact `calls` control, so the
# hydration arms vary one thing against a control that is known to work.
PYTHON_FIXTURE = {
    "pkg/__init__.py": "",
    "pkg/parsing.py": (
        '"""Parsing helpers."""\n\n\n'
        "class Note:\n"
        '    """One parsed note: a title and the body under it."""\n\n'
        "    def __init__(self, title: str, body: str) -> None:\n"
        "        self.title = title\n"
        "        self.body = body\n\n"
        "    def word_count(self) -> int:\n"
        "        return len(self.body.split())\n\n\n"
        "def blank_code(text: str) -> str:\n"
        '    """Mask fenced code so tags inside it are not markup."""\n'
        "    out = []\n"
        "    for line in text.splitlines():\n"
        "        out.append('' if line.startswith('```') else line)\n"
        "    return '\\n'.join(out)\n\n\n"
        "def extract_tags(text: str) -> list:\n"
        "    masked = blank_code(text)\n"
        "    return [w[1:] for w in masked.split() if w.startswith('#')]\n\n\n"
        "def parse_note(text: str) -> Note:\n"
        "    title, _, body = text.partition('\\n')\n"
        "    return Note(title.strip('# '), blank_code(body))\n"
    ),
    "pkg/search.py": (
        "from pkg.parsing import Note, blank_code, extract_tags, parse_note\n\n\n"
        "def index_note(text: str) -> dict:\n"
        "    note: Note = parse_note(text)\n"
        "    body = blank_code(text)\n"
        "    return {'title': note.title, 'tags': extract_tags(text),\n"
        "            'words': note.word_count(), 'raw_words': len(body.split())}\n"
    ),
    "tests/__init__.py": "",
    "tests/test_parsing.py": (
        "from pkg.parsing import Note, blank_code, parse_note\n\n\n"
        "def test_fenced_tags_are_masked():\n"
        "    assert '#nope' not in blank_code('real #tag\\n```\\n#nope\\n```')\n\n\n"
        "def test_parsed_title_is_kept():\n"
        "    note: Note = parse_note('# Alpha\\nbody')\n"
        "    assert note.title == 'Alpha'\n"
    ),
}


def write_python_fixture(root):
    for relative, body in PYTHON_FIXTURE.items():
        path = os.path.join(root, *relative.split("/"))
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(path, "w") as handle:
            handle.write(body)


def read_stamp(repo):
    """The creation record a store published, or a reason it could not be read."""
    path = os.path.join(repo, STAMP_REL)
    try:
        with open(path) as handle:
            return json.load(handle), None
    except FileNotFoundError:
        return None, "no record at %s" % path
    except (OSError, ValueError) as error:
        return None, "%s: %s" % (type(error).__name__, error)


def parse_json_object(text):
    start = (text or "").find("{")
    end = (text or "").rfind("}")
    if start < 0 or end < start:
        raise ValueError("no JSON object in output")
    return json.loads(text[start : end + 1])


class Suite(object):
    def __init__(self, kin, workdir, daemon=None, verbose=False):
        self.kin = kin
        self.daemon = daemon
        self.workdir = workdir
        self.verbose = verbose
        self.repo = os.path.join(workdir, "fixture")
        self.kin_home = os.path.join(workdir, "kin-home")
        os.makedirs(self.kin_home, exist_ok=True)
        self.env = dict(os.environ)
        self.env["KIN_HOME"] = self.kin_home
        self.env["KIN_DAEMON_AUTO_EMBED"] = "0"
        self.env["KIN_EMBED_BACKEND"] = "cpu"
        self.env["KIN_VFS_DISABLE"] = "1"
        self.env.pop("KIN_MCP_REPO", None)
        self.env.pop("KIN_DIR", None)
        if daemon:
            self.env["KIN_DAEMON_BIN"] = daemon
        self.original_stamp = None
        self.derives = None
        self.observations = {}
        self._doors = None
        self._transfer = None
        self._stop_repos = []

    def log(self, line):
        if self.verbose:
            print("  " + line, flush=True)

    def git(self, args):
        base = ["git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false"]
        return run(base + args, cwd=self.repo, env=self.env)

    def kin_run(self, args, timeout=600):
        rc, out = run([self.kin] + args, cwd=self.repo, env=self.env, timeout=timeout)
        self.log("kin %s -> %d" % (" ".join(args), rc))
        return rc, out

    def mcp(self, tool, args, timeout=300, repo=None):
        repo = repo or self.repo
        env = dict(self.env)
        env["KIN_MCP_REPO"] = repo
        proc = subprocess.Popen(
            [self.kin, "mcp", "start", "--repo", repo],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=repo,
            env=env,
            text=True,
        )
        frames = [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "kin-hydration-semantics-repro", "version": "1"},
                },
            },
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": tool, "arguments": args},
            },
        ]
        try:
            out, err = proc.communicate(
                "".join(json.dumps(frame) + "\n" for frame in frames), timeout=timeout
            )
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            raise RuntimeError("mcp %s timed out after %ss" % (tool, timeout))
        response = None
        for line in out.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                candidate = json.loads(line)
            except ValueError:
                continue
            if candidate.get("id") == 2:
                response = candidate
        if response is None:
            raise RuntimeError(
                "mcp %s returned no id=2 frame (stderr tail: %s)"
                % (tool, tail(err, 300).replace("\n", " "))
            )
        if "error" in response:
            raise RuntimeError("mcp %s error: %s" % (tool, tail(json.dumps(response["error"]))))
        content = (response.get("result") or {}).get("content") or []
        if not content or "text" not in content[0]:
            raise RuntimeError("mcp %s returned no text content" % tool)
        return json.loads(content[0]["text"])

    @property
    def stamp_path(self):
        return os.path.join(self.repo, STAMP_REL)

    def build_fixture(self):
        write_python_fixture(self.repo)
        rc, out = self.git(["init", "-q", "--initial-branch=main"])
        if rc != 0:
            raise RuntimeError("git init failed: %s" % tail(out))
        self.git(["config", "user.email", "repro@example.invalid"])
        self.git(["config", "user.name", "kin-hydration-semantics-repro"])
        self.git(["add", "--all"])
        rc, out = self.git(["commit", "-q", "-m", "hydration fixture"])
        if rc != 0:
            raise RuntimeError("git commit failed: %s" % tail(out))
        rc, out = self.kin_run(["init"], timeout=900)
        if rc != 0:
            raise RuntimeError("kin init failed: %s" % tail(out))
        try:
            with open(self.stamp_path) as handle:
                self.original_stamp = json.load(handle)
        except (OSError, ValueError) as error:
            raise RuntimeError("fresh store carries no readable creation-time stamp: %s" % error)
        derives = self.original_stamp.get("created_under")
        if not isinstance(derives, int) or isinstance(derives, bool) or derives < 1:
            raise RuntimeError("fresh store stamp carries invalid created_under: %r" % derives)
        self.derives = derives

    def select_arm(self, name):
        if name == "current":
            body = dict(self.original_stamp)
        elif name == "behind":
            body = dict(self.original_stamp)
            body["created_under"] = self.derives - 1
        elif name == "ahead":
            body = dict(self.original_stamp)
            body["created_under"] = self.derives + 1
        elif name == "absent":
            try:
                os.unlink(self.stamp_path)
            except FileNotFoundError:
                pass
            return
        elif name == "unreadable":
            body = dict(self.original_stamp)
            body["schema"] = "kin.hydration-semantics.v2"
        else:
            raise ValueError("unknown arm %r" % name)
        staged = self.stamp_path + ".repro"
        with open(staged, "w") as handle:
            json.dump(body, handle, sort_keys=True)
        os.replace(staged, self.stamp_path)

    def observe(self, name):
        if name in self.observations:
            return self.observations[name]
        self.select_arm(name)
        status = self.kin_run(["graph", "status"], timeout=900)
        doctor_rc, doctor_out = self.kin_run(["doctor", "--json"], timeout=900)
        try:
            doctor = (doctor_rc, parse_json_object(doctor_out), None)
        except (ValueError, json.JSONDecodeError) as error:
            doctor = (doctor_rc, None, "%s: %s" % (error, tail(doctor_out)))
        try:
            envelope = (self.mcp("kin_graph_status", {}), None)
        except (RuntimeError, ValueError, json.JSONDecodeError) as error:
            envelope = (None, str(error))
        try:
            retrieval = (self.find_references(), None)
        except (RuntimeError, ValueError, json.JSONDecodeError) as error:
            retrieval = (None, str(error))
        observation = {
            "status": status,
            "doctor": doctor,
            "envelope": envelope,
            "retrieval": retrieval,
        }
        self.observations[name] = observation
        return observation

    def kin_in(self, cwd, args, timeout=900):
        rc, out = run([self.kin] + args, cwd=cwd, env=self.env, timeout=timeout)
        self.log("kin %s (in %s) -> %d" % (" ".join(args), cwd, rc))
        return rc, out

    def git_in(self, cwd, args):
        base = ["git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false"]
        return run(base + args, cwd=cwd, env=self.env)

    def seed_git_repo(self, path, body):
        os.makedirs(path, exist_ok=True)
        with open(os.path.join(path, "seed.py"), "w") as handle:
            handle.write(body)
        rc, out = self.git_in(path, ["init", "-q", "--initial-branch=main"])
        if rc != 0:
            raise RuntimeError("git init failed in %s: %s" % (path, tail(out)))
        self.git_in(path, ["config", "user.email", "repro@example.invalid"])
        self.git_in(path, ["config", "user.name", "kin-hydration-semantics-repro"])
        self.git_in(path, ["add", "--all"])
        rc, out = self.git_in(path, ["commit", "-q", "-m", "creation door"])
        if rc != 0:
            raise RuntimeError("git commit failed in %s: %s" % (path, tail(out)))

    def creation_doors(self):
        """Build one store through each product door and return where it landed.

        Bounded on purpose: these are the doors the shipped binaries expose. The
        adopting door is the one a native replica is created through, so it is
        the door whose empty receiver later admits transported history.
        """
        if self._doors is not None:
            return self._doors
        root = os.path.join(self.workdir, "doors")
        os.makedirs(root, exist_ok=True)
        doors = []

        native = os.path.join(root, "native-unborn")
        os.makedirs(native, exist_ok=True)
        rc, out = self.kin_in(native, ["init"])
        doors.append(("kin init (bare directory)", native, None if rc == 0 else tail(out)))

        over_git = os.path.join(root, "over-git")
        try:
            self.seed_git_repo(over_git, "def over_git():\n    return 1\n")
            rc, out = self.kin_in(over_git, ["init"])
            doors.append(("kin init (Git checkout)", over_git, None if rc == 0 else tail(out)))
        except RuntimeError as error:
            doors.append(("kin init (Git checkout)", over_git, str(error)))

        adopting = os.path.join(root, "adopting")
        os.makedirs(adopting, exist_ok=True)
        adopted = str(uuid.uuid4())
        rc, out = self.kin_in(
            adopting, ["init", "--adopt-repository-id", adopted]
        )
        doors.append(
            ("kin init --adopt-repository-id", adopting, None if rc == 0 else tail(out))
        )

        clone_source = os.path.join(root, "clone-source")
        clone_target = os.path.join(root, "clone-target")
        try:
            self.seed_git_repo(clone_source, "def cloned():\n    return 2\n")
            rc, out = self.kin_in(root, ["clone", clone_source, clone_target])
            doors.append(
                ("kin clone (Git transport)", clone_target, None if rc == 0 else tail(out))
            )
        except RuntimeError as error:
            doors.append(("kin clone (Git transport)", clone_target, str(error)))

        self._doors = doors
        self._stop_repos.extend(repo for _, repo, error in doors if error is None)
        return doors

    def repository_id_of(self, repo):
        with open(os.path.join(repo, ".kin", "manifest.json")) as handle:
            manifest = json.load(handle)
        repo_id = manifest.get("repo_id")
        if not isinstance(repo_id, str) or not repo_id:
            raise RuntimeError("%s carries no repo_id in its manifest" % repo)
        return repo_id

    def transfer_endpoint(self, repo_path, attempts=6, pause=3):
        """The base URL this KIN_HOME's registry serves `repo_path` on.

        Matched on the repository ROOT the daemon line prints, not on the
        repository identity. The registry's `route` is a local route label such
        as `local-d91e230c53b7b8da` and is never the repository UUID, so a
        lookup keyed on identity finds nothing and reads exactly like a daemon
        that never came up.

        Retried because registration lands a moment after the command that
        spawned the worker returns, and a single read one second later is a race
        this suite lost on its first run.
        """
        root = os.path.realpath(repo_path)
        out = ""
        for attempt in range(attempts):
            rc, out = self.kin_run(["daemon", "status"], timeout=300)
            if rc != 0:
                raise RuntimeError("kin daemon status exited %d: %s" % (rc, tail(out)))
            in_block = False
            for line in out.splitlines():
                stripped = line.strip()
                if stripped.startswith("endpoint:"):
                    if in_block:
                        return stripped.split(":", 1)[1].strip()
                elif not line.startswith("    "):
                    # A daemon's own line, which ends with its repository root.
                    in_block = os.path.realpath(stripped.split("  ")[-1].strip()) == root
            if attempt + 1 < attempts:
                self.kin_in(repo_path, ["graph", "status"])
                time.sleep(pause)
        raise RuntimeError(
            "no daemon endpoint is registered for %s after %d reads; status was: %s"
            % (root, attempts, tail(out))
        )

    def native_transfer(self):
        """Move real history between two replicas and read the receiver after.

        Both doors are shipped CLI: the receiver is created by
        `kin init --adopt-repository-id`, which is how a store comes to share
        another repository's identity, and the history moves by `kin pull --url`.
        The source's own stamp is rewritten one version back purely as provenance
        setup; the transfer protocol carries no such field, which is the whole
        reason the receiver cannot keep claiming one.
        """
        if self._transfer is not None:
            return self._transfer

        source = os.path.join(self.workdir, "transfer-source")
        destination = os.path.join(self.workdir, "transfer-destination")
        self.seed_git_repo(source, "def transported():\n    return 3\n")
        rc, out = self.kin_in(source, ["init"])
        if rc != 0:
            raise RuntimeError("kin init on the transfer source failed: %s" % tail(out))
        self._stop_repos.append(source)
        repo_id = self.repository_id_of(source)

        source_stamp, why = read_stamp(source)
        if source_stamp is None:
            raise RuntimeError("the transfer source published no creation record: %s" % why)
        behind = dict(source_stamp)
        behind["created_under"] = self.derives - 1
        staged = os.path.join(source, STAMP_REL) + ".repro"
        with open(staged, "w") as handle:
            json.dump(behind, handle, sort_keys=True)
        os.replace(staged, os.path.join(source, STAMP_REL))

        os.makedirs(destination, exist_ok=True)
        rc, out = self.kin_in(destination, ["init", "--adopt-repository-id", repo_id])
        if rc != 0:
            raise RuntimeError("the adopting receiver could not be created: %s" % tail(out))
        self._stop_repos.append(destination)
        created, why = read_stamp(destination)
        if created is None or created.get("created_under") != self.derives:
            raise RuntimeError(
                "the receiver did not start current (%s)" % (why or created.get("created_under"))
            )

        # Bring the source's daemon up so it serves the transfer endpoint the
        # receiver will negotiate against.
        rc, out = self.kin_in(source, ["graph", "status"])
        if rc != 0:
            raise RuntimeError("the source daemon did not come up: %s" % tail(out))
        endpoint = self.transfer_endpoint(source)

        # And the receiver's own daemon, which is where a pull actually runs:
        # repository authority and every view derived from it live there, so
        # `kin pull` against a replica with no daemon refuses before it
        # negotiates anything. Creating the replica does not leave one running.
        rc, out = self.kin_in(destination, ["graph", "status"])
        if rc != 0:
            raise RuntimeError("the receiver's daemon did not come up: %s" % tail(out))

        rc, out = self.kin_in(destination, ["pull", "--url", endpoint, "--json"])
        if rc != 0:
            raise RuntimeError("kin pull exited %d: %s" % (rc, tail(out)))
        try:
            pulled = parse_json_object(out)
        except (ValueError, json.JSONDecodeError) as error:
            raise RuntimeError("kin pull printed no JSON object: %s (%s)" % (error, tail(out)))
        receipts = ((pulled.get("outcome") or {}).get("receipts")) or []

        status_rc, status = self.kin_in(destination, ["graph", "status"])
        doctor_rc, doctor_out = self.kin_in(destination, ["doctor", "--json"])
        try:
            doctor = parse_json_object(doctor_out)
        except (ValueError, json.JSONDecodeError):
            doctor = None
        envelope_error = None
        try:
            envelope = self.mcp("kin_graph_status", {}, repo=destination)
        except (RuntimeError, ValueError, json.JSONDecodeError) as error:
            envelope, envelope_error = None, str(error)

        # The no-admission control, on the same receiver: put the record back and
        # pull again, now that both replicas hold the same head.
        restored = dict(source_stamp)
        restored["created_under"] = self.derives
        staged = os.path.join(destination, STAMP_REL) + ".repro"
        os.makedirs(os.path.dirname(staged), exist_ok=True)
        with open(staged, "w") as handle:
            json.dump(restored, handle, sort_keys=True)
        os.replace(staged, os.path.join(destination, STAMP_REL))
        rc, control_out = self.kin_in(destination, ["pull", "--url", endpoint, "--json"])
        control_receipts = []
        if rc == 0:
            try:
                control_receipts = (
                    (parse_json_object(control_out).get("outcome") or {}).get("receipts")
                ) or []
            except (ValueError, json.JSONDecodeError):
                control_receipts = []

        self._transfer = {
            "destination": destination,
            "source": source,
            "moved_history": bool(receipts),
            "pull_output": out,
            "status": status,
            "status_rc": status_rc,
            "envelope_error": envelope_error,
            "doctor": doctor,
            "envelope": envelope,
            "control_moved_history": bool(control_receipts),
            "source_stamp": read_stamp(source)[0],
            "doctor_rc": doctor_rc,
        }
        return self._transfer

    def find_references(self, attempts=8, pause=4):
        """One negative-capable retrieval call, retried while enrichment settles.

        `calls` only, because that is the class this fixture defines directly and
        the one the exact control can certify. A populated answer is the point:
        it proves the real finalizer ran, and `find_references` still emits a
        `negative` block over a qualified answer, so a current store certifies
        and a hydration gap has to withdraw that.

        The wait is on the `calls` class reading `present`, not on the row count.
        `references` reads short until the language server has run, which is a
        fact about timing rather than about the verdict, and a retry keyed on
        rows alone stops as soon as one arrives with the class still settling.
        """
        payload = None
        for attempt in range(attempts):
            self.kin_run(["graph", "status"], timeout=900)
            payload = self.mcp(
                "find_references",
                {"query": "blank_code", "relation_kinds": ["calls"]},
            )
            rows = payload.get("references")
            classes = ((payload.get("_kin") or {}).get("completeness") or {}).get(
                "classes"
            ) or {}
            if isinstance(rows, list) and rows and classes.get("calls") == "present":
                return payload
            if attempt + 1 < attempts:
                time.sleep(pause)
        return payload


ARMS = ("current", "behind", "ahead", "absent", "unreadable")


def arm_created_under(suite, standing):
    if standing == "current":
        return suite.derives
    if standing == "behind":
        return suite.derives - 1
    if standing == "ahead":
        return suite.derives + 1
    return None


def check_status(suite):
    result = Result("status", "graph status stays silent on agreement and discloses every gap")
    for standing in ARMS:
        rc, out = suite.observe(standing)["status"]
        if rc != 0:
            result.unknown(
                "%s: graph status exited %d: %s" % (standing, rc, tail(out))
            )
            continue
        recorded_under = arm_created_under(suite, standing)
        problems = status_problems(out, standing, recorded_under, suite.derives)
        if problems:
            result.bad(
                "%s: %s; output: %s"
                % (standing, "; ".join(problems), tail(out))
            )
        else:
            result.ok(
                "%s: %s"
                % (
                    standing,
                    "current and silent" if standing == "current" else "gap disclosed",
                )
            )
    return result


def check_doctor(suite):
    result = Result("doctor", "doctor separates current from stale creation-time semantics")
    for standing in ARMS:
        rc, report, error = suite.observe(standing)["doctor"]
        if report is None:
            result.unknown(
                "%s: doctor output unreadable (rc=%d): %s"
                % (standing, rc, error)
            )
            continue
        recorded_under = arm_created_under(suite, standing)
        problems = doctor_problems(report, standing, recorded_under, suite.derives)
        if problems:
            result.bad("%s: %s" % (standing, "; ".join(problems)))
        else:
            result.ok(
                "%s: %s row"
                % (standing, "healthy" if standing == "current" else "stale")
            )
    return result


def check_envelope(suite):
    result = Result(
        "envelope",
        "the stdio MCP envelope publishes the standing, both versions and the safe action",
    )
    for standing in ARMS:
        payload, error = suite.observe(standing)["envelope"]
        if payload is None:
            result.unknown("%s: MCP envelope unreadable: %s" % (standing, error))
            continue
        problems = envelope_problems(
            payload, standing, arm_created_under(suite, standing), suite.derives
        )
        if problems:
            result.bad(
                "%s: %s; payload: %s"
                % (standing, "; ".join(problems), tail(json.dumps(payload)))
            )
        else:
            result.ok(
                "%s: %s observation%s"
                % (
                    standing,
                    WIRE_STANDING[standing],
                    "" if standing == "current" else " with the canonical remedy",
                )
            )
    return result


def check_verdict(suite):
    """The one verdict a reader acts on, over a real negative-capable call.

    The gate FIR-2829 states is that a successful answer stops being
    authoritative when the store cannot show its persisted history matches this
    build's replay semantics. A graph-status flag cannot establish that:
    `kin_graph_status` is not a negative-capable tool, so nothing about its
    output constrains `negative` or `_kin.verdict`. This drives
    `find_references` instead, which produces both.
    """
    result = Result(
        "verdict",
        "the same negative-capable answer certifies on a current store and is inconclusive on "
        "every gap",
    )
    control, error = suite.observe("current")["retrieval"]
    if control is None:
        result.unknown("current: find_references unreadable: %s" % error)
        return result
    problems = verdict_problems(control, gap=False)
    if problems:
        # A control that cannot certify makes every gap arm meaningless, because
        # an answer that was never authoritative cannot be shown to have lost
        # its authority. Report what stopped it rather than weakening the bar.
        result.unknown(
            "current: the exact control could not certify, so the gap arms prove nothing: %s"
            % "; ".join(problems)
        )
        return result
    result.ok("current: certified, exact, calls present")

    for standing in ARMS:
        if standing == "current":
            continue
        payload, error = suite.observe(standing)["retrieval"]
        if payload is None:
            result.unknown("%s: find_references unreadable: %s" % (standing, error))
            continue
        problems = verdict_problems(payload, gap=True)
        if problems:
            result.bad(
                "%s: %s; envelope: %s"
                % (
                    standing,
                    "; ".join(problems),
                    tail(json.dumps((payload or {}).get("_kin", {}))),
                )
            )
        else:
            result.ok("%s: inconclusive, absence gate withdrawn" % standing)
    return result


def check_creation_doors(suite):
    """Every product door that creates a store publishes a readable record.

    One door proved nothing about the others. The implementation converges every
    creation path on one staging boundary, and a future path can leave that
    boundary while a suite that only ever built one store stays green.
    """
    result = Result(
        "creation_doors",
        "every creation door publishes a readable creation record",
    )
    doors = suite.creation_doors()
    if not doors:
        result.unknown("no creation door could be built")
        return result
    for door, repo, error in doors:
        if error:
            result.unknown("%s: %s" % (door, error))
            continue
        stamp, why = read_stamp(repo)
        if stamp is None:
            result.bad("%s: %s" % (door, why))
            continue
        recorded = stamp.get("created_under")
        if recorded != suite.derives:
            result.bad(
                "%s: recorded created_under %r, this build derives %r"
                % (door, recorded, suite.derives)
            )
        elif stamp.get("schema") != suite.original_stamp.get("schema"):
            result.bad(
                "%s: schema %r is not %r"
                % (door, stamp.get("schema"), suite.original_stamp.get("schema"))
            )
        else:
            result.ok("%s: recorded %d" % (door, recorded))
    return result


def check_native_transfer(suite):
    """Transported history must not inherit the receiver's creation record.

    The defect: a receiver created by this build stamps itself with this build's
    version, then admits history authored somewhere else by some other build,
    and every surface reads current over it. The transfer protocol carries no
    authoring version, so the only honest outcome is that the receiver stops
    claiming one.
    """
    result = Result(
        "native_transfer",
        "admitting version-unknown transported history withdraws the receiver's creation record",
    )
    try:
        transfer = suite.native_transfer()
    except RuntimeError as error:
        result.unknown("the native transfer fixture could not be built: %s" % error)
        return result

    if not transfer["moved_history"]:
        result.unknown(
            "the pull admitted no history, so it says nothing about the commit boundary: %s"
            % tail(transfer["pull_output"])
        )
        return result
    result.ok("the pull admitted the source's history")

    stamp, why = read_stamp(transfer["destination"])
    if stamp is not None:
        result.bad(
            "the receiver still records created_under %r after admitting transported history"
            % (stamp.get("created_under"),)
        )
    else:
        result.ok("the receiver's creation record is gone (%s)" % why)

    # An unreadable surface is UNREADABLE, never a FAIL. A doctor report that
    # would not parse and a doctor report with no hydration row are different
    # facts, and the graders below cannot tell them apart on their own.
    if transfer["status_rc"] != 0:
        result.unknown(
            "graph status exited %d on the receiver: %s"
            % (transfer["status_rc"], tail(transfer["status"]))
        )
    else:
        problems = status_problems(transfer["status"], "absent", None, suite.derives)
        if problems:
            result.bad("status does not disclose the transported-history gap: %s" % "; ".join(problems))
        else:
            result.ok("status discloses the gap")

    if transfer["doctor"] is None:
        result.unknown("the receiver's doctor output was unreadable (rc=%d)" % transfer["doctor_rc"])
    else:
        problems = doctor_problems(transfer["doctor"], "absent", None, suite.derives)
        if problems:
            result.bad("doctor does not disclose the transported-history gap: %s" % "; ".join(problems))
        else:
            result.ok("doctor discloses the gap")

    if transfer["envelope"] is None:
        result.unknown("the receiver's MCP envelope was unreadable: %s" % transfer["envelope_error"])
    else:
        problems = envelope_problems(transfer["envelope"], "absent", None, suite.derives)
        if problems:
            result.bad("the MCP envelope does not disclose the transported-history gap: %s" % "; ".join(problems))
        else:
            result.ok("the MCP envelope discloses the gap")

    # The control. A receiver that discarded its record on every pull, rather
    # than on every admission, would pass everything above and degrade a healthy
    # store on each no-op sync.
    if transfer["control_moved_history"]:
        result.unknown(
            "the control pull admitted history, so it is not a no-admission control"
        )
    else:
        control_stamp, control_why = read_stamp(transfer["destination"])
        if control_stamp is None:
            result.bad(
                "a pull that admitted nothing still discarded the record (%s)" % control_why
            )
        elif control_stamp.get("created_under") != suite.derives:
            result.bad(
                "the control receiver records %r, wanted %r"
                % (control_stamp.get("created_under"), suite.derives)
            )
        else:
            result.ok("a pull that admitted nothing left the record alone")

    source_stamp = transfer["source_stamp"]
    if source_stamp is None:
        result.bad("the transfer removed the SOURCE's creation record, which it must never do")
    elif source_stamp.get("created_under") != suite.derives - 1:
        result.bad(
            "the transfer rewrote the SOURCE's creation record to %r, wanted the %r it was set to"
            % (source_stamp.get("created_under"), suite.derives - 1)
        )
    else:
        result.ok("the source's own record still reads %d" % (suite.derives - 1))
    return result


CHECKS = (
    check_status,
    check_doctor,
    check_envelope,
    check_verdict,
    check_creation_doors,
    check_native_transfer,
)
DECLARED = (
    "status",
    "doctor",
    "envelope",
    "verdict",
    "creation_doors",
    "native_transfer",
)


def self_test():
    failures = []
    count = [0]

    def expect(label, got, want):
        count[0] += 1
        if got != want:
            failures.append("%s: got %r, wanted %r" % (label, got, want))

    def rejects(label, problems):
        count[0] += 1
        if not problems:
            failures.append("%s: accepted, wanted a rejection" % label)

    # Every fixture below is built from the canonical remedy rather than from a
    # hand-typed paraphrase. A grader and a fixture that each hardcode the same
    # invented string agree perfectly and say nothing about the product, and a
    # renamed remedy would leave both green over text nothing emits.
    def status_line(sentence, remedy):
        return "⚠ hydration semantics: %s.%s\n" % (
            sentence,
            "" if remedy is None else " Remedy: %s." % remedy,
        )

    current_line = "Graph healthy\n"
    behind_line = status_line(
        "this store records hydration semantics version 9 at creation and this build derives "
        "version 10, so the store cannot certify that its persisted history reflects this "
        "build's replay semantics",
        REMEDY_BEHIND,
    )
    ahead_line = status_line(
        "this store records hydration semantics version 11 at creation and this build derives "
        "the older version 10, so this binary predates the store's recorded semantics",
        REMEDY_AHEAD,
    )
    absent_line = status_line(
        "this store records no hydration semantics version, so its persisted history cannot be "
        "shown to match the version 10 this build derives",
        REMEDY_UNKNOWN,
    )
    unreadable_line = status_line(
        "this store's hydration semantics record could not be read (future schema), so its "
        "creation-time version cannot be shown to match the version 10 this build derives",
        REMEDY_UNKNOWN,
    )
    expect("status current", status_problems(current_line, "current", 10, 10), [])
    expect("status behind", status_problems(behind_line, "behind", 9, 10), [])
    expect("status ahead", status_problems(ahead_line, "ahead", 11, 10), [])
    expect("status absent", status_problems(absent_line, "absent", None, 10), [])
    expect(
        "status unreadable",
        status_problems(unreadable_line, "unreadable", None, 10),
        [],
    )
    rejects(
        "status unconditional warning",
        status_problems(behind_line, "current", 10, 10),
    )
    rejects(
        "status missing remedy",
        status_problems(
            behind_line.replace(" Remedy: %s." % REMEDY_BEHIND, ""), "behind", 9, 10
        ),
    )
    for label, line, standing, recorded, wrong in (
        ("ahead", ahead_line, "ahead", 11, REMEDY_BEHIND),
        ("absent", absent_line, "absent", None, REMEDY_BEHIND),
        ("unreadable", unreadable_line, "unreadable", None, REMEDY_BEHIND),
        ("behind", behind_line, "behind", 9, REMEDY_AHEAD),
    ):
        rejects(
            "status %s carrying the wrong remedy" % label,
            status_problems(
                line.replace(CANONICAL_REMEDY[standing], wrong), standing, recorded, 10
            ),
        )

    # The mixed safe-plus-unsafe arms. Each begins with the exact canonical
    # advice and then contradicts it, which is what a prefix or substring grader
    # accepts and what actually destroys a store.
    UNSAFE_AHEAD_TAIL = (
        " Then re-ingest this store with the running older build and replace the existing store."
    )
    UNSAFE_UNKNOWN_TAIL = " Then replace the original store in place."
    rejects(
        "status ahead with an unsafe tail",
        status_problems(
            ahead_line.rstrip("\n") + UNSAFE_AHEAD_TAIL + "\n", "ahead", 11, 10
        ),
    )
    rejects(
        "status absent with an unsafe tail",
        status_problems(
            absent_line.rstrip("\n") + UNSAFE_UNKNOWN_TAIL + "\n", "absent", None, 10
        ),
    )
    rejects(
        "status unreadable with an unsafe tail",
        status_problems(
            unreadable_line.rstrip("\n") + UNSAFE_UNKNOWN_TAIL + "\n",
            "unreadable",
            None,
            10,
        ),
    )
    rejects(
        "status behind with an unsafe tail",
        status_problems(
            behind_line.rstrip("\n") + " Then keep using the old store and do not re-ingest.\n",
            "behind",
            9,
            10,
        ),
    )
    # And the control that keeps the four arms above from being satisfied by a
    # grader that rejects every long line: the canonical text is still accepted.
    expect(
        "status ahead canonical still accepted",
        status_problems(ahead_line, "ahead", 11, 10),
        [],
    )

    def doctor_row(standing, detail, fix):
        return {
            "checks": [
                {
                    "id": "hydration_semantics",
                    "status": "healthy" if standing == "current" else "stale",
                    "detail": detail,
                    "manual_fix": fix,
                }
            ]
        }

    current_row = doctor_row(
        "current",
        "this store records hydration semantics version 10 at creation, matching the version "
        "this build derives",
        None,
    )
    behind_row = doctor_row(
        "behind",
        "this store records hydration semantics version 9 at creation and this build derives "
        "version 10, so the store cannot certify its persisted history",
        REMEDY_BEHIND,
    )
    ahead_row = doctor_row(
        "ahead",
        "this store records hydration semantics version 11 at creation and this build derives "
        "the older version 10, so this binary predates the record",
        REMEDY_AHEAD,
    )
    absent_row = doctor_row(
        "absent",
        "this store records no hydration semantics version, so its persisted history cannot be "
        "shown to match the version 10 this build derives",
        REMEDY_UNKNOWN,
    )
    unreadable_row = doctor_row(
        "unreadable",
        "this store's hydration semantics record could not be read (future schema), so its "
        "creation-time version cannot be shown to match version 10",
        REMEDY_UNKNOWN,
    )
    expect("doctor current", doctor_problems(current_row, "current", 10, 10), [])
    expect("doctor behind", doctor_problems(behind_row, "behind", 9, 10), [])
    expect("doctor ahead", doctor_problems(ahead_row, "ahead", 11, 10), [])
    expect("doctor absent", doctor_problems(absent_row, "absent", None, 10), [])
    expect(
        "doctor unreadable",
        doctor_problems(unreadable_row, "unreadable", None, 10),
        [],
    )
    rejects("doctor false healthy", doctor_problems(current_row, "behind", 9, 10))
    rejects("doctor missing row", doctor_problems({"checks": []}, "current", 10, 10))

    def with_fix(row, fix):
        mutated = json.loads(json.dumps(row))
        mutated["checks"][0]["manual_fix"] = fix
        return mutated

    for label, row, standing, recorded, wrong in (
        ("ahead", ahead_row, "ahead", 11, REMEDY_BEHIND),
        ("behind", behind_row, "behind", 9, REMEDY_AHEAD),
        ("absent", absent_row, "absent", None, REMEDY_BEHIND),
        ("unreadable", unreadable_row, "unreadable", None, REMEDY_BEHIND),
    ):
        rejects(
            "doctor %s carrying the wrong remedy" % label,
            doctor_problems(with_fix(row, wrong), standing, recorded, 10),
        )
    rejects(
        "doctor ahead with an unsafe clause",
        doctor_problems(
            with_fix(
                ahead_row,
                REMEDY_AHEAD
                + "; then re-ingest this store with this older binary and replace it",
            ),
            "ahead",
            11,
            10,
        ),
    )
    for label, row, standing in (
        ("absent", absent_row, "absent"),
        ("unreadable", unreadable_row, "unreadable"),
    ):
        rejects(
            "doctor %s with an unsafe clause" % label,
            doctor_problems(
                with_fix(row, REMEDY_UNKNOWN + "; then replace the original store in place"),
                standing,
                None,
                10,
            ),
        )
    rejects(
        "doctor current with a manufactured remedy",
        doctor_problems(with_fix(current_row, REMEDY_BEHIND), "current", 10, 10),
    )

    def envelope_payload(standing, created_under=None, derives=10, **overrides):
        observation = {"standing": WIRE_STANDING[standing], "derives": derives}
        if created_under is not None:
            observation["created_under"] = created_under
        if standing == "unreadable":
            observation["reason"] = "schema kin.hydration-semantics.v2 is not v1"
        remedy = CANONICAL_REMEDY[standing]
        if remedy is not None:
            observation["remedy"] = remedy
        observation.update(overrides)
        degraded = {} if standing == "current" else {FLAG: True}
        return {"_kin": {"degraded": degraded, OBSERVATION: observation}}

    expect(
        "envelope current",
        envelope_problems(envelope_payload("current", 10), "current", 10, 10),
        [],
    )
    expect(
        "envelope behind",
        envelope_problems(envelope_payload("behind", 9), "behind", 9, 10),
        [],
    )
    expect(
        "envelope ahead",
        envelope_problems(envelope_payload("ahead", 11), "ahead", 11, 10),
        [],
    )
    expect(
        "envelope absent",
        envelope_problems(envelope_payload("absent"), "absent", None, 10),
        [],
    )
    expect(
        "envelope unreadable",
        envelope_problems(envelope_payload("unreadable"), "unreadable", None, 10),
        [],
    )

    # The nine structured mutants. Each is a response that would satisfy a
    # boolean-only grader and mislead an agent about what is safe to do.
    wrong_direction = envelope_payload("ahead", 11)
    wrong_direction["_kin"][OBSERVATION]["standing"] = "behind"
    rejects("envelope gap flagged with the wrong direction", envelope_problems(wrong_direction, "ahead", 11, 10))

    remedied_current = envelope_payload("current", 10, remedy=REMEDY_BEHIND)
    rejects("envelope current carrying a remedy", envelope_problems(remedied_current, "current", 10, 10))

    ahead_as_behind = envelope_payload("ahead", 9, remedy=REMEDY_BEHIND)
    rejects("envelope ahead with behind ordering and advice", envelope_problems(ahead_as_behind, "ahead", 11, 10))

    behind_as_ahead = envelope_payload("behind", 11, remedy=REMEDY_AHEAD)
    rejects("envelope behind with ahead ordering and advice", envelope_problems(behind_as_ahead, "behind", 9, 10))

    fabricated = envelope_payload("absent", created_under=10)
    rejects("envelope unstamped with a fabricated version", envelope_problems(fabricated, "absent", None, 10))

    for label, reason in (("omitted", None), ("empty", "   ")):
        blank = envelope_payload("unreadable")
        if reason is None:
            blank["_kin"][OBSERVATION].pop("reason")
        else:
            blank["_kin"][OBSERVATION]["reason"] = reason
        rejects("envelope unreadable with a %s reason" % label, envelope_problems(blank, "unreadable", None, 10))

    # One field each, for the same reason the verdict arms below carry
    # single-field inputs: the two mutants above move the version AND the advice,
    # so either assertion alone would have satisfied them and the other could
    # have been deleted unnoticed.
    wrong_version_only = envelope_payload("ahead", 12)
    rejects(
        "envelope ahead naming the wrong recorded version",
        envelope_problems(wrong_version_only, "ahead", 11, 10),
    )

    wrong_remedy_only = envelope_payload("ahead", 11, remedy=REMEDY_UNKNOWN)
    rejects(
        "envelope ahead carrying the unknown-direction advice",
        envelope_problems(wrong_remedy_only, "ahead", 11, 10),
    )

    wrong_derives_only = envelope_payload("behind", 9, derives=11)
    rejects(
        "envelope naming the wrong derived version",
        envelope_problems(wrong_derives_only, "behind", 9, 10),
    )

    erased = envelope_payload("behind", 9)
    erased["_kin"].pop(OBSERVATION)
    rejects(
        "envelope keeping the boolean and erasing the observation",
        envelope_problems(erased, "behind", 9, 10),
    )

    silent_flag = envelope_payload("behind", 9)
    silent_flag["_kin"]["degraded"] = {}
    rejects("envelope gap with no degraded flag", envelope_problems(silent_flag, "behind", 9, 10))

    false_flag = envelope_payload("behind", 9)
    false_flag["_kin"]["degraded"][FLAG] = False
    rejects("envelope false is not a gap", envelope_problems(false_flag, "behind", 9, 10))
    rejects("envelope missing is unreadable", envelope_problems({}, "behind", 9, 10))
    rejects(
        "envelope current serializing the gap flag",
        envelope_problems(
            {"_kin": {"degraded": {FLAG: True}, OBSERVATION: {"standing": "current", "derives": 10, "created_under": 10}}},
            "current",
            10,
            10,
        ),
    )

    def retrieval_payload(gap):
        # `negative` beside `_kin`, not inside it, exactly as a real
        # `find_references` response carries it.
        return {
            "references": [{"id": "pkg/search.py::index_note"}],
            "negative": {
                "interpretation": "qualified_answer",
                "trust": "inconclusive" if gap else "authoritative",
                "safe_to_conclude_absent": False,
                "degraded_signals": [FLAG] if gap else [],
            },
            "_kin": {
                "degraded": {FLAG: True} if gap else {},
                OBSERVATION: {
                    "standing": "behind" if gap else "current",
                    "derives": 10,
                    "created_under": 9 if gap else 10,
                },
                "verdict": {
                    "state": "inconclusive" if gap else "certified",
                    "absence_claim": "not_applicable",
                    "safe_to_conclude_absent": False,
                    "limiting_factor": (
                        "degraded signals %s" % FLAG if gap else None
                    ),
                    "inputs": {"absence_gate": "inconclusive" if gap else "certified"},
                },
                "completeness": {
                    "bound": "at_least" if gap else "exact",
                    "counted": {"exact": not gap},
                    "limits": (
                        ["degraded:%s" % FLAG, "verdict_inconclusive"] if gap else []
                    ),
                    "classes": {"calls": "present"},
                },
            },
        }

    expect("verdict current control", verdict_problems(retrieval_payload(False), gap=False), [])
    expect("verdict gap arm", verdict_problems(retrieval_payload(True), gap=True), [])

    still_trusted = retrieval_payload(True)
    still_trusted["negative"]["trust"] = "authoritative"
    rejects("verdict gap answering authoritative", verdict_problems(still_trusted, gap=True))

    still_certified = retrieval_payload(True)
    still_certified["_kin"]["verdict"]["state"] = "certified"
    still_certified["_kin"]["verdict"]["inputs"]["absence_gate"] = "certified"
    still_certified["_kin"]["verdict"]["limiting_factor"] = None
    rejects("verdict gap still certified", verdict_problems(still_certified, gap=True))

    # One field each, from here down. The arm above moves three fields at once,
    # so three assertions can catch it and any two of them could be deleted
    # without the suite noticing. Each input below is inconsistent on purpose,
    # because that is the shape a half-finished regression actually produces and
    # it is the only input its own assertion can catch alone.
    def one_field(mutate):
        payload = retrieval_payload(True)
        mutate(payload)
        return payload

    def set_state(payload):
        payload["_kin"]["verdict"]["state"] = "certified"

    def set_safe(payload):
        payload["_kin"]["verdict"]["safe_to_conclude_absent"] = True

    def set_gate(payload):
        payload["_kin"]["verdict"]["inputs"]["absence_gate"] = "certified"

    def set_negative_safe(payload):
        payload["negative"]["safe_to_conclude_absent"] = True

    def set_interpretation(payload):
        payload["negative"]["interpretation"] = "absent_as_indexed"

    def set_bound(payload):
        payload["_kin"]["completeness"]["bound"] = "exact"

    def set_counted(payload):
        payload["_kin"]["completeness"]["counted"]["exact"] = True

    def drop_degraded_limit(payload):
        payload["_kin"]["completeness"]["limits"] = ["verdict_inconclusive"]

    def drop_verdict_limit(payload):
        payload["_kin"]["completeness"]["limits"] = ["degraded:%s" % FLAG]

    def drop_flag(payload):
        payload["_kin"]["degraded"] = {}

    def drop_signal(payload):
        payload["negative"]["degraded_signals"] = []

    for label, mutate in (
        ("verdict.state alone", set_state),
        ("verdict.safe_to_conclude_absent alone", set_safe),
        ("verdict.inputs.absence_gate alone", set_gate),
        ("negative.safe_to_conclude_absent alone", set_negative_safe),
        ("negative.interpretation alone", set_interpretation),
        ("completeness.bound alone", set_bound),
        ("completeness.counted.exact alone", set_counted),
        ("the degraded limit alone", drop_degraded_limit),
        ("the verdict_inconclusive limit alone", drop_verdict_limit),
        ("the degraded flag alone", drop_flag),
        ("the degraded signal alone", drop_signal),
    ):
        rejects("verdict gap moving %s" % label, verdict_problems(one_field(mutate), gap=True))

    unnamed = retrieval_payload(True)
    unnamed["_kin"]["verdict"]["limiting_factor"] = (
        "coverage_unknown: embedding coverage was not reported"
    )
    rejects("verdict gap blaming a non-degraded cause", verdict_problems(unnamed, gap=True))

    unblamed = retrieval_payload(True)
    unblamed["_kin"]["verdict"]["limiting_factor"] = None
    rejects("verdict gap naming no limiting factor", verdict_problems(unblamed, gap=True))

    untrusted_current = retrieval_payload(False)
    untrusted_current["negative"]["trust"] = "inconclusive"
    rejects(
        "verdict current answering inconclusive trust",
        verdict_problems(untrusted_current, gap=False),
    )

    uncertified_current = retrieval_payload(False)
    uncertified_current["_kin"]["verdict"]["state"] = "inconclusive"
    rejects(
        "verdict current refusing to certify",
        verdict_problems(uncertified_current, gap=False),
    )

    inexact_current = retrieval_payload(False)
    inexact_current["_kin"]["completeness"]["bound"] = "at_least"
    rejects("verdict current bounded at_least", verdict_problems(inexact_current, gap=False))

    uncounted_current = retrieval_payload(False)
    uncounted_current["_kin"]["completeness"]["counted"]["exact"] = False
    rejects("verdict current counting inexactly", verdict_problems(uncounted_current, gap=False))

    absent_class = retrieval_payload(False)
    absent_class["_kin"]["completeness"]["classes"]["calls"] = "absent"
    rejects("verdict current with the calls class absent", verdict_problems(absent_class, gap=False))

    flagged_current = retrieval_payload(False)
    flagged_current["_kin"]["degraded"] = {FLAG: True}
    rejects("verdict current flagged as degraded", verdict_problems(flagged_current, gap=False))

    signalled_current = retrieval_payload(False)
    signalled_current["negative"]["degraded_signals"] = [FLAG]
    rejects(
        "verdict current naming itself a degraded signal",
        verdict_problems(signalled_current, gap=False),
    )

    blamed_current = retrieval_payload(False)
    blamed_current["_kin"]["verdict"]["limiting_factor"] = "degraded signals %s" % FLAG
    rejects("verdict current naming a limiting factor", verdict_problems(blamed_current, gap=False))

    empty_answer = retrieval_payload(False)
    empty_answer["references"] = []
    rejects("verdict grading an answer with no rows", verdict_problems(empty_answer, gap=False))
    rejects("verdict grading a payload with no envelope", verdict_problems({}, gap=False))

    expect("declared checks are exact", tuple(check.__name__.replace("check_", "") for check in CHECKS), DECLARED)
    for wanted, rows in (
        (PASS, [(PASS, "ok")]),
        (FAIL, [(PASS, "ok"), (FAIL, "bad")]),
        (UNREADABLE, [(PASS, "ok"), (UNREADABLE, "unknown")]),
        (UNREADABLE, []),
    ):
        result = Result("test", "test")
        for status, detail in rows:
            result.asserts.append({"status": status, "detail": detail})
        expect("Result.status %r" % (rows,), result.status, wanted)

    for failure in failures:
        print("SELFTEST FAIL %s" % failure)
    print(
        "kin-hydration-semantics-repro: self-test %d/%d cases"
        % (count[0] - len(failures), count[0])
    )
    return 1 if failures else 0


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--kin", default=os.environ.get("KIN_BIN"))
    parser.add_argument("--daemon", default=os.environ.get("KIN_DAEMON_BIN"))
    parser.add_argument("--json", dest="json_path", default=None)
    parser.add_argument("--label", default=os.environ.get("KIN_ACCEPTANCE_LABEL"))
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()
    if not args.kin:
        print("kin-hydration-semantics-repro: no kin binary. Pass --kin or set KIN_BIN.")
        return 3
    kin = os.path.abspath(os.path.expanduser(args.kin))
    if not os.path.isfile(kin) or not os.access(kin, os.X_OK):
        print("kin-hydration-semantics-repro: %s is not executable" % kin)
        return 3
    daemon = args.daemon and os.path.abspath(os.path.expanduser(args.daemon))
    if not daemon:
        beside = os.path.join(os.path.dirname(kin), "kin-daemon")
        daemon = beside if os.path.isfile(beside) else None

    workdir = tempfile.mkdtemp(prefix="kin-hydration-semantics-repro-")
    suite = None
    try:
        suite = Suite(kin, workdir, daemon=daemon, verbose=args.verbose)
        suite.build_fixture()
        results = []
        for check in CHECKS:
            try:
                results.append(check(suite))
            except Exception as error:  # noqa: BLE001
                result = Result(check.__name__.replace("check_", ""), "probe crashed")
                result.unknown("%s: %s" % (type(error).__name__, error))
                results.append(result)
        for result in results:
            print("CHECK %s %s %s %s" % (result.id, TICKET, result.status, result.detail))
        answered = tuple(result.id for result in results)
        if answered != DECLARED:
            print("kin-hydration-semantics-repro: declared %r but %r answered" % (DECLARED, answered))
            return 3
        failed = [result for result in results if result.status == FAIL]
        unreadable = [result for result in results if result.status == UNREADABLE]
        print(
            "kin-hydration-semantics-repro: %d checks, %d pass, %d FAIL, %d UNREADABLE"
            % (len(results), len(results) - len(failed) - len(unreadable), len(failed), len(unreadable))
        )
        if args.json_path:
            payload = {
                "suite": "hydration_semantics_repro",
                "ticket": TICKET,
                "label": args.label,
                "kin": kin,
                "results": [
                    {
                        "id": result.id,
                        "ticket": TICKET,
                        "title": result.title,
                        "status": result.status,
                        "detail": result.detail,
                        "asserts": result.asserts,
                    }
                    for result in results
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
    except Exception as error:  # noqa: BLE001
        print("kin-hydration-semantics-repro: setup failed: %s" % error)
        return 3
    finally:
        if suite is not None:
            # Every repository this suite brought a daemon up for, not just the
            # fixture. A creation door and both transfer replicas each start one,
            # and a left-behind worker holds a port and a store directory the
            # cleanup below is about to delete underneath it.
            for repo in [suite.repo] + list(suite._stop_repos):
                if os.path.isdir(os.path.join(repo, ".kin")):
                    suite.kin_in(repo, ["daemon", "stop"], timeout=300)
        if not args.keep:
            shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
