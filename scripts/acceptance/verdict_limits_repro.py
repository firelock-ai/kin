#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
"""NON-CITABLE acceptance suite for the one-verdict contract (FIR-2672).

Its output is a regression gate, never proof, never investor-facing and never a
released claim. It shares the CHECK line format, the exit codes and the
`--self-test` discipline of its siblings in this directory.

What it is for
--------------
The rc0552s green stranger asked `find_references` for a Python function on
0.5.52, got a verdict reading `state: certified`, `edge_coverage: certified`,
`limiting_factor: null`, `completeness.status: complete`, `bound: exact`, and a
note saying the counts were the whole set, in the same `_kin` block that
recorded `classes.imports: "absent"` and `limits: ["edge_coverage:imports_absent"]`.
It renamed the sites Kin certified and the code broke on the import sites Kin
had never been able to read. Every release from 0.5.43, the first to carry the
one verdict, certified the same way; the rule was born certifying over a
recorded limit.

The contract the MCP instructions state is one verdict per response, computed
from every block that qualifies the answer, with the most pessimistic input
winning. These checks hold the envelope to it on a live store:

  invariant   on the default query (calls, imports, references), no requested
              class in `completeness.classes` may read anything but `present`
              while the verdict certifies; when one does, the verdict is
              inconclusive, its limiting factor names the class, the
              completeness status is not `complete`, the bound is a floor, and
              `limits` names the class. When every class is present, the
              verdict certifies. Either world passes; the shipped shape fails.
  inverse     the control that keeps the invariant from being satisfied by
              refusing everything. On a build whose linker produces import
              edges, the default query has every requested class present and
              must certify with `limiting_factor: null` and an exact count;
              that is the genuine inverse. On a build whose linker does not,
              the check falls back to the same focal over `calls` alone, a
              class the fixture proves present, and says so in its detail.
  unproduced  the import class is never `absent` on a source whose files
              import one another: it reads `unproduced` on a build whose
              linker emits no entity-level import edge, and `present` on one
              whose linker does. `absent` on this source is the 0.5.52 wording
              this ticket is about.
  two_reasons the same query under the server's smallest response budget,
              which withholds rows and refuses on its own. Every input the
              verdict records as inconclusive keeps its clause in
              `limiting_factor`, each label once: the budget's clause beside
              the class gap on a build that cannot produce the import class,
              the budget's clause alone on one that can. The shape this guards
              against kept one clause and dropped the rest, which one level up
              is a CLI line naming the edge gap and not the dead embedding
              worker beside it.

    CHECK <id> <ticket> PASS|FAIL|UNREADABLE <detail>

UNREADABLE is a distinct outcome from FAIL and is never reported as a pass.
Exit status is 1 when any check FAILs, 2 when none fail but some are
UNREADABLE, 0 only when every check passes, 3 on a setup error.

The binary under test
---------------------
    cargo build --release --locked --bin kin --bin kin-daemon
    python3 scripts/acceptance/verdict_limits_repro.py --kin target/release/kin

`--kin` may also come from KIN_BIN. The kin-daemon beside it is used when one
exists. The fixture is Python and the `references` class needs a Python
language server (pyright) reachable by the daemon, as the acceptance workflow
installs; without one, `references` reads short and the checks say so.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

PASS = "PASS"
FAIL = "FAIL"
UNREADABLE = "UNREADABLE"
TICKET = "FIR-2672"
CLASSES = ("calls", "imports", "references")

# The `_kin` block the rc0552s stranger received on 0.5.52, verbatim in every
# field the graders read. It must fail the invariant grader or this suite
# guards nothing.
SHIPPED_0552 = {
    "_kin": {
        "completeness": {
            "bound": "exact",
            "classes": {"calls": "present", "imports": "absent", "references": "present"},
            "counted": {"exact": True, "reported": 5, "unit": "referencing_entities"},
            "decided_by": ["calls", "references"],
            "limits": ["edge_coverage:imports_absent"],
            "note": "This answer rested on the calls, references edge class(es), and each was "
                    "observed present, so the counts here are the whole set.",
            "status": "complete",
            "substrate": "edges",
        },
        "verdict": {
            "inputs": {"absence_gate": "certified", "completeness": "certified",
                       "degradations": "not_applicable", "edge_coverage": "certified",
                       "withheld_candidates": "certified"},
            "limiting_factor": None,
            "note": "Every input that could qualify this answer agreed, so the counts here are "
                    "the whole set and an absence in it is authoritative.",
            "safe_to_conclude_absent": False,
            "state": "certified",
        },
    },
    "references": [{}] * 5,
    "relation_kinds": ["calls", "imports", "references"],
}


def tail(text, limit=400):
    text = (text or "").strip()
    return text if len(text) <= limit else "..." + text[-limit:]


def run(cmd, cwd=None, env=None, timeout=600):
    proc = subprocess.run(cmd, cwd=cwd, env=env, timeout=timeout,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
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


# ------------------------------------------------------------------- graders

def verdict_honours_classes(payload):
    """Every requested class the answer could not read makes the verdict
    inconclusive and names itself; every class present certifies.

    Returns (verdict, problems). `verdict` is None when the payload does not
    carry the fields, which is UNREADABLE rather than a finding.
    """
    kin = payload.get("_kin") or {}
    comp = kin.get("completeness") or {}
    verdict = kin.get("verdict") or {}
    classes = comp.get("classes")
    state = verdict.get("state")
    if not isinstance(classes, dict) or state not in ("certified", "inconclusive"):
        return None, ["no completeness.classes map or no verdict state"]
    requested = [c for c in (payload.get("relation_kinds") or list(classes)) if c in classes]
    if not requested:
        return None, ["no requested class is in completeness.classes"]
    short = [c for c in requested if classes.get(c) != "present"]
    problems = []
    limits = comp.get("limits") or []
    counted = comp.get("counted") or {}
    if short:
        if state != "inconclusive":
            problems.append("verdict is %r while %s read %s"
                            % (state, ", ".join(short), [classes[c] for c in short]))
        factor = verdict.get("limiting_factor") or ""
        if not any(c in factor for c in short):
            problems.append("limiting_factor %r names none of %s" % (factor[:120], short))
        if comp.get("status") == "complete":
            problems.append("completeness.status is complete over %s" % short)
        if comp.get("bound") == "exact" or counted.get("exact") is True:
            problems.append("bound/counted.exact claim an exact count over %s" % short)
        if not any(any(l.startswith("edge_coverage:%s_" % c) for c in short) for l in limits):
            problems.append("limits %s name none of %s" % (limits, short))
        if (verdict.get("inputs") or {}).get("edge_coverage") == "certified":
            problems.append("inputs.edge_coverage reads certified over %s" % short)
    else:
        if state != "certified":
            problems.append("every class is present yet the verdict is %r (%s)"
                            % (state, (verdict.get("limiting_factor") or "")[:160]))
    return state, problems


def import_class_never_absent_on_importing_source(payload):
    """On a source whose files import one another the import class is a fact
    about the build (`unproduced`) or a witnessed edge (`present`), never a
    completed observation about the code (`absent`)."""
    classes = ((payload.get("_kin") or {}).get("completeness") or {}).get("classes")
    if not isinstance(classes, dict) or "imports" not in classes:
        return None
    return classes["imports"] in ("unproduced", "present"), classes["imports"]


# Which clause of `limiting_factor` each verdict input is entitled to, by the
# label its reading writes. The absence gate composes its own clauses out of
# every gap it pushed and is not held to one label.
INPUT_CLAUSE_LABELS = {
    "edge_coverage": ("cross_file_edges_", "edge_coverage_unknown"),
    "withheld_candidates": ("withheld_candidates",),
    "degradations": ("retrieval_degraded",),
    "completeness": ("substrate_", "counts_are_a_floor"),
    "response_budget": ("response_bounded",),
}

# The smallest response budget the server serves (`RESPONSE_MIN_MAX_CHARS`).
# Asking for it on a populated answer withholds rows, which is the one refusal
# an acceptance run can add to an answer on purpose.
BUDGET_FLOOR_CHARS = 2000


def factor_clauses(factor):
    """The `label: text` clauses of one limiting factor, in order."""
    clauses = [c.strip() for c in (factor or "").split("; ") if c.strip()]
    return [(c.split(":", 1)[0].strip(), c) for c in clauses]


def factor_carries_every_refusing_input(payload):
    """Every input the verdict records as inconclusive has its clause in
    `limiting_factor`, each label once, and a verdict no input refuses carries
    no clause at all.

    Returns (labels, problems). `labels` is None when the payload carries no
    verdict inputs, which is UNREADABLE rather than a finding.
    """
    verdict = ((payload.get("_kin") or {}).get("verdict") or {})
    inputs = verdict.get("inputs")
    if not isinstance(inputs, dict) or verdict.get("state") not in ("certified", "inconclusive"):
        return None, ["no verdict inputs"]
    labels = [label for label, _ in factor_clauses(verdict.get("limiting_factor"))]
    refusing = [name for name, state in inputs.items() if state == "inconclusive"]
    problems = []
    if refusing and verdict.get("state") != "inconclusive":
        problems.append("inputs %s refuse while the verdict is %r" % (refusing, verdict.get("state")))
    if refusing and not labels:
        problems.append("inputs %s refuse and limiting_factor is empty" % refusing)
    for name in refusing:
        prefixes = INPUT_CLAUSE_LABELS.get(name)
        if prefixes and not any(label.startswith(prefixes) for label in labels):
            problems.append("input %s refuses and no clause of the factor is its (labels %s)"
                            % (name, labels))
    dupes = sorted({label for label in labels if labels.count(label) > 1})
    if dupes:
        problems.append("a label is said twice: %s" % dupes)
    if not refusing and labels:
        problems.append("no input refuses yet the factor reads %r" % labels)
    return labels, problems


GRADERS = {
    "verdict_honours_classes": verdict_honours_classes,
    "import_class_never_absent_on_importing_source": import_class_never_absent_on_importing_source,
    "factor_carries_every_refusing_input": factor_carries_every_refusing_input,
}


# ------------------------------------------------------------------- fixtures

# Three files that reach one another through every class the verdict reads:
# `search.py` and the test import from `parsing.py` (imports), call
# `blank_code` (calls), and use the `Note` class as an annotation and read its
# attributes (references, which a language server resolves). A fixture with
# calls alone reads `references: absent` honestly, and the genuine inverse
# needs every class present.
FILES = {
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
    # The test's name does not contain the focal's name on purpose: the query
    # resolves its focal by name pattern, and a second match would make the
    # focal ambiguous, which is a refusal of its own and not the one under test.
    "tests/test_parsing.py": (
        "from pkg.parsing import Note, blank_code, parse_note\n\n\n"
        "def test_fenced_tags_are_masked():\n"
        "    assert '#nope' not in blank_code('real #tag\\n```\\n#nope\\n```')\n\n\n"
        "def test_parsed_title_is_kept():\n"
        "    note: Note = parse_note('# Alpha\\nbody')\n"
        "    assert note.title == 'Alpha'\n"
    ),
}


class Suite(object):
    def __init__(self, kin, workdir, daemon=None, verbose=False):
        self.kin = kin
        self.workdir = workdir
        self.verbose = verbose
        self.kin_home = os.path.join(workdir, "kin-home-%d" % os.getpid())
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
        self.repo = None
        self.payloads = {}

    def log(self, line):
        if self.verbose:
            print("  " + line, flush=True)

    def git(self, args, cwd):
        base = ["git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false"]
        return run(base + args, cwd=cwd, env=self.env)

    def kin_run(self, args, repo, timeout=600):
        rc, out = run([self.kin] + args, cwd=repo, env=self.env, timeout=timeout)
        self.log("kin %s -> %d" % (" ".join(args), rc))
        return rc, out

    def mcp(self, repo, tool, args, timeout=300):
        env = dict(self.env)
        env["KIN_MCP_REPO"] = repo
        proc = subprocess.Popen([self.kin, "mcp", "start", "--repo", repo],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, cwd=repo, env=env, text=True)
        msgs = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                        "clientInfo": {"name": "kin-verdict-limits-repro", "version": "1"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
             "params": {"name": tool, "arguments": args}},
        ]
        try:
            out, err = proc.communicate("".join(json.dumps(m) + "\n" for m in msgs),
                                        timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            raise RuntimeError("mcp %s timed out after %ss" % (tool, timeout))
        resp = None
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("{"):
                try:
                    obj = json.loads(line)
                except ValueError:
                    continue
                if obj.get("id") == 2:
                    resp = obj
        if resp is None:
            raise RuntimeError("mcp %s returned no id=2 frame (stderr tail: %s)"
                               % (tool, err[-300:].replace("\n", " ")))
        if "error" in resp:
            raise RuntimeError("mcp %s error: %s" % (tool, json.dumps(resp["error"])[:200]))
        content = (resp.get("result") or {}).get("content") or []
        if not content or "text" not in content[0]:
            raise RuntimeError("mcp %s returned no text content" % tool)
        return json.loads(content[0]["text"])

    def fixture(self):
        """A three-file Python package whose files import and call one another,
        admitted through `kin init`, with its enrichment sweep given time."""
        if self.repo:
            return self.repo
        repo = os.path.join(self.workdir, "importing")
        for rel, body in FILES.items():
            path = os.path.join(repo, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as handle:
                handle.write(body)
        rc, out = self.git(["init", "-q", "--initial-branch=main"], repo)
        if rc != 0:
            raise RuntimeError("git init failed: %s" % tail(out))
        self.git(["config", "user.email", "repro@example.invalid"], repo)
        self.git(["config", "user.name", "kin-verdict-limits-repro"], repo)
        self.git(["add", "--all"], repo)
        rc, out = self.git(["commit", "-q", "-m", "a package whose files import one another"], repo)
        if rc != 0:
            raise RuntimeError("git commit failed: %s" % tail(out))
        rc, out = self.kin_run(["init"], repo, timeout=900)
        if rc != 0:
            raise RuntimeError("kin init failed: %s" % tail(out))
        self.repo = repo
        return repo

    def references(self, kinds=None, attempts=10, extra=None):
        """find_references(blank_code), retried while the reference sweep
        settles, because `references` reads short until the language server has
        run and that is a fact about timing rather than about the verdict.
        `extra` adds arguments to the call, such as a response budget."""
        repo = self.fixture()
        key = (tuple(kinds or ()), tuple(sorted((extra or {}).items())))
        if key in self.payloads:
            return self.payloads[key]
        args = {"query": "blank_code"}
        if kinds:
            args["relation_kinds"] = list(kinds)
        args.update(extra or {})
        payload = None
        for attempt in range(attempts):
            self.kin_run(["graph", "status"], repo)
            payload = self.mcp(repo, "find_references", args)
            classes = ((payload.get("_kin") or {}).get("completeness") or {}).get("classes") or {}
            if all(classes.get(c) == "present" for c in classes if c != "imports"):
                break
            time.sleep(4)
        self.payloads[key] = payload
        return payload


# --------------------------------------------------------------------- checks

def check_invariant(suite):
    result = Result("invariant", "the verdict never certifies over a requested class it could "
                                 "not read, and certifies when every class is present")
    try:
        payload = suite.references()
    except Exception as error:  # noqa: BLE001
        result.unknown("find_references(blank_code) unreadable: %s" % error)
        return result
    refs = payload.get("references") or []
    if not refs:
        result.unknown("find_references(blank_code) returned no rows, so the populated-answer "
                       "verdict is not exercised: %s" % tail(json.dumps(payload), 300))
        return result
    state, problems = verdict_honours_classes(payload)
    classes = payload["_kin"]["completeness"].get("classes")
    if state is None:
        result.unknown("; ".join(problems))
    elif problems:
        result.bad("classes=%s verdict=%s: %s" % (json.dumps(classes), state, "; ".join(problems)))
    else:
        result.ok("%d rows, classes=%s, verdict=%s, limiting_factor=%s"
                  % (len(refs), json.dumps(classes), state,
                     (payload["_kin"]["verdict"].get("limiting_factor") or "null")[:90]))
    return result


def check_inverse(suite):
    result = Result("inverse", "an answer with every requested class present certifies cleanly, "
                               "with no limiting factor and an exact count")
    # The genuine inverse first: the default query, on a build whose linker
    # produces import edges, has every requested class present.
    try:
        payload = suite.references()
    except Exception as error:  # noqa: BLE001
        result.unknown("find_references(blank_code) unreadable: %s" % error)
        return result
    classes = ((payload.get("_kin") or {}).get("completeness") or {}).get("classes") or {}
    if classes and all(classes.get(c) == "present" for c in CLASSES if c in classes):
        return grade_inverse(result, payload, "every requested class present")
    # The fallback control on a build whose linker produces no import edge: the
    # same focal over `calls` alone, a class the fixture proves present. It is a
    # control over a class that IS present, not over classes left unrequested
    # by accident, and the detail says which arm ran.
    try:
        payload = suite.references(kinds=("calls",))
    except Exception as error:  # noqa: BLE001
        result.unknown("find_references(blank_code, calls) unreadable: %s" % error)
        return result
    calls_classes = ((payload.get("_kin") or {}).get("completeness") or {}).get("classes") or {}
    if calls_classes.get("calls") != "present":
        result.unknown("the calls class reads %r on the fixture, so no certified control is "
                       "available" % calls_classes.get("calls"))
        return result
    return grade_inverse(result, payload, "control: calls alone, while imports reads %r on this "
                                          "build" % classes.get("imports"))


def grade_inverse(result, payload, arm):
    refs = payload.get("references") or []
    state, problems = verdict_honours_classes(payload)
    kin = payload.get("_kin") or {}
    comp = kin.get("completeness") or {}
    factor = (kin.get("verdict") or {}).get("limiting_factor")
    if state == "certified" and not problems and comp.get("bound") == "exact" and factor is None:
        result.ok("%s: %d rows, certified, limiting_factor null, bound exact" % (arm, len(refs)))
    else:
        result.bad("%s: did not certify cleanly: state=%s limiting_factor=%s bound=%s %s"
                   % (arm, state, (factor or "null")[:120], comp.get("bound"),
                      "; ".join(problems)))
    return result


def check_unproduced(suite):
    result = Result("unproduced", "the import class on an importing source reads unproduced or "
                                  "present, never absent")
    try:
        payload = suite.references()
    except Exception as error:  # noqa: BLE001
        result.unknown("find_references(blank_code) unreadable: %s" % error)
        return result
    graded = import_class_never_absent_on_importing_source(payload)
    if graded is None:
        result.unknown("this build's completeness block carries no imports class")
        return result
    honest, state = graded
    if honest:
        result.ok("imports reads %r on a source whose files import one another" % state)
    else:
        result.bad("imports reads %r on a source whose files import one another; the class was "
                   "never readable on this build, and absent says the code has no such site"
                   % state)
    return result


def check_two_reasons(suite):
    result = Result("two_reasons", "a verdict with more than one reason to refuse names every "
                                   "one of them in its limiting factor, each once")
    # The response budget at the server's floor withholds rows from the
    # populated answer, which downgrades the verdict independently of what the
    # graph holds. Beside an import class this build cannot produce that is two
    # reasons; on a build whose linker produces the class it is one, and the
    # check says which world it graded. Either way every refusing input must
    # keep its clause: the shape this guards against kept the budget's clause
    # and dropped the rest, and one level up the CLI kept the class gap and
    # dropped a dead embedding worker.
    try:
        payload = suite.references(extra={"max_chars": BUDGET_FLOOR_CHARS})
    except Exception as error:  # noqa: BLE001
        result.unknown("find_references(blank_code, max_chars=%d) unreadable: %s"
                       % (BUDGET_FLOOR_CHARS, error))
        return result
    inputs = (((payload.get("_kin") or {}).get("verdict") or {}).get("inputs") or {})
    if inputs.get("response_budget") != "inconclusive":
        result.unknown("the response budget did not withhold rows at max_chars=%d (inputs %s), "
                       "so no second reason was added and nothing was graded"
                       % (BUDGET_FLOOR_CHARS, inputs))
        return result
    labels, problems = factor_carries_every_refusing_input(payload)
    if labels is None:
        result.unknown("the bounded answer carries no verdict inputs")
        return result
    refusing = sorted(name for name, state in inputs.items() if state == "inconclusive")
    if problems:
        result.bad("%s (refusing inputs %s, factor labels %s)"
                   % ("; ".join(problems), refusing, labels))
    else:
        result.ok("%d refusing input(s) %s and the factor carries %s"
                  % (len(refusing), refusing, labels))
    return result


CHECKS = [check_invariant, check_inverse, check_unproduced, check_two_reasons]
DECLARED = ("invariant", "inverse", "unproduced", "two_reasons")


# ------------------------------------------------------------------ self-test

def self_test():
    failures = []
    counted = [0]

    def expect(label, got, want):
        counted[0] += 1
        if got != want:
            failures.append("%s: got %r, wanted %r" % (label, got, want))

    # The shipped 0.5.52 shape must fail, at every field a reader acts on.
    state, problems = verdict_honours_classes(SHIPPED_0552)
    expect("the shipped shape is graded", state, "certified")
    expect("the shipped shape fails", len(problems) >= 5, True)
    expect("the shipped shape's verdict is named", any("verdict is" in p for p in problems), True)
    expect("the shipped shape's exact count is named",
           any("exact" in p for p in problems), True)

    def honest(imports="present", state="certified", factor=None, status="complete",
               bound="exact", limits=None, edge_in="certified"):
        return {
            "_kin": {
                "completeness": {"bound": bound, "status": status,
                                 "classes": {"calls": "present", "imports": imports,
                                             "references": "present"},
                                 "counted": {"exact": bound == "exact", "reported": 5},
                                 "limits": limits or []},
                "verdict": {"state": state, "limiting_factor": factor,
                            "inputs": {"edge_coverage": edge_in}},
            },
            "references": [{}] * 5,
            "relation_kinds": ["calls", "imports", "references"],
        }
    expect("every class present and certified passes", verdict_honours_classes(honest())[1], [])
    fixed = honest(imports="unproduced", state="inconclusive",
                   factor="cross_file_edges_unproduced: this build produced no entity-level "
                          "imports edge for Python", status="partial", bound="at_least",
                   limits=["edge_coverage:imports_unproduced", "verdict_inconclusive"],
                   edge_in="inconclusive")
    expect("the fixed shape passes", verdict_honours_classes(fixed)[1], [])
    expect("a fixed shape whose factor names another class fails",
           len(verdict_honours_classes(dict(fixed, _kin={
               "completeness": fixed["_kin"]["completeness"],
               "verdict": dict(fixed["_kin"]["verdict"], limiting_factor="retrieval_degraded")}))[1]) >= 1,
           True)
    expect("all present but inconclusive fails (no false inconclusive)",
           len(verdict_honours_classes(honest(state="inconclusive", factor="x"))[1]), 1)
    expect("a payload with no classes is unreadable",
           verdict_honours_classes({"_kin": {"verdict": {"state": "certified"}}})[0], None)
    expect("calls-only query reads only calls",
           verdict_honours_classes(dict(honest(imports="absent"),
                                        relation_kinds=["calls"]))[1], [])

    expect("unproduced is honest",
           import_class_never_absent_on_importing_source(honest(imports="unproduced")),
           (True, "unproduced"))
    expect("present is honest",
           import_class_never_absent_on_importing_source(honest()), (True, "present"))
    expect("absent is the shipped wording",
           import_class_never_absent_on_importing_source(SHIPPED_0552), (False, "absent"))
    expect("no imports class is unreadable",
           import_class_never_absent_on_importing_source({"_kin": {}}), None)

    def bounded(inputs, factor):
        return {"_kin": {"verdict": {"state": "inconclusive", "limiting_factor": factor,
                                     "inputs": inputs}}}
    two = {"absence_gate": "inconclusive", "edge_coverage": "inconclusive",
           "withheld_candidates": "certified", "degradations": "certified",
           "completeness": "inconclusive", "response_budget": "inconclusive"}
    full = ("response_bounded: the response budget withheld part of this answer; "
            "cross_file_edges_unproduced: this build produced no entity-level imports edge for "
            "Python; substrate_partial: the coverage classes this answer depended on were not "
            "all observed present (calls, imports, references)")
    expect("every refusing input has its clause",
           factor_carries_every_refusing_input(bounded(two, full))[1], [])
    expect("the factor a budget cut used to replace outright fails twice",
           len(factor_carries_every_refusing_input(bounded(
               two, "response_bounded: the response budget withheld part of this answer"))[1]), 2)
    expect("a factor that kept only the first reading fails on the completeness clause",
           factor_carries_every_refusing_input(bounded(
               two, "response_bounded: x; cross_file_edges_unproduced: y"))[1],
           ["input completeness refuses and no clause of the factor is its (labels "
            "['response_bounded', 'cross_file_edges_unproduced'])"])
    expect("a label said twice fails",
           len(factor_carries_every_refusing_input(bounded(two, full + "; substrate_partial: again"))[1]),
           1)
    expect("a certified verdict with no clause passes",
           factor_carries_every_refusing_input({"_kin": {"verdict": {
               "state": "certified", "limiting_factor": None,
               "inputs": {"edge_coverage": "certified"}}}})[1], [])
    expect("a certified verdict carrying a clause fails",
           len(factor_carries_every_refusing_input({"_kin": {"verdict": {
               "state": "certified", "limiting_factor": "retrieval_degraded: x",
               "inputs": {"edge_coverage": "certified"}}}})[1]), 1)
    expect("no verdict inputs is unreadable", factor_carries_every_refusing_input({})[0], None)

    expect("every declared id has a check",
           tuple(c.__name__.replace("check_", "") for c in CHECKS), DECLARED)

    grade_cases = [(PASS, [(PASS, "a")]), (FAIL, [(PASS, "a"), (FAIL, "b")]),
                   (UNREADABLE, [(PASS, "a"), (UNREADABLE, "b")]), (UNREADABLE, [])]
    for want, entries in grade_cases:
        r = Result("t", "t")
        for status, detail in entries:
            r.asserts.append({"status": status, "detail": detail})
        if r.status != want:
            failures.append("Result.status(%s) = %s, wanted %s" % (entries, r.status, want))

    for failure in failures:
        print("SELFTEST FAIL %s" % failure)
    total = counted[0] + len(grade_cases)
    print("kin-verdict-limits-repro: self-test %d/%d cases" % (total - len(failures), total))
    return 1 if failures else 0


# ----------------------------------------------------------------------- main

def main(argv):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
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
        print("kin-verdict-limits-repro: no kin binary. Pass --kin or set KIN_BIN.")
        return 3
    kin = os.path.abspath(os.path.expanduser(args.kin))
    if not os.path.isfile(kin) or not os.access(kin, os.X_OK):
        print("kin-verdict-limits-repro: %s is not an executable file" % kin)
        return 3
    daemon = args.daemon and os.path.abspath(os.path.expanduser(args.daemon))
    if not daemon:
        beside = os.path.join(os.path.dirname(kin), "kin-daemon")
        daemon = beside if os.path.isfile(beside) else None

    workdir = tempfile.mkdtemp(prefix="kin-verdict-limits-repro-")
    suite = None
    try:
        suite = Suite(kin, workdir, daemon=daemon, verbose=args.verbose)
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
        answered = tuple(r.id for r in results)
        if answered != DECLARED:
            print("kin-verdict-limits-repro: declared %s but %s answered" % (DECLARED, answered))
            return 3
        print("kin-verdict-limits-repro: %d of %d declared checks answered"
              % (len(answered), len(DECLARED)))
        failed = [r for r in results if r.status == FAIL]
        unreadable = [r for r in results if r.status == UNREADABLE]
        print("kin-verdict-limits-repro: %d checks, %d pass, %d FAIL, %d UNREADABLE"
              % (len(results), len(results) - len(failed) - len(unreadable),
                 len(failed), len(unreadable)))
        if args.json_path:
            payload = {"suite": "verdict_limits_repro", "ticket": TICKET, "label": args.label,
                       "kin": kin,
                       "results": [{"id": r.id, "ticket": TICKET, "title": r.title,
                                    "status": r.status, "detail": r.detail, "asserts": r.asserts}
                                   for r in results]}
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
        if suite is not None and suite.repo:
            suite.kin_run(["daemon", "stop"], suite.repo)
        if not args.keep:
            shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
