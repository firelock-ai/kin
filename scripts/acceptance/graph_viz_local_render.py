#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
"""Grade whether `kin graph viz` draws the store it was pointed at, or lies quietly.

What this class is
------------------
`kin graph viz` served `{"nodes": [], "links": [], "unresolved_links": 0}` at
`/api/graph.json` on a repository holding 20,298 entities and 86,814 relations,
at exit 0, with nothing on stdout or stderr saying anything had gone wrong. Two
independent faults produced it, and each on its own is enough to hand a viewer a
blank canvas that looks like a small repository:

  1. The local read addressed `.kin/kindb/graph.kndb`, a file repository-v6
     retired and nothing writes. KinDB answers a path holding no artifacts with a
     valid EMPTY graph and no error, because for an uninitialized namespace that
     is the correct answer, so the wrong path produced a successful nothing.
  2. The daemon read asked `/graph/bootstrap`, an uncapped whole-snapshot export
     measured at 119.6 MiB against the 1.0 MiB a renderer draws on a
     23,098-entity repository, under a 30-second client timeout. It failed
     first, which is what sent the command to fault 1.

An empty answer with a zero exit is the worst possible shape for both. It is
indistinguishable from a genuinely fresh repository, so nobody investigates.

Why this suite runs the binary
------------------------------
A crate test grades the resolver, and that is where the rule belongs. What a
crate test cannot see is the whole path: a real store admitted by the real
import, the real binary started against it, a real HTTP request to the page's
own endpoint, and the real exit status a person or a script would read. Every
fault above lived in the seam between those pieces, and each piece was fine.

What it grades

    CHECK 1 FIR-3498 PASS|FAIL|UNREADABLE the page's payload carries nodes
    CHECK 2 FIR-3498 PASS|FAIL|UNREADABLE the payload reports the population it sampled
    CHECK 3 FIR-3498 PASS|FAIL|UNREADABLE a resolvable-nothing store refuses, non-zero
    CHECK 4 FIR-3498 PASS|FAIL|UNREADABLE that refusal names the directory it read

Checks 3 and 4 are separate because they fail differently. A build that refused
without naming the path reds 4 alone, and that is the failure that matters most:
a refusal nobody can act on sends the reader back to guessing, which is where
this whole class started.
"""

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

TICKET = "FIR-3498"

PASS = "PASS"
FAIL = "FAIL"
UNREADABLE = "UNREADABLE"

CORPUS = {
    "src/lib.rs": (
        "pub fn greeting(name: &str) -> String {\n"
        '    format!("hello {name}")\n'
        "}\n\n"
        "pub fn greet_world() -> String {\n"
        '    greeting("world")\n'
        "}\n"
    ),
    "src/main.rs": (
        "fn main() {\n"
        "    println!(\"{}\", kin_viz_fixture::greet_world());\n"
        "}\n"
    ),
}


class Result:
    def __init__(self, ident, title):
        self.id = ident
        self.title = title
        self.status = UNREADABLE
        self.detail = "not evaluated"
        self.asserts = []

    def ok(self, detail):
        self.status = PASS
        self.detail = detail
        self.asserts.append(detail)

    def bad(self, detail):
        self.status = FAIL
        self.detail = detail
        self.asserts.append(detail)

    def unknown(self, detail):
        self.status = UNREADABLE
        self.detail = detail
        self.asserts.append(detail)


# ── Graders ───────────────────────────────────────────────────────────────────
#
# Pure functions over a payload or a refusal, so `--self-test` can drive each
# against the shape that must flip it. A grader that cannot separate its two
# cases reports a healthy product over a broken one, which is the same defect
# this suite was written for, one level up.


def payload_has_nodes(payload):
    """The page has something to draw.

    Not `payload != {}` and not `"nodes" in payload`: the defect served a
    perfectly well-formed object whose `nodes` was an empty list.
    """
    if not isinstance(payload, dict):
        return False
    nodes = payload.get("nodes")
    return isinstance(nodes, list) and len(nodes) > 0


def payload_reports_population(payload):
    """The payload says what population its nodes were drawn from.

    The export is capped and sampled server side, so a payload carrying only its
    own counts lets the page imply it drew the whole repository. `entity_count`
    is what makes "showing N of M" possible, and it must be at least the number
    of nodes drawn or it is describing some other graph.
    """
    if not isinstance(payload, dict):
        return False
    entity_count = payload.get("entity_count")
    nodes = payload.get("nodes")
    if not isinstance(entity_count, int) or not isinstance(nodes, list):
        return False
    return entity_count >= len(nodes)


def refusal_names_namespace(text, namespace):
    """The refusal names the directory that was read.

    A refusal naming only the repository id tells the reader an identity they
    already knew and not the place it resolved to, which is exactly the gap that
    made the original fault take a source read to diagnose.
    """
    return bool(namespace) and namespace in (text or "")


def refusal_is_nonzero(rc):
    """A refusal exits non-zero.

    Stated as its own grader because the original defect's whole signature was a
    zero exit over a wrong answer: every wrapper, script and eye treats that as
    success.
    """
    return isinstance(rc, int) and rc != 0


GRADERS = {
    "payload_has_nodes": payload_has_nodes,
    "payload_reports_population": payload_reports_population,
    "refusal_is_nonzero": refusal_is_nonzero,
}


# The exact payload the defect served, byte for byte as it was reported.
DEFECT_PAYLOAD = {"nodes": [], "links": [], "unresolved_links": 0}
# A drawn payload in the shape `kin graph viz` served BEFORE this change: nodes
# and links, no population. It must red the population grader alone.
OLD_SHAPE_PAYLOAD = {
    "nodes": [{"id": "a", "name": "alpha", "kind": "Function", "degree": 1}],
    "links": [],
    "unresolved_links": 0,
}
GOOD_PAYLOAD = {
    "root_hash": "abc",
    "seq": 0,
    "entity_count": 20298,
    "relation_count": 86814,
    "unresolved_links": 4,
    "filtered_links": 12,
    "sampled": True,
    "limit": 1400,
    "nodes": [{"id": "a", "name": "alpha", "kind": "Function", "degree": 1}],
    "links": [],
}
# A sample larger than the population it claims to come from is not a smaller
# graph, it is an incoherent one, and it must not read as a healthy payload.
INCOHERENT_PAYLOAD = dict(GOOD_PAYLOAD, entity_count=0)

NAMESPACE = "/tmp/store/.kin/kindb/c2fd2519-1d5a-4292-8511-7e9196accade"
REFUSAL_WITH_PATH = (
    "Error: cannot open repository authority for repository "
    "c2fd2519-1d5a-4292-8511-7e9196accade at "
    "/tmp/store/.kin/kindb/c2fd2519-1d5a-4292-8511-7e9196accade: "
    "local storage authority namespace has no persisted authority record\n"
)
REFUSAL_WITHOUT_PATH = (
    "Error: cannot open repository authority for repository "
    "c2fd2519-1d5a-4292-8511-7e9196accade: no persisted authority record\n"
)


def self_test():
    """Falsify every grader against the input that must flip it."""
    cases = [
        ("payload_has_nodes", True, GOOD_PAYLOAD),
        # The defect itself. If this row ever passes, the grader has stopped
        # being able to see the bug it exists for.
        ("payload_has_nodes", False, DEFECT_PAYLOAD),
        ("payload_has_nodes", True, OLD_SHAPE_PAYLOAD),
        ("payload_has_nodes", False, {}),
        ("payload_has_nodes", False, "not a payload"),
        ("payload_reports_population", True, GOOD_PAYLOAD),
        # The mutation that draws a picture and says nothing about how much of
        # the graph it is. It must red the population grader ALONE, which is why
        # the row above asserts the node grader still passes on this same shape.
        ("payload_reports_population", False, OLD_SHAPE_PAYLOAD),
        ("payload_reports_population", False, INCOHERENT_PAYLOAD),
        ("payload_reports_population", False, DEFECT_PAYLOAD),
        ("refusal_is_nonzero", True, 1),
        ("refusal_is_nonzero", False, 0),
        # A build that never exits has no status, and `run_refusal` reports that
        # as None rather than inventing one. It must not read as a refusal: a
        # server still listening over a namespace that is not there is the
        # regression, not evidence against it.
        ("refusal_is_nonzero", False, None),
    ]
    failures = []
    for name, want, value in cases:
        got = GRADERS[name](value)
        if got != want:
            failures.append("%s(...) = %s, wanted %s" % (name, got, want))

    # The path grader takes two arguments, so it is driven separately rather
    # than bent into the table above.
    path_cases = [
        (True, REFUSAL_WITH_PATH, NAMESPACE),
        # A refusal that names only the identity. This is the shape that shipped
        # before the fix and it must not read as an actionable refusal.
        (False, REFUSAL_WITHOUT_PATH, NAMESPACE),
        (False, "", NAMESPACE),
        (False, REFUSAL_WITH_PATH, ""),
    ]
    for want, text, namespace in path_cases:
        got = refusal_names_namespace(text, namespace)
        if got != want:
            failures.append(
                "refusal_names_namespace(%r, %r) = %s, wanted %s"
                % (text[:40], namespace, got, want)
            )

    # The report this suite writes must load through the gate's own loader, or
    # every CHECK line above it is printed over a report the verdict cannot read.
    sample = Result(1, "a sample check")
    sample.ok("the shape this suite writes")
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import gate  # noqa: E402 - located relative to this file on purpose

    with tempfile.TemporaryDirectory() as scratch:
        written = os.path.join(scratch, "report.json")
        with open(written, "w") as handle:
            json.dump(report_payload([sample], None), handle)
        try:
            loaded = gate.load_report(written)
        except Exception as error:  # noqa: BLE001 - the point is that it must not raise
            failures.append("gate loader refused this suite's own report: %s" % error)
            loaded = None
        if not loaded:
            failures.append("the gate loader read no results from this suite's report")

        # The control. A report keyed the old way must still be refused, or the
        # row above would pass for a loader that accepts anything.
        wrong = os.path.join(scratch, "wrong.json")
        with open(wrong, "w") as handle:
            json.dump({"ticket": TICKET, "checks": [{"id": 1, "status": PASS}]}, handle)
        try:
            gate.load_report(wrong)
            failures.append("the gate loader accepted a report keyed `checks`")
        except Exception:  # noqa: BLE001 - refusing is the expected outcome
            pass

    if failures:
        for line in failures:
            print("SELF-TEST FAIL %s" % line)
        return 1
    print("SELF-TEST PASS %d grader cases" % (len(cases) + len(path_cases)))
    return 0


# ── Harness ───────────────────────────────────────────────────────────────────


def report_payload(results, label):
    """The report shape `scripts/acceptance/gate.py` reads.

    The key is `results`, not `checks`: the gate calls `payload.get("results")`
    and refuses anything else. Five suites have shipped the wrong key; the
    self-test above loads what this returns back through the gate's own loader
    so this is not the sixth.
    """
    return {
        "label": label,
        "ticket": TICKET,
        "results": [
            {
                "id": r.id,
                "title": r.title,
                "status": r.status,
                "detail": r.detail,
                "asserts": r.asserts,
            }
            for r in results
        ],
    }


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def suite_env(home, daemon):
    env = {
        "HOME": str(home),
        "KIN_HOME": str(home),
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "KIN_EMBED_BACKEND": "cpu",
        "KIN_DAEMON_DISABLE_LSP": "1",
        "TERM": "dumb",
    }
    if daemon:
        env["KIN_DAEMON_BIN"] = str(daemon)
    return env


def build_store(kin, env, work):
    """Admit a two-file Rust corpus through the real `kin init`.

    Two functions and a call between them, because the property under test is
    "non-empty" and a corpus that admits nothing would make the defect and the
    fix indistinguishable.
    """
    work.mkdir(parents=True, exist_ok=True)
    for rel, body in CORPUS.items():
        path = work / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)
    (work / "Cargo.toml").write_text(
        '[package]\nname = "kin-viz-fixture"\nversion = "0.0.0"\nedition = "2021"\n'
    )
    hooks = work.parent / "nohooks"
    hooks.mkdir(exist_ok=True)
    for args in (
        ["init", "-q", "--initial-branch=main"],
        ["config", "user.email", "acceptance@example.invalid"],
        ["config", "user.name", "acceptance"],
        ["config", "core.hooksPath", str(hooks)],
        ["config", "commit.gpgsign", "false"],
        ["add", "-A"],
        ["commit", "-q", "-m", "corpus"],
    ):
        subprocess.run(["git", "-C", str(work)] + args, check=True, env=env)
    return subprocess.run(
        [str(kin), "init", "."],
        cwd=str(work),
        env=env,
        capture_output=True,
        text=True,
        timeout=900,
    )


def namespace_of(work):
    """`.kin/kindb/<repository-id>/`, read the way the product resolves it."""
    manifest = json.loads((work / ".kin" / "manifest.json").read_text())
    return work / ".kin" / "kindb" / manifest["repo_id"]


def fetch_payload(kin, env, work, port, timeout=180):
    """Start `kin graph viz`, read `/api/graph.json`, stop it.

    The process is killed in a `finally`: a server left listening would hold the
    port and make the next arm's failure look like a bind error.
    """
    process = subprocess.Popen(
        [str(kin), "graph", "viz", "--port", str(port)],
        cwd=str(work),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    deadline = time.time() + timeout
    try:
        while time.time() < deadline:
            if process.poll() is not None:
                return None, process.communicate()[0], process.returncode
            try:
                with urllib.request.urlopen(
                    "http://127.0.0.1:%d/api/graph.json" % port, timeout=5
                ) as response:
                    return json.loads(response.read().decode("utf-8")), "", 0
            except (urllib.error.URLError, OSError, ValueError):
                time.sleep(0.25)
        return None, "the page never answered within %ds" % timeout, None
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=30)


def run_refusal(kin, env, work, port, timeout=180):
    """Run `kin graph viz` where the namespace cannot be resolved.

    The timeout is caught rather than allowed to propagate, and that is the
    whole reason this is a function. A build carrying the regression this check
    exists for does not exit at all: it binds its listener and serves an empty
    canvas forever. An uncaught `TimeoutExpired` would end the suite in a
    traceback with no CHECK line, which reads as a broken harness rather than as
    the defect it actually is. `None` here is not an exit status, so
    `refusal_is_nonzero` rejects it and the check goes red saying why.
    """
    try:
        got = subprocess.run(
            [str(kin), "graph", "viz", "--port", str(port)],
            cwd=str(work),
            env=dict(env, KIN_ALLOW_DAEMON_BOOTSTRAP_ADMIN="1"),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as expired:
        served = "".join(
            part.decode("utf-8", "replace") if isinstance(part, bytes) else (part or "")
            for part in (expired.stdout, expired.stderr)
        )
        return None, (
            "kin graph viz was still serving after %ds over a namespace that is "
            "not there, so it never refused: %s" % (timeout, served[-400:])
        )
    return got.returncode, got.stdout + got.stderr


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--kin", default=os.environ.get("KIN_BIN"))
    parser.add_argument("--daemon", default=os.environ.get("KIN_DAEMON_BIN"))
    parser.add_argument("--json", dest="json_path", default=None)
    parser.add_argument("--label", default=None)
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--self-test", action="store_true", dest="self_test")
    args = parser.parse_args()

    if args.self_test:
        return self_test()
    if not args.kin or not Path(args.kin).exists():
        print("graph-viz-local-render: no kin binary. Pass --kin or set KIN_BIN.")
        return 3
    kin = Path(args.kin).resolve()
    daemon = Path(args.daemon).resolve() if args.daemon else None

    drawn = Result(1, "the page's payload carries nodes")
    population = Result(2, "the payload reports the population it sampled")
    refuses = Result(3, "an unresolvable store refuses, non-zero")
    names_path = Result(4, "that refusal names the directory it read")
    results = [drawn, population, refuses, names_path]

    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)

        # Arm A: a real store, served, read over HTTP.
        home_a = tmp / "home-a"
        home_a.mkdir()
        work_a = tmp / "work-a"
        env_a = suite_env(home_a, daemon)
        init_a = build_store(kin, env_a, work_a)
        if init_a.returncode != 0:
            note = "kin init failed on the fixture: %s" % (
                (init_a.stdout + init_a.stderr)[-400:]
            )
            drawn.unknown(note)
            population.unknown(note)
        else:
            payload, note, rc = fetch_payload(kin, env_a, work_a, free_port())
            if payload is None:
                note = "no payload from /api/graph.json (exit %r): %s" % (
                    rc,
                    (note or "")[-400:],
                )
                drawn.unknown(note)
                population.unknown(note)
            else:
                node_count = len(payload.get("nodes") or [])
                if payload_has_nodes(payload):
                    drawn.ok("the page carries %d node(s)" % node_count)
                else:
                    drawn.bad(
                        "the page served %d nodes over a store kin init just "
                        "admitted; this is the empty-canvas defect" % node_count
                    )
                if payload_reports_population(payload):
                    population.ok(
                        "%d node(s) drawn out of %s entities"
                        % (node_count, payload.get("entity_count"))
                    )
                else:
                    population.bad(
                        "the payload cannot say how much of the graph it drew: "
                        "entity_count=%r, nodes=%d"
                        % (payload.get("entity_count"), node_count)
                    )

        # Arm B: the same shape of store, with the namespace the resolver names
        # taken away. Nothing about the working tree or the manifest changes, so
        # this is the exact situation the reported failure was in: a manifest
        # naming an identity whose graph the reader cannot reach.
        home_b = tmp / "home-b"
        home_b.mkdir()
        work_b = tmp / "work-b"
        env_b = suite_env(home_b, daemon)
        init_b = build_store(kin, env_b, work_b)
        if init_b.returncode != 0:
            note = "kin init failed on the refusal fixture: %s" % (
                (init_b.stdout + init_b.stderr)[-400:]
            )
            refuses.unknown(note)
            names_path.unknown(note)
        else:
            subprocess.run(
                [str(kin), "daemon", "stop"],
                cwd=str(work_b),
                env=env_b,
                capture_output=True,
                text=True,
            )
            namespace = namespace_of(work_b)
            if not namespace.is_dir():
                note = (
                    "the resolved namespace %s does not exist after a successful "
                    "init, so this arm cannot be identified" % namespace
                )
                refuses.unknown(note)
                names_path.unknown(note)
            else:
                shutil.rmtree(namespace)
                rc, text = run_refusal(kin, env_b, work_b, free_port())
                if refusal_is_nonzero(rc):
                    refuses.ok("exit %d over an unresolvable namespace" % rc)
                else:
                    refuses.bad(
                        "exit %r over a namespace that is not there; a zero exit "
                        "over a wrong answer is the whole defect" % rc
                    )
                if refusal_names_namespace(text, str(namespace)):
                    names_path.ok("the refusal names %s" % namespace)
                else:
                    names_path.bad(
                        "the refusal does not name %s, so a reader cannot act on "
                        "it: %s" % (namespace, text[-400:])
                    )

    for result in results:
        print(
            "CHECK %d %s %s %s" % (result.id, TICKET, result.status, result.detail),
            flush=True,
        )

    if args.json_path:
        with open(args.json_path, "w") as handle:
            json.dump(report_payload(results, args.label), handle, indent=2)

    if any(r.status == FAIL for r in results):
        return 1
    if any(r.status == UNREADABLE for r in results):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
