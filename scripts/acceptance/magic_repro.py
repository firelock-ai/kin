#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
#
# Ported from the kin-ecosystem umbrella's bin/kin-magic-repro on 2026-08-21.
# kin owns this copy from now on, so the suite versions with the product it
# tests and every pull request runs it against its own build. The umbrella copy
# is still what bin/kin-release-preflight and bin/kin-shipped-gate call; until
# those become wrappers around this file, a change to either copy has to be
# reconciled with the other. The CHECK line format, the exit codes, the
# fixtures, and the `kin-magic-repro:` summary-line prefix are what make that
# reconciliation mechanical, and kin-shipped-gate parses two of those summary
# lines by prefix.
"""Falsifiable repro suite for the 2026-08-17 isolation-experiment defects.

Each check builds a fixture, probes the surface the ticket's claim is about, and
prints one line:

    CHECK <id> <ticket> PASS|FAIL|UNREADABLE <detail>

UNREADABLE is a distinct outcome from FAIL and is never reported as a pass: it
means the probe could not be evaluated (no response, a non-JSON payload, a field
whose name the fix has not defined yet). Exit status is 1 when any check FAILs,
2 when none fail but some are UNREADABLE, 0 only when every selected check
passes.

Every check is required to be able to fail. Run the suite against the shipped
0.5.36 binary first: a check that passes there is not testing its defect.
Measured on 0.5.36 (4fd558da), checks 1-9 all FAIL.

Usage:
    python3 scripts/acceptance/magic_repro.py --kin <path-to-kin-binary> [options]

Options:
    --kin PATH        kin binary under test (required)
    --workdir PATH    fixture root (default: a fresh temp dir)
    --label NAME      label recorded in the JSON report
    --only IDS        comma-separated check ids to run (default: all)
    --json PATH       write machine-readable results here
    --tips PATH       record this file's contents in the JSON as the composed set
    --compare PATH    a prior run's --json output; each check is reported against
                      its status there, so a check that passed in that run and
                      fails in this one reads REGRESSION rather than plain FAIL
    --keep            keep fixtures after the run
    --verbose         print every sub-assertion, not just the deciding one

The suite never runs GPU work: KIN_DAEMON_AUTO_EMBED=0 is exported for every
fixture and check 0 asserts the daemon logged the operator opt-out.
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
import time

ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")

PASS = "PASS"
FAIL = "FAIL"
UNREADABLE = "UNREADABLE"

AUTO_EMBED_OPT_OUT_LINE = "background embedding deferred by operator opt-out"

SPINE_REASON = re.compile(r"cross_repo|spine", re.I)
EDGE_GAP_REASON = re.compile(
    r"cross_file_edges_absent|edge_coverage|cross-file|cross_file|enrichment", re.I
)
CROSS_FILE_METRIC = re.compile(
    r"Cross-file entity relations:\s*(\d+)\s+of\s+(\d+)", re.I
)


print = functools.partial(print, flush=True)


def strip_ansi(text):
    return ANSI.sub("", text or "")


def run(cmd, cwd=None, env=None, timeout=600):
    proc = subprocess.run(
        cmd,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )
    return (
        proc.returncode,
        strip_ansi(proc.stdout.decode("utf-8", "replace")),
        strip_ansi(proc.stderr.decode("utf-8", "replace")),
    )


class McpError(Exception):
    pass


class Suite(object):
    def __init__(self, kin, workdir, verbose=False, daemon=None):
        self.kin = kin
        self.daemon = daemon
        self.workdir = workdir
        self.verbose = verbose
        self.fixtures = {}
        self.run_id = "r%d" % os.getpid()
        self.env = dict(os.environ)
        self.env["KIN_DAEMON_AUTO_EMBED"] = "0"
        self.env["KIN_VFS_DISABLE"] = "1"
        self.env.pop("KIN_MCP_REPO", None)
        if daemon:
            self.env["KIN_DAEMON_BIN"] = daemon

    # ---------------------------------------------------------------- plumbing

    def kin_run(self, args, repo, timeout=600):
        return run([self.kin] + args, cwd=repo, env=self.env, timeout=timeout)

    def git(self, args, repo):
        base = ["git", "-c", "core.hooksPath=/dev/null",
                "-c", "user.email=repro@example.invalid",
                "-c", "user.name=kin-magic-repro",
                "-c", "commit.gpgsign=false"]
        return run(base + args, cwd=repo, env=self.env)

    def mcp(self, repo, tool, args, timeout=300):
        """One tools/call over kin's stdio MCP server.

        The MCP path is the surface that applies the negative/completeness
        envelope, so envelope claims are probed here rather than on the raw
        daemon route, which wraps a payload carrying no such envelope.
        """
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
        msgs = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                        "clientInfo": {"name": "kin-magic-repro", "version": "1"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": tool,
             "params": args} if tool.startswith("tools/") else
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
             "params": {"name": tool, "arguments": args}},
        ]
        payload = "".join(json.dumps(m) + "\n" for m in msgs)
        try:
            out, err = proc.communicate(payload, timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            raise McpError("mcp %s timed out after %ss" % (tool, timeout))
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
            raise McpError("mcp %s returned no id=2 frame (stderr tail: %s)"
                           % (tool, strip_ansi(err)[-200:].replace("\n", " ")))
        if "error" in resp:
            raise McpError("mcp %s error: %s" % (tool, json.dumps(resp["error"])[:200]))
        result = resp.get("result") or {}
        if tool.startswith("tools/"):
            return result, len(json.dumps(result))
        content = result.get("content") or []
        if not content or "text" not in content[0]:
            raise McpError("mcp %s returned no text content" % tool)
        text = content[0]["text"]
        try:
            payload = json.loads(text)
        except ValueError:
            raise McpError("mcp %s%s payload is not JSON (first 160 chars: %r)"
                           % (tool, " isError" if result.get("isError") else "",
                              text[:160]))
        if result.get("isError") and not isinstance(payload, dict):
            raise McpError("mcp %s isError with a non-object payload" % tool)
        return payload, len(text)

    # ---------------------------------------------------------------- fixtures

    def fixture(self, name):
        if name not in self.fixtures:
            path = os.path.join(self.workdir, "%s-%s" % (name, self.run_id))
            attempt = 0
            while os.path.exists(path):
                attempt += 1
                path = os.path.join(self.workdir,
                                    "%s-%s-%d" % (name, self.run_id, attempt))
            os.makedirs(path)
            getattr(self, "_build_" + name)(path)
            self.fixtures[name] = path
        return self.fixtures[name]

    def shutdown(self):
        """Stop the per-fixture daemons this run started.

        Each fixture is a fresh repository, so its daemon has nothing to serve
        once the run ends; leaving them alive leaks one process per fixture per
        run and holds the fixture's files against removal.
        """
        stopped = []
        for path in self.fixtures.values():
            pid_file = os.path.join(path, ".kin", "daemon.pid")
            if not os.path.exists(pid_file):
                continue
            try:
                with open(pid_file) as handle:
                    pid = int(handle.read().strip())
                os.kill(pid, 15)
                stopped.append(pid)
            except (ValueError, OSError):
                continue
        return stopped

    def _write(self, repo, rel, text):
        full = os.path.join(repo, rel)
        parent = os.path.dirname(full)
        if parent and not os.path.isdir(parent):
            os.makedirs(parent)
        with open(full, "w") as handle:
            handle.write(text)

    def _kin_init(self, repo):
        rc, out, err = self.kin_run(["init", "."], repo)
        if rc != 0:
            raise RuntimeError("kin init failed in %s: %s" % (repo, (err or out)[-300:]))

    def _kin_commit(self, repo, message):
        rc, out, err = self.kin_run(["commit", "-m", message], repo)
        if rc != 0:
            raise RuntimeError("kin commit failed in %s: %s" % (repo, (err or out)[-300:]))

    def _build_incremental(self, repo):
        """The greenfield shape: modules written and committed one at a time.

        This is the ingestion path the isolation session used, and it is the
        path FIR-2354 is about. The same sources bulk-converted through git DO
        get cross-file edges, so the fixture must not be built in bulk.
        """
        self.git(["init", "-q", "."], repo)
        self._write(repo, ".gitignore", "*.db\n__pycache__/\n")
        self._write(repo, "pyproject.toml",
                    '[project]\nname = "nk"\nversion = "0.1.0"\n\n'
                    '[project.scripts]\nnk = "pkg.cli:main"\n')
        self._write(repo, "pkg/__init__.py", "")
        self._write(repo, "pkg/parsing.py", PARSING_PY)
        self._kin_init(repo)
        self._kin_commit(repo, "Add parsing module")
        self._write(repo, "pkg/storage.py", STORAGE_PY)
        self._kin_commit(repo, "Add storage module")
        self._write(repo, "pkg/linkgraph.py", LINKGRAPH_PY)
        self._kin_commit(repo, "Add link graph module")
        self._write(repo, "pkg/cli.py", CLI_PY)
        self._kin_commit(repo, "Add CLI entry point")

    def _build_converted(self, repo):
        """The brownfield shape: a git history converted by kin init.

        FIR-2360's false edges were observed on a conversion, so the precision
        fixture uses the path that emits cross-file edges at all.
        """
        self.git(["init", "-q", "."], repo)
        self._write(repo, ".gitignore", "__pycache__/\n")
        self._write(repo, "app/__init__.py", "")
        self._write(repo, "app/adapter.py", ADAPTER_PY)
        self._write(repo, "app/session.py", SESSION_PY)
        self._write(repo, "app/pipeline.py", PIPELINE_PY)
        self._write(repo, "tests/test_session.py", TEST_SESSION_PY)
        self.git(["add", "-A"], repo)
        rc, out, err = self.git(["commit", "-q", "-m", "initial fixture"], repo)
        if rc != 0:
            raise RuntimeError("git commit failed: %s" % (err or out)[-300:])
        self._kin_init(repo)

    def _build_js(self, repo):
        self.git(["init", "-q", "."], repo)
        self._write(repo, ".gitignore", "node_modules/\n")
        self._write(repo, "lib/router.js", ROUTER_JS)
        self._write(repo, "lib/app.js", APP_JS)
        self.git(["add", "-A"], repo)
        rc, out, err = self.git(["commit", "-q", "-m", "initial js fixture"], repo)
        if rc != 0:
            raise RuntimeError("git commit failed: %s" % (err or out)[-300:])
        self._kin_init(repo)

    def _build_venv(self, repo):
        self.git(["init", "-q", "."], repo)
        self._write(repo, ".gitignore", "*.log\n")
        self._write(repo, "tool.py", "def run():\n    return \"ok\"\n")
        self._kin_init(repo)
        self._kin_commit(repo, "Add tool module")

    # ------------------------------------------------------------ status probes

    def graph_status(self, repo):
        rc, out, err = self.kin_run(["graph", "status"], repo)
        text = out + "\n" + err
        info = {"raw": text, "rc": rc, "entities": None, "relations": None,
                "files": None, "relation_kinds": {}, "kinds": {}, "cross_file": None}
        head = re.search(r"Entities:\s*(\d+).*?relations:\s*(\d+).*?Files:\s*(\d+)", text)
        if head:
            info["entities"] = int(head.group(1))
            info["relations"] = int(head.group(2))
            info["files"] = int(head.group(3))
        kinds = re.search(r"Entity-to-entity relation kinds:\s*(.*)", text)
        if kinds:
            for part in kinds.group(1).split(","):
                bits = part.strip().split(":")
                if len(bits) == 2 and bits[1].strip().isdigit():
                    info["relation_kinds"][bits[0].strip()] = int(bits[1].strip())
        ekinds = re.search(r"^Kinds:\s*(.*)$", text, re.M)
        if ekinds:
            for part in ekinds.group(1).split(","):
                bits = part.strip().split(":")
                if len(bits) == 2 and bits[1].strip().isdigit():
                    info["kinds"][bits[0].strip()] = int(bits[1].strip())
        metric = CROSS_FILE_METRIC.search(text)
        if metric:
            info["cross_file"] = (int(metric.group(1)), int(metric.group(2)))
        if info["entities"] is None:
            raise McpError("kin graph status rc=%d printed no counters: %s"
                           % (rc, text.strip()[-200:]))
        return info

    def search_entities(self, repo, query):
        rc, out, err = self.kin_run(["search", query], repo)
        rows = []
        for line in (out + "\n" + err).splitlines():
            match = re.match(r"\s+(.+?)\s+\((\w+),\s*(\w+)\)\s+-\s+(.+?)\s*$", line)
            if match and "fallback" not in line:
                rows.append({"name": match.group(1), "kind": match.group(2),
                             "language": match.group(3), "file": match.group(4)})
        return rows

    def inspect(self, repo, name):
        rc, out, err = self.kin_run(["graph", "inspect", name], repo)
        text = out + "\n" + err
        if rc != 0:
            return None
        rels = []
        for line in text.splitlines():
            match = re.match(
                r"\s*(<-|->)\s+(\w+)\s+(.+?)\s+\[(\w+)\]\s+\((.+?);", line)
            if match:
                rels.append({"dir": "in" if match.group(1) == "<-" else "out",
                             "relation": match.group(2), "name": match.group(3),
                             "kind": match.group(4), "file": match.group(5)})
        return {"raw": text, "relations": rels}

    def dead_code(self, repo):
        rc, out, err = self.kin_run(["dead-code"], repo)
        text = out + "\n" + err
        rows = []
        for line in text.splitlines():
            match = re.match(r"\s+(\S+)\s+\((\w+),\s*(\w+)\)\s+-\s+(.+?)\s*$", line)
            if match:
                rows.append({"name": match.group(1), "kind": match.group(2),
                             "file": match.group(4)})
        return {"raw": text, "rows": rows, "rc": rc}

    def references(self, repo, query, settle=2):
        """find_references, retried once while the graph settles.

        A commit's enrichment lands asynchronously, so a probe fired
        immediately after the last fixture commit can hit a graph that has not
        resolved the symbol yet. The retry is bounded and a symbol that never
        resolves still reports unresolved rather than absent.
        """
        payload, _ = self.mcp(repo, "find_references", {"query": query})
        if (payload.get("focal_entity") or {}).get("id"):
            return payload
        time.sleep(settle)
        payload, _ = self.mcp(repo, "find_references", {"query": query})
        return payload


# ----------------------------------------------------------------- fixture code

PARSING_PY = '''import re

TAG_RE = re.compile(r"(?<![\\w#])#([A-Za-z][\\w/-]*)")


def normalize_title(title):
    return title.strip().lower()


def strip_code(text):
    return text.replace("`", "")


def extract_tags(text):
    return TAG_RE.findall(strip_code(text))


def extract_links(text):
    return [normalize_title(part) for part in text.split("|")]


def parse_note(text, path):
    return {"path": str(path), "tags": extract_tags(text), "links": extract_links(text)}
'''

STORAGE_PY = '''from .parsing import parse_note, normalize_title


class Database:
    def __init__(self, path):
        self.path = path
        self.notes = {}

    def ingest_note(self, note):
        key = normalize_title(note["path"])
        self.notes[key] = note
        return normalize_title(key)

    def ingest_dir(self, root):
        for name, text in root.items():
            self.ingest_note(parse_note(text, name))
        return len(self.notes)

    def all_notes(self):
        return list(self.notes.values())
'''

LINKGRAPH_PY = '''from .parsing import normalize_title
from .storage import Database


class LinkGraph:
    def __init__(self, edges):
        self.edges = edges

    @staticmethod
    def from_db(db: Database):
        edges = {}
        for note in db.all_notes():
            edges[normalize_title(note["path"])] = [normalize_title(link)
                                                    for link in note["links"]]
        return LinkGraph(edges)

    def backlinks(self, title):
        return [src for src, dsts in self.edges.items() if title in dsts]
'''

CLI_PY = '''from .linkgraph import LinkGraph
from .storage import Database


def main():
    db = Database(":memory:")
    db.ingest_dir({"a.md": "hello #tag b|c"})
    return LinkGraph.from_db(db).backlinks("b")
'''

ADAPTER_PY = '''class Adapter:
    def send(self, request):
        return {"ok": True, "request": request}

    def close(self):
        return None
'''

SESSION_PY = '''from .adapter import Adapter


class Session:
    def __init__(self):
        self.adapter = Adapter()

    def send(self, request):
        return self.adapter.send(request)

    def request(self, url):
        return self.send({"url": url})

    def shutdown(self):
        return self.adapter.close()

    def drain(self, thing):
        return thing.close()
'''

PIPELINE_PY = '''from .session import Session


def run_all(session: Session):
    session.request("a")
    session.send({"url": "b"})
    session.shutdown()
    session.drain(session.adapter)
    return True
'''

TEST_SESSION_PY = '''from app.session import Session


class FakeAdapter:
    def send(self, request):
        return {"ok": False, "request": request}

    def close(self):
        return None


def test_session_send():
    session = Session()
    session.adapter = FakeAdapter()
    assert session.send({"url": "u"})["ok"] is False
'''

ROUTER_JS = '''class Router {
  constructor(options) {
    this.options = options || {};
    this.stack = [];
  }

  use(fn) {
    this.stack.push(fn);
    return this;
  }

  handle(req) {
    return this.stack.map((fn) => fn(req));
  }
}

function Layer(path) {
  this.path = path;
}

Layer.prototype.match = function match(candidate) {
  return this.path === candidate;
};

Layer.prototype.describe = function describe() {
  return "layer:" + this.path;
};

const helpers = {
  normalize(path) {
    return String(path).toLowerCase();
  },
  join: function join(a, b) {
    return helpers.normalize(a) + "/" + helpers.normalize(b);
  },
};

const compose = (first, second) => (value) => second(first(value));

module.exports = { Router, Layer, helpers, compose };
'''

APP_JS = '''const { Router, helpers } = require("./router");

class Application {
  constructor() {
    this.router = new Router({});
  }

  mount(fn) {
    this.router.use(fn);
    return this;
  }

  route(path) {
    return helpers.normalize(path);
  }
}

module.exports = { Application };
'''


# ------------------------------------------------------------------- assertions

def resolution_miss(payload, query):
    """A payload whose focal entity never resolved answers nothing.

    An unresolved symbol and a symbol with no references are different facts
    and the second must never be inferred from the first.
    """
    if (payload.get("focal_entity") or {}).get("id"):
        return None
    negative = payload.get("negative") or {}
    return "find_references(%s) resolved no focal entity (%s)" % (
        query, negative.get("kind") or negative.get("subject") or "no reason given")


def trend_of(status, prior):
    """Where this check moved since the run being compared against.

    A prior run that could not be read reports `unknown` rather than `same`,
    because "no baseline" and "no change" are different facts and the second
    must never be inferred from the first.
    """
    if prior is None:
        return "unknown"
    if prior == PASS and status != PASS:
        return "regression"
    if prior != PASS and status == PASS:
        return "fixed"
    return "same"


class Result(object):
    def __init__(self, check_id, ticket, title):
        self.id = check_id
        self.ticket = ticket
        self.title = title
        self.prior = None
        self.trend = "unknown"
        self.asserts = []

    def add(self, status, detail):
        self.asserts.append({"status": status, "detail": detail})

    def ok(self, detail):
        self.add(PASS, detail)

    def bad(self, detail):
        self.add(FAIL, detail)

    def unknown(self, detail):
        self.add(UNREADABLE, detail)

    @property
    def status(self):
        if any(a["status"] == FAIL for a in self.asserts):
            return FAIL
        if any(a["status"] == UNREADABLE for a in self.asserts):
            return UNREADABLE
        if not self.asserts:
            return UNREADABLE
        return PASS

    @property
    def detail(self):
        for wanted in (FAIL, UNREADABLE):
            for a in self.asserts:
                if a["status"] == wanted:
                    return a["detail"]
        return self.asserts[-1]["detail"]


# ---------------------------------------------------------------------- checks

def check_0(suite):
    """The GPU opt-out is honored, so no check in this suite runs inference."""
    res = Result("0", "GPU-OPTOUT", "auto-embed deferred by operator opt-out")
    repo = suite.fixture("incremental")
    log = os.path.join(repo, ".kin", "daemon.log")
    if not os.path.exists(log):
        res.unknown("no daemon log at %s, cannot confirm the opt-out was honored" % log)
        return res
    deferred = 0
    with open(log, errors="replace") as handle:
        for line in handle:
            if AUTO_EMBED_OPT_OUT_LINE in strip_ansi(line):
                deferred += 1
    pid_file = os.path.join(repo, ".kin", "daemon.pid")
    served = None
    if os.path.exists(pid_file):
        try:
            with open(pid_file) as handle:
                pid = handle.read().strip()
            # /proc/<pid>/exe is the only read that returns the executable's
            # real path on Linux. `ps -o comm=` there is the bare process name
            # truncated to fifteen characters, so comparing it with an absolute
            # path is a check that can never pass; it only ever worked on
            # macOS, where comm carries the full path. The first Linux-leg run
            # of this suite (2026-08-19) failed exactly that way.
            exe_link = "/proc/%s/exe" % pid
            if os.path.exists(exe_link):
                try:
                    served = os.readlink(exe_link)
                except OSError:
                    served = None
            else:
                prc, pout, _perr = run(["ps", "-p", pid, "-o", "comm="], timeout=30)
                served = pout.strip() if prc == 0 else None
        except (OSError, ValueError):
            served = None
    if served is None:
        res.unknown("could not resolve which kin-daemon binary served the fixture")
    elif suite.daemon and os.path.realpath(served) != os.path.realpath(suite.daemon):
        res.bad("fixture served by %s, not the requested %s" % (served, suite.daemon))
    else:
        res.ok("fixture served by %s" % served)
    status = suite.graph_status(repo)
    indexed = re.search(r"Embeddings:\s*(\d+)/(\d+)\s*indexed", status["raw"])
    if deferred == 0:
        res.bad("daemon log carries no %r line; embeddings may have run"
                % AUTO_EMBED_OPT_OUT_LINE)
    else:
        res.ok("daemon logged the opt-out %d time(s)" % deferred)
    if indexed and int(indexed.group(1)) != 0:
        res.bad("embeddings indexed=%s despite the opt-out" % indexed.group(1))
    elif indexed:
        res.ok("embeddings indexed=0/%s" % indexed.group(2))
    return res


def check_1(suite):
    """FIR-2354: the incremental path must produce cross-file edges."""
    res = Result("1", "FIR-2354", "cross-file edges on the incremental commit path")
    repo = suite.fixture("incremental")
    status = suite.graph_status(repo)
    kinds = status["relation_kinds"]
    if status["cross_file"] is not None:
        seen, total = status["cross_file"]
        if seen > 0:
            res.ok("graph status reports %d of %d relations cross-file" % (seen, total))
        else:
            res.bad("graph status reports 0 of %d relations cross-file" % total)
    elif "Imports" in kinds and kinds["Imports"] > 0:
        res.ok("relation kinds carry Imports: %d" % kinds["Imports"])
    else:
        res.bad("relation kinds are %s: no Imports kind and no cross-file metric"
                % (kinds or "{}"))
    try:
        payload = suite.references(repo, "parse_note")
    except McpError as exc:
        res.unknown("find_references(parse_note) unreadable: %s" % exc)
        return res
    miss = resolution_miss(payload, "parse_note")
    if miss:
        res.unknown(miss)
        return res
    files = sorted({r.get("file_path") for r in payload.get("references") or []})
    if any(f and f.endswith("storage.py") for f in files):
        res.ok("find_references(parse_note) crosses into storage.py")
    else:
        res.bad("find_references(parse_note) returned %d reference(s) %s; "
                "storage.py imports and calls it"
                % (len(payload.get("references") or []), files))
    return res


def check_2(suite):
    """FIR-2353: an empty absence may never be authoritative, and its reason
    must name the limiting factor rather than a cross-repo spine mismatch."""
    res = Result("2", "FIR-2353", "absence authority on an empty find_references")
    repo = suite.fixture("incremental")
    try:
        payload = suite.references(repo, "parse_note")
    except McpError as exc:
        res.unknown("find_references(parse_note) unreadable: %s" % exc)
        return res
    miss = resolution_miss(payload, "parse_note")
    if miss:
        res.unknown(miss)
        return res
    refs = payload.get("references") or []
    if refs:
        res.ok("references returned (%d), so the absence path is not exercised"
               % len(refs))
        return res
    negative = payload.get("negative")
    if not isinstance(negative, dict):
        res.bad("empty result carries no negative object at all")
        return res
    safe = negative.get("safe_to_conclude_absent")
    trust = negative.get("trust")
    reason = negative.get("trust_reason") or ""
    if safe is True or trust == "authoritative":
        res.bad("empty result claims safe_to_conclude_absent=%r trust=%r on a graph "
                "holding no cross-file edges" % (safe, trust))
        return res
    res.ok("safe_to_conclude_absent=%r trust=%r" % (safe, trust))
    leading = reason.split(":", 1)[0].strip()
    if EDGE_GAP_REASON.search(leading):
        res.ok("trust_reason leads with the edge gap: %s" % leading)
    elif SPINE_REASON.search(leading):
        res.bad("trust_reason leads with %r, a cross-repo/spine cause, for a cross-file "
                "edge gap: %s" % (leading, reason[:200]))
    else:
        res.bad("trust_reason does not lead with the limiting factor: %s"
                % (reason[:200] or "(empty)"))
    return res


def check_3(suite):
    """FIR-2357: a partial answer must say it is partial.

    normalize_title has five call sites across three files in the fixture:
    extract_links (parsing), ingest_note twice (storage), from_db twice
    (linkgraph).
    """
    res = Result("3", "FIR-2357", "completeness signal on a partial find_references")
    repo = suite.fixture("incremental")
    try:
        payload = suite.references(repo, "normalize_title")
    except McpError as exc:
        res.unknown("find_references(normalize_title) unreadable: %s" % exc)
        return res
    miss = resolution_miss(payload, "normalize_title")
    if miss:
        res.unknown(miss)
        return res
    refs = payload.get("references") or []
    files = sorted({r.get("file_path") for r in refs if r.get("file_path")})
    expected_files = {"pkg/parsing.py", "pkg/storage.py", "pkg/linkgraph.py"}
    if expected_files.issubset(set(files)):
        res.ok("all three calling files returned: %s" % files)
        return res
    signal = None
    for key in ("completeness", "edge_coverage"):
        if isinstance(payload.get(key), dict):
            signal = key
            break
    if signal is None and isinstance(payload.get("negative"), dict):
        signal = "negative"
    if signal is None:
        res.bad("partial answer (%d ref(s) from %s, ground truth 5 sites in 3 files) "
                "carries no completeness signal" % (len(refs), files))
        return res
    res.ok("partial answer carries a %r signal" % signal)
    marked = json.dumps(payload.get(signal))
    if re.search(r"absent|partial|incomplete|unknown|false", marked, re.I):
        res.ok("%s marks the answer partial" % signal)
    else:
        res.bad("%s is present but marks nothing partial: %s" % (signal, marked[:160]))
    return res


def check_4(suite):
    """FIR-2356: dead-code must not contradict find_references, must not list a
    declared entry point, and must label rows when coverage is incomplete."""
    res = Result("4", "FIR-2356", "dead-code delete list against real references")
    repo = suite.fixture("incremental")
    dead = suite.dead_code(repo)
    names = [row["name"] for row in dead["rows"]]
    if "main" in names:
        res.bad("dead-code lists 'main', the declared console entry point in pyproject.toml")
    else:
        res.ok("dead-code does not list the declared entry point")
    contradictions = []
    unreadable = []
    for name in names:
        try:
            payload = suite.references(repo, name)
        except McpError as exc:
            unreadable.append("%s (%s)" % (name, exc))
            continue
        if resolution_miss(payload, name):
            unreadable.append("%s (unresolved)" % name)
            continue
        if payload.get("references"):
            callers = ", ".join(sorted({r.get("name", "?")
                                        for r in payload["references"]})[:3])
            contradictions.append("%s <- %s" % (name, callers))
    if contradictions:
        res.bad("dead-code lists %d entit(ies) find_references says have callers: %s"
                % (len(contradictions), "; ".join(contradictions[:4])))
    elif unreadable:
        res.unknown("could not read references for %d listed entit(ies): %s"
                    % (len(unreadable), unreadable[0]))
    else:
        res.ok("no listed entity has references (%d listed)" % len(names))
    status = suite.graph_status(repo)
    # The cross-file metric is the authority on whether this graph is missing the
    # edge class the delete list rests on. The absence of an `Imports` relation
    # kind is only a proxy for that, and a linker that resolves cross-file calls
    # without minting a separate Imports kind makes the proxy wrong: a graph
    # reporting 8 of 21 relations cross-file is not missing cross-file edges, so
    # demanding an incompleteness label on it asks the tool to disclose a gap it
    # does not have. Read the metric when it exists; fall back to the proxy only
    # when nothing reports coverage at all.
    if status["cross_file"] is not None:
        incomplete = status["cross_file"][0] == 0
        basis = "graph status reports %d of %d relations cross-file" % status["cross_file"]
    else:
        incomplete = "Imports" not in status["relation_kinds"]
        basis = "no cross-file metric, and relation kinds are %s" % (
            status["relation_kinds"] or "{}")
    labeled = re.search(r"unverified|not verified|incomplete|coverage", dead["raw"], re.I)
    if names and incomplete and not labeled:
        res.bad("delete list printed with no unverified/coverage label although %s"
                % basis)
    elif names and incomplete:
        res.ok("delete list is labeled for incomplete coverage (%s)" % basis)
    else:
        res.ok("coverage is not reported incomplete (%s)" % basis)
    return res


def check_5(suite):
    """FIR-2360: a call edge must not resolve a production call site onto a test
    double, and a genuinely ambiguous receiver must be marked name-only."""
    res = Result("5", "FIR-2360", "call-edge precision against a test double")
    repo = suite.fixture("converted")
    sends = suite.inspect(repo, "Session.send")
    if sends is None:
        res.unknown("kin graph inspect Session.send did not resolve")
        return res
    false_edges = [r for r in sends["relations"]
                   if r["dir"] == "out" and r["relation"] == "Calls"
                   and r["file"].startswith("tests/")]
    if false_edges:
        res.bad("Session.send -> %s: a production call site resolved onto a test double"
                % ", ".join(r["name"] for r in false_edges))
    else:
        res.ok("Session.send has no outgoing Calls edge into tests/")
    try:
        payload = suite.references(repo, "Adapter.send")
    except McpError as exc:
        res.unknown("find_references(Adapter.send) unreadable: %s" % exc)
        return res
    miss = resolution_miss(payload, "Adapter.send")
    if miss:
        res.unknown(miss)
        return res
    test_callers = [r for r in payload.get("references") or []
                    if (r.get("file_path") or "").startswith("tests/")]
    if test_callers:
        res.bad("Adapter.send claims caller(s) %s; the test calls Session.send"
                % ", ".join(r.get("name", "?") for r in test_callers))
    else:
        res.ok("Adapter.send claims no test caller")
    drain = suite.inspect(repo, "Session.drain")
    if drain is None:
        res.unknown("kin graph inspect Session.drain did not resolve")
        return res
    candidates = [r for r in drain["relations"]
                  if r["dir"] == "out" and r["relation"] == "Calls"]
    if len(candidates) <= 1:
        res.ok("the ambiguous receiver in Session.drain produced %d edge(s)"
               % len(candidates))
        return res
    marker = re.search(r"name[_ -]?only|name_match|resolution", drain["raw"], re.I)
    if marker:
        res.ok("ambiguous candidates carry a resolution marker: %s" % marker.group(0))
    else:
        res.unknown("Session.drain fans out to %d candidates with no confidence "
                    "marker; pending FIR-2360 field name"
                    % len(candidates))
    return res


def check_6(suite):
    """FIR-2361: a shape query must be cheap, and truncation must say where."""
    res = Result("6", "FIR-2361", "trace_data_flow compact mode and localized truncation")
    repo = suite.fixture("converted")
    try:
        tools, _ = suite.mcp(repo, "tools/list", {})
    except McpError as exc:
        res.unknown("tools/list unreadable: %s" % exc)
        return res
    schema = None
    for tool in tools.get("tools") or []:
        if tool.get("name") == "trace_data_flow":
            schema = (tool.get("inputSchema") or {}).get("properties") or {}
    if schema is None:
        res.unknown("trace_data_flow absent from tools/list")
        return res
    knob = None
    for candidate in ("include_body", "compact"):
        if candidate in schema:
            knob = candidate
            break
    if knob is None:
        res.bad("trace_data_flow declares no compact/include_body parameter: %s"
                % sorted(schema.keys()))
    else:
        res.ok("trace_data_flow declares %r" % knob)
    base_args = {"focal": "run_all", "direction": "calls", "depth": 3,
                 "limit_per_step": 25}
    try:
        full, full_size = suite.mcp(repo, "trace_data_flow", dict(base_args))
        if not (full.get("chain") or []):
            # Same settle race find_references has: enrichment from the fixture's
            # last commit lands asynchronously, so a trace fired immediately can
            # walk a graph that has not linked the focal yet. Bounded, and an
            # empty chain after it still reports vacuous rather than passing.
            time.sleep(3)
            full, full_size = suite.mcp(repo, "trace_data_flow", dict(base_args))
    except McpError as exc:
        res.unknown("trace_data_flow (full) unreadable: %s" % exc)
        return res
    full_steps = len(full.get("chain") or [])
    if knob and full_steps == 0:
        # Two empty responses are the same size, and reading that as "the flag
        # saved nothing" convicts the tool of a defect the run never tested.
        res.unknown("the full trace returned no steps for %r, so the shape-query "
                    "comparison is vacuous" % base_args["focal"])
    elif knob:
        args = dict(base_args)
        args[knob] = False if knob == "include_body" else True
        try:
            compact, compact_size = suite.mcp(repo, "trace_data_flow", args)
        except McpError as exc:
            res.unknown("trace_data_flow (%s) unreadable: %s" % (knob, exc))
            return res
        bodies = [step for step in compact.get("chain") or []
                  if (step.get("entity") or {}).get("body")]
        budget = compact.get("max_response_chars")
        if bodies:
            res.bad("%s honored nothing: %d step(s) still inline a body"
                    % (knob, len(bodies)))
        elif compact_size >= full_size:
            res.bad("%s response is %d chars against %d full: it saved nothing"
                    % (knob, compact_size, full_size))
        elif isinstance(budget, int) and compact_size > budget:
            res.bad("%s response is %d chars against the %d the tool declares as its "
                    "own budget" % (knob, compact_size, budget))
        else:
            # Deliberately not a ratio. A ratio measures how much of THIS fixture
            # was body text, and on a fixture whose bodies are two lines each it
            # fails a correct implementation for having little to strip. What the
            # contract actually asks is that a shape query carries no bodies and
            # stays inside the budget the tool publishes, both of which are
            # properties of the tool rather than of the fixture.
            res.ok("%s response carries no bodies, %d chars against %d full%s"
                   % (knob, compact_size, full_size,
                      "" if budget is None else " and a %d budget" % budget))
    cut_args = {"focal": "run_all", "direction": "calls", "depth": 3,
                "limit_per_step": 1}
    try:
        cut, _ = suite.mcp(repo, "trace_data_flow", cut_args)
    except McpError as exc:
        res.unknown("trace_data_flow (truncating) unreadable: %s" % exc)
        return res
    if not cut.get("truncated"):
        res.unknown("limit_per_step=1 did not truncate on this fixture; "
                    "per-step localization is untested")
        return res
    localized = False
    for step in cut.get("chain") or []:
        for key in step:
            if "truncat" in key.lower() or "dropped" in key.lower():
                localized = True
    if localized:
        res.ok("truncation is localized per step")
    else:
        res.bad("truncated=true is reported only at the top level; no step says "
                "which fan-out was clipped or how many were dropped")
    return res


def check_7(suite):
    """FIR-2362: the JavaScript adapter must model structure, not just symbols.

    Floor derivation from this fixture: 15 entities, 10 Contains edges (Router 3,
    Application 3, Layer 2 prototype methods, helpers 2 object-literal methods),
    and at least 3 Calls (Application.constructor -> Router,
    Application.route -> helpers.normalize, helpers.join -> helpers.normalize),
    so 13 over 15 is 0.86 and the floor sits at 0.85. Shipped 0.5.36 delivers
    0.50.
    """
    res = Result("7", "FIR-2362", "JavaScript entity kinds, Contains edges, edge density")
    repo = suite.fixture("js")
    status = suite.graph_status(repo)
    kinds = status["kinds"]
    rel_kinds = status["relation_kinds"]
    if kinds.get("Class", 0) >= 2 and kinds.get("Method", 0) >= 6:
        res.ok("ES classes produce Class=%d Method=%d"
               % (kinds.get("Class", 0), kinds.get("Method", 0)))
    else:
        res.bad("ES class structure missing: kinds=%s" % (kinds or "{}"))
    if rel_kinds.get("Contains", 0) > 0:
        res.ok("Contains edges present: %d" % rel_kinds["Contains"])
    else:
        res.bad("no Contains edges: relation kinds=%s" % (rel_kinds or "{}"))
    proto = {}
    for query in ("Layer", "match", "describe"):
        for row in suite.search_entities(repo, query):
            proto[row["name"]] = row
    bound = [n for n, row in proto.items()
             if re.search(r"(^|\.)(match|describe)$", n) and "." in n
             and row["kind"] == "Method"]
    if len(bound) >= 2:
        res.ok("prototype assignments bind to their constructor: %s" % sorted(bound))
    else:
        loose = sorted(n for n in proto if n in ("match", "describe"))
        res.bad("prototype methods are unbound top-level entities %s, not methods of "
                "Layer" % (loose or "(absent entirely)"))
    literal = {}
    for query in ("normalize", "join", "helpers"):
        for row in suite.search_entities(repo, query):
            literal[row["name"]] = row
    named = sorted(n for n, row in literal.items()
                   if re.search(r"(^|\.)(normalize|join)$", n)
                   and row["kind"] in ("Method", "Function"))
    if named:
        res.ok("object-literal methods are entities: %s" % named)
    else:
        res.bad("object-literal methods normalize/join are not entities at all")
    compose = [row for row in suite.search_entities(repo, "compose")
               if row["name"] == "compose"]
    if compose and compose[0]["kind"] == "Function":
        res.ok("const-bound arrow is a Function")
    elif compose:
        res.bad("const-bound arrow 'compose' is a %s" % compose[0]["kind"])
    else:
        res.bad("const-bound arrow 'compose' is not an entity")
    junk = [row["name"] for row in suite.search_entities(repo, "Router")
            if "{" in row["name"]]
    if junk:
        res.bad("destructuring pattern admitted as an entity name: %s" % junk[:2])
    else:
        res.ok("no destructuring pattern admitted as an entity")
    join = suite.inspect(repo, "helpers.join")
    if join is None:
        res.unknown("kin graph inspect helpers.join did not resolve")
    else:
        outgoing = [r for r in join["relations"]
                    if r["dir"] == "out" and r["relation"] == "Calls"]
        if outgoing:
            res.ok("helpers.join calls %s" % ", ".join(r["name"] for r in outgoing))
        else:
            res.bad("helpers.join has no outgoing Calls edge although its body calls "
                    "helpers.normalize twice in the same file")
    if status["entities"]:
        density = float(status["relations"]) / float(status["entities"])
        if density >= 0.85:
            res.ok("relations per entity %.2f" % density)
        else:
            res.bad("relations per entity %.2f is below the 0.85 floor this fixture's "
                    "structure supports (%d relations over %d entities)"
                    % (density, status["relations"], status["entities"]))
    else:
        res.unknown("graph status reported no entity count")
    return res


def check_8(suite):
    """FIR-2359: a virtual environment must not race the watcher into the graph,
    and the context pack must not spend its budget on decimal byte arrays."""
    res = Result("8", "FIR-2359", "venv admission and context-pack byte arrays")
    repo = suite.fixture("venv")
    before = suite.graph_status(repo)
    rc, out, err = run([sys.executable, "-m", "venv", "venv"], cwd=repo,
                       env=suite.env, timeout=300)
    if rc != 0:
        res.unknown("python -m venv failed: %s" % (err or out)[-160:])
    else:
        planted = 0
        for _root, _dirs, files in os.walk(os.path.join(repo, "venv")):
            planted += len([f for f in files if f.endswith(".py")])
        with open(os.path.join(repo, ".gitignore")) as handle:
            ignore = handle.read()
        if "venv" in ignore:
            res.unknown(".gitignore already names venv; the race is not exercised")
        else:
            time.sleep(2)
            # A real edit to a tracked file, so the commit has work to record. Since
            # kin#899 (FIR-2403) a commit whose tree equals the base refuses with
            # "nothing to commit", so a bare commit here would measure that refusal
            # rather than whether the venv broke anything.
            suite._write(repo, "tool.py",
                         "def run():\n    return \"ok\"\n\n\ndef after_venv():\n    return \"still ok\"\n")
            time.sleep(2)
            crc, cout, cerr = suite.kin_run(["commit", "-m", "Work after venv"], repo)
            commit_text = cout + "\n" + cerr
            time.sleep(2)
            after = suite.graph_status(repo)
            delta = (after["entities"] or 0) - (before["entities"] or 0)
            if crc != 0:
                res.bad("a %d-file venv broke the next commit (rc=%d): %s"
                        % (planted, crc, commit_text.strip().splitlines()[0][:200]
                           if commit_text.strip() else "(no output)"))
            else:
                res.ok("the next commit after a %d-file venv succeeded" % planted)
            if delta > 50:
                res.bad("a %d-file venv added %d entities to the graph (%d -> %d) with "
                        "no ignore line and no warning"
                        % (planted, delta, before["entities"], after["entities"]))
            else:
                res.ok("the venv added %d entities" % delta)
    src = suite.fixture("incremental")
    try:
        refs = suite.references(src, "parse_note")
        entity_id = (refs.get("focal_entity") or {}).get("id")
        if not entity_id:
            raise McpError("find_references returned no focal entity id")
        pack, size = suite.mcp(src, "get_context_pack",
                               {"entity_id": entity_id, "depth": 2,
                                "token_budget": 8000})
    except McpError as exc:
        res.unknown("get_context_pack unreadable: %s" % exc)
        return res

    def byte_arrays(node, path=""):
        found = []
        if isinstance(node, dict):
            for key, value in node.items():
                found += byte_arrays(value, path + "/" + key)
        elif isinstance(node, list):
            if len(node) == 32 and all(isinstance(x, int) for x in node):
                found.append(path)
            else:
                for index, value in enumerate(node):
                    found += byte_arrays(value, "%s[%d]" % (path, index))
        return found

    arrays = byte_arrays(pack)
    if arrays:
        res.bad("context pack carries %d 32-element decimal byte array(s) (%s) in a "
                "%d-char response budgeted at 8000 tokens"
                % (len(arrays), arrays[0], size))
    else:
        res.ok("context pack carries no decimal byte arrays (%d chars)" % size)
    return res


def check_9(suite):
    """FIR-2358: some surface must report relation-graph completeness, and
    validate must not read as a completeness bill."""
    res = Result("9", "FIR-2358", "relation-graph completeness reporting")
    repo = suite.fixture("incremental")
    status = suite.graph_status(repo)
    if status["cross_file"] is not None:
        res.ok("graph status reports cross-file coverage %d of %d" % status["cross_file"])
    elif re.search(r"completeness|resolved of|parsed versus|call sites parsed",
                   status["raw"], re.I):
        res.ok("graph status carries a completeness metric")
    else:
        res.bad("graph status reports counts but no completeness metric")
    rc, out, err = suite.kin_run(["graph", "validate"], repo)
    text = out + "\n" + err
    if rc != 0:
        res.unknown("kin graph validate rc=%d" % rc)
        return res
    qualified = re.search(
        r"integrity only|does not check completeness|structural integrity, not "
        r"completeness|completeness", text, re.I)
    clean_bill = re.search(r"All checks passed", text, re.I)
    if clean_bill and not qualified:
        res.bad("graph validate prints %r with no completeness qualifier on a graph "
                "missing every cross-file edge" % "All checks passed")
    else:
        res.ok("graph validate does not read as a completeness bill")
    return res


CHECKS = [
    ("0", check_0),
    ("1", check_1),
    ("2", check_2),
    ("3", check_3),
    ("4", check_4),
    ("5", check_5),
    ("6", check_6),
    ("7", check_7),
    ("8", check_8),
    ("9", check_9),
]


def main(argv):
    parser = argparse.ArgumentParser(add_help=True, description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--kin", required=True)
    parser.add_argument("--daemon",
                        help="kin-daemon binary to serve the fixtures "
                             "(default: the sibling of --kin when one exists)")
    parser.add_argument("--workdir")
    parser.add_argument("--label", default="")
    parser.add_argument("--only", default="")
    parser.add_argument("--json", dest="json_out")
    parser.add_argument("--tips")
    parser.add_argument("--compare")
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    opts = parser.parse_args(argv)

    kin = os.path.abspath(os.path.expanduser(opts.kin))
    if not os.path.exists(kin):
        sys.stderr.write("kin binary not found: %s\n" % kin)
        return 3
    rc, out, err = run([kin, "--version"], timeout=600)
    version = strip_ansi(out).strip().splitlines()[-1] if out.strip() else "unknown"

    daemon = opts.daemon and os.path.abspath(os.path.expanduser(opts.daemon))
    if daemon is None:
        sibling = os.path.join(os.path.dirname(kin), "kin-daemon")
        daemon = sibling if os.path.exists(sibling) else None
    if daemon and not os.path.exists(daemon):
        sys.stderr.write("kin-daemon binary not found: %s\n" % daemon)
        return 3

    workdir = opts.workdir or tempfile.mkdtemp(prefix="kin-magic-repro-")
    if not os.path.isdir(workdir):
        os.makedirs(workdir)
    wanted = [w.strip() for w in opts.only.split(",") if w.strip()] or None

    suite = Suite(kin, workdir, verbose=opts.verbose, daemon=daemon)
    print("kin-magic-repro: %s" % version)
    print("kin-magic-repro: binary %s" % kin)
    print("kin-magic-repro: daemon %s" % (daemon or "(resolved by kin itself)"))
    print("kin-magic-repro: workdir %s" % workdir)

    prior = {}
    prior_label = ""
    if opts.compare:
        try:
            with open(opts.compare) as handle:
                loaded = json.load(handle)
            prior_label = loaded.get("label") or os.path.basename(opts.compare)
            prior = {row["id"]: row.get("status") for row in loaded.get("results", [])}
            print("kin-magic-repro: comparing against %s (%s)"
                  % (prior_label, opts.compare))
        except (IOError, ValueError, KeyError) as exc:
            # An unreadable baseline must not silently become "no regressions".
            print("kin-magic-repro: comparison baseline unreadable (%s): %s"
                  % (opts.compare, exc))
            prior = None

    tips = ""
    if opts.tips:
        try:
            with open(opts.tips) as handle:
                tips = handle.read()
        except IOError as exc:
            print("kin-magic-repro: tips file unreadable (%s): %s" % (opts.tips, exc))

    results = []
    for check_id, fn in CHECKS:
        if wanted and check_id not in wanted:
            continue
        try:
            res = fn(suite)
        except Exception as exc:
            res = Result(check_id, "?", "harness failure")
            res.unknown("%s: %s" % (type(exc).__name__, str(exc)[:200]))
        results.append(res)
        res.prior = None if prior is None else prior.get(res.id)
        res.trend = trend_of(res.status, res.prior)
        marker = res.status
        if res.trend == "regression":
            marker = "%s REGRESSION-from-%s-in-%s" % (res.status, res.prior, prior_label)
        elif res.trend == "fixed":
            marker = "%s fixed-since-%s" % (res.status, prior_label)
        elif res.trend == "unknown":
            marker = "%s trend-unknown" % res.status
        print("CHECK %s %s %s %s" % (res.id, res.ticket, marker, res.detail))
        if opts.verbose:
            for a in res.asserts:
                print("      %-11s %s" % (a["status"], a["detail"]))

    stopped = suite.shutdown()
    if stopped:
        print("kin-magic-repro: stopped %d fixture daemon(s)" % len(stopped))

    failed = [r for r in results if r.status == FAIL]
    unread = [r for r in results if r.status == UNREADABLE]
    regressed = [r for r in results if r.trend == "regression"]
    print("kin-magic-repro: %d pass, %d fail, %d unreadable"
          % (len(results) - len(failed) - len(unread), len(failed), len(unread)))
    if regressed:
        print("kin-magic-repro: %d regression(s) against %s: %s"
              % (len(regressed), prior_label,
                 ", ".join("%s/%s" % (r.id, r.ticket) for r in regressed)))

    if opts.json_out:
        with open(opts.json_out, "w") as handle:
            json.dump({"label": opts.label, "kin": kin, "version": version,
                       "workdir": workdir, "daemon": daemon, "tips": tips,
                       "compared_against": prior_label,
                       "results": [{"id": r.id, "ticket": r.ticket, "title": r.title,
                                    "status": r.status, "detail": r.detail,
                                    "prior_status": r.prior, "trend": r.trend,
                                    "asserts": r.asserts} for r in results]},
                      handle, indent=2)
        print("kin-magic-repro: json %s" % opts.json_out)

    if not opts.keep and not opts.workdir:
        shutil.rmtree(workdir, ignore_errors=True)

    if failed:
        return 1
    if unread:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
