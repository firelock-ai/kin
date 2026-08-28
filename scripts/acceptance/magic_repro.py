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
        self._comment_only_evidence = None
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

    def _build_answersurface(self, repo):
        """The incremental shape once more, read-only for check 24.

        Its own repository because check 24 grades the words `kin locate` and
        `kin deps` print, and an earlier check's rename or commit inside a
        shared fixture would move them.
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

    def _build_rename(self, repo):
        """The incremental shape again, in its own repository.

        Check 22 renames a symbol and then commits an unrelated file, so it
        cannot share the `incremental` fixture: the rename would reach every
        later check that reads it. Same modules, same one-at-a-time commits,
        plus a README the rename check appends to.
        """
        self.git(["init", "-q", "."], repo)
        self._write(repo, ".gitignore", "*.db\n__pycache__/\n")
        self._write(repo, "README.md", "# nk\n\nA note keeper.\n")
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

    def _build_threestate(self, repo):
        """A store converted from Git holding one file of each parse outcome.

        Converted, not committed through Kin, and that is the whole point. The
        Git import parses every file and drops the layout it derived, so before
        FIR-2604 every file on a store built this way reported `parsed: absent,
        tier: none, certifies_enumeration: false`, including files an adapter
        had read completely. A store built by `kin commit` never had the gap,
        which is why this fixture must take the conversion path to be able to
        fail.
        """
        self.git(["init", "-q", "."], repo)
        self._write(repo, ".gitignore", "__pycache__/\n")
        self._write(repo, "pkg/__init__.py", "")
        self._write(repo, THREE_STATE_FILES["parsed"], THREE_STATE_PARSED_PY)
        self._write(repo, THREE_STATE_FILES["broken"], THREE_STATE_BROKEN_PY)
        self._write(repo, THREE_STATE_FILES["empty"], THREE_STATE_EMPTY_PY)
        self._write(repo, NO_ADAPTER_FILE, NO_ADAPTER_BODY)
        self.git(["add", "-A"], repo)
        rc, out, err = self.git(["commit", "-q", "-m", "three parse outcomes"], repo)
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

    def _build_mixin(self, repo):
        """The shape a comment-only commit cost eleven edges on (FIR-2598).

        A mixin declares a method, a sibling calls it through `self`, and a
        subclass overrides it. That is what makes the `Overrides` edge
        load-bearing: `find_references` on the subclass method composes its
        second caller through the base declaration, and losing the override
        edge halves the answer without moving any confidence field.
        """
        self.git(["init", "-q", "."], repo)
        self._write(repo, ".gitignore", "__pycache__/\n")
        self._write(repo, "pkg/__init__.py", "")
        self._write(repo, "pkg/sessions.py", MIXIN_PY)
        self._kin_init(repo)
        self._kin_commit(repo, "Add the sessions module")

    def _build_mixinadapter(self, repo):
        """The FIR-2644 shape, built through the path that emits cross-file edges.

        Converted from git rather than committed through Kin, because the
        cross-file `Calls` edge into `adapters.py` is what carries the reference
        line the defect left stale, and a store built one commit at a time does
        not get one at conversion.
        """
        self.git(["init", "-q", "."], repo)
        self._write(repo, ".gitignore", "__pycache__/\n")
        self._write(repo, "pkg/__init__.py", "")
        self._write(repo, "pkg/adapters.py", MIXIN_ADAPTERS_PY)
        self._write(repo, "pkg/sessions.py", MIXIN_SESSIONS_PY)
        self.git(["add", "-A"], repo)
        rc, out, err = self.git(["commit", "-q", "-m", "initial mixin adapter fixture"], repo)
        if rc != 0:
            raise RuntimeError("git commit failed: %s" % (err or out)[-300:])
        self._kin_init(repo)

    def _build_reexport(self, repo):
        """A store holding a file that legitimately declares nothing.

        `src/prelude.rs` re-exports one name and declares none of its own, which
        is an ordinary Rust public surface. It reaches the store as an admitted
        file that produced no entity, which is exactly how a file no adapter
        could read reaches it, and the two are not the same thing. Rust is the
        language for this fixture and Python is not: kin mints a Module entity
        for every Python file, so no Python file is ever a file that produced
        nothing, and the same fixture written in Python cannot hold the shape
        this check is about.

        Built through git and converted by `kin init`, because that is the path
        that emits cross-file edges. Without them `load` reads as unreferenced
        too, and the check could no longer tell a scan that answered from one
        that withheld its answer.
        """
        self.git(["init", "-q", "."], repo)
        self._write(repo, ".gitignore", "target/\n")
        self._write(repo, "Cargo.toml", REEXPORT_CARGO_TOML)
        self._write(repo, "src/lib.rs", REEXPORT_LIB_RS)
        self._write(repo, "src/core.rs", REEXPORT_CORE_RS)
        self._write(repo, REEXPORT_BENIGN_FILE, REEXPORT_PRELUDE_RS)
        self.git(["add", "-A"], repo)
        rc, out, err = self.git(["commit", "-q", "-m", "initial reexport fixture"], repo)
        if rc != 0:
            raise RuntimeError("git commit failed: %s" % (err or out)[-300:])
        self._kin_init(repo)

    def _build_relimport(self, repo):
        """A package whose CLI reaches its modules by relative module import.

        The stranger's own shape, trimmed to three files. `pkg/cli.py` writes
        `from . import store` and then `store.connect(path)`, which is ordinary
        Python and is the shape that produced no Calls edge at all before
        kin#1181: the receiver resolved to `pkg/__init__.py` and the callee lives
        in the sibling `pkg/store.py`.

        Every call in this fixture resolves, deliberately. It is the arm that
        says a genuinely dead function still reads dead and reads dead WITHOUT a
        caveat, so the gate the sibling fixture exercises cannot pass here by
        labelling everything.
        """
        self._relimport_files(repo)

    def _relimport_files(self, repo):
        self.git(["init", "-q", "."], repo)
        self._write(repo, "pkg/__init__.py",
                    '"""pkg: a tiny package reached through a relative module '
                    'import."""\n\n__version__ = "0.1.0"\n')
        self._write(repo, "pkg/store.py", RELIMPORT_STORE_PY)
        self._write(repo, "pkg/cli.py", RELIMPORT_CLI_PY)
        self.git(["add", "-A"], repo)
        rc, out, err = self.git(["commit", "-q", "-m", "initial relimport fixture"], repo)
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
        """`kin dead-code`, with every listed row parsed off the output.

        Rows are read with DEAD_CODE_ROW rather than a pattern of this method's
        own, because the renderer puts an `[unverified: <factor>]` label in front
        of a row it cannot stand behind and a pattern that does not tolerate one
        reads a labelled row as no row at all. That is not a cosmetic miss: a
        check that grades an empty `rows` list passes both its arms on nothing.
        The label is carried on the row rather than discarded, so a caller can
        assert on it instead of re-parsing `raw`.
        """
        rc, out, err = self.kin_run(["dead-code"], repo)
        text = out + "\n" + err
        rows = []
        for line in text.splitlines():
            match = DEAD_CODE_ROW.match(line)
            if match:
                rows.append({"name": match.group(2), "kind": match.group(3),
                             "file": match.group(5),
                             "label": (match.group(1) or "").strip()})
        return {"raw": text, "rows": rows, "rc": rc}

    def references(self, repo, query, settle=2, relation_kinds=None):
        """find_references, retried once while the graph settles.

        A commit's enrichment lands asynchronously, so a probe fired
        immediately after the last fixture commit can hit a graph that has not
        resolved the symbol yet. The retry is bounded and a symbol that never
        resolves still reports unresolved rather than absent.
        """
        args = {"query": query}
        if relation_kinds:
            args["relation_kinds"] = list(relation_kinds)
        payload, _ = self.mcp(repo, "find_references", args)
        if (payload.get("focal_entity") or {}).get("id"):
            return payload
        time.sleep(settle)
        payload, _ = self.mcp(repo, "find_references", args)
        return payload

    def comment_only_commit_evidence(self):
        """The FIR-2644 experiment, run once and read by three checks.

        A `kin commit` of a module docstring and nothing else, with the caller
        sets and the reference lines recorded on both sides of it. Cached
        because the experiment is destructive: the second checker to run it
        would be measuring a store the first one had already edited, and the
        edit is the whole subject.
        """
        if self._comment_only_evidence is not None:
            return self._comment_only_evidence

        repo = self.fixture("mixinadapter")
        evidence = {"repo": repo, "error": None}
        evidence["before_status"] = self.graph_status(repo)
        evidence["before_send"] = self.references(
            repo, MIXIN_FOCAL_SEND, relation_kinds=["calls"])
        evidence["before_adapter"] = self.references(repo, MIXIN_FOCAL_ADAPTER_SEND)

        source = os.path.join(repo, "pkg", "sessions.py")
        with open(source) as handle:
            original = handle.read()
        with open(source, "w") as handle:
            handle.write(MIXIN_DOCSTRING + original)
        with open(source) as handle:
            edited = handle.read()
        if not edited.endswith(original):
            evidence["error"] = "the fixture edit did not leave the original bytes intact"
            self._comment_only_evidence = evidence
            return evidence
        evidence["added_lines"] = len(edited.splitlines()) - len(original.splitlines())
        try:
            self._kin_commit(repo, "Document the redirect flow in the module docstring")
        except RuntimeError as exc:
            evidence["error"] = "the comment-only commit failed: %s" % exc
            self._comment_only_evidence = evidence
            return evidence

        evidence["after_status"] = self.graph_status(repo)
        evidence["after_send"] = self.references(
            repo, MIXIN_FOCAL_SEND, relation_kinds=["calls"])
        evidence["after_adapter"] = self.references(repo, MIXIN_FOCAL_ADAPTER_SEND)
        with open(source) as handle:
            evidence["source_lines"] = handle.read().splitlines()
        self._comment_only_evidence = evidence
        return evidence


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


MIXIN_PY = """import time


class SessionRedirectMixin:
    def send(self, request, **kwargs):
        raise NotImplementedError

    def get_redirect_target(self, resp):
        return resp.get("location")

    def resolve_redirects(self, resp, req, **kwargs):
        target = self.get_redirect_target(resp)
        while target:
            resp = self.send(req, **kwargs)
            target = self.get_redirect_target(resp)
        return resp

    def rebuild_auth(self, prepared, response):
        return prepared


class Session(SessionRedirectMixin):
    def request(self, method, url):
        prepared = self.prepare(method, url)
        return self.send(prepared)

    def prepare(self, method, url):
        return (method, url)

    def send(self, request, **kwargs):
        time.sleep(0)
        return self.resolve_redirects(request, request)
"""

# Twenty-six lines of prose above every declaration, which is the edit the
# rc0547b run made to psf/requests' sessions.py. It shifts every line below it
# and touches no executable statement.
MIXIN_DOCSTRING = ('"""Session and redirect handling.\n'
                   + "".join("Redirect flow note %d.\n" % i for i in range(1, 24))
                   + '"""\n\n')


# The FIR-2644 shape: the mixin above, plus the transport hop that makes a call
# site cross a file. `psf/requests` is the original: `SessionRedirectMixin`
# declares `send` and calls it through `self`, `Session` overrides `send` and
# also calls `adapter.send(...)` in `adapters.py`. Both halves are needed. The
# override carries the caller `find_references` composes, and the cross-file
# call carries the reference line that went stale.
MIXIN_ADAPTERS_PY = """\"\"\"Transport adapters.\"\"\"


class BaseAdapter:
    def send(self, request, **kwargs):
        raise NotImplementedError

    def close(self):
        return None


class HTTPAdapter(BaseAdapter):
    def send(self, request, **kwargs):
        return {"status": 200, "request": request}

    def close(self):
        return None
"""

MIXIN_SESSIONS_PY = """import time

from .adapters import HTTPAdapter


class SessionRedirectMixin:
    def send(self, request, **kwargs):
        raise NotImplementedError

    def get_redirect_target(self, resp):
        return resp.get("location")

    def resolve_redirects(self, resp, req, **kwargs):
        target = self.get_redirect_target(resp)
        while target:
            resp = self.send(req, **kwargs)
            target = self.get_redirect_target(resp)
        return resp

    def rebuild_auth(self, prepared, response):
        return prepared


class Session(SessionRedirectMixin):
    def request(self, method, url):
        prepared = self.prepare(method, url)
        return self.send(prepared)

    def prepare(self, method, url):
        return {"method": method, "url": url}

    def get_adapter(self, url):
        return HTTPAdapter()

    def send(self, request, **kwargs):
        time.sleep(0)
        adapter = self.get_adapter(request)
        return adapter.send(request, **kwargs)
"""

# The two symbols the FIR-2644 checks probe. Named once so a check and its
# failure text cannot drift apart.
MIXIN_FOCAL_SEND = "Session.send"
MIXIN_FOCAL_ADAPTER_SEND = "HTTPAdapter.send"

# The fixture behind check 12. `src/prelude.rs` is the whole point: a file that
# declares nothing and that no adapter failed on. Measured on kin 0.5.48, the
# store reads "of the 5 admitted, 3 carry a full language adapter; 1 of those
# produced no entity", and that one is the prelude.
# The three file shapes FIR-2604's acceptance names. All three are admitted as
# Python and all three are valid UTF-8, so nothing here reaches the opaque facet
# by accident, which is the mistake that made an earlier parse-hole fixture
# prove nothing.
THREE_STATE_PARSED_PY = '''"""A module an adapter reads completely."""


def alpha(value):
    """Return the successor."""
    return value + 1


class Beta:
    def gamma(self):
        return 2
'''

# Not valid Python. tree-sitter recovers what it can and reports error ranges,
# which is the parse outcome that must be distinguishable from never having
# been parsed at all.
THREE_STATE_BROKEN_PY = '''def delta(:
    this is not python at all ]]]
'''

# Valid Python that correctly declares nothing. An enumeration over it IS
# certified and IS empty, and those two facts together are what no store could
# say before this check existed.
THREE_STATE_EMPTY_PY = '''"""Only a docstring and a comment live here."""
# nothing is declared in this file
'''

THREE_STATE_FILES = {
    "parsed": "pkg/parsed.py",
    "broken": "pkg/broken.py",
    "empty": "pkg/empty.py",
}

# A path no language adapter claims, admitted to the same converted store.
#
# FIR-2641's negative control, and the reason check 17 can fail in the direction
# that matters. Every arm of check 15 reads a Python file, so a build that
# certified everything would satisfy two of its three arms and its
# not-a-constant arm as well, since `broken.py` supplies the second state on its
# own. Certification is only worth anything if something is left uncertified,
# and this is the file that must stay that way.
NO_ADAPTER_FILE = "docs/notes.md"
NO_ADAPTER_BODY = """# Notes

This file has no language adapter. Nothing can enumerate it, so nothing may
certify an enumeration of it.
"""

# FIR-2821. `from . import store` binds the MODULE and no name inside it, so the
# graph records a References edge into store.py's Module entity and no Imports
# edge into any of its entities. Every function reached that way looked
# uncalled: the v0.6.1 stranger's `kin dead-code` listed eleven live functions,
# two of which run on every invocation of the program, with no caveat on any of
# them while the one row it could resolve carried a careful one.
RELIMPORT_LIVE_FUNCTION = "connect"
RELIMPORT_DEAD_FUNCTION = "orphaned_helper"

REEXPORT_BENIGN_FILE = "src/prelude.rs"
REEXPORT_DEAD_FUNCTION = "legacy_shim"

REEXPORT_CARGO_TOML = '''[package]
name = "fixture"
version = "0.1.0"
edition = "2021"
'''

REEXPORT_LIB_RS = '''pub mod core;
pub mod prelude;

pub fn entry(text: &str) -> String {
    core::load(text)
}
'''

REEXPORT_CORE_RS = '''pub fn normalize(text: &str) -> String {
    text.trim().to_lowercase()
}

pub fn load(text: &str) -> String {
    normalize(text)
}

/// Nothing calls this, here or in any other file.
pub fn legacy_shim(text: &str) -> String {
    text.chars().rev().collect()
}
'''

REEXPORT_PRELUDE_RS = '''pub use crate::core::load;
'''

RELIMPORT_STORE_PY = '''"""Storage helpers, reached only through a relative module import."""


def connect(path):
    """Open the store. Called from cli.py as `store.connect(path)`."""
    return {"path": path}


def orphaned_helper(value):
    """Nothing in this repository calls this. It is the genuinely dead one."""
    return value
'''

RELIMPORT_CLI_PY = '''"""The command line, which reaches its modules by relative module import."""

from . import store


def main(path):
    """Every call here resolves, so this file leaves no arrival gap."""
    return store.connect(path)
'''


# The verdict sentence `kin dead-code` opens with. A run whose output matches
# none of these is unreadable rather than passing: the check cannot grade an
# answer it cannot find.
DEAD_CODE_VERDICT = re.compile(
    r"^(REFUSED\b|UNVERIFIED\b|No dead code found\.|No unreferenced entities\.|"
    r"Found \d+ unreferenced entit)")

# A row, with the optional label the renderer puts in front of one it cannot
# stand behind. Suite.dead_code's own row pattern does not tolerate that prefix,
# and a labeled row read as an absent row would report the wrong defect.
DEAD_CODE_ROW = re.compile(
    r"^\s*(\[unverified[^\]]*\]\s+)?(\S+)\s+\((\w+),\s*(\w+)\)\s+-\s+(\S.*?)\s*$")


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

    # Both graded arms below run over `names`, and an empty `names` passes them
    # both while proving nothing: the entry point is not in an empty list, and
    # the contradiction loop iterates nothing. That is not hypothetical. The row
    # parser was blind to the `[unverified: <factor>]` label the renderer puts on
    # a row it cannot stand behind, so on any store where every row is labelled
    # this check stopped grading its own ticket and said so in the affirmative.
    #
    # So the parse is joined to the verdict sentence, which counts rows in prose
    # and cannot be read by the same pattern. A verdict claiming candidates over
    # a parse that found none is a blind parser, and it refuses here rather than
    # passing two arms over nothing.
    #
    # Measured on 2026-08-28, this arm is a guard rather than a live assertion:
    # this fixture's store lists no dead code at all, so the run reads "0 claimed,
    # 0 row(s) read" and the two arms below have always graded an empty list here.
    # The consumer that can catch a blind parser today is check 12, whose store
    # does list labelled rows. Said out loud so nobody reads this arm's green as
    # evidence the parse was exercised.
    claimed = re.search(r"^(?:Found (\d+) unreferenced entit|UNVERIFIED: (\d+) candidate)",
                        dead["raw"], re.M)
    claimed_rows = int(claimed.group(1) or claimed.group(2)) if claimed else 0
    if claimed_rows and not names:
        res.bad("the verdict claims %d candidate row(s) and this suite parsed none, so the "
                "arms below would grade an empty list and pass on nothing; the row parser "
                "cannot read the output it was handed. Verdict: %s"
                % (claimed_rows, (claimed.group(0) if claimed else "")))
        return res
    res.ok("the parse agrees with the verdict sentence: %d claimed, %d row(s) read"
           % (claimed_rows, len(names)))

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


def check_10(suite):
    """FIR-2598: a comment-only commit must not cost the graph an edge.

    The rc0547b run added 26 lines of docstring above `psf/requests`'
    `sessions.py` and the store went from 1279 `Calls` and 11 `Overrides`
    edges to 1268 and 10, over an entity count that did not move. Every one of
    those edges was still true about the file, and every health surface read
    green over the loss.
    """
    res = Result("10", "FIR-2598", "a comment-only commit keeps every relation kind")
    repo = suite.fixture("mixin")
    before = suite.graph_status(repo)
    if not before["relation_kinds"]:
        res.unknown("graph status printed no relation-kind histogram to compare against")
        return res
    if before["relation_kinds"].get("Calls", 0) == 0:
        res.unknown("the fixture produced no Calls edges, so there is nothing to lose: %s"
                    % before["relation_kinds"])
        return res

    source = os.path.join(repo, "pkg", "sessions.py")
    with open(source) as handle:
        original = handle.read()
    with open(source, "w") as handle:
        handle.write(MIXIN_DOCSTRING + original)
    with open(source) as handle:
        edited = handle.read()
    if not edited.endswith(original):
        res.unknown("the fixture edit did not leave the original bytes intact")
        return res
    added = len(edited.splitlines()) - len(original.splitlines())
    if added != 26:
        res.unknown("the fixture edit added %d lines, not the 26 the run made" % added)
        return res
    try:
        suite._kin_commit(repo, "Document the redirect flow in the module docstring")
    except RuntimeError as exc:
        res.unknown("the comment-only commit failed: %s" % exc)
        return res

    after = suite.graph_status(repo)
    if before["entities"] is not None and after["entities"] is not None \
            and after["entities"] < before["entities"]:
        res.unknown("the commit removed entities (%d to %d), so a smaller relation count is "
                    "not evidence of a lost edge"
                    % (before["entities"], after["entities"]))
        return res
    res.ok("the entity count held at %s across the commit" % after["entities"])

    lost = []
    for kind, count in sorted(before["relation_kinds"].items()):
        now = after["relation_kinds"].get(kind, 0)
        if now < count:
            lost.append("%s %d to %d" % (kind, count, now))
    if lost:
        res.bad("a comment-only commit cost the graph %s, with no entity removed"
                % ", ".join(lost))
    else:
        res.ok("every relation kind held or grew: %s" % after["relation_kinds"])
    return res


def check_11(suite):
    """FIR-2598: the census must be able to see a loss a commit introduced.

    The census kin#1007 added compares the live graph to a record the commit
    installing a change writes for itself, so on the rc0547b store the
    comparison point moved with the loss and `kin doctor` reported
    `no relation kind has lost ground`. This forces the state that reading is
    only correct in: a recorded baseline holding more edges than the graph does,
    over the same entity count. The surfaces must name the kind and both counts,
    and the commit that follows must not be able to reset the baseline.
    """
    res = Result("11", "FIR-2598", "the census names a kind that lost ground across a commit")
    repo = suite.fixture("mixin")
    record = os.path.join(repo, ".kin", "kindb", "relation-census")
    if not os.path.exists(record):
        res.unknown("no relation census recorded at %s after a commit" % record)
        return res
    try:
        with open(record) as handle:
            recorded = json.load(handle)
    except (ValueError, IOError) as exc:
        res.unknown("the recorded census is unreadable: %s" % exc)
        return res
    if "entities" not in recorded:
        res.unknown("the recorded census carries no entity count, so it cannot tell a lost "
                    "edge from removed code: %s" % sorted(recorded))
        return res

    status = suite.graph_status(repo)
    live = status["relation_kinds"]
    if not live.get("Calls"):
        res.unknown("the fixture holds no Calls edges to raise a baseline above: %s" % live)
        return res

    # A baseline claiming one more Calls edge than the graph holds, over the
    # same entity count. One edge is far inside the 25% sharp-fall threshold on
    # any kind this fixture can hold, so nothing but the entity count can
    # distinguish it from ordinary movement. That is precisely the case the
    # rc0547b run needed and did not get: eleven of 1279 is 0.9%, and a
    # magnitude rule was never going to see it.
    raised = dict(recorded)
    raised["kinds"] = dict(recorded.get("kinds") or {})
    raised["kinds"]["Calls"] = live["Calls"] + 1
    raised["total"] = sum(raised["kinds"].values())
    raised["entities"] = status["entities"]
    baseline_at = raised.get("at")
    with open(record, "w") as handle:
        json.dump(raised, handle)

    after = suite.graph_status(repo)
    text = after["raw"]
    expected = "Calls slipped %d to %d" % (live["Calls"] + 1, live["Calls"])
    if expected in text:
        res.ok("graph status names the kind and both counts: %s" % expected)
    else:
        line = ""
        for candidate in text.splitlines():
            if candidate.startswith("Relation census:"):
                line = candidate.strip()
        res.bad("graph status did not name the lost kind. Expected %r, census row read: %s"
                % (expected, line or "(no census row printed)"))

    rc, out, err = suite.kin_run(["doctor"], repo)
    doctor = strip_ansi(out + "\n" + err)
    # The row, not the summary. `kin doctor` closes with a line naming every
    # check that needs attention, and on a runner where several do, that line
    # contains the words "Relation census" too. A substring search picked it and
    # reported the check red over a product that had answered correctly. The row
    # carries its status marker and then the label; the summary carries a count
    # between the two.
    row = ""
    for candidate in doctor.splitlines():
        if re.match(r"^\s*\S?\s+Relation census\b", candidate):
            row = candidate.strip()
    if not row:
        res.unknown("kin doctor rc=%d printed no relation-census row" % rc)
    elif "no relation kind has lost ground" in doctor:
        res.bad("kin doctor reports the census green over a kind that lost ground: %s" % row)
    elif expected not in doctor:
        res.bad("kin doctor does not name the kind that lost ground. Expected %r, census row "
                "read: %s" % (expected, row))
    elif "entity count held" not in doctor:
        res.bad("kin doctor names the loss without the entity count that makes it a "
                "regression rather than a deletion: %s" % row)
    else:
        res.ok("kin doctor names the kind and the entity count: %s" % row)

    # The second half of the defect. A commit taken while the graph is below
    # its baseline must not install its own census as the new comparison point,
    # or the loss is invisible from the next command onward.
    source = os.path.join(repo, "pkg", "sessions.py")
    with open(source, "a") as handle:
        handle.write("\n\n# A trailing note.\n")
    try:
        suite._kin_commit(repo, "Note the trailing comment")
    except RuntimeError as exc:
        res.unknown("the follow-up commit failed: %s" % exc)
        return res
    try:
        with open(record) as handle:
            settled = json.load(handle)
    except (ValueError, IOError) as exc:
        res.unknown("the census is unreadable after the follow-up commit: %s" % exc)
        return res
    if settled.get("at") != baseline_at:
        res.bad("a commit taken over a graph below its baseline replaced the baseline: "
                "recorded at %s, now %s" % (baseline_at, settled.get("at")))
    else:
        res.ok("the commit did not move the comparison point off %s" % baseline_at)
    return res


def check_12(suite):
    """FIR-2605: a file that declares nothing must not cost the scan its answer.

    A pure re-export file imports names and declares none of its own, so it
    reaches the store as an admitted file that produced no entity, which is
    exactly how a file no adapter could read reaches it. On 2026-08-22 lane
    parseloud's branch treated the two alike and withheld every `kin dead-code`
    row over a store holding one. Every parity run on that branch stayed green,
    because no fixture in this suite held such a file. This is that fixture.

    Four arms, and the third is what makes the others falsifiable. The scan
    must not REFUSE, which replaces the answer outright; the benign file is
    named nowhere in the answer; the one function nothing calls is still listed,
    so the check cannot pass by the scan reporting nothing at all; and any label
    that row carries names an arrival factor rather than anything a file
    declaring nothing could have caused.

    The first and fourth arms used to forbid an UNVERIFIED verdict and any label
    at all. That stopped grading this ticket the day the arrival reading began
    declining over call edges that record no call-site span, which this fixture's
    language does not emit: every row here is now labelled for a reason that has
    nothing to do with a re-export file, and a check red for someone else's cause
    is measuring the wrong thing. So the arms name the cause instead of the
    symptom. A regression of the FIR-2605 class labels rows because a file
    produced no entity, and that label is not an arrival factor, so it still goes
    red here; a REFUSED verdict still goes red outright.
    """
    res = Result("12", "FIR-2605", "dead-code answers over a benign re-export file")
    repo = suite.fixture("reexport")

    # Read through Suite.dead_code's own parse rather than a second copy of it.
    # A duplicated parser is only ever wrong in a way that looks like a passing
    # run, and this fixture lists labelled rows, which makes it the consumer that
    # can actually catch the shared parser going blind to a label. Check 4 cannot:
    # its store lists nothing at all, so its arms grade an empty list either way.
    def listed_rows(scan):
        return {row["name"]: row["label"] for row in scan["rows"]}

    dead = suite.dead_code(repo)
    listed = listed_rows(dead)
    if not listed:
        # A conversion's enrichment lands asynchronously, so a scan fired
        # immediately after `kin init` can read a graph that has not resolved
        # the fixture's one cross-file call yet. Bounded, and a scan that
        # withholds its answer keeps withholding it across the retry.
        time.sleep(3)
        dead = suite.dead_code(repo)
        listed = listed_rows(dead)
    text = dead["raw"]

    verdict = ""
    for line in text.splitlines():
        stripped = line.strip()
        if DEAD_CODE_VERDICT.match(stripped):
            verdict = stripped
            break
    if not verdict:
        # The daemon's environment-override WARN lines land in this text and are
        # the last thing in it, so an excerpt taken off the end would be nothing
        # but them. The exit status is reported beside the excerpt either way.
        excerpt = " / ".join(line.strip() for line in text.splitlines()
                             if line.strip() and "WARN" not in line)
        res.unknown("kin dead-code rc=%d printed no verdict sentence this suite can read: %s"
                    % (dead["rc"], excerpt[-300:] or "(no output)"))
        return res

    # The first arm. REFUSED replaces the answer outright, which is what this
    # ticket forbids however the store looks. An UNVERIFIED opener is allowed
    # only when every reason behind it is one the fourth arm recognizes, and it
    # is read there per row rather than guessed at from the opener.
    if verdict.startswith("REFUSED"):
        res.bad("kin dead-code replaced its answer with a refusal over a store whose only "
                "unusual file is a pure re-export: %s" % verdict)
    else:
        res.ok("kin dead-code answered rather than refusing: %s" % verdict)

    # The second arm. The benign file holds no entity, so it can be neither a
    # row nor a reason; naming it at all means the scan read "declares nothing"
    # as "could not be read".
    blamed = [line.strip() for line in text.splitlines()
              if REEXPORT_BENIGN_FILE in line]
    if blamed:
        res.bad("the scan names %s, a file that declares nothing and that no adapter failed "
                "on: %s" % (REEXPORT_BENIGN_FILE, blamed[0][:200]))
    else:
        res.ok("%s is named nowhere in the answer" % REEXPORT_BENIGN_FILE)

    # The third arm, the positive one. Without it every assertion above is
    # satisfied by a scan that found nothing and said so.
    if REEXPORT_DEAD_FUNCTION not in listed:
        res.bad("%s is unreferenced in this fixture and was not listed, so this check would "
                "pass over a scan that reports nothing at all. Listed: %s"
                % (REEXPORT_DEAD_FUNCTION, ", ".join(sorted(listed)) or "(nothing)"))
        return res
    res.ok("the one function nothing calls is listed (%d row(s): %s)"
           % (len(listed), ", ".join(sorted(listed))))

    # A disclosure rather than a graded arm, so the run says which branch of the
    # spanless rule answered for this fixture instead of leaving a reader to
    # infer it from the absence of a label. The rule certifies when a file parses
    # at most one call site, discloses a floor when it parses more sites than it
    # holds edges of any kind, and declines only when the fan-out decides.
    try:
        arrival = (suite.references(repo, REEXPORT_DEAD_FUNCTION).get("caller_arrival")
                   or {})
    except McpError as exc:
        arrival = {"state": "unreadable: %s" % exc}
    res.ok("arrival state for this fixture reads %r, which is the branch of the spanless "
           "rule that answered here" % arrival.get("state", "absent"))

    # The fourth arm, and the one that carries this ticket's claim now. A label
    # is allowed, because this fixture's language emits no call-site span and the
    # arrival reading declines over that for every row in every such store. What
    # is not allowed is a label naming any other cause, because the only thing
    # unusual about this store is a file that declares nothing, and that must
    # never be what costs a row its standing.
    label = listed[REEXPORT_DEAD_FUNCTION]
    arrival_labels = ["caller_arrival_unmeasured", "caller_arrival_unresolved"]
    if not label:
        res.ok("the row for %s carries no unverified label" % REEXPORT_DEAD_FUNCTION)
    elif any(factor in label for factor in arrival_labels):
        res.ok("the row for %s is labeled %s, which names the arrival reading rather than "
               "anything a file that declares nothing could have caused"
               % (REEXPORT_DEAD_FUNCTION, label))
    else:
        res.bad("the row for %s is labeled %s over a store whose only unusual file declares "
                "nothing, and that factor is not the arrival reading, so something about the "
                "benign file cost this row its standing"
                % (REEXPORT_DEAD_FUNCTION, label))
    return res


def check_13(suite):
    """FIR-2504: the memory knobs an operator sets must outlive the daemon.

    The rc0543b stranger set `kin embed --batch-size 16` and exported
    KIN_RESOURCE_PROFILE=ci on a 12 GiB host, restarted the daemon exactly as
    Kin instructed, and got neither back. The batch reverted to 512 on every
    daemon start, which on that host was every OOM kill, and inspect kept
    reporting `interactive`. The corrected mechanism is worse than the report,
    because the flag DOES take effect for its own pass, so the knob looks like
    it works right up until the restart that needed it.

    Six arms. The fifth is the negative control: without it every assertion
    below is satisfied by a build that hardcodes ci and 16.
    """
    res = Result("13", "FIR-2504", "resource knobs survive a daemon restart")
    repo = suite.fixture("incremental")
    try:
        return _check_13(suite, res, repo)
    finally:
        # The fixture is shared, and several arms return early. Leave no
        # [resources] section behind for whatever check runs next.
        suite.kin_run(["resources", "set", "--clear"], repo)
        suite.kin_run(["daemon", "stop"], repo)


def _check_13(suite, res, repo):

    rc, out, err = suite.kin_run(
        ["resources", "set", "--profile", "ci", "--embed-batch-size", "16"], repo)
    if rc != 0:
        res.unknown("kin resources set rc=%d: %s" % (rc, (err or out).strip()[-200:]))
        return res
    res.ok("kin resources set recorded both knobs")

    # Arm 1: the file, because nothing else proves the knob outlived the
    # process that set it.
    config_path = os.path.join(repo, ".kin", "config.toml")
    try:
        with open(config_path) as handle:
            config_text = handle.read()
    except IOError as error:
        res.unknown("could not read %s: %s" % (config_path, error))
        return res
    if "[resources]" not in config_text:
        res.bad("kin resources set wrote no [resources] section to .kin/config.toml: %s"
                % config_text.strip()[-200:])
        return res
    if 'profile = "ci"' not in config_text or "embed_batch_size = 16" not in config_text:
        res.bad("[resources] does not carry both knobs: %s" % config_text.strip()[-300:])
        return res
    res.ok("both knobs are recorded in .kin/config.toml")

    def inspect_after_restart():
        suite.kin_run(["daemon", "stop"], repo)
        time.sleep(1)
        rc, out, err = suite.kin_run(["resources", "inspect", "--json"], repo)
        for line in (out or "").splitlines():
            line = line.strip()
            if line.startswith("{"):
                try:
                    return json.loads(line)
                except ValueError:
                    continue
        raise McpError("kin resources inspect --json rc=%d printed no JSON object: %s"
                       % (rc, ((err or out) or "").strip()[-200:]))

    try:
        report = inspect_after_restart()
    except McpError as error:
        res.unknown(str(error))
        return res

    # Arm 2: the line the stranger read wrong.
    profile = report.get("profile")
    if profile != "ci":
        res.bad("a daemon restarted with profile=ci recorded plans under %r instead"
                % profile)
    else:
        res.ok("the restarted daemon plans under ci")

    # Arm 3: provenance. A config choice reported as an operator override is
    # FIR-2434's lie in a new costume.
    actual = report.get("actual") or {}
    if actual.get("resource_profile_repository_config") is not True:
        res.bad("the restarted daemon does not report the profile as this repository's "
                "choice: %s" % json.dumps({k: actual.get(k) for k in
                                           ("resource_profile_env",
                                            "resource_profile_product_selected",
                                            "resource_profile_repository_config")}))
    elif actual.get("resource_profile_env") != "ci":
        res.bad("the provenance says repository config but the selector reads %r"
                % actual.get("resource_profile_env"))
    else:
        res.ok("the profile is reported as this repository's recorded choice")

    # Arm 4: the batch size the background queue is actually running with.
    embed_runtime = report.get("embed_runtime") or {}
    if "embed_batch_size" not in embed_runtime:
        res.unknown("kin resources inspect --json reports no embed_batch_size, so whether "
                    "the batch knob took cannot be read at all")
        return res
    if embed_runtime.get("embed_batch_size") != 16:
        res.bad("the restarted daemon's background embed batch is %r, not the recorded 16"
                % embed_runtime.get("embed_batch_size"))
    else:
        res.ok("the restarted daemon's background embed batch is the recorded 16")

    # Arm 5. The knobs are still set from arm 1, which is what this needs.
    # Using the feature must not make the
    # tool complain about the machine: kin#1075 shipped the daemon adopting the
    # repository profile while the CLI did not, so the two environments differed
    # on KIN_RESOURCE_PROFILE, every command in such a repository printed a
    # behavior-env divergence whose stated remedy cannot clear it (the restart it
    # asks for re-adopts the same value from the same file), and under
    # KIN_STRICT_BEHAVIOR_ENV=1 it was a hard failure rather than a warning.
    rc, out, err = suite.kin_run(["resources", "inspect"], repo)
    if "KIN_RESOURCE_PROFILE" in (err or "") and "differs between this command" in (err or ""):
        res.bad("recording a profile makes the CLI report a behavior-env divergence it "
                "cannot clear: %s" % " ".join((err or "").split())[:220])
    else:
        res.ok("recording a profile produces no behavior-env divergence")

    strict_env = dict(suite.env)
    strict_env["KIN_STRICT_BEHAVIOR_ENV"] = "1"
    strict = run([suite.kin, "resources", "inspect"], cwd=repo, env=strict_env)
    if strict[0] != 0:
        res.bad("kin resources inspect exits %d under KIN_STRICT_BEHAVIOR_ENV=1 in a "
                "repository that recorded a profile: %s"
                % (strict[0], " ".join((strict[2] or strict[1]).split())[:220]))
    else:
        res.ok("the same command exits 0 under KIN_STRICT_BEHAVIOR_ENV=1")

    # Arm 6, the negative control.
    rc, out, err = suite.kin_run(["resources", "set", "--clear"], repo)
    if rc != 0:
        res.unknown("kin resources set --clear rc=%d: %s" % (rc, (err or out).strip()[-200:]))
        return res
    try:
        cleared = inspect_after_restart()
    except McpError as error:
        res.unknown("after --clear: %s" % error)
        return res
    cleared_actual = cleared.get("actual") or {}
    cleared_embed = cleared.get("embed_runtime") or {}
    if cleared_actual.get("resource_profile_repository_config") is True:
        res.bad("--clear left the repository still claiming the profile: %r"
                % cleared_actual.get("resource_profile_env"))
    elif cleared_embed.get("embed_batch_size") == 16:
        res.bad("--clear left the background embed batch at 16, so the arms above would "
                "pass over a build that hardcodes it")
    else:
        res.ok("--clear returns the daemon to its defaults (batch %r, repository profile %r), "
               "so the arms above read a knob rather than a constant"
               % (cleared_embed.get("embed_batch_size"),
                  cleared_actual.get("resource_profile_repository_config")))

    # Arm 7: the provenance field has to move in BOTH directions or it is
    # decoration. Set says this repository chose it, cleared says kin did, and
    # the two cannot both be true of one field.
    if cleared_actual.get("resource_profile_product_selected") is not True:
        res.bad("after --clear the profile is neither this repository's nor kin's own "
                "default, so the provenance field does not track the knob: %s"
                % json.dumps({k: cleared_actual.get(k) for k in
                              ("resource_profile_env",
                               "resource_profile_product_selected",
                               "resource_profile_repository_config")}))
    else:
        res.ok("the provenance field moves both ways: repository while set, kin's own "
               "default once cleared")
    return res


def check_14(suite):
    """FIR-2135: the health tool must answer while the box is busy.

    dg-baseline saw kin_graph_status fail 11 of 11 with an instruction to
    retry, under exactly the reconcile churn someone would be running it to
    diagnose. A status surface that requires a quiet system answers precisely
    when nobody needs it. The fix answers with the last settled reading of the
    same selected graph, labelled as of that instant, and keeps a bare retry
    instruction as no caller's only path.

    The deterministic proof is in the daemon unit tests, where the blocking
    state is held rather than raced. This check probes the shipped surface: the
    quiet shape, a burst under real mutation, the agent-facing contract, and
    that the degraded shape is not sticky.
    """
    res = Result("14", "FIR-2135", "graph status answers instead of refusing")
    repo = suite.fixture("incremental")

    def status(label):
        payload, _ = suite.mcp(repo, "kin_graph_status", {})
        if not isinstance(payload, dict):
            raise McpError("%s: kin_graph_status payload is not an object" % label)
        return payload

    # Arm 1, the positive control: without it every arm below is satisfied by a
    # probe that is reading the wrong surface.
    try:
        quiet = status("quiet")
    except McpError as error:
        res.unknown(str(error))
        return res
    if quiet.get("sampling") != "point_in_time_selected_graph":
        res.bad("a quiet store's status is not a live sample: sampling=%r"
                % quiet.get("sampling"))
        return res
    if quiet.get("stale") is not None:
        res.bad("a live sample carries a stale disclosure: %s"
                % json.dumps(quiet.get("stale"))[:200])
        return res
    res.ok("a quiet store answers with a live point-in-time sample and no stale block")

    # Arm 2: a burst fired while the graph is being mutated. Whether contention
    # actually lands is the host's business; what must never happen is a
    # refusal, and the stale count prints every run so a burst that never
    # contended is visible rather than silently green.
    for index in range(6):
        suite._write(repo, "churn_%d.py" % index,
                     "def churn_%d():\n    return %d\n" % (index, index))
    commit = subprocess.Popen(
        [suite.kin, "commit", "-m", "churn the graph"],
        cwd=repo, env=suite.env,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    refusals = []
    stale = []
    live = 0
    try:
        for attempt in range(6):
            try:
                payload = status("burst %d" % attempt)
            except McpError as error:
                # An MCP-level error IS the refusal shape this ticket is about.
                refusals.append(str(error)[:200])
                continue
            sampling = payload.get("sampling")
            if sampling == "last_settled_selected_graph":
                stale.append(payload)
            elif sampling == "point_in_time_selected_graph":
                live += 1
            else:
                refusals.append("unknown sampling %r" % sampling)
    finally:
        try:
            commit.communicate(timeout=300)
        except subprocess.TimeoutExpired:
            commit.kill()
            commit.communicate()

    bare_retry = [text for text in refusals if "retry kin_graph_status" in text]
    if bare_retry:
        res.bad("status still answers a busy store with a bare retry instruction: %s"
                % bare_retry[0])
    elif refusals:
        res.bad("status refused %d of 6 calls under mutation: %s"
                % (len(refusals), refusals[0]))
    else:
        res.ok("6 of 6 status calls under mutation answered (%d live, %d as-of-earlier)"
               % (live, len(stale)))

    # Every stale answer has to carry the disclosure that makes it honest.
    for payload in stale:
        block = payload.get("stale") or {}
        missing = [key for key in
                   ("reason", "settled_age_ms", "live_attempts", "note")
                   if block.get(key) in (None, "")]
        if missing:
            res.bad("an as-of-earlier reading is missing its disclosure fields %s: %s"
                    % (", ".join(missing), json.dumps(block)[:200]))
            break
    else:
        if stale:
            res.ok("every as-of-earlier reading carries reason, age, attempts and a note")

    # The pairing, asserted here on the wire in BOTH directions rather than left
    # to the report's own validation. A replay that forgot to disclose itself
    # reads as a live sample, and a live sample carrying a disclosure reads as
    # stale when it is not; neither may ever reach a caller.
    mismatched = ["stale block under sampling=%r" % payload.get("sampling")
                  for payload in stale
                  if payload.get("sampling") != "last_settled_selected_graph"]
    if quiet.get("stale") is not None:
        mismatched.append("live sample carrying a stale block")
    if mismatched:
        res.bad("sampling and stale disagree on the wire: %s" % "; ".join(mismatched))
    else:
        res.ok("sampling and stale agree in both directions across %d response(s)"
               % (1 + len(stale) + live))

    # Arm 3, the contract an agent reads before it trusts the answer.
    try:
        tools, _ = suite.mcp(repo, "tools/list", {})
    except McpError as error:
        res.unknown("tools/list: %s" % error)
        return res
    description = ""
    for tool in (tools.get("tools") or []):
        if tool.get("name") == "kin_graph_status":
            description = tool.get("description") or ""
            break
    if not description:
        res.unknown("tools/list carries no kin_graph_status description")
        return res
    if "last_settled_selected_graph" not in description:
        res.bad("the kin_graph_status description does not tell a caller a reading as of an "
                "earlier instant is possible, so an agent cannot know to read `stale`")
    else:
        res.ok("the tool description names the as-of-earlier shape and its stale block")

    # Arm 4: the degraded shape is not sticky.
    try:
        settled = status("settled")
    except McpError as error:
        res.unknown("after the burst: %s" % error)
        return res
    if settled.get("sampling") != "point_in_time_selected_graph" or settled.get("stale"):
        res.bad("status did not go back to a live sample once the store settled: "
                "sampling=%r stale=%s"
                % (settled.get("sampling"), json.dumps(settled.get("stale"))[:160]))
    else:
        res.ok("status is live again once the store settles")
    return res


# How long a check waits for a conversion's enrichment to land before it believes
# the reading it was handed.
ENRICHMENT_SETTLE_SECONDS = 30
ENRICHMENT_POLL_SECONDS = 3


def read_until_enriched(read, rel):
    """Read `rel` through `read`, waiting out a conversion's asynchronous enrichment.

    A store converted from Git gets its layout facet backfilled by the daemon's
    reconcile loop after `kin init` has returned, so the first reader of a fresh
    fixture can be handed `parsed='absent'` for a file an adapter read
    completely. The retry these checks carried fired only when the call itself
    failed, which is the one shape this race never takes: the call succeeds, and
    the answer is simply older than the backfill.

    That is not hypothetical. In acceptance run 32608116193 check 15 read all
    three Python files as `parsed='absent'` and failed every arm, while check 17
    read `pkg/parsed.py` on the same store moments later and got
    `parsed=full tier=entity_source certifies_enumeration=True`. One store, two
    answers, and the only difference was which check asked first.

    The wait is bounded and the verdict when it expires is the reading itself, so
    a backfill that never lands still fails the check. This buys latency, never a
    pass. It is deliberately not used for a file that must STAY uncertified: an
    expected `absent` is the answer there, not a stale one.
    """
    cov, why = read(rel)
    deadline = time.time() + ENRICHMENT_SETTLE_SECONDS
    while time.time() < deadline and (cov is None or cov.get("parsed") in (None, "absent")):
        time.sleep(ENRICHMENT_POLL_SECONDS)
        cov, why = read(rel)
    return cov, why


def check_15(suite):
    """FIR-2604: parsed, tier and certifies_enumeration must be observations.

    `list_file_entities` computes its completeness verdict from the file's
    layout facet, and a store converted from Git had none: the import parses
    every file, keeps the parse completeness only long enough to link
    cross-file references, and drops the layout, because the semantic
    transaction it builds has nowhere to put one. Every file then read
    `parsed: absent, tier: none, certifies_enumeration: false`, so the
    certification kin#1009 shipped could never be true on a converted store and
    no consumer could tell a file an adapter read completely from one it failed
    on from one that declares nothing.

    Measured on 2026-08-22 against main at 38bb51f2, on this fixture's shape:

        pkg/parsed.py  parsed=absent tier=none certifies=False total=4
        pkg/broken.py  parsed=absent tier=none certifies=False total=2
        pkg/empty.py   parsed=absent tier=none certifies=False total=1

    Three files, three genuinely different states, one answer. After the fix,
    on the same fixture:

        pkg/parsed.py  parsed=full    tier=entity_source certifies=True
        pkg/broken.py  parsed=partial tier=entity_source certifies=False
                       detail="2 parse error range(s) during indexing"
        pkg/empty.py   parsed=full    tier=entity_source certifies=True

    Four arms. The first three read each shape on its own terms. The fourth is
    the one that makes the check falsifiable rather than decorative: it asserts
    the three readings are not all the same, which is exactly what fails on
    pre-fix bytes and what a future regression would break again. Reverting the
    backfill in kin-daemon's reconcile loop returns all three to `absent` and
    fails arms one, three and four.
    """
    res = Result("15", "FIR-2604", "three parse outcomes read three ways on a converted store")
    repo = suite.fixture("threestate")

    def coverage(rel):
        try:
            payload, _ = suite.mcp(repo, "list_file_entities", {"path": rel})
        except McpError as exc:
            return None, str(exc)
        cov = payload.get("file_coverage")
        if not isinstance(cov, dict):
            return None, ("the response carries no file_coverage object; keys were %s"
                          % sorted(payload.keys())[:12])
        cov = dict(cov)
        cov["total_in_file"] = payload.get("total_in_file")
        cov["entities"] = payload.get("entities") or []
        return cov, None

    readings = {}
    for name, rel in sorted(THREE_STATE_FILES.items()):
        # Every file here is one an adapter reads, so `absent` is either the
        # backfill not having landed yet or the regression this check exists to
        # catch. Waiting separates them; the reading decides.
        cov, why = read_until_enriched(coverage, rel)
        if cov is None:
            res.unknown("%s could not be read through MCP: %s" % (rel, why[:250]))
            return res
        readings[name] = cov

    parsed = readings["parsed"]
    if parsed.get("parsed") == "full" and parsed.get("certifies_enumeration") is True:
        res.ok("%s reads parsed=full, tier=%s, certifies_enumeration=true over %s entities"
               % (THREE_STATE_FILES["parsed"], parsed.get("tier"), parsed.get("total_in_file")))
    else:
        res.bad("%s holds entities an adapter read completely but reads parsed=%r "
                "certifies_enumeration=%r tier=%r, so no enumeration on this store can be "
                "certified" % (THREE_STATE_FILES["parsed"], parsed.get("parsed"),
                               parsed.get("certifies_enumeration"), parsed.get("tier")))

    broken = readings["broken"]
    if broken.get("parsed") in ("partial", "failed") and \
            broken.get("certifies_enumeration") is not True:
        res.ok("%s reads parsed=%s with detail %r and certifies nothing"
               % (THREE_STATE_FILES["broken"], broken.get("parsed"),
                  str(broken.get("parse_detail"))[:80]))
    elif broken.get("certifies_enumeration") is True:
        res.bad("%s is not valid Python yet certifies its enumeration (parsed=%r), which "
                "licenses reading an adapter failure as the file's whole surface"
                % (THREE_STATE_FILES["broken"], broken.get("parsed")))
    else:
        res.bad("%s is not valid Python and its parse outcome reads %r, which does not "
                "distinguish an adapter failure from a file nothing ever parsed"
                % (THREE_STATE_FILES["broken"], broken.get("parsed")))

    # The declares-nothing arm. Python's adapter emits a module entity for every
    # file it reads, so "declares nothing" is the absence of a function or a
    # class rather than an empty list, and asserting an empty list here would be
    # asserting something no Python file can satisfy.
    empty = readings["empty"]
    declarations = [entity.get("name") for entity in empty.get("entities", [])
                    if entity.get("kind") in ("function", "class", "method")]
    if empty.get("parsed") == "full" and empty.get("certifies_enumeration") is True \
            and not declarations:
        res.ok("%s parsed completely and declares nothing, and its enumeration is certified "
               "anyway, which is what separates it from a file an adapter failed on"
               % THREE_STATE_FILES["empty"])
    elif declarations:
        res.unknown("%s was written to declare nothing but the graph holds %s for it, so this "
                    "arm cannot test what it is for"
                    % (THREE_STATE_FILES["empty"], declarations[:4]))
    else:
        res.bad("%s declares nothing and parses cleanly, so an enumeration over it is complete "
                "and should say so; it reads parsed=%r certifies_enumeration=%r"
                % (THREE_STATE_FILES["empty"], empty.get("parsed"),
                   empty.get("certifies_enumeration")))

    # The arm that makes the other three falsifiable. Without it, a build that
    # answered `full`/`true` for everything would satisfy two of the three
    # above, and the constant this ticket is about would be back wearing the
    # other value.
    states = set()
    certifications = set()
    for cov in readings.values():
        states.add(cov.get("parsed"))
        certifications.add(cov.get("certifies_enumeration"))
    if len(states) >= 2 and certifications == {True, False}:
        res.ok("the three files read %d distinct parse states and certification differs "
               "between them, so these fields are observations rather than constants"
               % len(states))
    else:
        res.bad("three files with three different parse outcomes read parse states %s and "
                "certifications %s, so the fields carry no information about any file"
                % (sorted(str(state) for state in states),
                   sorted(str(value) for value in certifications)))
    return res


# The sentence rung one, two and three all render, shared by every CLI surface
# that answers an absence question (crates/kin-cli/src/commands/absence_qualifier.rs).
CANNOT_RULE_OUT = re.compile(r"Kin cannot rule out ", re.I)


def check_16(suite):
    """FIR-2524 rung three: the CLI must carry the verdict MCP publishes, on the
    partial-vocabulary command group.

    Numbered 16, and the ledger for why is worth carrying: three branches added a
    "check 13" off one base. kin#1075 took 13 and 14, lane fir2604 took 15, and
    both landed while this one was in flight. Renumbering a check someone else
    has landed would break the allowance entries that name it, so the free number
    is taken rather than the next one that merely looks free.

    Rungs one and two gave `kin impact`, `kin trace` and `kin search` the
    absence verdict. All three are in the ticket's ZERO-vocabulary row group, so
    the requirement to falsify one command from EACH group stayed undischarged.
    This check is the other group: `kin refs` and `kin dead-code`, which started
    with partial vocabulary of their own and could reach a different conclusion
    from their MCP counterparts about one store.

    Three arms, and the last two are what stop this from becoming the FIR-2404
    failure in its opposite costume: a fix that stamps every empty result
    uncertain has failed, and so has one that qualifies an answer holding rows.
    """
    res = Result("16", "FIR-2524", "CLI absence verdict on refs and dead-code")
    repo = suite.fixture("incremental")

    # ARM A, refusing direction, partial-vocabulary group (`kin refs`).
    # Same focal check 2 uses for the MCP half, so the two surfaces are being
    # asked one question about one store.
    try:
        payload = suite.references(repo, "parse_note")
    except McpError as exc:
        res.unknown("find_references(parse_note) unreadable: %s" % exc)
        return res
    miss = resolution_miss(payload, "parse_note")
    if miss:
        res.unknown(miss)
        return res
    negative = payload.get("negative")
    mcp_refuses = (isinstance(negative, dict)
                   and negative.get("safe_to_conclude_absent") is False)

    rc, out, err = suite.kin_run(["refs", "parse_note"], repo)
    text = out + "\n" + err
    if rc != 0 and not text.strip():
        res.unknown("kin refs parse_note exited %d with no output" % rc)
        return res
    cli_qualifies = bool(CANNOT_RULE_OUT.search(text))

    if not (payload.get("references") or []):
        # The absence path is live, so the two surfaces must agree.
        if mcp_refuses and not cli_qualifies:
            res.bad("MCP refuses to certify this absence (safe_to_conclude_absent=false) "
                    "while the CLI prints a bare answer: %s" % text.strip()[:240])
        elif mcp_refuses and cli_qualifies:
            res.ok("group=partial-vocabulary refs: both surfaces refuse; CLI carries "
                   "the verdict")
        elif not mcp_refuses and cli_qualifies:
            res.bad("the CLI qualifies an absence MCP certifies, so the two surfaces "
                    "disagree in the other direction: %s" % text.strip()[:240])
        else:
            res.ok("group=partial-vocabulary refs: both surfaces certify")
    else:
        res.ok("references returned (%d), so the refusing arm is not exercised here"
               % len(payload.get("references") or []))

    # ARM B, the positive control. An answer holding rows is not an absence, so
    # it carries no qualifier. This is the arm a fix that stamps everything
    # uncertain fails.
    rc_b, out_b, err_b = suite.kin_run(["refs", "normalize_title"], repo)
    text_b = out_b + "\n" + err_b
    has_rows = bool(re.search(r"referenced by \d+ entit", text_b))
    if not has_rows:
        res.unknown("kin refs normalize_title returned no rows, so the positive control "
                    "cannot be evaluated: %s" % text_b.strip()[:200])
    elif CANNOT_RULE_OUT.search(text_b):
        res.bad("an answer holding rows was qualified anyway, which is the "
                "stamp-everything-uncertain regression: %s" % text_b.strip()[:240])
    else:
        res.ok("positive control: an answer holding rows stays unqualified")

    # ARM C, the negative control on the ruled exclusion, second row-group
    # command. `dead_code`'s empty result is the INVERSE claim, so kin_mcp gives
    # it no cross-file classes and no language scope; only the SUBSTRATE can put
    # it in doubt. On a sound daemon it certifies, so a clean scan says nothing
    # extra. This arm fails if a future change bolts a coverage refusal onto the
    # inverse claim.
    dead = suite.dead_code(repo)
    dead_text = dead.get("raw") or ""
    if not dead_text.strip():
        res.unknown("kin dead-code produced no output, so the negative control cannot "
                    "be evaluated")
    elif "No dead code found." in dead_text:
        if CANNOT_RULE_OUT.search(dead_text):
            res.bad("a clean dead-code scan on a sound substrate was qualified; its "
                    "empty result is the INVERSE claim and missing edges produce MORE "
                    "candidates, never fewer: %s" % dead_text.strip()[:240])
        else:
            res.ok("group=partial-vocabulary dead-code: a clean scan on a sound "
                   "substrate stays unqualified")
    elif CANNOT_RULE_OUT.search(dead_text):
        res.bad("a dead-code scan that LISTED rows was qualified; a populated answer "
                "is not an absence claim: %s" % dead_text.strip()[:240])
    else:
        res.ok("group=partial-vocabulary dead-code: a populated scan stays unqualified")
    return res


def check_17(suite):
    """FIR-2641: a complete enumeration must certify, and an unparsable one must not.

    The rc0550 brown stranger asked `list_file_entities` for
    `src/requests/sessions.py`, got all 32 entities with `truncated: false`, and
    was told in the same payload `parsed: "absent", tier: "none",
    certifies_enumeration: false`, with `limiting_factor: "file_not_parsed"`.
    `kin graph status` on that store said `python: 37/37 (100%)`. The identical
    contradiction appeared on express `lib/application.js`, so it was not
    adapter-specific. The whole value of this surface over grep is that it can
    certify completeness, and it was refusing to certify answers that were in
    fact complete, which sends a reader back to grep for no reason.

    kin#1080 fixed the cause: a store converted from Git never had a layout
    facet, because the import parses every file and drops the layout it derived.
    Verified on main at bfda9bab4, `pkg/parsed.py` reads `parsed=full,
    tier=entity_source, certifies_enumeration=true`.

    So this check exists to hold that fixed, and to close the half the existing
    FIR-2604 check cannot reach. Every file that check reads is Python, so a
    build that certified everything would pass it. The ticket's own acceptance
    names the missing arm: a file with no language adapter must keep
    `parsed: absent`. Certification means nothing unless something is left
    uncertified.

    Falsify by breaking the coverage join, which is what the ticket asks for:
    query the observation under a key the store does not hold, and the positive
    arm fails while the negative control still passes.

    Numbered 17 because kin#1078 landed FIR-2524 as check 16 while this one was
    in flight, and a landed number is named by allowance entries, so the free
    number is taken rather than the one that merely looks next.
    """
    res = Result("17", "FIR-2641", "an enumeration certifies only when the file actually parsed")
    repo = suite.fixture("threestate")

    def coverage(rel):
        try:
            payload, _ = suite.mcp(repo, "list_file_entities", {"path": rel})
        except McpError as exc:
            return None, str(exc)
        cov = payload.get("file_coverage")
        if not isinstance(cov, dict):
            return None, ("the response carries no file_coverage object; keys were %s"
                          % sorted(payload.keys())[:12])
        cov = dict(cov)
        cov["total_in_file"] = payload.get("total_in_file")
        cov["truncated"] = payload.get("truncated")
        return cov, None

    # The positive arm, in the shape the stranger hit: a complete enumeration
    # that must say so.
    parsed_rel = THREE_STATE_FILES["parsed"]
    cov, why = read_until_enriched(coverage, parsed_rel)
    if cov is None:
        res.unknown("%s could not be read through MCP: %s" % (parsed_rel, why[:250]))
        return res
    if cov.get("certifies_enumeration") is True and cov.get("parsed") not in (None, "absent"):
        res.ok("%s enumerates %s entities (truncated=%s) and certifies it, reading parsed=%s "
               "tier=%s" % (parsed_rel, cov.get("total_in_file"), cov.get("truncated"),
                            cov.get("parsed"), cov.get("tier")))
    else:
        res.bad("%s returned an enumeration of %s entities and refuses to certify it: "
                "parsed=%r tier=%r certifies_enumeration=%r. That is the contradiction the "
                "stranger hit, and following the envelope's own advice sends a reader back "
                "to grep over a complete answer"
                % (parsed_rel, cov.get("total_in_file"), cov.get("parsed"),
                   cov.get("tier"), cov.get("certifies_enumeration")))

    # The negative control. Without it the arm above is satisfied by a build
    # that certifies everything, which is the same defect wearing the other
    # value.
    control, why = coverage(NO_ADAPTER_FILE)
    if control is None:
        # A surface that refuses the call outright is an acceptable answer for a
        # file it cannot enumerate, and it is certainly not a false
        # certification, so it is reported rather than failed.
        res.ok("%s is refused by the surface rather than enumerated (%s), so nothing certifies "
               "an enumeration of it" % (NO_ADAPTER_FILE, why[:120]))
    elif control.get("certifies_enumeration") is True:
        res.bad("%s has no language adapter, yet its enumeration is certified "
                "(parsed=%r tier=%r). Certification that is unconditional carries no "
                "information, which is the FIR-2604 constant back wearing the other value"
                % (NO_ADAPTER_FILE, control.get("parsed"), control.get("tier")))
    else:
        res.ok("%s has no language adapter and stays uncertified (parsed=%r tier=%r), so "
               "certification separates files rather than blessing them"
               % (NO_ADAPTER_FILE, control.get("parsed"), control.get("tier")))
    return res


def reference_rows(payload):
    """The caller rows a find_references payload returned, keyed by name."""
    rows = {}
    for row in payload.get("references") or []:
        name = row.get("name")
        if name:
            rows[name] = row
    return rows


def check_18(suite):
    """FIR-2644: a comment-only commit must keep every caller it had.

    The rc0550 run committed a module docstring on `psf/requests`'
    `sessions.py` and `find_references(Session.send, [calls])` went from two
    rows to one. The row it lost was `SessionRedirectMixin.resolve_redirects`,
    resolved through the override edge `Session.send -> SessionRedirectMixin.send`,
    and the call it names is still in the file. Nothing in the response said so:
    `degraded_signals` was empty and `edge_coverage.calls` read `present`.

    The override-resolved row is the one this check exists for. A caller
    composed through a proven override is the answer a whole-program tool gives
    and grep does not, and it is carried by an edge with exactly one producer,
    so it is the first thing a re-anchor that does not re-derive everything
    loses.
    """
    res = Result("18", "FIR-2644",
                 "a comment-only commit keeps every caller, override-resolved included")
    evidence = suite.comment_only_commit_evidence()
    if evidence["error"]:
        res.unknown(evidence["error"])
        return res
    if evidence.get("added_lines") != 26:
        res.unknown("the fixture edit added %s lines, not the 26 the run made"
                    % evidence.get("added_lines"))
        return res

    for label, payload in (("before", evidence["before_send"]),
                           ("after", evidence["after_send"])):
        unresolved = resolution_miss(payload, "%s %s" % (label, MIXIN_FOCAL_SEND))
        if unresolved:
            res.unknown(unresolved)
            return res

    before = reference_rows(evidence["before_send"])
    after = reference_rows(evidence["after_send"])
    composed = [name for name, row in before.items() if row.get("via_override_of")]
    if not composed:
        res.unknown("no caller of %s was composed through an override before the commit, so "
                    "this fixture cannot hold the shape the check is about: %s"
                    % (MIXIN_FOCAL_SEND, sorted(before)))
        return res
    res.ok("the pre-commit answer composes %s through %s"
           % (", ".join(sorted(composed)),
              ", ".join(sorted({before[n]["via_override_of"] for n in composed}))))

    lost = sorted(set(before) - set(after))
    if lost:
        res.bad("a comment-only commit lost caller(s) %s from find_references(%s); "
                "before %s, after %s"
                % (", ".join(lost), MIXIN_FOCAL_SEND, sorted(before), sorted(after)))
        return res

    still_composed = [name for name in composed if after.get(name, {}).get("via_override_of")]
    if sorted(still_composed) != sorted(composed):
        res.bad("the caller set survived but the override composition did not: %s no longer "
                "carries via_override_of"
                % ", ".join(sorted(set(composed) - set(still_composed))))
        return res
    res.ok("the caller set is unchanged at %s and every override-resolved row kept its "
           "composition" % sorted(after))
    return res


def check_19(suite):
    """FIR-2644: every reported reference line must still carry the call.

    The same commit shifted `sessions.py` by 26 lines and
    `find_references(HTTPAdapter.send)` came back with the call site at both its
    old line and its new one, stamped `reference_sites_complete: true`. The old
    line is not a call any more; on the run that produced this ticket it read
    `kwargs.setdefault("cert", self.cert)`.

    Graded against the file on disk after the commit, because that is the only
    thing that can tell a re-anchored line from a remembered one. A row that
    reports no line at all is not failed here: an absent line is a different
    answer from a wrong one, and the payload already distinguishes them.
    """
    res = Result("19", "FIR-2644", "every reported reference line still carries the call")
    evidence = suite.comment_only_commit_evidence()
    if evidence["error"]:
        res.unknown(evidence["error"])
        return res
    lines = evidence.get("source_lines")
    if not lines:
        res.unknown("the edited fixture source could not be read back")
        return res

    graded = 0
    stale = []
    for focal, payload in ((MIXIN_FOCAL_SEND, evidence["after_send"]),
                           (MIXIN_FOCAL_ADAPTER_SEND, evidence["after_adapter"])):
        unresolved = resolution_miss(payload, focal)
        if unresolved:
            res.unknown(unresolved)
            return res
        token = "%s(" % focal.rsplit(".", 1)[-1]
        for name, row in sorted(reference_rows(payload).items()):
            if (row.get("file_path") or "") != "pkg/sessions.py":
                continue
            for line_no in row.get("reference_lines") or []:
                graded += 1
                text = lines[line_no - 1] if 0 < line_no <= len(lines) else "<past end of file>"
                if token not in text:
                    stale.append("%s -> %s line %d reads %r"
                                 % (name, focal, line_no, text.strip()))
    if graded == 0:
        res.unknown("no caller reported a reference line in pkg/sessions.py after the commit, "
                    "so there is nothing to grade")
        return res
    if stale:
        res.bad("%d of %d reported reference line(s) no longer carry the call: %s"
                % (len(stale), graded, "; ".join(stale)))
    else:
        res.ok("all %d reported reference line(s) still carry the call they name" % graded)
    return res


def check_20(suite):
    """FIR-2644: a query answer taken over a short graph must say so.

    Both defects above were silent at the response level. The rows that came
    back were true, the counts agreed with themselves, and only the relation
    census, reached through a different command, knew the graph had lost edges.
    A caller acting on `find_references` cannot run `kin graph status` first and
    would have no reason to.

    The control runs first and on the same store: a healthy graph must carry no
    such signal, or the flag is one that fires always and proves nothing. Then
    the recorded baseline is raised by a single `Calls` edge over an unchanged
    entity count, which is the state the rc0550 store was in, and a commit
    offers its census and is refused. The answer taken after that must disclose
    it.
    """
    res = Result("20", "FIR-2644", "find_references discloses a relation-census loss")
    evidence = suite.comment_only_commit_evidence()
    if evidence["error"]:
        res.unknown(evidence["error"])
        return res
    repo = evidence["repo"]

    control = suite.references(repo, MIXIN_FOCAL_SEND, relation_kinds=["calls"])
    control_degraded = ((control.get("_kin") or {}).get("degraded") or {})
    if control_degraded.get("relation_census_loss"):
        res.bad("the store reports a census loss before one was introduced, so the signal "
                "cannot separate a short graph from a whole one: %s" % control_degraded)
        return res
    res.ok("the control answer on a whole graph carries no census-loss signal")

    record = os.path.join(repo, ".kin", "kindb", "relation-census")
    if not os.path.exists(record):
        res.unknown("no relation census recorded at %s" % record)
        return res
    try:
        with open(record) as handle:
            recorded = json.load(handle)
    except (ValueError, IOError) as exc:
        res.unknown("the recorded census is unreadable: %s" % exc)
        return res
    status = suite.graph_status(repo)
    live = status["relation_kinds"]
    if not live.get("Calls"):
        res.unknown("the fixture holds no Calls edges to raise a baseline above: %s" % live)
        return res
    raised = dict(recorded)
    raised["kinds"] = dict(recorded.get("kinds") or {})
    raised["kinds"]["Calls"] = live["Calls"] + 1
    raised["total"] = sum(raised["kinds"].values())
    raised["entities"] = status["entities"]
    with open(record, "w") as handle:
        json.dump(raised, handle)

    # A pass that measures the census is what publishes the hold, and a commit
    # is one. It must be refused as a baseline and must leave the disclosure
    # behind; check 11 already proves the refusal half on its own fixture.
    with open(os.path.join(repo, "pkg", "sessions.py"), "a") as handle:
        handle.write("\n\n# A trailing note.\n")
    try:
        suite._kin_commit(repo, "Note the trailing comment")
    except RuntimeError as exc:
        res.unknown("the follow-up commit failed: %s" % exc)
        return res

    after = suite.references(repo, MIXIN_FOCAL_SEND, relation_kinds=["calls"])
    degraded = ((after.get("_kin") or {}).get("degraded") or {})
    signals = ((after.get("negative") or {}).get("degraded_signals") or [])
    if not degraded.get("relation_census_loss"):
        res.bad("find_references answered over a graph short of its own census with "
                "_kin.degraded %s and degraded_signals %s, claiming nothing was wrong"
                % (degraded, signals))
    elif "relation_census_loss" not in signals:
        res.bad("the flag is set but the answer's own degraded_signals do not carry it, so a "
                "reader of the verdict never sees it: %s" % signals)
    else:
        res.ok("the answer discloses the loss structurally: _kin.degraded.relation_census_loss "
               "true and degraded_signals %s" % signals)
    return res


def check_21(suite):
    """A file no adapter claims must say WHY it holds nothing, and a file an
    adapter read must not borrow that reason.

    Kin admits every file it is given. One whose extension no language adapter
    claims is content-addressed, previewed, stored as an opaque artifact, and
    extracts nothing. Until now every surface reported that outcome in exactly
    the words it uses for a parse that was attempted and fell short: `parsed:
    absent`, and `file_parsed_absent` as the envelope's limiting factor. Those
    are opposite facts and only the second is evidence about the code, so seven
    markdown files going into a graph and producing nothing read as a parser
    defect to the reader who put them there. Nothing anywhere named the cause.

    Check 17 already proves the neighbouring fact, that such a file must not be
    certified. This proves the one after it: the answer has to say why. The two
    are separable, and a build can pass 17 while telling the reader nothing.

    Three arms, and the second and third are what let this fail. The disclosure
    is computed from the adapter registry, which is the one authority on the
    supported set, so:

    - `docs/notes.md` must carry `content_opaque` true and an `opaque_reason`
      naming its own extension. Naming the extension, rather than merely being
      present, is what makes this arm able to fail: a flag computed from anything
      other than the registry names something else or nothing.
    - `pkg/parsed.py` must carry neither. A flag hardcoded true fails here.
    - `pkg/empty.py` must carry neither. It is a docstring-only module that an
      adapter read successfully, so it holds an entity rather than none; what it
      controls is that the disclosure keys on the adapter and not on how thin a
      file is.

    Both mutations were run against a release build and both went red, each on a
    different arm, which is the point of having three.

    - Hardcoding the flag true fails on `pkg/parsed.py`, which reports 4 entities
      and would be labelled opaque.
    - Deriving the flag from the entity count fails on `docs/notes.md`, whose
      reason then reads `no_adapter_for_extension:derived` and names no
      extension at all.

    One thing this suite deliberately does NOT prove, because its fixture cannot:
    that a file an adapter read and found genuinely EMPTY is not reported opaque.
    `pkg/empty.py` holds one entity, so a count-derived flag would not fire on it
    here. That control lives in the unit fixtures beside the code
    (`crates/kin-mcp/src/handlers/file_entities.rs`), where `src/empty.py` is
    parsed `full` with zero entities. Said out loud because an arm that reads
    like a control and is not one is worse than no arm.
    """
    res = Result("21", "MD-OPAQUE",
                 "a file whose type no adapter claims discloses that as the reason")
    repo = suite.fixture("threestate")

    def coverage(rel):
        try:
            payload, _ = suite.mcp(repo, "list_file_entities", {"path": rel})
        except McpError as exc:
            return None, str(exc)
        cov = payload.get("file_coverage")
        if not isinstance(cov, dict):
            return None, ("the response carries no file_coverage object; keys were %s"
                          % sorted(payload.keys())[:12])
        cov = dict(cov)
        cov["total_in_file"] = payload.get("total_in_file")
        return cov, None

    # Arm 1: the unclaimed type names itself.
    cov, why = coverage(NO_ADAPTER_FILE)
    if cov is None:
        res.unknown("%s could not be read through MCP: %s" % (NO_ADAPTER_FILE, why[:250]))
    elif "content_opaque" not in cov:
        res.unknown("%s reports no content_opaque field; file_coverage keys were %s"
                    % (NO_ADAPTER_FILE, sorted(cov.keys())))
    else:
        extension = NO_ADAPTER_FILE.rsplit(".", 1)[-1]
        reason = cov.get("opaque_reason")
        if cov.get("content_opaque") is not True:
            res.bad("%s has no language adapter and its enumeration is empty, yet the answer "
                    "reports content_opaque=%r. The reader is left with parsed=%r, which is "
                    "the same word a failed parse earns. Whole file_coverage: %r"
                    % (NO_ADAPTER_FILE, cov.get("content_opaque"), cov.get("parsed"), cov))
        elif not isinstance(reason, str) or extension not in reason:
            res.bad("%s is disclosed as opaque but the reason does not name its extension "
                    "%r: opaque_reason=%r. A cause that names the wrong type is not a cause"
                    % (NO_ADAPTER_FILE, extension, reason))
        else:
            res.ok("%s discloses its type as the reason it holds nothing: content_opaque=True "
                   "opaque_reason=%r tier=%r" % (NO_ADAPTER_FILE, reason, cov.get("tier")))

    # Arms 2 and 3: the controls. Without them the arm above is satisfied by a
    # build that reports every file opaque, which carries no information at all.
    for label in ("parsed", "empty"):
        rel = THREE_STATE_FILES[label]
        cov, why = coverage(rel)
        if cov is None:
            res.unknown("%s could not be read through MCP: %s" % (rel, why[:250]))
            continue
        if "content_opaque" not in cov:
            res.unknown("%s reports no content_opaque field; keys were %s"
                        % (rel, sorted(cov.keys())))
        elif cov.get("content_opaque") is not False or cov.get("opaque_reason") is not None:
            res.bad("%s was read by a language adapter and holds %s entities, yet it reports "
                    "content_opaque=%r opaque_reason=%r. A file with no entities is not the "
                    "same fact as a file with no adapter, and this control is what separates "
                    "them"
                    % (rel, cov.get("total_in_file"), cov.get("content_opaque"),
                       cov.get("opaque_reason")))
        else:
            res.ok("%s holds %s entities and claims no opaque cause, so the disclosure is "
                   "computed rather than unconditional"
                   % (rel, cov.get("total_in_file")))
    return res


def check_22(suite):
    """A rename must land in one commit and must not wedge the repository.

    FIR-2838, found by the rc061a green-arm stranger. Renaming one function
    reported success in 448 ms and did not reach the graph: the old name kept
    resolving, the new one did not exist, the renamed symbol lost every incoming
    edge, `kin graph status` reported `Calls slipped 175 to 174` with the entity
    count unchanged, and then every later commit in that repository failed with
    HTTP 500 naming a relation whose endpoint was the retired entity. Appending
    one blank line to `README.md` and committing that alone reproduced the 500,
    so the blast radius was the whole repository, and the recovery was a daemon
    restart.

    Two rules kin-db enforces on every transaction were not enforced where the
    delta is built: a delta may not add a relation identity the store already
    holds, and a delta may not leave an edge naming an entity it removes. The
    reconcile caller logs a refused delta and drops it, so a commit that
    reconciled nothing still exits 0, which is why nothing upstream caught it.

    Four arms, and the last two are the ones a user meets:

    - the new name resolves after ONE commit;
    - the old name is gone, so the rename is not merely additive;
    - the renamed symbol keeps its callers, which is what a rename is for;
    - a later commit to an unrelated file succeeds and `kin graph status`
      reports no relation census loss.

    The caller arm is what separates this from a graph that quietly dropped the
    edges: an empty reference list would satisfy "the new name resolves".
    """
    res = Result("22", "FIR-2838", "a rename lands in one commit and leaves writes working")
    repo = suite.fixture("rename")

    for rel in ("pkg/parsing.py", "pkg/storage.py", "pkg/linkgraph.py"):
        full = os.path.join(repo, rel)
        with open(full) as handle:
            text = handle.read()
        with open(full, "w") as handle:
            handle.write(text.replace("normalize_title", "canonical_title"))
    rc, out, err = suite.kin_run(["commit", "-m", "Rename normalize_title to canonical_title"],
                                 repo)
    if rc != 0:
        res.unknown("the rename commit itself failed rc=%d: %s"
                    % (rc, strip_ansi(err or out)[-300:]))
        return res

    rc, out, _ = suite.kin_run(["refs", "canonical_title"], repo)
    new_name = strip_ansi(out)
    if rc != 0 or "not found" in new_name:
        res.bad("one commit after the rename the graph still does not hold "
                "`canonical_title`: rc=%d %r" % (rc, new_name[:300]))
    else:
        res.ok("`canonical_title` resolves after one commit")

    rc, out, _ = suite.kin_run(["refs", "normalize_title"], repo)
    old_name = strip_ansi(out)
    if "not found" not in old_name:
        res.bad("the old name still resolves after the rename, so the graph is carrying a "
                "declaration the file no longer has: %r" % old_name[:300])
    else:
        res.ok("the old name is gone from the graph")

    # The callers. Both files that called it were edited in the same commit, so
    # a rename that landed has both edges; the rc061a run had none.
    callers = [line for line in new_name.splitlines()
               if "pkg/storage.py" in line or "pkg/linkgraph.py" in line]
    if len(callers) < 2:
        res.bad("the renamed symbol lost its callers: `kin refs canonical_title` names %d of "
                "the 2 files that call it. Full answer: %r" % (len(callers), new_name[:400]))
    else:
        res.ok("the renamed symbol keeps its callers: %s"
               % "; ".join(line.strip() for line in callers[:3]))

    # The blast radius. One blank line in a file the rename never touched.
    with open(os.path.join(repo, "README.md"), "a") as handle:
        handle.write("\n")
    rc, out, err = suite.kin_run(["commit", "-m", "Append a blank line to the README"], repo)
    combined = strip_ansi((out or "") + (err or ""))
    if rc != 0 or "unadmitted" in combined:
        res.bad("a commit to a file the rename never touched was refused rc=%d, which is the "
                "whole repository wedged for writes: %s" % (rc, combined[-400:]))
    else:
        res.ok("a later commit to an unrelated file still lands")

    rc, out, _ = suite.kin_run(["graph", "status"], repo)
    status = strip_ansi(out)
    if "lost edges with no entity removed" in status or "relation_census_loss" in status:
        loss = [line.strip() for line in status.splitlines()
                if "lost edges with no entity removed" in line]
        res.bad("the graph reports its own census loss after the rename: %s"
                % (loss[0][:300] if loss else status[:300]))
    else:
        res.ok("graph status reports no relation census loss")
    return res


def check_23(suite):
    """FIR-2821: a function reached by relative module import is not dead code.

    The v0.6.1 stranger asked the one question a graph is supposed to answer
    better than grep, and `kin dead-code` named twelve entities of which eleven
    were live. `connect` and `ingest_directory` run on every invocation of the
    program. The shape is `from . import store` then `store.connect(path)`: the
    receiver resolves to the package `__init__` and the callee is defined in the
    sibling module, so before kin#1181 no Calls edge was produced at all. What
    made it the worst failure of that session was where the hedging went. The one
    row the tool could resolve carried a careful caveat and the eleven wrong ones
    carried none.

    Both halves are pinned here and each has its own control, because either
    alone leaves a stranger deletable. Before grading absence from dead-code,
    the precondition resolves `connect` itself and its incoming `main @
    pkg/cli.py` Calls edge. `connect` must then not be listed, and
    `orphaned_helper` must be listed so a scan returning nothing cannot pass.
    The clean scan must exit zero under a confident `Found` verdict, and the
    dead row's label must be exactly empty. That exact silence stops a generic
    refusal or a renamed arrival caveat from passing by labelling everything.

    Arm 1 asserts an OUTCOME and is not a falsification of the linker tier that
    produces it, which was measured rather than assumed. Reverting that tier and
    rebuilding leaves this check green, because on a daemon-backed store the
    edge has a second producer: reading the mutated run's own store back,
    `connect` still carried `main @ pkg/cli.py [Calls, References]
    (type_resolved)`, and `type_resolved` is the language-server origin label
    (`kin-index/src/resolution.rs`). So this arm is a regression gate on the
    answer a user gets, which is worth having and is what the ticket's
    acceptance names. The tier itself is falsified where only one producer
    exists, in `kin-index`'s `receiver_module_hop` arms and its corpus census,
    both linker-only with no daemon and no language server.

    The third arm grades the arrival consumer itself, and it does it as a JOIN
    rather than as a fixed expectation. `find_references(connect)` publishes the
    arrival reading for `pkg/store.py`, which is the file `orphaned_helper` also
    lives in, so the two surfaces are reading one store about one file. The
    check derives from that block what the dead-code row and the top-level
    verdict have to say, and then requires exactly that. A store that accounted
    for every arrival owes an empty label and a confident `Found`; a store that
    could not owes the matching `caller_arrival_` factor on the row and a verdict
    that is not confident.

    That join is what a fixed expectation could not do. Requiring an exactly
    empty label passed whether or not dead-code consulted the reading at all,
    because the already-fixed linker keeps `connect` off the list on its own and
    a clean row is clean either way. Under the join, removing the consumer leaves
    the row bare while the reading still says the arrival could not be accounted
    for, and the two halves contradict. Which branch runs is a property of the
    store rather than of this check, so the result names the branch it took: only
    the non-accounted branch grades the consumer, and this fixture takes the
    accounted one, because the graph accounts for every arrival into the file
    both functions live in. So what this arm grades here is the gate's ability to
    stay silent, and the consumer itself is graded on check 12's re-export
    fixture, whose arrival state reads unmeasured and whose row carries the
    matching label. Said out loud so nobody reads this arm's green as evidence
    the consumer ran.
    """
    res = Result("23", "FIR-2821",
                 "dead-code over a relative module import, and its arrival gate")

    def listed_rows(repo):
        # Suite.dead_code's own parse, for the reason check 12 states: a second
        # copy of a row parser cannot fail in a way anyone notices.
        scan = suite.dead_code(repo)
        found = {row["name"]: row["label"] for row in scan["rows"]}
        if not found:
            # A conversion's enrichment lands asynchronously, so a scan fired
            # straight after `kin init` can read a graph that has not resolved
            # the fixture's cross-file call yet. Bounded, and a scan that
            # withholds its answer keeps withholding it across the retry.
            time.sleep(3)
            scan = suite.dead_code(repo)
            found = {row["name"]: row["label"] for row in scan["rows"]}
        return scan, found

    repo = suite.fixture("relimport")

    # Preconditions before absence. `connect` missing from the dead-code rows
    # means something only after graph truth proves the subject exists and the
    # expected caller reaches it through a Calls edge. Otherwise dropping the
    # live entity during parsing satisfies the check for the wrong reason.
    try:
        live_refs = suite.references(
            repo, RELIMPORT_LIVE_FUNCTION, relation_kinds=["calls"])
    except McpError as exc:
        res.unknown("find_references(%s) unreadable: %s"
                    % (RELIMPORT_LIVE_FUNCTION, exc))
        return res
    miss = resolution_miss(live_refs, RELIMPORT_LIVE_FUNCTION)
    if miss:
        res.bad(miss)
        return res
    focal = live_refs.get("focal_entity") or {}
    if (focal.get("name") != RELIMPORT_LIVE_FUNCTION
            or not (focal.get("file_path") or "").endswith("pkg/store.py")):
        res.bad("find_references(%s) resolved the wrong focal: %r"
                % (RELIMPORT_LIVE_FUNCTION, focal))
        return res
    expected_callers = [
        row for row in live_refs.get("references") or []
        if row.get("name") == "main"
        and (row.get("file_path") or "").endswith("pkg/cli.py")
        and "calls" in (row.get("relation_kinds") or [])
    ]
    if not expected_callers:
        res.bad("find_references(%s, calls) did not return main @ pkg/cli.py; "
                "the live edge precondition is absent. Rows: %r"
                % (RELIMPORT_LIVE_FUNCTION, live_refs.get("references") or []))
        return res
    res.ok("graph truth contains %s and its incoming main @ pkg/cli.py Calls edge"
           % RELIMPORT_LIVE_FUNCTION)

    clean, listed = listed_rows(repo)
    if clean["rc"] != 0:
        res.bad("kin dead-code exited %d on the clean fixture: %s"
                % (clean["rc"], clean["raw"].strip()[-300:] or "(no output)"))
        return res
    verdict = ""
    for line in clean["raw"].splitlines():
        stripped = line.strip()
        if DEAD_CODE_VERDICT.match(stripped):
            verdict = stripped
            break
    if not verdict:
        excerpt = " / ".join(line.strip() for line in clean["raw"].splitlines()
                             if line.strip() and "WARN" not in line)
        res.unknown("kin dead-code rc=%d printed no verdict sentence this suite can read: %s"
                    % (clean["rc"], excerpt[-300:] or "(no output)"))
        return res
    # `Found N unreferenced entities, M of them UNVERIFIED:` also starts with
    # `Found `, and it is not a confident verdict. Both halves are required.
    confident_verdict = verdict.startswith("Found ") and "UNVERIFIED" not in verdict

    # The dead positive control. A scan that listed nothing satisfies
    # "connect is not listed" for the wrong reason.
    if RELIMPORT_DEAD_FUNCTION not in listed:
        res.bad("%s is called by nothing in this fixture and was not listed, so this check "
                "would pass over a scan that reports nothing at all. Verdict: %s. Listed: %s"
                % (RELIMPORT_DEAD_FUNCTION, verdict,
                   ", ".join(sorted(listed)) or "(nothing)"))
        return res
    res.ok("the one function nothing calls is listed (%d row(s): %s)"
           % (len(listed), ", ".join(sorted(listed))))

    # The whole finding, after the positive graph precondition above.
    if RELIMPORT_LIVE_FUNCTION in listed:
        res.bad("%s is called from pkg/cli.py through `from . import store` and dead-code "
                "lists it as unreferenced; a stranger acting on this row deletes a live "
                "function. Row label: %r"
                % (RELIMPORT_LIVE_FUNCTION, listed[RELIMPORT_LIVE_FUNCTION]))
    else:
        res.ok("%s is reached through the relative module import and is not listed"
               % RELIMPORT_LIVE_FUNCTION)

    # The join. `orphaned_helper` and `connect` share pkg/store.py, so the
    # arrival block find_references published for one is the reading dead-code
    # owes an answer to for the other.
    arrival = live_refs.get("caller_arrival")
    if not isinstance(arrival, dict) or not arrival.get("state"):
        res.unknown("find_references(%s) published no readable caller_arrival block, so the "
                    "arrival consumer cannot be graded against it: %r"
                    % (RELIMPORT_LIVE_FUNCTION, arrival))
        return res
    state = arrival["state"]
    unaccounted_files = arrival.get("unaccounted_files") or []
    measured_shortfall = [
        row for row in unaccounted_files
        if isinstance(row.get("unaccounted_call_sites"), int)
        and row["unaccounted_call_sites"] > 0
    ]
    if state == "accounted":
        expected_label = ""
    elif state == "unmeasured":
        expected_label = "[unverified: caller_arrival_unmeasured]"
    elif state == "unaccounted":
        expected_label = ("[unverified: caller_arrival_unresolved]" if measured_shortfall
                          else "[unverified: caller_arrival_unmeasured]")
    else:
        res.unknown("find_references(%s) reported an arrival state this check cannot map to a "
                    "row label: %r" % (RELIMPORT_LIVE_FUNCTION, state))
        return res

    clean_label = listed[RELIMPORT_DEAD_FUNCTION]
    # The published block carries the FAMILY reading. The delete-list authority
    # also accounts the focal's own file, which is in no family and which this
    # suite therefore cannot see, so an accounted family may still owe a label
    # for a call beside the row. That one combination is graded on the coupling
    # below rather than on a derived value the suite cannot compute.
    same_file_only = (state == "accounted"
                      and clean_label.startswith("[unverified: caller_arrival_"))
    if same_file_only:
        res.ok("join branch=same-file (does not grade the consumer): the family accounted for "
               "its arrivals and the row still carries %s, which is the focal's own file; this "
               "suite grades that through the verdict coupling below rather than against a "
               "value it cannot compute" % clean_label)
    elif clean_label != expected_label:
        res.bad("find_references reports caller_arrival state %r for pkg/store.py, so the "
                "dead-code row for %s owes the label %r and carries %r instead; the two "
                "surfaces are reading one store about one file and disagree"
                % (state, RELIMPORT_DEAD_FUNCTION, expected_label, clean_label))
    elif expected_label:
        res.ok("join branch=non-accounted (grades the consumer): the dead row carries exactly "
               "the label its own file's arrival state (%s) owes, %s, and removing the consumer "
               "leaves it bare while the reading still reports the gap"
               % (state, expected_label))
    else:
        res.ok("join branch=accounted (does not grade the consumer): arrival is accounted for "
               "this file and the dead row carries no caveat, which grades the gate's ability "
               "to stay silent")

    # And the coupling, which is the half that holds whichever branch ran: a row
    # this graph cannot stand behind must not sit under a confident heading, and
    # a scan that labelled nothing must not withhold one. Stated over the label
    # the scan actually printed rather than the derived one, so it grades the
    # same-file case the suite cannot derive.
    if clean_label and confident_verdict:
        res.bad("the row for %s is not supportable (%s) yet the scan printed a confident "
                "verdict: %s" % (RELIMPORT_DEAD_FUNCTION, clean_label, verdict))
    elif clean_label:
        res.ok("the scan withholds a confident verdict over the unsupportable row: %s" % verdict)
    elif confident_verdict:
        res.ok("the fully accounted fixture prints a confident verdict: %s" % verdict)
    else:
        res.bad("no row carries an arrival caveat, yet the scan did not print a confident "
                "Found verdict: %s" % verdict)

    return res


def check_24(suite):
    """What a `kin locate` row claims, and what a first one buries under.

    Two defects from the J6 cold-user walk on 0.6.0, both on the surface a
    stranger's first semantic question comes back on, and both invisible to
    every suite here because every one of them reads `--json`.

    A first `kin locate` on axum printed 1,400 characters of coverage warnings
    ahead of 432 characters of answer: the vector index was absent, the
    capability tier had narrowed a budget, and the role filter had withheld 134
    test paths. Each is worth having. Stacked ahead of five result lines on a
    first run, the answer is buried.

    And the rows carried no relevance signal at all, so `kin locate "Router
    path_router"` inside a Flask store returned six confident-looking Flask
    paths. Scoping was correct in both directions, which is the good news; the
    rows simply never said nothing had matched.

    Four arms. The collapse has to hold and it has to hide nothing, so
    `--explain` is graded beside it; and the row labels have to distinguish, so
    a query that names a symbol is graded against one that names none. An arm
    that only checked a label was present would pass against a build that
    printed the same label on every row.
    """
    res = Result("24", "J6-14/18/21",
                 "a locate row says what it rests on and the notes collapse")
    repo = suite.fixture("answersurface")

    rc, out, err = suite.kin_run(["locate", "normalize_title"], repo)
    rows = strip_ansi(out)
    notes = strip_ansi(err)
    if rc != 0 or not rows.strip():
        res.unknown("`kin locate` on a symbol this fixture defines exited %d with no rows: %s"
                    % (rc, notes[-300:]))
        return res

    note_lines = [line for line in notes.splitlines() if line.strip().startswith("\u26a0")]
    collapsed = [line for line in note_lines if "how this answer was produced" in line]
    if len(note_lines) > 1 and not collapsed:
        res.bad("a default locate still stacks %d warning lines ahead of the answer: %s"
                % (len(note_lines), " | ".join(l[:120] for l in note_lines[:4])))
    elif collapsed and "--explain" not in collapsed[0]:
        res.bad("the notes collapsed but the line does not say how to read them: %s"
                % collapsed[0][:300])
    else:
        res.ok("the answer is not buried: %d note line(s) ahead of %d rows"
               % (len(note_lines), len([l for l in rows.splitlines() if l.strip()])))

    # Nothing may be hidden by the collapse: --explain still prints it all.
    if collapsed:
        rc_x, _, err_x = suite.kin_run(["locate", "--explain", "normalize_title"], repo)
        explained = strip_ansi(err_x)
        named = re.findall(r"\(([^)]*)\)\.", collapsed[0])
        components = [c.strip() for c in (named[0].split(",") if named else [])]
        missing = [c for c in components if c and c not in explained]
        if rc_x != 0 or missing:
            res.bad("--explain does not carry back every component the summary named: "
                    "missing %r from %s" % (missing, explained[:300]))
        else:
            res.ok("--explain carries back every component the summary named: %s"
                   % (", ".join(components) or "none named"))

    labelled = [line for line in rows.splitlines() if line.strip().startswith(("1.", "  1."))]
    if not any("[" in line and "]" in line for line in rows.splitlines() if line.strip()):
        res.bad("no locate row says what evidence it rests on: %s" % rows[:300])
    elif not any("[named match]" in line for line in rows.splitlines()):
        res.bad("a query naming a symbol this repository defines produced no named match: %s"
                % rows[:400])
    else:
        res.ok("a query that names a symbol gets a named row: %s"
               % (labelled[0].strip()[:160] if labelled else rows.splitlines()[0][:160]))

    # The control: a question this repository has no answer to. The rows that
    # come back must not look like the rows above.
    rc_o, out_o, err_o = suite.kin_run(["locate", "Router path_router axum tower"], repo)
    off = strip_ansi(out_o)
    off_notes = strip_ansi(err_o)
    off_rows = [line for line in off.splitlines() if line.strip() and "[" in line]
    if rc_o != 0:
        res.unknown("the off-topic control exited %d: %s" % (rc_o, off_notes[-200:]))
    elif not off_rows:
        res.ok("the off-topic control returned no rows at all, which is its own honest state")
    elif any("[named match]" in line for line in off_rows):
        res.unknown("the off-topic control named a symbol this fixture holds, so it is not "
                    "off-topic here: %s" % off[:300])
    elif "answer floor" not in off_notes:
        res.bad("six confident-looking rows and nothing saying nothing matched: rows=%s "
                "notes=%s" % (off[:300], off_notes[:200]))
    else:
        res.ok("an answer where no row cleared the floor says so and names the floor")

    # Finding 21 from the same walk: the caveat named repositories this binary
    # had just registered, because the only thing it keyed on was the empty
    # listing, where a correct zero and an unrecorded one look identical.
    rc_d, out_d, _ = suite.kin_run(["deps", "--all"], repo)
    deps = strip_ansi(out_d)
    if rc_d != 0:
        res.unknown("`kin deps --all` exited %d: %s" % (rc_d, deps[-200:]))
    else:
        caveat = [line for line in deps.splitlines() if "predate" in line or "before this build" in line]
        repo_id = os.path.basename(repo)
        if caveat and any(repo_id in line for line in caveat):
            res.bad("`kin deps --all` names a repository this same binary registered in its "
                    "predates-recording caveat: %s" % caveat[0][:300])
        else:
            res.ok("the predates-recording caveat does not name a repository this build "
                   "registered")
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
    ("10", check_10),
    ("11", check_11),
    ("12", check_12),
    ("13", check_13),
    ("14", check_14),
    ("15", check_15),
    ("16", check_16),
    ("17", check_17),
    ("18", check_18),
    ("19", check_19),
    ("20", check_20),
    ("21", check_21),
    ("22", check_22),
    ("23", check_23),
    ("24", check_24),
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
        # A check that falls off the end returns None, which is legal Python and
        # survives every syntax check, then dies four lines down dereferencing
        # `res.id` with an AttributeError that names neither the check nor the
        # cause. It happened here: a conflict resolution truncated one check's
        # tail, the file still parsed, and the suite crashed after fourteen
        # green checks. Name it as this check's own UNREADABLE instead, so the
        # run reports which check is broken and still grades the rest.
        if res is None:
            res = Result(check_id, "?", "harness failure")
            res.unknown("check %s returned no Result, so it falls off the end of its "
                        "own body; a check that returns None cannot be graded"
                        % check_id)
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
