#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
#
# Ported from the kin-ecosystem umbrella's bin/kin-brownfield-repro on
# 2026-08-21. kin owns this copy from now on, so the suite versions with the
# product it tests and every pull request runs it against its own build. The
# umbrella copy is still what bin/kin-parity and the release tooling call;
# until those become wrappers around this file, a change to either copy has to
# be reconciled with the other, and the CHECK line format, exit codes, corpus
# pins, and fixtures are what make that reconciliation mechanical.
"""NON-CITABLE brownfield acceptance suite for reference enrichment.

Its output is a regression gate, never proof, never investor-facing, and never a
released claim. The citable gates all live in the kin-ecosystem umbrella
(`bin/kin-release-preflight`, `bin/kin-stranger`, `bin/kin-shipped-gate`) and
nothing here substitutes for any of them. What this suite adds is timing: it runs
on every pull request against that request's own build, so a reference-enrichment
regression is a red check rather than something a release discovers.

What it is for
--------------
The npm-0541 stranger run measured the brownfield A/B on shipped v0.5.42 bytes and
Kin lost all five tasks. Waiting on a release to learn whether an enrichment change
moved any of them costs hours. This suite reproduces the mechanical half of that run
against a LOCAL kin build in minutes, so a lane can iterate.

Each check builds a fixture from a pinned upstream tree, probes the surface the
ticket's claim is about, and prints one line:

    CHECK <id> <ticket> PASS|FAIL|UNREADABLE <detail>

UNREADABLE is a distinct outcome from FAIL and is never reported as a pass: it means
the probe could not be evaluated (no response, a non-JSON payload, an unresolved
focal entity, a field the fix has not defined yet). A crashed probe is UNREADABLE,
never a verdict. Exit status is 1 when any check FAILs, 2 when none fail but some are
UNREADABLE, 0 only when every selected check passes, 3 on a setup error.

Every check is required to be able to fail. Measured 2026-08-19 against a build of
kin main at 0545b154 (0.5.42): checks 0 and 1 pass, checks 2 through 8 fail, none is
unreadable, and the whole run takes about 15 s once the corpus cache is warm. That is
the shape the npm-0541 stranger run reported. A run in which checks 2 through 8 pass
before enrichment ships is a broken suite, not a fixed product.

Both directions are falsifiable, and were falsified. The same suite against a 0.5.37
binary fails check 1 (`imports 0/305 (0%)` on express, against 70/220 today), so a
pass there is a real fix rather than a check that cannot fail. Check 2's negative
control also fires on 0.5.37, where `Server.text_response_server` and
`TestPreparingURLs.test_different_connection_pool_for_mtls_settings` were counted as
callers of HTTPAdapter.send by bare-name match. Checks 4 through 6 report UNREADABLE
on 0.5.37 rather than a verdict, because that build answers a different payload
shape, which is the outcome those states exist for.

The binary under test
---------------------
    cargo build --locked --bin kin --bin kin-daemon
    python3 scripts/acceptance/brownfield_repro.py --kin target/debug/kin

`--kin` may also come from the KIN_BIN environment variable. The kin-daemon beside it
is used automatically when one exists. No binary is built by this script.

Corpora
-------
The same two upstream trees the npm-0541 stranger converted, pinned by commit AND by
tree object, so a fixture whose content drifted is refused rather than measured:

    psf/requests       8f8b212de8c2129d7954c6cd373762880375620a
                       tree 19e4272a9f1e9048c27fb6daa1b4916497a70193
    expressjs/express  a3714473feb3d2908add734d340e7755fd85e0a3
                       tree 134de344af9d2e7785aae9a991d02fd85b404bcf

One deliberate deviation from the stranger, stated because it bounds what this suite
can say. The stranger converted the full histories, 6491 and 6158 commits, which cost
1208 s and 584 s of `kin init`. Each fixture here is a fresh single-commit repository
holding the identical tree, which converts in about 3 s. Kin refuses a shallow clone
outright, so a one-commit repository is how a full tree converts quickly. Symbol
resolution reads the tree, so the resolution facts these checks assert are unchanged;
history-shaped behavior (conversion cost, provenance depth, commit peak memory) is
NOT exercised here and stays the stranger's job.

Fixtures are cached under --corpus-cache (default ~/.cache/kin-brownfield-repro) as
depth-1 fetches of the pinned commits, so only the first run touches the network.
Point --corpus-cache at any directory already holding `requests` and `express` git
repositories that carry the pinned commits to skip the network entirely.

The GPU and the fleet daemon
----------------------------
This suite never runs inference and never touches the fleet daemon or an existing
store. Every run gets its own scratch KIN_HOME under the workdir, exports
KIN_DAEMON_AUTO_EMBED=0, and check 0 asserts the daemon logged the operator opt-out
and indexed nothing. Fixture daemons are stopped at the end of the run.

Usage:
    python3 scripts/acceptance/brownfield_repro.py --kin <path-to-kin-binary> [options]

Options:
    --kin PATH           kin binary under test (or KIN_BIN; required)
    --daemon PATH        kin-daemon to serve fixtures (default: sibling of --kin)
    --workdir PATH       fixture root (default: a fresh temp dir)
    --corpus-cache PATH  pinned upstream clones (default: ~/.cache/kin-brownfield-repro)
    --offline            refuse to fetch; the cache must already carry both pins
    --label NAME         label recorded in the JSON report
    --only IDS           comma-separated check ids to run, 0 through 8 (default: all)
    --json PATH          write machine-readable results here
    --compare PATH       a prior run's --json; a check that passed there and fails
                         here reads REGRESSION rather than plain FAIL
    --keep               keep fixtures after the run
    --verbose            print every sub-assertion, not just the deciding one

Tickets: FIR-2463 (one verdict per response), FIR-2464 (ship reference enrichment for
Python and JavaScript), FIR-2441 (JavaScript import specifiers, the positive control).
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

NON_CITABLE = (
    "NON-CITABLE: DEV-LOCAL iteration only. Not proof, not a release gate, "
    "not an investor or published claim."
)

# Every fixture here is a pinned tree replayed as ONE commit, so every recall result
# this suite reports is a one-commit-shape result. That scope is not cosmetic: on
# 2026-08-20 the scale canary ran checks 2 and 3 unmodified against the identical tree
# and binary at 6,491 commits of history, and check 3 FAILED at that depth on every
# build tested while passing here on all of them, with the sweep converged and the
# revision identical. State the limitation as depth-dependent recall rather than as one
# signature, because the OBSERVED SHAPE VARIES BY VERSION and two descriptions of it in
# this file were already wrong: on shipped 0.5.43 the caller is counted with its
# reference_lines empty, [] against [312]; on the 2a80f4a6 and bb8bebe3 candidates it is
# absent from the payload entirely, not even a withheld candidate. What holds across all
# of them is that this suite cannot see any of it, because it never tests that shape. A
# green here is evidence about the shape it tests and nothing more.
FIXTURE_SCOPE = (
    "FIXTURE SCOPE: single-commit fixtures. Recall greens do NOT generalize to "
    "real history; at 6,491 commits on the identical tree check 3 fails on every "
    "build tested, its shape varying by version (0.5.43: counted, reference_lines "
    "empty; 2a80f4a6 and bb8bebe3: absent entirely). Use the umbrella's "
    "bin/kin-magic-at-scale "
    "for history-shape claims."
)

AUTO_EMBED_OPT_OUT_LINE = "background embedding deferred by operator opt-out"

CORPORA = {
    "requests": {
        "url": "https://github.com/psf/requests",
        "commit": "8f8b212de8c2129d7954c6cd373762880375620a",
        "tree": "19e4272a9f1e9048c27fb6daa1b4916497a70193",
        "language": "python",
    },
    "express": {
        "url": "https://github.com/expressjs/express",
        "commit": "a3714473feb3d2908add734d340e7755fd85e0a3",
        "tree": "134de344af9d2e7785aae9a991d02fd85b404bcf",
        "language": "javascript",
    },
}

# Reference-edge coverage line, e.g.
#   javascript: 137 files, calls 209/568 (36%), imports 0/305 (0%), cross-file 104
COVERAGE_LINE = re.compile(
    r"^\s*(?P<lang>\w+):\s*(?P<files>\d+)\s+files,\s*"
    r"calls\s+(?P<cres>\d+)/(?P<ctot>\d+)"
    r"(?:.*?imports\s+(?P<ires>\d+)/(?P<itot>\d+))?",
    re.M,
)

# requests, task 2. Ground truth established by the stranger's classic arm and
# re-verified in the pinned tree: HTTPAdapter.send has exactly two call sites in the
# repository and none in the tests.
#   src/requests/sessions.py:784  Session.send                r = adapter.send(request, **kwargs)
#   src/requests/auth.py:312      HTTPDigestAuth.handle_401   _r = r.connection.send(prep, **kwargs)
HTTPADAPTER_SEND = "HTTPAdapter.send"
REAL_CALLER_ONE = "Session.send"
REAL_CALLER_ONE_FILE = "src/requests/sessions.py"
REAL_CALLER_ONE_LINE = 784
REAL_CALLER_TWO = "HTTPDigestAuth.handle_401"
REAL_CALLER_TWO_FILE = "src/requests/auth.py"
REAL_CALLER_TWO_LINE = 312

# Entities the shipped build offered as callers of HTTPAdapter.send that call no such
# thing. Every one is a bare-name match on `send`. They are the negative control: a
# build that reports any of them as a resolved upstream reference has fabricated it.
FABRICATED_SEND_CALLERS = {
    "Server.text_response_server",
    "TestPreparingURLs.test_different_connection_pool_for_mtls_settings",
    "test_redirect_rfc1808_to_non_ascii_location",
}

# express, task 5. trace_data_flow on app.handle, direction calls, depth 2 returned
# eleven steps of which the stranger verified nine were fabricated, all descended from
# bare-name matching the single `this.get('env')` call site against every entity in
# the repository named `get` or ending in `.get`.
APP_HANDLE = "app.handle"
APP_HANDLE_FILE = "lib/application.js"
# Verified in the pinned tree: app.handle at :152, this.enabled('x-powered-by') at
# :160, finalhandler at :154, and the one edge that answers the question, the
# hand-off this.router.handle(req, res, done), at :177.
APP_HANDLE_REAL_CALLEES = ["app.enabled", "finalhandler"]
APP_HANDLE_MISSING_CALLEE = "router.handle"
# app.set was removed from this list 2026-08-20: it is a GENUINE depth-2 callee,
# app.handle calls this.enabled (lib/application.js:160) and app.enabled's body is
# `return Boolean(this.set(setting))` (:420), verified in the pinned tree. The list
# matches on name alone and is depth-blind, so keeping it here failed exactly the
# build that fixed the receiver fan (FIR-2472).
APP_HANDLE_FABRICATED = [
    "req.get",
    "res.get",
    "create",
    "users.get",
    "message",
    "redirect",
    "res.send",
    "escapeHtml",
]

# express, task 6. Ten exports in lib/express.js and none is dead: the shipped build
# called four of them unused. The graph names the entity `Router` and its signature is
# `exports.Router = Router;`. It carries 32 in-repo hits, the first at
# examples/multi-router/controllers/api_v1.js:5, so an authoritative absence on it is
# the delete-what-Kin-called-safe case.
EXPRESS_EXPORT = "Router"
EXPRESS_EXPORT_FILE = "lib/express.js"
EXPRESS_EXPORT_LINE = 71

# requests, task 1. Session.request is a method at src/requests/sessions.py:557. The
# shipped build's semantic_search answered zero for query "request" under a kind
# filter and certified that zero as authoritative, on the same repository where
# find_references refuses to certify. Same missing dependency, opposite verdict,
# decided by which internal route answered.
PY_SEARCH_QUERY = "request"
PY_SEARCH_KIND = "method"
PY_KNOWN_METHOD = "Session.request"
PY_KNOWN_METHOD_FILE = "src/requests/sessions.py"
PY_KNOWN_METHOD_LINE = 557

LANGUAGE_SERVERS = ["pyright", "pyright-langserver", "typescript-language-server"]


print = functools.partial(print, flush=True)


def strip_ansi(text):
    return ANSI.sub("", text or "")


def run(cmd, cwd=None, env=None, timeout=900):
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


class ProbeError(Exception):
    """A probe that could not be evaluated. Always UNREADABLE, never a verdict."""


def entity_names(rows):
    out = []
    for row in rows or []:
        if isinstance(row, dict):
            name = row.get("name") or row.get("entity_name") or row.get("target")
            if name:
                out.append(name)
    return out


def basename_of(name):
    """`Session.send` and `send` compare equal; `req.get` and `res.get` do not.

    Kin names a method either bare or receiver-qualified depending on the surface,
    so a check that compares only full strings misses half its own subject.
    """
    return (name or "").rsplit(".", 1)[-1]


def name_matches(candidate, wanted):
    if not candidate or not wanted:
        return False
    if candidate == wanted:
        return True
    if candidate.endswith("." + wanted):
        return True
    if wanted.endswith("." + candidate):
        return True
    return False


# One "LSP cold sweep complete" accounting line, ANSI already stripped. The
# fields arrived with kin#985; a line without `enriched=` is an older build.
SWEEP_COMPLETE_LINE = re.compile(r"LSP cold sweep complete\s+(?P<fields>.*)$")
SWEEP_FIELD = re.compile(r"(?P<key>[a-z_]+)=(?P<value>[a-z0-9]+)")


def sweep_lines(log_text):
    """Every cold-sweep completion line in a daemon log, as field dicts."""
    out = []
    for line in strip_ansi(log_text).splitlines():
        match = SWEEP_COMPLETE_LINE.search(line)
        if not match:
            continue
        fields = {}
        for pair in SWEEP_FIELD.finditer(match.group("fields")):
            value = pair.group("value")
            if value in ("true", "false"):
                fields[pair.group("key")] = (value == "true")
            elif value.isdigit():
                fields[pair.group("key")] = int(value)
        out.append(fields)
    return out


def sweep_verdict(lines):
    """Decide whether recall assertions may run over a store's sweep record.

    `lines` is sweep_lines() of the fixture's daemon log. Admits recall only when
    some completed sweep enriched at least one file and left nothing blocked,
    unvisited, interrupted, or unaccounted. A line missing the tally fields is
    exempted LOUDLY rather than silently, and a missing field never defaults to a
    passing zero: absence refuses, because an absent key defaulting to zero is the
    exact class of check that cannot fail.

    The exemption names TWO possible causes, not one. Missing tallies originally
    meant a pre-985 build. On 2026-08-21 a lane proved they also appear on a
    POST-985 build when the sweep is triggered explicitly through POST /lsp/sweep:
    that route's completion line carries only files/total_files/relations, so
    985's accounting does not reach it. A gate that exempts a post-985 build as
    pre-985 has stopped enforcing without saying so; this one now says so.
    """
    if not lines:
        return (False, "daemon.log records no completed sweep; the graph was "
                       "never enriched or the log is unreadable")
    required = ("enriched", "server_unavailable", "source_unreadable",
                "not_visited", "unaccounted", "ended_early")
    tallied = [ln for ln in lines if all(k in ln for k in required)]
    if not tallied:
        return (True, "sweep completion lines carry no tally fields; recall gate "
                      "not enforceable, checks run ungated. Cause is EITHER a "
                      "pre-985 build OR a post-985 sweep triggered via "
                      "POST /lsp/sweep, whose completion line skips 985's "
                      "accounting; do not read this as proof of build age")
    for ln in tallied:
        if (ln["enriched"] > 0 and ln["server_unavailable"] == 0
                and ln["source_unreadable"] == 0 and ln["not_visited"] == 0
                and ln["unaccounted"] == 0 and not ln["ended_early"]):
            return (True, "sweep concluded clean: enriched=%d of files=%s, "
                          "nothing blocked or unvisited"
                    % (ln["enriched"], ln.get("files", "?")))
    worst = max(tallied, key=lambda ln: (ln["server_unavailable"]
                                         + ln["source_unreadable"]
                                         + ln["not_visited"] + ln["unaccounted"]))
    return (False, "no clean completed sweep: best evidence enriched=%s "
                   "server_unavailable=%s source_unreadable=%s not_visited=%s "
                   "unaccounted=%s ended_early=%s; recall against this graph "
                   "would attribute the gap to the wrong ticket"
            % (worst.get("enriched"), worst.get("server_unavailable"),
               worst.get("source_unreadable"), worst.get("not_visited"),
               worst.get("unaccounted"), worst.get("ended_early")))


class Suite(object):
    def __init__(self, kin, workdir, corpus_cache, daemon=None, offline=False,
                 verbose=False):
        self.kin = kin
        self.daemon = daemon
        self.workdir = workdir
        self.corpus_cache = corpus_cache
        self.offline = offline
        self.verbose = verbose
        self.fixtures = {}
        self.payloads = {}
        self.sweep_gates = {}
        self.run_id = "r%d" % os.getpid()
        self.kin_home = os.path.join(workdir, "kin-home-" + self.run_id)
        if not os.path.isdir(self.kin_home):
            os.makedirs(self.kin_home)
        self.env = dict(os.environ)
        # The scratch KIN_HOME is what keeps this run off the fleet's stores, and
        # the auto-embed opt-out is what keeps it off the GPU. Check 0 asserts both
        # held rather than trusting that setting them was enough.
        self.env["KIN_HOME"] = self.kin_home
        self.env["KIN_DAEMON_AUTO_EMBED"] = "0"
        self.env["KIN_VFS_DISABLE"] = "1"
        self.env.pop("KIN_MCP_REPO", None)
        self.env.pop("KIN_DIR", None)
        if daemon:
            self.env["KIN_DAEMON_BIN"] = daemon

    # ---------------------------------------------------------------- plumbing

    def kin_run(self, args, repo, timeout=900):
        return run([self.kin] + args, cwd=repo, env=self.env, timeout=timeout)

    def git(self, args, cwd=None, timeout=900):
        base = ["git",
                "-c", "core.hooksPath=/dev/null",
                "-c", "user.email=repro@example.invalid",
                "-c", "user.name=kin-brownfield-repro",
                "-c", "commit.gpgsign=false",
                "-c", "core.fsmonitor=false",
                "-c", "protocol.version=2"]
        return run(base + args, cwd=cwd, env=self.env, timeout=timeout)

    def mcp(self, repo, tool, args, timeout=600):
        """One tools/call over kin's stdio MCP server.

        The MCP path is the surface that applies the negative and completeness
        envelope, so every envelope claim here is probed on it rather than on the
        raw daemon route, which wraps a payload carrying no such envelope. The real
        payload is a JSON string inside content[0].text; reading fields off the
        outer result object returns empty for every one of them.
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
                        "clientInfo": {"name": "kin-brownfield-repro",
                                       "version": "1"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
             "params": {"name": tool, "arguments": args}},
        ]
        payload = "".join(json.dumps(m) + "\n" for m in msgs)
        try:
            out, err = proc.communicate(payload, timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            raise ProbeError("mcp %s timed out after %ss" % (tool, timeout))
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
            raise ProbeError("mcp %s returned no id=2 frame (stderr tail: %s)"
                             % (tool, strip_ansi(err)[-200:].replace("\n", " ")))
        if "error" in resp:
            raise ProbeError("mcp %s error: %s"
                             % (tool, json.dumps(resp["error"])[:200]))
        result = resp.get("result") or {}
        content = result.get("content") or []
        if not content or "text" not in content[0]:
            raise ProbeError("mcp %s returned no text content" % tool)
        text = content[0]["text"]
        try:
            body = json.loads(text)
        except ValueError:
            raise ProbeError("mcp %s%s payload is not JSON (first 160 chars: %r)"
                             % (tool, " isError" if result.get("isError") else "",
                                text[:160]))
        if not isinstance(body, dict):
            raise ProbeError("mcp %s payload is not an object" % tool)
        return body

    def cached(self, repo, tool, args, key=None):
        """Probe once per run; several checks read the same payload."""
        cache_key = key or (repo, tool, json.dumps(args, sort_keys=True))
        if cache_key not in self.payloads:
            self.payloads[cache_key] = self.mcp(repo, tool, args)
        return self.payloads[cache_key]

    # ---------------------------------------------------------------- fixtures

    def _cache_repo(self, name):
        """A depth-1 fetch of the pinned commit, reused across runs."""
        spec = CORPORA[name]
        path = os.path.join(self.corpus_cache, name)
        if not os.path.isdir(os.path.join(path, ".git")):
            if not os.path.isdir(path):
                os.makedirs(path)
            rc, out, err = self.git(["init", "-q", "."], cwd=path)
            if rc != 0:
                raise ProbeError("git init failed in %s: %s" % (path, (err or out)[-200:]))
        rc, _out, _err = self.git(["cat-file", "-e", spec["commit"] + "^{commit}"],
                                  cwd=path)
        if rc != 0:
            if self.offline:
                raise ProbeError(
                    "corpus cache %s does not carry %s and --offline forbids fetching"
                    % (path, spec["commit"][:12]))
            rc, out, err = self.git(
                ["fetch", "--quiet", "--depth", "1", spec["url"], spec["commit"]],
                cwd=path, timeout=900)
            if rc != 0:
                raise ProbeError("fetch of %s %s failed: %s"
                                 % (spec["url"], spec["commit"][:12],
                                    (err or out).strip()[-200:]))
        return path

    def fixture(self, name):
        """A fresh single-commit repository holding the pinned tree, kin-initialized.

        Kin refuses a shallow repository outright, so the pinned tree is replayed
        into a complete one-commit repository rather than cloned shallow. The tree
        object is verified against the pin before anything is measured, because a
        fixture whose content drifted would answer a different question in the same
        shape as this one.
        """
        if name in self.fixtures:
            return self.fixtures[name]
        spec = CORPORA[name]
        cache = self._cache_repo(name)
        path = os.path.join(self.workdir, "%s-%s" % (name, self.run_id))
        if os.path.exists(path):
            shutil.rmtree(path, ignore_errors=True)
        os.makedirs(path)
        rc, out, err = self.git(["init", "-q", "-b", "main", "."], cwd=path)
        if rc != 0:
            raise ProbeError("git init failed: %s" % (err or out)[-200:])
        archive = subprocess.Popen(
            ["git", "--git-dir", os.path.join(cache, ".git"),
             "archive", spec["tree"]],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        untar = subprocess.Popen(["tar", "-x"], stdin=archive.stdout,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 cwd=path)
        archive.stdout.close()
        _uout, uerr = untar.communicate(timeout=600)
        archive.wait(timeout=60)
        if archive.returncode != 0 or untar.returncode != 0:
            raise ProbeError("replaying tree %s failed (archive rc=%s, tar rc=%s): %s"
                             % (spec["tree"][:12], archive.returncode,
                                untar.returncode,
                                uerr.decode("utf-8", "replace")[-200:]))
        rc, out, err = self.git(["add", "-A"], cwd=path)
        if rc != 0:
            raise ProbeError("git add failed: %s" % (err or out)[-200:])
        rc, out, err = self.git(
            ["commit", "-q", "-m", "%s at %s" % (name, spec["commit"][:12])], cwd=path)
        if rc != 0:
            raise ProbeError("git commit failed: %s" % (err or out)[-200:])
        rc, out, err = self.git(["rev-parse", "HEAD^{tree}"], cwd=path)
        got = out.strip()
        if rc != 0 or got != spec["tree"]:
            raise ProbeError("fixture %s tree is %s, pinned tree is %s"
                             % (name, got or "unreadable", spec["tree"]))
        # A real checkout of a JavaScript repository has node_modules on disk,
        # and the language server needs it to resolve require() targets (check
        # 4's hand-off, this.router.handle, resolves through the vendored
        # `router` package or not at all). Installed AFTER the tree-hash
        # verification and never committed, so the pinned tree is unchanged and
        # kin's git-based admission never sees it; the language server reads
        # disk regardless. Cached beside the corpus clone so only the first run
        # pays the network. A missing npm degrades to a note, and check 4 then
        # reports its own failure honestly rather than this step hiding it.
        if os.path.exists(os.path.join(path, "package.json")):
            cache_nm = os.path.join(self.corpus_cache, "%s-node_modules-%s"
                                    % (name, spec["commit"][:12]))
            dst_nm = os.path.join(path, "node_modules")
            if os.path.isdir(cache_nm):
                shutil.copytree(cache_nm, dst_nm, symlinks=True)
                print("kin-brownfield-repro: fixture %s: node_modules restored from cache" % name)
            elif shutil.which("npm"):
                rc, out, err = run(
                    ["npm", "install", "--omit=dev", "--no-fund", "--no-audit",
                     "--no-progress", "--ignore-scripts"],
                    cwd=path, env=self.env, timeout=300)
                if rc == 0 and os.path.isdir(dst_nm):
                    shutil.copytree(dst_nm, cache_nm, symlinks=True)
                    print("kin-brownfield-repro: fixture %s: node_modules installed and cached" % name)
                else:
                    print("kin-brownfield-repro: fixture %s: npm install failed "
                          "(rc=%s); require() targets will not resolve"
                          % (name, rc))
            else:
                print("kin-brownfield-repro: fixture %s: no npm on PATH; "
                      "require() targets will not resolve" % name)
        rc, out, err = self.kin_run(["init", "."], path)
        if rc != 0:
            raise ProbeError("kin init failed in %s: %s" % (path, (err or out)[-300:]))
        self.fixtures[name] = path
        return path

    def shutdown(self):
        """Stop the per-fixture daemons this run started.

        Each fixture is a throwaway repository, so its daemon has nothing to serve
        once the run ends; leaving them alive leaks one process per fixture per run
        and holds the fixture's files against removal.
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

    # ------------------------------------------------------------ status probes

    def graph_status(self, name):
        repo = self.fixture(name)
        rc, out, err = self.kin_run(["graph", "status"], repo)
        text = out + "\n" + err
        info = {"raw": text, "rc": rc, "coverage": {}}
        for match in COVERAGE_LINE.finditer(text):
            info["coverage"][match.group("lang")] = {
                "files": int(match.group("files")),
                "calls_resolved": int(match.group("cres")),
                "calls_parsed": int(match.group("ctot")),
                "imports_resolved": (int(match.group("ires"))
                                     if match.group("ires") is not None else None),
                "imports_parsed": (int(match.group("itot"))
                                   if match.group("itot") is not None else None),
                "line": match.group(0).strip(),
            }
        head = re.search(r"Entities:\s*(\d+)", text)
        info["entities"] = int(head.group(1)) if head else None
        if info["entities"] is None:
            raise ProbeError("kin graph status rc=%d printed no entity counter: %s"
                             % (rc, text.strip()[-200:]))
        return info

    def sweep_gate(self, name):
        """Block recall assertions until the fixture's enrichment sweep provably ran.

        `kin init` has printed "complete (0/66 files)" over a sweep whose language
        server never started, and a recall check against that graph passes its
        negative controls vacuously: zero counted references contains no impostor.
        kin#985 made the sweep write a full accounting line, so this reads the
        fixture's own daemon.log and refuses the check unless some completed sweep
        enriched files and left nothing blocked, unvisited, or unaccounted.

        KNOWN EXPOSURE, unfixed on purpose: this trusts that every sweep line in a
        fixture's daemon.log describes THAT fixture. A daemon serving more than one
        store can write into one log; on 2026-08-20 a lane found 333 foreign lines in
        its own fixture's log, and this suite's requests log carried 216 mentions of
        other sessions' paths. Those were registry-identity warnings rather than sweep
        completions, and both sweep lines here matched the fixture's own file count, so
        the gate was not fooled. It could be: a foreign sweep completion would satisfy
        it. Binding a sweep line to its store needs a repo id the line does not carry,
        so the fix is a real change rather than a grep, and it is deliberately not being
        written at midnight on a release night. A
        build predating the accounting fields is exempt, so baseline comparison
        runs keep their historical semantics; the exemption is printed, never
        silent.
        """
        if name in self.sweep_gates:
            ok, detail = self.sweep_gates[name]
            if ok:
                return detail
            raise ProbeError(detail)
        repo = self.fixture(name)
        log_path = os.path.join(repo, ".kin", "daemon.log")
        # The daemon that ran init's sweep has usually exited by now, deleting
        # its port file, and a freshly spawned daemon's counters start at zero,
        # so the live /lsp/sweep/status endpoint is the wrong authority for a
        # post-init read. The store's own daemon.log carries the sweep's
        # accounting line durably. Init waits for its sweep, so one short retry
        # window covers filesystem lag, not sweep progress.
        deadline = time.time() + 10
        text = ""
        while True:
            try:
                with open(log_path) as handle:
                    text = handle.read()
            except OSError:
                text = ""
            if sweep_lines(text) or time.time() >= deadline:
                break
            time.sleep(1)
        ok, detail = sweep_verdict(sweep_lines(text))
        detail = "fixture %s: %s" % (name, detail)
        self.sweep_gates[name] = (ok, detail)
        print("kin-brownfield-repro: %s" % detail)
        if not ok:
            raise ProbeError(detail)
        return detail

    def references(self, name, query):
        repo = self.fixture(name)
        payload = self.cached(repo, "find_references", {"query": query})
        if not (payload.get("focal_entity") or {}).get("id"):
            negative = payload.get("negative") or {}
            raise ProbeError(
                "find_references(%s) resolved no focal entity (%s); an unresolved "
                "symbol and a symbol with no references are different facts"
                % (query, negative.get("trust_reason") or negative.get("kind")
                   or "no reason given"))
        return payload


def upstream_rows(payload):
    """Every entity the payload offers as an upstream, split by whether it counted.

    A build that counts a caller and a build that withholds it as a same-name
    candidate both mention the caller, so a check reading one array cannot tell
    them apart. Both arrays are returned, tagged.
    """
    counted = []
    withheld = []
    for row in payload.get("references") or []:
        if isinstance(row, dict):
            counted.append(row)
    for key in ("candidates", "name_candidates", "receiver_name_candidates"):
        for row in payload.get(key) or []:
            if isinstance(row, dict):
                withheld.append(row)
    return counted, withheld


def find_row(rows, wanted):
    for row in rows:
        if name_matches(row.get("name"), wanted):
            return row
    return None


def verdict_surfaces(payload):
    """The verdict blocks one payload carries, normalized to certify or refuse.

    Returns a dict of surface name to (verdict, evidence). `certify` means the
    surface asserts the answer is the whole set and may be acted on; `refuse` means
    it says the answer cannot be trusted as complete. A surface that is simply
    absent appears in neither, because "this payload made no claim" is a third fact
    and folding it into either would invent a verdict nothing stated.

    Under FIR-2463's fix shape the most pessimistic input wins, so a surface that
    admits it did not look, or that reports a class as unknown, counts as refusing
    rather than as saying nothing.
    """
    out = {}
    negative = payload.get("negative")
    if isinstance(negative, dict):
        safe = negative.get("safe_to_conclude_absent")
        trust = negative.get("trust")
        if safe is True or trust == "authoritative":
            out["negative"] = ("certify", "safe_to_conclude_absent=%r trust=%r"
                               % (safe, trust))
        elif safe is False or trust in ("inconclusive", "unreliable"):
            out["negative"] = ("refuse", "safe_to_conclude_absent=%r trust=%r"
                               % (safe, trust))
    # Kin publishes completeness inside the `_kin` envelope, not at the payload's
    # top level (entities.rs reads response["_kin"]["completeness"] in its own
    # tests). Reading only the top level made this surface dead code against every
    # real payload, so the three-block contradiction the stranger quoted was
    # invisible to check 5. The top-level read stays as a fallback for older
    # payload shapes.
    kin_envelope = payload.get("_kin")
    completeness = kin_envelope.get("completeness") if isinstance(kin_envelope, dict) else None
    if not isinstance(completeness, dict):
        completeness = payload.get("completeness")
    if isinstance(completeness, dict):
        status = completeness.get("status")
        bound = completeness.get("bound")
        if status == "complete" or bound == "exact":
            out["completeness"] = ("certify", "status=%r bound=%r"
                                   % (status, bound))
        elif status in ("partial", "incomplete", "unknown", "lower_bound"):
            out["completeness"] = ("refuse", "status=%r bound=%r" % (status, bound))
        classes = completeness.get("classes")
        if isinstance(classes, dict):
            absent = sorted(k for k, v in classes.items()
                            if v in ("absent", "unknown"))
            if absent:
                out["completeness.classes"] = (
                    "refuse", "classes not present: %s" % ", ".join(absent))
        limits = completeness.get("limits")
        if isinstance(limits, list):
            edge = [str(x) for x in limits if str(x).startswith("edge_coverage")]
            if edge:
                out["completeness.limits"] = (
                    "refuse", "limits: %s" % ", ".join(edge))
    coverage = payload.get("edge_coverage")
    if isinstance(coverage, dict):
        classes = coverage.get("classes")
        gaps = []
        if isinstance(classes, dict):
            missing = sorted(k for k, v in classes.items()
                             if v in ("absent", "unknown"))
            if missing:
                gaps.append("classes not present: %s" % ", ".join(missing))
        enrichment = coverage.get("reference_enrichment")
        if enrichment in ("unknown", "unsupported", "absent", "unprobed"):
            gaps.append("reference_enrichment=%r" % enrichment)
        scan = coverage.get("scan")
        if isinstance(scan, str) and scan.startswith("skipped"):
            gaps.append("scan=%r" % scan)
        if coverage.get("budget_exhausted") is True:
            gaps.append("budget_exhausted=True")
        if gaps:
            out["edge_coverage"] = ("refuse", "; ".join(gaps))
        elif classes or enrichment:
            out["edge_coverage"] = (
                "certify", "reference_enrichment=%r, every requested class present"
                % enrichment)
    return out


def surface_conflict(surfaces):
    """The certifying and refusing surfaces of one payload, when both exist."""
    certifying = sorted(k for k, (v, _e) in surfaces.items() if v == "certify")
    refusing = sorted(k for k, (v, _e) in surfaces.items() if v == "refuse")
    if certifying and refusing:
        return certifying, refusing
    return None, None


def trend_of(status, prior):
    """Where this check moved since the run being compared against.

    A prior run that could not be read reports `unknown` rather than `same`,
    because "no baseline" and "no change" are different facts and the second must
    never be inferred from the first.
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

    def note(self, detail):
        """Attributable context that decides nothing. Never a verdict."""
        self.asserts.append({"status": "NOTE", "detail": detail})

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
        graded = [a for a in self.asserts if a["status"] == PASS]
        return graded[-1]["detail"] if graded else "no assertion was reached"


# ---------------------------------------------------------------------- checks

def check_0(suite):
    """The run stays off the GPU and off every store but its own."""
    res = Result("0", "SUITE-GUARD", "no inference, no fleet store, own KIN_HOME")
    # The status probe runs first on purpose: `kin init` writes no daemon log, so a
    # read before any daemon has started finds no file and reports UNREADABLE on a
    # run whose opt-out was in fact honored.
    status = suite.graph_status("express")
    repo = suite.fixture("express")
    log = os.path.join(repo, ".kin", "daemon.log")
    if not os.path.exists(log):
        res.unknown("no daemon log at %s, cannot confirm the opt-out was honored" % log)
    else:
        deferred = 0
        with open(log, errors="replace") as handle:
            for line in handle:
                if AUTO_EMBED_OPT_OUT_LINE in strip_ansi(line):
                    deferred += 1
        if deferred == 0:
            res.bad("daemon log carries no %r line; embeddings may have run"
                    % AUTO_EMBED_OPT_OUT_LINE)
        else:
            res.ok("daemon logged the opt-out %d time(s)" % deferred)
    indexed = re.search(r"Embeddings:\s*(\d+)/(\d+)\s*indexed", status["raw"])
    if indexed and int(indexed.group(1)) != 0:
        res.bad("embeddings indexed=%s despite the opt-out" % indexed.group(1))
    elif indexed:
        res.ok("embeddings indexed=0/%s, so no inference ran" % indexed.group(2))
    else:
        res.unknown("graph status printed no embedding counter")
    if not os.path.realpath(suite.kin_home).startswith(
            os.path.realpath(suite.workdir)):
        res.bad("KIN_HOME %s is outside the run workdir" % suite.kin_home)
    else:
        res.ok("scratch KIN_HOME %s" % suite.kin_home)
    # Attributable context, not a verdict. FIR-2464 established that the npm-0541
    # container carried no language server at all, so Python enrichment never ran
    # there. A failure below is a different fact depending on this line.
    present = [name for name in LANGUAGE_SERVERS if shutil.which(name)]
    res.note("language servers on PATH: %s"
             % (", ".join(present) if present else "none"))
    return res


def check_1(suite):
    """FIR-2441: JavaScript import specifiers resolve, so imports are above zero.

    The positive control. This is the one grep-flip fix the stranger confirmed
    working on shipped bytes, and it is what proves the suite can report a pass.
    A pre-FIR-2441 binary reports `imports 0/305 (0%)` on this same fixture.
    """
    res = Result("1", "FIR-2441", "express resolves JavaScript imports above zero")
    status = suite.graph_status("express")
    js = status["coverage"].get("javascript")
    if js is None:
        res.unknown("graph status printed no javascript reference-edge coverage line")
        return res
    if js["imports_resolved"] is None:
        res.unknown("javascript coverage line carries no imports counter: %s"
                    % js["line"])
        return res
    if js["imports_parsed"] == 0:
        res.unknown("javascript coverage parsed zero imports, so the ratio says "
                    "nothing: %s" % js["line"])
        return res
    if js["imports_resolved"] > 0:
        res.ok("%d of %d javascript imports resolved (%s)"
               % (js["imports_resolved"], js["imports_parsed"], js["line"]))
    else:
        res.bad("0 of %d javascript imports resolved: %s"
                % (js["imports_parsed"], js["line"]))
    return res


def check_2(suite):
    """FIR-2464: the first real caller of HTTPAdapter.send counts as one.

    src/requests/sessions.py:784 is `r = adapter.send(request, **kwargs)` inside
    Session.send. On shipped v0.5.42 that caller was demoted to the candidates
    array as name_only and excluded, leaving total_upstream 0 on a response that
    held the answer.
    """
    res = Result("2", "FIR-2464", "Session.send counts as a real caller of "
                                  "HTTPAdapter.send")
    try:
        suite.sweep_gate("requests")
        payload = suite.references("requests", HTTPADAPTER_SEND)
    except ProbeError as exc:
        res.unknown(str(exc))
        return res
    counted, withheld = upstream_rows(payload)
    total = payload.get("total_upstream")
    counted_row = find_row(counted, REAL_CALLER_ONE)
    withheld_row = find_row(withheld, REAL_CALLER_ONE)
    if counted_row is not None:
        lines = counted_row.get("reference_lines") or []
        if REAL_CALLER_ONE_LINE in lines:
            res.ok("%s counted as a reference with reference_lines %s"
                   % (REAL_CALLER_ONE, lines))
        else:
            res.bad("%s is counted but its reference_lines are %s, not the call site "
                    "at %s:%d"
                    % (REAL_CALLER_ONE, lines or "[]", REAL_CALLER_ONE_FILE,
                       REAL_CALLER_ONE_LINE))
        if counted_row.get("resolution") == "name_only":
            res.bad("%s is counted but still resolution=name_only, so the count "
                    "rests on a bare-name match" % REAL_CALLER_ONE)
    elif withheld_row is not None:
        res.bad("%s is withheld as a same-name candidate (resolution=%r, "
                "reference_lines=%s) and excluded from total_upstream=%r; the real "
                "call site is %s:%d"
                % (REAL_CALLER_ONE, withheld_row.get("resolution"),
                   withheld_row.get("reference_lines") or "[]", total,
                   REAL_CALLER_ONE_FILE, REAL_CALLER_ONE_LINE))
    else:
        res.bad("%s appears in neither references nor candidates; total_upstream=%r, "
                "counted=%d, withheld=%d"
                % (REAL_CALLER_ONE, total, len(counted), len(withheld)))
    if isinstance(total, int) and total < 1:
        res.bad("total_upstream=%d on a symbol with a real caller at %s:%d"
                % (total, REAL_CALLER_ONE_FILE, REAL_CALLER_ONE_LINE))
    elif not isinstance(total, int):
        res.unknown("total_upstream is %r, not an integer" % (total,))
    # The negative control. Every name below is a bare-name match on `send` and
    # calls no HTTPAdapter. Counting one is fabrication, not coverage.
    fabricated = sorted({row.get("name") for row in counted
                         if row.get("name") in FABRICATED_SEND_CALLERS})
    if fabricated:
        res.bad("counted as real callers by bare-name match: %s"
                % ", ".join(fabricated))
    else:
        res.ok("no known bare-name impostor counted as a caller")
    return res


def check_3(suite):
    """FIR-2464: the second real caller, reached through a two-hop receiver.

    src/requests/auth.py:312 is `_r = r.connection.send(prep, **kwargs)` inside
    HTTPDigestAuth.handle_401, and r.connection is always an HTTPAdapter here. The
    shipped extractor emitted a bare-name candidate for the one-hop receiver
    `adapter.send` and nothing at all for this two-hop one, so the
    receiver_name_candidates degradation could not even count what it never made.
    """
    res = Result("3", "FIR-2464", "HTTPDigestAuth.handle_401 reaches "
                                  "HTTPAdapter.send through r.connection")
    try:
        suite.sweep_gate("requests")
        payload = suite.references("requests", HTTPADAPTER_SEND)
    except ProbeError as exc:
        res.unknown(str(exc))
        return res
    counted, withheld = upstream_rows(payload)
    counted_row = find_row(counted, REAL_CALLER_TWO)
    withheld_row = find_row(withheld, REAL_CALLER_TWO)
    if counted_row is not None:
        lines = counted_row.get("reference_lines") or []
        if REAL_CALLER_TWO_LINE in lines:
            res.ok("%s counted with reference_lines %s" % (REAL_CALLER_TWO, lines))
        else:
            res.bad("%s is counted but its reference_lines are %s, not the call site "
                    "at %s:%d" % (REAL_CALLER_TWO, lines or "[]",
                                  REAL_CALLER_TWO_FILE, REAL_CALLER_TWO_LINE))
    elif withheld_row is not None:
        res.bad("%s exists only as a withheld candidate (resolution=%r); the two-hop "
                "receiver call at %s:%d is real and must count"
                % (REAL_CALLER_TWO, withheld_row.get("resolution"),
                   REAL_CALLER_TWO_FILE, REAL_CALLER_TWO_LINE))
    else:
        res.bad("%s appears nowhere in the payload, not even as a candidate; the "
                "extractor emits no edge at all for the two-hop receiver "
                "r.connection.send at %s:%d"
                % (REAL_CALLER_TWO, REAL_CALLER_TWO_FILE, REAL_CALLER_TWO_LINE))
    return res


def check_4(suite):
    """FIR-2464: express cross-file edges are real, and the one that matters is there.

    trace_data_flow on app.handle, direction calls, depth 2 returned eleven steps on
    shipped bytes. Two were real (app.enabled at lib/application.js:160 and
    finalhandler at :154). Nine were fabricated, all descended from bare-name
    matching the single `this.get('env')` call. The hand-off the question is about,
    this.router.handle at lib/application.js:177, was absent from the walk entirely.
    """
    res = Result("4", "FIR-2464", "express app.handle walk carries the real edges "
                                  "and no fabricated ones")
    repo = suite.fixture("express")
    try:
        suite.sweep_gate("express")
        # limit_per_step is raised to its cap and bodies are dropped on purpose. At
        # the default of 5 this walk clips one of app.handle's own callees and the
        # response comes back truncated, so an absent edge cannot be told from a
        # dropped one, and the check's central assertion would be measuring a budget
        # rather than the graph.
        payload = suite.cached(repo, "trace_data_flow",
                               {"focal": APP_HANDLE, "direction": "calls",
                                "depth": 2, "include_body": False,
                                "limit_per_step": 25, "max_chars": 200000})
    except ProbeError as exc:
        res.unknown(str(exc))
        return res
    steps = None
    for key in ("chain", "steps", "flow", "path"):
        if isinstance(payload.get(key), list):
            steps = payload[key]
            break
    if not isinstance(steps, list):
        res.unknown("trace_data_flow payload carries no step list; keys are %s"
                    % sorted(payload.keys()))
        return res
    if not steps:
        res.unknown("trace_data_flow on %s returned zero steps, so neither the real "
                    "edges nor the fabricated ones can be judged" % APP_HANDLE)
        return res
    if payload.get("truncated") or payload.get("clipped_steps"):
        res.unknown("the walk came back truncated (truncated=%r, clipped_steps=%r), "
                    "so an absent edge cannot be told from a dropped one"
                    % (payload.get("truncated"), payload.get("clipped_steps")))
        return res

    def step_name(step):
        if not isinstance(step, dict):
            return ""
        for key in ("entity_name", "callee", "name", "target_name", "to"):
            value = step.get(key)
            if isinstance(value, str) and value:
                return value
            if isinstance(value, dict) and value.get("name"):
                return value["name"]
        return ""

    def counted_step(step):
        """A step the answer stands behind, as opposed to one it disclaims.

        A build that keeps a fabricated edge but labels it name_only and excludes
        it from the count has done what the fix asks. One that keeps it in the
        counted flow has not. Distinguishing them is the whole point of this check.
        """
        if not isinstance(step, dict):
            return False
        if step.get("resolution") == "name_only":
            return False
        if step.get("proven") is False or step.get("unproven") is True:
            return False
        return True

    named = [(step_name(s), s) for s in steps]
    counted = [(n, s) for n, s in named if counted_step(s)]
    all_names = [n for n, _s in named]

    def descent(step):
        """How a step got here, so a counted one names the edge that carried it.

        A step whose own edge resolved by type but whose parent did not is still
        fabricated: the walk reached it only through the parent's bad guess. Saying
        so in the failure is the difference between a lane fixing the resolver and a
        lane fixing the wrong step.
        """
        # parent_step is 1-based with 0 meaning the focal, while `named` is
        # 0-indexed over steps; indexing named[parent] misattributed every parent
        # by one (reported app.set as reached through req.get when parent_step=1
        # means app.enabled).
        parent = step.get("parent_step")
        if not isinstance(parent, int) or parent < 0 or parent > len(named):
            return "resolution=%r at depth %r" % (step.get("resolution"),
                                                  step.get("depth"))
        if parent == 0:
            return ("resolution=%r, reached directly from the focal %s"
                    % (step.get("resolution"), APP_HANDLE))
        return "resolution=%r, reached through %s" % (step.get("resolution"),
                                                      named[parent - 1][0]
                                                      or "step %d" % parent)

    fabricated_counted = sorted({"%s (%s)" % (n, descent(s)) for n, s in counted
                                 if any(name_matches(n, f)
                                        for f in APP_HANDLE_FABRICATED)})
    if fabricated_counted:
        res.bad("counted steps include fabricated callees %s; %d of %d steps counted, "
                "unproven_steps=%r"
                % ("; ".join(fabricated_counted), len(counted), len(steps),
                   payload.get("unproven_steps")))
    else:
        res.ok("no fabricated callee is counted (%d of %d steps counted)"
               % (len(counted), len(steps)))
    missing_real = [want for want in APP_HANDLE_REAL_CALLEES
                    if not any(name_matches(n, want) for n in all_names)]
    if missing_real:
        res.bad("the real callees %s are absent from the walk; steps are %s"
                % (", ".join(missing_real), all_names[:12]))
    else:
        res.ok("both real callees %s are present"
               % ", ".join(APP_HANDLE_REAL_CALLEES))
    if any(name_matches(n, APP_HANDLE_MISSING_CALLEE)
           or basename_of(n) == "handle" for n in all_names):
        res.ok("the hand-off %s is in the walk" % APP_HANDLE_MISSING_CALLEE)
    else:
        res.bad("the hand-off this.router.handle at %s:177, the last line of "
                "app.handle and the edge the question is about, is absent from the "
                "walk; steps are %s" % (APP_HANDLE_FILE, all_names[:12]))
    return res


def check_5(suite):
    """FIR-2463: one payload, one verdict.

    On shipped bytes a single find_references response on an express export said
    negative.safe_to_conclude_absent false and trust inconclusive, while its own
    completeness block said status complete, bound exact, counted.exact true, and a
    note reading "Every edge class this answer depended on was observed present",
    sitting directly above a classes map marking imports and references absent and a
    limits array naming three edge_coverage gaps. An agent reading completeness acts;
    an agent reading negative does not. The fix is one verdict, most pessimistic
    input wins.
    """
    res = Result("5", "FIR-2463", "one payload reaches one verdict")
    express = suite.fixture("express")
    requests = suite.fixture("requests")
    probes = [
        ("express find_references(%s)" % EXPRESS_EXPORT,
         express, "find_references", {"query": EXPRESS_EXPORT}),
        ("requests find_references(%s)" % HTTPADAPTER_SEND,
         requests, "find_references", {"query": HTTPADAPTER_SEND}),
        ("requests semantic_search(%r, kind=%r)" % (PY_SEARCH_QUERY, PY_SEARCH_KIND),
         requests, "semantic_search",
         {"query": PY_SEARCH_QUERY, "kind": PY_SEARCH_KIND}),
    ]
    graded = 0
    for label, repo, tool, args in probes:
        try:
            payload = suite.cached(repo, tool, args)
        except ProbeError as exc:
            res.unknown("%s unreadable: %s" % (label, exc))
            continue
        surfaces = verdict_surfaces(payload)
        if not surfaces:
            res.unknown("%s carries no readable verdict surface; keys are %s"
                        % (label, sorted(payload.keys())))
            continue
        if len(surfaces) < 2:
            res.unknown("%s carries only one verdict surface (%s), so disagreement "
                        "cannot be observed" % (label, ", ".join(surfaces)))
            continue
        graded += 1
        certifying, refusing = surface_conflict(surfaces)
        if certifying:
            res.bad("%s: %s certif%s (%s) while %s refuse%s (%s)"
                    % (label, ", ".join(certifying),
                       "ies" if len(certifying) == 1 else "y",
                       "; ".join(surfaces[k][1] for k in certifying),
                       ", ".join(refusing), "s" if len(refusing) == 1 else "",
                       "; ".join(surfaces[k][1] for k in refusing)))
        else:
            res.ok("%s: all %d surfaces agree (%s)"
                   % (label, len(surfaces),
                      "; ".join("%s %s" % (k, surfaces[k][1])
                                for k in sorted(surfaces))))
    if graded == 0:
        res.unknown("no probe produced two comparable verdict surfaces")
    return res


def check_6(suite):
    """FIR-2463: two surfaces, one graph, one question, one verdict.

    On shipped bytes find_references on HTTPAdapter.send refused to certify its
    zero, while graph_neighborhood direction in on the same entity framed the same
    two inbound edges as complete, exact, "the whole set", carrying no negative
    object and no hedge. Whichever tool you reach for first decides what you believe.
    """
    res = Result("6", "FIR-2463", "find_references and graph_neighborhood agree on "
                                  "one entity")
    repo = suite.fixture("requests")
    try:
        refs = suite.references("requests", HTTPADAPTER_SEND)
    except ProbeError as exc:
        res.unknown("find_references leg unreadable: %s" % exc)
        return res
    # graph_neighborhood takes an entity UUID and no name, so the focal id comes
    # from the find_references leg. Both legs then provably describe one entity,
    # which is what makes their disagreement a disagreement rather than two answers
    # about two things.
    focal_id = (refs.get("focal_entity") or {}).get("id")
    try:
        hood = suite.cached(repo, "graph_neighborhood",
                            {"entity_id": focal_id, "direction": "in"})
    except ProbeError as exc:
        res.unknown("graph_neighborhood leg unreadable: %s" % exc)
        return res
    if "message" in hood and not hood.get("relations"):
        res.unknown("graph_neighborhood returned an error payload: %s"
                    % str(hood.get("message"))[:200])
        return res
    ref_surfaces = verdict_surfaces(refs)
    hood_surfaces = verdict_surfaces(hood)
    if not ref_surfaces:
        res.unknown("find_references payload carries no readable verdict surface")
        return res
    if not hood_surfaces:
        res.bad("graph_neighborhood on %s walked %r entities over %r relations and "
                "carries no verdict surface at all, while find_references on the "
                "same entity reports %s; an answer with no epistemic claim is not "
                "agreement, it is a missing one"
                % (HTTPADAPTER_SEND, hood.get("entity_count"),
                   hood.get("relation_count"),
                   "; ".join("%s %s" % (k, v[1])
                             for k, v in sorted(ref_surfaces.items()))))
        return res
    ref_verdicts = {v for v, _e in ref_surfaces.values()}
    hood_verdicts = {v for v, _e in hood_surfaces.values()}
    if ref_verdicts != hood_verdicts:
        res.bad("the two tools reach opposite verdicts on %s: find_references says "
                "%s (%s) while graph_neighborhood says %s (%s)"
                % (HTTPADAPTER_SEND,
                   "/".join(sorted(ref_verdicts)),
                   "; ".join("%s %s" % (k, v[1])
                             for k, v in sorted(ref_surfaces.items())),
                   "/".join(sorted(hood_verdicts)),
                   "; ".join("%s %s" % (k, v[1])
                             for k, v in sorted(hood_surfaces.items()))))
    else:
        res.ok("both tools reach %s on %s"
               % ("/".join(sorted(ref_verdicts)), HTTPADAPTER_SEND))
    return res


def check_7(suite):
    """FIR-2464: an express export nothing certifies as unused.

    Ten exports live in lib/express.js and the stranger's classic arm proved none
    of them is dead. Kin called four dead. exports.Router carries 32 in-repo hits,
    the first at examples/multi-router/controllers/api_v1.js:5, so certifying its
    absence is the delete-what-Kin-called-safe case with the widest blast radius.
    """
    res = Result("7", "FIR-2464", "express exports.Router is not certified unused")
    repo = suite.fixture("express")
    try:
        suite.sweep_gate("express")
        payload = suite.cached(repo, "find_references", {"query": EXPRESS_EXPORT})
    except ProbeError as exc:
        res.unknown(str(exc))
        return res
    if not (payload.get("focal_entity") or {}).get("id"):
        res.unknown("find_references(%s) resolved no focal entity, so neither its "
                    "references nor its absence claim can be judged" % EXPRESS_EXPORT)
        return res
    counted, withheld = upstream_rows(payload)
    total = payload.get("total_upstream")
    negative = payload.get("negative") or {}
    if negative.get("safe_to_conclude_absent") is True:
        res.bad("%s (%s:%d) is certified absent (trust=%r) on a symbol with 32 "
                "in-repo hits, the first at "
                "examples/multi-router/controllers/api_v1.js:5"
                % (EXPRESS_EXPORT, EXPRESS_EXPORT_FILE, EXPRESS_EXPORT_LINE,
                   negative.get("trust")))
    if counted:
        res.ok("%s carries %d counted reference(s), total_upstream=%r"
               % (EXPRESS_EXPORT, len(counted), total))
    else:
        res.bad("%s carries zero counted references (total_upstream=%r, %d withheld "
                "candidate(s)) on a symbol used 32 times in this repository"
                % (EXPRESS_EXPORT, total, len(withheld)))
    return res


def check_8(suite):
    """FIR-2463 and FIR-2452: a certified absence has to be true.

    Session.request is a method at src/requests/sessions.py:557. On shipped bytes
    semantic_search under a kind filter answered zero for it and certified that zero
    as authoritative, on the same graph where find_references refuses to certify
    anything. The two answers are decided by which internal route ran rather than by
    what is knowable: the search path takes a scan shortcut and reports its
    reference enrichment as unknown, then certifies anyway.
    """
    res = Result("8", "FIR-2463", "semantic_search does not certify a false absence")
    repo = suite.fixture("requests")
    try:
        payload = suite.cached(repo, "semantic_search",
                               {"query": PY_SEARCH_QUERY, "kind": PY_SEARCH_KIND})
    except ProbeError as exc:
        res.unknown(str(exc))
        return res
    results = payload.get("results")
    if not isinstance(results, list):
        res.unknown("semantic_search payload carries no results list; keys are %s"
                    % sorted(payload.keys()))
        return res
    negative = payload.get("negative") or {}
    certified = (negative.get("safe_to_conclude_absent") is True
                 or negative.get("trust") == "authoritative")
    if results:
        names = entity_names(results)
        if any(name_matches(n, PY_KNOWN_METHOD) for n in names):
            res.ok("semantic_search found %s among %d result(s)"
                   % (PY_KNOWN_METHOD, len(results)))
        else:
            res.ok("semantic_search returned %d result(s) and certified nothing "
                   "absent" % len(results))
        if certified:
            res.bad("semantic_search returned %d result(s) and still reports "
                    "safe_to_conclude_absent=%r trust=%r"
                    % (len(results), negative.get("safe_to_conclude_absent"),
                       negative.get("trust")))
        return res
    coverage = payload.get("edge_coverage") or {}
    if certified:
        res.bad("semantic_search(%r, kind=%r) returned zero and certified it "
                "(safe_to_conclude_absent=%r, trust=%r, advice %r) while %s is a "
                "method at %s:%d; its own edge_coverage says scan=%r and "
                "reference_enrichment=%r, so it certified a question it did not ask"
                % (PY_SEARCH_QUERY, PY_SEARCH_KIND,
                   negative.get("safe_to_conclude_absent"), negative.get("trust"),
                   str(negative.get("advice"))[:120], PY_KNOWN_METHOD,
                   PY_KNOWN_METHOD_FILE, PY_KNOWN_METHOD_LINE,
                   coverage.get("scan"), coverage.get("reference_enrichment")))
    else:
        res.ok("semantic_search returned zero and refused to certify it "
               "(safe_to_conclude_absent=%r, trust=%r)"
               % (negative.get("safe_to_conclude_absent"), negative.get("trust")))
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
]


def self_test():
    """Exercise the graders on fixed payloads, with no binary and no corpus.

    Every verdict this suite reports is decided by verdict_surfaces, name_matches
    and Result.status. A grader that cannot distinguish its own cases would report
    a clean product on a broken one, so each case below is paired with its inverse:
    the payloads are the literal shapes the npm-0541 run and this build produced,
    and the assertions require the grader to answer differently on each.
    """
    failures = []

    def expect(label, got, want):
        if got != want:
            failures.append("%s: got %r, wanted %r" % (label, got, want))

    # The shipped v0.5.42 find_references shape: negative refuses, completeness
    # certifies. One payload, two verdicts, which is the defect FIR-2463 names.
    shipped = {
        "negative": {"safe_to_conclude_absent": False, "trust": "inconclusive"},
        "completeness": {
            "bound": "exact", "status": "complete",
            "classes": {"calls": "present", "imports": "absent",
                        "references": "absent"},
            "limits": ["edge_coverage:imports_absent",
                       "edge_coverage:reference_enrichment_unsupported"],
        },
    }
    certifying, refusing = surface_conflict(verdict_surfaces(shipped))
    expect("shipped payload conflict certifying", certifying, ["completeness"])
    expect("shipped payload conflict refusing", refusing,
           ["completeness.classes", "completeness.limits", "negative"])

    # The semantic_search shape this build still produces: negative certifies while
    # edge_coverage admits it took a shortcut.
    search = {
        "negative": {"safe_to_conclude_absent": True, "trust": "authoritative"},
        "edge_coverage": {"classes": {}, "reference_enrichment": "unknown",
                          "scan": "skipped_no_edge_dependency"},
    }
    certifying, refusing = surface_conflict(verdict_surfaces(search))
    expect("search payload certifying", certifying, ["negative"])
    expect("search payload refusing", refusing, ["edge_coverage"])

    # The inverse: one verdict, agreed. The grader must NOT report a conflict here,
    # or every fixed build would still read as broken.
    agreed = {
        "negative": {"safe_to_conclude_absent": False, "trust": "inconclusive"},
        "edge_coverage": {"classes": {"calls": "present", "imports": "absent"},
                          "reference_enrichment": "unsupported", "scan": "ran"},
    }
    certifying, _refusing = surface_conflict(verdict_surfaces(agreed))
    expect("agreed payload reports no conflict", certifying, None)

    # A payload carrying no verdict block at all yields no surfaces, so a check
    # reports UNREADABLE rather than inventing agreement out of silence.
    expect("silent payload has no surfaces", verdict_surfaces({"entities": []}), {})

    expect("bare name matches qualified", name_matches("Session.send", "send"), True)
    expect("qualified matches bare", name_matches("send", "Session.send"), True)
    expect("siblings do not match", name_matches("req.get", "res.get"), False)
    expect("empty never matches", name_matches("", "send"), False)

    counted, withheld = upstream_rows(
        {"references": [{"name": "A"}],
         "candidates": [{"name": "B", "resolution": "name_only"}]})
    expect("counted rows", entity_names(counted), ["A"])
    expect("withheld rows", entity_names(withheld), ["B"])

    res = Result("t", "T", "t")
    res.ok("fine")
    res.note("context only")
    expect("a note never decides a result", res.status, PASS)
    res.unknown("cannot read")
    expect("unreadable outranks pass", res.status, UNREADABLE)
    res.bad("broken")
    expect("fail outranks unreadable", res.status, FAIL)
    expect("the deciding detail is the failure", res.detail, "broken")
    expect("an empty result is unreadable, not a pass",
           Result("t", "T", "t").status, UNREADABLE)
    expect("a result holding only notes is unreadable",
           (lambda r: (r.note("x"), r.status)[1])(Result("t", "T", "t")), UNREADABLE)

    expect("no baseline is not no change", trend_of(FAIL, None), "unknown")
    expect("pass to fail is a regression", trend_of(FAIL, PASS), "regression")
    expect("fail to pass is fixed", trend_of(PASS, FAIL), "fixed")

    # The recall gate's predicate, every refusal beside its passing inverse. The
    # lines are the literal accounting shapes 985-era daemons wrote on this
    # machine, including the one that hid a dead JS server behind a clean exit.
    clean = ("LSP cold sweep complete files=37 total_files=37 relations=4441 "
             "enriched=37 already_enriched=0 unsupported_language=0 "
             "server_unavailable=0 source_unreadable=0 not_visited=0 "
             "ended_early=false unaccounted=0")
    dead_server = clean.replace("enriched=37", "enriched=0").replace(
        "server_unavailable=0", "server_unavailable=37").replace(
        "relations=4441", "relations=0")
    expect("a clean converged sweep admits recall",
           sweep_verdict(sweep_lines(clean))[0], True)
    expect("a dead-server sweep refuses recall",
           sweep_verdict(sweep_lines(dead_server))[0], False)
    expect("an interrupted sweep refuses recall",
           sweep_verdict(sweep_lines(clean.replace(
               "ended_early=false", "ended_early=true")))[0], False)
    expect("an unvisited remainder refuses recall",
           sweep_verdict(sweep_lines(clean.replace(
               "not_visited=0", "not_visited=5")))[0], False)
    expect("a nothing-enriched sweep refuses recall",
           sweep_verdict(sweep_lines(clean.replace(
               "enriched=37", "enriched=0")))[0], False)
    expect("an empty log refuses recall", sweep_verdict([])[0], False)
    expect("one clean line among dead ones admits recall",
           sweep_verdict(sweep_lines(dead_server + "\n" + clean))[0], True)
    pre985 = "LSP cold sweep complete files=37 total_files=37 relations=4441"
    ok985, detail985 = sweep_verdict(sweep_lines(pre985))
    expect("a pre-tally line exempts rather than refuses", ok985, True)
    expect("the exemption says so out loud",
           "not enforceable" in detail985, True)
    ansi_clean = "\x1b[32mINFO\x1b[0m kin_daemon::daemon: " + clean
    expect("ANSI colour never hides a clean sweep",
           sweep_verdict(sweep_lines(ansi_clean))[0], True)

    for line in failures:
        print("SELF-TEST FAIL %s" % line)
    print("kin-brownfield-repro: self-test %s"
          % ("FAILED (%d)" % len(failures) if failures else "passed"))
    return 1 if failures else 0


def main(argv):
    parser = argparse.ArgumentParser(
        add_help=True, description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--kin", default=os.environ.get("KIN_BIN"),
                        help="kin binary under test (or KIN_BIN); "
                             "cargo build --bin kin --bin kin-daemon builds one")
    parser.add_argument("--daemon",
                        help="kin-daemon binary to serve the fixtures "
                             "(default: the sibling of --kin when one exists)")
    parser.add_argument("--workdir")
    parser.add_argument("--corpus-cache",
                        default=os.path.expanduser("~/.cache/kin-brownfield-repro"))
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--label", default="")
    parser.add_argument("--only", default="")
    parser.add_argument("--json", dest="json_out")
    parser.add_argument("--compare")
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--self-test", action="store_true",
                        help="exercise the verdict graders on fixed payloads and "
                             "exit; needs no kin binary and no corpus")
    opts = parser.parse_args(argv)

    if opts.self_test:
        return self_test()

    if not opts.kin:
        sys.stderr.write("no kin binary: pass --kin or set KIN_BIN "
                         "(cargo build --bin kin --bin kin-daemon produces one)\n")
        return 3
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

    workdir = opts.workdir or tempfile.mkdtemp(prefix="kin-brownfield-repro-")
    if not os.path.isdir(workdir):
        os.makedirs(workdir)
    corpus_cache = os.path.abspath(os.path.expanduser(opts.corpus_cache))
    if not os.path.isdir(corpus_cache):
        os.makedirs(corpus_cache)
    wanted = [w.strip() for w in opts.only.split(",") if w.strip()] or None

    suite = Suite(kin, workdir, corpus_cache, daemon=daemon, offline=opts.offline,
                  verbose=opts.verbose)
    print("kin-brownfield-repro: %s" % NON_CITABLE)
    print("kin-brownfield-repro: %s" % FIXTURE_SCOPE)
    print("kin-brownfield-repro: %s" % version)
    print("kin-brownfield-repro: binary %s" % kin)
    print("kin-brownfield-repro: daemon %s" % (daemon or "(resolved by kin itself)"))
    print("kin-brownfield-repro: workdir %s" % workdir)
    print("kin-brownfield-repro: corpus cache %s%s"
          % (corpus_cache, " (offline)" if opts.offline else ""))
    for name in sorted(CORPORA):
        spec = CORPORA[name]
        print("kin-brownfield-repro: corpus %s %s commit %s tree %s"
              % (name, spec["url"], spec["commit"], spec["tree"]))

    prior = {}
    prior_label = ""
    if opts.compare:
        try:
            with open(opts.compare) as handle:
                loaded = json.load(handle)
            prior_label = loaded.get("label") or os.path.basename(opts.compare)
            prior = {row["id"]: row.get("status") for row in loaded.get("results", [])}
            print("kin-brownfield-repro: comparing against %s (%s)"
                  % (prior_label, opts.compare))
        except (IOError, ValueError, KeyError) as exc:
            # An unreadable baseline must not silently become "no regressions".
            print("kin-brownfield-repro: comparison baseline unreadable (%s): %s"
                  % (opts.compare, exc))
            prior = None

    results = []
    for check_id, fn in CHECKS:
        if wanted and check_id not in wanted:
            continue
        try:
            res = fn(suite)
        except ProbeError as exc:
            res = Result(check_id, "?", "probe failure")
            res.unknown(str(exc)[:300])
        except Exception as exc:
            res = Result(check_id, "?", "harness failure")
            res.unknown("%s: %s" % (type(exc).__name__, str(exc)[:300]))
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
        print("kin-brownfield-repro: stopped %d fixture daemon(s)" % len(stopped))

    failed = [r for r in results if r.status == FAIL]
    unread = [r for r in results if r.status == UNREADABLE]
    regressed = [r for r in results if r.trend == "regression"]
    print("kin-brownfield-repro: %d pass, %d fail, %d unreadable"
          % (len(results) - len(failed) - len(unread), len(failed), len(unread)))
    if regressed:
        print("kin-brownfield-repro: %d regression(s) against %s: %s"
              % (len(regressed), prior_label,
                 ", ".join("%s/%s" % (r.id, r.ticket) for r in regressed)))
    print("kin-brownfield-repro: %s" % NON_CITABLE)
    print("kin-brownfield-repro: %s" % FIXTURE_SCOPE)

    if opts.json_out:
        with open(opts.json_out, "w") as handle:
            json.dump({"citable": False, "lane": "DEV-LOCAL",
                       "fixture_scope": FIXTURE_SCOPE,
                       "label": opts.label, "kin": kin, "version": version,
                       "workdir": workdir, "daemon": daemon,
                       "corpora": CORPORA,
                       "compared_against": prior_label,
                       "results": [{"id": r.id, "ticket": r.ticket, "title": r.title,
                                    "status": r.status, "detail": r.detail,
                                    "prior_status": r.prior, "trend": r.trend,
                                    "asserts": r.asserts} for r in results]},
                      handle, indent=2)
        print("kin-brownfield-repro: json %s" % opts.json_out)

    if not opts.keep and not opts.workdir:
        shutil.rmtree(workdir, ignore_errors=True)

    if failed:
        return 1
    if unread:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
