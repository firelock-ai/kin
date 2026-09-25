#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
"""NON-CITABLE acceptance suite: a store the last published release wrote serves.

Its output is a regression gate, never proof, never investor-facing and never a
released claim. It shares the CHECK line format, the exit codes and the
`--self-test` discipline of its siblings in this directory.

What it is for
--------------
Someone upgrading Kin keeps the store the previous release wrote. On the v0.8.0
candidate such a store never served when it held edits no commit had recorded,
which is the ordinary state of a working copy mid-edit. The daemon's startup
repair ran one pass per cause: the owed parses, the entities a stopped daemon
never published, and the declarations the older parser minted differently. Each
pass read the other causes' files through the strict dependency reader and was
refused by them, the repair reported incomplete, and the daemon exited without
publishing its endpoint. A store the candidate wrote itself opened fine, so no
suite that builds its store with the binary under test could see it.

So this one builds its store with the PUBLISHED release. It downloads the
release archive, checks it against a pinned SHA-256, runs that release's own
`kin init` on a small Rust, Python and JavaScript repository, edits three files
without committing, lets that release's daemon admit the edits, and stops it.
Then the binary under test opens the store.

    serve       the daemon under test publishes its endpoint within the bound
    disclosure  `kin status` names the start's re-derivation
    answer      the uncommitted edit's new declaration answers at its current line

The fixture carries its own control. A published build that left no owed parse
behind did not produce the upgrade state this suite is about, so every check
reads UNREADABLE rather than PASS over a store that could not have failed.

Each check prints:

    CHECK <id> <topic> PASS|FAIL|UNREADABLE <detail>

Exit status is 1 when any check fails, 2 when none fail but some are
unreadable, 3 on a setup failure, and 0 only when every check passes.
`--self-test` drives every grader against its inverse without a binary.

The binary under test
---------------------
    cargo build --release --locked --bin kin --bin kin-daemon
    python3 scripts/acceptance/published_store_upgrade_repro.py --kin target/release/kin

`--published-kin` takes an already unpacked published `kin` (its `kin-daemon`
beside it) instead of downloading one.
"""

from __future__ import print_function

import argparse
import functools
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request

print = functools.partial(print, flush=True)

PASS = "PASS"
FAIL = "FAIL"
UNREADABLE = "UNREADABLE"
TOPIC = "published-store-upgrade"

PUBLISHED_VERSION = "0.7.21"
RELEASE_URL = "https://github.com/firelock-ai/kin/releases/download/v%s/%s"
# The release's own checksums-sha256.txt, pinned so a replaced asset fails here
# instead of grading the binary under test against a store nobody published.
PUBLISHED_ARCHIVES = {
    ("Linux", "x86_64"): (
        "kin-linux-x86_64.tar.gz",
        "c6dd7caa442594487578adbd45ec794622d1fb1353bb32c4d542e62291cfdb0d",
    ),
    ("Linux", "aarch64"): (
        "kin-linux-aarch64.tar.gz",
        "a4c5291c97fa53b0eb19aa490c489662e8516f74deedf149bcd60f05966b9f8e",
    ),
    ("Darwin", "arm64"): (
        "kin-macos-aarch64.tar.gz",
        "48336290b92e633235f393b6c811f498c99bc53f83fcd1056ff21eb9209466c7",
    ),
    ("Darwin", "x86_64"): (
        "kin-macos-x86_64.tar.gz",
        "6a18d7c176ad9950ca6615d9e36f4681d5fa724955575dd969c657c4fc4e3c4e",
    ),
}

# Generous, because the runner is shared and a debug of this suite should not
# chase load. The failure it exists for is not slowness: the daemon exited
# with a refusal after its repair, so a start that serves at all within two
# minutes on a twelve-file store is the property under test.
SERVE_BOUND_SECONDS = 120

FIXTURE = {
    "Cargo.toml": '[package]\nname = "fixture"\nversion = "0.1.0"\nedition = "2021"\n',
    "src/lib.rs": "mod util;\n\npub use util::helper;\n\n"
                  "pub fn entry(value: u32) -> u32 {\n    helper(value) + 1\n}\n",
    "src/util.rs": "pub fn helper(value: u32) -> u32 {\n    value * 2\n}\n",
    "pkg/__init__.py": "",
    "pkg/a.py": "from pkg.b import double\n\n\ndef run(value):\n    return double(value) + 1\n",
    "pkg/b.py": "def double(value):\n    return value * 2\n",
    "web/lib.mjs": "export function triple(value) {\n  return value * 3;\n}\n",
    "web/index.mjs": "import { triple } from './lib.mjs';\n\n"
                     "export function main() {\n  return triple(2);\n}\n",
    # A file the published parser minted a module for and this build does not,
    # so the store carries a declaration set the current parser no longer derives.
    "web/quiet.js": "// nothing is declared in this file\n",
}

# Edits that no commit records. One per language, so the owed parses span the
# Rust project batch and the sources outside it.
EDITS = {
    "pkg/b.py": "\n\ndef quadruple(value):\n    return double(double(value))\n",
    "web/lib.mjs": "\nexport function sextuple(value) {\n  return triple(value) * 2;\n}\n",
    "src/util.rs": "\npub fn unused_helper() -> u32 {\n    7\n}\n",
}
EDITED_NAME = "quadruple"
EDITED_FILE = "pkg/b.py"


def expected_edit_line():
    """The 1-based line the edited declaration starts on in the edited bytes."""
    text = FIXTURE[EDITED_FILE] + EDITS[EDITED_FILE]
    for index, line in enumerate(text.splitlines(), start=1):
        if line.startswith("def %s(" % EDITED_NAME):
            return index
    raise AssertionError("the fixture edit declares no %s" % EDITED_NAME)


ANSI = re.compile(r"\x1b\[[0-9;]*m")


def tail(text, limit=600):
    text = ANSI.sub("", text or "").strip()
    return text if len(text) <= limit else "..." + text[-limit:]


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


# ------------------------------------------------------------------ graders

def owed_parse_control(debt_bytes):
    """How many owed parses the published build left, or None when unreadable.

    The record is the published build's own account of paths whose bytes reached
    authority without their parse. None and zero both mean the fixture did not
    reach the upgrade state, and neither may read as a pass.
    """
    if debt_bytes is None:
        return None
    try:
        entries = json.loads(debt_bytes)
    except ValueError:
        return None
    if not isinstance(entries, list):
        return None
    return sum(1 for entry in entries if isinstance(entry, dict) and entry.get("path"))


def serve_verdict(returncode, elapsed, bound, timed_out):
    """PASS only for a command that exited 0 inside the bound."""
    if timed_out:
        return FAIL, "the daemon did not serve within %ds" % bound
    if returncode != 0:
        return FAIL, "the command exited %d after %.1fs" % (returncode, elapsed)
    if elapsed > bound:
        return FAIL, "the daemon served after %.1fs, over the %ds bound" % (elapsed, bound)
    return PASS, "served in %.1fs" % elapsed


def disclosure_problems(status_text):
    """Problems with how `kin status` reported the start's re-derivation."""
    lines = [line.strip() for line in (status_text or "").splitlines()]
    hits = [line for line in lines if line.startswith("Startup repair:")]
    if len(hits) != 1:
        return ["expected one `Startup repair:` line, got %d" % len(hits)]
    line = hits[0]
    problems = []
    if "re-derived" not in line or "source file(s)" not in line:
        problems.append("the line does not say how many files it re-derived: %r" % line)
    elif " 0 source file(s)" in line:
        problems.append("the line claims a re-derivation of nothing: %r" % line)
    if "commit" not in line:
        problems.append("the line does not say what records the result durably: %r" % line)
    return problems


def answer_problems(search_json, name, path, line):
    """Problems with a `kin search --json` answer for the edited declaration."""
    try:
        rows = json.loads(search_json)
    except (TypeError, ValueError):
        return None
    if not isinstance(rows, list):
        return None
    named = [row for row in rows if isinstance(row, dict)
             and row.get("name") == name and row.get("file") == path]
    if len(named) != 1:
        return ["expected one %s in %s, found %d" % (name, path, len(named))]
    if named[0].get("line") != line:
        return ["%s answered at line %r, and its current bytes put it at %d"
                % (name, named[0].get("line"), line)]
    return []


GRADERS = {
    "owed_parse_control": owed_parse_control,
    "serve_verdict": serve_verdict,
    "disclosure_problems": disclosure_problems,
    "answer_problems": answer_problems,
}


# ------------------------------------------------------------------ fixture

def run(cmd, cwd=None, env=None, timeout=600, stdout_only=False):
    """Run one command. `stdout_only` keeps the log lines a build writes on
    stderr out of an output that has to parse as JSON."""
    started = time.monotonic()
    try:
        proc = subprocess.run(cmd, cwd=cwd, env=env, timeout=timeout,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL if stdout_only else subprocess.STDOUT,
                              text=True)
        return proc.returncode, proc.stdout, time.monotonic() - started, False
    except subprocess.TimeoutExpired as expired:
        output = expired.stdout or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", "replace")
        return None, output, time.monotonic() - started, True


def published_archive():
    system = platform.system()
    machine = platform.machine().lower()
    if machine in ("amd64", "x86_64"):
        machine = "x86_64"
    elif machine in ("arm64", "aarch64"):
        machine = "arm64" if system == "Darwin" else "aarch64"
    key = (system, machine)
    if key not in PUBLISHED_ARCHIVES:
        raise RuntimeError("no published %s archive is pinned for %s %s"
                           % (PUBLISHED_VERSION, key[0], key[1]))
    return PUBLISHED_ARCHIVES[key]


def fetch_published(workdir):
    """Download, verify and unpack the published release; return its `kin`."""
    name, digest = published_archive()
    archive = os.path.join(workdir, name)
    url = RELEASE_URL % (PUBLISHED_VERSION, name)
    with urllib.request.urlopen(url, timeout=300) as response, open(archive, "wb") as out:
        shutil.copyfileobj(response, out)
    with open(archive, "rb") as handle:
        actual = hashlib.sha256(handle.read()).hexdigest()
    if actual != digest:
        raise RuntimeError("%s has SHA-256 %s, and the release published %s"
                           % (url, actual, digest))
    unpacked = os.path.join(workdir, "published")
    os.makedirs(unpacked)
    with tarfile.open(archive) as bundle:
        root = os.path.realpath(unpacked)
        for member in bundle.getmembers():
            target = os.path.realpath(os.path.join(unpacked, member.name))
            if target != root and not target.startswith(root + os.sep):
                raise RuntimeError("%s carries a path outside its root: %s"
                                   % (name, member.name))
            if member.issym() or member.islnk():
                raise RuntimeError("%s carries a link: %s" % (name, member.name))
        bundle.extractall(unpacked)
    for directory, _, files in os.walk(unpacked):
        if "kin" in files and "kin-daemon" in files:
            return os.path.join(directory, "kin")
    raise RuntimeError("%s holds no kin beside a kin-daemon" % name)


def cleanup_result(status, detail):
    result = Result("cleanup", "fixture workers stopped and endpoints retired")
    (result.ok if status == PASS else result.bad)(detail)
    return result


def stop_confirmed(rc, report):
    """A successful exit alone does not prove that a worker was retired."""
    if not isinstance(report, dict):
        return False
    stopped = report.get("stopped")
    return (rc == 0 and isinstance(stopped, list)
            and report.get("schema") == "kin.daemon-stop.v1"
            and report.get("scope") == "current-repo"
            and report.get("all_stopped") is True
            and report.get("endpoints_retired", not stopped) is True
            and all(isinstance(row, dict)
                    and row.get("result") in ("stopped", "not-running")
                    and "preserved_endpoint" not in row for row in stopped))


def finish_run_root(workdir, results, keep, explicit=False):
    """Only a successful, stopped, disposable run may lose its fixtures."""
    reasons = []
    if keep:
        reasons.append("--keep")
    if explicit:
        reasons.append("caller-owned workdir")
    if not results or any(result.status != PASS for result in results):
        reasons.append("failed or unreadable check or cleanup")
    if not reasons:
        try:
            shutil.rmtree(workdir)
        except OSError as error:
            removal = cleanup_result(FAIL, "fixture removal failed: %s" % error)
            removal.id = "cleanup-root"
            results.append(removal)
            reasons.append("fixture removal failed; remaining evidence retained")
    if reasons:
        print("fixtures kept at %s (%s)" % (workdir, "; ".join(reasons)))
    return {"run_root": workdir, "run_root_retained": bool(reasons),
            "run_root_retention_reason": "; ".join(reasons) if reasons else "successful disposable run"}


class Suite(object):
    def __init__(self, kin, daemon, published_kin, workdir, verbose=False):
        self.kin = kin
        self.daemon = daemon
        self.published_kin = published_kin
        self.published_daemon = os.path.join(os.path.dirname(published_kin), "kin-daemon")
        self.workdir = workdir
        self.verbose = verbose
        self.repo = os.path.join(workdir, "repo")
        self.owned_repos = {self.repo}
        self.cleanup_kin = self.published_kin
        self.cleanup_home = "home-published"
        self.cleanup_daemon = self.published_daemon

    def shutdown(self):
        """Stop only this run's repositories, including a failed initialization."""
        # Match both the CLI and KIN_HOME to the last daemon generation.
        # A failure while preparing the published store still belongs to it.
        records = []
        errors = []
        for repo in sorted(self.owned_repos):
            record = {"repo": repo}
            records.append(record)
            # Never let discovery walk upward and select an unrelated repository.
            if not os.path.isfile(os.path.join(repo, ".kin", "manifest.json")):
                record["error"] = "fixture manifest missing; stop was not attempted"
                errors.append("%s: %s" % (repo, record["error"]))
                continue
            try:
                proc = subprocess.run(
                    [self.cleanup_kin, "daemon", "stop", "--json"], cwd=repo, env=self.env(self.cleanup_home, self.cleanup_daemon),
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=120)
                rc, out, err = proc.returncode, proc.stdout, proc.stderr
                record.update({"returncode": rc, "stdout": out, "stderr": err})
                report = json.loads(out) if rc == 0 else None
                if not stop_confirmed(rc, report):
                    record["error"] = "worker stop and endpoint retirement were not confirmed"
                    errors.append("%s: %s" % (repo, record["error"]))
            except Exception as error:
                record["error"] = "%s: %s" % (type(error).__name__, error)
                errors.append("%s: %s" % (repo, record["error"]))
        evidence = os.path.join(self.workdir, "daemon-cleanup.json")
        with open(evidence, "w") as handle:
            json.dump(records, handle, indent=2)
            handle.write("\n")
        detail = ("; ".join(errors) + "; see " + evidence if errors else
                  "%d owned fixture workers stopped and endpoints retired" % len(records))
        return cleanup_result(FAIL if errors else PASS, detail)

    def env(self, home, daemon):
        env = dict(os.environ)
        # A sealed KIN_HOME per build: the published daemon and the one under
        # test must not share a supervisor or a registry, and neither may reach
        # the operator's own stores. Nothing here runs inference.
        env["KIN_HOME"] = os.path.join(self.workdir, home)
        env["KIN_DAEMON_BIN"] = daemon
        env["KIN_DAEMON_AUTO_EMBED"] = "0"
        env["KIN_EMBED_BACKEND"] = "cpu"
        env["KIN_VFS_DISABLE"] = "1"
        env["KIN_DAEMON_DISABLE_LSP"] = "1"
        env["KIN_DAEMON_READY_TIMEOUT_SECS"] = str(SERVE_BOUND_SECONDS)
        for name in ("KIN_MCP_REPO", "KIN_DIR", "KIN_DAEMON_URL"):
            env.pop(name, None)
        os.makedirs(env["KIN_HOME"], exist_ok=True)
        return env

    def published(self, args, timeout=900):
        return run([self.published_kin] + args, cwd=self.repo,
                   env=self.env("home-published", self.published_daemon), timeout=timeout)

    def under_test(self, args, timeout=SERVE_BOUND_SECONDS + 60, stdout_only=False):
        self.cleanup_kin = self.kin
        self.cleanup_home = "home-under-test"
        self.cleanup_daemon = self.daemon
        return run([self.kin] + args, cwd=self.repo,
                   env=self.env("home-under-test", self.daemon), timeout=timeout,
                   stdout_only=stdout_only)

    def git(self, args):
        base = ["git", "-c", "core.hooksPath=/dev/null",
                "-c", "user.email=repro@example.invalid",
                "-c", "user.name=kin-published-store-upgrade",
                "-c", "commit.gpgsign=false"]
        rc, out, _, _ = run(base + args, cwd=self.repo)
        if rc != 0:
            raise RuntimeError("git %s failed: %s" % (" ".join(args), tail(out)))

    def build_published_store(self):
        """The upgrade state: a published store holding uncommitted edits.

        Returns the owed-parse count the published build recorded.
        """
        for path, body in FIXTURE.items():
            full = os.path.join(self.repo, path)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "w") as handle:
                handle.write(body)
        self.git(["init", "--initial-branch=main"])
        self.git(["add", "--all"])
        self.git(["commit", "-m", "fixture"])
        rc, out, _, _ = self.published(["init"])
        # 7 and 8 are a real store whose enrichment or reopen section could
        # not be attested; the store is what this suite needs.
        if rc not in (0, 7, 8):
            raise RuntimeError("published kin init exited %s: %s" % (rc, tail(out)))
        # `kin status` admits the working copy only through a daemon that is
        # already serving and never starts one, so one is started first. With
        # none serving, status exits 9 without admitting the edits and the
        # store holds no owed parse, which the control below reads as a store
        # that is not the upgrade state.
        rc, out, _, _ = self.published(["graph", "status"])
        if rc != 0:
            raise RuntimeError("published kin graph status exited %s: %s" % (rc, tail(out)))
        for path, addition in EDITS.items():
            with open(os.path.join(self.repo, path), "a") as handle:
                handle.write(addition)
        rc, out, _, _ = self.published(["status"])
        if rc != 0:
            raise RuntimeError("published kin status exited %s: %s" % (rc, tail(out)))
        self.published(["daemon", "stop"], timeout=120)
        try:
            with open(os.path.join(self.repo, ".kin", "semantic-debt.json"), "rb") as handle:
                debt = handle.read()
        except OSError:
            debt = None
        return owed_parse_control(debt)


# ------------------------------------------------------------------ checks

def check_all(suite, owed):
    serve = Result("serve", "the binary under test serves a published store")
    disclosure = Result("disclosure", "kin status names the start's re-derivation")
    answer = Result("answer", "an uncommitted edit answers at its current line")
    results = [serve, disclosure, answer]
    if not owed:
        for result in results:
            result.unknown(
                "the published %s build left no owed parse behind (record read %r), so this "
                "store is not the upgrade state under test" % (PUBLISHED_VERSION, owed))
        return results

    rc, out, elapsed, timed_out = suite.under_test(["graph", "status"])
    verdict, detail = serve_verdict(rc, elapsed, SERVE_BOUND_SECONDS, timed_out)
    if verdict == PASS:
        serve.ok("%s over a store the published %s wrote with %d owed parse(s)"
                 % (detail, PUBLISHED_VERSION, owed))
    else:
        serve.bad("%s: %s" % (detail, tail(out)))
        for result in (disclosure, answer):
            result.unknown("the daemon under test never served, so there is nothing to read")
        return results

    rc, out, _, _ = suite.under_test(["status"])
    if rc not in (0, 9):
        disclosure.unknown("`kin status` exited %s: %s" % (rc, tail(out)))
    else:
        problems = disclosure_problems(out)
        if problems:
            disclosure.bad("; ".join(problems) + ". Output: " + tail(out))
        else:
            disclosure.ok("kin status named the re-derivation")

    rc, out, _, _ = suite.under_test(["search", EDITED_NAME, "--json"], stdout_only=True)
    problems = answer_problems(out, EDITED_NAME, EDITED_FILE, expected_edit_line())
    if rc != 0 or problems is None:
        answer.unknown("`kin search --json` exited %s with %s" % (rc, tail(out)))
    elif problems:
        answer.bad("; ".join(problems))
    else:
        answer.ok("%s answers in %s at line %d, its current position"
                  % (EDITED_NAME, EDITED_FILE, expected_edit_line()))
    return results


# ------------------------------------------------------------------ self-test

def cleanup_self_test():
    report = {"schema": "kin.daemon-stop.v1", "scope": "current-repo",
              "stopped": [], "all_stopped": True}
    assert stop_confirmed(0, report)
    assert not stop_confirmed(1, report)
    assert not stop_confirmed(0, None)
    assert not stop_confirmed(0, dict(report, all_stopped=False))
    assert not stop_confirmed(0, dict(report, scope="all"))
    assert not stop_confirmed(0, dict(report, endpoints_retired=False))
    assert not stop_confirmed(0, dict(report, stopped=[{"result": "stopped"}]))
    retired = dict(report, stopped=[{"result": "stopped"}], endpoints_retired=True)
    assert stop_confirmed(0, retired)
    assert not stop_confirmed(0, dict(retired, stopped=[{"result": "failed"}]))
    assert not stop_confirmed(0, dict(retired, stopped=[{
        "result": "stopped", "preserved_endpoint": "still published"}]))


def self_test():
    cleanup_self_test()
    failures = []

    def expect(name, got, want):
        if got != want:
            failures.append("%s: got %r, want %r" % (name, got, want))

    expect("control counts owed parses",
           owed_parse_control(b'[{"path": "pkg/b.py", "body": "ab"}]'), 1)
    expect("control reads an empty record as zero", owed_parse_control(b"[]"), 0)
    expect("control refuses an absent record", owed_parse_control(None), None)
    expect("control refuses a record that is not JSON", owed_parse_control(b"{"), None)

    expect("serve passes inside the bound", serve_verdict(0, 3.0, 120, False)[0], PASS)
    expect("serve fails the refusal that shipped", serve_verdict(1, 4.8, 120, False)[0], FAIL)
    expect("serve fails a start that never answered", serve_verdict(None, 180, 120, True)[0], FAIL)
    expect("serve fails a start past the bound", serve_verdict(0, 121.0, 120, False)[0], FAIL)

    named = ("Startup repair: this daemon re-derived 5 source file(s) (pkg/b.py, and 4 more) "
             "from the bytes the store holds, in 40 ms, before it served (2s ago). The next "
             "commit records the re-derived semantics durably.")
    expect("disclosure passes the named line", disclosure_problems("Tree: x\n" + named), [])
    expect("disclosure fails a silent status", bool(disclosure_problems("Tree: x\n")), True)
    expect("disclosure fails a line that counts nothing",
           bool(disclosure_problems(named.replace(" 5 source", " 0 source"))), True)
    expect("disclosure fails a line with no durable remedy",
           bool(disclosure_problems(named.split(" The next")[0])), True)
    expect("disclosure fails a doubled line",
           bool(disclosure_problems(named + "\n" + named)), True)

    line = expected_edit_line()
    current = json.dumps([{"name": EDITED_NAME, "file": EDITED_FILE, "line": line}])
    expect("answer passes the current line", answer_problems(current, EDITED_NAME,
                                                             EDITED_FILE, line), [])
    stale = json.dumps([{"name": EDITED_NAME, "file": EDITED_FILE, "line": line - 2}])
    expect("answer fails a stale line",
           bool(answer_problems(stale, EDITED_NAME, EDITED_FILE, line)), True)
    expect("answer fails an absent declaration",
           bool(answer_problems("[]", EDITED_NAME, EDITED_FILE, line)), True)
    expect("answer refuses output that is not JSON",
           answer_problems("Error: kin daemon is required", EDITED_NAME, EDITED_FILE, line),
           None)

    for failure in failures:
        print("SELF-TEST FAIL %s" % failure)
    print("published-store-upgrade self-test: %d grader case(s) failed" % len(failures))
    return 1 if failures else 0


# ------------------------------------------------------------------ main

def main(argv):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--kin", default=os.environ.get("KIN_BIN"),
                        help="the kin binary under test")
    parser.add_argument("--daemon", default=os.environ.get("KIN_DAEMON_BIN"),
                        help="the kin-daemon beside it")
    parser.add_argument("--published-kin", default=None,
                        help="an unpacked published kin, its kin-daemon beside it, "
                             "instead of downloading %s" % PUBLISHED_VERSION)
    parser.add_argument("--json", dest="json_path", default=None,
                        help="write the machine-readable report here, for gate.py")
    parser.add_argument("--label", default=os.environ.get("KIN_ACCEPTANCE_LABEL"),
                        help="an opaque run label recorded in the report")
    parser.add_argument("--keep", action="store_true", help="keep the fixture")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--self-test", action="store_true",
                        help="falsify this suite's graders and exit")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()
    if not args.kin:
        print("published-store-upgrade: no kin binary. Pass --kin or set KIN_BIN.")
        return 3
    # Absolute, because every command runs with its cwd inside the fixture.
    kin = os.path.abspath(os.path.expanduser(args.kin))
    daemon = os.path.abspath(os.path.expanduser(
        args.daemon or os.path.join(os.path.dirname(kin), "kin-daemon")))
    for binary in (kin, daemon):
        if not os.path.isfile(binary) or not os.access(binary, os.X_OK):
            print("published-store-upgrade: %s is not an executable file" % binary)
            return 3

    workdir = tempfile.mkdtemp(prefix="kin-published-store-upgrade-")
    print("run root: %s" % workdir)
    suite = None
    results = []
    setup_failed = False
    try:
        try:
            published = (os.path.abspath(args.published_kin) if args.published_kin
                         else fetch_published(workdir))
            os.makedirs(os.path.join(workdir, "repo"))
            suite = Suite(kin, daemon, published, workdir, verbose=args.verbose)
            owed = suite.build_published_store()
        except Exception as error:  # noqa: BLE001 - setup names its own failure
            print("published-store-upgrade: setup failed: %s: %s"
                  % (type(error).__name__, error))
            setup_failed = True
            result = Result("setup", "published store could not be prepared")
            result.unknown("%s: %s" % (type(error).__name__, error))
            results.append(result)
        if not setup_failed:
            results.extend(check_all(suite, owed))
    finally:
        if suite is not None:
            try:
                results.append(suite.shutdown())
            except Exception as error:
                results.append(cleanup_result(FAIL, "cleanup raised: %s" % error))
    retention = finish_run_root(workdir, results, args.keep)
    for result in results:
        print("CHECK %s %s %s %s" % (result.id, TOPIC, result.status, result.detail))
    failed = [r for r in results if r.status == FAIL]
    unreadable = [r for r in results if r.status == UNREADABLE]
    print("published-store-upgrade: %d checks, %d pass, %d FAIL, %d UNREADABLE"
          % (len(results), len(results) - len(failed) - len(unreadable),
             len(failed), len(unreadable)))
    if args.json_path:
        payload = {
            "suite": "published_store_upgrade_repro",
            "topic": TOPIC,
            "published_version": PUBLISHED_VERSION,
            "label": args.label,
            "kin": kin,
            "results": [
                {"id": r.id, "title": r.title, "status": r.status,
                 "detail": r.detail, "asserts": r.asserts}
                for r in results
            ],
        }
        payload.update(retention)
        directory = os.path.dirname(os.path.abspath(args.json_path))
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(args.json_path, "w") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
    if setup_failed:
        return 3
    if failed:
        return 1
    if unreadable:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
