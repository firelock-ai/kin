#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
"""NON-CITABLE acceptance suite for per-language parse coverage (FIR-2599).

Its output is a regression gate, never proof, never investor-facing and never a
released claim. It shares the CHECK line format, the exit codes and the
`--self-test` discipline of its siblings in this directory, so a reader who
knows one knows all of them.

What it is for
--------------
The rc0547b brownfield stranger measured expressjs/express on v0.5.47 and found
75 of 141 admitted files producing no entity, with `lib/express.js` among them,
while every surface a person or an agent reads said the store was fine. The page
already carried a repository-grain count. What it could not say was WHICH
language and WHICH files, which is the part a reader can act on, and this suite
holds that.

What it deliberately does NOT assert
------------------------------------
A verdict. A file that produced no entity is not on its own evidence that
anything failed: a side-effect script, a re-export and a comment-only file each
correctly produce nothing, and no graph-owned signal separates those from a file
an adapter could not read. Measured on a five-file JavaScript repository holding
one real module beside one of each, the ratio reads 1/5, LOWER than the express
checkout this was built for. So the doctor row must stay `healthy` and this
suite fails if it does not, because a row that went red on the count would go
red on most JavaScript repositories.

Every check is paired with its own control on a repository whose files all
produce entities, because a surface that named files unconditionally would pass
the first half of each check and is the failure this suite exists to catch.

    CHECK <id> <ticket> PASS|FAIL|UNREADABLE <detail>

UNREADABLE is a distinct outcome from FAIL and is never reported as a pass: it
means the probe could not be evaluated (no output, a non-JSON payload, a field
this build does not define). A crashed probe is UNREADABLE, never a verdict.
Exit status is 1 when any check FAILs, 2 when none fail but some are UNREADABLE,
0 only when every check passes, 3 on a setup error.

The binary under test
---------------------
    cargo build --release --locked --bin kin --bin kin-daemon
    python3 scripts/acceptance/parse_hole_repro.py --kin target/release/kin

`--kin` may also come from KIN_BIN. The kin-daemon beside it is used when one
exists. No binary is built by this script.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

PASS = "PASS"
FAIL = "FAIL"
UNREADABLE = "UNREADABLE"
TICKET = "FIR-2599"

# Four modules that declare a function, and one comment-only file per silent
# language, all valid UTF-8.
READABLE = 4

# The silent languages, as (census row name, extension, bytes).
#
# A table rather than one language, and that is the point of it. The rule a
# silent file depends on is "mint the file-module surface only when the file
# produced an entity or an import", and that rule was written for Rust and for
# nothing else. Every other adapter minted the module for any file with a
# resolvable module name, so a comment-only JavaScript, TypeScript, Go, Java,
# PHP, Kotlin or Swift file counted as parsed, the doctor row read `javascript
# 4/4`, and this suite could not name the holed file. One language in this table
# cannot catch that. Every adapter the rule was ported into has a row, and
# adding a row here is what grades the next adapter.
#
# Each entry is bytes an adapter is registered for, admitted as source, valid
# UTF-8, parsing clean and declaring nothing. NUL bytes would route the file to
# the opaque facet instead, which is a different state wearing the same numbers,
# and it is what an earlier version of this fixture used.
SILENT_LANGUAGES = (
    ("rust", "rs", "// nothing is declared here\n"),
    ("javascript", "js", "// nothing is declared here\n"),
    ("typescript", "ts", "// nothing is declared here\n"),
    ("go", "go", "// nothing is declared here\n"),
    ("java", "java", "// nothing is declared here\n"),
    ("kotlin", "kt", "// nothing is declared here\n"),
    ("swift", "swift", "// nothing is declared here\n"),
    ("php", "php", "<?php\n// nothing is declared here\n"),
)
SILENT_PER_LANGUAGE = 1


def silent_path(extension, index):
    """Where the fixture writes one silent file."""
    return "lib/silent_%s%d.%s" % (extension, index, extension)


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


def tail(text, limit=400):
    """A command's output as evidence, quoted through `failure_excerpt`."""
    return failure_excerpt(text, limit)


def run(cmd, cwd=None, env=None, timeout=600):
    proc = subprocess.run(
        cmd, cwd=cwd, env=env, timeout=timeout,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
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
        # Every passing assertion, not the last one. Each check here grades a
        # fixture WITH the hole and its control without, and a line naming only
        # the control would read as a pass for a suite that never probed the
        # case it exists for.
        graded = [a["detail"] for a in self.asserts if a["status"] == PASS]
        return "; ".join(graded) if graded else "no assertion was reached"


# ------------------------------------------------------------------- graders

def status_publishes_the_census(text):
    """Whether `kin graph status` published the per-language section.

    Both halves are required. The section header alone is not the fix, because
    the repository-grain count already exists on the page above it; the delta is
    the per-language row and the named paths.
    """
    return ("Parse coverage (files whose current bytes produced an entity / files admitted):" in text
            and "no_entity:" in text)


def doctor_row_names_the_files(report):
    """Whether the doctor's parse row published its numbers and its paths.

    Reads the structured report rather than the rendered table, because the
    table's column widths are presentation. Returns None when the row is absent,
    which is UNREADABLE rather than a verdict about the store.

    The row must stay `healthy`: a count is not a defect, and a doctor row that
    went red on it would go red on most JavaScript repositories.
    """
    rows = [row for row in report.get("checks", []) if row.get("id") == "parse_coverage"]
    if not rows:
        return None
    row = rows[0]
    detail = row.get("detail") or ""
    return row.get("status") == "healthy" and all(
        silent_path(extension, 0) in detail for _, extension, _ in SILENT_LANGUAGES
    )


def status_names_every_silent_language(text):
    """Whether the census named a holed file for EVERY silent language.

    One row reading a hole is not the fix. The module-surface rule this suite
    depends on held for one adapter and skipped seven, and a check that accepted
    any one language would have passed throughout that.
    """
    return all(
        ("admitted %s files produced no entity" % language) in text
        and silent_path(extension, 0) in text
        for language, extension, _ in SILENT_LANGUAGES
    )


GRADERS = {
    "status_publishes_the_census": status_publishes_the_census,
    "status_names_every_silent_language": status_names_every_silent_language,
}


# ------------------------------------------------------------------- fixtures

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
    def __init__(self, kin, workdir, daemon=None, verbose=False):
        self.kin = kin
        self.workdir = workdir
        self.verbose = verbose
        self.kin_home = os.path.join(workdir, "kin-home-%d" % os.getpid())
        os.makedirs(self.kin_home, exist_ok=True)
        self.env = dict(os.environ)
        # A scratch KIN_HOME keeps this run off the fleet's stores and the
        # auto-embed opt-out keeps it off the GPU. Neither is a nicety: this
        # suite is meant to run on every pull request beside other work.
        self.env["KIN_HOME"] = self.kin_home
        self.env["KIN_DAEMON_AUTO_EMBED"] = "0"
        self.env["KIN_EMBED_BACKEND"] = "cpu"
        self.env["KIN_VFS_DISABLE"] = "1"
        self.env.pop("KIN_MCP_REPO", None)
        self.env.pop("KIN_DIR", None)
        if daemon:
            self.env["KIN_DAEMON_BIN"] = daemon
        self.repos = {}
        self.owned_repos = set()

    def git(self, args, cwd):
        base = ["git",
                "-c", "core.hooksPath=/dev/null",
                "-c", "user.email=repro@example.invalid",
                "-c", "user.name=kin-parse-hole-repro",
                "-c", "commit.gpgsign=false"]
        return run(base + args, cwd=cwd, env=self.env)

    def shutdown(self):
        """Stop only this run's repositories, including a failed initialization."""
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
                    [self.kin, "daemon", "stop", "--json"], cwd=repo, env=self.env,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60)
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

    def kin_run(self, args, repo, timeout=600):
        return run([self.kin] + args, cwd=repo, env=self.env, timeout=timeout)

    def fixture(self, name, silent_languages):
        """A JavaScript library of `READABLE` modules plus one comment-only file
        per entry in `silent_languages`, each valid source declaring nothing.

        Admitted through `kin init`, the boundary a user crosses, so the census
        reads the same tree and entity table the product does.
        """
        if name in self.repos:
            return self.repos[name]
        repo = os.path.join(self.workdir, name)
        os.makedirs(os.path.join(repo, "lib"), exist_ok=True)
        self.owned_repos.add(repo)
        rc, out = self.git(["init", "--initial-branch=main"], repo)
        if rc != 0:
            raise RuntimeError("git init failed: %s" % out)
        # Every readable module requires the next one round a cycle, so each has
        # an inbound edge and the scan lists nothing. The empty answer is the one
        # the ticket is about: a bare "No dead code found." over a hole reads as
        # a licence to act.
        for index in range(READABLE):
            following = (index + 1) % READABLE
            with open(os.path.join(repo, "lib", "module%d.js" % index), "w") as handle:
                handle.write(
                    "const next = require('./module%d');\n"
                    "function handler%d() {\n  return next;\n}\n"
                    "module.exports = handler%d;\n" % (following, index, index)
                )
        # The silent files used to be JavaScript, then Rust alone. Every
        # JavaScript and TypeScript file began emitting a Module entity whether
        # or not its bytes declared anything, so a comment-only `.js` file
        # stopped being silent and emptied this fixture's hole, which is what
        # this suite caught. Rust kept the rule that the module surface is
        # minted only for a file that produced an entity or an import, so a
        # comment-only `.rs` file still measured 0 and the fixture moved there.
        #
        # The other adapters carry that rule now, so the fixture holds more than
        # one language again and grades each of them separately. An adapter that
        # goes back to minting the module unconditionally turns its own row from
        # `0/1` into `1/1` and fails the check below rather than passing on Rust.
        for language, extension, body in silent_languages:
            for index in range(SILENT_PER_LANGUAGE):
                path = os.path.join(repo, silent_path(extension, index))
                with open(path, "w") as handle:
                    handle.write(body)
        self.git(["add", "--all"], repo)
        rc, out = self.git(["commit", "-m", "a javascript library"], repo)
        if rc != 0:
            raise RuntimeError("git commit failed: %s" % out)
        rc, out = self.kin_run(["init"], repo, timeout=900)
        if rc != 0:
            raise RuntimeError("kin init failed in %s: %s" % (repo, out))
        self.repos[name] = repo
        return repo


# --------------------------------------------------------------------- checks

def check_status(suite):
    """`kin graph status` publishes per-language parse coverage and names files.

    The page already carried a repository-grain count before this: "of the N
    admitted, N carry a full language adapter; M of those produced no entity".
    What it could not do was say WHICH language and WHICH files, which is the
    part a reader can act on.
    """
    result = Result("status", "graph status publishes the per-language census and names files")
    for name, silent, want in (("holed", SILENT_LANGUAGES, True), ("whole", (), False)):
        repo = suite.fixture(name, silent)
        rc, out = suite.kin_run(["graph", "status"], repo)
        if rc != 0:
            result.unknown("%s: `kin graph status` exited %d: %s" % (name, rc, tail(out)))
            continue
        published = status_publishes_the_census(out)
        # The section prints in every state, so the holed fixture must name a
        # file and the whole one must name none. Both halves read the same
        # grader, and the header alone satisfies neither.
        named = "no_entity:" in out
        if published == want or (not want and "Parse coverage (" in out and not named):
            result.ok("%s: census published=%s named=%s as expected" % (name, published, named))
        else:
            result.bad("%s: published=%s named=%s, wanted named=%s. Output: %s"
                       % (name, published, named, want, tail(out, 700)))
        # Every silent language separately, on the holed fixture only. A suite
        # that read the census as one boolean passed while seven adapters
        # counted a comment-only file as parsed.
        if want:
            if status_names_every_silent_language(out):
                result.ok("holed: every silent language names its own holed file")
            else:
                result.bad("holed: the census did not name a file for every silent language "
                           "(%s). Output: %s"
                           % (", ".join(lang for lang, _, _ in SILENT_LANGUAGES), tail(out, 900)))
    return result


def check_doctor(suite):
    """`kin doctor` carries a parse-coverage row that reports and never judges."""
    result = Result("doctor", "doctor publishes a parse-coverage row that stays healthy")
    for name, silent in (("holed", SILENT_LANGUAGES), ("whole", ())):
        repo = suite.fixture(name, silent)
        # The row reads the run's one `graph status`, which needs a daemon, and
        # `kin init` leaves none running. Without this the row reports "no
        # daemon is serving this repository" and the check grades a fact about
        # the fixture as a fact about the product.
        warm_rc, warm_out = suite.kin_run(["graph", "status"], repo)
        if warm_rc != 0:
            result.unknown("%s: could not start a daemon, `kin graph status` exited %d: %s"
                           % (name, warm_rc, tail(warm_out)))
            continue
        rc, out = suite.kin_run(["doctor", "--json"], repo)
        try:
            report = json.loads(out[out.index("{"):out.rindex("}") + 1])
        except (ValueError, json.JSONDecodeError):
            result.unknown("%s: `kin doctor --json` payload was not JSON (rc=%d): %s"
                           % (name, rc, tail(out)))
            continue
        got = doctor_row_names_the_files(report)
        rows = [r for r in report.get("checks", []) if r.get("id") == "parse_coverage"]
        if got is None:
            result.unknown("%s: this build's doctor report carries no `parse_coverage` row" % name)
        elif name == "holed" and got:
            result.ok("holed: the row is healthy and names a file in every silent language")
        elif name == "whole" and rows and rows[0].get("status") == "healthy":
            result.ok("whole: the row is healthy and names none")
        else:
            result.bad("%s: row did not read as expected. Row: %s" % (name, json.dumps(rows)))
    return result


CHECKS = [check_status, check_doctor]


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
    """Falsify every grader against its own inverse.

    A grader that cannot tell its two cases apart reports a clean product on a
    broken one, so each case here is paired with the input that must produce the
    opposite verdict. This runs before any build in CI, so a broken grader is
    named in seconds rather than after three minutes of compiling.
    """
    # The page the holed fixture produces, composed here so a case that drops
    # one language is written as a deletion from the real shape rather than as a
    # hand-made string that never resembled it.
    def census_page(languages):
        lines = ["Parse coverage (files whose current bytes produced an entity / files "
                 "admitted):", "  javascript: 4/5 (80%)"]
        for language, extension, _ in languages:
            lines.append("  no_entity: 1 of 1 admitted %s files produced no entity, "
                         "including %s (shallowest paths first)"
                         % (language, silent_path(extension, 0)))
        return "\n".join(lines)

    every = census_page(SILENT_LANGUAGES)
    cases = [
        ("status_publishes_the_census", True, every),
        # The header alone is not the delta: a repository-grain count already
        # existed on that page, and the per-language row plus the named paths
        # are what this suite is about.
        ("status_publishes_the_census", False,
         "Parse coverage (files whose current bytes produced an entity / files admitted):\n"
         "  rust: 3/3 (100%)"),
        ("status_publishes_the_census", False, "no_entity: 3 of 3 admitted rust files"),
        ("status_publishes_the_census", False, "Entities: 4  |  Files: 4"),
        ("status_names_every_silent_language", True, every),
        # One language short is the exact regression this table exists for: the
        # module-surface rule held for Rust and skipped the others, so the Rust
        # row read the hole and every other row read clean.
        ("status_names_every_silent_language", False, census_page(SILENT_LANGUAGES[:1])),
        ("status_names_every_silent_language", False, census_page(SILENT_LANGUAGES[1:])),
        # A language counted but not named is the half this suite was built to
        # refuse: the count already existed before it.
        ("status_names_every_silent_language", False,
         every.replace(silent_path(SILENT_LANGUAGES[-1][1], 0), "")),
        ("status_names_every_silent_language", False, "Entities: 4  |  Files: 4"),
    ]
    cleanup_self_test()
    failures = []
    for name, want, text in cases:
        got = GRADERS[name](text)
        if got != want:
            failures.append("%s(%r) = %s, wanted %s" % (name, text, got, want))

    # The doctor grader reads a structure rather than a string.
    def doctor_detail(languages):
        return "; ".join(
            ["javascript 4/5"]
            + ["no_entity: 1 of 1 admitted %s files produced no entity, including %s "
               "(shallowest paths first)" % (language, silent_path(extension, 0))
               for language, extension, _ in languages]
        )

    doctor_cases = [
        (True, {"checks": [{"id": "parse_coverage", "status": "healthy",
                            "detail": doctor_detail(SILENT_LANGUAGES)}]}),
        # A row that went red on a count is the failure mode this suite exists
        # to prevent, so the grader must not accept one.
        (False, {"checks": [{"id": "parse_coverage", "status": "stale",
                             "detail": doctor_detail(SILENT_LANGUAGES)}]}),
        # One language short. A grader reading only Rust passed while six
        # adapters counted a comment-only file as parsed.
        (False, {"checks": [{"id": "parse_coverage", "status": "healthy",
                             "detail": doctor_detail(SILENT_LANGUAGES[:1])}]}),
        (False, {"checks": [{"id": "parse_coverage", "status": "healthy",
                             "detail": "rust 3/3"}]}),
        (False, {"checks": [{"id": "parse_coverage", "status": "healthy"}]}),
        (None, {"checks": [{"id": "relation_census", "status": "healthy"}]}),
        (None, {"checks": []}),
    ]
    for want, report in doctor_cases:
        got = doctor_row_names_the_files(report)
        if got != want:
            failures.append("doctor_row_names_the_files(%s) = %s, wanted %s"
                            % (json.dumps(report), got, want))

    # `tail` must keep the END of an output, which is where the error is.
    tail_cases = [
        ("short", "short"),
        ("WARN noise " * 60 + "Error: the real cause", None),
    ]
    for text, exact in tail_cases:
        got = tail(text, 40)
        if exact is not None and got != exact:
            failures.append("tail(%r) = %r, wanted %r" % (text, got, exact))
        if exact is None and not got.endswith("Error: the real cause"):
            failures.append("tail dropped the end of the output: %r" % got)

    # Result.status must never grade a FAIL or an ungraded run as a pass.
    grade_cases = [
        (PASS, [(PASS, "a")]),
        (FAIL, [(PASS, "a"), (FAIL, "b")]),
        (UNREADABLE, [(PASS, "a"), (UNREADABLE, "b")]),
        (FAIL, [(UNREADABLE, "a"), (FAIL, "b")]),
        (UNREADABLE, []),
    ]
    for want, entries in grade_cases:
        result = Result("t", "t")
        for status, detail in entries:
            result.asserts.append({"status": status, "detail": detail})
        if result.status != want:
            failures.append("Result.status(%s) = %s, wanted %s"
                            % (entries, result.status, want))

    for failure in failures:
        print("SELFTEST FAIL %s" % failure)
    total = len(cases) + len(doctor_cases) + len(tail_cases) + len(grade_cases)
    print("kin-parse-hole-repro: self-test %d/%d cases"
          % (total - len(failures), total))
    return 1 if failures else 0


# ----------------------------------------------------------------------- main

def main(argv):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--kin", default=os.environ.get("KIN_BIN"),
                        help="the kin binary under test")
    parser.add_argument("--daemon", default=os.environ.get("KIN_DAEMON_BIN"),
                        help="the kin-daemon beside it")
    parser.add_argument("--json", dest="json_path", default=None,
                        help="write the machine-readable report here, for scripts/acceptance/gate.py")
    parser.add_argument("--label", default=os.environ.get("KIN_ACCEPTANCE_LABEL"),
                        help="an opaque run label recorded in the report")
    parser.add_argument("--keep", action="store_true", help="keep the fixtures")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--self-test", action="store_true",
                        help="falsify this suite's graders and exit")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    if not args.kin:
        print("kin-parse-hole-repro: no kin binary. Pass --kin or set KIN_BIN.")
        return 3
    # Absolute, because every command below runs with cwd inside a fixture in a
    # temp directory. A relative `--daemon target/release/kin-daemon`, which is
    # exactly what the CI step passes, resolves against that fixture and not
    # against the checkout, and `kin` then refuses with "explicit KIN_DAEMON_BIN
    # does not exist". `--kin` was already absolute here and `--daemon` was not,
    # which is why the suite ran at all and could not reach a verdict.
    kin = os.path.abspath(os.path.expanduser(args.kin))
    if not os.path.isfile(kin) or not os.access(kin, os.X_OK):
        print("kin-parse-hole-repro: %s is not an executable file" % kin)
        return 3
    daemon = args.daemon and os.path.abspath(os.path.expanduser(args.daemon))
    if not daemon:
        beside = os.path.join(os.path.dirname(kin), "kin-daemon")
        daemon = beside if os.path.isfile(beside) else None

    workdir = tempfile.mkdtemp(prefix="kin-parse-hole-repro-")
    print("run root: %s" % workdir)
    suite = Suite(kin, workdir, daemon=daemon, verbose=args.verbose)
    results = []
    try:
        for check in CHECKS:
            try:
                results.append(check(suite))
            except Exception as error:  # noqa: BLE001 - a crashed probe is UNREADABLE
                result = Result(getattr(check, "__name__", "check"), "probe crashed")
                result.unknown("%s: %s" % (type(error).__name__, error))
                results.append(result)
    finally:
        try:
            results.append(suite.shutdown())
        except Exception as error:
            results.append(cleanup_result(FAIL, "cleanup raised: %s" % error))
    retention = finish_run_root(workdir, results, args.keep)
    for result in results:
        print("CHECK %s %s %s %s" % (result.id, TICKET, result.status, result.detail))
    failed = [r for r in results if r.status == FAIL]
    unreadable = [r for r in results if r.status == UNREADABLE]
    print("kin-parse-hole-repro: %d checks, %d pass, %d FAIL, %d UNREADABLE"
          % (len(results), len(results) - len(failed) - len(unreadable),
             len(failed), len(unreadable)))
    if args.json_path:
        # The gate reads this rather than the exit code, because an exit
        # status is one lever with two settings and a check blocked on
        # something outside the change under review needs a third.
        payload = {
            "suite": "parse_hole_repro",
            "ticket": TICKET,
            "label": args.label,
            "kin": kin,
            "results": [
                {"id": r.id, "ticket": TICKET, "title": r.title,
                 "status": r.status, "detail": r.detail, "asserts": r.asserts}
                for r in results
            ],
        }
        payload.update(retention)
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


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
