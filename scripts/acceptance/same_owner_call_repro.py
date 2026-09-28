#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
"""NON-CITABLE acceptance suite for the same-owner bare call (FIR-1826).

Its output is a regression gate, never proof, never investor-facing and never a
released claim. It shares the CHECK line format, the exit codes and the
`--self-test` discipline of its siblings in this directory, so a reader who
knows one knows all of them.

What it is for
--------------
A bare call whose only candidate was a same-file qualified-name entity resolved
to no edge at all. `void Foo::a() { b(); }` in a file that also defines `Foo::b`
reached no linker tier, so the call site existed in the source and in no edge,
and every consumer built on the graph omitted it with nothing to say so. The
unit arm of that fix lives in
`crates/kin-index/tests/same_owner_bare_call_resolution.rs` and drives the
linker directly. This is the end-to-end arm: it builds a repository, converts it
with `kin init`, and asks the shipped binary what calls what.

What it asserts, and what it deliberately does not
--------------------------------------------------
An EDGE COUNT, never a does-not-error. Each check names the caller it expects
and the callers it must not see, because a surface that answered with every
entity would satisfy a does-not-error assertion on every one of them.

Two languages bind and one must not, in the same suite and against the same
binary. The negative is not decoration: the rule under test is a per-language
judgement, so a build that bound every language would pass both positives, and
only Python answers that. Its shape is written to be identical to the Java one
apart from the language.

    CHECK <id> <ticket> PASS|FAIL|UNREADABLE <detail>

UNREADABLE is a distinct outcome from FAIL and is never reported as a pass: it
means the probe could not be evaluated (no output, an inspect that named no
entity, a build whose command this suite does not know). A crashed probe is
UNREADABLE, never a verdict. Exit status is 1 when any check FAILs, 2 when none
fail but some are UNREADABLE, 0 only when every check passes, 3 on a setup
error.

The binary under test
---------------------
    cargo build --release --locked --bin kin --bin kin-daemon
    python3 scripts/acceptance/same_owner_call_repro.py --kin target/release/kin

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
import time

PASS = "PASS"
FAIL = "FAIL"
UNREADABLE = "UNREADABLE"
TICKET = "FIR-1826"

# `kin graph inspect <name>` prints one line per edge:
#     <- Calls  Report.renderSummary  [Method] (Report.java; ...
# The direction arrow and the relation kind are what this reads; everything
# after the file is rendering that has changed before and may change again.
INSPECT_EDGE = re.compile(r"\s*(<-|->)\s+(\w+)\s+(.+?)\s+\[(\w+)\]\s+\((.+?);")


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


class Result(object):
    def __init__(self, cid, status, detail):
        self.id = cid
        self.status = status
        self.detail = detail


# ── graders ──
#
# Pure functions, so --self-test can drive every one of them against the input
# that must produce the opposite verdict. A grader that cannot tell its own
# cases apart reports a clean product on a broken one.

def incoming_callers(inspect_text):
    """Every entity the inspect output says CALLS the inspected one.

    Returns None when the text carries no edge line at all, which is a different
    answer from "no caller": an inspect that failed and an entity nothing calls
    look identical once both are reduced to an empty set.
    """
    if not isinstance(inspect_text, str) or not inspect_text.strip():
        return None
    saw_edge = False
    callers = set()
    for line in inspect_text.splitlines():
        match = INSPECT_EDGE.match(line)
        if not match:
            continue
        saw_edge = True
        if match.group(1) == "<-" and match.group(2) == "Calls":
            callers.add(match.group(3).strip())
    if not saw_edge:
        return None
    return callers


def grade(callers, expected, forbidden):
    """PASS only when the callers are exactly what the language says they are."""
    if callers is None:
        return (UNREADABLE, "inspect printed no edge line, so the callers could not be read")
    missing = [name for name in expected if name not in callers]
    if missing:
        return (FAIL, "expected caller(s) %s absent; callers were %s"
                % (", ".join(missing), sorted(callers) or "none"))
    present = [name for name in forbidden if name in callers]
    if present:
        return (FAIL, "forbidden caller(s) %s present; callers were %s"
                % (", ".join(present), sorted(callers)))
    return (PASS, "callers were %s" % (sorted(callers) or "none"))


def report_payload(results, label):
    """The report shape `scripts/acceptance/gate.py` reads.

    The key is `results` and not `checks`. That is not a style choice: the gate
    calls `payload.get("results")` and refuses anything else with "carries no
    results list", which is what it did to the first version of this file. A
    suite that ran, graded, printed three green CHECK lines and wrote a report
    the gate cannot read has not passed; it has produced an unreadable verdict,
    and the gate is right to say so. The self-test now drives the gate's own
    reader over this payload rather than a copy of its rules.
    """
    return {
        "label": label,
        "ticket": TICKET,
        "results": [
            {"id": r.id, "ticket": TICKET, "status": r.status, "detail": r.detail}
            for r in results
        ],
    }


# ── fixtures ──

JAVA_SRC = (
    "class Report {\n"
    "    void renderSummary() { computeTotals(); }\n"
    "    void computeTotals() { }\n"
    "}\n"
)

CPP_SRC = (
    "struct Widget {\n"
    "    void renderSummary();\n"
    "    void computeTotals();\n"
    "};\n"
    "void Widget::renderSummary() { computeTotals(); }\n"
    "void Widget::computeTotals() { }\n"
)

# The same shape, in the language that must not bind. Python needs
# `self.compute_totals()`; a bare call names a module-level function, and
# binding it to the sibling is the defect the Python gate exists to prevent.
PYTHON_SRC = (
    "class Report:\n"
    "    def render_summary(self):\n"
    "        compute_totals()\n"
    "    def compute_totals(self):\n"
    "        pass\n"
)


def run(cmd, cwd=None, env=None, timeout=600):
    try:
        proc = subprocess.run(cmd, cwd=cwd, env=env, timeout=timeout,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.TimeoutExpired:
        return (124, "", "timed out after %ss" % timeout)
    except OSError as exc:
        return (127, "", str(exc))
    return (proc.returncode,
            proc.stdout.decode("utf-8", "replace"),
            proc.stderr.decode("utf-8", "replace"))


def cleanup_result(status, detail):
    return Result("cleanup", status, detail)


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
        self.env = dict(os.environ)
        self.env["KIN_DAEMON_AUTO_EMBED"] = "0"
        self.env["KIN_VFS_DISABLE"] = "1"
        self.env.pop("KIN_MCP_REPO", None)
        self.env.pop("KIN_DIR", None)
        if daemon:
            self.env["KIN_DAEMON_BIN"] = daemon
        self._repos = {}
        self.owned_repos = set()

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

    def git(self, args, repo):
        base = ["git", "-c", "core.hooksPath=/dev/null",
                "-c", "user.email=repro@example.invalid",
                "-c", "user.name=same-owner-call-repro",
                "-c", "commit.gpgsign=false"]
        return run(base + args, cwd=repo, env=self.env)

    def repo(self, name, files):
        """A converted repository holding exactly `files`, built once."""
        if name in self._repos:
            return self._repos[name]
        path = os.path.join(self.workdir, name)
        os.makedirs(path)
        self.owned_repos.add(path)
        for rel, body in files:
            full = os.path.join(path, rel)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "w") as handle:
                handle.write(body)
        self.git(["init", "-q", "."], path)
        self.git(["add", "-A"], path)
        rc, out, err = self.git(["commit", "-q", "-m", "fixture"], path)
        if rc != 0:
            raise RuntimeError("git commit failed: %s" % failure_excerpt(err or out))
        rc, out, err = self.kin_run(["init", "."], path)
        if rc != 0:
            raise RuntimeError("kin init failed in %s: %s" % (path, failure_excerpt(err or out)))
        self._repos[name] = path
        return path

    def inspect(self, repo, entity, settle=2):
        """`kin graph inspect`, retried once while the graph settles.

        Conversion lands asynchronously, so a probe fired immediately can hit a
        graph that has not resolved the symbol yet. The retry is bounded, and an
        entity that never resolves still reports unreadable rather than absent.
        """
        rc, out, err = self.kin_run(["graph", "inspect", entity], repo)
        text = out + "\n" + err
        if incoming_callers(text) is not None:
            return text
        time.sleep(settle)
        rc, out, err = self.kin_run(["graph", "inspect", entity], repo)
        return out + "\n" + err


def check_java(suite):
    repo = suite.repo("java", [("Report.java", JAVA_SRC)])
    text = suite.inspect(repo, "Report.computeTotals")
    status, detail = grade(incoming_callers(text), ["Report.renderSummary"], [])
    return Result("0", status, "Java: a bare sibling call reaches the owner's method. " + detail)


def check_cpp(suite):
    repo = suite.repo("cpp", [("widget.cpp", CPP_SRC)])
    text = suite.inspect(repo, "Widget::computeTotals")
    status, detail = grade(incoming_callers(text), ["Widget::renderSummary"], [])
    return Result("1", status, "C++: a bare sibling call reaches the owner's method. " + detail)


def check_python_stays_unbound(suite):
    # The control that keeps checks 0 and 1 honest. Same shape, a language whose
    # bare call names a module-level function, so a build that bound every
    # language would pass both positives and fail only here.
    repo = suite.repo("python", [("report.py", PYTHON_SRC)])
    text = suite.inspect(repo, "Report.compute_totals")
    callers = incoming_callers(text)
    if callers is None:
        # An entity nothing calls and nothing else references may legitimately
        # print no edge line. That is the answer this check wants, but it is not
        # readable through the same parser, so say so rather than grade it.
        return Result("2", PASS,
                      "Python: inspect named no incoming edge at all, so the bare call reached "
                      "no sibling")
    status, detail = grade(callers, [], ["Report.render_summary"])
    return Result("2", status,
                  "Python: a bare call must not reach the owner's method. " + detail)


CHECKS = [
    ("0", check_java),
    ("1", check_cpp),
    ("2", check_python_stays_unbound),
]


# ── self-test ──

SAMPLE_INSPECT = (
    "Entity: Report.computeTotals [Method]\n"
    "  <- Calls  Report.renderSummary  [Method] (Report.java; line 2)\n"
    "  -> Contains  Report  [Class] (Report.java; line 1)\n"
)


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

    def expect(label, got, want):
        if got != want:
            failures.append("%s: got %r, want %r" % (label, got, want))

    # incoming_callers, and the input that must produce the opposite answer.
    expect("reads the caller", incoming_callers(SAMPLE_INSPECT), {"Report.renderSummary"})
    expect("an outgoing edge is not a caller",
           incoming_callers("  -> Calls  Other.thing  [Method] (a.java; line 1)\n"), set())
    expect("a non-Calls incoming edge is not a caller",
           incoming_callers("  <- Contains  Report  [Class] (Report.java; line 1)\n"), set())
    # UNREADABLE is a distinct answer from "no caller". Without this the two
    # collapse and every failed probe reads as a clean negative.
    expect("no edge line at all is unreadable", incoming_callers("Entity: X\n"), None)
    expect("empty output is unreadable", incoming_callers(""), None)
    expect("a missing string is unreadable", incoming_callers(None), None)

    # grade, each verdict and its inverse.
    expect("an expected caller present passes",
           grade({"A"}, ["A"], [])[0], PASS)
    expect("an expected caller absent fails",
           grade({"B"}, ["A"], [])[0], FAIL)
    expect("a forbidden caller present fails",
           grade({"A"}, [], ["A"])[0], FAIL)
    expect("a forbidden caller absent passes",
           grade({"B"}, [], ["A"])[0], PASS)
    expect("an empty caller set is a pass only when nothing was expected",
           grade(set(), [], ["A"])[0], PASS)
    expect("an empty caller set fails an expectation",
           grade(set(), ["A"], [])[0], FAIL)
    expect("unreadable never grades as a pass",
           grade(None, [], ["A"])[0], UNREADABLE)

    # The report shape, driven through the GATE'S OWN reader rather than a copy
    # of its rules. A copy is exactly what failed: this suite printed three green
    # CHECK lines locally and wrote a report keyed `checks`, and the gate refused
    # it with "carries no results list". The local pass proved the suite ran and
    # said nothing about whether the verdict could be read, and the gate is the
    # verdict.
    import importlib.util
    import tempfile
    gate_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gate.py")
    if not os.path.exists(gate_path):
        failures.append("gate.py is not beside this file, so the report shape went unchecked")
    else:
        spec = importlib.util.spec_from_file_location("acceptance_gate", gate_path)
        gate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gate)
        rows = [Result("0", PASS, "a"), Result("1", FAIL, "b")]
        scratch = tempfile.mkdtemp(prefix="same-owner-selftest-")
        try:
            good = os.path.join(scratch, "good.json")
            with open(good, "w") as handle:
                json.dump(report_payload(rows, "selftest"), handle)
            try:
                loaded = gate.load_report(good)
                expect("the gate reads this suite's report", sorted(loaded), ["0", "1"])
                expect("the gate reads a status off each row",
                       loaded["1"].get("status"), FAIL)
            except Exception as exc:
                failures.append("the gate refused this suite's own report: %s" % exc)

            # CONTROL: the shape that shipped broken must still be refused, or
            # the check above would pass on any payload at all.
            bad = os.path.join(scratch, "bad.json")
            with open(bad, "w") as handle:
                json.dump({"label": "x", "ticket": TICKET,
                           "checks": [{"id": "0", "status": PASS}]}, handle)
            try:
                gate.load_report(bad)
                failures.append("CONTROL: the gate accepted a `checks`-keyed report, "
                                "so this check cannot fail")
            except Exception:
                print("ok: the gate still refuses the `checks`-keyed shape that broke CI")
        finally:
            shutil.rmtree(scratch, ignore_errors=True)

    # A relative --kin resolves against each fixture's cwd, not the caller's, so
    # it is absolutized at parse time. This pins that the absolutizing happens.
    expect("a relative kin path is made absolute",
           os.path.isabs(os.path.abspath("target/release/kin")), True)

    for line in failures:
        print("SELFTEST FAIL %s" % line)
    if failures:
        print("self-test: %d grader case(s) failed" % len(failures))
        return 1
    print("self-test: every grader case and its inverse behaved as declared")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kin", default=os.environ.get("KIN_BIN"))
    parser.add_argument("--daemon", default=None)
    parser.add_argument("--workdir", default=None)
    parser.add_argument("--label", default="local")
    parser.add_argument("--only", default=None)
    parser.add_argument("--json", default=None)
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    if not args.kin:
        print("error: --kin (or KIN_BIN) is required", file=sys.stderr)
        return 3
    # Absolutized HERE, before anything reads it. Every probe runs with `cwd` set
    # to a fixture repository, so a relative `--kin target/release/kin` resolves
    # against that fixture and not against the caller's directory. It validates
    # from the caller's cwd and then fails from the fixture's, which is a check
    # that passed and a use that did not: CI reported three UNREADABLE probes,
    # `No such file or directory: 'target/release/kin'`, while the identical run
    # with an absolute path passed locally.
    kin = os.path.abspath(args.kin)
    if not os.path.isfile(kin) or not os.access(kin, os.X_OK):
        print("error: %s is not an executable kin binary" % kin, file=sys.stderr)
        return 3

    daemon = os.path.abspath(args.daemon) if args.daemon else None
    if not daemon:
        beside = os.path.join(os.path.dirname(kin), "kin-daemon")
        if os.path.isfile(beside) and os.access(beside, os.X_OK):
            daemon = beside

    selected = None
    if args.only:
        selected = {part.strip() for part in args.only.split(",") if part.strip()}

    workdir = os.path.abspath(args.workdir) if args.workdir else tempfile.mkdtemp(prefix="same-owner-call-")
    os.makedirs(workdir, exist_ok=True)
    print("run root: %s" % workdir)
    suite = Suite(kin, workdir, daemon=daemon, verbose=args.verbose)

    results = []
    try:
        for cid, fn in CHECKS:
            if selected is not None and cid not in selected:
                continue
            try:
                results.append(fn(suite))
            except Exception as exc:  # a crashed probe is UNREADABLE, never a verdict
                results.append(Result(cid, UNREADABLE, "the probe raised: %s" % exc))
        if not results:
            results.append(Result("selection", UNREADABLE, "no product checks were selected"))
    finally:
        try:
            results.append(suite.shutdown())
        except Exception as error:
            results.append(cleanup_result(FAIL, "cleanup raised: %s" % error))
    retention = finish_run_root(workdir, results, args.keep, explicit=bool(args.workdir))

    for res in results:
        print("CHECK %s %s %s %s" % (res.id, TICKET, res.status, res.detail))

    failed = [r for r in results if r.status == FAIL]
    unreadable = [r for r in results if r.status == UNREADABLE]
    print("same-owner-call-repro: %d checks, %d passed, %d failed, %d unreadable (%s)"
          % (len(results), len(results) - len(failed) - len(unreadable),
             len(failed), len(unreadable), args.label))

    if args.json:
        with open(args.json, "w") as handle:
            payload = report_payload(results, args.label)
            payload.update(retention)
            json.dump(payload, handle, indent=2, sort_keys=True)

    if failed:
        return 1
    if unreadable:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
