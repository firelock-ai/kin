#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
"""NON-CITABLE acceptance suite for hydration-semantics disclosure (FIR-2829).

This suite proves one control and two gaps against a store built by the binary
under test. A fresh store must carry the creation-time stamp and stay silent on
``kin graph status`` and the MCP degraded map while ``kin doctor`` reports a
healthy row. A store stamped one replay version behind and a store with no
stamp must both disclose on all three surfaces.

The control is load-bearing. A writer that silently stopped writing would make
every new store look legacy, and a comparator that always reported a gap would
make both gap arms green. Requiring the fresh store to stay silent catches both
defects.

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


PASS = "PASS"
FAIL = "FAIL"
UNREADABLE = "UNREADABLE"
TICKET = "FIR-2829"
STAMP_REL = os.path.join(".kin", "kindb", "hydration-semantics")
FLAG = "hydration_semantics_stale"


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


def status_problems(text, gap, created_under=None, derives=None):
    """Return problems in one ``kin graph status`` rendering."""
    lines = [line.strip() for line in (text or "").splitlines()]
    hits = [line for line in lines if "hydration semantics:" in line.lower()]
    if not gap:
        return [] if not hits else ["a current store printed %r" % hits]
    if len(hits) != 1:
        return ["expected one hydration-semantics warning, got %d" % len(hits)]
    line = hits[0]
    problems = []
    if "Remedy:" not in line:
        problems.append("the warning carries no remedy")
    if created_under is None:
        if "records no hydration semantics version" not in line:
            problems.append("an unstamped store is not named as unstamped")
        if "Remedy: upgrade Kin before changing this store" not in line:
            problems.append("an unstamped store is not given upgrade-first advice")
    else:
        if "records hydration semantics version %d at creation" % created_under not in line:
            problems.append("the warning does not name recorded version %d" % created_under)
    if derives is not None and str(derives) not in line:
        problems.append("the warning does not name binary version %d" % derives)
    return problems


def doctor_problems(report, gap, created_under=None, derives=None):
    """Return problems in the ``hydration_semantics`` doctor row."""
    rows = [
        row
        for row in (report or {}).get("checks", [])
        if row.get("id") == "hydration_semantics"
    ]
    if len(rows) != 1:
        return ["expected one hydration_semantics row, got %d" % len(rows)]
    row = rows[0]
    wanted = "stale" if gap else "healthy"
    problems = []
    if row.get("status") != wanted:
        problems.append("status is %r, wanted %r" % (row.get("status"), wanted))
    detail = row.get("detail") or ""
    fix = row.get("manual_fix")
    if gap and not isinstance(fix, str):
        problems.append("a stale row carries no manual_fix")
    if not gap and fix is not None:
        problems.append("a current row manufactured a manual_fix")
    if created_under is None and gap:
        if "records no hydration semantics version" not in detail:
            problems.append("an unstamped row is not named as unstamped")
        if not isinstance(fix, str) or not fix.startswith(
            "upgrade Kin before changing this store"
        ):
            problems.append("an unstamped row is not given upgrade-first advice")
    elif created_under is not None and str(created_under) not in detail:
        problems.append("detail does not name recorded version %d" % created_under)
    if derives is not None and str(derives) not in detail:
        problems.append("detail does not name binary version %d" % derives)
    return problems


def envelope_problems(payload, gap):
    """Return problems in the stdio MCP response envelope."""
    envelope = (payload or {}).get("_kin")
    if not isinstance(envelope, dict):
        return ["the MCP payload carries no _kin envelope"]
    degraded = envelope.get("degraded")
    if not isinstance(degraded, dict):
        return ["the _kin envelope carries no degraded object"]
    if gap:
        return [] if degraded.get(FLAG) is True else ["%s is not true" % FLAG]
    return [] if FLAG not in degraded else ["a current store serialized %s" % FLAG]


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

    def mcp(self, tool, args, timeout=300):
        env = dict(self.env)
        env["KIN_MCP_REPO"] = self.repo
        proc = subprocess.Popen(
            [self.kin, "mcp", "start", "--repo", self.repo],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=self.repo,
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
        os.makedirs(os.path.join(self.repo, "src"), exist_ok=True)
        with open(os.path.join(self.repo, "src", "lib.rs"), "w") as handle:
            handle.write("pub fn hydration_fixture() -> usize { 1 }\n")
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
        if name == "control":
            body = dict(self.original_stamp)
        elif name == "behind":
            body = dict(self.original_stamp)
            body["created_under"] = self.derives - 1
        elif name == "absent":
            try:
                os.unlink(self.stamp_path)
            except FileNotFoundError:
                pass
            return
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
        observation = {"status": status, "doctor": doctor, "envelope": envelope}
        self.observations[name] = observation
        return observation


ARMS = (
    ("control", False, None),
    ("behind", True, "behind"),
    ("absent", True, None),
)


def check_status(suite):
    result = Result("status", "graph status stays silent on agreement and discloses every gap")
    for name, gap, recorded in ARMS:
        rc, out = suite.observe(name)["status"]
        if rc != 0:
            result.unknown("%s: graph status exited %d: %s" % (name, rc, tail(out)))
            continue
        recorded_under = suite.derives - 1 if recorded == "behind" else None
        problems = status_problems(out, gap, recorded_under, suite.derives)
        if problems:
            result.bad("%s: %s; output: %s" % (name, "; ".join(problems), tail(out)))
        else:
            result.ok("%s: %s" % (name, "gap disclosed" if gap else "current and silent"))
    return result


def check_doctor(suite):
    result = Result("doctor", "doctor separates current from stale creation-time semantics")
    for name, gap, recorded in ARMS:
        rc, report, error = suite.observe(name)["doctor"]
        if report is None:
            result.unknown("%s: doctor output unreadable (rc=%d): %s" % (name, rc, error))
            continue
        recorded_under = suite.derives - 1 if recorded == "behind" else None
        problems = doctor_problems(report, gap, recorded_under, suite.derives)
        if problems:
            result.bad("%s: %s" % (name, "; ".join(problems)))
        else:
            result.ok("%s: %s row" % (name, "stale" if gap else "healthy"))
    return result


def check_envelope(suite):
    result = Result("envelope", "the stdio MCP envelope carries only affirmative gaps")
    for name, gap, _recorded in ARMS:
        payload, error = suite.observe(name)["envelope"]
        if payload is None:
            result.unknown("%s: MCP envelope unreadable: %s" % (name, error))
            continue
        problems = envelope_problems(payload, gap)
        if problems:
            result.bad("%s: %s; payload: %s" % (name, "; ".join(problems), tail(json.dumps(payload))))
        else:
            result.ok("%s: flag %s" % (name, "true" if gap else "absent"))
    return result


CHECKS = (check_status, check_doctor, check_envelope)
DECLARED = ("status", "doctor", "envelope")


def self_test():
    failures = []
    count = [0]

    def expect(label, got, want):
        count[0] += 1
        if got != want:
            failures.append("%s: got %r, wanted %r" % (label, got, want))

    current_line = "Graph healthy\n"
    gap_line = (
        "⚠ hydration semantics: this store records hydration semantics version 9 at creation "
        "and this build derives version 10. Remedy: re-ingest the repository.\n"
    )
    absent_line = (
        "⚠ hydration semantics: this graph records no hydration semantics version, and this "
        "build derives version 10. Remedy: upgrade Kin before changing this store.\n"
    )
    expect("status control", status_problems(current_line, False), [])
    expect("status gap", status_problems(gap_line, True, 9, 10), [])
    expect("status absent", status_problems(absent_line, True, None, 10), [])
    expect("status unconditional warning fails", len(status_problems(gap_line, False)) > 0, True)
    expect("status missing remedy fails", len(status_problems(gap_line.replace(" Remedy: re-ingest the repository.", ""), True, 9, 10)) > 0, True)

    current_row = {"checks": [{"id": "hydration_semantics", "status": "healthy", "detail": "version 10, which is what this build derives", "manual_fix": None}]}
    stale_row = {"checks": [{"id": "hydration_semantics", "status": "stale", "detail": "records hydration semantics version 9 at creation, this build derives 10", "manual_fix": "re-ingest"}]}
    absent_row = {"checks": [{"id": "hydration_semantics", "status": "stale", "detail": "records no hydration semantics version; derives 10", "manual_fix": "upgrade Kin before changing this store"}]}
    expect("doctor control", doctor_problems(current_row, False, None, 10), [])
    expect("doctor stale", doctor_problems(stale_row, True, 9, 10), [])
    expect("doctor absent", doctor_problems(absent_row, True, None, 10), [])
    expect("doctor false healthy fails", len(doctor_problems(current_row, True, 9, 10)) > 0, True)
    expect("doctor missing row fails", len(doctor_problems({"checks": []}, False, None, 10)) > 0, True)

    clean_env = {"_kin": {"degraded": {}}}
    gap_env = {"_kin": {"degraded": {FLAG: True}}}
    false_env = {"_kin": {"degraded": {FLAG: False}}}
    expect("envelope control", envelope_problems(clean_env, False), [])
    expect("envelope gap", envelope_problems(gap_env, True), [])
    expect("envelope false is not a gap", len(envelope_problems(false_env, True)) > 0, True)
    expect("envelope false is not silence", len(envelope_problems(false_env, False)) > 0, True)
    expect("envelope missing is unreadable", len(envelope_problems({}, True)) > 0, True)

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
        if suite is not None and os.path.isdir(suite.repo):
            suite.kin_run(["daemon", "stop"])
        if not args.keep:
            shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
