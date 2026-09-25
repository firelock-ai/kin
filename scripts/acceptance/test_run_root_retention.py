#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
"""Drive four acceptance suites' real main() through cleanup and retention, no kin, no daemon.

trace_spine_clipping_repro, mcp_spawn_admission_repro, graph_viz_local_render and
response_budget_elisions each stop the repositories they own with
`kin daemon stop --json`, report that stop as a `cleanup` result row, and then
keep or remove their run root. A stop counts only when its report confirms the
worker stopped and its endpoint was retired; a repository with no manifest is
never stopped, so discovery cannot walk up to an unrelated one. The root goes
only after a run where every row, cleanup included, passed, and nobody asked to
keep it or named it.

What is stubbed, and why:

- `kin`: a shell script that logs every call with its working directory, answers
  `kin daemon stop --json` with a confirmed, unconfirmed or failing
  kin.daemon-stop.v1 report as its `mode` file says, and fails `kin init` when an
  `init-fails` file sits beside it. No real binary is needed.
- The checks themselves, because a real one needs a kin build and a daemon:
  trace_spine's CHECKS, mcp_spawn's four check functions, graph_viz's
  build_store, fetch_payload, namespace_of and run_refusal, and response_budget's
  CHECKS and Suite.fixture. Each synthetic check owns a repository the way the
  real fixture does, so the real shutdown path stops it.
- subprocess.run, raising for the stop call only, for a stop that raises.
- shutil.rmtree, raising for the run root only, for a root that will not go.

Where a test needs a real init to fail, it runs the suite's real fixture builder
with real git and the stub kin. tempfile.tempdir points at a directory this test
owns, so every run root can be found on disk.
"""

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


def _load(name):
    spec = importlib.util.spec_from_file_location(
        name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


trace = _load("trace_spine_clipping_repro")
spawn = _load("mcp_spawn_admission_repro")
viz = _load("graph_viz_local_render")
budget = _load("response_budget_elisions")

REAL_RMTREE = shutil.rmtree
REAL_RUN = subprocess.run

STUB_KIN = """#!/bin/sh
here=$(cd "$(dirname "$0")" && pwd -P)
printf '%s|%s\\n' "$(pwd -P)" "$*" >> "$here/calls.log"
if [ "$1" = "init" ] && [ -f "$here/init-fails" ]; then
  echo "stub init refuses" >&2
  exit 1
fi
if [ "$1" = "daemon" ] && [ "$2" = "stop" ]; then
  mode=$(cat "$here/mode" 2>/dev/null)
  case "$mode" in
    unconfirmed)
      echo '{"schema": "kin.daemon-stop.v1", "scope": "current-repo", "stopped": [{"kind": "repo-daemon", "result": "timeout"}], "all_stopped": false, "endpoints_retired": true}'
      exit 0 ;;
    rc1)
      echo '{"schema": "kin.daemon-stop.v1", "scope": "current-repo", "stopped": [], "all_stopped": true}'
      exit 1 ;;
    *)
      echo '{"schema": "kin.daemon-stop.v1", "scope": "current-repo", "stopped": [{"kind": "repo-daemon", "result": "stopped"}], "all_stopped": true, "endpoints_retired": true}'
      exit 0 ;;
  esac
fi
exit 0
"""

CONFIRMED = {"schema": "kin.daemon-stop.v1", "scope": "current-repo",
             "stopped": [], "all_stopped": True}


class StopConfirmed(unittest.TestCase):
    """Every suite's own stop_confirmed reads the product's report the same way."""

    def test_each_suite_confirms_only_a_retired_worker(self):
        retired = dict(CONFIRMED, stopped=[{"result": "stopped"}], endpoints_retired=True)
        for module in (trace, spawn, viz, budget):
            confirmed = module.stop_confirmed
            with self.subTest(suite=module.__name__):
                self.assertTrue(confirmed(0, CONFIRMED))
                self.assertTrue(confirmed(0, retired))
                self.assertTrue(confirmed(0, dict(retired, stopped=[{"result": "not-running"}])))
                self.assertFalse(confirmed(1, CONFIRMED))
                self.assertFalse(confirmed(0, None))
                self.assertFalse(confirmed(0, dict(CONFIRMED, schema="kin.daemon-stop.v0")))
                self.assertFalse(confirmed(0, dict(CONFIRMED, scope="all")))
                self.assertFalse(confirmed(0, dict(CONFIRMED, all_stopped=False)))
                self.assertFalse(confirmed(0, dict(CONFIRMED, endpoints_retired=False)))
                self.assertFalse(confirmed(0, dict(CONFIRMED, stopped=[{"result": "stopped"}])))
                self.assertFalse(confirmed(0, dict(retired, stopped=[{"result": "timeout"}])))
                self.assertFalse(confirmed(0, dict(retired, stopped=[
                    {"result": "stopped", "preserved_endpoint": {"reason": "still published"}}])))


class RunRootCase(unittest.TestCase):
    """A scratch tree per test: a stub kin, a temp root to find runs in, a report."""

    def setUp(self):
        self.scratch = Path(os.path.realpath(tempfile.mkdtemp(prefix="run-root-retention-test-")))
        self.roots = self.scratch / "roots"
        self.roots.mkdir()
        self.bin = self.scratch / "bin"
        self.bin.mkdir()
        self.kin = self.bin / "kin"
        self.kin.write_text(STUB_KIN)
        self.kin.chmod(0o755)
        self.report = self.scratch / "report.json"
        redirect = mock.patch.object(tempfile, "tempdir", str(self.roots))
        redirect.start()
        self.addCleanup(redirect.stop)

    def tearDown(self):
        for path, _, _ in os.walk(self.scratch):
            os.chmod(path, 0o755)
        REAL_RMTREE(self.scratch, ignore_errors=True)

    def stop_mode(self, mode):
        (self.bin / "mode").write_text(mode)

    def init_fails(self):
        (self.bin / "init-fails").write_text("")

    def stop_calls_in(self, repo):
        log = self.bin / "calls.log"
        if not log.exists():
            return []
        where = os.path.realpath(str(repo))
        return [line for line in log.read_text().splitlines()
                if line.startswith(where + "|daemon stop")]

    def run_roots(self):
        return sorted(self.roots.iterdir())

    @staticmethod
    def owned_repo(path, manifest=True):
        path = Path(path)
        (path / ".kin").mkdir(parents=True, exist_ok=True)
        if manifest:
            (path / ".kin" / "manifest.json").write_text("{}")
        return str(path)

    @contextlib.contextmanager
    def rmtree_fails_for_the_run_root(self):
        def failing(path, *args, **kwargs):
            if Path(path).parent == self.roots:
                if kwargs.get("ignore_errors"):
                    return None  # as the real one: the error is swallowed
                raise PermissionError(13, "Permission denied", str(path))
            return REAL_RMTREE(path, *args, **kwargs)
        with mock.patch.object(shutil, "rmtree", failing):
            yield

    @contextlib.contextmanager
    def stop_raises(self):
        def raising(argv, *args, **kwargs):
            if [str(part) for part in list(argv)[1:4]] == ["daemon", "stop", "--json"]:
                raise OSError("synthetic: the stop could not be started")
            return REAL_RUN(argv, *args, **kwargs)
        with mock.patch.object(subprocess, "run", raising):
            yield

    def read_report(self):
        with open(self.report) as handle:
            return json.load(handle)

    def row(self, report, ident):
        rows = [row for row in report["results"] if str(row["id"]) == ident]
        self.assertEqual(len(rows), 1, report["results"])
        return rows[0]

    def assert_removed(self, report):
        self.assertEqual(self.run_roots(), [], "a successful, stopped run removes its root")
        self.assertFalse(report["run_root_retained"])
        self.assertEqual(report["run_root_retention_reason"], "successful disposable run")
        self.assertEqual(self.row(report, "cleanup")["status"], "PASS")

    def assert_retained(self, report, reason, cleanup="PASS"):
        roots = self.run_roots()
        self.assertEqual(len(roots), 1, "a retained run keeps exactly its root")
        self.assertEqual(os.path.realpath(str(roots[0])), os.path.realpath(report["run_root"]))
        self.assertTrue(report["run_root_retained"])
        self.assertIn(reason, report["run_root_retention_reason"])
        self.assertEqual(self.row(report, "cleanup")["status"], cleanup)


class TraceSpineCleanup(RunRootCase):
    """trace_spine_clipping_repro: one fixture repository, stopped by Suite.shutdown."""

    def run_main(self, statuses=None, keep=False, manifest=True):
        statuses = statuses or [trace.PASS] * 8
        self.repo = None
        checks = []
        for index, (ident, _) in enumerate(trace.CHECKS):
            def check(suite, ident=ident, status=statuses[index], first=index == 0):
                if first:
                    self.repo = self.owned_repo(Path(suite.workdir) / "sessions", manifest)
                    suite.owned_repos.add(self.repo)
                return trace.Result(ident, status, "synthetic")
            checks.append((ident, check))
        argv = ["--kin", str(self.kin), "--daemon", str(self.kin),
                "--json", str(self.report)] + (["--keep"] if keep else [])
        with mock.patch.object(trace, "CHECKS", checks):
            with contextlib.redirect_stdout(io.StringIO()):
                code = trace.main(argv)
        return code, self.read_report()

    def test_trace_spine_a_confirmed_stop_passes_and_the_root_goes(self):
        code, report = self.run_main()
        self.assertEqual(code, 0)
        self.assert_removed(report)
        self.assertEqual(len(self.stop_calls_in(self.repo)), 1)
        self.assertEqual(len(report["results"]), 9, "eight checks and the cleanup row")

    def test_trace_spine_an_unconfirmed_stop_fails_and_keeps_the_root(self):
        self.stop_mode("unconfirmed")
        code, report = self.run_main()
        self.assertEqual(code, 1)
        self.assert_retained(report, "failed or unreadable", cleanup="FAIL")

    def test_trace_spine_a_nonzero_stop_fails_and_keeps_the_root(self):
        self.stop_mode("rc1")
        code, report = self.run_main()
        self.assertEqual(code, 1)
        self.assert_retained(report, "failed or unreadable", cleanup="FAIL")

    def test_trace_spine_a_stop_that_raises_fails_and_keeps_the_root(self):
        with self.stop_raises():
            code, report = self.run_main()
        self.assertEqual(code, 1)
        self.assert_retained(report, "failed or unreadable", cleanup="FAIL")
        self.assertIn("OSError", self.row(report, "cleanup")["detail"])

    def test_trace_spine_a_missing_manifest_is_never_stopped(self):
        code, report = self.run_main(manifest=False)
        self.assertEqual(self.stop_calls_in(self.repo), [])
        self.assertEqual(code, 1)
        self.assert_retained(report, "failed or unreadable", cleanup="FAIL")
        self.assertIn("manifest missing", self.row(report, "cleanup")["detail"])

    def test_trace_spine_a_failing_check_keeps_the_root(self):
        code, report = self.run_main([trace.PASS] * 3 + [trace.FAIL] + [trace.PASS] * 4)
        self.assertEqual(code, 1)
        self.assert_retained(report, "failed or unreadable")

    def test_trace_spine_an_unreadable_check_keeps_the_root(self):
        code, report = self.run_main([trace.PASS] * 7 + [trace.UNREADABLE])
        self.assertEqual(code, 2)
        self.assert_retained(report, "failed or unreadable")

    def test_trace_spine_a_root_that_will_not_go_gets_its_own_row(self):
        with self.rmtree_fails_for_the_run_root():
            code, report = self.run_main()
        self.assertEqual(code, 1)
        self.assert_retained(report, "fixture removal failed")
        self.assertEqual(self.row(report, "cleanup-root")["status"], "FAIL")

    def test_trace_spine_keep_keeps_the_root(self):
        code, report = self.run_main(keep=True)
        self.assertEqual(code, 0)
        self.assert_retained(report, "--keep")

    def test_trace_spine_a_failed_init_is_still_owned(self):
        self.init_fails()
        suite = trace.Suite(str(self.kin), str(self.scratch))
        with self.assertRaises(RuntimeError):
            suite.repo()
        self.assertIn(os.path.join(str(self.scratch), "sessions"), suite.owned_repos)


class McpSpawnCleanup(RunRootCase):
    """mcp_spawn_admission_repro: each arm stops its own repository inside session()."""

    CHECKS = (
        "check_handshake_starts_no_daemon",
        "check_roots_answer_starts_no_daemon",
        "check_a_tool_call_still_starts_the_daemon",
        "check_a_tool_call_still_dispatches_the_embed",
    )

    def run_main(self, statuses=None, keep=False, manifest=True, session_stops=True):
        statuses = statuses or ["PASS"] * 4
        self.repos = []
        patches = []
        for name, status in zip(self.CHECKS, statuses):
            def check(kin, daemon_bin, workdir, name=name, status=status):
                repo = Path(self.owned_repo(Path(workdir) / name / "repo", manifest))
                spawn.OWNED_REPOS[str(repo)] = dict(os.environ)
                self.repos.append(repo)
                if session_stops:
                    spawn.stop_owned_repo(kin, repo, dict(os.environ))
                return spawn.emit(name, status, "synthetic")
            patches.append(mock.patch.object(spawn, name, check))
        argv = ["mcp_spawn_admission_repro.py", "--kin", str(self.kin),
                "--daemon", str(self.kin), "--json", str(self.report)]
        argv += ["--keep"] if keep else []
        with contextlib.ExitStack() as stack:
            for patch in patches:
                stack.enter_context(patch)
            stack.enter_context(mock.patch.object(sys, "argv", argv))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            code = spawn.main()
        return code, self.read_report()

    def test_mcp_spawn_confirmed_session_stops_pass_and_the_root_goes(self):
        code, report = self.run_main()
        self.assertEqual(code, 0)
        self.assert_removed(report)
        for repo in self.repos:
            self.assertEqual(len(self.stop_calls_in(repo)), 1, "stopped once, by its session")

    def test_mcp_spawn_an_owned_repo_no_session_stopped_is_stopped_at_shutdown(self):
        code, report = self.run_main(session_stops=False)
        self.assert_removed(report)
        for repo in self.repos:
            self.assertEqual(len(self.stop_calls_in(repo)), 1, "stopped once, at shutdown")

    def test_mcp_spawn_an_unconfirmed_stop_fails_and_keeps_the_root(self):
        self.stop_mode("unconfirmed")
        code, report = self.run_main()
        self.assertEqual(code, 0, "this suite's exit never carried a verdict")
        self.assert_retained(report, "failed or unreadable", cleanup="FAIL")

    def test_mcp_spawn_a_nonzero_stop_fails_and_keeps_the_root(self):
        self.stop_mode("rc1")
        code, report = self.run_main()
        self.assert_retained(report, "failed or unreadable", cleanup="FAIL")

    def test_mcp_spawn_a_stop_that_raises_fails_and_keeps_the_root(self):
        with self.stop_raises():
            code, report = self.run_main()
        self.assert_retained(report, "failed or unreadable", cleanup="FAIL")

    def test_mcp_spawn_a_missing_manifest_is_never_stopped(self):
        code, report = self.run_main(manifest=False)
        for repo in self.repos:
            self.assertEqual(self.stop_calls_in(repo), [])
        self.assert_retained(report, "failed or unreadable", cleanup="FAIL")

    def test_mcp_spawn_a_failing_check_keeps_the_root(self):
        code, report = self.run_main(["PASS", "FAIL", "PASS", "PASS"])
        self.assert_retained(report, "failed or unreadable")

    def test_mcp_spawn_a_root_that_will_not_go_gets_its_own_row(self):
        with self.rmtree_fails_for_the_run_root():
            code, report = self.run_main()
        self.assert_retained(report, "fixture removal failed")
        self.assertEqual(self.row(report, "cleanup-root")["status"], "FAIL")

    def test_mcp_spawn_keep_keeps_the_root(self):
        code, report = self.run_main(keep=True)
        self.assert_retained(report, "--keep")

    def test_mcp_spawn_a_failed_init_is_still_owned(self):
        self.init_fails()
        spawn.OWNED_REPOS.clear()
        root = self.scratch / "failed-init"
        env = {**os.environ, "KIN_HOME": str(self.scratch / "home")}
        with self.assertRaises(RuntimeError):
            spawn.build_fixture(root, str(self.kin), env)
        self.assertIn(str(root / "repo"), spawn.OWNED_REPOS)


class GraphVizCleanup(RunRootCase):
    """Every graph-viz arm stays owned even when initialization fails."""

    def run_main(self, mode="pass", keep=False, manifest=True):
        def build_store(kin, env, work):
            work.mkdir(parents=True, exist_ok=True)
            if manifest and mode != "init-fails":
                self.owned_repo(work)
            failed_after_manifest = mode == "partial-init-" + work.name
            code = 1 if mode in ("unreadable", "init-fails") or failed_after_manifest else 0
            return subprocess.CompletedProcess([], code, "", "synthetic")

        def fetch_payload(kin, env, work, port, timeout=180):
            nodes = [] if mode == "fail" else [{"id": "a"}]
            return ({"nodes": nodes, "entity_count": len(nodes)},
                    "drawing from the local store directly", 0)

        def namespace_of(work):
            namespace = work / ".kin" / "kindb" / "synthetic"
            namespace.mkdir(parents=True, exist_ok=True)
            return namespace

        def run_refusal(kin, env, work, port, timeout=180):
            return 1, "cannot read %s" % (work / ".kin" / "kindb" / "synthetic")

        argv = ["graph_viz_local_render.py", "--kin", str(self.kin),
                "--json", str(self.report)] + (["--keep"] if keep else [])
        with contextlib.ExitStack() as stack:
            for name, stub in (("build_store", build_store),
                               ("fetch_payload", fetch_payload),
                               ("namespace_of", namespace_of),
                               ("run_refusal", run_refusal)):
                stack.enter_context(mock.patch.object(viz, name, stub))
            stack.enter_context(mock.patch.object(sys, "argv", argv))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            code = viz.main()
        report = self.read_report()
        self.work_a = Path(report["run_root"]) / "work-a"
        return code, report

    def test_graph_viz_arm_a_is_stopped_and_the_root_goes(self):
        code, report = self.run_main()
        self.assertEqual(code, 0)
        self.assert_removed(report)
        self.assertEqual(len(self.stop_calls_in(self.work_a)), 1)

    def test_graph_viz_refusal_arm_failed_init_is_stopped(self):
        code, report = self.run_main(mode="partial-init-work-b")
        self.assertEqual(code, 2)
        self.assert_retained(report, "failed or unreadable")
        self.assertEqual(len(self.stop_calls_in(Path(report["run_root"]) / "work-b")), 1)

    def test_graph_viz_local_arm_failed_init_is_stopped(self):
        code, report = self.run_main(mode="partial-init-work-c")
        self.assertEqual(code, 2)
        self.assert_retained(report, "failed or unreadable")
        self.assertEqual(len(self.stop_calls_in(Path(report["run_root"]) / "work-c")), 1)

    def test_graph_viz_an_unconfirmed_stop_fails_and_keeps_the_root(self):
        self.stop_mode("unconfirmed")
        code, report = self.run_main()
        self.assertEqual(code, 1)
        self.assert_retained(report, "failed or unreadable", cleanup="FAIL")

    def test_graph_viz_a_nonzero_stop_fails_and_keeps_the_root(self):
        self.stop_mode("rc1")
        code, report = self.run_main()
        self.assertEqual(code, 1)
        self.assert_retained(report, "failed or unreadable", cleanup="FAIL")

    def test_graph_viz_a_stop_that_raises_fails_and_keeps_the_root(self):
        with self.stop_raises():
            code, report = self.run_main()
        self.assertEqual(code, 1)
        self.assert_retained(report, "failed or unreadable", cleanup="FAIL")

    def test_graph_viz_a_missing_manifest_is_never_stopped(self):
        code, report = self.run_main(manifest=False)
        self.assertEqual(self.stop_calls_in(self.work_a), [])
        self.assert_retained(report, "failed or unreadable", cleanup="FAIL")

    def test_graph_viz_a_failed_init_is_still_owned(self):
        code, report = self.run_main(mode="init-fails")
        self.assertEqual(code, 1)
        records = json.loads((Path(report["run_root"]) / "daemon-cleanup.json").read_text())
        self.assertEqual([record["repo"] for record in records],
                         [str(self.work_a.parent / ("work-" + arm)) for arm in "abc"])
        self.assertTrue(all("manifest missing" in record["error"] for record in records))

    def test_graph_viz_a_failing_check_keeps_the_root(self):
        code, report = self.run_main(mode="fail")
        self.assertEqual(code, 1)
        self.assert_retained(report, "failed or unreadable")

    def test_graph_viz_a_root_that_will_not_go_gets_its_own_row(self):
        with self.rmtree_fails_for_the_run_root():
            code, report = self.run_main()
        self.assertEqual(code, 1)
        self.assert_retained(report, "fixture removal failed")
        self.assertEqual(self.row(report, "cleanup-root")["status"], "FAIL")

    def test_graph_viz_keep_keeps_the_root(self):
        code, report = self.run_main(keep=True)
        self.assertEqual(code, 0)
        self.assert_retained(report, "--keep")


class ResponseBudgetCleanup(RunRootCase):
    """response_budget_elisions: the MCP-started daemon is stopped, and --workdir is kept."""

    def run_main(self, statuses=None, keep=False, manifest=True, workdir=None,
                 setup_fails=False):
        statuses = statuses or ["PASS"] * 3
        self.repo = None

        def fixture(suite):
            repo = os.path.join(suite.workdir, "fixture-" + suite.run_id)
            self.repo = self.owned_repo(repo, manifest)
            suite.owned_repos.add(self.repo)
            if setup_fails:
                raise budget.SetupError("synthetic setup failure")
            suite.repo = self.repo
            return self.repo

        checks = []
        for index, status in enumerate(statuses):
            def check(suite, ident=str(index), status=status):
                res = budget.Result(ident, None, "synthetic check %s" % ident)
                {"PASS": res.ok, "FAIL": res.bad, "UNREADABLE": res.unknown}[status]("synthetic")
                return res
            checks.append((str(index), check))
        argv = ["--kin", str(self.kin), "--json", str(self.report)]
        argv += ["--keep"] if keep else []
        argv += ["--workdir", str(workdir)] if workdir else []
        with mock.patch.object(budget, "CHECKS", checks), \
                mock.patch.object(budget.Suite, "fixture", fixture), \
                contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            code = budget.main(argv)
        return code

    def test_response_budget_a_confirmed_stop_passes_and_the_default_root_goes(self):
        self.assertEqual(self.run_main(), 0)
        report = self.read_report()
        self.assert_removed(report)
        self.assertEqual(len(self.stop_calls_in(self.repo)), 1)

    def test_response_budget_an_unconfirmed_stop_fails_and_keeps_the_root(self):
        self.stop_mode("unconfirmed")
        self.assertEqual(self.run_main(), 1)
        self.assert_retained(self.read_report(), "failed or unreadable", cleanup="FAIL")

    def test_response_budget_a_nonzero_stop_fails_and_keeps_the_root(self):
        self.stop_mode("rc1")
        self.assertEqual(self.run_main(), 1)
        self.assert_retained(self.read_report(), "failed or unreadable", cleanup="FAIL")

    def test_response_budget_a_stop_that_raises_fails_and_keeps_the_root(self):
        with self.stop_raises():
            self.assertEqual(self.run_main(), 1)
        self.assert_retained(self.read_report(), "failed or unreadable", cleanup="FAIL")

    def test_response_budget_a_missing_manifest_is_never_stopped(self):
        self.assertEqual(self.run_main(manifest=False), 1)
        self.assertEqual(self.stop_calls_in(self.repo), [])
        self.assert_retained(self.read_report(), "failed or unreadable", cleanup="FAIL")

    def test_response_budget_a_failing_check_keeps_the_root(self):
        self.assertEqual(self.run_main(["PASS", "FAIL", "PASS"]), 1)
        self.assert_retained(self.read_report(), "failed or unreadable")

    def test_response_budget_a_setup_failure_still_stops_and_keeps(self):
        self.assertEqual(self.run_main(setup_fails=True), 3)
        self.assertFalse(self.report.exists(), "that path writes no report, as before")
        self.assertEqual(len(self.stop_calls_in(self.repo)), 1)
        self.assertEqual(len(self.run_roots()), 1)

    def test_response_budget_a_root_that_will_not_go_gets_its_own_row(self):
        with self.rmtree_fails_for_the_run_root():
            self.assertEqual(self.run_main(), 1)
        report = self.read_report()
        self.assert_retained(report, "fixture removal failed")
        self.assertEqual(self.row(report, "cleanup-root")["status"], "FAIL")

    def test_response_budget_keep_keeps_the_root(self):
        self.assertEqual(self.run_main(keep=True), 0)
        self.assert_retained(self.read_report(), "--keep")

    def test_response_budget_an_explicit_workdir_is_never_removed(self):
        explicit = self.roots / "caller-owned"
        self.assertEqual(self.run_main(workdir=explicit), 0)
        self.assert_retained(self.read_report(), "caller-owned workdir")
        self.assertTrue(explicit.is_dir())

    def test_response_budget_a_failed_init_is_still_owned(self):
        self.init_fails()
        suite = budget.Suite(str(self.kin), str(self.scratch), False)
        with self.assertRaises(budget.SetupError):
            suite.fixture()
        self.assertIn(os.path.join(str(self.scratch), "fixture-" + suite.run_id),
                      suite.owned_repos)


if __name__ == "__main__":
    unittest.main()
