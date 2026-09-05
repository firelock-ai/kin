#!/usr/bin/env python3
"""Exercise fixture cleanup with synthetic stop responses and no processes."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MODULES = [load("magic_repro"), load("brownfield_repro")]
GATE = load("gate")


def response(**changes):
    payload = {"schema": "kin.daemon-stop.v1", "scope": "current-repo",
               "stopped": [{"result": "stopped"}], "all_stopped": True,
               "endpoints_retired": True}
    payload.update(changes)
    return json.dumps(payload)


class FixtureShutdownTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="fixture-shutdown-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.kill = mock.patch("os.kill").start()
        self.addCleanup(mock.patch.stopall)
        mock.patch("subprocess.Popen", side_effect=AssertionError("unexpected process")).start()

    def suite(self, module, pids=("424242",)):
        suite = module.Suite.__new__(module.Suite)
        suite.fixtures = {}
        for index, pid in enumerate(pids):
            path = self.root / module.__name__ / str(index)
            (path / ".kin").mkdir(parents=True, exist_ok=True)
            (path / ".kin" / "manifest.json").write_text("{}")
            if pid is not None:
                (path / ".kin" / "daemon.pid").write_text(pid)
            suite.fixtures[str(index)] = str(path)
        suite.kin_run = mock.Mock(return_value=(0, response(), ""))
        return suite

    def test_foreign_or_reused_pid_never_authorizes_a_signal(self):
        for module in MODULES:
            with self.subTest(suite=module.__name__):
                suite = self.suite(module)
                result = suite.shutdown()
                self.kill.assert_not_called()
                suite.kin_run.assert_called_once_with(
                    ["daemon", "stop", "--json"], next(iter(suite.fixtures.values())), timeout=60)
                self.assertEqual(result.status, module.PASS)

    def test_stop_does_not_depend_on_pid_file(self):
        for module in MODULES:
            for pid in (None, "not a pid"):
                with self.subTest(suite=module.__name__, pid=pid):
                    suite = self.suite(module, (pid,))
                    result = suite.shutdown()
                    self.assertEqual(suite.kin_run.call_count, 1)
                    self.assertEqual(result.status, module.PASS)
                    self.kill.assert_not_called()

    def test_refusals_are_failures_and_remaining_fixtures_are_attempted(self):
        cases = [(1, response(), "command failed"), (1, response(all_stopped=False), "identity mismatch"),
                 (-9, "", "timeout"), (0, "not JSON", ""),
                 (0, response(endpoints_retired=False), ""),
                 (0, response(scope="home"), ""),
                 (0, response(all_stopped=False), ""),
                 (0, response(stopped=[{"result": "signal-failed"}]), ""),
                 (0, response(stopped=[{"result": "stopped", "preserved_endpoint": {}}]), ""),
                 (1, response(stopped=[{"result": "stopped"}, {"result": "timeout"}], all_stopped=False), "partial stop"),
                 (0, response(stopped=[], schema="wrong-schema"), ""),
                 (0, response(stopped=[], all_stopped=False), ""),
                 (0, response(stopped=[], endpoints_retired=False), ""),
                 (0, response(stopped=["malformed row"]), ""),
                 (0, "[]", ""),
                 OSError("cannot execute stop")]
        for module in MODULES:
            for failure in cases:
                with self.subTest(suite=module.__name__, failure=str(failure)):
                    suite = self.suite(module, ("424242", "424243"))
                    suite.kin_run.side_effect = [failure, (0, response(), "")]
                    result = suite.shutdown()
                    self.assertEqual(result.status, module.FAIL)
                    self.assertEqual(suite.kin_run.call_count, 2)
                    self.kill.assert_not_called()

    def test_missing_manifest_cannot_stop_an_enclosing_repository(self):
        for module in MODULES:
            suite = self.suite(module)
            path = Path(next(iter(suite.fixtures.values())))
            (path / ".kin" / "manifest.json").unlink()
            result = suite.shutdown()
            self.assertEqual(result.status, module.FAIL)
            suite.kin_run.assert_not_called()
            self.kill.assert_not_called()

    def test_failed_magic_builder_stays_registered_for_cleanup(self):
        module = MODULES[0]
        suite = self.suite(module, ())
        suite.workdir = str(self.root)
        suite.run_id = "synthetic"
        def partial(path):
            marker = Path(path) / ".kin"
            marker.mkdir()
            (marker / "manifest.json").write_text("{}")
            raise RuntimeError("partial init")
        suite._build_partial = partial
        with self.assertRaises(RuntimeError):
            suite.fixture("partial")
        self.assertIn("partial", suite.fixtures)
        self.assertEqual(suite.shutdown().status, module.PASS)
        suite.kin_run.assert_called_once()
        self.kill.assert_not_called()

    def test_failed_brownfield_init_stays_registered_for_cleanup(self):
        module = MODULES[1]
        suite = self.suite(module, ())
        suite.workdir = str(self.root)
        suite.run_id = "synthetic"
        name = next(iter(module.CORPORA))
        suite._cache_repo = mock.Mock(return_value=str(self.root / "cache"))
        suite.git = mock.Mock(return_value=(0, module.CORPORA[name]["tree"], ""))
        def partial(args, repo, **kwargs):
            if args[0] == "init":
                marker = Path(repo) / ".kin"
                marker.mkdir()
                (marker / "manifest.json").write_text("{}")
                return (1, "", "partial init")
            return (0, response(), "")
        suite.kin_run.side_effect = partial
        process = mock.Mock(returncode=0)
        process.communicate.return_value = (b"", b"")
        with mock.patch.object(module.subprocess, "Popen", return_value=process):
            with self.assertRaises(module.ProbeError):
                suite.fixture(name)
        self.assertIn(name, suite.fixtures)
        self.assertEqual(suite.shutdown().status, module.PASS)
        self.assertEqual(suite.kin_run.call_count, 2)
        self.kill.assert_not_called()

    def test_no_running_worker_and_no_fixtures_are_successful(self):
        for module in MODULES:
            suite = self.suite(module)
            suite.kin_run.return_value = (0, json.dumps({"schema": "kin.daemon-stop.v1",
                "scope": "current-repo", "stopped": [], "all_stopped": True}), "")
            self.assertEqual(suite.shutdown().status, module.PASS)
            suite.fixtures = {}
            suite.kin_run.reset_mock()
            self.assertEqual(suite.shutdown().status, module.PASS)
            suite.kin_run.assert_not_called()

    def test_main_grades_cleanup_in_json_and_keeps_failed_fixture(self):
        for module in MODULES:
            for failed in (False, True, "interrupt", "empty"):
                with self.subTest(suite=module.__name__, failed=failed):
                    suite = self.suite(module)
                    if failed is True:
                        suite.kin_run.return_value = (1, response(all_stopped=False), "refused")
                    workdir = self.root / (module.__name__ + str(failed))
                    workdir.mkdir()
                    output = self.root / "result.json"
                    probe = module.Result("probe", "TEST", "synthetic probe")
                    probe.ok("synthetic success")
                    args = ["--kin", sys.executable, "--daemon", sys.executable,
                            "--json", str(output)]
                    if module.__name__ == "brownfield_repro":
                        args += ["--corpus-cache", str(self.root / "cache")]
                    with mock.patch.object(module, "Suite", return_value=suite), \
                         mock.patch.object(module, "CHECKS", [] if failed == "empty" else [("probe", mock.Mock(side_effect=KeyboardInterrupt) if failed == "interrupt" else lambda _: probe)]), \
                         mock.patch.object(module, "run", return_value=(0, "kin synthetic", "")), \
                         mock.patch.object(module.tempfile, "mkdtemp", return_value=str(workdir)), \
                         contextlib.redirect_stdout(io.StringIO()):
                        if failed == "interrupt":
                            with self.assertRaises(KeyboardInterrupt):
                                module.main(args)
                            suite.kin_run.assert_called_once()
                            self.kill.assert_not_called()
                            continue
                        rc = module.main(args)
                    self.assertEqual(rc, 1 if failed else 0)
                    rows = GATE.load_report(str(output))
                    self.assertEqual(rows["cleanup"]["status"], module.FAIL if failed is True else module.PASS)
                    failures, _ = GATE.decide({"fixture": rows}, {})
                    self.assertEqual(bool(failures), bool(failed))
                    self.assertEqual(workdir.exists(), failed is True)
                    self.kill.assert_not_called()


if __name__ == "__main__":
    unittest.main()
