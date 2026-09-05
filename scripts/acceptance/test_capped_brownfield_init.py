#!/usr/bin/env python3
"""Regression tests for capped_brownfield_init's final-verdict logic.

capped_init_no_oom_kill grades three things that must ALL hold before it
passes: no OOM kill, a clean init exit, and a cgroup memory.max that matches
what --cap asked for at both the start and the end of the run. Docker and the
twelve-minute conversion are never touched here; MODULE.run and MODULE.docker
are replaced with fakes that answer the exact sequence main() issues, so what
is graded is the verdict arithmetic itself.

Three cases are red against the pre-fix logic, which read oom_kill alone:

    failed init, zero OOM      -- init_rc was recorded but never graded
    cap differs from request   -- the cgroup cap was never compared to --cap
    cap unreadable at the end  -- read_cgroup drops memory.max silently when
                                   the file holds cgroup v2's literal "max"
                                   (unlimited) instead of a byte count, which
                                   is a real value a container can report

Each is falsified in the PR body by reverting just the branch it guards and
showing that one test go red again.
"""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


def load():
    spec = importlib.util.spec_from_file_location(
        "capped_brownfield_init", Path(__file__).with_name("capped_brownfield_init.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MODULE = load()


def cgroup_text(memory_max="17179869184", memory_peak="1048576", oom_kill=0):
    """Render what `cat memory.max memory.peak; cat memory.events` prints.

    memory_max is a string because the real file can hold either a byte count
    or cgroup v2's literal "max" for "no limit currently applied".
    """
    return ("%s\n%s\n"
            "low 0\nhigh 0\nmax 0\noom 0\noom_kill %d\noom_group_kill 0\n"
            % (memory_max, memory_peak, oom_kill))


class FakeCompleted:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class CappedBrownfieldInitTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(MODULE, "run", side_effect=self._fake_run).start()
        mock.patch.object(MODULE, "docker", side_effect=self._fake_docker).start()
        mock.patch("os.path.isfile", return_value=True).start()
        # Popped in call order: read_cgroup runs once before install and once
        # after init, so index 0 is the start read and index 1 is the end read.
        self.cgroup_reads = [cgroup_text(), cgroup_text()]
        self.init_rc = 0
        self.init_stdout = "kin init: converted 1200 objects\n"

    def _fake_run(self, argv, **kw):
        if argv[:2] == ["docker", "info"]:
            return FakeCompleted(0)
        if argv[:2] == ["docker", "run"]:
            return FakeCompleted(0, stdout="fake-container-id\n")
        raise AssertionError("unexpected run() call: %r" % (argv,))

    def _fake_docker(self, name, script):
        if "memory.max" in script and "memory.peak" in script:
            return FakeCompleted(0, stdout=self.cgroup_reads.pop(0))
        if "tar xzf" in script:
            return FakeCompleted(0, stdout="kin\nkin-daemon\n")
        if script == "test -x /work/bin/kin-daemon":
            return FakeCompleted(0)
        if script == "/work/bin/kin --version":
            return FakeCompleted(0, stdout="kin 0.7.2-test\n")
        if "git clone -q" in script:
            return FakeCompleted(0, stdout="%s\n" % MODULE.REVISION)
        if "kin init" in script:
            return FakeCompleted(self.init_rc, stdout=self.init_stdout)
        raise AssertionError("unexpected docker() call: %r" % (script,))

    def run_main(self, cap="16g", json_path=None):
        args = ["--run", "--archive", "/fake/kin-linux-aarch64.tar.gz", "--cap", cap]
        if json_path:
            args += ["--json", json_path]
        # EMITTED is a module-level accumulator that a real invocation never
        # reuses (one process, one main() call). This test process calls
        # main() once per test method, so it must be cleared here or later
        # calls inherit earlier tests' CHECK lines and trip the "expected 2"
        # tally for a reason that has nothing to do with the code under test.
        MODULE.EMITTED.clear()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = MODULE.main(args)
        return rc, out.getvalue()

    # --- the three red-first regressions -----------------------------------

    def test_failed_init_with_zero_oom_fails(self):
        """A failed init with oom_kill 0 must not read as a pass.

        Pre-fix: init_rc is stored in result["init_rc"] but no branch reads
        it, so oom_kill == 0 alone reaches the PASS branch on both checks.
        """
        self.init_rc = 1
        self.init_stdout = "kin init: fatal: could not reach registry\n"
        rc, out = self.run_main()
        self.assertEqual(rc, 1, out)
        self.assertIn("CHECK capped_init_no_oom_kill FIR-2988 FAIL", out)
        self.assertIn("init exited 1", out)

    def test_cap_differing_from_request_fails(self):
        """A cgroup cap that does not match --cap must not read as a pass.

        Pre-fix: the cgroup's memory.max is captured at start and end
        (result["memory.max_at_start"], result["memory.max"]) but neither is
        ever compared against the requested --cap, so a container that ran
        under the wrong limit passes exactly like one that ran under the
        right one.
        """
        requested = MODULE.parse_mem_bytes("12g")
        actual = MODULE.parse_mem_bytes("16g")
        self.assertNotEqual(requested, actual)
        self.cgroup_reads = [cgroup_text(memory_max=str(actual)),
                             cgroup_text(memory_max=str(actual))]
        with tempfile.TemporaryDirectory(prefix="capped-init-test-") as tmp:
            json_path = str(Path(tmp) / "result.json")
            rc, out = self.run_main(cap="12g", json_path=json_path)
            self.assertEqual(rc, 1, out)
            self.assertIn("CHECK capped_init_no_oom_kill FIR-2988 FAIL", out)
            self.assertIn("does not match the requested cap 12g", out)
            result = json.loads(Path(json_path).read_text())
        self.assertEqual(result["cap_requested_bytes"], requested)
        self.assertFalse(result["cap_matches_request"])

    def test_unreadable_cap_fails(self):
        """A cap that cannot be confirmed must not read as a pass.

        The end-of-run memory.max reads the literal "max" (cgroup v2's
        spelling for "no limit"), a real value a container can report.
        read_cgroup's own number parsing drops it silently (it is not
        `.isdigit()`), so memory.max is simply absent from the end read while
        memory.peak and oom_kill still parse fine. Pre-fix, nothing reads
        memory.max at the end at all, so this is invisible.
        """
        self.cgroup_reads = [cgroup_text(),
                             cgroup_text(memory_max="max", memory_peak="999999")]
        with tempfile.TemporaryDirectory(prefix="capped-init-test-") as tmp:
            json_path = str(Path(tmp) / "result.json")
            rc, out = self.run_main(json_path=json_path)
            self.assertEqual(rc, 1, out)
            self.assertIn("CHECK capped_init_no_oom_kill FIR-2988 FAIL", out)
            self.assertIn("does not match the requested cap", out)
            result = json.loads(Path(json_path).read_text())
        self.assertNotIn("memory.max", result)  # read_cgroup never set it
        self.assertFalse(result["cap_matches_request"])

    # --- control: the same run, nothing wrong, must still pass --------------

    def test_clean_run_still_passes(self):
        rc, out = self.run_main()
        self.assertEqual(rc, 0, out)
        self.assertIn("CHECK capped_init_no_oom_kill FIR-2988 PASS", out)
        self.assertIn("CHECK capped_init_no_kill_line FIR-2988 PASS", out)

    # --- the OOM-kill positive control this suite already had --------------

    def test_real_oom_kill_still_fails_first(self):
        """oom_kill > 0 must still FAIL and must still name the kill count,
        even with a matching cap and a zero init_rc, unchanged from before
        this fix."""
        self.cgroup_reads = [cgroup_text(), cgroup_text(oom_kill=1)]
        rc, out = self.run_main()
        self.assertEqual(rc, 1, out)
        self.assertIn("CHECK capped_init_no_oom_kill FIR-2988 FAIL", out)
        self.assertIn("oom_kill 1", out)


class ParseMemBytesTests(unittest.TestCase):
    def test_known_units(self):
        self.assertEqual(MODULE.parse_mem_bytes("16g"), 16 * (1 << 30))
        self.assertEqual(MODULE.parse_mem_bytes("12g"), 12 * (1 << 30))
        self.assertEqual(MODULE.parse_mem_bytes("500m"), 500 * (1 << 20))
        self.assertEqual(MODULE.parse_mem_bytes("2048k"), 2048 * (1 << 10))
        self.assertEqual(MODULE.parse_mem_bytes("1024b"), 1024)
        self.assertEqual(MODULE.parse_mem_bytes("2048"), 2048)

    def test_unparseable_is_none(self):
        for spec in ("max", "16gb", "16 g", "", None, "-16g"):
            self.assertIsNone(MODULE.parse_mem_bytes(spec), spec)


if __name__ == "__main__":
    unittest.main()
