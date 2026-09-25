#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
"""Grade magic-repro's conversion reading and its run-root retention, no repo, no daemon.

Checks 15, 17 and 21 read one file's conversion coverage and its entity counts
by kind through that diagnostic. Check 15's empty-file arm passes when the file
declares no function, class or method, so a report that carried no counts must
never read as one that counted none: that would pass the arm without observing
anything. These cases hold the reading to the counts the report actually states.

A losing run must also keep what it produced: the run root and the responses its
checks read. The last cases hold the rule that decides when a root may go.
"""

import importlib.util
from pathlib import Path
import unittest


def _load(name):
    spec = importlib.util.spec_from_file_location(
        name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


m = _load("magic_repro")


class ConversionCounts(unittest.TestCase):
    """The observed total and counts, or a reason the report cannot be read."""

    def test_counts_that_add_up_are_read_as_observed(self):
        total, counts, why = m.conversion_counts(
            {"total": 3, "counts_by_kind": {"function": 2, "class": 1}})
        self.assertIsNone(why)
        self.assertEqual((total, counts), (3, {"function": 2, "class": 1}))

    def test_an_empty_file_is_an_observation_of_zero(self):
        total, counts, why = m.conversion_counts({"total": 0, "counts_by_kind": {}})
        self.assertIsNone(why)
        self.assertEqual((total, counts), (0, {}))

    def test_missing_or_malformed_counts_are_unreadable(self):
        for report in (
            {"total": 0},
            {"total": 0, "counts_by_kind": None},
            {"total": 0, "counts_by_kind": []},
            {"counts_by_kind": {}},
            {"total": None, "counts_by_kind": {}},
            {"total": True, "counts_by_kind": {"function": True}},
            {"total": -1, "counts_by_kind": {}},
            {"total": 2.0, "counts_by_kind": {"function": 2}},
            {"total": 1, "counts_by_kind": {"function": "1"}},
            {"total": 1, "counts_by_kind": {"function": -1, "class": 2}},
            {"total": 3, "counts_by_kind": {"function": 2}},
        ):
            total, counts, why = m.conversion_counts(report)
            self.assertIsNotNone(why, report)
            self.assertIsNone(total, report)
            self.assertIsNone(counts, report)


class ConversionCoverage(unittest.TestCase):
    """The whole reading, with the command stubbed at the suite boundary."""

    class Suite(object):
        def __init__(self, rc, out):
            self.rc, self.out = rc, out

        def kin_run(self, args, repo):
            return self.rc, self.out, ""

    def read(self, report, rc=0):
        import json
        return m.conversion_coverage(self.Suite(rc, json.dumps(report)), "/repo", "empty.py")

    def test_a_well_formed_report_folds_in_the_observed_counts(self):
        cov, why = self.read({"path": "empty.py", "file_coverage": {"parsed": "full"},
                              "counts_by_kind": {}, "total": 0})
        self.assertIsNone(why)
        self.assertEqual((cov["parsed"], cov["total"], cov["counts_by_kind"]),
                         ("full", 0, {}))

    def test_a_report_without_counts_is_not_an_empty_file(self):
        cov, why = self.read({"path": "empty.py", "file_coverage": {"parsed": "full"},
                              "total": 0})
        self.assertIsNone(cov)
        self.assertIn("counts_by_kind", why)

    def test_a_refused_path_is_unreadable(self):
        cov, why = self.read({}, rc=1)
        self.assertIsNone(cov)
        self.assertIn("exited 1", why)

    def test_the_report_is_recorded_for_a_failing_run_to_keep(self):
        import json
        suite = self.Suite(0, json.dumps({"file_coverage": {}, "total": 1}))
        suite.responses = []
        m.conversion_coverage(suite, "/repo", "src/a.py")
        self.assertEqual(len(suite.responses), 1)
        recorded = suite.responses[0]
        self.assertEqual(recorded["command"], ["doctor", "--conversion-source", "src/a.py", "--json"])
        self.assertEqual(recorded["exit"], 0)
        self.assertIn('"total": 1', recorded["stdout"])


class RunRootRetention(unittest.TestCase):
    """A run root goes only when nothing was lost; every losing run keeps it."""

    def test_only_a_clean_unasked_run_removes_its_root(self):
        self.assertTrue(m.run_root_removable([], [], m.PASS, False, None))

    def test_a_losing_or_kept_run_keeps_its_root(self):
        for failed, unread, cleanup, keep, workdir in (
            (["check"], [], m.PASS, False, None),
            ([], ["check"], m.PASS, False, None),
            (["check"], ["other"], m.PASS, False, None),
            ([], [], m.FAIL, False, None),
            ([], [], m.PASS, True, None),
            ([], [], m.PASS, False, "/explicit/root"),
        ):
            self.assertFalse(m.run_root_removable(failed, unread, cleanup, keep, workdir),
                             (failed, unread, cleanup, keep, workdir))


if __name__ == "__main__":
    unittest.main()
