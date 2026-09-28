#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
"""Grade how magic-repro case 16 reads its two surfaces, no repo, no daemon.

Why this file exists
--------------------
On 2026-09-09 the release train stopped for an evening. Release Cut failed
three times running on `Preflight kin-macos-aarch64` with

    16/FIR-2524 FAIL: healthy isolated empty control did not certify plainly
    on both surfaces

and both Linux legs passed every time. The message reads as a disagreement
between the CLI and MCP. There was none. Both surfaces refused the absence,
together, for one reason: the hosted macOS runner had no Python language
server, so Kin could never have produced a cross-file Calls edge for the
fixture and correctly declined to certify that the symbol was unused. Kin was
right and the cut failed on a right answer.

Two defects, and this file grades the second.

The first was environmental: `scripts/ci-install-language-servers.sh` bounded
its npm install with GNU `timeout`, macOS has none, and all three attempts died
on `timeout: command not found` sixty-five seconds before the next step in the
same job installed coreutils.

The second is the one a check can hold: the arm blamed the product for its
host, and named a disagreement rather than the condition that tripped. Nobody
could tell which surface was wrong, because the arm's own receipt never left
the runner. Reading the code was the only way to learn there was no
disagreement to find.

Where it runs, and why here
---------------------------
`scripts/acceptance/magic_repro.py` is graded by acceptance.yml, whose
`Product Acceptance` job carries `if: github.event_name != 'pull_request'`, so
it never runs on the pull request that could break it. kin#1642 added the arm
this file grades and the daemon route it exercises in one commit, and no
acceptance suite ran before that commit merged. This file is wired into
`ci.yml`'s fast-gate-lint job, which does run on a pull request and carries the
required `Fast gate lint and policy` context, so the class is refused at the
pull request rather than a release later.
"""
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


def _load(name):
    spec = importlib.util.spec_from_file_location(
        name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


m = _load("magic_repro")

# Verbatim from a real receipt, read out of repro.json on 2026-09-09 running
# the v0.7.8 candidate archive (08490e9f3) against an isolated store on a macOS
# host with no Python language server. Paraphrasing these would let the fixture
# drift away from what the product actually prints, which is the whole failure
# mode this file guards. The one exception is the header line, which is in the
# form `kin refs` prints now that it names an entity by id and its file only as
# the projection it is (the id is this fixture's, since a real one is minted
# per store): the receipt's header carried `@ callee.py` in their place.
ABSENCE_LINE = "No incoming Calls relations."
CLEAN_STDOUT = (
    "References to 'unused_absence_probe' -> unused_absence_probe (Function) "
    "[5f0c1d9e-3a47-4b1e-9d62-7c8e2f4a6b10] (projection: callee.py)\n"
    + ABSENCE_LINE + "\n")
HEDGED_STDOUT = CLEAN_STDOUT + (
    "Kin cannot rule out references it did not see: this answer carries "
    "[edge_coverage:reference_enrichment_unsupported], so it may not reflect current truth.\n")
HOST_GAP = (
    "reference_enrichment_unsupported: no language server for Python is installed on this "
    "host, so no cross-file reference or override edge was ever produced for it, so an empty "
    "result cannot separate a symbol nothing uses from one this graph could never have "
    "linked; reference_enrichment_no_language_server: an adapter is wired for Python but no "
    "language server for it is installed on this host")
# The neighbouring state in crates/kin-mcp/src/verdict.rs, and the one that is
# NOT a host fact: a build that ships no adapter for a language Kin claims to
# enrich is a regression, and must never be excused as somebody's laptop.
BUILD_GAP = (
    "reference_enrichment_unsupported: this build wires no language-server adapter for "
    "Python, so cross-file reference and override edges cannot exist for it at all")


def payload(certified, limiting=""):
    return {
        "focal_entity": {"id": "e1"},
        "references": [],
        "negative": {"safe_to_conclude_absent": certified,
                     "kind": "no_references",
                     "trust_reason": limiting},
        "_kin": {"verdict": {"safe_to_conclude_absent": certified,
                             "limiting_factor": limiting}},
    }


def cli(stdout, exit_code=0, stderr=""):
    return {"args": ["refs", "unused_absence_probe", "--kind", "calls"],
            "exit_code": exit_code, "stdout": stdout, "stderr": stderr}


class HealthyControlArm(unittest.TestCase):
    """The arm's four original conditions, unchanged, plus what a non-pass says."""

    def test_both_surfaces_certifying_passes(self):
        status, detail = m.certification_arm_reading(payload(True), cli(CLEAN_STDOUT))
        self.assertEqual(status, m.PASS, detail)
        self.assertIn("certifies plainly on both surfaces", detail)

    def test_a_host_with_no_language_server_is_not_graded(self):
        # The macOS leg, exactly. UNREADABLE rather than FAIL, and the detail
        # quotes the verdict's own sentence rather than composing one.
        status, detail = m.certification_arm_reading(
            payload(False, HOST_GAP), cli(HEDGED_STDOUT))
        self.assertEqual(status, m.UNREADABLE, detail)
        self.assertIn("no language server for it is installed on this host", detail)
        self.assertIn("scripts/ci-install-language-servers.sh", detail)
        self.assertNotIn("did not certify plainly", detail)

    def test_mcp_refusing_while_the_cli_certifies_still_fails(self):
        # Half of the excuse is the surface disagreement FIR-2524 exists to
        # catch. The host gap is present in the verdict and must not buy it.
        status, detail = m.certification_arm_reading(
            payload(False, HOST_GAP), cli(CLEAN_STDOUT))
        self.assertEqual(status, m.FAIL, detail)
        self.assertIn("safe_to_conclude_absent is false, not true", detail)

    def test_the_cli_qualifying_while_mcp_certifies_still_fails(self):
        status, detail = m.certification_arm_reading(
            payload(True, HOST_GAP), cli(HEDGED_STDOUT))
        self.assertEqual(status, m.FAIL, detail)
        self.assertIn("the CLI qualified the answer", detail)

    def test_a_build_that_wires_no_adapter_is_not_excused(self):
        # Same shape as the macOS leg, one token different, and that token is
        # the difference between a runner nobody provisioned and a build that
        # lost an adapter it ships.
        status, detail = m.certification_arm_reading(
            payload(False, BUILD_GAP), cli(HEDGED_STDOUT))
        self.assertEqual(status, m.FAIL, detail)

    def test_a_nonzero_exit_is_never_the_hosts_fault(self):
        status, detail = m.certification_arm_reading(
            payload(False, HOST_GAP), cli(HEDGED_STDOUT, exit_code=2))
        self.assertEqual(status, m.FAIL, detail)
        self.assertIn("the CLI exited 2", detail)

    def test_a_missing_absence_line_is_never_the_hosts_fault(self):
        status, detail = m.certification_arm_reading(
            payload(False, HOST_GAP), cli(HEDGED_STDOUT.replace(ABSENCE_LINE, "")))
        self.assertEqual(status, m.FAIL, detail)
        self.assertIn(ABSENCE_LINE, detail)

    def test_a_failure_names_every_condition_that_tripped(self):
        # The misdiagnosis class itself. A reader of the release log must learn
        # what went wrong from the line, not from reading the check.
        status, detail = m.certification_arm_reading(
            payload(None), cli("", exit_code=1))
        self.assertEqual(status, m.FAIL, detail)
        for expected in ("safe_to_conclude_absent is null",
                         "the CLI exited 1",
                         ABSENCE_LINE):
            self.assertIn(expected, detail)


class GapPredicate(unittest.TestCase):
    """Both surfaces, or it is not a host gap."""

    def test_both_surfaces_naming_the_gap_reads_it(self):
        self.assertTrue(m.host_lacks_reference_enrichment(
            payload(False, HOST_GAP), HEDGED_STDOUT))

    def test_a_codes_only_factor_still_reads_the_gap(self):
        # Envelope v2: the verdict's factor is codes alone, while trust_reason
        # keeps its sentence until negative.rs moves. The reader keys on the
        # label, so the code has to be enough on its own.
        v2 = payload(False, HOST_GAP)
        v2["_kin"]["verdict"]["limiting_factor"] = (
            "reference_enrichment_unsupported; reference_enrichment_no_language_server")
        v2["negative"]["trust_reason"] = ""
        self.assertIsNotNone(m.host_lacks_reference_enrichment(v2, HEDGED_STDOUT))

    def test_a_quiet_cli_is_not_agreement(self):
        self.assertIsNone(m.host_lacks_reference_enrichment(
            payload(False, HOST_GAP), CLEAN_STDOUT))

    def test_a_quiet_verdict_is_not_agreement(self):
        self.assertIsNone(m.host_lacks_reference_enrichment(
            payload(False, ""), HEDGED_STDOUT))

    def test_a_cli_hedging_about_something_else_is_not_this_class(self):
        other = CLEAN_STDOUT + (
            "Kin cannot rule out references it did not see: this answer carries "
            "[edge_coverage:cross_file_edges_unproduced], so it may not reflect current truth.\n")
        self.assertIsNone(m.host_lacks_reference_enrichment(
            payload(False, HOST_GAP), other))


class IsolatedFixtureReadiness(unittest.TestCase):
    def graph(self, **changes):
        sites = {"settled": True, "callers": 5, "census": 1,
                 "callers_owed": 0, "callers_stale": 0,
                 "callers_unverified": 0, "callers_unproven_no_resolver": 0}
        sites.update(changes)
        return {"call_sites": sites}

    def work(self, **changes):
        work = {"pending_work": 0, "failed_work": 0, "merge_pending": False,
                "worker_available": True, "running": False, "files_blocked": 0,
                "languages_skipped": [], "files_owed": 0, "evidence_unrecorded_files": []}
        work.update(changes)
        return work

    def test_independent_readiness_does_not_require_a_certifying_verdict(self):
        graph = self.graph()
        graph.update(payload(False, "a verdict regression must still fail the next assertion"))
        self.assertTrue(m.absence_control_ready(graph, self.work()))
        status, _ = m.certification_arm_reading(graph, cli(HEDGED_STDOUT))
        self.assertEqual(status, m.FAIL)

    def test_drained_worker_does_not_hide_owed_or_unverified_graph_callers(self):
        for changes in ({"settled": False, "callers_owed": 2},
                        {"callers_stale": 1}, {"callers_unverified": 1},
                        {"callers_unproven_no_resolver": 1}, {"census": 0}, {"callers": 0}):
            with self.subTest(changes=changes):
                self.assertFalse(m.absence_control_ready(self.graph(**changes), self.work()))

    def test_settled_graph_does_not_hide_pending_or_unrecorded_work(self):
        for changes in ({"pending_work": 1}, {"running": True}, {"merge_pending": True},
                        {"files_owed": 1}, {"evidence_unrecorded_files": ["caller.py"]}):
            with self.subTest(changes=changes):
                self.assertFalse(m.absence_control_ready(self.graph(), self.work(**changes)))

    def test_failed_or_unavailable_enrichment_never_becomes_ready(self):
        for changes in ({"failed_work": 1}, {"worker_available": False},
                        {"files_blocked": 1}, {"languages_skipped": ["python"]}):
            with self.subTest(changes=changes), self.assertRaises(RuntimeError):
                m.absence_control_ready(self.graph(), self.work(**changes))

    def test_missing_or_malformed_readings_fail_closed(self):
        for graph in ({}, self.graph(settled="true"), self.graph(callers_owed=None),
                      self.graph(census=-1)):
            with self.subTest(graph=graph), self.assertRaises(RuntimeError):
                m.absence_control_ready(graph, self.work())
        with self.assertRaises(RuntimeError):
            m.absence_control_ready(self.graph(), self.work(files_owed=None))

    def test_wait_reads_only_independent_status_and_keeps_one_deadline(self):
        with tempfile.TemporaryDirectory() as repo:
            kin = Path(repo) / ".kin"
            kin.mkdir()
            (kin / "daemon.port").write_text("4219\n")
            (kin / "daemon.token").write_text("fixture-token")
            suite = m.Suite("unused", repo)
            suite.kin_run = mock.Mock(return_value=(0, json.dumps(self.graph(settled=False)), ""))
            suite.mcp = mock.Mock(side_effect=AssertionError("readiness must not query a verdict"))
            elapsed = [0.0]
            def sleep(seconds):
                elapsed[0] += seconds
            with mock.patch.object(m.time, "monotonic", side_effect=lambda: elapsed[0]), \
                    mock.patch.object(m.time, "sleep", side_effect=sleep), \
                    mock.patch.object(m.urllib.request, "urlopen",
                                      side_effect=lambda *a, **k: io.StringIO(json.dumps(self.work()))):
                with self.assertRaisesRegex(RuntimeError, "did not settle in 0.5s"):
                    suite.await_absence_control_ready(repo, timeout=0.5)
            self.assertEqual(elapsed[0], 0.5)
            self.assertEqual(suite.kin_run.call_count, 2)
            for call in suite.kin_run.call_args_list:
                self.assertEqual(call.args[0], ["graph", "status", "--json"])
                self.assertLessEqual(call.kwargs["timeout"], 0.5)
            suite.mcp.assert_not_called()


class TokensStillExistInTheProduct(unittest.TestCase):
    """The check keys on two product strings, so a rename must be loud.

    Without this, renaming either token in `kin-mcp` would leave the predicate
    matching nothing: the UNREADABLE branch would quietly go dead and the macOS
    leg would be back to blaming the product for its runner, with nothing red
    to say so.
    """

    def _verdict_source(self):
        source = (Path(__file__).resolve().parents[2]
                  / "crates" / "kin-mcp" / "src" / "verdict.rs")
        self.assertTrue(source.is_file(), "kin-mcp verdict.rs moved: %s" % source)
        return source.read_text(encoding="utf-8")

    def test_the_two_enrichment_tokens_are_still_published(self):
        text = self._verdict_source()
        for token in (m.NO_LANGUAGE_SERVER, m.ENRICHMENT_CLASS):
            self.assertIn(token, text,
                          "%s no longer appears in kin-mcp's verdict, so case 16's host-gap "
                          "reading matches nothing and must be rewired" % token)

    def test_the_positive_control_would_notice_a_dead_read(self):
        # Proves the search above can fail: a token the file cannot contain
        # must not be found by the same read.
        self.assertNotIn("reference_enrichment_this_token_cannot_exist",
                         self._verdict_source())


class QualifierRegex(unittest.TestCase):
    """The hedge the CLI actually prints, matched by the pattern in use."""

    def test_the_product_sentence_matches(self):
        self.assertTrue(m.CANNOT_RULE_OUT.search(HEDGED_STDOUT))

    def test_a_clean_answer_does_not(self):
        self.assertFalse(m.CANNOT_RULE_OUT.search(CLEAN_STDOUT))


if __name__ == "__main__":
    unittest.main()
