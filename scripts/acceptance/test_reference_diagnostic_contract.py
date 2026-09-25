#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
"""Acceptance requests must ask for the diagnostics their assertions read."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock


def load(name):
    spec = importlib.util.spec_from_file_location(
        name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


brownfield = load("brownfield_repro")
hydration = load("hydration_semantics_repro")
magic = load("magic_repro")
limits = load("verdict_limits_repro")
freshness = load("working_copy_freshness_repro")


class DiagnosticRequests(unittest.TestCase):
    def test_brownfield_cache_requests_full_without_changing_explicit_choice(self):
        suite = brownfield.Suite.__new__(brownfield.Suite)
        suite.payloads = {}
        suite.mcp = Mock(return_value={})
        original = {"query": "target"}
        suite.cached("repo", "find_references", original)
        self.assertIs(suite.mcp.call_args.args[2].get("answer_only"), False)
        self.assertEqual(original, {"query": "target"})
        suite.cached("repo", "find_references", {**original, "answer_only": True})
        self.assertIs(suite.mcp.call_args.args[2]["answer_only"], True)
        suite.cached("repo", "semantic_search", original)
        self.assertNotIn("answer_only", suite.mcp.call_args.args[2])

    def test_hydration_asks_for_the_classes_it_waits_for(self):
        suite = hydration.Suite.__new__(hydration.Suite)
        suite.kin_run = Mock()
        payload = {"references": [{"name": "caller"}],
                   "_kin": {"completeness": {"classes": {"calls": "present"}}}}
        suite.mcp = Mock(return_value=payload)
        self.assertIs(suite.find_references(attempts=1), payload)
        self.assertIs(suite.mcp.call_args.args[1].get("answer_only"), False)

    def test_magic_asks_for_arrival_and_negative_diagnostics(self):
        suite = magic.Suite.__new__(magic.Suite)
        suite.mcp = Mock(return_value=({"focal_entity": {"id": "target"}}, {}))
        suite.references("repo", "target", relation_kinds=["calls"])
        self.assertIs(suite.mcp.call_args.args[2].get("answer_only"), False)
        self.assertEqual(suite.mcp.call_args.args[2]["relation_kinds"], ["calls"])

    def test_limits_asks_for_full_even_with_a_response_budget(self):
        suite = limits.Suite.__new__(limits.Suite)
        suite.fixture = Mock(return_value="repo")
        suite.kin_run = Mock()
        suite.payloads = {}
        suite.mcp = Mock(return_value={"_kin": {
            "completeness": {"classes": {"calls": "present"}}}})
        suite.references(kinds=["calls"], attempts=1, extra={"max_chars": 2000})
        args = suite.mcp.call_args.args[2]
        self.assertIs(args.get("answer_only"), False)
        self.assertEqual(args["max_chars"], 2000)

    def test_freshness_asks_for_the_negative_block_it_grades(self):
        suite = Mock()
        suite.mcp.return_value = {2: {"negative": {
            "safe_to_conclude_absent": False,
            "trust_reason": "cross_file_edges_absent"}}}
        freshness.check_absence(suite)
        calls = suite.mcp.call_args.args[0]
        self.assertIs(calls[0][1].get("answer_only"), False)


def compact(state, safe=False, factor=None):
    return {"references": [{"name": "caller"}], "_kin": {
        "shape": "answer_only", "verdict": {
            "state": state, "safe_to_conclude_absent": safe,
            "limiting_factor": factor}}}


class VerdictReaders(unittest.TestCase):
    def test_compact_and_full_read_the_same_authoritative_verdict(self):
        for state, expected, factor in [
            ("certified", "certify", None),
            ("inconclusive", "refuse", "cross_file_edges_absent"),
        ]:
            with self.subTest(state=state):
                small = compact(state, factor=factor)
                full = copy.deepcopy(small)
                del full["_kin"]["shape"]
                full["negative"] = {"trust": "authoritative" if state == "certified"
                                    else "inconclusive", "safe_to_conclude_absent": False}
                for payload in (small, full):
                    surfaces = brownfield.verdict_surfaces(payload)
                    self.assertEqual(surfaces["_kin.verdict"][0], expected)
                    self.assertEqual(brownfield.surface_conflict(surfaces), (None, None))

    def test_contradictory_full_payload_is_still_a_failure(self):
        bad = compact("certified")
        bad["negative"] = {"trust": "inconclusive", "safe_to_conclude_absent": False}
        yes, no = brownfield.surface_conflict(brownfield.verdict_surfaces(bad))
        self.assertIn("_kin.verdict", yes)
        self.assertIn("negative", no)

    def test_malformed_verdict_is_unreadable_never_certified(self):
        for verdict in ({}, {"state": "new_state"}, {"state": "certified"}):
            with self.subTest(verdict=verdict):
                with self.assertRaises(brownfield.UnknownClassState):
                    brownfield.verdict_surfaces({"_kin": {"verdict": verdict}})

    def test_compact_internal_contradictions_still_fail(self):
        for payload in (compact("certified", factor="cross_file_edges_absent"),
                        compact("certified", factor=""),
                        compact("inconclusive", safe=True, factor="cross_file_edges_absent")):
            with self.subTest(payload=payload):
                yes, no = brownfield.surface_conflict(brownfield.verdict_surfaces(payload))
                self.assertTrue(yes and no)

    def test_compact_cannot_stand_in_for_unreported_diagnostics(self):
        payload = compact("certified")
        self.assertTrue(hydration.verdict_problems(payload, False))
        self.assertIsNone(limits.verdict_honours_classes(payload)[0])
        self.assertIsNone(limits.factor_carries_every_refusing_input(payload)[0])
        self.assertNotEqual(freshness.grade_absence_names_the_gap_it_is_withheld_for(payload)[0],
                            freshness.PASS)

    def test_missing_payload_has_no_readable_verdict(self):
        self.assertEqual(brownfield.verdict_surfaces({}), {})


class AdmittedDurability(unittest.TestCase):
    def evidence(self):
        status = {"_kin": {"runtime": "repo-daemon", "answered_by": {"repo_id": "repo"},
                  "freshness": {"state": "recorded", "at": "observed", "age_seconds": 0},
                  "durability": {"state": "live_uncommitted", "live_entities": 10,
                                 "durable_entities": 6, "live_only_entities": 4}}}
        body = freshness.ADMITTED_FUNCTION_BODY.encode("utf-8")
        start = freshness.LINKGRAPH_SRC.encode("utf-8").index(body)
        end = start + len(body)
        digest = hashlib.sha256(freshness.LINKGRAPH_SRC.encode("utf-8")).hexdigest()
        source = {"_kin": copy.deepcopy(status["_kin"]), "id": "function", "kind": "Function",
                  "name": freshness.ADMITTED_FUNCTION_NAME,
                  "file_path": "linkgraph/predicates.py", "body": freshness.ADMITTED_FUNCTION_BODY,
                  "start_byte": start, "end_byte": end, "span_coherence": "digest_verified",
                  "source_base": {"schema": "kin.entity.source_base.v1", "entity_id": "function",
                                  "artifact_id": "artifact", "start_byte": start, "end_byte": end,
                                  "body_hash": hashlib.sha256(body).hexdigest(), "source_blob_hash": digest,
                                  "context": {"repository_id": "repo", "workspace_tree_hash": "tree"}}}
        return status, source

    def grade(self, status, source):
        return freshness.grade_durability_after_admission(status, source, "linkgraph/predicates.py")[0]

    def test_exact_admitted_graph_body_explains_missing_behind(self):
        status, source = self.evidence()
        self.assertEqual(freshness.grade_durability_withholds_the_all_clear(status)[0], freshness.FAIL)
        self.assertEqual(self.grade(status, source), freshness.PASS)

    def test_missing_source_or_unbound_source_never_passes(self):
        for key, value in [("body", "stale body"), ("file_path", "other.py"),
                           ("kind", "Module"), ("name", "another_function"),
                           ("span_coherence", "unverified"), ("source_base", {}),
                           ("end_byte", 1)]:
            with self.subTest(key=key):
                status, source = self.evidence()
                source[key] = value
                self.assertNotEqual(self.grade(status, source), freshness.PASS)
        status, _ = self.evidence()
        self.assertNotEqual(self.grade(status, None), freshness.PASS)

    def test_bad_counts_or_cross_repository_evidence_still_fail(self):
        for change in (lambda p: p["_kin"]["durability"].update(state="recorded"),
                       lambda p: p["_kin"]["durability"].update(live_only_entities=0),
                       lambda p: p["_kin"]["durability"].update(live_only_entities=3),
                       lambda p: p["_kin"].update(behind={}),
                       lambda p: p["_kin"]["answered_by"].update(repo_id="other"),
                       lambda p: p["_kin"].update(freshness={})):
            with self.subTest(change=change):
                status, source = self.evidence()
                change(status)
                self.assertEqual(self.grade(status, source), freshness.FAIL)

    def test_matching_but_wrong_digests_do_not_prove_fixture_admission(self):
        status, source = self.evidence()
        source["source_base"].update(body_hash="a" * 64, source_blob_hash="a" * 64)
        self.assertEqual(self.grade(status, source), freshness.FAIL)

    def test_artifact_and_entity_digest_checks_are_independent(self):
        for field in ("body_hash", "source_blob_hash"):
            with self.subTest(field=field):
                status, source = self.evidence()
                source["source_base"][field] = "a" * 64
                self.assertEqual(self.grade(status, source), freshness.FAIL)

    def test_whole_file_module_cannot_substitute_for_targeted_function(self):
        status, source = self.evidence()
        size = len(freshness.LINKGRAPH_SRC.encode("utf-8"))
        digest = hashlib.sha256(freshness.LINKGRAPH_SRC.encode("utf-8")).hexdigest()
        source.update(kind="Module", body=freshness.LINKGRAPH_SRC, start_byte=0, end_byte=size)
        source["source_base"].update(start_byte=0, end_byte=size, body_hash=digest)
        self.assertEqual(self.grade(status, source), freshness.FAIL)

    def test_original_false_all_clear_does_not_retry_until_it_passes(self):
        suite = Mock()
        suite.ground_truth.return_value = 2
        suite.mcp.return_value = {2: freshness.SHIPPED_0_6_1}
        self.assertEqual(freshness.check_durability(suite).status, freshness.FAIL)
        self.assertEqual(suite.mcp.call_count, 1)

    def test_actual_route_verifies_both_initial_and_final_status(self):
        status, source = self.evidence()
        suite = Mock()
        suite.unadmitted_path = "linkgraph/predicates.py"
        suite.ground_truth.return_value = 2
        for final, expected in [(status, freshness.PASS),
                                (freshness.SHIPPED_0_6_1, freshness.FAIL)]:
            suite.mcp.side_effect = [{2: status},
                                    {2: {"results": [{"id": "module", "kind": "module"},
                                                     {"id": "function", "kind": "function",
                                                      "name": freshness.ADMITTED_FUNCTION_NAME}]}},
                                    {2: source, 3: final}]
            self.assertEqual(freshness.check_durability(suite).status, expected)
            self.assertEqual(suite.mcp.call_args.args[0][0],
                             ("get_entity_source", {"entity_id": "function"}))


if __name__ == "__main__":
    unittest.main()
