#!/usr/bin/env python3
"""Grade bounded trace witnesses and the gate that reads them, no repo, no process."""
import contextlib
import importlib.util
import io
from pathlib import Path
import unittest


def _load(name):
    spec = importlib.util.spec_from_file_location(
        name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


m = _load("brownfield_repro")
gate = _load("gate")


class Fixture:
    def __init__(self):
        self.trace = {"truncated": True, "chain": [
            {"entity_id": "enabled", "entity_name": "app.enabled", "depth": 1},
            {"entity_id": "final", "entity_name": "finalhandler", "depth": 1},
            {"entity_id": "router", "entity_name": "router.handle", "depth": 1},
            {"entity_id": "application", "entity_name": "application", "depth": 1}],
            "clipped_steps": [{"step": 4, "entity_id": "application",
                               "limit_per_step": 25, "dropped_callees": 2,
                               "dropped_callers": 0}]}
        self.hood = {"focal_id": "application", "depth": 1, "direction": "out",
                     "truncated": False, "entities": [{"id": "application", "name": "application"}],
                     "relations": []}
        for i in range(27):
            self.hood["entities"].append({"id": str(i), "name": "safe" + str(i)})
            self.hood["relations"].append({"src": {"Entity": "application"},
                "dst": {"Entity": str(i)}, "from": "application", "direction": "outgoing",
                "kind": "Calls", "resolution": "type_resolved"})
        self.hood.update(entity_count=28, relation_count=27)
        self.focused = {"focal_id": "application", "depth": 1, "direction": "calls", "chain": [{"entity_id": "26", "entity_name": "req.get",
                                   "resolution": "type_resolved", "depth": 1}]}
        self.calls = []

    def fixture(self, name):
        assert name == "express"
        return "fixture"

    def sweep_gate(self, name):
        assert name == "express"

    def cached(self, repo, tool, args):
        self.calls.append((tool, args))
        if tool == "graph_neighborhood":
            assert args == {"entity_id": "application", "depth": 1, "direction": "out", "limit": 50, "max_chars": 60000}
            return self.hood
        if "target" in args:
            assert args == {"focal": "application", "target": "26", "direction": "calls",
                            "depth": 1, "include_body": False, "limit_per_step": 25, "max_chars": 200000}
            return self.focused
        assert args == {"focal": m.APP_HANDLE, "direction": "calls", "depth": 2,
                        "include_body": False, "limit_per_step": 25, "max_chars": 200000}
        return self.trace


class WitnessTests(unittest.TestCase):
    def setUp(self):
        self.s = Fixture()

    def grade(self, expected):
        result = m.check_4(self.s)
        self.assertEqual(result.status, expected, result.asserts)
        return result

    def test_complete_27_destination_witness(self):
        result = self.grade(m.PASS)
        self.assertIn("27 trace-eligible", str(result.asserts))
        self.assertEqual(len(self.s.calls), 2)

    def test_returned_forbidden_survives_unreadable_clip(self):
        self.s.trace["chain"].append({"entity_name": "req.get"})
        self.s.hood["truncated"] = True
        self.grade(m.FAIL)

    def test_missing_positive_still_fails(self):
        self.s.trace["chain"][0]["entity_name"] = "something_else"
        self.grade(m.FAIL)

    def test_missing_router_handoff_still_fails(self):
        self.s.trace["chain"][2]["entity_name"] = "something_else"
        self.grade(m.FAIL)

    # The three arms of the classification, one per row. A clip's witness
    # re-supplies exactly the rows the cap dropped, so an absence has to be read
    # over the walk AND the witness. Read over the walk alone while the witness
    # licensed the verdict, a dropped required edge reads as an absent one, which
    # is the distinction FIR-2593's allowance says this check cannot make.
    def test_witness_resupplies_a_dropped_handoff(self):
        self.s.trace["chain"][2]["entity_name"] = "something_else"
        self.s.hood["entities"][-1]["name"] = "router.handle"
        result = self.grade(m.PASS)
        self.assertIn("the clip's complete witness, which the walk dropped",
                      str(result.asserts))
        self.assertEqual(len(self.s.calls), 2)

    def test_witness_resupplies_a_dropped_real_callee(self):
        self.s.trace["chain"][0]["entity_name"] = "something_else"
        self.s.hood["entities"][-1]["name"] = "app.enabled"
        self.grade(m.PASS)

    def test_name_only_witness_row_still_surfaces_the_handoff(self):
        # The walk's own name list carries name_only steps, so the witness has to
        # answer on the same terms. Counting a candidate and surfacing it are
        # different questions and only the second one is being asked here.
        self.s.trace["chain"][2]["entity_name"] = "something_else"
        self.s.hood["entities"][-1]["name"] = "router.handle"
        self.s.hood["relations"][-1]["resolution"] = "name_only"
        self.grade(m.PASS)

    def test_witness_without_the_handoff_still_fails(self):
        # The other arm, and brownfield:4's real one: every dropped row is inside
        # the witness, the witness is complete, and the edge is in neither.
        self.s.trace["chain"][2]["entity_name"] = "something_else"
        result = self.grade(m.FAIL)
        self.assertIn("witnessed destination(s) the clips dropped", str(result.asserts))

    def test_unwitnessable_clip_leaves_the_handoff_unreadable(self):
        # The third arm. A clip nothing can witness re-supplies nothing, so an
        # absent edge cannot be told from a dropped one and the check says so.
        self.s.trace["chain"][2]["entity_name"] = "something_else"
        self.s.trace["clipped_steps"][0]["step"] = 0
        self.grade(m.UNREADABLE)
        self.assertEqual(len(self.s.calls), 1)

    def test_omitted_forbidden_requires_trace_confirmation(self):
        self.s.hood["entities"][-1]["name"] = "req.get"
        self.grade(m.FAIL)
        self.assertEqual(len(self.s.calls), 3)

    def test_raw_forbidden_without_confirmation_is_unreadable(self):
        self.s.hood["entities"][-1]["name"] = "req.get"
        self.s.focused["chain"] = []
        self.grade(m.UNREADABLE)

    def test_name_only_candidate_is_not_counted(self):
        self.s.hood["entities"][-1]["name"] = "req.get"
        self.s.hood["relations"][-1]["resolution"] = "name_only"
        self.grade(m.PASS)
        self.assertEqual(len(self.s.calls), 2)

    def test_focused_name_only_is_not_counted(self):
        self.s.hood["entities"][-1]["name"] = "req.get"
        self.s.focused["chain"][0]["resolution"] = "name_only"
        self.grade(m.PASS)

    def test_non_trace_relation_does_not_count(self):
        self.s.hood["entities"][-1]["name"] = "req.get"
        self.s.hood["relations"].append(dict(self.s.hood["relations"][-1], kind="Contains"))
        self.s.hood["relations"][-2]["resolution"] = "name_only"
        self.s.hood["relation_count"] += 1
        self.grade(m.PASS)

    def test_contradictory_small_witness_is_unreadable(self):
        self.s.hood["entities"] = self.s.hood["entities"][:1]
        self.s.hood["relations"] = []
        self.s.hood.update(entity_count=1, relation_count=0)
        self.grade(m.UNREADABLE)

    def test_malformed_endpoint_is_unreadable(self):
        self.s.hood["relations"][-1]["src"] = "bad"
        self.grade(m.UNREADABLE)

    def test_unrelated_handle_is_not_router(self):
        self.s.trace["chain"][2]["entity_name"] = "unrelated.handle"
        self.grade(m.FAIL)

    def test_relation_clip_is_unreadable_even_without_flag(self):
        self.s.hood["relation_count"] += 1
        self.grade(m.UNREADABLE)

    def test_wrong_focal_is_unreadable(self):
        self.s.hood["focal_id"] = "other"
        self.grade(m.UNREADABLE)

    def test_root_clip_is_unreadable(self):
        self.s.trace["clipped_steps"][0]["step"] = 0
        self.grade(m.UNREADABLE)
        self.assertEqual(len(self.s.calls), 1)

    def test_unresolved_endpoint_is_unreadable(self):
        self.s.hood["relations"][-1]["dst"] = {"Entity": "missing"}
        self.grade(m.UNREADABLE)

    def test_output_budget_loss_is_unreadable(self):
        for target in (self.s.trace, self.s.hood):
            target["degradations"] = [{"component": "response_budget"}]
            self.grade(m.UNREADABLE)
            del target["degradations"]


class GateTests(unittest.TestCase):
    """The verdict half of the same path, graded where a pull request can see it.

    `gate.py --self-test` is a step in `acceptance.yml`, and that whole job
    carries `if: github.event_name != 'pull_request'`, so it never runs on the
    pull request that could break it. This file is wired into `ci.yml`'s
    fast-gate-lint job, which does, so driving the gate's own self-test from here
    is what makes its rules refuse a bad change before that change merges rather
    than a release later.
    """

    def test_gate_self_test_passes(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            rc = gate.self_test()
        self.assertEqual(rc, 0, output.getvalue())
        self.assertIn("self-test passed", output.getvalue())

    def test_a_fail_allowance_needs_its_ticket(self):
        # The one rule this file exists beside: a tolerated FAIL that nobody is
        # tracking is a defect nobody is fixing.
        with self.assertRaises(gate.GateError):
            gate.parse_fail_allowance("brownfield:4=|the hand-off|no ticket")
        key, spec = gate.parse_fail_allowance(
            "brownfield:4=FIR-2464|the hand-off|tracked")
        self.assertEqual((key, spec.ticket), (("brownfield", "4"), "FIR-2464"))


if __name__ == "__main__":
    unittest.main()
