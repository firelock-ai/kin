#!/usr/bin/env python3
"""Grade bounded trace witnesses without opening a repository or process."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    "brownfield_repro", Path(__file__).with_name("brownfield_repro.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


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


if __name__ == "__main__":
    unittest.main()
