#!/usr/bin/env python3
"""Grade bounded trace witnesses and the gate that reads them, no repo, no process."""
import contextlib
import copy
import copy
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


class DepthBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.s = Fixture()
        del self.s.trace["clipped_steps"]
        self.s.trace["chain"].extend([
            {"entity_id": "set", "entity_name": "app.set", "depth": 2, "parent_step": 1},
            {"entity_id": "leaf", "entity_name": "safe", "depth": 2, "parent_step": 4},
        ])
        for index, row in enumerate(self.s.trace["chain"], 1):
            row.update(step=index, fanout_truncated=False, fanout_dropped=0,
                       terminal="bound_reached" if row["depth"] == 2 else None)
            row.setdefault("parent_step", 0)
        self.s.trace.update(depth=2, direction="calls", total_steps=6, terminal_bound_steps=2)

    def grade(self, expected):
        result = m.check_4(self.s)
        self.assertEqual(result.status, expected, result.asserts)
        return result

    def test_depth_limit_preserves_the_requested_walk(self):
        result = self.grade(m.PASS)
        self.assertIn("2 terminal(s) stop at the declared depth bound", str(result.asserts))
        self.assertEqual(len(self.s.calls), 1)

    def test_depth_limit_does_not_hide_a_missing_handoff(self):
        self.s.trace["chain"][2]["entity_name"] = "something_else"
        self.grade(m.FAIL)

    def test_name_only_candidates_do_not_hide_the_bound(self):
        self.s.trace["degradations"] = [{"component": "call_resolution", "reason": "name_only_steps"}]
        self.s.trace["chain"][3].update(entity_name="req.get", resolution="name_only")
        self.grade(m.PASS)

    def test_unexplained_or_malformed_bounds_refuse(self):
        original = copy.deepcopy(self.s.trace)
        for update in ({"terminal_bound_steps": 0}, {"terminal_bound_steps": 3},
                       {"terminal_bound_steps": True}, {"depth": 1}, {"direction": "callers"},
                       {"total_steps": 7}, {"degradations": [{"component": "walk_timeout"}]},
                       {"degradations": {}}):
            with self.subTest(update=update):
                self.s.trace = dict(copy.deepcopy(original), **update)
                self.grade(m.UNREADABLE)
        self.s.trace = original
        del self.s.trace["terminal_bound_steps"]
        self.grade(m.UNREADABLE)

    def test_incomplete_or_contradictory_rows_refuse(self):
        original = copy.deepcopy(self.s.trace)
        for index, update in ((0, {"fanout_truncated": True}), (0, {"fanout_dropped": 2}),
                              (0, {"fanout_dropped": False}), (0, {"terminal": "bound_reached"}),
                              (4, {"parent_step": 5}), (4, {"parent_step": 0}),
                              (4, {"depth": 3}), (4, {"step": 6})):
            with self.subTest(index=index, update=update):
                self.s.trace = copy.deepcopy(original)
                self.s.trace["chain"][index].update(update)
                self.grade(m.UNREADABLE)
        self.s.trace = original
        del self.s.trace["chain"][0]["fanout_truncated"]
        self.grade(m.UNREADABLE)

    def test_lost_output_is_not_excused_by_a_depth_bound(self):
        original = copy.deepcopy(self.s.trace)
        for update in ({"steps_omitted": 1}, {"fanout_narrowed": True},
                       {"_kin": {"response": {"bounded": True}}},
                       {"degradations": [{"component": "response_budget"}]}):
            with self.subTest(update=update):
                self.s.trace = dict(copy.deepcopy(original), **update)
                self.grade(m.UNREADABLE)

    def test_real_fanout_clip_still_needs_its_witness(self):
        self.s.trace["clipped_steps"] = [{"step": 4, "entity_id": "application",
                                         "limit_per_step": 25, "dropped_callees": 2,
                                         "dropped_callers": 0}]
        self.s.trace["chain"][3].update(fanout_truncated=True, fanout_dropped=2)
        self.s.hood["truncated"] = True
        self.grade(m.UNREADABLE)
        self.assertEqual(len(self.s.calls), 2)

    def test_coverage_gap_or_unknown_terminal_stays_unreadable(self):
        original = copy.deepcopy(self.s.trace)
        for update in ({"focal_terminal": "coverage_gap"}, {"focal_terminal": "leaf"},
                       {"terminal_coverage_gap_steps": 1}):
            with self.subTest(update=update):
                self.s.trace = dict(copy.deepcopy(original), **update)
                self.grade(m.UNREADABLE)
        for terminal in ("coverage_gap", "unknown_new_shortfall", {}, False):
            with self.subTest(terminal=terminal):
                self.s.trace = copy.deepcopy(original)
                self.s.trace["chain"][0]["terminal"] = terminal
                self.s.trace["chain"][2]["entity_name"] = "something_else"
                self.grade(m.UNREADABLE)

    def test_terminal_counters_cannot_disagree_with_the_rows(self):
        original = copy.deepcopy(self.s.trace)
        for field in ("terminal_leaf_steps", "terminal_annotation_steps", "terminal_external_steps"):
            with self.subTest(field=field):
                self.s.trace = dict(copy.deepcopy(original), **{field: 1})
                self.grade(m.UNREADABLE)
        self.s.trace = dict(original, terminal_leaf_steps=0, terminal_annotation_steps=0,
                            terminal_external_steps=0, terminal_coverage_gap_steps=0)
        self.grade(m.PASS)

    def test_terminal_cannot_have_children_or_be_undisclosed_at_the_bound(self):
        self.s.trace["chain"][0]["terminal"] = "leaf"
        self.grade(m.UNREADABLE)
        self.s.trace["chain"][0]["terminal"] = None
        self.s.trace["chain"][4]["terminal"] = None
        self.s.trace["terminal_bound_steps"] = 1
        self.grade(m.UNREADABLE)


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


class ExportReferenceTests(unittest.TestCase):
    """The export identity selects the answer before any site line is graded."""

    def setUp(self):
        self.payloads = {}
        for export, caller, line in m.EXPRESS_MODULE_SOURCED_SITES:
            self.payloads[export] = self.body(export, "lib/express.js", "constant", caller, line)
        self.export = self.payloads["response"]
        self.module = self.body("response", "lib/response.js", "module", "lib/express.js", 21)
        self.other = self.body("app.response", "test/app.response.js", "module", "test/exports.js", 48)

    @staticmethod
    def body(name, file_path, kind, caller, line):
        identity = file_path + ":" + name
        return {"focal_entity": {"id": identity, "name": name, "file_path": file_path,
                                 "kind": kind},
                "entity_id": identity, "owner_qualified_name": name,
                "references": [{"file_path": caller, "kind": "Module",
                                "reference_lines": [line]}]}

    def sections(self, *bodies):
        self.payloads["response"] = {"ambiguous_focal": True,
            "candidate_count": len(bodies), "candidates_by_owner": list(bodies)}
        return self.payloads["response"]

    def fixture(self, name):
        self.assertEqual(name, "express")
        return "fixture"

    def sweep_gate(self, name):
        self.assertEqual(name, "express")

    def cached(self, repo, tool, args):
        self.assertEqual(repo, "fixture")
        self.assertEqual(tool, "find_references")
        return self.payloads[args["query"]]

    def grade(self, expected):
        result = m.check_11(self)
        self.assertEqual(result.status, expected, result.asserts)
        return result

    def test_single_focal_export_still_passes(self):
        self.grade(m.PASS)

    def test_exact_export_in_any_section_position_passes(self):
        for bodies in [(self.export, self.module, self.other),
                       (self.module, self.export, self.other),
                       (self.other, self.module, self.export)]:
            with self.subTest(order=[b["entity_id"] for b in bodies]):
                self.sections(*bodies)
                self.grade(m.PASS)

    def test_other_section_cannot_supply_missing_export_line(self):
        self.export["references"][0]["reference_lines"] = []
        self.sections(self.other, self.module, self.export)
        self.grade(m.FAIL)

    def test_other_section_cannot_supply_missing_export_consumer(self):
        self.export["references"] = []
        self.sections(self.other, self.export)
        self.grade(m.FAIL)

    def test_wrong_consumer_kind_or_file_does_not_pass(self):
        for key, value in [("kind", "Method"), ("file_path", "test/unrelated.js")]:
            with self.subTest(key=key):
                original = self.export["references"][0][key]
                self.export["references"][0][key] = value
                self.sections(self.other, self.export)
                self.grade(m.FAIL)
                self.export["references"][0][key] = original

    def test_missing_exact_export_is_unreadable_despite_matching_line_elsewhere(self):
        self.sections(self.other, self.module)
        self.grade(m.UNREADABLE)

    def test_single_focal_must_be_the_pinned_export(self):
        for replacement in (self.module, self.other):
            with self.subTest(focal=replacement["focal_entity"]):
                self.payloads["response"] = replacement
                self.grade(m.UNREADABLE)

    def test_two_exact_exports_are_unreadable_even_with_distinct_ids(self):
        duplicate = copy.deepcopy(self.export)
        duplicate["entity_id"] = duplicate["focal_entity"]["id"] = "different-id"
        self.sections(self.export, duplicate)
        self.grade(m.UNREADABLE)

    def test_each_export_identity_component_must_match(self):
        for key, value in (("name", "other"), ("kind", "module"),
                           ("file_path", "lib/other.js")):
            with self.subTest(key=key):
                malformed = copy.deepcopy(self.export)
                malformed["focal_entity"][key] = value
                malformed["owner_qualified_name"] = malformed["focal_entity"]["name"]
                self.sections(malformed, self.module)
                self.grade(m.UNREADABLE)

    def test_repeated_identity_is_unreadable(self):
        self.sections(self.export, copy.deepcopy(self.export))
        self.grade(m.UNREADABLE)

    def test_section_label_must_agree_with_focal(self):
        for key in ("entity_id", "owner_qualified_name"):
            with self.subTest(key=key):
                malformed = copy.deepcopy(self.export)
                malformed[key] = "unrelated"
                self.sections(malformed, self.module)
                self.grade(m.UNREADABLE)

    def test_malformed_section_and_missing_identity_are_unreadable(self):
        for malformed in (None, [], {}, {"focal_entity": {"id": "incomplete"}}):
            with self.subTest(section=malformed):
                self.sections(self.export, malformed)
                self.grade(m.UNREADABLE)

    def test_malformed_section_header_is_unreadable(self):
        for key, value in (("ambiguous_focal", False), ("candidate_count", 0),
                           ("candidate_count", 3), ("truncated", True),
                           ("candidate_count", "2"), ("candidate_count", True),
                           ("candidates_by_owner", {}), ("focal_entity", {})):
            with self.subTest(key=key, value=value):
                self.sections(self.export, self.module)[key] = value
                self.grade(m.UNREADABLE)

    def test_malformed_selected_reference_rows_are_unreadable(self):
        for malformed in (None, {}, [None]):
            with self.subTest(rows=malformed):
                self.export["references"] = malformed
                self.sections(self.export, self.module)
                self.grade(m.UNREADABLE)

    def test_true_resolution_miss_stays_unreadable(self):
        self.payloads["response"] = {"message": "Entity not found"}
        self.grade(m.UNREADABLE)

    def test_malformed_reference_lines_stay_unreadable(self):
        for malformed in ("48", [48, "49"], [False], [0]):
            with self.subTest(lines=malformed):
                self.export["references"][0]["reference_lines"] = malformed
                self.sections(self.export, self.module)
                self.grade(m.UNREADABLE)


if __name__ == "__main__":
    unittest.main()
