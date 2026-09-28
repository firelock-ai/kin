#!/usr/bin/env python3
"""Grade bounded trace witnesses and the gate that reads them, no repo, no process."""
import contextlib
import copy
import copy
import importlib.util
import io
import json
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

    def test_guessed_parent_cannot_be_proven_by_a_focused_child_query(self):
        self.s.trace["chain"][3]["resolution"] = "name_only"
        self.s.hood["entities"][-1]["name"] = "req.get"
        self.grade(m.PASS)
        self.assertEqual(len(self.s.calls), 2)

    def test_uppercase_forbidden_descendant_is_counted(self):
        self.s.trace["chain"].append({"entity_name": "escapeHTML",
                                     "resolution": "type_resolved", "parent_step": 4})
        self.grade(m.FAIL)

    def test_uppercase_guessed_descendant_is_not_counted(self):
        self.s.trace["chain"].append({"entity_name": "escapeHTML",
                                     "resolution": "name_only", "parent_step": 4})
        self.grade(m.PASS)

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
        # Metadata-only graph inspect presents these starts as 1-based lines.
        # The fixture stores zero-based starts to build relative sites.
        self.starts = {}
        self.payloads = {}
        for export, caller, line in m.EXPRESS_MODULE_SOURCED_SITES:
            self.payloads[export] = self.body(export, "lib/express.js", "constant", caller, line)
        self.export = self.payloads["response"]
        self.module = self.body("response", "lib/response.js", "module", "lib/express.js", 21)
        self.other = self.body("app.response", "test/app.response.js", "module", "test/exports.js", 48)

    def body(self, name, file_path, kind, caller, line):
        identity = file_path + ":" + name
        module_id = "module:" + caller
        self.starts[module_id] = 0
        return {"focal_entity": {"id": identity, "name": name,
                                 "projection": {"path": file_path}, "kind": kind},
                "entity_id": identity, "owner_qualified_name": name,
                "references": [{"entity_id": module_id, "kind": "Module",
                                "projection": {"path": caller}, "site_count": 1,
                                "sites": [{"line_in_entity": line - 1, "callee": None,
                                           "callee_unavailable": "caller_source_unavailable"}],
                                "sites_absent_reason": None}]}

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

    def kin_run(self, args, repo, timeout):
        self.assertEqual((repo, timeout), ("fixture", 30))
        self.assertEqual((args[:2], args[3:]), (["graph", "inspect"], ["--json"]))
        entity_id = args[2]
        start = self.starts.get(entity_id)
        if start is None:
            return 0, json.dumps({"error": "Entity not found", "lines": []}), ""
        lines = ["Entity: consumer (Module)", "  ID: " + entity_id,
                 "  File: " + entity_id.removeprefix("module:"),
                 "  Span: lines %d-%d" % (start + 1, start + 100)]
        if hasattr(self, "metadata_override"):
            lines = self.metadata_override(lines)
        return 0, json.dumps({"error": None, "lines": lines}), ""

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
        row = self.export["references"][0]
        row.update(sites=[], site_count=0, sites_absent_reason="no_evidence_span")
        self.sections(self.other, self.module, self.export)
        self.grade(m.FAIL)

    def test_a_site_is_placed_through_its_callers_span(self):
        # The file line is the caller's 0-based span start plus one plus the
        # site's offset inside it, so moving either alone moves the line off the
        # pinned one, and moving both keeps it.
        # test/exports.js is one module entity holding two exports' sites, so
        # both of them move with its span.
        module_id = self.export["references"][0]["entity_id"]
        sites = [row["sites"][0] for body in self.payloads.values()
                 for row in body["references"] if row["entity_id"] == module_id]
        self.assertEqual(len(sites), 2)
        self.starts[module_id] = 2
        self.grade(m.FAIL)
        for site in sites:
            site["line_in_entity"] -= 2
        self.grade(m.PASS)
        self.export["references"][0]["sites"][0]["line_in_entity"] += 1
        self.grade(m.FAIL)

    def test_a_site_kin_cannot_place_inside_its_caller_names_no_line(self):
        self.export["references"][0]["sites"][0]["line_in_entity"] = None
        self.grade(m.FAIL)

    def test_an_unreadable_caller_record_is_unreadable_not_a_wrong_line(self):
        del self.starts[self.export["references"][0]["entity_id"]]
        self.grade(m.UNREADABLE)

    def test_stale_or_wrong_module_metadata_cannot_place_a_site(self):
        for old, new in (("Span: lines", "Span: stale lines"),
                         ("ID: module:", "ID: unrelated:"),
                         ("File: test/", "File: other/"),
                         ("(Module)", "(Function)")):
            with self.subTest(replacement=new):
                self.metadata_override = lambda lines: [line.replace(old, new) for line in lines]
                self.grade(m.UNREADABLE)

    def test_a_site_outside_the_current_module_span_fails(self):
        self.metadata_override = lambda lines: [
            "  Span: lines 1-2" if "Span: " in line else line for line in lines]
        self.grade(m.FAIL)

    def test_module_metadata_timeout_is_unreadable(self):
        def timed_out(*args, **kwargs):
            raise m.subprocess.TimeoutExpired("graph inspect", 30)
        self.kin_run = timed_out
        self.grade(m.UNREADABLE)

    def test_sites_without_a_caller_id_are_unreadable(self):
        del self.export["references"][0]["entity_id"]
        self.grade(m.UNREADABLE)

    def test_other_section_cannot_supply_missing_export_consumer(self):
        self.export["references"] = []
        self.sections(self.other, self.export)
        self.grade(m.FAIL)

    def test_wrong_consumer_kind_or_file_does_not_pass(self):
        for key, value in [("kind", "Method"), ("projection", {"path": "test/unrelated.js"}),
                           ("projection", None), ("projection", "test/exports.js")]:
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
                           ("projection", {"path": "lib/other.js"}),
                           ("projection", None), ("projection", "lib/express.js"),
                           # A focal still carrying a bare file path is the
                           # retired shape, even beside a matching projection.
                           ("file_path", "lib/express.js")):
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

    def test_malformed_reference_sites_stay_unreadable(self):
        for malformed in ("48", [47], [None], [{"line_in_entity": "47"}],
                          [{"line_in_entity": False}], [{"line_in_entity": -1}],
                          [{"line_in_entity": 47.0}], [{"line_in_entity": 47, "callee": 7}]):
            with self.subTest(sites=malformed):
                self.export["references"][0]["sites"] = malformed
                self.sections(self.export, self.module)
                self.grade(m.UNREADABLE)

    def test_a_site_count_that_miscounts_its_sites_is_unreadable(self):
        for count in (0, 2, True, "1"):
            with self.subTest(site_count=count):
                self.export["references"][0]["site_count"] = count
                self.sections(self.export, self.module)
                self.grade(m.UNREADABLE)


class PinnedCallSiteTests(unittest.TestCase):
    """Checks 2 and 3 place each counted caller's site in its file and read the call there."""

    SESSION_START = m.REAL_CALLER_ONE_LINE - 25
    DIGEST_START = m.REAL_CALLER_TWO_LINE - 40

    def setUp(self):
        self.reference_requests = []
        self.starts = {"session-send": self.SESSION_START + 1,
                       "digest-401": self.DIGEST_START + 1}
        self.payload = {
            "focal_entity": {"id": "adapter-send", "name": m.HTTPADAPTER_SEND},
            "total_upstream": 2,
            "references": [
                self.row("session-send", m.REAL_CALLER_ONE, m.REAL_CALLER_ONE_FILE,
                         m.REAL_CALLER_ONE_LINE - 1 - self.SESSION_START,
                         m.REAL_CALLER_ONE_CALL),
                self.row("digest-401", m.REAL_CALLER_TWO, m.REAL_CALLER_TWO_FILE,
                         m.REAL_CALLER_TWO_LINE - 1 - self.DIGEST_START,
                         m.REAL_CALLER_TWO_CALL)],
            "candidates": []}
        self.bodies = {}
        for row in self.payload["references"]:
            site = row["sites"][0]
            lines = ["# unrelated"] * (site["line_in_entity"] + 2)
            lines[site["line_in_entity"]] = "return %s()" % site["callee"]
            self.bodies[row["entity_id"]] = "\n".join(lines)

    @staticmethod
    def row(entity_id, name, path, offset, callee):
        return {"entity_id": entity_id, "name": name, "kind": "Method",
                "projection": {"path": path}, "resolution": "type_resolved",
                "relation_kinds": ["calls"], "site_count": 1,
                "sites": [{"line_in_entity": offset, "callee": callee}],
                "sites_absent_reason": None, "sites_partial_reason": None}

    def sweep_gate(self, name, dependencies=None):
        self.assertEqual(name, "requests")

    def fixture(self, name):
        self.assertEqual(name, "requests")
        return "requests-fixture"

    def references(self, name, query, max_chars=None):
        self.assertEqual((name, query), ("requests", m.HTTPADAPTER_SEND))
        return m.Suite.references(self, name, query, max_chars)

    def cached(self, repo, tool, args):
        if tool == "find_references":
            self.reference_requests.append(args)
            return self.payload
        self.assertEqual((repo, tool), ("requests-fixture", "get_entity_source"))
        start = self.starts.get(args["entity_id"])
        if start is None:
            raise m.ProbeError("mcp get_entity_source isError: Entity not found")
        return {"id": args["entity_id"], "start_line": start,
                "body": self.bodies[args["entity_id"]]}

    def site(self, index):
        return self.payload["references"][index]["sites"][0]

    def grade(self, check, expected):
        result = check(self)
        self.assertEqual(result.status, expected, result.asserts)
        return result

    def test_both_pinned_call_sites_pass(self):
        self.grade(m.check_2, m.PASS)
        self.grade(m.check_3, m.PASS)

    def test_recall_requests_larger_budget_without_changing_relation_scope(self):
        self.grade(m.check_2, m.PASS)
        self.assertEqual(self.reference_requests,
                         [{"query": m.HTTPADAPTER_SEND, "max_chars": 60000}])

    def test_a_bounded_reply_cannot_grade_missing_caller_or_negative_control(self):
        for disclosure in (
                {"_kin": {"response": {"bounded": True, "max_chars": 12000}}},
                {"_kin": {"response": {"bounded": True, "max_chars": 60000}}},
                {"degradations": [{"component": "response_budget", "code": "response_over_budget"}]},
                {"truncated": True}):
            with self.subTest(disclosure=disclosure):
                self.setUp()
                self.payload["references"] = self.payload["references"][1:]
                self.payload.update(disclosure)
                result = self.grade(m.check_2, m.UNREADABLE)
                self.assertFalse(any(row["status"] in (m.PASS, m.FAIL) for row in result.asserts))

    def test_an_unbounded_missing_caller_still_fails(self):
        self.payload["references"] = self.payload["references"][1:]
        self.payload["_kin"] = {"response": {"bounded": False, "max_chars": 60000}}
        self.grade(m.check_2, m.FAIL)

    def test_a_bare_name_quote_is_the_pinned_call(self):
        # A language server's span is the name alone, and the quote reads `send`.
        self.site(0)["callee"] = "send"
        self.site(1)["callee"] = "connection.send"
        self.grade(m.check_2, m.PASS)
        self.grade(m.check_3, m.PASS)

    def test_a_site_one_line_off_fails(self):
        for index, check in ((0, m.check_2), (1, m.check_3)):
            for delta in (-1, 1):
                with self.subTest(check=check.__name__, delta=delta):
                    self.setUp()
                    self.site(index)["line_in_entity"] += delta
                    self.grade(check, m.FAIL)

    def test_the_callers_span_start_decides_the_file_line(self):
        self.starts["session-send"] += 1
        self.grade(m.check_2, m.FAIL)

    def test_the_wrong_text_at_the_right_line_fails(self):
        for callee in ("adapter.close", "r.send", "HTTPAdapter", "", None):
            with self.subTest(callee=callee):
                self.setUp()
                self.site(0)["callee"] = callee
                self.site(1)["callee"] = callee
                self.grade(m.check_2, m.FAIL)
                self.grade(m.check_3, m.FAIL)

    def test_a_site_kin_cannot_place_inside_its_caller_fails(self):
        self.site(0)["line_in_entity"] = None
        self.grade(m.check_2, m.FAIL)

    def test_a_caller_projected_into_another_file_fails(self):
        self.payload["references"][0]["projection"] = {"path": "src/requests/adapters.py"}
        self.grade(m.check_2, m.FAIL)

    def test_a_row_with_no_sites_fails(self):
        row = self.payload["references"][1]
        row.update(sites=[], site_count=0, sites_absent_reason="no_evidence_span")
        self.grade(m.check_3, m.FAIL)

    def test_an_unreadable_caller_record_is_unreadable(self):
        del self.starts["digest-401"]
        self.grade(m.check_3, m.UNREADABLE)

    def test_a_pinned_line_and_quote_do_not_pass_without_the_entity_call(self):
        for body in ("", "return unrelated()", "\n" * 100):
            with self.subTest(body=body):
                self.bodies["session-send"] = body
                self.grade(m.check_2, m.FAIL)

    def test_missing_body_or_invalid_one_based_start_is_unreadable(self):
        for start, body in ((0, "code"), (-1, "code"), (True, "code"), (1, None)):
            with self.subTest(start=start, body=body):
                self.starts["session-send"] = start
                self.bodies["session-send"] = body
                self.grade(m.check_2, m.UNREADABLE)

    def test_malformed_sites_are_unreadable_not_a_wrong_line(self):
        for sites in ("+23", [23], [{"line_in_entity": "23"}], [{"line_in_entity": -1}]):
            with self.subTest(sites=sites):
                self.setUp()
                self.payload["references"][0]["sites"] = sites
                self.grade(m.check_2, m.UNREADABLE)


if __name__ == "__main__":
    unittest.main()
