#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
"""Grade how magic-repro reads reference rows that address sites inside callers.

A `find_references` row names its caller by entity id, serves the caller's file
only as `projection.path`, and addresses each site as `line_in_entity`, counted
from 0 at the caller's first line, with the `callee` text Kin cut from the
caller's body there. It carries no file line.

Case 19 still has to grade every site against the file on disk, because that is
the only thing that tells a re-anchored site from a remembered one. It places a
site in the file through `get_entity_source`: its 1-based `start_line` plus
the site's `line_in_entity`, checked against the returned entity-only body.
These cases hold that placement, and the rule that a site Kin cannot place
inside its caller is the stale site itself rather than something to skip. The
checks that ask which file a caller lives in read `projection.path`, and the
last cases hold that reading.

No repo, no daemon: every input is a literal payload.
"""
import ast
import copy
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

# The fixture file exactly as case 19 reads it back: the module docstring the
# comment-only commit prepended, then the original source.
LINES = (m.MIXIN_DOCSTRING + m.MIXIN_SESSIONS_PY).splitlines()
PATH = "pkg/sessions.py"


def first_line(text, after=0):
    """The 0-based index of the first line at or after `after` that starts with `text`."""
    return next(index for index in range(after, len(LINES))
                if LINES[index].strip().startswith(text))


RESOLVE = first_line("def resolve_redirects")
REQUEST = first_line("def request")
# Session.send is the second `def send` in the file; the first is the mixin's.
SEND = first_line("def send", first_line("class Session("))


def offset(start, text):
    """A site's `line_in_entity`: its line counted from 0 at the caller's first line."""
    return first_line(text, start) - start


def row(name, entity_id, start, call, callee, path=PATH):
    return {"entity_id": entity_id, "name": name, "kind": "Method",
            "projection": {"path": path}, "resolution": "type_resolved",
            "relation_kinds": ["calls"], "site_count": 1,
            "sites": [{"line_in_entity": offset(start, call), "callee": callee}],
            "sites_absent_reason": None, "sites_partial_reason": None}


def evidence():
    return {
        "error": None,
        "source_lines": LINES,
        "after_send": {"focal_entity": {"id": "session-send"}, "references": [
            row("SessionRedirectMixin.resolve_redirects", "resolve", RESOLVE,
                "resp = self.send(", "self.send"),
            row("Session.request", "request", REQUEST, "return self.send(", "self.send")]},
        "after_adapter": {"focal_entity": {"id": "adapter-send"}, "references": [
            row("Session.send", "send", SEND, "return adapter.send(", "adapter.send")]},
        "after_caller_starts": {"resolve": entity_source(RESOLVE),
                                "request": entity_source(REQUEST),
                                "send": entity_source(SEND)},
    }


def entity_source(start):
    node = next(node for node in ast.walk(ast.parse("\n".join(LINES)))
                if isinstance(node, ast.FunctionDef) and node.lineno == start + 1)
    return {"start_line": node.lineno, "body": "\n".join(LINES[start:node.end_lineno])}


class Suite:
    def __init__(self, recorded):
        self.recorded = recorded

    def comment_only_commit_evidence(self):
        return self.recorded


def grade(recorded):
    return m.check_19(Suite(recorded))


def rows(recorded, key):
    return recorded[key]["references"]


class Check19(unittest.TestCase):
    """Every reported site, placed in the edited file, must still carry the call."""

    def assert_status(self, recorded, expected):
        result = grade(recorded)
        self.assertEqual(result.status, expected, result.asserts)
        return result

    def test_the_fixture_places_each_call_where_the_file_has_it(self):
        # Guards the fixture itself: the offsets above must name the real calls.
        for start, call in ((RESOLVE, "resp = self.send("), (REQUEST, "return self.send("),
                            (SEND, "return adapter.send(")):
            self.assertGreater(offset(start, call), 0)
            self.assertIn(call, LINES[start + offset(start, call)])

    def test_sites_that_carry_their_calls_pass(self):
        result = self.assert_status(evidence(), m.PASS)
        self.assertIn("all 3 reported reference site(s)", result.detail)

    def test_a_site_remembered_from_before_the_commit_fails(self):
        # The defect this check exists for: the caller moved down 26 lines with
        # its file and one of its sites did not, so Kin can place that site
        # inside no caller.
        recorded = evidence()
        rows(recorded, "after_adapter")[0]["sites"].append(
            {"line_in_entity": None, "callee": None, "callee_unavailable": "site_outside_caller"})
        rows(recorded, "after_adapter")[0]["site_count"] = 2
        self.assert_status(recorded, m.FAIL)

    def test_a_site_one_line_off_fails(self):
        for key, index in (("after_send", 0), ("after_send", 1), ("after_adapter", 0)):
            for delta in (-1, 1):
                with self.subTest(key=key, index=index, delta=delta):
                    recorded = evidence()
                    rows(recorded, key)[index]["sites"][0]["line_in_entity"] += delta
                    self.assert_status(recorded, m.FAIL)

    def test_a_caller_span_left_at_its_old_place_fails(self):
        # Placement runs through the caller's own span, so a caller the graph
        # never re-anchored puts even a correct offset on the wrong file line.
        recorded = evidence()
        recorded["after_caller_starts"]["send"]["start_line"] -= 26
        self.assert_status(recorded, m.FAIL)

    def test_the_right_line_quoting_another_call_fails(self):
        recorded = evidence()
        rows(recorded, "after_send")[0]["sites"][0]["callee"] = "self.get_redirect_target"
        self.assert_status(recorded, m.FAIL)

    def test_text_kin_says_lies_outside_the_caller_fails(self):
        recorded = evidence()
        site = rows(recorded, "after_adapter")[0]["sites"][0]
        site.update(callee=None, callee_unavailable="site_outside_caller")
        self.assert_status(recorded, m.FAIL)

    def test_a_quote_that_is_only_unavailable_is_not_staleness(self):
        recorded = evidence()
        site = rows(recorded, "after_adapter")[0]["sites"][0]
        site.update(callee=None, callee_unavailable="caller_source_unavailable")
        self.assert_status(recorded, m.PASS)

    def test_a_bare_name_quote_names_the_method(self):
        recorded = evidence()
        rows(recorded, "after_adapter")[0]["sites"][0]["callee"] = "send"
        self.assert_status(recorded, m.PASS)

    def test_a_caller_that_cannot_be_placed_is_unreadable_not_a_pass(self):
        recorded = evidence()
        recorded["after_caller_starts"]["request"] = {"error": "get_entity unreadable"}
        self.assert_status(recorded, m.UNREADABLE)
        recorded = evidence()
        del recorded["after_caller_starts"]["send"]
        self.assert_status(recorded, m.UNREADABLE)

    def test_a_correct_file_line_cannot_substitute_for_missing_entity_source(self):
        for body in (None, 17):
            with self.subTest(body=body):
                recorded = evidence()
                recorded["after_caller_starts"]["send"]["body"] = body
                self.assert_status(recorded, m.UNREADABLE)

    def test_a_correct_file_line_cannot_substitute_for_a_wrong_entity_body(self):
        for body in ("", "def send():\n    return unrelated()"):
            with self.subTest(body=body):
                recorded = evidence()
                recorded["after_caller_starts"]["send"]["body"] = body
                self.assert_status(recorded, m.FAIL)

    def test_a_stale_site_outranks_an_unplaced_caller(self):
        recorded = evidence()
        recorded["after_caller_starts"]["request"] = {"error": "get_entity unreadable"}
        rows(recorded, "after_adapter")[0]["sites"][0]["line_in_entity"] = None
        self.assert_status(recorded, m.FAIL)

    def test_malformed_sites_are_unreadable(self):
        recorded = evidence()
        rows(recorded, "after_adapter")[0]["sites"] = "+3"
        self.assert_status(recorded, m.UNREADABLE)

    def test_rows_with_no_site_are_not_failed(self):
        # An absent site is a different answer from a wrong one.
        recorded = evidence()
        row = rows(recorded, "after_send")[1]
        row.update(sites=[], site_count=0, sites_absent_reason="no_evidence_span")
        self.assert_status(recorded, m.PASS)

    def test_nothing_graded_is_unreadable(self):
        recorded = evidence()
        for key in ("after_send", "after_adapter"):
            for each in rows(recorded, key):
                each.update(sites=[], site_count=0, sites_absent_reason="no_evidence_span")
        self.assert_status(recorded, m.UNREADABLE)

    def test_only_callers_projected_into_the_edited_file_are_graded(self):
        recorded = evidence()
        for key in ("after_send", "after_adapter"):
            for each in rows(recorded, key):
                each["projection"] = {"path": "pkg/adapters.py"}
                each["sites"][0]["line_in_entity"] = None
        self.assert_status(recorded, m.UNREADABLE)

    def test_a_row_carrying_only_the_retired_file_path_is_not_read_as_placed(self):
        recorded = evidence()
        for key in ("after_send", "after_adapter"):
            for each in rows(recorded, key):
                each["file_path"] = each.pop("projection")["path"]
        self.assert_status(recorded, m.UNREADABLE)


class CallerSpanStarts(unittest.TestCase):
    """The caller starts case 19 places sites by, read once per caller."""

    class Mcp:
        def __init__(self, records):
            self.records = records
            self.calls = []

        def mcp(self, repo, tool, args):
            self.calls.append((repo, tool, args["entity_id"]))
            record = self.records[args["entity_id"]]
            if isinstance(record, Exception):
                raise record
            return record, 0

    def test_each_caller_is_read_once_through_get_entity_source(self):
        records = {"a": {"start_line": 31, "body": "def a(): pass"},
                   "b": {"start_line": 1, "body": "def b(): pass"}}
        fake = self.Mcp(records)
        payloads = ({"references": [{"entity_id": "a"}, {"entity_id": "b"}]},
                    {"references": [{"entity_id": "a"}, {"name": "federated"}, None]})
        starts = m.Suite.caller_span_starts(fake, "repo", payloads)
        self.assertEqual(starts, records)
        self.assertEqual(fake.calls, [("repo", "get_entity_source", "a"),
                                      ("repo", "get_entity_source", "b")])

    def test_an_unreadable_record_is_named_rather_than_guessed(self):
        fake = self.Mcp({"refused": m.McpError("mcp get_entity_source isError"),
                         "spanless": {"id": "spanless"},
                         "negative": {"start_line": -1, "body": "code"},
                         "zero": {"start_line": 0, "body": "code"},
                         "boolean": {"start_line": True, "body": "code"},
                         "bodyless": {"start_line": 1}})
        payloads = ({"references": [{"entity_id": key} for key in fake.records]},)
        starts = m.Suite.caller_span_starts(fake, "repo", payloads)
        for key in fake.records:
            self.assertNotIn("start_line", starts[key], key)
            self.assertTrue(starts[key]["error"], key)

    def test_whole_file_callers_do_not_request_source(self):
        fake = self.Mcp({})
        payloads = ({"references": [{"entity_id": "m", "kind": "Module"},
                                     {"entity_id": "f", "kind": "File"}]},)
        starts = m.Suite.caller_span_starts(fake, "repo", payloads)
        self.assertEqual(fake.calls, [])
        self.assertTrue(all("error" in source for source in starts.values()))


class ProjectionPath(unittest.TestCase):
    """Which file a caller is projected into, read from `projection.path` only."""

    def test_the_projection_path_is_read(self):
        self.assertEqual(m.projection_path({"projection": {"path": "pkg/cli.py"}}), "pkg/cli.py")

    def test_anything_else_reads_as_no_projection(self):
        for value in ({}, {"file_path": "pkg/cli.py"}, {"projection": None},
                      {"projection": "pkg/cli.py"}, {"projection": {"path": ""}},
                      {"projection": {"path": None}}, None, []):
            with self.subTest(row=value):
                self.assertIsNone(m.projection_path(value))


class Check5(unittest.TestCase):
    """No test file may claim a caller of Adapter.send, read from each row's projection."""

    def setUp(self):
        self.payload = {"focal_entity": {"id": "adapter-send"}, "references": [
            {"entity_id": "s", "name": "Session.send", "projection": {"path": "pkg/client.py"}}]}

    def fixture(self, name):
        return "converted"

    def inspect(self, repo, name):
        return {"raw": "", "relations": []}

    def references(self, repo, query):
        return copy.deepcopy(self.payload)

    def status(self):
        return m.check_5(self).status

    def test_production_callers_pass(self):
        self.assertEqual(self.status(), m.PASS)

    def test_a_caller_projected_into_tests_fails(self):
        self.payload["references"].append(
            {"entity_id": "t", "name": "test_send", "projection": {"path": "tests/test_client.py"}})
        self.assertEqual(self.status(), m.FAIL)

    def test_a_caller_with_no_projection_is_unreadable_not_a_pass(self):
        self.payload["references"].append(
            {"entity_id": "t", "name": "test_send", "file_path": "tests/test_client.py"})
        self.assertEqual(self.status(), m.UNREADABLE)


class RelimportFocal(unittest.TestCase):
    """Check 23 identifies its focal by name and projected file, as a row is read."""

    def focal(self, **fields):
        focal = {"id": "c", "name": m.RELIMPORT_LIVE_FUNCTION, "kind": "Function",
                 "projection": {"path": "pkg/store.py"}}
        focal.update(fields)
        return focal

    def test_the_projected_focal_is_the_live_function(self):
        self.assertTrue(m.is_relimport_live_focal(self.focal()))

    def test_another_name_or_file_is_the_wrong_focal(self):
        self.assertFalse(m.is_relimport_live_focal(self.focal(name="orphaned_helper")))
        self.assertFalse(m.is_relimport_live_focal(
            self.focal(projection={"path": "pkg/cli.py"})))

    def test_a_focal_with_only_the_retired_file_path_is_not_identified(self):
        focal = self.focal(file_path="pkg/store.py")
        del focal["projection"]
        self.assertFalse(m.is_relimport_live_focal(focal))
        self.assertFalse(m.is_relimport_live_focal(None))


if __name__ == "__main__":
    unittest.main()
