#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
"""The budget probe grades page limits and the reconstructed verdict separately."""
import copy
import json
import unittest

import verdict_limits_repro as verdict_limits
from trace_pages import drain_references


def wire(page):
    page = copy.deepcopy(page)
    accounting = page["_kin"].setdefault("response", {})
    accounting.update(max_chars=2000, chars_after_budget=0)
    for _ in range(8):
        text = json.dumps(page, separators=(",", ":"), ensure_ascii=False)
        size = len(text.encode("utf-8"))
        if accounting["chars_after_budget"] == size:
            return page, text
        accounting["chars_after_budget"] = size
    raise AssertionError("wire accounting did not converge")


def pages():
    shell = {
        "references": [], "next_cursor": None,
        "negative": {"safe_to_conclude_absent": False},
        "_kin": {
            "page": {"version": 1, "kind": "references", "complete": False,
                     "total_references": 2},
            "verdict": {"state": "inconclusive", "safe_to_conclude_absent": False,
                        "limiting_factor": "reference_page_partial"},
        },
    }
    first, last = copy.deepcopy(shell), copy.deepcopy(shell)
    first.update(references=[{"entity_id": "first"}], next_cursor="last-page")
    last.update(references=[{"entity_id": "second"}], readings=[
        {"key": "call_sites", "value": {"settled": False,
         "clauses": ["call_sites_owed: one caller still needs enrichment"]}},
        {"key": "negative", "value": {"safe_to_conclude_absent": False,
         "trust_reason": "call_sites_owed: one caller still needs enrichment"}},
        {"key": "_kin", "value": {"verdict": {
            "state": "inconclusive", "safe_to_conclude_absent": False,
            "limiting_factor": "call_sites_owed",
            "inputs": {"call_sites": "inconclusive", "absence_gate": "inconclusive"},
        }}},
    ])
    return [first, last]


def assemble(sequence):
    by_cursor = {None: sequence[0], "last-page": sequence[1]}
    return drain_references(lambda cursor: wire(by_cursor[cursor]), 2000)


def grade(payload):
    class Suite:
        def references(self, extra):
            assert extra == {"max_chars": 2000}
            return payload
    return verdict_limits.check_two_reasons(Suite())


class PagedVerdictLimits(unittest.TestCase):
    def test_actual_drain_preserves_both_transport_and_original_limit(self):
        answer = assemble(pages())
        self.assertEqual(answer["references"], [{"entity_id": "first"}, {"entity_id": "second"}])
        self.assertEqual(answer["_kin"]["verdict"]["limiting_factor"], "call_sites_owed")
        self.assertEqual(answer["call_sites"]["clauses"],
                         ["call_sites_owed: one caller still needs enrichment"])
        self.assertEqual(len(answer.page_observations), 2)
        self.assertTrue(all(size <= 2000 for size in answer.page_bytes))
        result = grade(answer)
        self.assertEqual(result.status, verdict_limits.PASS, result.detail)

    def test_each_page_must_name_its_partial_reason_and_refuse_absence(self):
        for index in (0, 1):
            for factor in (None, "", "call_sites_owed", "reference_page_partial; call_sites_owed"):
                with self.subTest(index=index, factor=factor):
                    sequence = pages()
                    sequence[index]["_kin"]["verdict"]["limiting_factor"] = factor
                    self.assertEqual(grade(assemble(sequence)).status, verdict_limits.FAIL)
            for section in ("negative", "verdict"):
                sequence = pages()
                target = sequence[index] if section == "negative" else sequence[index]["_kin"]
                target[section]["safe_to_conclude_absent"] = True
                with self.assertRaisesRegex(ValueError, "absence|unqualified"):
                    assemble(sequence)

    def test_reassembly_must_restore_every_original_qualifying_clause(self):
        for factor in (None, "reference_page_partial", "other_gap"):
            sequence = pages()
            sequence[1]["readings"][-1]["value"]["verdict"]["limiting_factor"] = factor
            result = grade(assemble(sequence))
            self.assertEqual(result.status, verdict_limits.FAIL, result.detail)

        for value in (None, {}, {"settled": True, "clauses": []},
                      {"settled": False, "clauses": ["other_gap: unknown"]}):
            sequence = pages()
            sequence[1]["readings"][0]["value"] = value
            self.assertEqual(grade(assemble(sequence)).status, verdict_limits.FAIL)

    def test_complete_first_page_does_not_pretend_it_exercised_a_transport_limit(self):
        full = dict(assemble(pages()))
        full["_kin"]["page"] = {"version": 1, "kind": "references", "complete": True}
        answer = drain_references(lambda cursor: wire(full), 2000)
        self.assertEqual(len(answer.page_observations), 1)
        self.assertNotIn("reference_page_partial", answer["_kin"]["verdict"]["limiting_factor"])
        self.assertEqual(grade(answer).status, verdict_limits.UNREADABLE)
        full["_kin"]["verdict"]["limiting_factor"] += "; reference_page_partial"
        with self.assertRaisesRegex(ValueError, "complete response carries a partial-page"):
            drain_references(lambda cursor: wire(full), 2000)


if __name__ == "__main__":
    unittest.main()
