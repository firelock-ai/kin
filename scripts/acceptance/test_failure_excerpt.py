#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

"""Keep the failure evidence the acceptance suites report.

A suite reports why a command failed by quoting its output, and it used to
quote a fixed slice of it: the first 220 characters, or the last 400. The first
slice kept a warning printed ahead of the error and dropped the error. The last
dropped a Rust panic that was followed by a longer log. Either way the report
said a command failed and not why.

Every suite now quotes through one `failure_excerpt` block, carried in each
suite byte for byte because a suite is also copied out and run as a single
file. This test keeps the copies equal, keeps each copy in use, refuses a
suite that slices a command's error output directly again, and drives the
block itself against the shapes that lost evidence before.
"""

from __future__ import annotations

import ast
import pathlib
import re
import sys
import unittest

HERE = pathlib.Path(__file__).resolve().parent
BEGIN = "# BEGIN failure evidence excerpt\n"
END = "# END failure evidence excerpt\n"

# A direct slice of a command's error output: `err[:200]`, `stderr[-2000:]`,
# `flatten(err)[:220]`, `(err or out)[-300:]`, `err.strip()[-600:]`,
# `proc.stderr[-400:]`, `outcome["stderr"][-400:]`. Each of these is how
# evidence was cut before, and none is needed now.
ERROR_SLICE = re.compile(
    r"""(?:\b[a-z_]*err\b|\bstderr\w*\b|\[['"]stderr['"]\])"""
    r"""[^\[\]\n]{0,40}?\)?\s*\[\s*-?\d*\s*:\s*-?\d*\s*\]"""
)


def suites():
    return sorted(path for path in HERE.glob("*.py") if not path.name.startswith("test_"))


def block_of(text):
    start = text.find(BEGIN)
    if start < 0:
        return None
    end = text.find(END, start)
    if end < 0:
        raise AssertionError("an excerpt block opens and never closes")
    return text[start:end + len(END)]


def load_block():
    reference = HERE / "first_contact_honesty.py"
    namespace = {"re": re}
    exec(compile(block_of(reference.read_text(encoding="utf-8")), str(reference), "exec"),
         namespace)
    return namespace


class CopiesTest(unittest.TestCase):
    def test_every_copy_is_the_same_block_and_is_used(self):
        blocks = {}
        for path in suites():
            text = path.read_text(encoding="utf-8")
            block = block_of(text)
            if block is None:
                continue
            blocks[path.name] = block
            outside = text.replace(block, "")
            self.assertIn("failure_excerpt(", outside,
                          "%s carries the block and never quotes through it" % path.name)
            self.assertRegex(text, r"(?m)^import re$",
                             "%s carries the block without importing re" % path.name)
        self.assertIn("first_contact_honesty.py", blocks)
        self.assertIn("init_memory_repro.py", blocks)
        reference = blocks["first_contact_honesty.py"]
        for name, block in blocks.items():
            self.assertEqual(block, reference, "%s carries a different excerpt block" % name)

    def test_no_suite_slices_a_command_error_directly(self):
        found = []
        for path in suites():
            text = path.read_text(encoding="utf-8")
            block = block_of(text) or ""
            for number, line in enumerate(text.replace(block, "").splitlines(), 1):
                if ERROR_SLICE.search(line):
                    found.append("%s: %s" % (path.name, line.strip()))
        self.assertEqual(found, [], "quote a command's error through failure_excerpt")

    def test_every_tail_helper_quotes_through_the_block(self):
        cutting = []
        for path in suites():
            tree = ast.parse(path.read_text(encoding="utf-8"), str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef) and node.name in ("tail", "_tail"):
                    calls = {call.func.id for call in ast.walk(node)
                             if isinstance(call, ast.Call) and isinstance(call.func, ast.Name)}
                    if "failure_excerpt" not in calls:
                        cutting.append("%s:%d" % (path.name, node.lineno))
        self.assertEqual(cutting, [], "a tail helper still cuts evidence on its own")

    def test_the_slice_rule_recognizes_every_shape_that_lost_evidence(self):
        for line in ('flatten(err)[:220]', 'stderr[-2000:]', '(err or out)[-300:]',
                     'err.strip()[-600:]', 'flatten(stderr_text)[:200]',
                     'err.decode("utf-8", "replace")[:400]', '((aerr or aout) or "")[-200:]',
                     '(done.stderr or done.stdout).strip()[:400]', "outcome['stderr'][-400:]",
                     '(init.stdout + init.stderr)[-400:]'):
            self.assertRegex(line, ERROR_SLICE)
        for line in ('flatten(failure_excerpt(err))', 'spec["commit"][:12]',
                     'json.dumps(resp["error"])[:200]', 'error_lines(text)[:3]'):
            self.assertNotRegex(line, ERROR_SLICE)


class ExcerptTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ns = load_block()
        cls.excerpt = staticmethod(cls.ns["failure_excerpt"])
        cls.limit = cls.ns["EVIDENCE_LIMIT"]

    def test_output_that_fits_is_returned_whole(self):
        text = "warning: one\nError: two"
        self.assertEqual(self.excerpt(text), text)
        self.assertEqual(self.excerpt("  \n"), "")
        self.assertEqual(self.excerpt(None), "")

    def test_an_error_behind_a_long_warning_survives(self):
        warning = "warning: KIN_REGISTRY_PATH names a registry this run does not own\n" * 200
        text = warning + "Error: kin init refused the store: the history is unreadable\n" + warning
        got = self.excerpt(text)
        self.assertIn("Error: kin init refused the store: the history is unreadable", got)
        self.assertLessEqual(len(got), self.limit + 64)

    def test_a_panic_and_its_message_survive_a_longer_log(self):
        log = "\n".join("2026-09-26T00:00:%02dZ INFO kin_daemon: step %d" % (i % 60, i)
                        for i in range(600))
        panic = ("thread 'main' panicked at crates/kin-db/src/store.rs:88:14:\n"
                 "called `Option::unwrap()` on a `None` value")
        text = log + "\n" + panic + "\n" + log
        got = self.excerpt(text)
        self.assertIn("panicked at crates/kin-db/src/store.rs:88:14:", got)
        self.assertIn("called `Option::unwrap()` on a `None` value", got)
        self.assertLessEqual(len(got), self.limit + 64)

    def test_the_last_error_is_kept_over_an_earlier_one(self):
        filler = "note: still working\n" * 400
        text = "error: first\n" + filler + "error: the final one\n" + filler
        got = self.excerpt(text)
        self.assertIn("error: the final one", got)

    def test_a_tracing_error_line_counts_as_an_error(self):
        filler = "2026-09-26T00:00:00Z  INFO kin: ok\n" * 400
        text = filler + "2026-09-26T00:00:01Z ERROR kin_daemon::sweep: store refused\n" + filler
        self.assertIn("ERROR kin_daemon::sweep: store refused", self.excerpt(text))

    def test_the_old_slices_are_still_inside_the_excerpt(self):
        text = "".join("line %05d of a long command output\n" % i for i in range(2000))
        got = self.excerpt(text)
        stripped = text.strip()
        self.assertIn(stripped[:600], got)
        self.assertIn(stripped[-600:], got)
        self.assertIn(stripped[-2000:], got)

    def test_the_limit_only_ever_raises_the_bound(self):
        text = "x" * 20000
        self.assertEqual(len(self.excerpt(text, 10)), len(self.excerpt(text)))
        wider = self.excerpt(text, 12000)
        self.assertGreater(len(wider), len(self.excerpt(text)))
        self.assertIn(text[-4000:], wider)

    def test_many_panics_stay_bounded(self):
        text = ("thread 'w' panicked at a.rs:1:1:\n" + "boom " * 200 + "\n") * 200
        self.assertLessEqual(len(self.excerpt(text)), self.limit + 64)

    def test_ansi_colour_does_not_hide_an_error_line(self):
        filler = "info\n" * 2000
        text = filler + "\x1b[31merror\x1b[0m: coloured refusal\n" + filler
        self.assertIn("coloured refusal", self.excerpt(text))


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]] + [a for a in sys.argv[1:] if a != "--self-test"])
