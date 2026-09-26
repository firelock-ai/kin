#!/usr/bin/env python3
"""Falsify the exact boundary pins added for current storage/session helpers.

These use the production scanner and policy loader against copied source, never
mutate the checkout, and require a reported primitive rather than just a red
policy exit. The full-repository and shell guards remain separate checks.
"""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
FILES = (
    "crates/kin-db/src/storage/backend.rs",
    "crates/kin-db/src/storage/binding_history.rs",
    "crates/kin-db/src/storage/binding_history_tests.rs",
    "crates/kin-db/src/storage/repository.rs",
    "crates/kin-db/src/storage/change_map.rs",
    "crates/kin-db/src/storage/repository/session_publication.rs",
    "crates/kin-db/src/storage/repository/session_publication_tests.rs",
    "crates/kin-db/src/storage/backend/session_publication.rs",
    "crates/kin-index/src/binding_history.rs",
    "crates/kin-mcp/tests_support/clause_codes.rs",
    "crates/kin-cli/src/daemon_client/process_executable/linux.rs",
    "crates/kin-daemon/src/binding_history.rs",
    "crates/kin-daemon/src/daemon.rs",
    "crates/kin-daemon/src/loop_runner.rs",
    "crates/kin-daemon/src/prepared_publication.rs",
    "crates/kin-daemon/src/supervisor.rs",
    "crates/kin-search/src/mapped.rs",
    "crates/kin-db/src/embed/model_identity.rs",
    "crates/kin-lsp/src/lifecycle.rs",
    "crates/kin-lsp/src/server_process.rs",
    "crates/kin-daemon/src/mcp_mutate.rs",
    "crates/kin-lsp/src/protocol.rs",
    "crates/kin-cli/src/commands/upgrade.rs",
    "crates/kin-daemon/src/repository_commit.rs",
    "crates/kin-agent/src/tests.rs",
    "crates/kin-daemon/src/mcp_source_base.rs",
    "crates/kin-daemon/src/unit_lifecycle.rs",
)
UNPINNED_FILES = ("crates/kin-agent/src/belt.rs",)
FUNCTIONS = (
    (FILES[0], "acquire_existing_lock_with_policy"),
    (FILES[4], "read_record_or_failure"),
    (FILES[7], "read_session_file"),
    (FILES[7], "session_file_links"),
    (FILES[9], "rust_files"),
    (FILES[9], "scanned_labels"),
    (FILES[10], "observe"),
    (FILES[10], "observe_opened_image"),
    (FILES[13], "host_entry_matches_entry"),
    (FILES[13], "revalidate_proposed_root_rule"),
    (FILES[13], "record_catch_up_arrivals"),
    (FILES[15], "acquire_supervisor_lifecycle_guard_until"),
    (FILES[15], "write_supervisor_endpoint_files_under_authority"),
    (FILES[16], "probe_image"),
    (FILES[22], "rewrite_upgrade_sidecar"),
)
POISON = (
    '\nfn __boundary_pin_probe(p: &str) -> String { '
    'std::fs::read_to_string(p).unwrap() }\n'
)


class BoundaryPins(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location(
            "zero_file_guard", ROOT / "scripts/verify-zero-file-search.py"
        )
        cls.guard = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.guard)
        policy = json.loads((ROOT / "scripts/zero-file-search-allowlist.json").read_text())
        cls.declared_files = {entry["file"] for entry in policy["allowlist"]}
        cls.entries = [entry for entry in policy["allowlist"] if entry["file"] in FILES]
        assert {entry["file"] for entry in cls.entries} == set(FILES)
        cls.originals = {file: (ROOT / file).read_text() for file in FILES + UNPINNED_FILES}

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="kin-boundary-pins-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        for file, source in self.originals.items():
            path = self.root / file
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source)
        policy = self.root / "policy.json"
        policy.write_text(json.dumps({"allowlist": self.entries}))
        self.guard.KIN_ROOT = str(self.root)
        self.guard.ALLOWLIST_PATH = str(policy)

    def policies(self):
        return self.guard.load_allowlist()

    def scan(self, file, policy):
        self.assertFalse(policy.whole_file, file)
        return self.guard.scan_file(
            str(self.root / file), file, policy.fns, policy.matches
        )

    def assert_read_reported(self, file, policy):
        violations = self.scan(file, policy)
        self.assertTrue(
            any("std::fs::read_to_string" in content for _, content, _ in violations),
            (file, violations),
        )

    def test_exact_current_boundaries_are_clean_and_never_whole_file(self):
        policies, errors = self.policies()
        self.assertEqual(errors, [])
        for file in FILES:
            with self.subTest(file=file):
                self.assertEqual(self.scan(file, policies[file]), [])

    def test_every_affected_file_still_reports_an_unapproved_read(self):
        for file in FILES:
            with self.subTest(file=file):
                path = self.root / file
                path.write_text(self.originals[file] + POISON)
                policies, errors = self.policies()
                self.assertEqual(errors, [])
                self.assert_read_reported(file, policies[file])
                path.write_text(self.originals[file])

    def test_each_new_function_scope_stops_at_its_closing_brace(self):
        for file, function in FUNCTIONS:
            lines = self.originals[file].splitlines(keepends=True)
            spans = self.guard.find_fn_body_ranges(lines)[function]
            for _, last in spans:
                with self.subTest(file=file, function=function, after=last + 1):
                    path = self.root / file
                    path.write_text("".join(lines[: last + 1]) + POISON + "".join(lines[last + 1 :]))
                    policies, errors = self.policies()
                    self.assertEqual(errors, [])
                    self.assert_read_reported(file, policies[file])
                    path.write_text(self.originals[file])

    def test_retired_file_belt_has_no_exemption_and_rejects_reads(self):
        policies, errors = self.policies()
        self.assertEqual(errors, [])
        for file in UNPINNED_FILES:
            with self.subTest(file=file):
                self.assertNotIn(file, self.declared_files)
                self.assertNotIn(file, policies)
                policy = self.guard.Policy()
                self.assertEqual(self.scan(file, policy), [])
                (self.root / file).write_text(self.originals[file] + POISON)
                self.assert_read_reported(file, policy)

    def test_second_primitive_beside_process_pins_is_reported(self):
        for file, old, new in (
            (
                FILES[21],
                "process_id: Some(std::process::id()),",
                'process_id: { let _ = std::fs::read_to_string("unapproved"); '
                'Some(std::process::id()) },',
            ),
            (
                FILES[24],
                "let mut child = std::process::Command::new(std::env::current_exe().unwrap());",
                'let _ = std::fs::read_to_string("unapproved"); '
                "let mut child = std::process::Command::new(std::env::current_exe().unwrap());",
            ),
        ):
            with self.subTest(file=file):
                self.assertEqual(self.originals[file].count(old), 1)
                path = self.root / file
                path.write_text(self.originals[file].replace(old, new))
                policies, errors = self.policies()
                self.assertEqual(errors, [])
                self.assert_read_reported(file, policies[file])
                path.write_text(self.originals[file])

    def test_extra_repository_metadata_occurrence_invalidates_pin(self):
        poison = "\nfn __extra_metadata(p: &std::path::Path) { let _ = p.metadata(); }\n"
        for file in (FILES[23], FILES[25], FILES[26]):
            with self.subTest(file=file):
                entry = next(entry for entry in self.entries if entry["file"] == file)
                pins = [pin for pin in entry["allow_match"]
                        if isinstance(pin, dict) and pin["expr"] == ".metadata()"]
                self.assertEqual(len(pins), 1)
                expected = pins[0]["count"]
                path = self.root / file
                path.write_text(self.originals[file] + poison)
                policies, errors = self.policies()
                mismatch = f"occurs {expected + 1} times in scanned code (want {expected})"
                self.assertTrue(any(file in error and mismatch in error for error in errors), errors)
                violations = self.scan(file, policies[file])
                self.assertTrue(any("p.metadata()" in content for _, content, _ in violations), violations)
                path.write_text(self.originals[file])

    def test_second_primitive_on_an_allowed_metadata_line_is_reported(self):
        file = "crates/kin-db/src/storage/binding_history.rs"
        old = "if self.successor.metadata().schema_version < BINDING_HISTORY_AUTHORITY_SCHEMA {"
        new = 'let _ = std::fs::read_to_string("unapproved"); ' + old
        self.assertEqual(self.originals[file].count(old), 1)
        (self.root / file).write_text(self.originals[file].replace(old, new))
        policies, errors = self.policies()
        self.assertEqual(errors, [])
        self.assert_read_reported(file, policies[file])

    def test_extra_metadata_occurrence_invalidates_pin_and_remains_visible(self):
        file = "crates/kin-daemon/src/binding_history.rs"
        poison = "\nfn __extra_metadata(p: &std::path::Path) { let _ = p.metadata(); }\n"
        (self.root / file).write_text(self.originals[file] + poison)
        policies, errors = self.policies()
        self.assertTrue(any(file in error and "occurs 2" in error for error in errors), errors)
        violations = self.scan(file, policies[file])
        self.assertTrue(any("p.metadata()" in content for _, content, _ in violations), violations)


if __name__ == "__main__":
    unittest.main(verbosity=2)
