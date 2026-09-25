#!/usr/bin/env python3
"""Poison controls for exact dedicated-module replay guards, and for holding a
replay version to one meaning against the base branch's manifest."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("verify-hydration-semantics.py")


class GuardedFiles(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="kin-hydration-files-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.scripts = self.root / "scripts"
        self.scripts.mkdir()
        (self.scripts / SCRIPT.name).write_bytes(SCRIPT.read_bytes())
        self.history = self.root / "crates/kin-index/src/history.rs"
        self.history.parent.mkdir(parents=True)
        self.history.write_text("pub const HYDRATION_SEMANTICS_VERSION: u32 = 17;\nfn replay() {}\n")
        self.source = self.history.with_name("authority.rs")
        self.source.write_text("struct Authority;\nimpl Authority { fn resolve(&self) -> bool { true } }\n")
        self.manifest = {
            "hydration_semantics_version": 17,
            "guarded": [{"file": "crates/kin-index/src/history.rs", "function": "replay", "digest": "sha256:" + hashlib.sha256(b"fn replay() {}\n").hexdigest(), "reason": "fixture", "owner": "test"}],
            "guarded_files": [{"file": "crates/kin-index/src/authority.rs", "digest": "sha256:" + hashlib.sha256(self.source.read_bytes()).hexdigest(), "reason": "method body fixture", "owner": "test"}],
        }

    def check(self, *args):
        (self.scripts / "hydration-semantics-manifest.json").write_text(json.dumps(self.manifest))
        return subprocess.run([sys.executable, str(self.scripts / SCRIPT.name), *args], text=True, capture_output=True, timeout=10)

    def test_exact_bytes_and_legacy_function_only_manifest_pass(self):
        self.assertEqual(self.check().returncode, 0)
        del self.manifest["guarded_files"]
        self.assertEqual(self.check().returncode, 0)

    def test_method_semantic_drift_is_rejected_then_explicit_refresh_records_it(self):
        self.source.write_text(self.source.read_text().replace("true", "false"))
        result = self.check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("guarded source file", result.stdout + result.stderr)
        self.assertEqual(self.check("--write").returncode, 0)
        # Run against the exact manifest that --write explicitly recorded.
        result = subprocess.run([sys.executable, str(self.scripts / SCRIPT.name)], text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_missing_file_refuses_both_check_and_refresh(self):
        self.source.unlink()
        for args in [(), ("--write",)]:
            result = self.check(*args)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("cannot read guarded file", result.stdout + result.stderr)

    def test_duplicate_malformed_and_escaping_paths_refuse(self):
        original = dict(self.manifest["guarded_files"][0])
        for entries in [[original, dict(original)], [dict(original, file="../authority.rs")], [dict(original, file="/tmp/authority.rs")], [dict(original, file="crates//authority.rs")], [dict(original, digest="not-a-digest")], [dict(original, owner="")], [None], "not-an-array"]:
            with self.subTest(entries=entries):
                self.manifest["guarded_files"] = entries
                result = self.check()
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("Traceback", result.stdout + result.stderr)

    def test_symlink_outside_selected_repository_refuses(self):
        with tempfile.TemporaryDirectory(prefix="kin-outside-guard-") as outside:
            source = Path(outside) / "source.rs"
            source.write_bytes(self.source.read_bytes())
            self.source.unlink()
            self.source.symlink_to(source)
            result = self.check()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("resolves outside repository", result.stdout + result.stderr)


class BaseEpoch(unittest.TestCase):
    """A version number names one replay, checked against the base's manifest.

    Two changes cut from one base can each move the replay surface and each
    claim the next number. Each passes the plain guard, and so does a merge
    that keeps both, so the comparison with the base is what refuses it.
    """

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="kin-hydration-epoch-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.scripts = self.root / "scripts"
        self.scripts.mkdir()
        (self.scripts / SCRIPT.name).write_bytes(SCRIPT.read_bytes())
        self.history = self.root / "crates/kin-index/src/history.rs"
        self.history.parent.mkdir(parents=True)
        self.manifest_path = self.scripts / "hydration-semantics-manifest.json"
        self.write_tree(version=17, replay="true", fold="true")
        self.manifest = {
            "hydration_semantics_version": 17,
            "guarded": [
                {"file": "crates/kin-index/src/history.rs", "function": "replay", "digest": "", "reason": "fixture", "owner": "test"},
                {"file": "crates/kin-index/src/history.rs", "function": "fold", "digest": "", "reason": "fixture", "owner": "test"},
            ],
        }
        self.record()
        self.base = self.root / "base-manifest.json"
        self.base.write_text(self.manifest_path.read_text())

    def write_tree(self, version, replay, fold):
        self.history.write_text(
            f"pub const HYDRATION_SEMANTICS_VERSION: u32 = {version};\n"
            f"fn replay() -> bool {{ {replay} }}\n"
            f"fn fold() -> bool {{ {fold} }}\n"
        )

    def record(self):
        """What an author does after deciding: rewrite the digests from the tree."""
        self.manifest_path.write_text(json.dumps(self.manifest))
        result = self.run_guard("--write")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.manifest = json.loads(self.manifest_path.read_text())

    def run_guard(self, *args):
        return subprocess.run([sys.executable, str(self.scripts / SCRIPT.name), *args], text=True, capture_output=True, timeout=30)

    def against_base(self):
        self.manifest_path.write_text(json.dumps(self.manifest))
        return self.run_guard("--base-manifest", str(self.base))

    def test_an_unchanged_surface_at_the_base_version_passes(self):
        result = self.against_base()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_a_changed_surface_needs_a_version_above_the_base(self):
        self.write_tree(version=17, replay="false", fold="true")
        self.record()
        self.assertEqual(self.run_guard().returncode, 0, "the plain guard cannot see the collision")
        result = self.against_base()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("stays at 17", result.stdout)
        self.assertIn("`replay`", result.stdout)
        self.assertNotIn("`fold`", result.stdout)

        self.write_tree(version=18, replay="false", fold="true")
        self.record()
        result = self.against_base()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_a_merge_that_keeps_both_changes_under_one_number_is_refused(self):
        # The base took 18 for a change to `replay`. A second change, cut from
        # 17, moved `fold` and also claimed 18; the merge kept both.
        self.write_tree(version=18, replay="false", fold="true")
        self.record()
        self.base.write_text(self.manifest_path.read_text())
        self.write_tree(version=18, replay="false", fold="false")
        self.record()
        self.assertEqual(self.run_guard().returncode, 0, "the plain guard cannot see the collision")
        result = self.against_base()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("`fold`", result.stdout)
        self.write_tree(version=19, replay="false", fold="false")
        self.record()
        self.assertEqual(self.against_base().returncode, 0)

    def test_a_version_below_the_base_is_refused(self):
        self.write_tree(version=16, replay="true", fold="true")
        self.record()
        result = self.against_base()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("below the 17", result.stdout)

    def test_a_same_epoch_entry_excuses_only_the_digest_it_names(self):
        self.write_tree(version=17, replay=" true ", fold="true")
        self.record()
        replay_digest = next(e["digest"] for e in self.manifest["guarded"] if e["function"] == "replay")
        self.manifest["same_epoch_changes"] = [
            {"file": "crates/kin-index/src/history.rs", "function": "replay", "digest": replay_digest, "reason": "whitespace only"},
        ]
        result = self.against_base()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

        # A later edit to the same function at the same number is not excused by
        # the earlier entry, and rewriting the digests drops the stale entry.
        self.write_tree(version=17, replay="false", fold="true")
        self.record()
        self.assertEqual(self.manifest["same_epoch_changes"], [])
        result = self.against_base()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("`replay`", result.stdout)

    def test_a_removed_pin_needs_a_version_or_an_entry(self):
        self.manifest["guarded"] = [e for e in self.manifest["guarded"] if e["function"] != "fold"]
        result = self.against_base()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("`fold`", result.stdout)
        self.manifest["same_epoch_changes"] = [
            {"file": "crates/kin-index/src/history.rs", "function": "fold", "digest": "removed", "reason": "fold is replay's own helper now"},
        ]
        self.assertEqual(self.against_base().returncode, 0)

    def test_malformed_same_epoch_entries_refuse(self):
        for entries in ["not-an-array", [None], [{"file": "x", "digest": "sha256:0"}], [{"file": "x", "digest": "d", "reason": "r", "function": ""}]]:
            with self.subTest(entries=entries):
                self.manifest["same_epoch_changes"] = entries
                for result in (self.against_base(), self.run_guard()):
                    self.assertNotEqual(result.returncode, 0)
                    self.assertNotIn("Traceback", result.stdout + result.stderr)

    def test_a_git_base_reads_the_manifest_beside_this_script(self):
        def git(*args):
            # A developer's own hooks and identity are not this fixture's.
            return subprocess.run(["git", "-C", str(self.root), "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", "-c", "user.name=guard", "-c", "user.email=guard@example.invalid", *args], text=True, capture_output=True, timeout=30)

        self.assertEqual(git("init", "-q").returncode, 0)
        self.assertEqual(git("add", "crates").returncode, 0)
        self.assertEqual(git("commit", "-qm", "before the manifest").returncode, 0)
        before = git("rev-parse", "HEAD").stdout.strip()
        self.assertEqual(git("add", "scripts").returncode, 0)
        self.assertEqual(git("commit", "-qm", "manifest at 17").returncode, 0)

        self.write_tree(version=17, replay="false", fold="true")
        self.record()
        result = self.run_guard("--base-ref", "HEAD")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("stays at 17", result.stdout)

        result = self.run_guard("--base-ref", before)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("has no manifest", result.stdout)

        result = self.run_guard("--base-ref", "no-such-ref")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not name a commit", result.stdout)

    def test_arguments_are_refused_rather_than_read_as_the_root(self):
        for args in (("--base-ref",), ("--base-manifest", "a", "--base-ref", "b"), ("--write", "--base-ref", "HEAD"), ("--bogus",), (".", "extra")):
            with self.subTest(args=args):
                result = self.run_guard(*args)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("Traceback", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
