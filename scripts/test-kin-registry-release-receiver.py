#!/usr/bin/env python3
"""Deterministic contract tests for the Kin registry-release receiver."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR_PATH = ROOT / "scripts" / "validate-kin-registry-release.py"
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "kin-registry-release.yml"
KIN_ACTIONS_SHA = "398595fa14ba1eaebca6eb176facd8a57ce9db05"
SOURCE_SHA = "f1ac2bd93f0e3b7162f01481822087151e3b3af4"

spec = importlib.util.spec_from_file_location("kin_registry_receiver", VALIDATOR_PATH)
if spec is None or spec.loader is None:
    raise RuntimeError("could not load Kin registry receiver validator")
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)


def valid_payload(
    *, crate: str = "kin-db", source: str = "firelock-ai/kin-db"
) -> dict[str, str]:
    version = "0.7.69"
    return {
        "crate_name": crate,
        "crate_version": version,
        "delivery_id": f"{source}@{SOURCE_SHA}:{crate}@{version}",
        "source_repo": source,
        "source_sha": SOURCE_SHA,
    }


def valid_context(**overrides: str) -> dict[str, str]:
    context = {
        "event_name": "repository_dispatch",
        "event_action": "kin-registry-release",
        "actor": "troyjr4103",
        "repository": "firelock-ai/kin",
        "default_branch": "main",
        "ref": "refs/heads/main",
        "workflow_sha": "a" * 40,
    }
    context.update(overrides)
    return context


class ValidatorTests(unittest.TestCase):
    def test_accepts_exact_kindb_release_contract(self) -> None:
        validator.validate_context(**valid_context())
        self.assertEqual(
            validator.validate_payload(valid_payload())["crate_version"], "0.7.69"
        )

    def test_accepts_every_allowed_root_manifest_source_pair(self) -> None:
        for crate, source in validator.ALLOWED_SOURCES.items():
            with self.subTest(crate=crate):
                self.assertEqual(
                    validator.validate_payload(
                        valid_payload(crate=crate, source=source)
                    )["source_repo"],
                    source,
                )

    def test_allowed_crates_are_exactly_the_root_registry_boundary(self) -> None:
        with (ROOT / "Cargo.toml").open("rb") as stream:
            dependencies = tomllib.load(stream)["workspace"]["dependencies"]
        root_registry_dependencies = {
            name
            for name, value in dependencies.items()
            if isinstance(value, dict) and value.get("registry") == "kin"
        }
        self.assertEqual(set(validator.ALLOWED_SOURCES), root_registry_dependencies)

    def test_rejects_wrong_event_action(self) -> None:
        with self.assertRaisesRegex(validator.ValidationError, "event action"):
            validator.validate_context(**valid_context(event_action="dependency-updated"))

    def test_rejects_missing_delivery_id(self) -> None:
        payload = valid_payload()
        del payload["delivery_id"]
        with self.assertRaisesRegex(validator.ValidationError, "missing=.*delivery_id"):
            validator.validate_payload(payload)

    def test_rejects_malformed_version(self) -> None:
        payload = valid_payload()
        payload["crate_version"] = "0.7"
        payload["delivery_id"] = (
            f"{payload['source_repo']}@{payload['source_sha']}:"
            f"{payload['crate_name']}@{payload['crate_version']}"
        )
        with self.assertRaisesRegex(validator.ValidationError, "stable SemVer"):
            validator.validate_payload(payload)

    def test_rejects_package_outside_boundary(self) -> None:
        payload = valid_payload(crate="serde", source="serde-rs/serde")
        with self.assertRaisesRegex(validator.ValidationError, "outside Kin's"):
            validator.validate_payload(payload)

    def test_rejects_source_repo_mismatch(self) -> None:
        payload = valid_payload(source="firelock-ai/kin-model")
        with self.assertRaisesRegex(validator.ValidationError, "must come from"):
            validator.validate_payload(payload)

    def test_rejects_unbound_delivery_id(self) -> None:
        payload = valid_payload()
        payload["delivery_id"] = "not-the-source-tuple"
        with self.assertRaisesRegex(validator.ValidationError, "does not bind"):
            validator.validate_payload(payload)

    def test_cli_fails_loud_on_malformed_payload(self) -> None:
        payload = valid_payload()
        del payload["source_sha"]
        result = self.run_cli(payload)
        self.assertEqual(result.returncode, 1)
        self.assertIn("::error title=Invalid Kin registry release::", result.stderr)

    def test_cli_accepts_valid_payload(self) -> None:
        result = self.run_cli(valid_payload())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("validated Kin registry release kin-db@0.7.69", result.stdout)

    def run_cli(self, payload: dict[str, str]) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            event_path = Path(directory) / "event.json"
            event_path.write_text(
                json.dumps(
                    {"action": "kin-registry-release", "client_payload": payload}
                ),
                encoding="utf-8",
            )
            command = [
                "python3",
                str(VALIDATOR_PATH),
                "--event-file",
                str(event_path),
            ]
            for key, value in valid_context().items():
                command.extend([f"--{key.replace('_', '-')}", value])
            return subprocess.run(
                command,
                cwd=ROOT,
                env=os.environ.copy(),
                text=True,
                capture_output=True,
                check=False,
            )


class WorkflowContractTests(unittest.TestCase):
    def test_receiver_trigger_and_write_boundary_are_pinned(self) -> None:
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        self.assertIn("types: [kin-registry-release]", workflow)
        self.assertNotIn("workflow_dispatch:", workflow)
        self.assertNotIn("schedule:", workflow)
        self.assertIn("group: kin-registry-release-${{ github.repository }}", workflow)
        self.assertIn("cancel-in-progress: false", workflow)
        self.assertIn("needs: validate-dispatch", workflow)
        self.assertIn("environment: release-tag", workflow)
        self.assertIn(
            f"KIN_ACTIONS_SHA: {KIN_ACTIONS_SHA}",
            workflow,
        )
        self.assertIn("repository: firelock-ai/kin-actions", workflow)
        self.assertIn(
            "WAVE_BRANCH: automation/kin-registry-dependency-wave",
            workflow,
        )
        self.assertIn("--bump-own-version false", workflow)
        for crate in validator.ALLOWED_SOURCES:
            self.assertIn(f"--crate {crate}", workflow)
        self.assertEqual(workflow.count("--crate "), len(validator.ALLOWED_SOURCES) + 1)
        self.assertIn("Open or update the dependency bump PR", workflow)
        self.assertIn("base: ${{ github.event.repository.default_branch }}", workflow)
        self.assertIn("Verify exact first-party generated PR", workflow)
        self.assertNotIn("gh pr merge", workflow)
        self.assertNotIn("KIN_DOWNSTREAM_DISPATCH_TOKEN", workflow)


if __name__ == "__main__":
    unittest.main()
