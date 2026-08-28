#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

"""Falsify the source and released-byte daemon compatibility guards."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from types import ModuleType
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
VALIDATOR = ROOT / "scripts" / "verify-daemon-compat-json.py"
CONTAINER_GUARD = ROOT / "scripts" / "verify-container-build-info.sh"
DAEMON_SOURCE = ROOT / "crates" / "kin-daemon" / "src" / "bin" / "kin-daemon.rs"
CLI_SOURCE = ROOT / "crates" / "kin-cli" / "src" / "daemon_client.rs"


def load_validator() -> ModuleType:
    spec = importlib.util.spec_from_file_location("daemon_compat_validator", VALIDATOR)
    if spec is None or spec.loader is None:
        raise AssertionError(f"could not load {VALIDATOR}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def valid_payload() -> dict[str, Any]:
    lock_digest = hashlib.sha256((ROOT / "Cargo.lock").read_bytes()).hexdigest()
    return {
        "schema": "kin.daemon.compat.v2",
        "version": "0.0.0-test",
        "graph_snapshot_version": 8,
        "graph_snapshot_min_supported_version": 6,
        "graph_snapshot_max_supported_version": 8,
        "gcs_full_authority_envelope_min_supported_version": 4,
        "gcs_full_authority_envelope_max_supported_version": 5,
        "build": {
            "sha": "a" * 40,
            "dirty": False,
            "source_known": True,
            "dependency_provenance": lock_digest,
        },
    }


def expect_rejected(validator: ModuleType, payload: dict[str, Any], label: str) -> None:
    try:
        validator.validate(payload)
    except ValueError:
        return
    raise AssertionError(f"validator accepted {label}")


def assert_source_bindings(daemon_source: str, cli_source: str) -> None:
    daemon_start = daemon_source.index("if args.compat_json {")
    daemon_end = daemon_source.index("        return 0;", daemon_start)
    daemon_block = daemon_source[daemon_start:daemon_end]
    daemon_block = re.sub(r"/\*.*?\*/", "", daemon_block, flags=re.DOTALL)
    daemon_block = re.sub(r"(?m)//.*$", "", daemon_block)

    validator_start = cli_source.index("fn validate_daemon_compat_response(")
    validator_end = cli_source.index("\nfn validate_daemon_binary(", validator_start)
    validator_block = cli_source[validator_start:validator_end]
    validator_block = re.sub(r"/\*.*?\*/", "", validator_block, flags=re.DOTALL)
    validator_block = re.sub(r"(?m)//.*$", "", validator_block)

    daemon_bindings = (
        (
            "graph_snapshot_version",
            r'"graph_snapshot_version"\s*:\s*kin_db::GraphSnapshot::CURRENT_VERSION',
        ),
        (
            "graph_snapshot_min_supported_version",
            r'"graph_snapshot_min_supported_version"\s*:\s*kin_db::GraphSnapshot::MIN_SUPPORTED_VERSION',
        ),
        (
            "graph_snapshot_max_supported_version",
            r'"graph_snapshot_max_supported_version"\s*:\s*kin_db::GraphSnapshot::CURRENT_VERSION',
        ),
        (
            "gcs_full_authority_envelope_min_supported_version",
            r'"gcs_full_authority_envelope_min_supported_version"\s*:\s*kin_db::GCS_FULL_AUTHORITY_ENVELOPE_COMPATIBILITY\.min_supported_version',
        ),
        (
            "gcs_full_authority_envelope_max_supported_version",
            r'"gcs_full_authority_envelope_max_supported_version"\s*:\s*kin_db::GCS_FULL_AUTHORITY_ENVELOPE_COMPATIBILITY\.current_version',
        ),
    )
    cli_bindings = (
        r"let\s+expected_graph_min\s*=\s*kin_db::GraphSnapshot::MIN_SUPPORTED_VERSION\s*;",
        r"let\s+expected_graph_max\s*=\s*kin_db::GraphSnapshot::CURRENT_VERSION\s*;",
        r"compat\.graph_snapshot_min_supported_version\s*!=\s*expected_graph_min",
        r"compat\.graph_snapshot_max_supported_version\s*!=\s*expected_graph_max",
        r"compat\.graph_snapshot_version\s*!=\s*expected_graph_max",
        r"let\s+expected_envelope\s*=\s*kin_db::GCS_FULL_AUTHORITY_ENVELOPE_COMPATIBILITY\s*;",
        r"compat\.gcs_full_authority_envelope_min_supported_version\s*!=\s*expected_envelope\.min_supported_version",
        r"compat\.gcs_full_authority_envelope_max_supported_version\s*!=\s*expected_envelope\.current_version",
    )
    for field, binding in daemon_bindings:
        if len(re.findall(rf'"{re.escape(field)}"\s*:', daemon_block)) != 1:
            raise AssertionError(
                f"daemon compatibility key must occur exactly once: {field}"
            )
        if len(re.findall(binding, daemon_block)) != 1:
            raise AssertionError(f"daemon compatibility field is not KinDB-bound: {binding}")
    for binding in cli_bindings:
        if len(re.findall(binding, validator_block)) != 1:
            raise AssertionError(f"CLI compatibility check is not KinDB-bound: {binding}")


def run_container_guard(payload: dict[str, Any]) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory(prefix="kin-compat-guard-") as temp_dir:
        fake_docker = Path(temp_dir) / "docker"
        fake_docker.write_text(
            "#!/usr/bin/env python3\n"
            "import os\n"
            "print(os.environ['KIN_TEST_COMPAT_PAYLOAD'])\n",
            encoding="utf-8",
        )
        fake_docker.chmod(0o755)
        env = os.environ.copy()
        env["PATH"] = f"{temp_dir}:{env['PATH']}"
        env["KIN_TEST_COMPAT_PAYLOAD"] = json.dumps(payload, separators=(",", ":"))
        return subprocess.run(
            ["bash", str(CONTAINER_GUARD), "kin:test", "a" * 40],
            cwd=ROOT,
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )


def main() -> int:
    validator = load_validator()
    good = valid_payload()
    validator.validate(good)

    missing_minimum = copy.deepcopy(good)
    del missing_minimum["graph_snapshot_min_supported_version"]
    expect_rejected(validator, missing_minimum, "a missing graph minimum")

    writer_above_maximum = copy.deepcopy(good)
    writer_above_maximum["graph_snapshot_version"] = 9
    expect_rejected(validator, writer_above_maximum, "a writer above the graph maximum")

    maximum_above_writer = copy.deepcopy(good)
    maximum_above_writer["graph_snapshot_max_supported_version"] = 9
    expect_rejected(validator, maximum_above_writer, "a graph maximum above the writer")

    envelope_inversion = copy.deepcopy(good)
    envelope_inversion["gcs_full_authority_envelope_min_supported_version"] = 6
    expect_rejected(validator, envelope_inversion, "an inverted envelope range")

    boolean_version = copy.deepcopy(good)
    boolean_version["graph_snapshot_min_supported_version"] = True
    expect_rejected(validator, boolean_version, "a boolean version")

    daemon_source = DAEMON_SOURCE.read_text(encoding="utf-8")
    cli_source = CLI_SOURCE.read_text(encoding="utf-8")
    assert_source_bindings(daemon_source, cli_source)

    copied_minimum_pattern = (
        r'("graph_snapshot_min_supported_version"\s*:)\s*'
        r'kin_db::GraphSnapshot::MIN_SUPPORTED_VERSION'
    )
    copied_constant, replacements = re.subn(
        copied_minimum_pattern,
        r'\1 1',
        daemon_source,
        count=1,
    )
    if replacements != 1:
        raise AssertionError("could not construct the copied-constant falsifier")
    comment_decoy = copied_constant.replace(
        "if args.compat_json {",
        "if args.compat_json {\n"
        "        // \"graph_snapshot_min_supported_version\": "
        "kin_db::GraphSnapshot::MIN_SUPPORTED_VERSION,",
        1,
    )
    try:
        assert_source_bindings(comment_decoy, cli_source)
    except AssertionError:
        pass
    else:
        raise AssertionError("source guard accepted a copied graph minimum")

    duplicate_key = daemon_source.replace(
        '"graph_snapshot_version": kin_db::GraphSnapshot::CURRENT_VERSION,',
        '"graph_snapshot_version": kin_db::GraphSnapshot::CURRENT_VERSION,\n'
        '                "graph_snapshot_version": 13,',
        1,
    )
    try:
        assert_source_bindings(duplicate_key, cli_source)
    except AssertionError:
        pass
    else:
        raise AssertionError("source guard accepted an overriding duplicate JSON key")

    copied_comparison, replacements = re.subn(
        r"compat\.graph_snapshot_min_supported_version\s*!=\s*expected_graph_min",
        "compat.graph_snapshot_min_supported_version != 13",
        cli_source,
        count=1,
    )
    if replacements != 1:
        raise AssertionError("could not construct the copied-comparison falsifier")
    try:
        assert_source_bindings(daemon_source, copied_comparison)
    except AssertionError:
        pass
    else:
        raise AssertionError("source guard accepted a copied CLI comparison")

    accepted = run_container_guard(good)
    if accepted.returncode != 0:
        raise AssertionError(
            "released-byte guard rejected the valid fixture:\n"
            f"stdout:\n{accepted.stdout}\nstderr:\n{accepted.stderr}"
        )
    rejected = run_container_guard(missing_minimum)
    if rejected.returncode == 0:
        raise AssertionError("released-byte guard accepted a missing graph minimum")

    print("daemon compatibility contract guard: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
