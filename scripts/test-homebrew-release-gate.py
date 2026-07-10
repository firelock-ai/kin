#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

"""Deterministic tests for the mandatory public Homebrew release gate."""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path


SCRIPTS_DIR = Path(__file__).resolve().parent
ROOT = SCRIPTS_DIR.parent
VERIFIER = SCRIPTS_DIR / "verify-homebrew-formula.sh"
WORKFLOW = ROOT / ".github/workflows/release.yml"


FAKE_CURL = r"""#!/usr/bin/env python3
import os
import pathlib
import sys

state_path = pathlib.Path(os.environ["FAKE_CURL_STATE"])
try:
    attempt = int(state_path.read_text(encoding="utf-8")) + 1
except FileNotFoundError:
    attempt = 1
state_path.write_text(str(attempt), encoding="utf-8")

args_path = pathlib.Path(os.environ["FAKE_CURL_ARGS"])
with args_path.open("a", encoding="utf-8") as handle:
    handle.write(" ".join(sys.argv[1:]) + "\n")

success_after = int(os.environ.get("FAKE_CURL_SUCCESS_AFTER", "1"))
if attempt >= success_after:
    print(f'version "{os.environ["EXPECTED_FORMULA_VERSION"]}"')
else:
    print('version "0.0.0"')
"""


def verifier_env(fake_bin: Path, state: Path, args: Path, *, success_after: int) -> dict[str, str]:
    env = os.environ.copy()
    env.pop("KIN_CI_BOT_TOKEN", None)
    env.update(
        {
            "PATH": f"{fake_bin}{os.pathsep}{env['PATH']}",
            "FAKE_CURL_STATE": str(state),
            "FAKE_CURL_ARGS": str(args),
            "FAKE_CURL_SUCCESS_AFTER": str(success_after),
            "EXPECTED_FORMULA_VERSION": "1.2.3",
            "KIN_HOMEBREW_VERIFY_MAX_WAIT_SECONDS": "10",
            "KIN_HOMEBREW_VERIFY_MAX_ATTEMPTS": "3",
            "KIN_HOMEBREW_VERIFY_POLL_SECONDS": "0",
            "KIN_HOMEBREW_VERIFY_CURL_MAX_SECONDS": "1",
        }
    )
    return env


def run_verifier(*, success_after: int) -> tuple[subprocess.CompletedProcess[str], str, int]:
    with tempfile.TemporaryDirectory() as directory:
        temp = Path(directory)
        fake_bin = temp / "bin"
        fake_bin.mkdir()
        fake_curl = fake_bin / "curl"
        fake_curl.write_text(FAKE_CURL, encoding="utf-8")
        fake_curl.chmod(0o755)
        state = temp / "state"
        args = temp / "args"
        result = subprocess.run(
            ["bash", str(VERIFIER), "v1.2.3"],
            check=False,
            capture_output=True,
            text=True,
            env=verifier_env(fake_bin, state, args, success_after=success_after),
        )
        curl_args = args.read_text(encoding="utf-8")
        attempts = int(state.read_text(encoding="utf-8"))
    return result, curl_args, attempts


def test_missing_token_independence() -> None:
    result, curl_args, attempts = run_verifier(success_after=1)
    assert result.returncode == 0, result.stderr
    assert attempts == 1
    assert "raw.githubusercontent.com/firelock-ai/homebrew-kin" in curl_args
    assert "Authorization" not in curl_args


def test_poll_then_success() -> None:
    result, _, attempts = run_verifier(success_after=2)
    assert result.returncode == 0, result.stderr
    assert attempts == 2
    assert "attempt 1/3" in result.stdout


def test_bounded_failure() -> None:
    result, _, attempts = run_verifier(success_after=99)
    assert result.returncode == 1
    assert attempts == 3
    assert "did not report version" in result.stderr
    assert "after 3 checks" in result.stderr


def test_dispatch_result_cannot_skip_verification() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    marker = "      - name: Verify the tap formula actually bumped to this version\n"
    start = workflow.index(marker)
    next_step = workflow.find("\n      - name:", start + len(marker))
    verification_step = workflow[start : next_step if next_step != -1 else None]

    assert "startsWith(github.ref, 'refs/tags/v')" in verification_step
    assert 'bash scripts/verify-homebrew-formula.sh "$GITHUB_REF_NAME"' in verification_step
    assert "steps.dispatch.outputs" not in verification_step
    assert "TAP_DISPATCH_TOKEN" not in verification_step


def main() -> None:
    tests = (
        test_missing_token_independence,
        test_poll_then_success,
        test_bounded_failure,
        test_dispatch_result_cannot_skip_verification,
    )
    for test in tests:
        test()
        print(f"PASS: {test.__name__}")
    print(f"{len(tests)} Homebrew release gate tests passed")


if __name__ == "__main__":
    main()
