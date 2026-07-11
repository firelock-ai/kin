#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

"""Behavioral failure-injection tests for two-package npm promotion rollback."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parent
PROMOTER = SCRIPTS / "promote-npm-release.sh"
PACKAGES = ("@kinlab/kin", "@kinlab/kin-mcp")
OLD = "0.2.15"
NEW = "0.2.16"
CANDIDATE = f"release-candidate-{NEW.replace('.', '-')}"


FAKE_NODE = r"""#!/usr/bin/env python3
import json, os, pathlib, sys
state_path = pathlib.Path(os.environ["FAKE_NPM_STATE"])
state = json.loads(state_path.read_text())
args = sys.argv[1:]
if not args or not args[0].endswith("release-order.mjs"):
    raise SystemExit(90)
command = args[1]
if command == "channel":
    print("latest")
elif command == "npm-channel":
    package, tag = args[2], args[3]
    print(state["tags"][package].get(tag, "<none>"))
elif command == "assert-not-rollback":
    print("allowed")
else:
    raise SystemExit(91)
"""


FAKE_NPM = r"""#!/usr/bin/env python3
import json, os, pathlib, sys
state_path = pathlib.Path(os.environ["FAKE_NPM_STATE"])
state = json.loads(state_path.read_text())
args = sys.argv[1:]

def split_spec(spec):
    package, tag = spec.rsplit("@", 1)
    return package, tag

def save():
    state_path.write_text(json.dumps(state, sort_keys=True))

if args[:1] == ["view"]:
    package, tag = split_spec(args[1])
    value = state["tags"][package].get(tag)
    if (
        state["mode"] == "second_proof_stale"
        and package == "@kinlab/kin-mcp"
        and tag == "latest"
        and value == state["new"]
    ):
        value = state["old"]
    if value is None:
        raise SystemExit(1)
    print(value)
elif args[:2] == ["dist-tag", "add"]:
    package, version = split_spec(args[2])
    tag = args[3]
    state["tags"][package][tag] = version
    save()
    if (
        state["mode"] == "second_add_lost_response"
        and package == "@kinlab/kin-mcp"
        and tag == "latest"
        and version == state["new"]
    ):
        raise SystemExit(42)
elif args[:2] == ["dist-tag", "rm"]:
    package, tag = args[2], args[3]
    state["tags"][package].pop(tag, None)
    save()
else:
    raise SystemExit(92)
"""


def run_case(mode: str, expected_success: bool) -> None:
    with tempfile.TemporaryDirectory() as raw_tmp:
        tmp = Path(raw_tmp)
        bin_dir = tmp / "bin"
        bin_dir.mkdir()
        for name, body in (("node", FAKE_NODE), ("npm", FAKE_NPM)):
            path = bin_dir / name
            path.write_text(body, encoding="utf-8")
            path.chmod(0o755)

        state_path = tmp / "state.json"
        state = {
            "mode": mode,
            "old": OLD,
            "new": NEW,
            "tags": {
                package: {"latest": OLD, CANDIDATE: NEW} for package in PACKAGES
            },
        }
        state_path.write_text(json.dumps(state), encoding="utf-8")
        env = os.environ.copy()
        env.update(
            {
                "PATH": f"{bin_dir}:{env['PATH']}",
                "FAKE_NPM_STATE": str(state_path),
                "NPM_TOKEN": "test-only-token",
                "NPM_PROMOTION_VERIFY_ATTEMPTS": "2",
                "NPM_PROMOTION_VERIFY_DELAY_SECONDS": "0",
            }
        )
        result = subprocess.run(
            ["bash", str(PROMOTER), NEW],
            cwd=SCRIPTS.parent,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        actual = json.loads(state_path.read_text(encoding="utf-8"))
        if expected_success:
            assert result.returncode == 0, result.stderr
            for package in PACKAGES:
                assert actual["tags"][package]["latest"] == NEW
                assert CANDIDATE not in actual["tags"][package]
        else:
            assert result.returncode != 0, result.stdout
            for package in PACKAGES:
                assert actual["tags"][package]["latest"] == OLD, (
                    mode,
                    package,
                    result.stdout,
                    result.stderr,
                )
                assert actual["tags"][package][CANDIDATE] == NEW
            assert "Restored @kinlab/kin@latest to 0.2.15" in result.stderr
        print(f"PASS: {mode}")


def main() -> None:
    run_case("success", expected_success=True)
    run_case("second_add_lost_response", expected_success=False)
    run_case("second_proof_stale", expected_success=False)


if __name__ == "__main__":
    main()
