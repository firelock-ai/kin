#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

"""Failure-injection regression for anonymous npm release verification."""

from __future__ import annotations

import base64
import json
import os
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
VERIFIER = ROOT / "scripts" / "verify-npm-release.sh"
PACKAGE = "@kinlab/kin"
VERSION = "0.2.23"
REF = f"refs/tags/v{VERSION}"
COMMIT = "a" * 40
INTEGRITY_BYTES = bytes([7]) * 64
INTEGRITY = f"sha512-{base64.b64encode(INTEGRITY_BYTES).decode()}"


FAKE_NPM = r"""#!/usr/bin/env python3
import base64
import json
import os
import pathlib
import sys

state_path = pathlib.Path(os.environ["FAKE_NPM_STATE"])
state = json.loads(state_path.read_text())
args = sys.argv[1:]
state.setdefault("commands", []).append(args)

def save():
    state_path.write_text(json.dumps(state, sort_keys=True))

if args[:1] in (["pack"], ["view"], ["install"], ["audit"]):
    if os.environ.get("NODE_AUTH_TOKEN") or os.environ.get("NPM_TOKEN"):
        save()
        print("fake npm detected inherited registry credentials", file=sys.stderr)
        raise SystemExit(96)

package = os.environ["FAKE_NPM_PACKAGE"]
version = os.environ["FAKE_NPM_VERSION"]
integrity = os.environ["FAKE_NPM_INTEGRITY"]
commit = os.environ["FAKE_NPM_COMMIT"]
ref = os.environ["FAKE_NPM_REF"]

if args[:1] == ["pack"]:
    destination = pathlib.Path(args[args.index("--pack-destination") + 1])
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "fake-package.tgz").write_bytes(b"deterministic npm proof fixture")
    save()
    print(json.dumps([{"filename": "fake-package.tgz", "integrity": integrity}]))
elif args[:1] == ["view"]:
    state["view_calls"] = state.get("view_calls", 0) + 1
    if state["view_calls"] == 1:
        # Registry propagation can expose a non-null dist object before its SRI.
        response = {
            "shasum": "0123456789abcdef0123456789abcdef01234567",
            "tarball": f"https://registry.npmjs.org/{package}/-/{version}.tgz",
        }
    else:
        response = {
            "integrity": integrity,
            "shasum": "0123456789abcdef0123456789abcdef01234567",
            "tarball": f"https://registry.npmjs.org/{package}/-/{version}.tgz",
        }
    save()
    print(json.dumps(response))
elif args[:1] == ["init"]:
    save()
    print(json.dumps({"name": "npm-proof-audit", "version": "1.0.0"}))
elif args[:1] == ["install"]:
    state["install_calls"] = state.get("install_calls", 0) + 1
    save()
elif args[:2] == ["audit", "signatures"]:
    state["audit_calls"] = state.get("audit_calls", 0) + 1
    digest = base64.b64decode(integrity.removeprefix("sha512-")).hex()
    statement = {
        "predicateType": "https://slsa.dev/provenance/v1",
        "subject": [{
            "name": f"pkg:npm/{package.replace('@', '%40', 1)}@{version}",
            "digest": {"sha512": digest},
        }],
        "predicate": {
            "buildDefinition": {
                "externalParameters": {
                    "workflow": {
                        "repository": "https://github.com/firelock-ai/kin",
                        "path": ".github/workflows/release.yml",
                        "ref": ref,
                    }
                },
                "resolvedDependencies": [{
                    "uri": f"git+https://github.com/firelock-ai/kin@{ref}",
                    "digest": {"gitCommit": commit},
                }],
            },
            "runDetails": {
                "builder": {
                    "id": "https://github.com/actions/runner/github-hosted"
                }
            },
        },
    }
    payload = base64.b64encode(json.dumps(statement).encode()).decode()
    audit = {
        "invalid": [],
        "missing": [],
        "verified": [{
            "name": package,
            "version": version,
            "attestations": {
                "provenance": {
                    "predicateType": "https://slsa.dev/provenance/v1"
                }
            },
            "attestationBundles": [{
                "predicateType": "https://slsa.dev/provenance/v1",
                "bundle": {"dsseEnvelope": {"payload": payload}},
            }],
        }],
    }
    save()
    print(json.dumps(audit))
else:
    save()
    print(f"unsupported fake npm command: {args}", file=sys.stderr)
    raise SystemExit(98)
"""


FAKE_SLEEP = r"""#!/usr/bin/env python3
import json
import os
import pathlib
import sys

state_path = pathlib.Path(os.environ["FAKE_NPM_STATE"])
state = json.loads(state_path.read_text())
state.setdefault("sleeps", []).append(sys.argv[1:])
state_path.write_text(json.dumps(state, sort_keys=True))
"""


def write_executable(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)


def main() -> None:
    with tempfile.TemporaryDirectory() as owner:
        tmp = Path(owner)
        bin_dir = tmp / "bin"
        package_dir = tmp / "package"
        bin_dir.mkdir()
        package_dir.mkdir()
        write_executable(bin_dir / "npm", FAKE_NPM)
        write_executable(bin_dir / "sleep", FAKE_SLEEP)
        (package_dir / "package.json").write_text(
            json.dumps({"name": PACKAGE, "version": VERSION}), encoding="utf-8"
        )
        state_path = tmp / "state.json"
        state_path.write_text(json.dumps({"commands": []}), encoding="utf-8")

        env = os.environ.copy()
        env.update(
            {
                "PATH": f"{bin_dir}:{env['PATH']}",
                "FAKE_NPM_STATE": str(state_path),
                "FAKE_NPM_PACKAGE": PACKAGE,
                "FAKE_NPM_VERSION": VERSION,
                "FAKE_NPM_INTEGRITY": INTEGRITY,
                "FAKE_NPM_COMMIT": COMMIT,
                "FAKE_NPM_REF": REF,
                "NODE_AUTH_TOKEN": "must-not-reach-registry-commands",
                "NPM_TOKEN": "must-not-reach-registry-commands",
            }
        )
        result = subprocess.run(
            [
                "bash",
                str(VERIFIER),
                PACKAGE,
                VERSION,
                str(package_dir),
                REF,
                COMMIT,
            ],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        state = json.loads(state_path.read_text(encoding="utf-8"))

    assert result.returncode == 0, result.stderr
    assert state.get("view_calls") == 2, state
    assert state.get("sleeps") == [["10"]], state
    assert state.get("install_calls") == 1, state
    assert state.get("audit_calls") == 1, state
    assert "Verified exact npm bytes and provenance" in result.stdout
    print(
        "PASS: verifier retries a partial non-null npm dist object until integrity is visible"
    )


if __name__ == "__main__":
    main()
