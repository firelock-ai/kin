#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

"""Deterministic failure-injection tests for Kin's staged npm release gate."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
STAGER = SCRIPTS / "stage-npm-release.sh"
WAITER = SCRIPTS / "wait-npm-approval.sh"
VERSION = "0.2.16"
OLD_VERSION = "0.2.15"
NEWER_VERSION = "0.2.17"
REF = f"refs/tags/v{VERSION}"
PACKAGE = "@kinlab/kin"
OTHER_PACKAGE = "@kinlab/kin-mcp"


FAKE_NPM = r"""#!/usr/bin/env python3
import json
import os
import pathlib
import sys

state_path = pathlib.Path(os.environ["FAKE_NPM_STATE"])
state = json.loads(state_path.read_text())
args = sys.argv[1:]
if os.environ.get("NODE_AUTH_TOKEN") or os.environ.get("NPM_TOKEN"):
    print("fake npm detected inherited registry credentials", file=sys.stderr)
    raise SystemExit(96)
state.setdefault("commands", []).append(args)

def save():
    state_path.write_text(json.dumps(state, sort_keys=True))

def split_spec(spec):
    package, selector = spec.rsplit("@", 1)
    return package, selector

if args[:1] == ["pack"]:
    package_dir = pathlib.Path(args[1])
    manifest = json.loads((package_dir / "package.json").read_text())
    destination = pathlib.Path(args[args.index("--pack-destination") + 1])
    filename = f"fake-{manifest['name'].split('/')[-1]}-{manifest['version']}.tgz"
    destination.mkdir(parents=True, exist_ok=True)
    (destination / filename).write_bytes(b"deterministic fake tarball")
    state["last_pack"] = {"package": manifest["name"], "version": manifest["version"]}
    if state.get("scenario") == "advance_before_stage":
        state["tags"][manifest["name"]]["latest"] = state["newer"]
    save()
    print(json.dumps([{
        "filename": filename,
        "integrity": "sha512-ZGV0ZXJtaW5pc3RpYy1mYWtlLWludGVncml0eQ==",
        "shasum": "0123456789abcdef0123456789abcdef01234567"
    }]))
elif args[:1] == ["view"]:
    package, selector = split_spec(args[1])
    scenario = state.get("scenario", "static")
    round_number = state.get("round", 0)
    value = None
    if scenario == "wait_then_both":
        if package == "@kinlab/kin":
            value = state["version"] if selector in (state["version"], "latest") else None
        elif package == "@kinlab/kin-mcp":
            if selector == state["version"] and round_number >= 1:
                value = state["version"]
            elif selector == "latest":
                value = state["version"] if round_number >= 1 else state["old"]
                state["round"] = round_number + 1
    elif scenario == "timeout":
        if package == "@kinlab/kin":
            value = state["version"] if selector in (state["version"], "latest") else None
        elif package == "@kinlab/kin-mcp" and selector == "latest":
            value = state["old"]
    elif scenario == "newer_channel":
        if selector == state["version"]:
            value = state["version"]
        elif selector == "latest":
            value = state["newer"] if package == "@kinlab/kin" else state["version"]
    else:
        if selector in state.get("public", {}).get(package, []):
            value = selector
        else:
            value = state.get("tags", {}).get(package, {}).get(selector)
    save()
    if value is None:
        raise SystemExit(1)
    print(value)
elif args[:2] == ["stage", "publish"]:
    packed = state["last_pack"]
    package = packed["package"]
    version = packed["version"]
    tag = args[args.index("--tag") + 1]
    staged = state.setdefault("staged", {}).get(package)
    if staged is not None and staged["version"] == version:
        save()
        print("npm error E409 version already exists as a staged version", file=sys.stderr)
        raise SystemExit(1)
    state["staged"][package] = {"version": version, "tag": tag}
    if state.get("scenario") == "advance_during_stage":
        state["tags"][package][tag] = state["newer"]
    save()
    print(f"staged {package}@{version} tag={tag}")
elif args[:1] == ["publish"] or args[:1] == ["dist-tag"]:
    save()
    print("forbidden direct npm mutation", file=sys.stderr)
    raise SystemExit(97)
else:
    save()
    print(f"unsupported fake npm command: {args}", file=sys.stderr)
    raise SystemExit(98)
"""


FAKE_VERIFY = r"""#!/usr/bin/env python3
import json
import os
import pathlib
import sys

if os.environ.get("NODE_AUTH_TOKEN") or os.environ.get("NPM_TOKEN"):
    print("fake verifier detected inherited registry credentials", file=sys.stderr)
    raise SystemExit(96)
pathlib.Path(os.environ["FAKE_VERIFY_LOG"]).write_text(json.dumps(sys.argv[1:]))
"""


FAKE_RELEASE_ORDER = r"""#!/usr/bin/env node
import fs from 'node:fs';

const statePath = process.env.FAKE_NPM_STATE;
const state = JSON.parse(fs.readFileSync(statePath, 'utf8'));
const [command, ...args] = process.argv.slice(2);

const compare = (left, right) => {
  const a = left.split('.').map(Number);
  const b = right.split('.').map(Number);
  for (let i = 0; i < 3; i += 1) {
    if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  }
  return 0;
};

if (command === 'channel') {
  console.log('latest');
} else if (command === 'npm-channel') {
  const [packageName, channel] = args;
  state.channel_reads = (state.channel_reads ?? 0) + 1;
  fs.writeFileSync(statePath, JSON.stringify(state));
  if (state.scenario === 'fail_post_stage_channel_read' && state.channel_reads >= 2) {
    console.error('simulated npm registry outage after stage acceptance');
    process.exit(1);
  }
  console.log(state.tags?.[packageName]?.[channel] ?? '<none>');
} else if (command === 'assert-not-rollback') {
  const [candidate, current, label = 'release channel'] = args;
  if (current !== '<none>' && compare(candidate, current) < 0) {
    console.error(`${label} is already ${current}; refusing to roll it back to ${candidate}`);
    process.exit(1);
  }
  console.log(`${label} may advance from ${current} to ${candidate}`);
} else {
  console.error(`unsupported fake release-order command: ${command}`);
  process.exit(98);
}
"""


def write_executable(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)


def base_state(**overrides: object) -> dict[str, object]:
    state: dict[str, object] = {
        "scenario": "static",
        "public": {PACKAGE: [], OTHER_PACKAGE: []},
        "tags": {
            PACKAGE: {"latest": OLD_VERSION},
            OTHER_PACKAGE: {"latest": OLD_VERSION},
        },
        "staged": {},
        "commands": [],
    }
    state.update(overrides)
    return state


def harness() -> tuple[tempfile.TemporaryDirectory[str], Path, dict[str, str]]:
    owner = tempfile.TemporaryDirectory()
    tmp = Path(owner.name)
    bin_dir = tmp / "bin"
    bin_dir.mkdir()
    write_executable(bin_dir / "npm", FAKE_NPM)
    write_executable(bin_dir / "verify", FAKE_VERIFY)
    write_executable(bin_dir / "release-order.mjs", FAKE_RELEASE_ORDER)
    package_dir = tmp / "package"
    package_dir.mkdir()
    (package_dir / "package.json").write_text(
        json.dumps({"name": PACKAGE, "version": VERSION}), encoding="utf-8"
    )
    env = os.environ.copy()
    env.update(
        {
            "PATH": f"{bin_dir}:{env['PATH']}",
            "FAKE_NPM_STATE": str(tmp / "state.json"),
            "FAKE_VERIFY_LOG": str(tmp / "verify.json"),
            "NPM_RELEASE_VERIFY_SCRIPT": str(bin_dir / "verify"),
            "NPM_RELEASE_ORDER_SCRIPT": str(bin_dir / "release-order.mjs"),
            "GITHUB_OUTPUT": str(tmp / "github-output"),
            "NODE_AUTH_TOKEN": "must-not-reach-npm",
            "NPM_TOKEN": "must-not-reach-npm",
        }
    )
    return owner, package_dir, env


def run_stage(
    state: dict[str, object],
) -> tuple[subprocess.CompletedProcess[str], dict[str, bytes]]:
    owner, package_dir, env = harness()
    tmp = Path(owner.name)
    (tmp / "state.json").write_text(json.dumps(state), encoding="utf-8")
    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    result = subprocess.run(
        ["bash", str(STAGER), str(package_dir), REF, commit],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    snapshot: dict[str, bytes] = {}
    for name in ("state.json", "verify.json", "github-output"):
        source = tmp / name
        if source.exists():
            snapshot[name] = source.read_bytes()
    owner.cleanup()
    return result, snapshot


def test_new_stage() -> None:
    result, snapshot = run_stage(base_state())
    assert result.returncode == 0, result.stderr
    state = json.loads(snapshot["state.json"])
    assert state["staged"][PACKAGE] == {"version": VERSION, "tag": "latest"}
    assert any(command[:2] == ["stage", "publish"] for command in state["commands"])
    stage_command = next(
        command for command in state["commands"] if command[:2] == ["stage", "publish"]
    )
    assert "--provenance" in stage_command
    assert not any(
        command[:1] in (["publish"], ["dist-tag"]) for command in state["commands"]
    )
    assert b"staged=true" in snapshot["github-output"]
    assert b"integrity=sha512-" in snapshot["github-output"]
    assert b"shasum=0123456789abcdef0123456789abcdef01234567" in snapshot["github-output"]
    assert "expected integrity=sha512-" in result.stdout
    assert "verify.json" not in snapshot
    print("PASS: new version is staged under its final channel")


def test_public_rerun_verifies_before_skip() -> None:
    state = base_state(
        public={PACKAGE: [VERSION], OTHER_PACKAGE: []},
        tags={PACKAGE: {"latest": VERSION}, OTHER_PACKAGE: {"latest": OLD_VERSION}},
    )
    result, snapshot = run_stage(state)
    assert result.returncode == 0, result.stderr
    actual = json.loads(snapshot["state.json"])
    assert not any(
        command[:2] == ["stage", "publish"] for command in actual["commands"]
    )
    verify_args = json.loads(snapshot["verify.json"])
    assert verify_args[0:2] == [PACKAGE, VERSION]
    assert verify_args[3] == REF
    assert b"staged=false" in snapshot["github-output"]
    print("PASS: public rerun verifies exact identity and provenance before skipping")


def test_pending_stage_fails_actionably() -> None:
    state = base_state(staged={PACKAGE: {"version": VERSION, "tag": "latest"}})
    result, snapshot = run_stage(state)
    assert result.returncode != 0
    assert "OIDC identity cannot inspect staged packages" in result.stderr
    assert "Approve it with 2FA" in result.stderr
    assert "GitHub Latest remains blocked" in result.stderr
    assert "Never cut or approve a newer release" in result.stderr
    assert "verify.json" not in snapshot
    print("PASS: pending staged version fails loud with human recovery instructions")


def test_newer_channel_before_stage_fails_without_submission() -> None:
    state = base_state(scenario="advance_before_stage", newer=NEWER_VERSION)
    result, snapshot = run_stage(state)
    assert result.returncode != 0
    actual = json.loads(snapshot["state.json"])
    assert not any(
        command[:2] == ["stage", "publish"] for command in actual["commands"]
    )
    assert "immediately before staging" in result.stderr
    assert "no stage was submitted" in result.stderr
    print("PASS: channel advancement during build fails before staging")


def test_newer_channel_during_stage_requires_rejection() -> None:
    state = base_state(scenario="advance_during_stage", newer=NEWER_VERSION)
    result, snapshot = run_stage(state)
    assert result.returncode != 0
    actual = json.loads(snapshot["state.json"])
    assert actual["staged"][PACKAGE] == {"version": VERSION, "tag": "latest"}
    assert "advanced to" in result.stderr
    assert "Reject the newly pending" in result.stderr
    assert "never approve it" in result.stderr
    print("PASS: post-stage channel race fails with mandatory rejection")


def test_post_stage_channel_read_failure_requires_rejection() -> None:
    state = base_state(scenario="fail_post_stage_channel_read")
    result, snapshot = run_stage(state)
    assert result.returncode != 0
    actual = json.loads(snapshot["state.json"])
    assert actual["staged"][PACKAGE] == {"version": VERSION, "tag": "latest"}
    assert "could not be re-read afterward" in result.stderr
    assert "Treat 0.2.16 as pending" in result.stderr
    assert "reject it before any approval or newer release" in result.stderr
    print("PASS: post-stage registry outage requires pending-stage rejection")


def run_wait(
    state: dict[str, object], attempts: int
) -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
    with tempfile.TemporaryDirectory() as raw_tmp:
        tmp = Path(raw_tmp)
        bin_dir = tmp / "bin"
        bin_dir.mkdir()
        write_executable(bin_dir / "npm", FAKE_NPM)
        state_path = tmp / "state.json"
        state_path.write_text(json.dumps(state), encoding="utf-8")
        env = os.environ.copy()
        env.update(
            {
                "PATH": f"{bin_dir}:{env['PATH']}",
                "FAKE_NPM_STATE": str(state_path),
                "NPM_APPROVAL_ATTEMPTS": str(attempts),
                "NPM_APPROVAL_DELAY_SECONDS": "0",
                "NODE_AUTH_TOKEN": "must-not-reach-npm",
                "NPM_TOKEN": "must-not-reach-npm",
            }
        )
        result = subprocess.run(
            ["bash", str(WAITER), VERSION],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        return result, json.loads(state_path.read_text())


def test_waits_for_both_approvals() -> None:
    result, state = run_wait(
        base_state(
            scenario="wait_then_both",
            version=VERSION,
            old=OLD_VERSION,
            round=0,
        ),
        attempts=3,
    )
    assert result.returncode == 0, result.stderr
    assert state["round"] >= 1
    assert "Partial npm approval detected" in result.stdout
    assert "Both npm packages are public" in result.stdout
    print("PASS: approval gate waits for both versions and both final tags")


def test_approval_timeout_blocks_latest() -> None:
    result, _ = run_wait(
        base_state(scenario="timeout", version=VERSION, old=OLD_VERSION), attempts=2
    )
    assert result.returncode != 0
    assert "Timed out waiting for both npm approvals" in result.stderr
    assert "GitHub Latest was not promoted" in result.stderr
    assert "Never leave an older stage pending across releases" in result.stderr
    print("PASS: bounded approval timeout keeps GitHub Latest blocked")


def test_newer_channel_fails_closed() -> None:
    result, _ = run_wait(
        base_state(
            scenario="newer_channel",
            version=VERSION,
            newer=NEWER_VERSION,
        ),
        attempts=2,
    )
    assert result.returncode != 0
    assert "already newer" in result.stderr
    assert "GitHub Latest remains blocked" in result.stderr
    assert "never approve it after the channel has advanced" in result.stderr
    print("PASS: newer final channel fails closed without rollback")


def main() -> None:
    test_new_stage()
    test_public_rerun_verifies_before_skip()
    test_pending_stage_fails_actionably()
    test_newer_channel_before_stage_fails_without_submission()
    test_newer_channel_during_stage_requires_rejection()
    test_post_stage_channel_read_failure_requires_rejection()
    test_waits_for_both_approvals()
    test_approval_timeout_blocks_latest()
    test_newer_channel_fails_closed()


if __name__ == "__main__":
    main()
