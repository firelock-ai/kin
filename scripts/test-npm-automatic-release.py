#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

"""Deterministic failure-injection tests for Kin's automatic npm release gate."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
PUBLISHER = SCRIPTS / "publish-npm-release.sh"
VERSION = "0.2.22"
OLD_VERSION = "0.2.21"
NEWER_VERSION = "0.2.23"
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
    if state.get("scenario") == "advance_before_publish":
        state["tags"][manifest["name"]]["latest"] = state["newer"]
    save()
    print(json.dumps([{
        "filename": filename,
        "integrity": "sha512-ZGV0ZXJtaW5pc3RpYy1mYWtlLWludGVncml0eQ==",
        "shasum": "0123456789abcdef0123456789abcdef01234567"
    }]))
elif args[:1] == ["view"]:
    package, selector = split_spec(args[1])
    if (state.get("scenario") == "targeted_view_outage" and
            selector == state.get("target_version")):
        save()
        print("npm error code E503\nnpm error registry unavailable", file=sys.stderr)
        raise SystemExit(1)
    value = None
    if selector in state.get("public", {}).get(package, []):
        value = selector
    else:
        value = state.get("tags", {}).get(package, {}).get(selector)
    save()
    if value is None:
        print("npm error code E404\nnpm error version not found", file=sys.stderr)
        raise SystemExit(1)
    print(value)
elif args[:1] == ["publish"]:
    packed = state["last_pack"]
    package = packed["package"]
    version = packed["version"]
    tag = args[args.index("--tag") + 1]
    public = state.setdefault("public", {}).setdefault(package, [])
    if version in public:
        save()
        print("npm error E403 version already exists", file=sys.stderr)
        raise SystemExit(1)
    if state.get("scenario") == "reject_publish":
        save()
        print("simulated trusted publisher rejection", file=sys.stderr)
        raise SystemExit(1)
    public.append(version)
    state["tags"][package][tag] = version
    if state.get("scenario") == "advance_during_publish":
        state["tags"][package][tag] = state["newer"]
    save()
    if state.get("scenario") == "fail_after_acceptance":
        print("simulated transport failure after acceptance", file=sys.stderr)
        raise SystemExit(1)
    print(f"published {package}@{version} tag={tag}")
elif args[:2] == ["stage", "publish"] or args[:1] == ["dist-tag"]:
    save()
    print("forbidden npm mutation", file=sys.stderr)
    raise SystemExit(97)
else:
    save()
    print(f"unsupported fake npm command: {args}", file=sys.stderr)
    raise SystemExit(98)
"""


FAKE_VERIFY = r"""#!/usr/bin/env bash
set -euo pipefail
if [ -n "${NODE_AUTH_TOKEN:-}" ] || [ -n "${NPM_TOKEN:-}" ]; then
  echo "fake verifier detected inherited registry credentials" >&2
  exit 96
fi
python3 - "$FAKE_VERIFY_LOG" "$@" <<'PY'
import json
import pathlib
import sys

pathlib.Path(sys.argv[1]).write_text(json.dumps(sys.argv[2:]))
PY
if [ "${FAKE_VERIFY_FAIL:-0}" = 1 ]; then
  echo "simulated exact-byte or provenance failure" >&2
  exit 1
fi
"""


FAKE_RELEASE_ORDER = r"""#!/usr/bin/env node
import fs from 'node:fs';
import { pathToFileURL } from 'node:url';

const compare = (left, right) => {
  const a = left.split('.').map(Number);
  const b = right.split('.').map(Number);
  for (let i = 0; i < 3; i += 1) {
    if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  }
  return 0;
};

const main = (argv) => {
  const statePath = process.env.FAKE_NPM_STATE;
  const state = JSON.parse(fs.readFileSync(statePath, 'utf8'));
  const [command, ...args] = argv;

  if (command === 'channel') {
    console.log('latest');
  } else if (command === 'npm-channel') {
    const [packageName, channel] = args;
    state.channel_reads = (state.channel_reads ?? 0) + 1;
    fs.writeFileSync(statePath, JSON.stringify(state));
    if (state.scenario === 'fail_post_publish_channel_read' && state.channel_reads >= 2) {
      console.error('simulated npm registry outage after publish acceptance');
      process.exit(1);
    }
    console.log(state.tags?.[packageName]?.[channel] ?? '<none>');
  } else if (command === 'assert-not-rollback') {
    const [candidate, current, label = 'release channel'] = args;
    state.rollback_checks = (state.rollback_checks ?? 0) + 1;
    fs.writeFileSync(statePath, JSON.stringify(state));
    if (current !== '<none>' && compare(candidate, current) < 0) {
      console.error(`${label} is already ${current}; refusing to roll it back to ${candidate}`);
      process.exit(1);
    }
    console.log(`${label} may advance from ${current} to ${candidate}`);
  } else {
    console.error(`unsupported fake release-order command: ${command}`);
    process.exit(98);
  }
};

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2));
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
    verify_path = bin_dir / "verify"
    write_executable(verify_path, FAKE_VERIFY)
    verify_path.chmod(0o644)
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
            "NPM_RELEASE_ORDER_SCRIPT": str((bin_dir / "release-order.mjs").resolve()),
            "GITHUB_OUTPUT": str(tmp / "github-output"),
            "NODE_AUTH_TOKEN": "must-not-reach-npm",
            "NPM_TOKEN": "must-not-reach-npm",
        }
    )
    return owner, package_dir, env


def run_publish(
    state: dict[str, object], *, preflight: bool = False, verify_fail: bool = False
) -> tuple[subprocess.CompletedProcess[str], dict[str, bytes]]:
    owner, package_dir, env = harness()
    tmp = Path(owner.name)
    (tmp / "state.json").write_text(json.dumps(state), encoding="utf-8")
    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    if verify_fail:
        env["FAKE_VERIFY_FAIL"] = "1"
    command = ["bash", str(PUBLISHER)]
    if preflight:
        command.append("--preflight")
    command.extend([str(package_dir), REF, commit])
    result = subprocess.run(
        command,
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


def test_absent_preflight_proves_channel_without_mutation() -> None:
    result, snapshot = run_publish(base_state(), preflight=True)
    assert result.returncode == 0, result.stderr
    state = json.loads(snapshot["state.json"])
    assert not any(command[:1] == ["publish"] for command in state["commands"])
    assert "Preflight ready for absent" in result.stdout
    assert "no registry mutation performed" in result.stdout
    assert "verify.json" not in snapshot
    assert "github-output" not in snapshot
    print("PASS: absent package preflight proves channel with zero mutation authority")


def test_existing_preflight_requires_exact_public_proof() -> None:
    state = base_state(
        public={PACKAGE: [VERSION], OTHER_PACKAGE: []},
        tags={PACKAGE: {"latest": VERSION}, OTHER_PACKAGE: {"latest": OLD_VERSION}},
    )
    result, snapshot = run_publish(state, preflight=True)
    assert result.returncode == 0, result.stderr
    actual = json.loads(snapshot["state.json"])
    assert not any(command[:1] == ["publish"] for command in actual["commands"])
    assert "Preflight verified existing" in result.stdout
    assert "verify.json" in snapshot
    assert "github-output" not in snapshot
    print("PASS: existing package preflight verifies bytes, provenance, and channel")


def test_targeted_view_outage_is_not_treated_as_absence() -> None:
    state = base_state(
        scenario="targeted_view_outage",
        target_version=VERSION,
        public={PACKAGE: [VERSION], OTHER_PACKAGE: []},
        tags={PACKAGE: {"latest": VERSION}, OTHER_PACKAGE: {"latest": OLD_VERSION}},
    )
    result, snapshot = run_publish(state, preflight=True)
    assert result.returncode != 0
    actual = json.loads(snapshot["state.json"])
    assert not any(command[:1] == ["publish"] for command in actual["commands"])
    assert "Only an explicit E404 is accepted as absence" in result.stderr
    assert "no publish authority was granted" in result.stderr
    assert "verify.json" not in snapshot
    print("PASS: targeted npm lookup outage fails closed before publish authority")


def test_bad_existing_package_blocks_absent_sibling_before_any_publish() -> None:
    state = base_state(
        public={PACKAGE: [VERSION], OTHER_PACKAGE: []},
        tags={PACKAGE: {"latest": VERSION}, OTHER_PACKAGE: {"latest": OLD_VERSION}},
    )
    owner, package_dir, env = harness()
    tmp = Path(owner.name)
    other_dir = tmp / "other-package"
    other_dir.mkdir()
    (other_dir / "package.json").write_text(
        json.dumps({"name": OTHER_PACKAGE, "version": VERSION}), encoding="utf-8"
    )
    state_path = tmp / "state.json"
    state_path.write_text(json.dumps(state), encoding="utf-8")
    env["FAKE_VERIFY_FAIL"] = "1"
    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    pipeline = r"""
set -euo pipefail
bash "$1" --preflight "$2" "$4" "$5"
bash "$1" --preflight "$3" "$4" "$5"
bash "$1" "$2" "$4" "$5"
bash "$1" "$3" "$4" "$5"
"""
    result = subprocess.run(
        [
            "bash",
            "-c",
            pipeline,
            "npm-two-package-preflight",
            str(PUBLISHER),
            str(package_dir),
            str(other_dir),
            REF,
            commit,
        ],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    snapshot = json.loads(state_path.read_text())
    owner.cleanup()
    assert result.returncode != 0
    assert VERSION not in snapshot["public"][OTHER_PACKAGE]
    assert not any(command[:1] == ["publish"] for command in snapshot["commands"])
    assert sum(command[:1] == ["pack"] for command in snapshot["commands"]) == 1
    assert "simulated exact-byte or provenance failure" in result.stderr
    print("PASS: bad existing package blocks absent sibling before either publish job")


def test_symlinked_checkout_runs_channel_and_rollback_preflight() -> None:
    owner, package_dir, env = harness()
    tmp = Path(owner.name)
    repo = tmp / "physical-repo"
    scripts = repo / "scripts"
    scripts.mkdir(parents=True)
    write_executable(scripts / PUBLISHER.name, PUBLISHER.read_text(encoding="utf-8"))
    write_executable(scripts / "release-order.mjs", FAKE_RELEASE_ORDER)
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "add", "scripts"], cwd=repo, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Kin Release Test",
            "-c",
            "user.email=release-test@kin.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.hooksPath=/dev/null",
            "commit",
            "-qm",
            "test fixture",
        ],
        cwd=repo,
        check=True,
    )
    logical_repo = tmp / "logical-repo"
    logical_repo.symlink_to(repo, target_is_directory=True)
    state_path = tmp / "state.json"
    state_path.write_text(json.dumps(base_state()), encoding="utf-8")
    env.pop("NPM_RELEASE_ORDER_SCRIPT")
    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=repo, text=True
    ).strip()
    result = subprocess.run(
        [
            "bash",
            str(logical_repo / "scripts" / PUBLISHER.name),
            "--preflight",
            str(package_dir),
            REF,
            commit,
        ],
        cwd=logical_repo,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    snapshot = json.loads(state_path.read_text())
    owner.cleanup()
    assert result.returncode == 0, result.stderr
    assert snapshot.get("channel_reads") == 1
    assert snapshot.get("rollback_checks") == 1
    assert "latest=0.2.21" in result.stdout
    assert "no registry mutation performed" in result.stdout
    assert not any(command[:1] == ["publish"] for command in snapshot["commands"])
    print("PASS: symlinked checkout executes channel and rollback preflight")


def test_new_publish() -> None:
    result, snapshot = run_publish(base_state())
    assert result.returncode == 0, result.stderr
    state = json.loads(snapshot["state.json"])
    assert VERSION in state["public"][PACKAGE]
    assert state["tags"][PACKAGE]["latest"] == VERSION
    publish_command = next(
        command for command in state["commands"] if command[:1] == ["publish"]
    )
    assert "--provenance" in publish_command
    assert not any(
        command[:2] == ["stage", "publish"] or command[:1] == ["dist-tag"]
        for command in state["commands"]
    )
    assert b"published=true" in snapshot["github-output"]
    assert b"integrity=sha512-" in snapshot["github-output"]
    assert (
        b"shasum=0123456789abcdef0123456789abcdef01234567" in snapshot["github-output"]
    )
    verify_args = json.loads(snapshot["verify.json"])
    assert verify_args[0:2] == [PACKAGE, VERSION]
    assert "Published" in result.stdout
    print("PASS: new version publishes through OIDC under its final channel")


def test_public_rerun_verifies_before_skip() -> None:
    state = base_state(
        public={PACKAGE: [VERSION], OTHER_PACKAGE: []},
        tags={PACKAGE: {"latest": VERSION}, OTHER_PACKAGE: {"latest": OLD_VERSION}},
    )
    result, snapshot = run_publish(state)
    assert result.returncode == 0, result.stderr
    actual = json.loads(snapshot["state.json"])
    assert not any(command[:1] == ["publish"] for command in actual["commands"])
    verify_args = json.loads(snapshot["verify.json"])
    assert verify_args[0:2] == [PACKAGE, VERSION]
    assert verify_args[3] == REF
    assert b"published=false" in snapshot["github-output"]
    print("PASS: public rerun verifies exact identity and provenance before skipping")


def test_rejected_publish_fails_without_public_version() -> None:
    result, snapshot = run_publish(base_state(scenario="reject_publish"))
    assert result.returncode != 0
    state = json.loads(snapshot["state.json"])
    assert VERSION not in state["public"][PACKAGE]
    assert "did not become publicly verifiable" in result.stderr
    assert "GitHub Latest remains blocked" in result.stderr
    assert "verify.json" not in snapshot
    print("PASS: rejected Trusted Publisher mutation fails without false success")


def test_failure_after_acceptance_recovers_from_public_authority() -> None:
    result, snapshot = run_publish(base_state(scenario="fail_after_acceptance"))
    assert result.returncode == 0, result.stderr
    state = json.loads(snapshot["state.json"])
    assert VERSION in state["public"][PACKAGE]
    assert state["tags"][PACKAGE]["latest"] == VERSION
    assert "recovering from anonymous public authority" in result.stdout
    assert "verify.json" in snapshot
    assert b"published=true" in snapshot["github-output"]
    print("PASS: post-acceptance transport failure recovers only from public proof")


def test_newer_channel_before_publish_fails_without_mutation() -> None:
    state = base_state(scenario="advance_before_publish", newer=NEWER_VERSION)
    result, snapshot = run_publish(state)
    assert result.returncode != 0
    actual = json.loads(snapshot["state.json"])
    assert not any(command[:1] == ["publish"] for command in actual["commands"])
    assert "refusing to roll it back" in result.stderr
    print("PASS: channel advancement during build fails before publication")


def test_newer_channel_during_publish_blocks_finalization() -> None:
    state = base_state(scenario="advance_during_publish", newer=NEWER_VERSION)
    result, snapshot = run_publish(state)
    assert result.returncode != 0
    actual = json.loads(snapshot["state.json"])
    assert VERSION in actual["public"][PACKAGE]
    assert actual["tags"][PACKAGE]["latest"] == NEWER_VERSION
    assert "resolves to 0.2.23" in result.stderr
    assert "GitHub Latest remains blocked" in result.stderr
    assert "verify.json" in snapshot
    print("PASS: concurrent channel advancement leaves GitHub Latest blocked")


def test_post_publish_channel_read_failure_blocks_finalization() -> None:
    state = base_state(scenario="fail_post_publish_channel_read")
    result, snapshot = run_publish(state)
    assert result.returncode != 0
    actual = json.loads(snapshot["state.json"])
    assert VERSION in actual["public"][PACKAGE]
    assert "could not be re-read after publication" in result.stderr
    assert "immutable version cannot be rolled back" in result.stderr
    assert "rerun this same release" in result.stderr
    assert "verify.json" in snapshot
    print("PASS: post-publish registry outage blocks finalization honestly")


def main() -> None:
    test_absent_preflight_proves_channel_without_mutation()
    test_existing_preflight_requires_exact_public_proof()
    test_targeted_view_outage_is_not_treated_as_absence()
    test_bad_existing_package_blocks_absent_sibling_before_any_publish()
    test_symlinked_checkout_runs_channel_and_rollback_preflight()
    test_new_publish()
    test_public_rerun_verifies_before_skip()
    test_rejected_publish_fails_without_public_version()
    test_failure_after_acceptance_recovers_from_public_authority()
    test_newer_channel_before_publish_fails_without_mutation()
    test_newer_channel_during_publish_blocks_finalization()
    test_post_publish_channel_read_failure_blocks_finalization()


if __name__ == "__main__":
    main()
