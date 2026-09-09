"""Run interrupted-store recovery against existing candidate binaries."""
if not __debug__:
    raise RuntimeError("proof assertions require Python without optimization")

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


def assert_fixture_profile(fixture, receipt, label):
    bodies = {
        'orphan.py': '4606c3a9405e3fca4541326a2f337c4a75a1aea108fef45f73935a5a38c43487',
        'empty.pyi': '0cbcf8e504eee2fe771a543f161fddd92bc280654a5ce78f46f5fc8828230b42',
        'sentinel.py': '34a1dcc6016547f2e309a65ba900b08d707f9551c2699e187d45dc738d558704',
    }
    expected_debt = ([] if label == 'legacy-fixed' else
                     [{'path': name, 'body': body} for name, body in bodies.items()])
    expected = {'authority_generation': 3, 'durable_entities': 0,
                'live_entities': 0, 'empty_cas_entities': 0, 'orphan_cas_entities': 2,
                'legacy': label == 'legacy-fixed', 'orphan_body': bodies['orphan.py'],
                'semantic_debt': expected_debt}
    profile = {key: value for key, value in receipt.items() if key != 'files'}
    assert profile == expected, 'interrupted recovery receipt profile changed'
    for name, body in bodies.items():
        assert receipt['files'][name] == body, 'synthetic source body changed'
    marker = fixture / '.kin/semantic-debt.json'
    actual_debt = json.loads(marker.read_text()) if marker.exists() else []
    assert actual_debt == expected_debt, 'exact initial semantic debt changed'
    # These frozen snapshots were measured before recovery. Keep the measured
    # authority bytes pinned independently of a regenerated package manifest.
    expected_snapshot = {
        'legacy-fixed': '0b960745e2b1dc4d3c81d7da81e940c90866f332b5367652a8a0bd83f22c89d9',
        'recorded-fixed': '88a6cfa7cd42b462ae5363029fb1c525a1412f88e8fe63b0caf118a7ed1a1793',
    }[label]
    snapshots = list((fixture / '.kin/kindb').glob('*/snapshots/*.kndb'))
    assert len(snapshots) == 1
    assert hashlib.sha256(snapshots[0].read_bytes()).hexdigest() == expected_snapshot, 'interrupted snapshot changed'


def verify(root):
    manifest = json.loads((root / "manifest.json").read_text())
    entries = list(root.rglob("*"))
    assert not any(path.is_symlink() for path in entries), "symlinks are not proof assets"
    actual = {path.relative_to(root).as_posix() for path in entries if path.is_file()}
    assert actual == set(manifest) | {"manifest.json"}, "proof asset inventory mismatch"
    for name, digest in manifest.items():
        assert hashlib.sha256((root / name).read_bytes()).hexdigest() == digest, name
    for label in ("legacy-fixed", "recorded-fixed"):
        fixture = root / "fixtures" / label
        receipt = json.loads((root / "fixtures" / (label + "-receipt.json")).read_text())
        assert_fixture_profile(fixture, receipt, label)
        assert not (fixture / ".kin/reconciliation").exists()
        actual_fixture = {path.relative_to(fixture).as_posix()
                          for path in fixture.rglob("*") if path.is_file()}
        assert actual_fixture == set(receipt["files"]), "fixture inventory mismatch"
        for name, digest in receipt["files"].items():
            assert hashlib.sha256((fixture / name).read_bytes()).hexdigest() == digest, name
    print("PROOF_ASSET_HASHES_VERIFIED", flush=True)


def prepare(root, label, output, kin):
    fixture = output / (label + "-fixture")
    fixture.mkdir()
    home = output / (label + "-init-home")
    home.mkdir()
    env = {k: v for k, v in os.environ.items() if not k.startswith("KIN_")}
    env.update(KIN_HOME=str(home), KIN_EMBED_BACKEND="cpu", KIN_DAEMON_AUTO_EMBED="false")
    command = [str(kin), "init", str(fixture), "--no-enrich", "--json"]
    result = subprocess.run(command, env=env, capture_output=True, text=True)
    (output / (label + "-init.log")).write_text(result.stdout + result.stderr)
    assert result.returncode == 0, "candidate initialization failed"
    store = fixture / ".kin"
    control = store / "reconciliation"
    assert (control / "authority.key").is_file()
    assert (control / "projection.lock").is_file()
    assert not (store / "daemon.port").exists(), "initialization started a daemon"
    # This directory was created by this invocation. Keep its freshly minted
    # private control pair while installing the synthetic interrupted history.
    for entry in store.iterdir():
        if entry.name == "reconciliation":
            continue
        if entry.is_dir() and not entry.is_symlink():
            shutil.rmtree(entry)
        else:
            entry.unlink()
    shutil.copytree(root / "fixtures" / label, fixture, dirs_exist_ok=True)
    # Checkout timestamps must not turn this already-admitted store into a
    # fresh filesystem-edit case and accidentally repair it through catch-up.
    for name in ("orphan.py", "sentinel.py", "empty.pyi"):
        os.utime(fixture / name, (0, 0))
    receipt = json.loads((root / "fixtures" / (label + "-receipt.json")).read_text())
    for name, digest in receipt["files"].items():
        assert hashlib.sha256((fixture / name).read_bytes()).hexdigest() == digest, name
    assert_fixture_profile(fixture, receipt, label)
    print("SYNTHETIC_STORE_PREPARED", label, flush=True)
    return fixture, receipt


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--kin", type=Path)
    parser.add_argument("--daemon", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--prepare-only", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    verify(root)
    if args.verify_only:
        return
    assert args.kin and args.output
    assert args.prepare_only or args.daemon
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    for label in ("legacy-fixed", "recorded-fixed"):
        fixture, receipt = prepare(root, label, output, args.kin.resolve())
        if args.prepare_only:
            continue
        for reopen in ([False, True] if label == "recorded-fixed" else [False]):
            name = label + ("-reopen" if reopen else "")
            command = [sys.executable, str(root / "probe_startup_binary.py"),
                       "--daemon", str(args.daemon.resolve()), "--fixture", str(fixture),
                       "--output", str(output / name), "--expect", "recovered", "--empty-control"]
            if label == "recorded-fixed":
                command += ["--require-orphan-debt", "--orphan-body", receipt["orphan_body"]]
            subprocess.run(command, check=True)
    if not args.prepare_only:
        print("STRICT_STARTUP_AND_LATER_WATCH_THREE_PROBES_PASS", flush=True)


if __name__ == "__main__":
    main()
