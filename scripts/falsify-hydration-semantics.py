#!/usr/bin/env python3
"""Falsify the hydration replay-semantics guard.

A guard that has never been shown to fail proves nothing. This plants a probe
in every guarded function in a throwaway copy of the tree, one at a time, and
asserts the real guard catches each one and names it. It also drives the two
non-digest failure modes: the dial drifting away from the manifest, and a
guarded function disappearing from under the pin.

The guard under test is always the REAL scripts/verify-hydration-semantics.py
with the REAL manifest — only the tree is poisoned. The manifest is policy, so
letting the poisoned copy supply it would falsify nothing.

Usage: falsify-hydration-semantics.py <poisoned_repo_root>
"""
import importlib.util
import os
import re
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
GUARD = os.path.join(SCRIPT_DIR, "verify-hydration-semantics.py")
MANIFEST = os.path.join(SCRIPT_DIR, "hydration-semantics-manifest.json")

spec = importlib.util.spec_from_file_location("hydration_guard", GUARD)
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


def run_guard(root):
    proc = subprocess.run(
        [sys.executable, GUARD, root], capture_output=True, text=True
    )
    return proc.returncode, proc.stdout + proc.stderr


def expect_failure(label, root, must_name):
    code, out = run_guard(root)
    if code == 0:
        print(f"::error::falsification failed — {label} did not fail the guard")
        print(out)
        sys.exit(1)
    if must_name not in out:
        print(
            f"::error::falsification failed — {label} failed but never named '{must_name}'"
        )
        print(out)
        sys.exit(1)
    print(f"  ok: {label}")


def read(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def write(path, text):
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def main():
    if len(sys.argv) < 2:
        print("::error::usage: falsify-hydration-semantics.py <poisoned_repo_root>")
        return 1
    root = os.path.abspath(sys.argv[1])

    import json

    with open(MANIFEST, "r", encoding="utf-8") as f:
        manifest = json.load(f)
    entries = manifest["guarded"]

    code, out = run_guard(root)
    if code != 0:
        print("::error::falsification cannot start — the guard already fails on the clean copy")
        print(out)
        return 1
    print(f"clean copy passes; planting {len(entries) + 2} probes")

    # 1. A probe in every guarded function, one at a time.
    for entry in entries:
        path = os.path.join(root, entry["file"])
        original = read(path)
        text, found = guard.extract_function(original, entry["function"])
        if text is None:
            print(
                f"::error::falsification setup failed — cannot extract "
                f"`{entry['function']}` (matches: {found})"
            )
            return 1
        brace = text.index("{")
        poisoned_fn = text[: brace + 1] + "\n    let _falsification_probe = 1;" + text[brace + 1 :]
        write(path, original.replace(text, poisoned_fn, 1))
        expect_failure(
            f"probe in `{entry['function']}`", root, entry["function"]
        )
        write(path, original)

    # 2. The dial moving without the manifest following it.
    version_path = os.path.join(root, guard.VERSION_FILE)
    original = read(version_path)
    bumped = re.sub(
        rf"(const\s+{guard.VERSION_CONST}\s*:\s*u32\s*=\s*)(\d+)",
        lambda m: m.group(1) + str(int(m.group(2)) + 1),
        original,
        count=1,
    )
    if bumped == original:
        print(f"::error::falsification setup failed — could not bump {guard.VERSION_CONST}")
        return 1
    write(version_path, bumped)
    expect_failure("dial bumped without the manifest", root, guard.VERSION_CONST)
    write(version_path, original)

    # 3. A guarded function vanishing from under its pin.
    entry = entries[0]
    path = os.path.join(root, entry["file"])
    original = read(path)
    text, _ = guard.extract_function(original, entry["function"])
    renamed = text.replace(
        f"fn {entry['function']}", f"fn {entry['function']}_relocated", 1
    )
    write(path, original.replace(text, renamed, 1))
    expect_failure(
        f"`{entry['function']}` renamed out from under the pin", root, entry["function"]
    )
    write(path, original)

    code, out = run_guard(root)
    if code != 0:
        print("::error::falsification left the copy dirty — the guard no longer passes")
        print(out)
        return 1

    print("Hydration replay-semantics guard is falsifiable: every probe was caught.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
