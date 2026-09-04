#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
"""Falsify verify-kin-actions-pin-visibility.py against synthetic mutants.

Every probe plants one kin-actions reference the guard must refuse to let
through ungoverned, or removes the tree state one ALLOWLIST entry depends on,
and requires the guard to fail naming the right thing. Two controls run
first and must PASS, so a guard that has stopped recognizing anything and
therefore rejects everything cannot read as "working" by refusing every
probe below for the wrong reason. A probe the guard lets through silently is
worse than no guard: a passing check that proves nothing is exactly the
shape that let kin#1449 happen unnoticed.

Usage: falsify-kin-actions-pin-visibility.py
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
GUARD = REPO_ROOT / "scripts" / "verify-kin-actions-pin-visibility.py"

# ALLOWLIST is checked against the whole scanned tree, not file-by-file: an
# entry that matches nothing anywhere is stale. So every synthetic tree below
# except [6/6], which tests staleness on purpose, carries this companion
# alongside its own probe file, standing in for the real kin-registry-
# release.yml and keeping both real entries satisfied while only the probe
# file is new. Content only has to contain the two allowlisted substrings;
# it does not have to be valid step YAML.
COMPANION_KIN_REGISTRY_RELEASE = (
    "jobs:\n"
    "  prepare-wave:\n"
    "    env:\n"
    "      KIN_ACTIONS_SHA: b424aa4f22684d91abe43d23fa7c4ab5b27c9a2f # v0.1.34\n"
    "    steps:\n"
    "      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0\n"
    "        with:\n"
    "          repository: firelock-ai/kin-actions\n"
    "          ref: ${{ env.KIN_ACTIONS_SHA }}\n"
)


def run_guard(root: Path) -> tuple[int, str]:
    completed = subprocess.run(
        [sys.executable, str(GUARD), str(root)],
        capture_output=True,
        text=True,
        check=False,
    )
    return completed.returncode, completed.stdout + completed.stderr


def make_tree(workflows: dict[str, str]) -> Path:
    root = Path(tempfile.mkdtemp(prefix="kin-actions-pin-falsify-"))
    workflow_dir = root / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    for name, content in workflows.items():
        (workflow_dir / name).write_text(content, encoding="utf-8")
    return root


def expect(
    label: str,
    root: Path,
    *,
    want_pass: bool,
    must_name: str | None = None,
) -> None:
    code, output = run_guard(root)
    passed = code == 0
    if passed != want_pass:
        print(f"FALSIFICATION FAILED: {label}", file=sys.stderr)
        print(
            f"  wanted {'PASS' if want_pass else 'FAIL'}, got "
            f"{'PASS' if passed else 'FAIL'} (exit {code})",
            file=sys.stderr,
        )
        print(output, file=sys.stderr)
        sys.exit(1)
    if must_name is not None and must_name not in output:
        print(f"FALSIFICATION FAILED: {label}", file=sys.stderr)
        print(f"  failed, but never named {must_name!r}", file=sys.stderr)
        print(output, file=sys.stderr)
        sys.exit(1)
    print(f"  ok: {label}")


def main() -> int:
    tmp_roots: list[Path] = []
    try:
        # [1/6] The real repository, today, passes: the two references this
        # guard is coupled to are named in ALLOWLIST and nothing ungoverned
        # has crept into any workflow file since.
        expect("real repository tree passes clean", REPO_ROOT, want_pass=True)

        # [2/6] Positive control on the recognizer: a bare bot-visible pin,
        # alone, must pass with no allowlist entry. If this fails, the
        # recognizer regex is broken, not the governance logic below it, and
        # every FAIL probe after this one would be meaningless. Shaped like
        # the real thing: kin-actions is called as a job-level reusable
        # workflow (`jobs.<id>.uses:`), never as a step inside `steps:`.
        root = make_tree(
            {
                "recognized.yml": (
                    "jobs:\n"
                    "  notify:\n"
                    "    uses: firelock-ai/kin-actions/.github/workflows/"
                    "notify-approver.yml@v0.1.34\n"
                ),
                "kin-registry-release.yml": COMPANION_KIN_REGISTRY_RELEASE,
            }
        )
        tmp_roots.append(root)
        expect("bare bot-visible pin passes alone", root, want_pass=True)

        # [3/6] Positive control on the comment skip: a full-line comment
        # naming kin-actions, alone, must pass without an allowlist entry.
        root = make_tree(
            {
                "commentary.yml": (
                    "# The shared implementation lives in "
                    "firelock-ai/kin-actions.\n"
                    "jobs:\n"
                    "  x:\n"
                    "    steps:\n"
                    "      - run: echo hi\n"
                ),
                "kin-registry-release.yml": COMPANION_KIN_REGISTRY_RELEASE,
            }
        )
        tmp_roots.append(root)
        expect(
            "full-line comment mention passes without allowlisting",
            root,
            want_pass=True,
        )

        # [4/6] The actual bug class: a fresh KIN_ACTIONS_SHA-shaped env pin
        # with no allowlist entry must fail, naming the file it appeared in.
        root = make_tree(
            {
                "new-consumer.yml": (
                    "jobs:\n"
                    "  x:\n"
                    "    env:\n"
                    "      KIN_ACTIONS_SHA: "
                    "0123456789abcdef0123456789abcdef01234567 # v9.9.9\n"
                    "    steps:\n"
                    "      - run: echo hi\n"
                ),
                "kin-registry-release.yml": COMPANION_KIN_REGISTRY_RELEASE,
            }
        )
        tmp_roots.append(root)
        expect(
            "new ungoverned KIN_ACTIONS_SHA pin fails",
            root,
            want_pass=False,
            must_name="new-consumer.yml",
        )

        # [5/6] The other half of the same bug: a fresh checkout-by-repository
        # reference with no allowlist entry must also fail.
        root = make_tree(
            {
                "new-checkout.yml": (
                    "jobs:\n"
                    "  x:\n"
                    "    steps:\n"
                    "      - uses: actions/checkout@"
                    "9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0\n"
                    "        with:\n"
                    "          repository: firelock-ai/kin-actions\n"
                    "          ref: deadbeefdeadbeefdeadbeefdeadbeefdeadbeef\n"
                ),
                "kin-registry-release.yml": COMPANION_KIN_REGISTRY_RELEASE,
            }
        )
        tmp_roots.append(root)
        expect(
            "new ungoverned checkout reference fails",
            root,
            want_pass=False,
            must_name="new-checkout.yml",
        )

        # [6/6] A stale ALLOWLIST entry must fail too, so the allowlist can
        # only ever shrink honestly, by deleting the entry, never by drifting
        # out of sync with a tree that moved the pin without it. Neither
        # allowlisted substring appears anywhere in this fixture tree, so
        # both entries go stale at once; the guard need only report one.
        root = make_tree(
            {
                "kin-registry-release.yml": (
                    "jobs:\n"
                    "  x:\n"
                    "    steps:\n"
                    "      - run: echo the pin moved elsewhere\n"
                )
            }
        )
        tmp_roots.append(root)
        expect(
            "stale ALLOWLIST entry fails",
            root,
            want_pass=False,
            must_name="stale ALLOWLIST entry",
        )

        print(
            "verify-kin-actions-pin-visibility.py is falsifiable: "
            "every probe was caught."
        )
        return 0
    finally:
        for root in tmp_roots:
            shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
