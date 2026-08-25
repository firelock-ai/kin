#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

"""Prove the two release version guards can fail, one poisoned tree at a time.

Both guards here are guards that already existed and could not fail. The
release version gate has carried the right refusal since before the release
train did and ran on no pull request; the release-intent gate read a version
whose tag already existed, called that nothing to release, and exited 0 on a
fifteen-minute cron with no tag cut and no alarm raised. A suite written for
guards of that shape has to be watched failing before it counts as evidence.

Each probe plants exactly one mutation in a copy of the tree and requires the
suite that covers it to go red naming the test that caught it. Half the probes
break the refusal, and half break the pass: a gate that refused every cycle
would be switched off within a day, so the green rows carry the same burden of
proof as the red ones.

The wiring is falsified elsewhere and on purpose. Whether ci.yml actually runs
the version gate on a pull request is asserted by
`assert_release_version_gate_wired` in scripts/test-release-workflow-authority.py,
which falsifies itself against a ci.yml with the job removed, the step
commented out, and the tests dropped. That is the half of this defect no unit
test can reach, because the script was always correct.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
INTENT = "scripts/release-intent.mjs"
INTENT_SUITE = "scripts/release-intent.test.mjs"
VERSION = "scripts/check-release-version.mjs"
VERSION_SUITE = "scripts/check-release-version.test.mjs"
COPIED = (INTENT, INTENT_SUITE, VERSION, VERSION_SUITE)


class FalsificationError(RuntimeError):
    """The suite did not fail where it must, so it proves nothing."""


def probe_tree(destination: Path) -> Path:
    for relative in COPIED:
        source = ROOT / relative
        if not source.is_file():
            raise FalsificationError(f"cannot build a probe tree without {relative}")
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    return destination


def poison(tree: Path, relative: str, old: str, new: str) -> None:
    """Plant one mutation at an anchor that appears exactly once.

    Requiring uniqueness is what stops a probe from mutating a line the suite
    never reads, leaving the suite correctly green while the probe reports that
    it proved something.
    """
    path = tree / relative
    source = path.read_text(encoding="utf-8")
    found = source.count(old)
    if found != 1:
        raise FalsificationError(
            f"probe could not plant its mutation: {relative} contains {found} "
            f"occurrences of {old!r}, expected exactly one"
        )
    path.write_text(source.replace(old, new, 1), encoding="utf-8")


def run_suite(tree: Path, suite: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["node", "--test", str(tree / suite)],
        check=False,
        capture_output=True,
        text=True,
        cwd=tree,
    )


def expect_failure(
    label: str,
    suite: str,
    expected: str,
    mutate: Callable[[Path], None],
) -> str:
    with tempfile.TemporaryDirectory() as temp:
        tree = probe_tree(Path(temp))
        mutate(tree)
        result = run_suite(tree, suite)
    if result.returncode == 0:
        raise FalsificationError(
            f"{label}: the suite passed against a poisoned tree, so it cannot "
            "fail on this defect"
        )
    output = f"{result.stdout}{result.stderr}"
    if "not ok" not in output or expected not in output:
        raise FalsificationError(
            f"{label}: the suite failed but never named {expected!r}, so the "
            "failure is not evidence about this defect\n" + output[-4000:]
        )
    return f"{label} -> {expected}"


# Anchors are the exact source lines the guards decide on. Each is unique in
# its file, which `poison` enforces, so a probe cannot quietly mutate something
# the suite does not read.
PROBES: tuple[tuple[str, str, str, Callable[[Path], None]], ...] = (
    (
        "the mint stops refusing a release whose bump never landed",
        INTENT_SUITE,
        "a release-affecting commit stranded behind an existing tag refuses loudly",
        lambda tree: poison(
            tree,
            INTENT,
            "  if (tagExists && strandedPaths.length > 0) {",
            "  if (false && tagExists && strandedPaths.length > 0) {",
        ),
    ),
    (
        "the mint refuses a quiet cycle it should have passed",
        INTENT_SUITE,
        "documentation stranded behind an existing tag stays a green no-op",
        lambda tree: poison(
            tree,
            INTENT,
            "export function classifyPath(path) {",
            "export function classifyPath(path) {\n  if (path) return 'release';",
        ),
    ),
    (
        "the copied classifier drifts from the one the version gate uses",
        INTENT_SUITE,
        "the copied classifier agrees with the version gate on every branch",
        lambda tree: poison(
            tree,
            INTENT,
            "    lower.startsWith('.github/') ||\n"
            "    lower.startsWith('docs/') ||\n"
            "    lower === 'agents.md' ||",
            "    lower.startsWith('docs/') ||\n" "    lower === 'agents.md' ||",
        ),
    ),
    (
        "a relative import creeps into the file the mint copies alone",
        INTENT_SUITE,
        "the gate imports nothing relative, so a single-file copy still runs",
        lambda tree: poison(
            tree,
            INTENT,
            "import { promisify } from 'node:util';",
            "import { promisify } from 'node:util';\n"
            "import { parseVersion } from './check-release-version.mjs';",
        ),
    ),
    (
        "the entry point goes back to comparing unresolved paths",
        INTENT_SUITE,
        "the gate runs from a copy reached through a symlinked directory",
        lambda tree: poison(
            tree,
            INTENT,
            "  try {\n"
            "    return realpathSync(entry) === realpathSync(self);\n"
            "  } catch {\n"
            "    return true;\n"
            "  }",
            "  return false;",
        ),
    ),
    (
        "the version gate stops refusing a release-affecting diff with no bump",
        VERSION_SUITE,
        "a release-affecting change with no bump is refused end to end",
        lambda tree: poison(
            tree,
            VERSION,
            "  if (releasePaths.length > 0 && !versionMoved) {",
            "  if (false && releasePaths.length > 0 && !versionMoved) {",
        ),
    ),
    (
        "the version gate stops refusing a bump that skips a version",
        VERSION_SUITE,
        "a bump that skips a version is refused end to end",
        lambda tree: poison(
            tree,
            VERSION,
            "  if (versionMoved && headVersion !== expected) {",
            "  if (false && versionMoved && headVersion !== expected) {",
        ),
    ),
    (
        "the version gate's entry point goes back to unresolved paths",
        VERSION_SUITE,
        "the gate runs from a copy reached through a symlinked directory",
        lambda tree: poison(
            tree,
            VERSION,
            "  try {\n"
            "    return realpathSync(entry) === realpathSync(self);\n"
            "  } catch {\n"
            "    return true;\n"
            "  }",
            "  return false;",
        ),
    ),
    (
        "the version gate starts demanding a bump for documentation",
        VERSION_SUITE,
        "a documentation-only release pull request needs no bump",
        lambda tree: poison(
            tree,
            VERSION,
            "export function classifyPath(path) {",
            "export function classifyPath(path) {\n  if (path) return 'release';",
        ),
    ),
)


def main() -> int:
    lines: list[str] = []
    try:
        for label, suite, expected, mutate in PROBES:
            lines.append(expect_failure(label, suite, expected, mutate))
    except FalsificationError as error:
        print(
            f"release version guard falsification FAILED\n  {error}",
            file=sys.stderr,
        )
        return 1

    print(f"the release version guards rejected all {len(PROBES)} poisoned trees:")
    for line in lines:
        print(f"  {line}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
