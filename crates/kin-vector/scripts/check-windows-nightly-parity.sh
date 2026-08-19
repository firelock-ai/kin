#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
#
# The Windows leg was moved out of the CI matrix and onto a nightly schedule.
# The claim that makes that safe is that it was MOVED rather than reduced: the
# nightly runs the same steps the matrix leg ran, so a nightly failure means
# what the pull-request failure meant.
#
# Nothing enforces that claim by itself. Two workflow files holding the same
# step list drift the first time somebody edits one of them, and the drift is
# invisible in both directions: a step added to CI and not to the nightly
# silently narrows the Windows coverage, and a lint allowance added to CI and
# not to the nightly turns the alarm into a false-alarm generator that teaches
# its readers to ignore it.
#
# So the parity is checked here, from the required CI job, where a divergence
# fails the pull request that introduced it.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

python3 - "$root" <<'PY'
import sys
from pathlib import Path

root = Path(sys.argv[1])
CI = root / ".github/workflows/ci.yml"
NIGHTLY = root / ".github/workflows/windows-nightly.yml"


def steps_of(path, job_key):
    """Return the `steps:` block of one job, normalised for comparison."""

    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    start = None
    for index, line in enumerate(lines):
        if line == f"  {job_key}:":
            start = index
            break
    if start is None:
        sys.exit(f"FAIL: no job '{job_key}' in {path}")

    end = len(lines)
    for index in range(start + 1, len(lines)):
        line = lines[index]
        if line.strip() and not line.startswith("   ") and line.startswith("  "):
            end = index
            break

    block = lines[start:end]
    try:
        steps_at = next(i for i, l in enumerate(block) if l.strip() == "steps:")
    except StopIteration:
        sys.exit(f"FAIL: job '{job_key}' in {path} declares no steps")

    body = [l.rstrip() for l in block[steps_at + 1:]]
    while body and not body[-1]:
        body.pop()
    if not body:
        sys.exit(f"FAIL: job '{job_key}' in {path} has an empty steps block")
    return body


ci_steps = steps_of(CI, "check")
nightly_steps = steps_of(NIGHTLY, "windows")

# The extraction has to be able to find something, or every comparison below
# passes for free on two empty lists.
for label, block in (("ci.yml check", ci_steps), ("windows-nightly.yml windows", nightly_steps)):
    if len([l for l in block if l.strip().startswith("- ")]) < 2:
        sys.exit(f"FAIL: extracted fewer than two steps from {label}; the check is vacuous")

if ci_steps != nightly_steps:
    print("FAIL: the nightly Windows job no longer runs the CI matrix steps.")
    print("")
    print("The nightly exists to carry the Windows leg that used to ride the CI")
    print("matrix. Once the two step lists differ, a green nightly stops meaning")
    print("what a green Windows leg meant, in whichever direction the edit went.")
    print("Apply the change to both files, or delete the nightly and say so.")
    print("")
    import difflib

    for line in difflib.unified_diff(
        ci_steps, nightly_steps,
        fromfile="ci.yml (job: check)",
        tofile="windows-nightly.yml (job: windows)",
        lineterm="",
    ):
        print(line)
    sys.exit(1)

print(f"OK: the nightly Windows job runs the same {len(ci_steps)} step lines as CI's matrix.")
PY
