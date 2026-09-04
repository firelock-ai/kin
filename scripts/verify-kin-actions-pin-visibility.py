#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
"""Fail when a kin-actions reference exists that the workflow-pin bot cannot see.

The dedicated `kin-workflow-pin[bot]` App (firelock-ai/kin-actions,
scripts/update-kin-actions-pins.py) rewrites exactly one shape of pin:

    uses: firelock-ai/kin-actions/.github/workflows/<file>.yml@v<semver>

Its manifest (firelock-ai/kin-actions .kin-release/consumers.json) lists the
workflow paths it owns in this repository, and its own self-check refuses a
manifest that is not exact. Both of those live in a different repository and
can only ever police the shape they already recognize. Neither can see a
kin-actions reference that never becomes a `uses:` value at all, which is
exactly how kin#1449 happened: `kin-registry-release.yml` pins kin-actions
through a job-level `KIN_ACTIONS_SHA` environment variable, consumed by
`actions/checkout`'s `repository:`/`ref:` inputs to check kin-actions out as a
script library and run its scripts in-job rather than call it as a reusable
workflow. The bot bumped three other files in kin#1450 the same night; this
one had to be moved by hand in kin#1449, and nothing reported the gap.

This guard runs entirely inside this repository: it scans every workflow file
for a live reference to `firelock-ai/kin-actions` or a `KIN_ACTIONS`-named
variable, accepts the one shape the bot owns, and requires everything else to
be named, with a reason, in the ALLOWLIST below. An unnamed reference fails
the build. An allowlist entry that no longer matches anything live fails it
too, the same direction verify-zero-file-search.py's own allowlist is held
to: a stale entry cannot silently keep excusing something that moved.

Full-line comments are skipped: a prose mention of kin-actions carries no
version to go stale, and this repository already has several. A mention
inside a trailing comment on an otherwise-live code line is out of scope, the
same trade check-docker-daemon-features.sh makes reading line-shaped text
instead of parsing YAML: every case here today is a whole-line comment, and
the day that stops being true is the day this needs a real YAML parser
instead of a line scan.

Usage: verify-kin-actions-pin-visibility.py [repo_root]

The optional repo_root selects the tree to scan (default: the repository
containing this script). The allowlist always travels with the script, which
lets a falsifier point the guard at a synthetic tree and assert it fails.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

BOT_VISIBLE_PIN = re.compile(
    r"^\s*uses:\s*firelock-ai/kin-actions/\.github/workflows/"
    r"[A-Za-z0-9_.-]+\.ya?ml@v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\b"
)

# Any of these appearing on a non-comment line means the line is talking
# about a specific kin-actions commit or release: exactly what the bot's own
# rewrite has to be able to find, and was never built to look for outside a
# `uses:` scalar.
REFERENCE_HINTS = (
    re.compile(r"firelock-ai/kin-actions"),
    re.compile(r"KIN_ACTIONS"),
)

# Every reference the scan finds outside the bot-visible shape has to be
# named here, with a reason. "match" is a substring: exact enough to identify
# the one thing it excuses, loose enough to survive the sha or version inside
# it changing under a hand-edit.
ALLOWLIST = [
    {
        "file": ".github/workflows/kin-registry-release.yml",
        "match": "KIN_ACTIONS_SHA",
        "reason": (
            "kin-actions is checked out as a script library and its scripts "
            "(update-cargo-registry-deps.py, validate-dependency-wave.py) "
            "run inline in this job, sharing its cargo/registry state, "
            "rather than being called as a workflow_call reusable workflow "
            "in a job of their own. It is deliberately sha-pinned, matching "
            "every other external action in this file, rather than "
            "tag-pinned like a bot-managed pin. update-kin-actions-pins.py "
            "only rewrites `uses: firelock-ai/kin-actions/.github/"
            "workflows/*.yml@vX.Y.Z`; this pin needs a human, or a taught "
            "bot, on every kin-actions release until the mechanism changes."
        ),
    },
    {
        "file": ".github/workflows/kin-registry-release.yml",
        "match": "repository: firelock-ai/kin-actions",
        "reason": "The checkout that KIN_ACTIONS_SHA (above) pins. Same gap.",
    },
]


def is_comment(line: str) -> bool:
    return line.lstrip().startswith("#")


def find_references(text: str) -> list[tuple[int, str]]:
    """Return (line_number, line) for every non-comment line that names a
    specific kin-actions reference outside the bot-visible pin shape."""

    found: list[tuple[int, str]] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if is_comment(line):
            continue
        if BOT_VISIBLE_PIN.match(line):
            continue
        if any(hint.search(line) for hint in REFERENCE_HINTS):
            found.append((lineno, line))
    return found


def check(root: Path) -> list[str]:
    root = root.resolve()
    workflow_dir = root / ".github" / "workflows"
    if not workflow_dir.is_dir():
        return [f"no .github/workflows directory under {root}"]

    live: dict[str, list[tuple[int, str]]] = {}
    for path in sorted(workflow_dir.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        if path.suffix not in (".yml", ".yaml"):
            continue
        relative = path.relative_to(root).as_posix()
        refs = find_references(path.read_text(encoding="utf-8"))
        if refs:
            live[relative] = refs

    errors: list[str] = []
    matched_allowlist: set[int] = set()
    for relative, refs in live.items():
        for lineno, line in refs:
            covered = False
            for index, entry in enumerate(ALLOWLIST):
                if entry["file"] == relative and entry["match"] in line:
                    covered = True
                    matched_allowlist.add(index)
                    break
            if not covered:
                errors.append(
                    f"{relative}:{lineno}: kin-actions reference is not the "
                    "bot-visible `uses: firelock-ai/kin-actions/.github/"
                    "workflows/*.yml@vX.Y.Z` pin and is not named in "
                    f"ALLOWLIST: {line.strip()!r}"
                )

    # Never short-circuit on a stale entry: report it alongside whatever else
    # was found, the same order verify-zero-file-search.py holds its own
    # allowlist to, so a red run always shows every problem it can see.
    for index, entry in enumerate(ALLOWLIST):
        if index not in matched_allowlist:
            errors.append(
                "stale ALLOWLIST entry matches nothing in the tree: "
                f"{entry['file']} {entry['match']!r}"
            )

    return errors


def main(argv: list[str]) -> int:
    root = Path(argv[1]) if len(argv) > 1 else Path(__file__).resolve().parent.parent
    errors = check(root)
    if errors:
        print(
            f"kin-actions pin visibility check FAILED ({len(errors)} problem(s)):",
            file=sys.stderr,
        )
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    print("kin-actions pin visibility check: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
