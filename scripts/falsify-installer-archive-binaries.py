#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

"""Prove the archive binary guard can fail, one poisoned tree at a time.

A guard nobody has watched fail is not evidence. Each probe below plants exactly
one disagreement between the binary names `scripts/install.sh` uses after
extracting an archive and the names the release actually packs into it, and
requires `scripts/verify-installer-archive-binaries.py` to fail.

The first probe reproduces the defect itself: the mandatory-daemon assertion
naming a bare `kin-daemon` inside a Windows archive that carries
`kin-daemon.exe`, which aborted the install after the download had already been
fetched and verified.

The last two probes are about the guard's own honesty rather than about a
mismatched name. A guard that cannot read what the installer asks for, or that
cannot read the release's own record of which binaries are mandatory, must say
so rather than derive nothing and report success.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
GUARD = "scripts/verify-installer-archive-binaries.py"
COPIED = (
    "scripts/install.sh",
    GUARD,
    ".github/workflows/release.yml",
)


class FalsificationError(RuntimeError):
    """The guard did not fail where it must, so it proves nothing."""


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

    Requiring uniqueness is what stops a probe from mutating a line the guard
    never reads, leaving the guard correctly green while the probe reports that
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


def run_guard(tree: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(tree / GUARD)],
        check=False,
        capture_output=True,
        text=True,
    )


def expect_failure(label: str, expected: str, mutate: Callable[[Path], None]) -> str:
    with tempfile.TemporaryDirectory() as temp:
        tree = probe_tree(Path(temp))
        mutate(tree)
        result = run_guard(tree)
    if result.returncode == 0:
        raise FalsificationError(
            f"{label}: the guard passed a tree it must reject.\n"
            f"        {result.stdout.strip()}"
        )
    output = f"{result.stdout}\n{result.stderr}"
    if expected not in output:
        raise FalsificationError(
            f"{label}: the guard failed, but not for the planted reason.\n"
            f"        expected to see {expected!r}\n"
            f"        got: {output.strip()}"
        )
    return f"{label}: rejected, naming {expected!r}"


PROBES: tuple[tuple[str, str, Callable[[Path], None]], ...] = (
    (
        "the shipped defect: mandatory daemon named without its suffix",
        "install.sh failed against a complete kin-windows-x86_64 archive",
        lambda tree: poison(
            tree,
            "scripts/install.sh",
            'if [ ! -f "$EXTRACT_DIR/kin-daemon$BIN_EXT" ]; then',
            'if [ ! -f "$EXTRACT_DIR/kin-daemon" ]; then',
        ),
    ),
    (
        "the suffix derivation neutered for windows",
        "install.sh failed against a complete kin-windows-x86_64 archive",
        lambda tree: poison(
            tree,
            "scripts/install.sh",
            'windows) BIN_EXT=".exe" ;;',
            'windows) BIN_EXT="" ;;',
        ),
    ),
    (
        "binaries installed under names the archive never carried",
        "kin-windows-x86_64",
        lambda tree: poison(
            tree,
            "scripts/install.sh",
            'mv "$EXTRACT_DIR/$bin$BIN_EXT" "$KIN_BIN/$bin$BIN_EXT"',
            'mv "$EXTRACT_DIR/$bin$BIN_EXT" "$KIN_BIN/$bin"',
        ),
    ),
    (
        "the release leg packaging a daemon the installer cannot name",
        "unaccounted for",
        lambda tree: poison(
            tree,
            ".github/workflows/release.yml",
            'Copy-Item "target/$env:TARGET/release/kin-daemon.exe" "$env:ARTIFACT/" -ErrorAction Stop',
            'Copy-Item "target/$env:TARGET/release/kin-daemon" "$env:ARTIFACT/" -ErrorAction Stop',
        ),
    ),
    (
        "an installer that no longer names what it downloads",
        "cannot read what it asks for",
        lambda tree: poison(
            tree,
            "scripts/install.sh",
            'info "Downloading $ARCHIVE..."',
            'info "Fetching $ARCHIVE"',
        ),
    ),
    (
        "one of the release's mandatory binary records made unreadable",
        "can be read",
        lambda tree: poison(
            tree,
            ".github/workflows/release.yml",
            '            target.includes("-windows-")\n'
            '              ? ["kin.exe", "kin-daemon.exe"]',
            '            target.includes("-windows-")\n'
            "              ? windowsAuthorityNames()",
        ),
    ),
)


def main() -> int:
    lines: list[str] = []
    try:
        for label, expected, mutate in PROBES:
            lines.append(expect_failure(label, expected, mutate))
    except FalsificationError as error:
        print(f"archive binary guard falsification FAILED\n  {error}", file=sys.stderr)
        return 1

    print(f"archive binary guard rejected all {len(PROBES)} poisoned trees:")
    for line in lines:
        print(f"  {line}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
