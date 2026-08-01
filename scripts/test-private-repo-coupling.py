#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

"""Deterministic tests for the private repo coupling guard.

The guard excludes its own pattern list with ripgrep globs, and ripgrep anchors
a glob containing a slash to the working directory rather than to the path it is
told to search. A guard that searched an absolute repo root therefore matched
its exclusions only when it happened to be invoked from that root, and reported
its own patterns as coupling from anywhere else. That shape cannot turn CI red,
because CI always invokes it from the root, so it is pinned here instead: every
case below runs the guard from a working directory that is not the tree it
scans.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path


SCRIPTS_DIR = Path(__file__).resolve().parent
GUARD = SCRIPTS_DIR / "check_private_repo_coupling.sh"
GUARD_RELATIVE = f"scripts/{GUARD.name}"

# The private project name, assembled so this file's own source never carries a
# reference the guard rejects. A test that plants coupling has to spell it out,
# and spelling it out in source would make the test itself a hit.
PRIVATE = "kin" + "lab"

# One reference of each shape the guard rejects, so a fixture proves the guard
# still fires rather than only that it stays quiet.
COUPLING_REFERENCES = (
    f"../{PRIVATE}",
    f"{PRIVATE}.git",
    f"pnpm --filter @{PRIVATE}/web",
    f"@{PRIVATE}/control-plane",
    f"@{PRIVATE}/web",
    f"{PRIVATE}-control-plane",
    f"{PRIVATE}-web",
    f"cargo install --git https://example.invalid/{PRIVATE}",
)


def run_guard(guard: Path, cwd: Path) -> subprocess.CompletedProcess[str]:
    """Run `guard` from `cwd`, which is never the tree the guard scans."""
    return subprocess.run(
        ["bash", str(guard)],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        check=False,
    )


def make_fixture_tree(tmp: Path) -> Path:
    """A minimal repository carrying a copy of the guard and clean sources."""
    repo = tmp / "repo"
    (repo / "scripts").mkdir(parents=True)
    shutil.copy2(GUARD, repo / GUARD_RELATIVE)
    (repo / "src").mkdir()
    (repo / "src/lib.rs").write_text("pub fn kin() -> &'static str { \"kin\" }\n")
    (repo / "README.md").write_text("# fixture\n\nNo private references here.\n")
    return repo


def test_clean_fixture_passes_from_a_foreign_working_directory() -> None:
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        repo = make_fixture_tree(tmp)
        elsewhere = tmp / "elsewhere"
        elsewhere.mkdir()

        result = run_guard(repo / GUARD_RELATIVE, elsewhere)

        assert result.returncode == 0, (
            "the guard must exclude its own pattern list wherever it is invoked "
            f"from; stdout={result.stdout!r} stderr={result.stderr!r}"
        )
        assert "passed" in result.stdout


def test_the_verdict_does_not_depend_on_the_working_directory() -> None:
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        repo = make_fixture_tree(tmp)
        elsewhere = tmp / "elsewhere"
        elsewhere.mkdir()
        guard = repo / GUARD_RELATIVE

        from_root = run_guard(guard, repo)
        from_elsewhere = run_guard(guard, elsewhere)
        from_filesystem_root = run_guard(guard, Path("/"))

        codes = {
            from_root.returncode,
            from_elsewhere.returncode,
            from_filesystem_root.returncode,
        }
        assert codes == {0}, f"the guard's verdict moved with the caller's cwd: {codes}"


def test_a_planted_coupling_still_fails_from_a_foreign_working_directory() -> None:
    for reference in COUPLING_REFERENCES:
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            repo = make_fixture_tree(tmp)
            elsewhere = tmp / "elsewhere"
            elsewhere.mkdir()
            planted = repo / "docs/dev-setup.md"
            planted.parent.mkdir()
            planted.write_text(f"Build the console with `{reference}` first.\n")

            result = run_guard(repo / GUARD_RELATIVE, elsewhere)

            assert result.returncode == 1, (
                f"a planted {reference!r} must fail the guard; "
                f"stdout={result.stdout!r} stderr={result.stderr!r}"
            )
            assert "docs/dev-setup.md" in result.stderr, (
                f"the guard must name the coupled file for {reference!r}: "
                f"{result.stderr!r}"
            )
            assert GUARD_RELATIVE not in result.stderr, (
                "the guard must not report its own pattern list beside a real "
                f"hit: {result.stderr!r}"
            )


def test_the_real_repository_passes_from_a_foreign_working_directory() -> None:
    with tempfile.TemporaryDirectory() as raw:
        result = run_guard(GUARD, Path(raw))

        assert result.returncode == 0, (
            "the checked-in tree must pass its own coupling guard from any "
            f"working directory; stdout={result.stdout!r} stderr={result.stderr!r}"
        )


def main() -> None:
    if shutil.which("rg") is None:
        raise SystemExit("private repo coupling guard tests require ripgrep (rg)")
    tests = (
        test_clean_fixture_passes_from_a_foreign_working_directory,
        test_the_verdict_does_not_depend_on_the_working_directory,
        test_a_planted_coupling_still_fails_from_a_foreign_working_directory,
        test_the_real_repository_passes_from_a_foreign_working_directory,
    )
    for test in tests:
        test()
        print(f"PASS: {test.__name__}")
    print(f"{len(tests)} private repo coupling guard tests passed")


if __name__ == "__main__":
    main()
