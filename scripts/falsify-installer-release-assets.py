#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

"""Prove the installer asset guard can fail, one poisoned tree at a time.

A guard that passes before and after a fix is not evidence. Each probe below
plants exactly one disagreement between what an install surface asks a release
for and what that release publishes, and requires
`scripts/verify-installer-release-assets.py` to fail and to name the asset it
could not find. The first probe reproduces the defect that shipped through every
release to date: the Windows leg published only a `.zip` while the POSIX
installer asked every platform, Windows included, for a `.tar.gz`.

The last two probes are about the guard's own honesty rather than about a
missing asset: a new release platform must not arrive unguarded, and a probe
that cannot read what the installer asks for must say so instead of deriving
nothing and passing.
"""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
GUARD = "scripts/verify-installer-release-assets.py"
COPIED = (
    "scripts/install.sh",
    "scripts/install.ps1",
    GUARD,
    "packages/kin/lib/provision.mjs",
    "packages/kin/lib/resolve.mjs",
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

    Requiring uniqueness is not pedantry. The near-miss probe first landed on
    the attestation list because the bare asset name appears in several lists,
    which left the list under test untouched and the guard correctly green, so
    the probe proved nothing while reporting that it had.
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


def run_guard(tree: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(tree / GUARD), *args],
        capture_output=True,
        text=True,
        timeout=900,
        check=False,
    )


def expect_failure(label: str, tree: Path, wanted: str, *args: str) -> None:
    completed = run_guard(tree, *args)
    output = completed.stdout + completed.stderr
    if completed.returncode == 0:
        raise FalsificationError(
            f"falsification failed: {label} did not fail the guard.\n{output}"
        )
    if wanted not in output:
        raise FalsificationError(
            f"falsification failed: {label} failed but never named {wanted!r}.\n{output}"
        )
    print(f"  ok: {label}")


def expect_success(label: str, tree: Path, *args: str) -> None:
    completed = run_guard(tree, *args)
    output = completed.stdout + completed.stderr
    if completed.returncode != 0:
        raise FalsificationError(
            f"falsification failed: {label} should pass the guard.\n{output}"
        )
    print(f"  ok: {label}")


def published_assets(tree: Path) -> list[str]:
    """Read the probe tree's own published file list through the guard's parser."""
    spec = importlib.util.spec_from_file_location("probe_guard", tree / GUARD)
    if spec is None or spec.loader is None:
        raise FalsificationError("could not load the probe tree's guard module")
    module = importlib.util.module_from_spec(spec)
    # Registered before execution: the guard's dataclasses resolve their own
    # module out of sys.modules while the class body is being processed.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    workflow = (tree / ".github/workflows/release.yml").read_text(encoding="utf-8")
    return module.workflow_step_block(workflow, module.RELEASE_STEP, module.RELEASE_FILES_KEY)


def unmodified_tree_passes(tree: Path) -> None:
    expect_success("an unmodified tree passes (positive control)", tree)


def windows_tarball_unpublished(tree: Path) -> None:
    # The exact state every release shipped in: the POSIX installer asks Windows
    # for a tarball and the release publishes only the zip.
    poison(
        tree,
        ".github/workflows/release.yml",
        "            kin-windows-x86_64.tar.gz\n            kin-windows-x86_64.tar.gz.sha256\n",
        "",
    )
    expect_failure(
        "the Windows tarball is not published", tree, "kin-windows-x86_64.tar.gz"
    )


def windows_tarball_arch_token_near_miss(tree: Path) -> None:
    # A near miss on the architecture token 404s exactly like an absent asset
    # while every other check still sees a Windows tarball being published. The
    # publish list is anchored through its checksum sidecar, because the same
    # bare file name also appears in the attestation subjects and a mutation
    # planted there would leave the list under test untouched.
    poison(
        tree,
        ".github/workflows/release.yml",
        "            kin-windows-x86_64.tar.gz\n            kin-windows-x86_64.tar.gz.sha256\n",
        "            kin-windows-amd64.tar.gz\n            kin-windows-amd64.tar.gz.sha256\n",
    )
    expect_failure(
        "the published Windows tarball carries the wrong arch token",
        tree,
        "kin-windows-x86_64.tar.gz",
    )


def windows_tarball_unattested(tree: Path) -> None:
    # Published but absent from the attestation subjects: the download resolves
    # and then fails verification, which reads to a user like a broken asset.
    poison(
        tree,
        ".github/workflows/release.yml",
        "            kin-windows-x86_64.zip\n            kin-windows-x86_64.tar.gz\n            release-provenance.json\n",
        "            kin-windows-x86_64.zip\n            release-provenance.json\n",
    )
    expect_failure(
        "the Windows tarball is published but not attested",
        tree,
        "the release attestation subject list",
    )


def windows_tarball_uninventoried(tree: Path) -> None:
    poison(
        tree,
        ".github/workflows/release.yml",
        "            kin-windows-x86_64.zip\n            kin-windows-x86_64.tar.gz\n          )\n",
        "            kin-windows-x86_64.zip\n          )\n",
    )
    expect_failure(
        "the Windows tarball is published but not inventoried",
        tree,
        "the release asset inventory",
    )


def windows_zip_unpublished(tree: Path) -> None:
    poison(
        tree,
        ".github/workflows/release.yml",
        "            kin-windows-x86_64.zip\n            kin-windows-x86_64.zip.sha256\n",
        "",
    )
    expect_failure("the Windows zip is not published", tree, "kin-windows-x86_64.zip")


def installer_extension_drift(tree: Path) -> None:
    # The names must be read out of the installer rather than restated here: a
    # changed extension has to show up as a changed requirement.
    poison(tree, "scripts/install.sh", 'ARCHIVE="kin-${TARGET}.tar.gz"', 'ARCHIVE="kin-${TARGET}.tgz"')
    expect_failure(
        "the POSIX installer asks for a different extension",
        tree,
        "kin-linux-x86_64.tgz",
    )


def unguarded_release_platform(tree: Path) -> None:
    poison(
        tree,
        ".github/workflows/release.yml",
        "            artifact: kin-windows-x86_64\n",
        "            artifact: kin-windows-aarch64\n",
    )
    expect_failure(
        "a release platform has no guarded install surface",
        tree,
        "kin-windows-aarch64",
    )


def unreadable_installer_probe(tree: Path) -> None:
    # If the probe cannot read what the installer asks for, it must report that
    # rather than deriving nothing and reporting agreement.
    poison(tree, "scripts/install.sh", 'info "Downloading $ARCHIVE..."', "true")
    expect_failure(
        "the probe cannot read what the installer downloads",
        tree,
        "expected exactly one",
    )


def staged_release_assets(tree: Path) -> None:
    # The mode the release itself runs in: check the bytes about to be uploaded,
    # not the workflow's intent.
    staged = tree / "staged-assets"
    staged.mkdir()
    names = published_assets(tree)
    for name in names:
        (staged / name).write_text("probe\n", encoding="utf-8")
    expect_success(
        "staged release assets carrying every requested name pass",
        tree,
        "--assets-dir",
        str(staged),
    )
    (staged / "kin-windows-x86_64.tar.gz").unlink()
    expect_failure(
        "staged release assets missing the Windows tarball fail",
        tree,
        "kin-windows-x86_64.tar.gz",
        "--assets-dir",
        str(staged),
    )


PROBES: tuple[tuple[str, Callable[[Path], None]], ...] = (
    ("positive control", unmodified_tree_passes),
    ("windows tarball unpublished", windows_tarball_unpublished),
    ("windows tarball arch token near miss", windows_tarball_arch_token_near_miss),
    ("windows tarball unattested", windows_tarball_unattested),
    ("windows tarball uninventoried", windows_tarball_uninventoried),
    ("windows zip unpublished", windows_zip_unpublished),
    ("installer extension drift", installer_extension_drift),
    ("unguarded release platform", unguarded_release_platform),
    ("unreadable installer probe", unreadable_installer_probe),
    ("staged release assets", staged_release_assets),
)


def main() -> int:
    for index, (label, probe) in enumerate(PROBES, start=1):
        print(f"[{index}/{len(PROBES)}] {label}")
        with tempfile.TemporaryDirectory() as temp:
            tree = probe_tree(Path(temp))
            try:
                probe(tree)
            except FalsificationError as error:
                print(f"::error::{error}", file=sys.stderr)
                return 1
    print(f"installer asset guard falsified through {len(PROBES)} probes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
