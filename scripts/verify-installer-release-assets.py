#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

"""Fail when a public installer asks a release for an asset it does not publish.

Every install surface builds a release asset name from the platform it detects,
and the release publishes a fixed list of asset names. Nothing compared the two
lists, so a disagreement shipped through every release to date: the POSIX
installer builds `kin-<os>-<arch>.tar.gz` on every platform it supports,
including the MSYS, MINGW, and CYGWIN shells it maps to `windows`, while the
Windows leg published only a `.zip`. Piping the documented curl command into a
shell on Windows therefore 404'd.

The names checked here are DERIVED from the installers rather than restated.
`scripts/install.sh` is executed once per platform against a stubbed `uname` and
asked what it would download; `packages/kin/lib/provision.mjs` exports the pure
function the npm launcher resolves with and is called directly; `install.ps1`
carries its construction in two literal assignments that are parsed under
anchored patterns that fail rather than skip when the source moves. A guard that
restated the expected names would agree with itself forever.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
INSTALL_SH = ROOT / "scripts" / "install.sh"
INSTALL_PS1 = ROOT / "scripts" / "install.ps1"
NPM_PROVISION = ROOT / "packages" / "kin" / "lib" / "provision.mjs"
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"

# Any pinned version keeps the probe off the network: the installer resolves
# `latest` through a redirect only when KIN_VERSION is unset.
PROBE_VERSION = "0.0.0-asset-name-probe"

ASSET_NAME = re.compile(r"^kin-[a-z0-9_]+-[a-z0-9_]+\.(?:tar\.gz|zip)$")
ANSI = re.compile(r"\x1b\[[0-9;]*m")
DOWNLOAD_LINE = re.compile(r"Downloading (\S+)\.\.\.")
MATRIX_ARTIFACT = re.compile(r"^\s+artifact: (kin-[a-z0-9_]+-[a-z0-9_]+)\s*$", re.M)
PS1_TARGET = re.compile(r'^\$Target = "windows-\$Arch"\s*$', re.M)
PS1_ARCHIVE = re.compile(r'^\$Archive = "kin-\$Target\.(?P<ext>[A-Za-z0-9.]+)"\s*$', re.M)
PS1_ARCH = re.compile(r'^\s*"AMD64" \{ return "(?P<arch>[A-Za-z0-9_]+)" \}\s*$', re.M)

RELEASE_STEP = "      - name: Create GitHub Release"
RELEASE_FILES_KEY = "          files: |"
ATTEST_STEP = "      - name: Attest final release archives and provenance"
ATTEST_SUBJECT_KEY = "          subject-path: |"
INVENTORY_STEP = "      - name: Verify complete release asset inventory"
INVENTORY_ASSETS = re.compile(r"^\s+assets=\(\n(?P<body>(?:\s+\S+\n)+?)\s*\)\s*$", re.M)


class GuardError(RuntimeError):
    """The installer surface and the published release assets disagree."""


@dataclass(frozen=True)
class Platform:
    """One host identity, and the release artifact a user on it must receive."""

    label: str
    artifact: str
    uname_s: str = ""
    uname_m: str = ""
    node: tuple[str, str] | None = None
    powershell: bool = False


# Host identities, not answers. Each row says "a user whose machine reports this
# is served this artifact"; what name the installers build from that identity is
# derived below and is exactly what this guard exists to check.
PLATFORMS: tuple[Platform, ...] = (
    Platform("linux x86_64", "kin-linux-x86_64", "Linux", "x86_64", ("linux", "x64")),
    Platform("linux aarch64", "kin-linux-aarch64", "Linux", "aarch64", ("linux", "arm64")),
    Platform("macos x86_64", "kin-macos-x86_64", "Darwin", "x86_64", ("darwin", "x64")),
    Platform("macos aarch64", "kin-macos-aarch64", "Darwin", "arm64", ("darwin", "arm64")),
    # The three shells whose uname the installer maps to `windows`. All three
    # reach the same published artifact, and all three 404'd before the Windows
    # leg published a tarball.
    Platform(
        "windows x86_64 (Git Bash)",
        "kin-windows-x86_64",
        "MINGW64_NT-10.0-22631",
        "x86_64",
        ("win32", "x64"),
        powershell=True,
    ),
    Platform("windows x86_64 (MSYS)", "kin-windows-x86_64", "MSYS_NT-10.0-22631", "x86_64"),
    Platform("windows x86_64 (Cygwin)", "kin-windows-x86_64", "CYGWIN_NT-10.0-22631", "amd64"),
)


@dataclass
class Requirement:
    """One asset name an install surface builds, and who builds it."""

    asset: str
    surfaces: list[str] = field(default_factory=list)


def executable(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def posix_installer_asset(install_sh: Path, platform: Platform) -> str:
    """Ask install.sh itself what it downloads on this platform."""
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        fake_bin = root / "fake-bin"
        fake_bin.mkdir()
        executable(
            fake_bin / "uname",
            "#!/bin/sh\n"
            'case "${1:-}" in\n'
            f"  -s) printf '{platform.uname_s}\\n' ;;\n"
            f"  -m) printf '{platform.uname_m}\\n' ;;\n"
            "  *) exit 2 ;;\n"
            "esac\n",
        )
        # An empty release directory: the installer prints the name it wants and
        # then fails to fetch it, which is all this probe needs and keeps the
        # run local.
        releases = root / "releases"
        releases.mkdir()
        home = root / "home"
        home.mkdir()
        env = os.environ.copy()
        env.update(
            {
                "PATH": f"{fake_bin}{os.pathsep}{env.get('PATH', '')}",
                "HOME": str(home),
                "KIN_HOME": str(home / ".kin"),
                "KIN_BASE_URL": releases.as_uri(),
                "KIN_VERSION": PROBE_VERSION,
                "KIN_NO_SETUP": "1",
            }
        )
        env.pop("KIN_DIR", None)
        completed = subprocess.run(
            ["sh", str(install_sh)],
            env=env,
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
    output = ANSI.sub("", completed.stdout + completed.stderr)
    names = DOWNLOAD_LINE.findall(output)
    if len(names) != 1:
        raise GuardError(
            f"{install_sh.name} named {len(names)} archives on {platform.label} "
            f"(expected exactly one). The probe could not read what the installer "
            f"asks for, so it proves nothing. Output:\n{output}"
        )
    return names[0]


def npm_launcher_asset(provision: Path, node_platform: str, node_arch: str) -> str:
    """Call the npm launcher's own artifactName() for this platform."""
    node = shutil.which("node")
    if node is None:
        raise GuardError("node is required to evaluate the npm launcher asset table")
    driver = (
        "const { pathToFileURL } = await import('node:url');"
        "const mod = await import(pathToFileURL(process.argv[1]).href);"
        "process.stdout.write(mod.artifactName(process.argv[2], process.argv[3]));"
    )
    completed = subprocess.run(
        [node, "--input-type=module", "-e", driver, str(provision), node_platform, node_arch],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    if completed.returncode != 0:
        raise GuardError(
            f"npm launcher artifactName({node_platform}, {node_arch}) failed:\n"
            f"{completed.stderr.strip()}"
        )
    return completed.stdout.strip()


def powershell_installer_asset(install_ps1: Path) -> str:
    """Read install.ps1's archive construction out of its own source."""
    source = install_ps1.read_text(encoding="utf-8")
    if len(PS1_TARGET.findall(source)) != 1:
        raise GuardError(
            f"{install_ps1.name} no longer builds its target as `windows-$Arch`; "
            "this guard cannot derive the asset name it requests"
        )
    archive = PS1_ARCHIVE.search(source)
    if archive is None or len(PS1_ARCHIVE.findall(source)) != 1:
        raise GuardError(
            f"{install_ps1.name} no longer builds its archive as `kin-$Target.<ext>`; "
            "this guard cannot derive the asset name it requests"
        )
    arch = PS1_ARCH.search(source)
    if arch is None:
        raise GuardError(
            f"{install_ps1.name} no longer maps an AMD64 process architecture; "
            "this guard cannot derive the asset name it requests"
        )
    return f"kin-windows-{arch.group('arch')}.{archive.group('ext')}"


def workflow_step_block(workflow: str, step: str, key: str) -> list[str]:
    """The indented block under `key` inside the named workflow step."""
    lines = workflow.splitlines()
    try:
        start = lines.index(step)
    except ValueError as error:
        raise GuardError(f"release workflow has no step {step.strip()!r}") from error
    try:
        key_index = lines.index(key, start)
    except ValueError as error:
        raise GuardError(
            f"release workflow step {step.strip()!r} has no {key.strip()!r} block"
        ) from error
    indent = len(key) - len(key.lstrip()) + 2
    block: list[str] = []
    for line in lines[key_index + 1 :]:
        if not line.strip():
            break
        if len(line) - len(line.lstrip()) < indent:
            break
        block.append(line.strip())
    if not block:
        raise GuardError(
            f"release workflow step {step.strip()!r} publishes an empty {key.strip()!r} block"
        )
    return block


def inventory_assets(workflow_source: str) -> set[str]:
    """The asset list the publish job asserts is complete before it uploads."""
    if INVENTORY_STEP not in workflow_source:
        raise GuardError(f"release workflow has no step {INVENTORY_STEP.strip()!r}")
    tail = workflow_source[workflow_source.index(INVENTORY_STEP) :]
    match = INVENTORY_ASSETS.search(tail)
    if match is None:
        raise GuardError("release workflow's asset inventory declares no asset list")
    return {line.strip() for line in match.group("body").splitlines() if line.strip()}


def asset_sources(assets_dir: Path | None, workflow_source: str) -> list[tuple[str, set[str]]]:
    """Every list a published asset has to appear in, with a name for each.

    An archive that exists but is missing from the checksum inventory or the
    attestation subjects fails verification downstream in a way that reads to a
    user like a broken download, so all three lists are judged together rather
    than trusting the upload list alone.
    """
    sources = [
        (
            "the release workflow's published file list",
            set(workflow_step_block(workflow_source, RELEASE_STEP, RELEASE_FILES_KEY)),
        ),
        (
            "the release attestation subject list",
            set(workflow_step_block(workflow_source, ATTEST_STEP, ATTEST_SUBJECT_KEY)),
        ),
        ("the release asset inventory", inventory_assets(workflow_source)),
    ]
    if assets_dir is not None:
        sources.append(
            (
                f"the assets staged in {assets_dir}",
                {entry.name for entry in assets_dir.iterdir() if entry.is_file()},
            )
        )
    return sources


def guarded_platform_artifacts(workflow_source: str) -> None:
    """Every artifact the release builds must have a platform row here."""
    matrix = set(MATRIX_ARTIFACT.findall(workflow_source))
    if not matrix:
        raise GuardError("could not read the release build matrix's artifact names")
    guarded = {platform.artifact for platform in PLATFORMS}
    unguarded = sorted(matrix - guarded)
    if unguarded:
        raise GuardError(
            "the release builds artifacts no platform row covers, so no installer "
            f"name is checked for them: {', '.join(unguarded)}"
        )
    stale = sorted(guarded - matrix)
    if stale:
        raise GuardError(
            "platform rows name artifacts the release no longer builds: "
            f"{', '.join(stale)}"
        )


def required_assets() -> dict[str, Requirement]:
    required: dict[str, Requirement] = {}

    def record(asset: str, surface: str) -> None:
        if not ASSET_NAME.fullmatch(asset):
            raise GuardError(f"{surface} built an implausible asset name {asset!r}")
        required.setdefault(asset, Requirement(asset)).surfaces.append(surface)

    for platform in PLATFORMS:
        if platform.uname_s:
            record(
                posix_installer_asset(INSTALL_SH, platform),
                f"scripts/install.sh on {platform.label}",
            )
        # The npm launcher and the PowerShell installer detect their platform
        # from the running process rather than from uname, so they are reported
        # against the artifact they resolve instead of against a shell name.
        if platform.node is not None:
            record(
                npm_launcher_asset(NPM_PROVISION, *platform.node),
                f"packages/kin/lib/provision.mjs for {platform.artifact}",
            )
        if platform.powershell:
            record(
                powershell_installer_asset(INSTALL_PS1),
                f"scripts/install.ps1 for {platform.artifact}",
            )
    if not required:
        raise GuardError("no installer asset names were derived; the check is vacuous")
    return required


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--assets-dir",
        type=Path,
        default=None,
        help=(
            "Check against the assets staged in this directory (the release "
            "being published). Defaults to the release workflow's published "
            "file list, which is what a pull request can check."
        ),
    )
    args = parser.parse_args()

    workflow_source = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    try:
        guarded_platform_artifacts(workflow_source)
        required = required_assets()
        sources = asset_sources(args.assets_dir, workflow_source)
    except GuardError as error:
        print(f"installer asset guard: {error}", file=sys.stderr)
        return 1

    failed = False
    for label, names in sources:
        if not names:
            print(f"installer asset guard: {label} is empty", file=sys.stderr)
            return 1
        for name in sorted(required):
            if name in names:
                continue
            failed = True
            print(
                f"::error::{name} is requested by {', '.join(required[name].surfaces)} "
                f"but is absent from {label}. That install path resolves to a 404.",
                file=sys.stderr,
            )
    if failed:
        return 1

    for name in sorted(required):
        print(f"  ok: {name} <- {', '.join(required[name].surfaces)}")
    print(
        f"installer asset guard: {len(required)} requested assets all present in "
        f"{len(sources)} release asset lists"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
