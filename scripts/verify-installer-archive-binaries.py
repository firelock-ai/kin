#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

"""Fail when the installer names binaries the release archive does not carry.

Resolving the right archive name is only half of an install. Once the download
lands, `scripts/install.sh` names the binaries inside it, and those names carry
a platform suffix: a Windows release archive holds `kin.exe` and
`kin-daemon.exe`, every other leg holds bare names. The installer named the bare
form on every platform, so the mandatory-daemon assertion failed against a
Windows archive that was present, complete, and checksum-verified. That abort
lands after the user has already waited for the download, which is a worse first
run than the 404 that preceded it.

Nothing here is restated. The member names come from the release workflow's own
packaging steps, honouring each matrix row's shim name and its `skip_vfs` key,
and the mandatory subset comes from the provenance manifest's own authority
list. Each host identity is mapped to its artifact by running `install.sh`
against a stubbed `uname` and reading the name it asks to download. A fixture
archive is then built with exactly those members and the real installer is run
against it end to end, so the post-extract path is exercised per platform rather
than described. The assertion is that the binaries the installer ends up with
are the ones the archive actually contained, suffixes included.

Anchored patterns fail rather than skip when the workflow moves. A guard that
derived nothing would pass forever.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
INSTALL_SH = ROOT / "scripts" / "install.sh"
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"

PROBE_VERSION = "0.0.0-archive-binary-probe"

ANSI = re.compile(r"\x1b\[[0-9;]*m")
DOWNLOAD_LINE = re.compile(r"Downloading (?P<asset>\S+)\.\.\.")

# One matrix row per release leg. Rows are recognised by their artifact key, so
# an unrelated matrix elsewhere in the workflow cannot be mistaken for one.
MATRIX_MARKER = re.compile(r"^(?P<indent>\s+)- os: (?P<os>\S+)\s*$")
ROW_KEY = re.compile(r"^\s+(?P<key>\w+): (?P<value>.*?)\s*$")

# The two packaging steps, each naming the components it copies into the
# archive root. The Windows leg marks optional components with
# `-ErrorAction SilentlyContinue`; the Unix leg has no optional copies.
UNIX_COPY = re.compile(
    r'^\s+cp "(?:target/\$\{TARGET\}|kin-vfs/target/\$\{VFS_TARGET\})'
    r'/release/(?P<name>[^"]+)" "\$ARTIFACT/"\s*$',
    re.M,
)
WINDOWS_COPY = re.compile(
    r'^\s+Copy-Item "(?:target/\$env:TARGET|kin-vfs/target/\$env:TARGET)'
    r'/release/(?P<name>[^"]+)" "\$env:ARTIFACT/"(?P<tail>.*?)\s*$',
    re.M,
)

# The release's own declaration of which binaries are mandatory per leg. It is
# declared in more than one place, so every declaration must be readable and all
# of them must agree. Reading only the first would let a second declaration drift
# or become unreadable without anything noticing.
AUTHORITY_DECLARATION = re.compile(r"authorityNames = new Set\(")
AUTHORITY_NAMES = re.compile(
    r'target\.includes\("-windows-"\)\s*\n'
    r'\s*\? \[(?P<windows>[^\]]+)\]\s*\n'
    r'\s*: \[(?P<unix>[^\]]+)\]',
    re.M,
)

# Host identities, not answers. Each row says only "a machine reporting this
# runs the installer"; which artifact it receives and which binaries that
# artifact carries are both derived below.
HOSTS: tuple[tuple[str, str, str], ...] = (
    ("linux x86_64", "Linux", "x86_64"),
    ("linux aarch64", "Linux", "aarch64"),
    ("macos x86_64", "Darwin", "x86_64"),
    ("macos aarch64", "Darwin", "arm64"),
    ("windows x86_64 (Git Bash)", "MINGW64_NT-10.0-22631", "x86_64"),
    ("windows x86_64 (MSYS)", "MSYS_NT-10.0-22631", "x86_64"),
    ("windows x86_64 (Cygwin)", "CYGWIN_NT-10.0-22631", "amd64"),
)


class GuardError(RuntimeError):
    """The installer and the release archive disagree about a binary name."""


@dataclass(frozen=True)
class Leg:
    """One release leg: the artifact it publishes and what it packs into it."""

    artifact: str
    windows: bool
    binaries: tuple[str, ...]
    shim: str | None
    notifier: bool


def executable(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def read_workflow() -> str:
    if not RELEASE_WORKFLOW.is_file():
        raise GuardError(f"cannot derive release contents without {RELEASE_WORKFLOW}")
    return RELEASE_WORKFLOW.read_text(encoding="utf-8")


def matrix_rows(workflow: str) -> dict[str, dict[str, str]]:
    """Every release leg keyed by artifact, with the keys that shape its archive.

    Read line by line rather than by one block pattern. Comment lines sit
    between matrix rows, and a block pattern that stopped at the next `- os:`
    silently dropped the row behind the first comment, which cost a real leg its
    coverage while the guard still reported a result.
    """
    rows: dict[str, dict[str, str]] = {}
    lines = workflow.splitlines()
    index = 0
    while index < len(lines):
        marker = MATRIX_MARKER.match(lines[index])
        if marker is None:
            index += 1
            continue
        indent = len(marker.group("indent"))
        keys = {"os": marker.group("os")}
        index += 1
        while index < len(lines):
            line = lines[index]
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                if len(line) - len(line.lstrip()) <= indent:
                    break
                pair = ROW_KEY.match(line)
                if pair:
                    keys[pair.group("key")] = pair.group("value")
            index += 1
        artifact = keys.get("artifact", "")
        if artifact.startswith("kin-"):
            rows[artifact] = keys
    if not rows:
        raise GuardError(
            "no release matrix rows found; the workflow's matrix shape moved and "
            "this guard would otherwise derive nothing and pass"
        )
    return rows


def authority_binaries(workflow: str) -> tuple[frozenset[str], frozenset[str]]:
    """The mandatory binary names the release records per leg."""

    def names(raw: str) -> frozenset[str]:
        found = frozenset(re.findall(r'"([^"]+)"', raw))
        if not found:
            raise GuardError(f"empty authority name list: {raw!r}")
        return found

    declared = len(AUTHORITY_DECLARATION.findall(workflow))
    matches = AUTHORITY_NAMES.findall(workflow)
    if not declared or not matches:
        raise GuardError(
            "release provenance authority names not found; without them this "
            "guard cannot say which binaries an archive must carry"
        )
    if len(matches) != declared:
        raise GuardError(
            f"the release declares {declared} mandatory-binary authority lists "
            f"but only {len(matches)} can be read; an unreadable list would let "
            "this guard derive its answer from a partial record"
        )
    windows = {names(pair[0]) for pair in matches}
    unix = {names(pair[1]) for pair in matches}
    if len(windows) != 1 or len(unix) != 1:
        raise GuardError(
            "the release's mandatory-binary authority lists disagree with each "
            f"other: windows {sorted(windows)}, unix {sorted(unix)}"
        )
    return windows.pop(), unix.pop()


def packaged_components(workflow: str, row: dict[str, str]) -> tuple[list[str], bool]:
    """The component names one leg copies into its archive root.

    Optional copies are dropped when the row does not build them. The Windows
    row carries `skip_vfs`, so its silently-tolerated projection copies produce
    nothing and the published archive holds the two mandatory binaries alone.
    """
    windows = row.get("os", "").startswith("windows")
    pattern = WINDOWS_COPY if windows else UNIX_COPY
    matches = list(pattern.finditer(workflow))
    if not matches:
        raise GuardError(
            f"no packaging copies found for {row.get('artifact')}; the packaging "
            "step moved and this guard would derive an empty archive"
        )

    skip_vfs = row.get("skip_vfs", "false") == "true"
    components: list[str] = []
    for match in matches:
        name = match.group("name")
        if name in {"${SHIM_NAME}", "$env:SHIM_NAME"}:
            shim = row.get("shim_name")
            if not shim:
                raise GuardError(f"matrix row {row.get('artifact')} names no shim")
            name = shim
        projection = name.startswith("kin-vfs") or "shim" in name
        if projection and skip_vfs:
            continue
        components.append(name)
    return components, windows


def legs(workflow: str) -> dict[str, Leg]:
    windows_authority, unix_authority = authority_binaries(workflow)
    resolved: dict[str, Leg] = {}
    for artifact, row in matrix_rows(workflow).items():
        components, windows = packaged_components(workflow, row)
        authority = windows_authority if windows else unix_authority
        missing = authority - set(components)
        if missing:
            raise GuardError(
                f"{artifact} packages {sorted(components)} but the release records "
                f"{sorted(authority)} as mandatory; {sorted(missing)} is unaccounted for"
            )
        shim = next((name for name in components if "shim" in name), None)
        binaries = tuple(name for name in components if name != shim)
        resolved[artifact] = Leg(
            artifact=artifact,
            windows=windows,
            binaries=binaries,
            shim=shim,
            notifier=artifact.startswith("kin-macos-"),
        )
    return resolved


def uname_stub(directory: Path, uname_s: str, uname_m: str) -> Path:
    fake_bin = directory / "fake-bin"
    fake_bin.mkdir(exist_ok=True)
    executable(
        fake_bin / "uname",
        "#!/bin/sh\n"
        'case "${1:-}" in\n'
        f"  -s) printf '{uname_s}\\n' ;;\n"
        f"  -m) printf '{uname_m}\\n' ;;\n"
        "  *) exit 2 ;;\n"
        "esac\n",
    )
    return fake_bin


def installer_env(root: Path, fake_bin: Path, releases: Path, home: Path) -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "PATH": f"{fake_bin}{os.pathsep}{env.get('PATH', '')}",
            "HOME": str(home),
            "KIN_HOME": str(home / ".kin"),
            "KIN_BASE_URL": releases.as_uri(),
            "KIN_VERSION": PROBE_VERSION,
            "KIN_NO_SETUP": "1",
            "SHELL": "/bin/sh",
        }
    )
    env.pop("KIN_DIR", None)
    return env


def requested_asset(uname_s: str, uname_m: str) -> str:
    """Ask install.sh which artifact this host is served.

    The release directory is empty on purpose: the installer prints the name it
    wants before it fails to fetch it, which is all this needs and keeps the
    probe off the network.
    """
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        fake_bin = uname_stub(root, uname_s, uname_m)
        releases = root / "releases"
        releases.mkdir()
        home = root / "home"
        home.mkdir()
        result = subprocess.run(
            ["sh", str(INSTALL_SH)],
            env=installer_env(root, fake_bin, releases, home),
            check=False,
            capture_output=True,
            text=True,
        )
    for line in ANSI.sub("", result.stdout).splitlines():
        match = DOWNLOAD_LINE.search(line)
        if match:
            asset = match.group("asset")
            for suffix in (".tar.gz", ".zip"):
                if asset.endswith(suffix):
                    return asset[: -len(suffix)]
            raise GuardError(f"installer asked for an unrecognised archive: {asset}")
    raise GuardError(
        f"install.sh named no download on a {uname_s}/{uname_m} host; the probe "
        "cannot read what it asks for and must not pass silently"
    )


def build_archive(directory: Path, leg: Leg) -> Path:
    """A fixture carrying exactly the members this leg publishes."""
    archive_root = directory / leg.artifact
    archive_root.mkdir()
    for name in leg.binaries:
        if name.startswith("kin.") or name == "kin":
            body = "#!/bin/sh\nprintf 'kin 9.9.9\\n'\n"
        else:
            body = "#!/bin/sh\nexit 0\n"
        executable(archive_root / name, body)
    if leg.shim:
        (archive_root / leg.shim).write_bytes(b"fixture shim")
    if leg.notifier:
        contents = archive_root / "KinNotifier.app" / "Contents"
        (contents / "MacOS").mkdir(parents=True)
        executable(contents / "MacOS" / "KinNotifier", "#!/bin/sh\nexit 0\n")
        (contents / "Info.plist").write_text("<plist>fixture</plist>", encoding="utf-8")

    releases = directory / "download" / f"v{PROBE_VERSION}"
    releases.mkdir(parents=True)
    archive = releases / f"{leg.artifact}.tar.gz"
    with tarfile.open(archive, "w:gz") as bundle:
        bundle.dereference = False
        bundle.add(archive_root, arcname=archive_root.name)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    archive.with_suffix(archive.suffix + ".sha256").write_text(
        f"{digest}  {archive.name}\n", encoding="utf-8"
    )
    return archive


def check_host(label: str, uname_s: str, uname_m: str, resolved: dict[str, Leg]) -> str:
    artifact = requested_asset(uname_s, uname_m)
    leg = resolved.get(artifact)
    if leg is None:
        raise GuardError(
            f"{label}: install.sh downloads {artifact}, which no release leg "
            "publishes; a platform cannot be served an archive nobody builds"
        )

    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        fake_bin = uname_stub(root, uname_s, uname_m)
        build_archive(root, leg)
        home = root / "home"
        home.mkdir()
        kin_home = home / ".kin"
        result = subprocess.run(
            ["sh", str(INSTALL_SH)],
            env=installer_env(root, fake_bin, root, home),
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise GuardError(
                f"{label}: install.sh failed against a complete {artifact} archive "
                f"carrying {sorted(leg.binaries)}.\n"
                f"        exit {result.returncode}\n"
                f"        {ANSI.sub('', result.stderr).strip()}"
            )
        installed = sorted(p.name for p in (kin_home / "bin").iterdir()) if (
            kin_home / "bin"
        ).is_dir() else []
        expected = sorted(leg.binaries)
        if installed != expected:
            raise GuardError(
                f"{label}: {artifact} carries {expected} but the install left "
                f"{installed} in bin; the installer names binaries the archive "
                "does not contain"
            )
        if leg.shim:
            shim_path = kin_home / "lib" / leg.shim
            if not shim_path.is_file():
                raise GuardError(
                    f"{label}: {artifact} carries {leg.shim} but it was not installed"
                )
    return f"{label}: {artifact} -> {', '.join(expected)}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()

    if not INSTALL_SH.is_file():
        print(f"cannot verify without {INSTALL_SH}", file=sys.stderr)
        return 1
    try:
        resolved = legs(read_workflow())
        lines = [check_host(*host, resolved) for host in HOSTS]
    except GuardError as error:
        print(f"installer archive binary guard FAILED\n  {error}", file=sys.stderr)
        return 1

    print("installer archive binaries agree with what the release packages:")
    for line in lines:
        print(f"  {line}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
