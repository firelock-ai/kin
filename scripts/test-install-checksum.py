#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

"""Portable fixture and wiring checks for the Windows installer checksum gate."""

from __future__ import annotations

import json
import re
from pathlib import Path


SCRIPTS_DIR = Path(__file__).resolve().parent
ROOT = SCRIPTS_DIR.parent
CHECKSUM_LINE = re.compile(r"^([0-9a-fA-F]{64})[ \t]+(\*?.+?)$")


def resolve_archive_checksum(content: str, archive: str) -> str:
    matches: list[str] = []
    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        parsed = CHECKSUM_LINE.fullmatch(raw_line)
        if parsed is None:
            raise ValueError(
                f"Checksum file contains malformed entry on line {line_number}"
            )
        checksum, filename = parsed.groups()
        if filename.startswith("*"):
            filename = filename[1:]
        if filename == archive:
            matches.append(checksum.lower())

    if not matches:
        raise ValueError(f"Checksum file has no entry for exact archive '{archive}'")
    unique = sorted(set(matches))
    if len(unique) > 1:
        raise ValueError(
            f"Checksum file has conflicting entries for exact archive '{archive}'"
        )
    return unique[0]


def check_fixtures() -> int:
    fixture_path = SCRIPTS_DIR / "install-checksum-fixtures.json"
    fixture_data = json.loads(fixture_path.read_text(encoding="utf-8"))
    cases = fixture_data.get("cases")
    if not isinstance(cases, list) or not cases:
        raise AssertionError(
            "checksum fixture file must contain a non-empty cases array"
        )

    passed = 0
    for case in cases:
        failure: str | None = None
        actual: str | None = None
        try:
            actual = resolve_archive_checksum(case["content"], case["archive"])
        except ValueError as error:
            failure = str(error)

        expected_error = case.get("error_contains")
        if expected_error is not None:
            if failure is None or expected_error not in failure:
                raise AssertionError(
                    f"{case['name']}: expected error containing {expected_error!r}, got {failure!r}"
                )
        else:
            if failure is not None:
                raise AssertionError(f"{case['name']}: unexpected error: {failure}")
            if actual != case["expected"]:
                raise AssertionError(
                    f"{case['name']}: expected {case['expected']!r}, got {actual!r}"
                )

        passed += 1
        print(f"PASS: {case['name']}")
    return passed


def check_product_wiring() -> None:
    installer = (SCRIPTS_DIR / "install.ps1").read_text(encoding="utf-8")
    powershell_harness = (SCRIPTS_DIR / "test-install-checksum.ps1").read_text(
        encoding="utf-8"
    )
    ci_workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    release_workflow = (ROOT / ".github/workflows/release.yml").read_text(
        encoding="utf-8"
    )

    installer_requirements = (
        "function Format-ByteCount",
        "function Invoke-ArchiveDownload",
        "[System.Net.Http.HttpCompletionOption]::ResponseHeadersRead",
        'Write-Progress -Activity "Downloading $ArchiveName"',
        "-ShowProgress:$ShowArchiveProgress",
        "Remove-Item -LiteralPath $TmpDir -Recurse -Force -ErrorAction SilentlyContinue",
        "function Resolve-ArchiveChecksum",
        "$Filename -cne $ArchiveName",
        "$UniqueHashes.Count -gt 1",
        "Resolve-ArchiveChecksum -ChecksumContent $ChecksumContent -ArchiveName $Archive",
        "function Resolve-KinWindowsArchiveArchitecture",
        '"AMD64" { return "x86_64" }',
        '"ARM64" { throw "No native Windows ARM64 archive is published.',
    )
    for requirement in installer_requirements:
        if requirement not in installer:
            raise AssertionError(
                f"install.ps1 is missing checksum guard wiring: {requirement}"
            )

    harness_requirements = (
        "function Invoke-PowerShellFile",
        "$Child = Start-Process",
        "ExitCode = [int]$Child.ExitCode",
        "if ($global:LASTEXITCODE -ne 0)",
        "PASS: expected child failures leave the harness exit status clean",
        "exit 0",
    )
    for requirement in harness_requirements:
        if requirement not in powershell_harness:
            raise AssertionError(
                "test-install-checksum.ps1 can leak an intentional child failure "
                f"into the successful harness exit: missing {requirement}"
            )
    if re.search(r"(?m)^\s*&\s+\$PowerShellExe(?:cutable)?\b", powershell_harness):
        raise AssertionError(
            "test-install-checksum.ps1 must capture intentional child failures "
            "through Start-Process rather than session-wide $LASTEXITCODE"
        )

    # Both Windows containers get the same filename-bound sidecar. Binding the
    # hash to the archive's own name is what lets install.ps1 refuse a checksum
    # file that names a different archive, so a second published container that
    # skipped this line would ship a sidecar nothing could match.
    release_requirements = (
        'foreach ($ArchivePath in @("$env:ARTIFACT.zip", "$env:ARTIFACT.tar.gz")) {',
        "$Hash = (Get-FileHash -Algorithm SHA256 $ArchivePath).Hash.ToLowerInvariant()",
        '"$Hash  $ArchivePath" | Set-Content -Encoding ascii "$ArchivePath.sha256"',
    )
    for requirement in release_requirements:
        if requirement not in release_workflow:
            raise AssertionError(
                f"release.yml is missing filename-bound checksum output: {requirement}"
            )

    ci_requirements = (
        "shell: pwsh",
        "shell: powershell",
        "run: ./scripts/test-install-checksum.ps1",
    )
    for requirement in ci_requirements:
        if requirement not in ci_workflow:
            raise AssertionError(
                f"ci.yml is missing Windows installer test coverage: {requirement}"
            )


def main() -> None:
    passed = check_fixtures()
    check_product_wiring()
    print(f"{passed} checksum fixture cases and product wiring passed")


if __name__ == "__main__":
    main()
