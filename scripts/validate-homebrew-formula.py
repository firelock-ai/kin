#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

"""Validate that the public Homebrew formula exactly matches one Kin release."""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass


VERSION_RE = re.compile(r'^\s*version\s+"([^"]+)"\s*(?:#.*)?$')
URL_RE = re.compile(r'^\s*url\s+"([^"]+)"\s*(?:#.*)?$')
SHA_RE = re.compile(r'^\s*sha256\s+"([^"]+)"\s*(?:#.*)?$')
OS_RE = re.compile(r"^\s*on_(macos|linux)\s+do\s*(?:#.*)?$")
ARCH_RE = re.compile(r"^\s*on_(arm|intel)\s+do\s*(?:#.*)?$")
END_RE = re.compile(r"^\s*end\s*(?:#.*)?$")
CHECKSUM_RE = re.compile(r"^\s*([0-9A-Fa-f]{64})[ \t]+\*?([^ \t]+)[ \t]*$")
HEX_RE = re.compile(r"^[0-9A-Fa-f]{64}$")


SUPPORTED_ARTIFACTS = {
    ("macos", "arm"): "kin-macos-aarch64.tar.gz",
    ("macos", "intel"): "kin-macos-x86_64.tar.gz",
    ("linux", "arm"): "kin-linux-aarch64.tar.gz",
    ("linux", "intel"): "kin-linux-x86_64.tar.gz",
}
ARTIFACT_ORDER = (
    "kin-macos-aarch64.tar.gz",
    "kin-macos-x86_64.tar.gz",
    "kin-linux-aarch64.tar.gz",
    "kin-linux-x86_64.tar.gz",
)


class ValidationError(ValueError):
    """The public formula or checksum sidecars are not an exact release match."""


@dataclass(frozen=True)
class FormulaPair:
    artifact: str
    url: str
    sha256: str


def expected_url(artifact: str) -> str:
    return (
        f"https://github.com/firelock-ai/kin/releases/download/v#{{version}}/{artifact}"
    )


def next_content_line(lines: list[str], start: int) -> tuple[int, str] | None:
    for index in range(start, len(lines)):
        stripped = lines[index].strip()
        if stripped and not stripped.startswith("#"):
            return index, lines[index]
    return None


def parse_formula(formula: str, expected_version: str) -> dict[str, FormulaPair]:
    lines = formula.splitlines()
    versions = [
        match.group(1) for line in lines if (match := VERSION_RE.fullmatch(line))
    ]
    if len(versions) != 1:
        raise ValidationError(
            "expected exactly one active version directive for "
            f"{expected_version}; found {len(versions)}"
        )
    if versions[0] != expected_version:
        raise ValidationError(
            f"formula version is {versions[0]!r}, expected {expected_version!r}"
        )

    current_os: str | None = None
    current_arch: str | None = None
    pairs_by_platform: dict[tuple[str, str], FormulaPair] = {}
    url_count = 0
    sha_lines: set[int] = set()

    for index, line in enumerate(lines):
        if match := OS_RE.fullmatch(line):
            if current_os is not None or current_arch is not None:
                raise ValidationError(
                    f"nested or duplicate operating-system block at formula line {index + 1}"
                )
            current_os = match.group(1)
            continue
        if match := ARCH_RE.fullmatch(line):
            if current_os is None or current_arch is not None:
                raise ValidationError(
                    f"architecture block has no unique operating-system parent at formula line {index + 1}"
                )
            current_arch = match.group(1)
            continue
        if END_RE.fullmatch(line):
            if current_arch is not None:
                current_arch = None
            elif current_os is not None:
                current_os = None
            continue

        url_match = URL_RE.fullmatch(line)
        if not url_match:
            continue
        url_count += 1
        if current_os is None or current_arch is None:
            raise ValidationError(
                f"formula URL at line {index + 1} is outside a supported platform block"
            )
        platform = (current_os, current_arch)
        artifact = SUPPORTED_ARTIFACTS[platform]
        if platform in pairs_by_platform:
            raise ValidationError(
                f"duplicate formula mapping for {current_os}/{current_arch}"
            )

        expected = expected_url(artifact)
        actual_url = url_match.group(1)
        if actual_url != expected:
            raise ValidationError(
                f"unexpected URL for {current_os}/{current_arch}: expected {expected!r}, got {actual_url!r}"
            )

        following = next_content_line(lines, index + 1)
        if following is None:
            raise ValidationError(f"missing sha256 directive after URL for {artifact}")
        sha_index, sha_line = following
        sha_match = SHA_RE.fullmatch(sha_line)
        if not sha_match:
            raise ValidationError(f"missing sha256 directive after URL for {artifact}")
        sha = sha_match.group(1)
        if not HEX_RE.fullmatch(sha):
            raise ValidationError(
                f"malformed sha256 for {artifact}: expected 64 hexadecimal characters"
            )
        sha_lines.add(sha_index)
        pairs_by_platform[platform] = FormulaPair(
            artifact=artifact,
            url=actual_url,
            sha256=sha.lower(),
        )

    all_sha_lines = {
        index for index, line in enumerate(lines) if SHA_RE.fullmatch(line)
    }
    if url_count != len(SUPPORTED_ARTIFACTS):
        raise ValidationError(
            f"expected exactly {len(SUPPORTED_ARTIFACTS)} formula URL directives; found {url_count}"
        )
    if all_sha_lines != sha_lines:
        raise ValidationError(
            "formula must contain exactly one sha256 directive paired with each supported URL"
        )

    missing = sorted(set(SUPPORTED_ARTIFACTS) - set(pairs_by_platform))
    if missing:
        rendered = ", ".join(f"{os_name}/{arch}" for os_name, arch in missing)
        raise ValidationError(f"missing formula platform mapping(s): {rendered}")

    return {pair.artifact: pair for pair in pairs_by_platform.values()}


def parse_sidecar(sidecar: str, expected_artifact: str) -> str:
    lines = [line for line in sidecar.splitlines() if line.strip()]
    if len(lines) != 1:
        raise ValidationError(
            f"public checksum sidecar for {expected_artifact} must contain exactly "
            f"one nonblank entry; found {len(lines)}"
        )
    match = CHECKSUM_RE.fullmatch(lines[0])
    if not match:
        raise ValidationError(
            f"malformed public checksum sidecar for {expected_artifact}"
        )
    sha, artifact = match.groups()
    if artifact != expected_artifact:
        raise ValidationError(
            f"public checksum sidecar for {expected_artifact} names {artifact!r}"
        )
    return sha.lower()


def validate(formula: str, sidecars: list[str], expected_version: str) -> None:
    formula_pairs = parse_formula(formula, expected_version)
    if len(sidecars) != len(ARTIFACT_ORDER):
        raise ValidationError(
            f"expected {len(ARTIFACT_ORDER)} public checksum sidecars; found {len(sidecars)}"
        )
    release_checksums = {
        artifact: parse_sidecar(sidecar, artifact)
        for artifact, sidecar in zip(ARTIFACT_ORDER, sidecars, strict=True)
    }
    for artifact in sorted(formula_pairs):
        formula_sha = formula_pairs[artifact].sha256
        release_sha = release_checksums[artifact]
        if formula_sha != release_sha:
            raise ValidationError(
                f"checksum mismatch for {artifact}: formula has {formula_sha}, "
                f"public release has {release_sha}"
            )


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <expected-version>", file=sys.stderr)
        return 2
    payload = sys.stdin.buffer.read()
    parts = payload.split(b"\0")
    if parts and parts[-1] == b"":
        parts.pop()
    expected_parts = 1 + len(ARTIFACT_ORDER)
    if len(parts) != expected_parts:
        print(
            f"error: expected NUL-delimited formula and {len(ARTIFACT_ORDER)} "
            f"checksum sidecars; found {max(0, len(parts) - 1)} sidecars",
            file=sys.stderr,
        )
        return 2
    try:
        formula = parts[0].decode("utf-8", errors="strict")
        sidecars = [part.decode("utf-8", errors="strict") for part in parts[1:]]
        validate(formula, sidecars, sys.argv[1])
    except (UnicodeDecodeError, ValidationError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
