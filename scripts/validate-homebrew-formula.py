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
KIN_CLASS_RE = re.compile(r"^class\s+Kin\s*<\s*Formula$")
OS_RE = re.compile(r"^on_(macos|linux)\s+do$")
ARCH_RE = re.compile(r"^on_(arm|intel)\s+do$")
BLOCK_KEYWORD_RE = re.compile(
    r"^(class|module|def|if|unless|case|begin|while|until|for)(?:\s|\(|$)"
)
DO_BLOCK_RE = re.compile(r"(?:^|\s)do(?:\s*\|[^|]*\|)?$")
INLINE_END_RE = re.compile(r"(?:^|;)\s*end\b")
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


@dataclass(frozen=True)
class RubyBlock:
    kind: str
    label: str
    line_number: int
    value: str | None = None


@dataclass(frozen=True)
class PendingUrl:
    line_number: int
    platform: tuple[str, str]
    artifact: str
    url: str


def expected_url(artifact: str) -> str:
    return (
        f"https://github.com/firelock-ai/kin/releases/download/v#{{version}}/{artifact}"
    )


def ruby_code(line: str) -> str:
    """Return code before a Ruby comment, preserving hashes inside strings."""

    quote: str | None = None
    escaped = False
    for index, character in enumerate(line):
        if quote is not None:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            continue
        if character in {'"', "'"}:
            quote = character
        elif character == "#":
            return line[:index].strip()
    return line.strip()


def ruby_structure_code(line: str) -> str:
    """Return Ruby code with strings/comments blanked for keyword checks."""

    retained: list[str] = []
    quote: str | None = None
    escaped = False
    for character in line:
        if quote is not None:
            retained.append(" ")
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            continue
        if character in {'"', "'"}:
            quote = character
            retained.append(" ")
        elif character == "#":
            break
        else:
            retained.append(character)
    return "".join(retained).strip()


def missing_sha_error(pending: PendingUrl) -> ValidationError:
    return ValidationError(
        f"missing sha256 directive after URL for {pending.artifact} "
        f"at formula line {pending.line_number}"
    )


def is_direct_kin_scope(blocks: list[RubyBlock]) -> bool:
    return len(blocks) == 1 and blocks[0].kind == "kin_class"


def current_platform(blocks: list[RubyBlock]) -> tuple[str, str] | None:
    if [block.kind for block in blocks] != ["kin_class", "os", "arch"]:
        return None
    os_name = blocks[1].value
    arch = blocks[2].value
    if os_name is None or arch is None:
        return None
    return os_name, arch


def render_unclosed_blocks(blocks: list[RubyBlock]) -> str:
    return ", ".join(
        f"{block.label} opened at line {block.line_number}" for block in blocks
    )


def parse_formula(formula: str, expected_version: str) -> dict[str, FormulaPair]:
    lines = formula.splitlines()
    blocks: list[RubyBlock] = []
    versions: list[str] = []
    kin_class_count = 0
    pairs_by_platform: dict[tuple[str, str], FormulaPair] = {}
    url_count = 0
    sha_count = 0
    pending_url: PendingUrl | None = None

    for index, line in enumerate(lines):
        line_number = index + 1
        code = ruby_code(line)
        if not code:
            continue

        if code == "end":
            if pending_url is not None:
                raise missing_sha_error(pending_url)
            if not blocks:
                raise ValidationError(
                    f"unmatched or extra end at formula line {line_number}"
                )
            blocks.pop()
            continue
        if INLINE_END_RE.search(ruby_structure_code(line)):
            raise ValidationError(
                f"unsupported inline or extra end at formula line {line_number}"
            )

        if match := OS_RE.fullmatch(code):
            if pending_url is not None:
                raise missing_sha_error(pending_url)
            if not is_direct_kin_scope(blocks):
                raise ValidationError(
                    "operating-system block must be directly inside "
                    f"class Kin < Formula at formula line {line_number}"
                )
            os_name = match.group(1)
            blocks.append(RubyBlock("os", f"on_{os_name} do", line_number, os_name))
            continue
        if match := ARCH_RE.fullmatch(code):
            if pending_url is not None:
                raise missing_sha_error(pending_url)
            if [block.kind for block in blocks] != ["kin_class", "os"]:
                raise ValidationError(
                    "architecture block must be directly inside a supported "
                    f"operating-system block at formula line {line_number}"
                )
            arch = match.group(1)
            blocks.append(RubyBlock("arch", f"on_{arch} do", line_number, arch))
            continue

        if KIN_CLASS_RE.fullmatch(code):
            if pending_url is not None:
                raise missing_sha_error(pending_url)
            kin_class_count += 1
            if kin_class_count > 1:
                raise ValidationError(
                    "expected exactly one class Kin < Formula declaration; "
                    f"found {kin_class_count}"
                )
            if blocks:
                raise ValidationError(
                    f"class Kin < Formula must be top-level at formula line {line_number}"
                )
            blocks.append(RubyBlock("kin_class", "class Kin < Formula", line_number))
            continue

        version_match = VERSION_RE.fullmatch(line)
        if version_match:
            if pending_url is not None:
                raise missing_sha_error(pending_url)
            if not is_direct_kin_scope(blocks):
                raise ValidationError(
                    "version directive must be directly inside class Kin < Formula "
                    f"at formula line {line_number}"
                )
            versions.append(version_match.group(1))
            continue

        url_match = URL_RE.fullmatch(line)
        if url_match:
            if pending_url is not None:
                raise missing_sha_error(pending_url)
            url_count += 1
            platform = current_platform(blocks)
            if platform is None:
                raise ValidationError(
                    "formula URL must be directly inside a supported architecture "
                    f"block at formula line {line_number}"
                )
            os_name, arch = platform
            artifact = SUPPORTED_ARTIFACTS[platform]
            if platform in pairs_by_platform:
                raise ValidationError(f"duplicate formula mapping for {os_name}/{arch}")

            expected = expected_url(artifact)
            actual_url = url_match.group(1)
            if actual_url != expected:
                raise ValidationError(
                    f"unexpected URL for {os_name}/{arch}: expected {expected!r}, got {actual_url!r}"
                )
            pending_url = PendingUrl(line_number, platform, artifact, actual_url)
            continue

        sha_match = SHA_RE.fullmatch(line)
        if sha_match:
            sha_count += 1
            if pending_url is None:
                raise ValidationError(
                    "sha256 directive is not paired with the immediately preceding "
                    f"supported URL at formula line {line_number}"
                )
            if current_platform(blocks) != pending_url.platform:
                raise ValidationError(
                    f"sha256 directive for {pending_url.artifact} is outside its architecture block"
                )
            sha = sha_match.group(1)
            if not HEX_RE.fullmatch(sha):
                raise ValidationError(
                    f"malformed sha256 for {pending_url.artifact}: expected 64 hexadecimal characters"
                )
            pairs_by_platform[pending_url.platform] = FormulaPair(
                artifact=pending_url.artifact,
                url=pending_url.url,
                sha256=sha.lower(),
            )
            pending_url = None
            continue

        if pending_url is not None:
            raise missing_sha_error(pending_url)

        if match := BLOCK_KEYWORD_RE.match(code):
            keyword = match.group(1)
            kind = "class" if keyword == "class" else keyword
            blocks.append(RubyBlock(kind, code, line_number))
            continue
        if DO_BLOCK_RE.search(code):
            blocks.append(RubyBlock("do", code, line_number))
            continue

    if pending_url is not None:
        raise missing_sha_error(pending_url)
    if blocks:
        raise ValidationError(
            f"unclosed Ruby block(s): {render_unclosed_blocks(blocks)}"
        )
    if kin_class_count != 1:
        raise ValidationError(
            "expected exactly one class Kin < Formula declaration; "
            f"found {kin_class_count}"
        )
    if len(versions) != 1:
        raise ValidationError(
            "expected exactly one active version directive for "
            f"{expected_version}; found {len(versions)}"
        )
    if versions[0] != expected_version:
        raise ValidationError(
            f"formula version is {versions[0]!r}, expected {expected_version!r}"
        )

    if url_count != len(SUPPORTED_ARTIFACTS):
        raise ValidationError(
            f"expected exactly {len(SUPPORTED_ARTIFACTS)} formula URL directives; found {url_count}"
        )
    if sha_count != len(SUPPORTED_ARTIFACTS):
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
