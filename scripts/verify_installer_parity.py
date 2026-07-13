#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

"""Verify that both public installers exactly match one published Kin tag."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any


TAG_RE = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
DEFAULT_REPOSITORY = "firelock-ai/kin"
DEFAULT_BASE_URL = "https://get.kinlab.dev"


class ParityError(RuntimeError):
    """The public installer surface does not match the requested release."""


@dataclass(frozen=True)
class ParityResult:
    install_sha256: str
    install_ps1_sha256: str
    install_generation: str
    install_ps1_generation: str


@dataclass(frozen=True)
class FetchResult:
    body: bytes
    generation: str | None


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_payloads(
    *,
    tag: str,
    commit: str,
    source_install: bytes,
    source_install_ps1: bytes,
    public_install: bytes,
    public_install_ps1: bytes,
    public_manifest: bytes,
    public_install_generation: str | None,
    public_install_ps1_generation: str | None,
) -> ParityResult:
    if TAG_RE.fullmatch(tag) is None:
        raise ParityError(f"invalid stable release tag: {tag}")
    if SHA_RE.fullmatch(commit) is None:
        raise ParityError(f"invalid peeled release commit: {commit}")

    install_sha = sha256(source_install)
    ps1_sha = sha256(source_install_ps1)
    public_install_sha = sha256(public_install)
    public_ps1_sha = sha256(public_install_ps1)
    if public_install_sha != install_sha:
        raise ParityError(
            "public install hash mismatch: "
            f"expected {install_sha}, served {public_install_sha}"
        )
    if public_ps1_sha != ps1_sha:
        raise ParityError(
            "public install.ps1 hash mismatch: "
            f"expected {ps1_sha}, served {public_ps1_sha}"
        )

    public_generations = {
        "install_generation": public_install_generation,
        "install_ps1_generation": public_install_ps1_generation,
    }
    for key, value in public_generations.items():
        if value is None or re.fullmatch(r"[0-9]+", value) is None:
            raise ParityError(
                f"public endpoint has missing or invalid x-goog-generation for {key}"
            )

    try:
        manifest: Any = json.loads(public_manifest)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ParityError(
            f"public current.json is missing or invalid: {error}"
        ) from error
    if not isinstance(manifest, dict):
        raise ParityError("public current.json is not a JSON object")
    expected = {
        "schema": 1,
        "tag": tag,
        "sha": commit,
        "install_sha256": install_sha,
        "install_ps1_sha256": ps1_sha,
        **public_generations,
    }
    for key, value in expected.items():
        if manifest.get(key) != value:
            raise ParityError(
                f"public current.json {key}={manifest.get(key)!r}, expected {value!r}"
            )
    return ParityResult(
        install_sha,
        ps1_sha,
        public_install_generation,
        public_install_ps1_generation,
    )


def fetch_response(url: str, attempts: int = 4) -> FetchResult:
    request = urllib.request.Request(
        url, headers={"User-Agent": "kin-installer-parity"}
    )
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                generation = response.headers.get("x-goog-generation")
                return FetchResult(
                    body=response.read(),
                    generation=generation.strip() if generation is not None else None,
                )
        except (urllib.error.URLError, TimeoutError) as error:
            last_error = error
            if attempt < attempts:
                time.sleep(attempt * 2)
    raise ParityError(f"could not fetch {url}: {last_error}")


def fetch(url: str, attempts: int = 4) -> bytes:
    return fetch_response(url, attempts).body


def resolve_tag(repository: str, tag: str) -> str:
    remote = f"https://github.com/{repository}.git"
    result = subprocess.run(
        [
            "git",
            "ls-remote",
            "--tags",
            remote,
            f"refs/tags/{tag}",
            f"refs/tags/{tag}^{{}}",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    direct = ""
    peeled = ""
    for line in result.stdout.splitlines():
        commit, ref = line.split(maxsplit=1)
        if ref == f"refs/tags/{tag}^{{}}":
            peeled = commit
        elif ref == f"refs/tags/{tag}":
            direct = commit
    commit = peeled or direct
    if SHA_RE.fullmatch(commit) is None:
        raise ParityError(f"could not resolve peeled commit for {tag}")
    return commit


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tag", help="Exact stable release tag, for example v0.2.20")
    parser.add_argument("--expected-sha", help="Optional expected peeled 40-hex commit")
    parser.add_argument("--repository", default=DEFAULT_REPOSITORY)
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    args = parser.parse_args()

    try:
        if TAG_RE.fullmatch(args.tag) is None:
            raise ParityError(f"invalid stable release tag: {args.tag}")
        commit = resolve_tag(args.repository, args.tag)
        if args.expected_sha is not None and commit != args.expected_sha:
            raise ParityError(
                f"{args.tag} peels to {commit}, expected {args.expected_sha}"
            )
        raw = f"https://raw.githubusercontent.com/{args.repository}/{commit}/scripts"
        base = args.base_url.rstrip("/")
        public_install = fetch_response(f"{base}/install")
        public_install_ps1 = fetch_response(f"{base}/install.ps1")
        result = verify_payloads(
            tag=args.tag,
            commit=commit,
            source_install=fetch(f"{raw}/install.sh"),
            source_install_ps1=fetch(f"{raw}/install.ps1"),
            public_install=public_install.body,
            public_install_ps1=public_install_ps1.body,
            public_manifest=fetch(f"{base}/current.json"),
            public_install_generation=public_install.generation,
            public_install_ps1_generation=public_install_ps1.generation,
        )
    except (
        ParityError,
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
    ) as error:
        print(f"installer parity failed: {error}", file=sys.stderr)
        return 1

    print(
        f"installer parity verified: {args.tag}@{commit} "
        f"install={result.install_sha256}#{result.install_generation} "
        f"install.ps1={result.install_ps1_sha256}#{result.install_ps1_generation}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
