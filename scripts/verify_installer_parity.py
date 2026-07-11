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

    try:
        manifest: Any = json.loads(public_manifest)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ParityError(f"public current.json is missing or invalid: {error}") from error
    if not isinstance(manifest, dict):
        raise ParityError("public current.json is not a JSON object")
    expected = {
        "schema": 1,
        "tag": tag,
        "sha": commit,
        "install_sha256": install_sha,
        "install_ps1_sha256": ps1_sha,
    }
    for key, value in expected.items():
        if manifest.get(key) != value:
            raise ParityError(
                f"public current.json {key}={manifest.get(key)!r}, expected {value!r}"
            )
    for key in ("install_generation", "install_ps1_generation"):
        if re.fullmatch(r"[0-9]+", str(manifest.get(key, ""))) is None:
            raise ParityError(f"public current.json has invalid {key}")

    return ParityResult(install_sha, ps1_sha)


def fetch(url: str, attempts: int = 4) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "kin-installer-parity"})
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return response.read()
        except (urllib.error.URLError, TimeoutError) as error:
            last_error = error
            if attempt < attempts:
                time.sleep(attempt * 2)
    raise ParityError(f"could not fetch {url}: {last_error}")


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
    parser.add_argument("tag", help="Exact stable release tag, for example v0.2.16")
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
        result = verify_payloads(
            tag=args.tag,
            commit=commit,
            source_install=fetch(f"{raw}/install.sh"),
            source_install_ps1=fetch(f"{raw}/install.ps1"),
            public_install=fetch(f"{base}/install"),
            public_install_ps1=fetch(f"{base}/install.ps1"),
            public_manifest=fetch(f"{base}/current.json"),
        )
    except (ParityError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        print(f"installer parity failed: {error}", file=sys.stderr)
        return 1

    print(
        f"installer parity verified: {args.tag}@{commit} "
        f"install={result.install_sha256} install.ps1={result.install_ps1_sha256}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
