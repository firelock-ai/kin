#!/usr/bin/env python3
"""Validate Kin registry-release dispatches before granting write authority."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


EXPECTED_EVENT = "repository_dispatch"
EXPECTED_ACTION = "kin-registry-release"
EXPECTED_REPOSITORY = "firelock-ai/kin"
EXPECTED_DEFAULT_BRANCH = "main"
ALLOWED_ACTORS = frozenset({"troyjr4103", "kin-release-bot[bot]"})
ALLOWED_SOURCES = {
    "kin-blobs": "firelock-ai/kin-blobs",
    "kin-db": "firelock-ai/kin-db",
    "kin-lsp": "firelock-ai/kin-lsp",
    "kin-model": "firelock-ai/kin-model",
    "kin-vfs-core": "firelock-ai/kin-vfs",
}
PAYLOAD_KEYS = frozenset(
    {"crate_name", "crate_version", "delivery_id", "source_repo", "source_sha"}
)
LOWER_SHA = re.compile(r"^[0-9a-f]{40}$")
STABLE_SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")


class ValidationError(ValueError):
    """The dispatch does not satisfy Kin's receiver contract."""


def _require_exact(label: str, actual: str, expected: str) -> None:
    if actual != expected:
        raise ValidationError(f"{label} must be {expected!r}, got {actual!r}")


def validate_context(
    *,
    event_name: str,
    event_action: str,
    actor: str,
    repository: str,
    default_branch: str,
    ref: str,
    workflow_sha: str,
) -> None:
    """Validate GitHub-owned dispatch context before loading write credentials."""

    _require_exact("event name", event_name, EXPECTED_EVENT)
    _require_exact("event action", event_action, EXPECTED_ACTION)
    _require_exact("repository", repository, EXPECTED_REPOSITORY)
    _require_exact("default branch", default_branch, EXPECTED_DEFAULT_BRANCH)
    _require_exact("workflow ref", ref, f"refs/heads/{EXPECTED_DEFAULT_BRANCH}")
    if actor not in ALLOWED_ACTORS:
        raise ValidationError(f"actor {actor!r} is not authorized")
    if LOWER_SHA.fullmatch(workflow_sha) is None:
        raise ValidationError(
            f"workflow sha must be 40-character lowercase hex, got {workflow_sha!r}"
        )


def validate_payload(payload: Any) -> dict[str, str]:
    """Validate the sender payload and its package-to-source boundary."""

    if not isinstance(payload, dict):
        raise ValidationError("client_payload must be an object")
    actual_keys = frozenset(payload)
    if actual_keys != PAYLOAD_KEYS:
        missing = sorted(PAYLOAD_KEYS - actual_keys)
        unexpected = sorted(actual_keys - PAYLOAD_KEYS)
        raise ValidationError(
            f"client_payload keys differ from contract; missing={missing}, "
            f"unexpected={unexpected}"
        )
    if any(not isinstance(payload[key], str) for key in PAYLOAD_KEYS):
        raise ValidationError("every client_payload value must be a string")

    normalized: dict[str, str] = {key: payload[key] for key in PAYLOAD_KEYS}
    crate_name = normalized["crate_name"]
    source_repo = normalized["source_repo"]
    expected_source = ALLOWED_SOURCES.get(crate_name)
    if expected_source is None:
        raise ValidationError(
            f"crate {crate_name!r} is outside Kin's root-manifest dependency boundary"
        )
    if source_repo != expected_source:
        raise ValidationError(
            f"crate {crate_name!r} must come from {expected_source!r}, "
            f"got {source_repo!r}"
        )

    crate_version = normalized["crate_version"]
    if STABLE_SEMVER.fullmatch(crate_version) is None:
        raise ValidationError(
            f"crate version must be stable SemVer X.Y.Z, got {crate_version!r}"
        )
    source_sha = normalized["source_sha"]
    if LOWER_SHA.fullmatch(source_sha) is None:
        raise ValidationError(
            f"source sha must be 40-character lowercase hex, got {source_sha!r}"
        )
    expected_delivery = (
        f"{source_repo}@{source_sha}:{crate_name}@{crate_version}"
    )
    if normalized["delivery_id"] != expected_delivery:
        raise ValidationError(
            "delivery_id does not bind the exact source repo, source sha, crate, "
            "and version"
        )
    return normalized


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--event-file", type=Path, required=True)
    parser.add_argument("--event-name", required=True)
    parser.add_argument("--event-action", required=True)
    parser.add_argument("--actor", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--default-branch", required=True)
    parser.add_argument("--ref", required=True)
    parser.add_argument("--workflow-sha", required=True)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        with args.event_file.open(encoding="utf-8") as stream:
            event = json.load(stream)
        if not isinstance(event, dict):
            raise ValidationError("event document must be an object")
        _require_exact(
            "event document action", str(event.get("action", "")), args.event_action
        )
        validate_context(
            event_name=args.event_name,
            event_action=args.event_action,
            actor=args.actor,
            repository=args.repository,
            default_branch=args.default_branch,
            ref=args.ref,
            workflow_sha=args.workflow_sha,
        )
        payload = validate_payload(event.get("client_payload"))
    except (OSError, json.JSONDecodeError, ValidationError) as error:
        print(
            f"::error title=Invalid Kin registry release::{error}",
            file=sys.stderr,
        )
        return 1

    print(
        "validated Kin registry release "
        f"{payload['crate_name']}@{payload['crate_version']} from "
        f"{payload['source_repo']}@{payload['source_sha']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
