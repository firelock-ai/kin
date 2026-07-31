#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
"""Select the highest release tag the serialized release rail must wait on.

The rail serializes on one predicate: the highest `vX.Y.Z` tag in the repository
must already be the finalized GitHub Latest release before a newer tag is minted
or a newer version is prepared. That predicate exists so an in-flight release is
never leapfrogged, and it holds the highest tag responsible for finishing.

A tag whose artifacts can never be built cannot finish. Left alone it holds the
predicate closed against every successor forever, including the successor that
repairs whatever made it unbuildable. Abandonment is the explicit way out, and
it is a reviewed record in tracked source rather than a runtime inference from
how a build happens to be going. Only a record waives the predicate for a tag; a
tag that is merely failing so far carries none and keeps blocking, which is
precisely the case the predicate exists to serialize.

A record is honoured only while it still describes the repository. It names the
exact commit its tag pointed at, so a tag that has since moved refuses loudly
instead of silently waiving a different object than the one that was reviewed.

A record outlives the tag it names, and it is not inert when the tag is deleted.
Ranking stops being affected, because nothing in the listing can match it and so
nothing is skipped, and the recorded commit can no longer be validated against
the repository. The mint-intent refusal below still applies, because it reads the
record rather than the listing: a version declared abandoned stays refused even
if its tag is removed, which is the point. Deleting an abandoned tag while the
workspace version still equals it therefore leaves the version itself burned and
no tag to advance past, and the only way out is the version bump that drift
resolution proposes. Record the abandonment and leave the tag in place unless a
bump is landing with it.

Usage:
  select-admissible-release-tag.py MANIFEST CANDIDATES MINTING_TAG OUTPUT

MANIFEST    the abandonment record, read from protected main
CANDIDATES  `<tag> <commit>` lines, version-descending, from git for-each-ref
MINTING_TAG the tag this release is about to produce, or empty when none is
OUTPUT      file receiving the highest admissible tag, empty when there is none
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import NoReturn

SCHEMA_VERSION = 1
RELEASE_TAG = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+$")
COMMIT_SHA = re.compile(r"^[0-9a-f]{40}$")
WORKFLOW_RUN_ID = re.compile(r"^[1-9][0-9]*$")
# Every field is required. `reason` and `superseded_by` carry no machine
# meaning, and that is the point: an abandonment is a claim a reviewer has to be
# able to judge in the diff, so the record cannot be reduced to a bare tag.
RECORD_FIELDS = (
    "tag",
    "sha",
    "reason",
    "superseded_by",
    "failed_release_run_id",
)
MANIFEST_FIELDS = ("schema_version", "abandoned")


def refuse(message: str) -> NoReturn:
    """Fail the release rail loudly rather than degrading to a silent skip."""

    print(f"::error::{message}")
    raise SystemExit(1)


def load_abandonments(path: Path) -> dict[str, str]:
    """Return the reviewed tag-to-commit waivers, refusing anything malformed."""

    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as error:
        refuse(f"abandoned release-tag record is unreadable: {error}")
    try:
        manifest = json.loads(raw)
    except json.JSONDecodeError as error:
        refuse(f"abandoned release-tag record is not valid JSON: {error}")
    if not isinstance(manifest, dict):
        refuse("abandoned release-tag record must be a JSON object")
    unreviewed = sorted(set(manifest) - set(MANIFEST_FIELDS))
    if unreviewed:
        refuse(
            "abandoned release-tag record carries unreviewed keys: "
            f"{', '.join(unreviewed)}"
        )
    if manifest.get("schema_version") != SCHEMA_VERSION:
        refuse(
            "abandoned release-tag record must declare schema_version "
            f"{SCHEMA_VERSION}"
        )
    records = manifest.get("abandoned")
    if not isinstance(records, list):
        refuse("abandoned release-tag record must carry an 'abandoned' array")

    abandoned: dict[str, str] = {}
    for record in records:
        if not isinstance(record, dict):
            refuse("every abandonment entry must be a JSON object")
        unreviewed = sorted(set(record) - set(RECORD_FIELDS))
        if unreviewed:
            refuse(
                "abandonment entry carries unreviewed fields: "
                f"{', '.join(unreviewed)}"
            )
        missing = [
            field
            for field in RECORD_FIELDS
            if not isinstance(record.get(field), str) or not record[field].strip()
        ]
        if missing:
            refuse(
                "abandonment entry is missing required evidence: "
                f"{', '.join(missing)}"
            )
        tag = record["tag"]
        if not RELEASE_TAG.match(tag):
            refuse(f"abandoned tag '{tag}' is not a vX.Y.Z release tag")
        if tag in abandoned:
            refuse(f"release tag {tag} is recorded as abandoned more than once")
        if not COMMIT_SHA.match(record["sha"]):
            refuse(
                f"abandonment of {tag} must record the exact 40-hex commit it "
                "waives"
            )
        superseded_by = record["superseded_by"]
        if not RELEASE_TAG.match(superseded_by):
            refuse(f"abandonment of {tag} must name a vX.Y.Z superseding tag")
        if superseded_by == tag:
            refuse(f"abandonment of {tag} cannot name itself as its successor")
        if not WORKFLOW_RUN_ID.match(record["failed_release_run_id"]):
            refuse(f"abandonment of {tag} must cite the Release run id that failed")
        abandoned[tag] = record["sha"]
    return abandoned


def load_candidates(path: Path) -> list[tuple[str, str]]:
    """Return `(tag, commit)` pairs in the order git already ranked them."""

    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as error:
        refuse(f"release tag listing is unreadable: {error}")
    candidates: list[tuple[str, str]] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        fields = line.split(" ")
        if len(fields) != 2 or not fields[0] or not COMMIT_SHA.match(fields[1]):
            refuse(f"release tag listing carries an unreadable record: {line}")
        candidates.append((fields[0], fields[1]))
    return candidates


def main(argv: list[str]) -> int:
    if len(argv) != 5:
        refuse(
            "usage: select-admissible-release-tag.py MANIFEST CANDIDATES "
            "MINTING_TAG OUTPUT"
        )
    manifest_path, candidates_path, minting_tag, output_path = argv[1:]
    abandoned = load_abandonments(Path(manifest_path))
    candidates = load_candidates(Path(candidates_path))

    present: dict[str, str] = {}
    for tag, commit in candidates:
        if present.get(tag, commit) != commit:
            refuse(f"release tag {tag} was listed against two different commits")
        present[tag] = commit

    for tag, commit in sorted(abandoned.items()):
        listed = present.get(tag)
        if listed is not None and listed != commit:
            refuse(
                f"abandonment of {tag} waives {commit} but the tag now names "
                f"{listed}; correct the reviewed record before releasing"
            )

    if minting_tag and minting_tag in abandoned:
        refuse(
            f"{minting_tag} is recorded as an abandoned release tag and must "
            "not be released"
        )

    highest = ""
    for tag, commit in candidates:
        if not RELEASE_TAG.match(tag):
            continue
        if abandoned.get(tag) == commit:
            print(f"::notice::skipping abandoned release tag {tag} at {commit}")
            continue
        highest = tag
        break

    Path(output_path).write_text(highest, encoding="utf-8")
    print(f"highest admissible release tag: {highest or '<none>'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
