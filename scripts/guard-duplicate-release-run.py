#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

"""Refuse a release run whose tag another run already released.

On 2026-09-02 the v0.6.4 tag produced two Release runs, 147 and 148, seven
seconds apart. kin pushed once: release-tag.yml holds a single `POST /git/refs`
call, the ref still reads as a lightweight tag at the sha the mint wrote, and
release.yml's trigger is a single `push: tags` entry. The two runs carry
different check suites, so GitHub delivered one tag-creation push twice. Nothing
in this repository can suppress that delivery.

What it can do is refuse the second run. `concurrency: kin-release-promotion`
sets `cancel-in-progress: false`, so a duplicate does not disappear; it sits
pending for the whole release and then re-executes publish, npm publish,
promotion and the completion marker against a tag that is already out. Run 148
idled for over forty minutes that way.

This script is the decision. release.yml runs it in a first job that every other
job hangs off, and a `duplicate=true` verdict skips the release.

The rule:

1. A rerun is never a duplicate. `run_attempt > 1` means a human asked for this
   run on purpose, and refusing it would make the rerun button silently do
   nothing.
2. Otherwise the run is a duplicate when some OTHER run of this workflow, for
   this same tag, from a push, with a LOWER run number, has already concluded
   `success`.
3. Anything else proceeds.

Only a completed successful run counts. A failed earlier run leaves the release
undone, so a second delivery is the only thing left to finish it and must be
allowed to. An earlier run still in flight is not evidence either, because it
may yet fail.

Direction of failure is deliberate. When the listing cannot be trusted, the
verdict is `false` and the release proceeds, with a warning on the job. Refusing
on an unreadable answer would let one bad API page cancel a real release, which
is strictly worse than the duplicate this guards against: a duplicate is noisy
and its mutations are individually guarded, while a skipped release ships
nothing and nobody is paged.

`decide()` is a pure function over one snapshot document, so the test feeds it
fixtures with no GitHub in the loop.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from typing import Any


WORKFLOW_PATH = ".github/workflows/release.yml"


@dataclass(frozen=True)
class Verdict:
    """One decision, plus the sentence a reader of the job log needs."""

    duplicate: bool
    reason: str
    # The run that already released this tag, when there is one.
    prior_run_id: int | None = None
    # Set when the snapshot could not be trusted and the guard stood aside.
    unreadable: bool = False


def _int(value: Any) -> int | None:
    """Read an int that may arrive as a string, or as nothing at all."""
    if isinstance(value, bool) or value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def decide(snapshot: dict[str, Any]) -> Verdict:
    """Judge one run against every earlier run for its tag.

    `snapshot` carries the run's own identity (`tag`, `run_id`, `run_number`,
    `run_attempt`), the `runs` listing, and the `total_count` the API reported
    beside it so a short page is caught rather than read as an absence.
    """
    tag = snapshot.get("tag")
    run_id = _int(snapshot.get("run_id"))
    run_number = _int(snapshot.get("run_number"))
    attempt = _int(snapshot.get("run_attempt"))

    if not tag or run_id is None or run_number is None:
        return Verdict(
            False,
            "run identity incomplete, so no duplicate can be proven; proceeding",
            unreadable=True,
        )

    # A rerun is a deliberate act. Never refuse one.
    if attempt is not None and attempt > 1:
        return Verdict(
            False,
            f"run attempt {attempt} is a deliberate rerun, not a duplicate delivery",
        )

    runs = snapshot.get("runs")
    if not isinstance(runs, list):
        return Verdict(
            False,
            "no readable run listing, so no duplicate can be proven; proceeding",
            unreadable=True,
        )

    # The listing pages, and a short page reads exactly like "no earlier run".
    # Assert the count the API reported beside it rather than trusting length.
    total = _int(snapshot.get("total_count"))
    if total is not None and total != len(runs):
        return Verdict(
            False,
            (
                f"run listing is short, {len(runs)} of {total} reported, so an "
                "earlier release could be missing from it; proceeding"
            ),
            unreadable=True,
        )

    for run in sorted(
        (r for r in runs if isinstance(r, dict)),
        key=lambda r: _int(r.get("run_number")) or 0,
    ):
        other_id = _int(run.get("id"))
        other_number = _int(run.get("run_number"))
        if other_id is None or other_number is None:
            continue
        # Never judge against itself.
        if other_id == run_id:
            continue
        # A run with a higher number is a later duplicate of THIS run, and must
        # not silence the run it duplicated.
        if other_number >= run_number:
            continue
        # A tag filter is applied server-side, but a filter that silently stops
        # matching is a check that cannot fail, so it is applied here too.
        if run.get("head_branch") != tag:
            continue
        if run.get("event") != "push":
            continue
        if run.get("status") != "completed":
            continue
        if run.get("conclusion") != "success":
            continue
        return Verdict(
            True,
            (
                f"run {other_id} (number {other_number}) already released tag "
                f"{tag} and concluded success"
            ),
            prior_run_id=other_id,
        )

    return Verdict(False, f"no earlier successful release run for tag {tag}")


def fetch_snapshot(
    repo: str,
    tag: str,
    run_id: int,
    run_number: int,
    run_attempt: int,
    workflow: str,
) -> dict[str, Any]:
    """Ask GitHub for every push run of this workflow against this tag."""
    query = (
        f"repos/{repo}/actions/workflows/{_workflow_key(workflow)}/runs"
        f"?branch={tag}&event=push&per_page=100"
    )
    snapshot: dict[str, Any] = {
        "tag": tag,
        "run_id": run_id,
        "run_number": run_number,
        "run_attempt": run_attempt,
    }
    try:
        raw = subprocess.run(
            ["gh", "api", query],
            check=True,
            capture_output=True,
            text=True,
            timeout=120,
        ).stdout
        payload = json.loads(raw)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        detail = getattr(exc, "stderr", "") or str(exc)
        snapshot["error"] = f"listing runs failed: {detail.strip()[:400]}"
        return snapshot
    except json.JSONDecodeError as exc:
        snapshot["error"] = f"run listing was not JSON: {exc}"
        return snapshot

    snapshot["runs"] = payload.get("workflow_runs")
    snapshot["total_count"] = payload.get("total_count")
    return snapshot


def _workflow_key(workflow: str) -> str:
    """The API takes a workflow file name, not a repo-relative path."""
    return workflow.rsplit("/", 1)[-1]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo")
    parser.add_argument("--tag")
    parser.add_argument("--run-id", type=int)
    parser.add_argument("--run-number", type=int)
    parser.add_argument("--run-attempt", type=int, default=1)
    parser.add_argument("--workflow", default=WORKFLOW_PATH)
    parser.add_argument(
        "--snapshot",
        help="judge this snapshot file instead of asking GitHub",
    )
    args = parser.parse_args(argv)

    if args.snapshot:
        with open(args.snapshot, encoding="utf-8") as handle:
            snapshot = json.load(handle)
    else:
        missing = [
            name
            for name, value in (
                ("--repo", args.repo),
                ("--tag", args.tag),
                ("--run-id", args.run_id),
                ("--run-number", args.run_number),
            )
            if value in (None, "")
        ]
        if missing:
            parser.error(f"needs {', '.join(missing)} when no --snapshot is given")
        snapshot = fetch_snapshot(
            args.repo,
            args.tag,
            args.run_id,
            args.run_number,
            args.run_attempt,
            args.workflow,
        )
        if "error" in snapshot:
            print(f"::warning::{snapshot['error']}", file=sys.stderr)

    verdict = decide(snapshot)

    if verdict.unreadable:
        print(f"::warning::duplicate guard stood aside: {verdict.reason}", file=sys.stderr)
    elif verdict.duplicate:
        print(f"::notice::skipping this release: {verdict.reason}", file=sys.stderr)
    else:
        print(f"releasing: {verdict.reason}", file=sys.stderr)

    print(f"duplicate={'true' if verdict.duplicate else 'false'}")
    if verdict.prior_run_id is not None:
        print(f"prior_run_id={verdict.prior_run_id}")
    print(f"reason={verdict.reason}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
