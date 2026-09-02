#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

"""Select the release candidate the proof loop proves next, with nobody at a keyboard.

release-tag.yml mints a tag for the newest reviewed main commit in the staged
version's range that carries both proof records, and it refuses a required
context that appears more than once at that sha as ambiguous authority. Until
now a captain chose the sha those records would be filed under, pushed the
candidate branch, dispatched rc-build.yml and ran the preflight by hand. On
2026-09-02 that procedure lost a day: a rerun of a flaky required job made the
first candidate unmintable, and the host carrying the proof ran out of memory.

This script is the selection half of the pipeline. `select` reads everything
the decision rests on and answers one of four things:

  stand-down  nothing to do now: the version is tagged, a fully evidenced sha
              is waiting on the mint, the current candidate's preflight is
              recorded and only the stranger record is missing, an rc-build is
              still running, or no complete green sha exists yet
  arm         move release/v<version>-candidate to the chosen sha and dispatch
              rc-build.yml there
  proof       an rc-build for the current candidate succeeded and carries the
              preflight leg records; merge and publish them
  refuse      no reviewed main commit carrying the version qualifies, named sha
              by sha with the context that disqualified it

The rule, in the order it is applied:

1. v<version> exists as a tag: the cut is done and the train owns the next
   version.
2. A sha in the range carries both records: the mint owns it.
3. A current candidate, the branch tip, which must lie in the range, is kept
   until it is proven or dead. With its preflight recorded it waits for the
   stranger. Alive with a usable rc-build it is proven; alive with none it is
   armed again, up to RC_BUILD_ATTEMPT_LIMIT attempts. Dead means a required
   context that is red or duplicated, a CI or Acceptance push run that did not
   conclude success, or exhausted rc-build attempts.
4. Otherwise the newest main commit in the range whose CI and Acceptance push
   runs concluded success, and whose required contexts each appear exactly once
   under push provenance and concluded green, becomes the candidate. A sha still
   being graded is skipped rather than waited for: on a busy night the newest
   sha is always pending, and a selector that waits never converges. A sha that
   is red or ambiguous is named and skipped.

Every judgment is a pure function over one snapshot document, so the test feeds
it fixtures and asserts the decision with no GitHub in the loop.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import subprocess
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Sequence


EXPECTED_REPOSITORY = "firelock-ai/kin"
BASE_BRANCH = "main"
EVIDENCE_REF = "release-evidence"
PREFLIGHT_RECORD = "preflight.json"
STRANGER_RECORD = "stranger.env"
CI_WORKFLOW = ".github/workflows/ci.yml"
CI_WORKFLOW_NAME = "CI"
ACCEPTANCE_WORKFLOW = ".github/workflows/acceptance.yml"
RC_BUILD_WORKFLOW = ".github/workflows/rc-build.yml"
RC_BUILD_WORKFLOW_NAME = "RC Build"
# The artifacts rc-build.yml's preflight job uploads, one leg record per
# archive. A run missing one of them proved less than a record built from it
# would claim, so it is not usable evidence.
PREFLIGHT_ARTIFACT_PREFIX = "kin-release-preflight-"
PREFLIGHT_ARTIFACTS = ("kin-linux-aarch64", "kin-linux-x86_64", "kin-macos-aarch64")
# One rebuild is a flake allowance. A second failure on the same sha is a
# verdict about the sha, and the next landing supplies a new one.
RC_BUILD_ATTEMPT_LIMIT = 2
RANGE_LIMIT = 1000
PAGE_SIZE = 100
LOWER_SHA = re.compile(r"^[0-9a-f]{40}$")
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
CANDIDATE_BRANCH = re.compile(r"^release/v([0-9]+\.[0-9]+\.[0-9]+)-candidate$")
# Only the GitHub Actions App may write a required context name, pinned by
# numeric id as well as slug so a renamed or impersonating App cannot inherit
# the name. Mirrors release-tag.yml.
GITHUB_ACTIONS_APP = (15368, "github-actions")
# release-tag.yml's REQUIRED_CHECKS with the workflow provenance its mint binds
# each context to. scripts/test-select-release-candidate.py holds this table
# equal to the mint's own, so the selector cannot pick a sha the mint refuses
# for a context it never read.
REQUIRED_CONTEXTS = (
    ("Check & Test (ubuntu-latest)", 245803170, CI_WORKFLOW),
    ("Check & Test (macos-latest)", 245803170, CI_WORKFLOW),
    ("Falsify guards", 245803170, CI_WORKFLOW),
    ("Feature permutation tests (ubuntu-latest)", 245803170, CI_WORKFLOW),
    ("Feature permutation tests (macos-latest)", 245803170, CI_WORKFLOW),
    ("DCO Sign-off", 245803170, CI_WORKFLOW),
    ("cargo-deny", 251549972, ".github/workflows/sast.yml"),
    ("gitleaks (full history)", 293452372, ".github/workflows/secret-scan.yml"),
    ("Windows installer + vector release build", 245803170, CI_WORKFLOW),
)
SKIPPABLE_REQUIRED = frozenset({"DCO Sign-off"})
# The typed manual kick and who may send it, mirroring release-tag.yml's
# break-glass shape: a repository_dispatch always runs this workflow from the
# default branch, and the actor is pinned to the captain and the release App.
KICK_ACTION = "release_cut"
KICK_ACTORS = frozenset({"troyjr4103", "kin-release-bot[bot]"})
KICK_REASON_LIMIT = 200
TRIGGER_KICK = "kick"
TRIGGER_CI = "ci-completed"
TRIGGER_RC_BUILD = "rc-build-completed"
TRIGGER_SWEEP = "sweep"

STAND_DOWN = "stand-down"
ARM = "arm"
PROOF = "proof"
REFUSE = "refuse"
GREEN = "green"
PENDING = "pending"
DEAD = "dead"
MOVE_CREATE = "create"
MOVE_FAST_FORWARD = "fast-forward"
MOVE_RESET = "reset"
MOVE_NONE = "none"


class SelectionError(RuntimeError):
    """The candidate could not be selected on a trustworthy reading."""


class NotFound(SelectionError):
    """GitHub answered 404: the one answer a caller may act on differently."""


Fetch = Callable[[str], Any]
Grader = Callable[[str], dict[str, Any]]


# ---------------------------------------------------------------------------
# Endpoints. Named here so the live gather and the test agree byte for byte.
# ---------------------------------------------------------------------------


def candidate_branch(version: str) -> str:
    return f"release/v{version}-candidate"


def tag_endpoint(repository: str, version: str) -> str:
    return f"repos/{repository}/git/ref/tags/v{version}"


def evidence_tree_endpoint(repository: str) -> str:
    return f"repos/{repository}/git/trees/{EVIDENCE_REF}?recursive=1"


def branch_endpoint(repository: str, branch: str) -> str:
    return f"repos/{repository}/git/ref/heads/{branch}"


def rc_build_runs_endpoint(repository: str, branch: str, page: int = 1) -> str:
    return (
        f"repos/{repository}/actions/workflows/rc-build.yml/runs"
        f"?branch={branch}&event=workflow_dispatch&per_page={PAGE_SIZE}&page={page}"
    )


def run_artifacts_endpoint(repository: str, run_id: int, page: int = 1) -> str:
    return f"repos/{repository}/actions/runs/{run_id}/artifacts?per_page={PAGE_SIZE}&page={page}"


def check_runs_endpoint(repository: str, sha: str, page: int = 1) -> str:
    # `filter=all` is deliberate: a rerun that claims one required name is
    # ambiguous authority, not evidence to collapse by recency.
    return f"repos/{repository}/commits/{sha}/check-runs?per_page={PAGE_SIZE}&filter=all&page={page}"


def workflow_runs_endpoint(repository: str, sha: str, page: int = 1) -> str:
    return f"repos/{repository}/actions/runs?head_sha={sha}&per_page={PAGE_SIZE}&page={page}"


# ---------------------------------------------------------------------------
# Trigger validation, from GitHub-owned context only.
# ---------------------------------------------------------------------------


def _sha(value: Any) -> str | None:
    if isinstance(value, str) and LOWER_SHA.fullmatch(value):
        return value
    return None


def validate_trigger(
    *,
    event_name: str,
    event_action: str,
    actor: str,
    repository: str,
    default_branch: str,
    ref: str,
    workflow_sha: str,
    event: Any,
) -> dict[str, Any]:
    """Admit one of four trigger shapes, every one resolved from protected main.

    A CI completion for a main push and an RC Build completion on a candidate
    branch are the occasions that move the cut along; the typed kick is the
    manual arm GitHub's cron cannot stall; the schedule is the fallback. The
    event only decides when to look. Which sha is released is re-derived from
    scratch by `gather` and `judge`, never read off the event.
    """

    if repository != EXPECTED_REPOSITORY:
        raise SelectionError(f"repository must be {EXPECTED_REPOSITORY!r}, got {repository!r}")
    if default_branch != BASE_BRANCH:
        raise SelectionError(f"default branch must be {BASE_BRANCH!r}, got {default_branch!r}")
    if ref != f"refs/heads/{BASE_BRANCH}":
        raise SelectionError(f"workflow ref must be refs/heads/{BASE_BRANCH}, got {ref!r}")
    if _sha(workflow_sha) is None:
        raise SelectionError(f"workflow sha must be 40-character lowercase hex, got {workflow_sha!r}")
    if not isinstance(event, dict):
        raise SelectionError("event document must be an object")
    if event_name == "repository_dispatch":
        if event_action != KICK_ACTION:
            raise SelectionError(f"event action must be {KICK_ACTION!r}, got {event_action!r}")
        if event.get("action") != event_action:
            raise SelectionError("event document action differs from the trigger context")
        if actor not in KICK_ACTORS:
            raise SelectionError(f"actor {actor!r} may not kick the release cut")
        payload = event.get("client_payload")
        if payload is None:
            payload = {}
        if not isinstance(payload, dict) or set(payload) - {"reason"}:
            raise SelectionError("kick payload may carry a reason and nothing else")
        reason = payload.get("reason", "")
        if not isinstance(reason, str) or len(reason) > KICK_REASON_LIMIT:
            raise SelectionError("kick reason must be text of at most 200 characters")
        return {"trigger": TRIGGER_KICK, "actor": actor, "reason": reason}
    if event_name == "workflow_run":
        if event_action != "completed":
            raise SelectionError(f"workflow_run action must be 'completed', got {event_action!r}")
        run = event.get("workflow_run")
        if not isinstance(run, dict):
            raise SelectionError("workflow_run event omitted its run")
        head_repository = run.get("head_repository")
        if (
            not isinstance(head_repository, dict)
            or head_repository.get("full_name") != repository
        ):
            raise SelectionError("workflow_run head repository is not first-party")
        if run.get("status") != "completed":
            raise SelectionError("workflow_run is not completed")
        head_branch = run.get("head_branch")
        if run.get("path") == CI_WORKFLOW:
            if run.get("event") != "push" or head_branch != BASE_BRANCH:
                raise SelectionError(
                    f"a CI completion is an occasion only for a push to {BASE_BRANCH}, "
                    f"got {run.get('event')!r} on {head_branch!r}"
                )
            return {
                "trigger": TRIGGER_CI,
                "conclusion": run.get("conclusion"),
                "head_sha": run.get("head_sha"),
            }
        if run.get("path") == RC_BUILD_WORKFLOW:
            if run.get("event") != "workflow_dispatch" or not (
                isinstance(head_branch, str) and CANDIDATE_BRANCH.fullmatch(head_branch)
            ):
                raise SelectionError(
                    "an RC Build completion is an occasion only for a dispatch on a "
                    f"release/v<version>-candidate branch, got {run.get('event')!r} on "
                    f"{head_branch!r}"
                )
            return {
                "trigger": TRIGGER_RC_BUILD,
                "conclusion": run.get("conclusion"),
                "head_sha": run.get("head_sha"),
                "head_branch": head_branch,
                "run_id": run.get("id"),
            }
        raise SelectionError(
            f"workflow_run path {run.get('path')!r} is neither {CI_WORKFLOW} nor {RC_BUILD_WORKFLOW}"
        )
    if event_name == "schedule":
        if event_action != "":
            raise SelectionError(f"scheduled event action must be empty, got {event_action!r}")
        return {"trigger": TRIGGER_SWEEP}
    raise SelectionError(
        f"event name must be workflow_run, repository_dispatch or schedule, got {event_name!r}"
    )


# ---------------------------------------------------------------------------
# GitHub reads.
# ---------------------------------------------------------------------------


def gh_json(endpoint: str) -> Any:
    result = subprocess.run(
        ["gh", "api", endpoint],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "no output"
        if "HTTP 404" in detail:
            raise NotFound(f"gh api {endpoint}: {detail}")
        raise SelectionError(f"gh api {endpoint} failed: {detail}")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise SelectionError(f"GitHub returned malformed JSON for {endpoint}") from exc


def _count(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise SelectionError(f"{label} is not a count: {value!r}")
    return value


def flatten_pages(pages: Any, key: str) -> list[dict[str, Any]]:
    """Flatten a paged listing and refuse one that does not add up.

    The endpoints page at 100 and fail toward green: a page that arrives short
    reads exactly like a sha with fewer checks. Every page carries the same
    `total_count`, so the listed length is asserted against it.
    """

    if not isinstance(pages, list) or not pages:
        raise SelectionError(f"{key} listing has no pages")
    items: list[dict[str, Any]] = []
    totals: set[int] = set()
    for page in pages:
        if not isinstance(page, dict):
            raise SelectionError(f"{key} page is not an object")
        totals.add(_count(page.get("total_count"), f"{key} total_count"))
        chunk = page.get(key)
        if not isinstance(chunk, list):
            raise SelectionError(f"{key} page carries no {key} list")
        for item in chunk:
            if not isinstance(item, dict):
                raise SelectionError(f"{key} entry is not an object")
            items.append(item)
    if len(totals) != 1:
        raise SelectionError(
            f"{key} listing changed under the read: total_count {sorted(totals)}"
        )
    total = totals.pop()
    if len(items) != total:
        raise SelectionError(f"{key} listing is incomplete: {len(items)} listed of {total}")
    return items


def read_listing(fetch: Fetch, endpoint_for_page: Callable[[int], str], key: str) -> list[dict[str, Any]]:
    first = fetch(endpoint_for_page(1))
    if not isinstance(first, dict):
        raise SelectionError(f"{key} listing is not an object")
    total = _count(first.get("total_count"), f"{key} total_count")
    pages = [first]
    for page in range(2, max(1, math.ceil(total / PAGE_SIZE)) + 1):
        pages.append(fetch(endpoint_for_page(page)))
    return flatten_pages(pages, key)


def read_tag_exists(fetch: Fetch, repository: str, version: str) -> bool:
    try:
        document = fetch(tag_endpoint(repository, version))
    except NotFound:
        return False
    ref_object = document.get("object") if isinstance(document, dict) else None
    if not isinstance(ref_object, dict) or _sha(ref_object.get("sha")) is None:
        raise SelectionError(f"tag v{version} read back without an exact object sha")
    return True


def read_evidence(fetch: Fetch, repository: str) -> dict[str, list[str]]:
    """Which candidates the proof loop recorded, the way the mint reads them.

    An unreadable listing is not an empty one, and a truncated listing could
    hide a newer proven candidate, so both refuse rather than answer.
    """

    listing = fetch(evidence_tree_endpoint(repository))
    if not isinstance(listing, dict) or not isinstance(listing.get("tree"), list):
        raise SelectionError(
            f"the {EVIDENCE_REF} listing is not a git tree object, so the proof "
            "loop's records cannot be read"
        )
    if listing.get("truncated") is True:
        raise SelectionError(
            f"the {EVIDENCE_REF} listing is truncated, so a newer proven candidate "
            "could be invisible"
        )
    pattern = re.compile(r"^evidence/([0-9a-f]{40})/(preflight\.json|stranger\.env)$")
    evidence: dict[str, list[str]] = {}
    for entry in listing["tree"]:
        if not isinstance(entry, dict) or entry.get("type") != "blob":
            continue
        match = pattern.fullmatch(str(entry.get("path", "")))
        if match is None:
            continue
        records = evidence.setdefault(match.group(1), [])
        if match.group(2) not in records:
            records.append(match.group(2))
    return evidence


def read_branch(fetch: Fetch, repository: str, branch: str) -> str | None:
    try:
        document = fetch(branch_endpoint(repository, branch))
    except NotFound:
        return None
    ref_object = document.get("object") if isinstance(document, dict) else None
    sha = _sha(ref_object.get("sha")) if isinstance(ref_object, dict) else None
    if sha is None:
        raise SelectionError(f"branch {branch} read back without an exact object sha")
    return sha


def read_rc_builds(fetch: Fetch, repository: str, branch: str) -> list[dict[str, Any]]:
    """Every rc-build dispatch on the candidate branch, newest first.

    A completed successful run also carries the names of its artifacts, which
    is how a run from before the preflight job existed is told apart from one
    whose leg records can be published.
    """

    runs = read_listing(
        fetch, lambda page: rc_build_runs_endpoint(repository, branch, page), "workflow_runs"
    )
    builds = []
    for run in runs:
        run_id = _count(run.get("id"), "rc-build run id")
        record = {
            "id": run_id,
            "head_sha": run.get("head_sha"),
            "head_branch": run.get("head_branch"),
            "event": run.get("event"),
            "status": run.get("status"),
            "conclusion": run.get("conclusion"),
            "created_at": run.get("created_at") or "",
            "artifacts": [],
        }
        if record["status"] == "completed" and record["conclusion"] == "success":
            artifacts = read_listing(
                fetch, lambda page, rid=run_id: run_artifacts_endpoint(repository, rid, page), "artifacts"
            )
            record["artifacts"] = sorted(
                str(artifact.get("name")) for artifact in artifacts if not artifact.get("expired")
            )
        builds.append(record)
    builds.sort(key=lambda build: (build["created_at"], build["id"]), reverse=True)
    return builds


def run_git(workspace: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(workspace), *arguments],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "no output"
        raise SelectionError(f"git {' '.join(arguments)} failed: {detail}")
    return result.stdout.strip()


def workspace_version(cargo_toml: str) -> str:
    try:
        version = tomllib.loads(cargo_toml)["workspace"]["package"]["version"]
    except (tomllib.TOMLDecodeError, KeyError, TypeError) as exc:
        raise SelectionError(f"Cargo.toml carries no [workspace.package] version: {exc}") from exc
    if not isinstance(version, str) or VERSION.fullmatch(version) is None:
        raise SelectionError(f"workspace version {version!r} is not semver-shaped")
    return version


def version_range(workspace: Path, tip: str, version: str) -> list[str]:
    """The reviewed main commits carrying `version`, newest first.

    The floor is the squash of the version bump: the oldest first-parent commit
    whose Cargo.toml carries this version. Nothing before it can be this
    release, because nothing before it carries the version the tag names.
    """

    log = run_git(workspace, "log", "--first-parent", f"--max-count={RANGE_LIMIT}", "--format=%H", tip)
    shas = []
    for sha in log.splitlines():
        sha = sha.strip()
        if _sha(sha) is None:
            raise SelectionError(f"git log produced a non-sha line {sha!r}")
        if workspace_version(run_git(workspace, "show", f"{sha}:Cargo.toml")) != version:
            break
        shas.append(sha)
    if not shas:
        raise SelectionError(f"the tip {tip} does not carry version {version}")
    return shas


# ---------------------------------------------------------------------------
# Grading one sha. Pure over the two listings the mint reads.
# ---------------------------------------------------------------------------


def grade_sha(sha: str, check_run_pages: Any, workflow_run_pages: Any) -> dict[str, Any]:
    """Decide whether one sha is green, pending or dead for the mint.

    Green means the CI and Acceptance push runs on main concluded success and
    every required context appears exactly once under push provenance at this
    sha, by the GitHub Actions App, concluded success (DCO Sign-off may report
    skipped on a merged commit). Pending means a producing run has not finished.
    Everything else is dead, and a rerun is the reason that matters most: the
    mint refuses a required context that appears more than once as ambiguous
    authority, whatever the copies concluded.
    """

    if _sha(sha) is None:
        raise SelectionError(f"cannot grade {sha!r}: not a 40-character lowercase sha")
    check_runs = flatten_pages(check_run_pages, "check_runs")
    workflow_runs = flatten_pages(workflow_run_pages, "workflow_runs")
    dead: list[str] = []
    pending: list[str] = []

    by_suite: dict[Any, list[dict[str, Any]]] = {}
    for run in workflow_runs:
        by_suite.setdefault(run.get("check_suite_id"), []).append(run)

    def push_runs(path: str) -> list[dict[str, Any]]:
        return [
            run
            for run in workflow_runs
            if run.get("path") == path
            and run.get("event") == "push"
            and run.get("head_branch") == BASE_BRANCH
            and run.get("head_sha") == sha
        ]

    for label, path in (("CI", CI_WORKFLOW), ("Acceptance", ACCEPTANCE_WORKFLOW)):
        runs = push_runs(path)
        if not runs:
            pending.append(f"no {label} push run on {BASE_BRANCH} at this sha yet")
        elif len(runs) > 1:
            dead.append(f"{len(runs)} {label} push runs at this sha: ambiguous authority")
        else:
            run = runs[0]
            if run.get("status") != "completed":
                pending.append(f"{label} push run {run.get('id')} is {run.get('status')}")
            elif run.get("conclusion") != "success":
                dead.append(f"{label} push run {run.get('id')} concluded {run.get('conclusion')}")

    by_name: dict[Any, list[dict[str, Any]]] = {}
    for check in check_runs:
        by_name.setdefault(check.get("name"), []).append(check)

    for name, workflow_id, path in REQUIRED_CONTEXTS:
        admitted = []
        for check in by_name.get(name, []):
            app = check.get("app") if isinstance(check.get("app"), dict) else {}
            if (app.get("id"), app.get("slug")) != GITHUB_ACTIONS_APP:
                dead.append(f"required check name claimed by another app: {name} ({app.get('slug')!r})")
                continue
            suite = check.get("check_suite") if isinstance(check.get("check_suite"), dict) else {}
            producers = by_suite.get(suite.get("id"), [])
            if len(producers) != 1:
                dead.append(
                    f"required check has ambiguous workflow provenance: {name} "
                    f"(suite={suite.get('id')}, workflow-runs={len(producers)})"
                )
                continue
            producer = producers[0]
            on_main_push = (
                producer.get("event") == "push"
                and producer.get("head_branch") == BASE_BRANCH
                and producer.get("head_sha") == sha
                and producer.get("conclusion") != "cancelled"
            )
            if (producer.get("workflow_id"), producer.get("path")) != (workflow_id, path):
                if on_main_push:
                    # A second writer of a required context name on the ref this
                    # release is proved from is an authority conflict, never a
                    # fallback. Off that ref it is somebody else's build at the
                    # same sha and is discounted.
                    dead.append(
                        f"required check workflow provenance mismatch: {name} "
                        f"produced by {producer.get('path')} run {producer.get('id')}"
                    )
                continue
            if on_main_push:
                admitted.append(check)
        if not admitted:
            producers_running = any(
                run.get("status") != "completed" for run in push_runs(path)
            )
            (pending if producers_running else dead).append(
                f"missing required check: {name} "
                f"({len(by_name.get(name, []))} same-named check-runs, none under push provenance)"
            )
            continue
        if len(admitted) != 1:
            dead.append(
                f"ambiguous required check: {name} ({len(admitted)} check-runs under one "
                "provenance; a rerun is what makes a sha unmintable)"
            )
            continue
        check = admitted[0]
        if check.get("status") != "completed":
            pending.append(f"required check not completed: {name} ({check.get('status')})")
            continue
        allowed = {"success", "skipped"} if name in SKIPPABLE_REQUIRED else {"success"}
        if check.get("conclusion") not in allowed:
            dead.append(f"required check not green: {name} (conclusion={check.get('conclusion')})")

    verdict = DEAD if dead else (PENDING if pending else GREEN)
    return {"sha": sha, "verdict": verdict, "dead": dead, "pending": pending}


def grade_live(fetch: Fetch, repository: str, sha: str) -> dict[str, Any]:
    check_pages = [fetch(check_runs_endpoint(repository, sha, 1))]
    total = _count(check_pages[0].get("total_count"), "check_runs total_count") if isinstance(check_pages[0], dict) else 0
    for page in range(2, max(1, math.ceil(total / PAGE_SIZE)) + 1):
        check_pages.append(fetch(check_runs_endpoint(repository, sha, page)))
    run_pages = [fetch(workflow_runs_endpoint(repository, sha, 1))]
    total = _count(run_pages[0].get("total_count"), "workflow_runs total_count") if isinstance(run_pages[0], dict) else 0
    for page in range(2, max(1, math.ceil(total / PAGE_SIZE)) + 1):
        run_pages.append(fetch(workflow_runs_endpoint(repository, sha, page)))
    return grade_sha(sha, check_pages, run_pages)


# ---------------------------------------------------------------------------
# The judgment.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Decision:
    decision: str
    reason: str
    version: str
    branch: str
    candidate: str | None = None
    rc_run: int | None = None
    move: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def document(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "reason": self.reason,
            "version": self.version,
            "branch": self.branch,
            "candidate": self.candidate,
            "rc_run": self.rc_run,
            "move": self.move,
            "details": self.details,
        }


def stranger_command(version: str, sha: str, rc_run: int | None) -> str:
    """The local step the workflow prints while the stranger has no hosted host.

    An exported ANTHROPIC_API_KEY drives it on a key instead of the account
    login: bin/kin-stranger scrubs that variable only for a local endpoint.
    """

    run_id = f"rc{version.replace('.', '')}-{sha[:7]}"
    download = f"/tmp/kin-rc-{sha[:12]}"
    lines = [
        f"gh run download {rc_run if rc_run is not None else '<rc-build run id>'} --repo {EXPECTED_REPOSITORY} --dir {download}",
        f"bin/kin-stranger prepare --run {run_id} --arms green,brown,vcs",
        f"bin/kin-stranger run --run {run_id} --archive {download}/kin-linux-aarch64/kin-linux-aarch64.tar.gz --candidate-sha {sha}",
    ]
    return "\n".join(lines)


def _snapshot_field(snapshot: dict[str, Any], key: str, kind: type) -> Any:
    value = snapshot.get(key)
    if not isinstance(value, kind) or (kind is int and isinstance(value, bool)):
        raise SelectionError(f"snapshot {key} is not a {kind.__name__}")
    return value


def judge(snapshot: dict[str, Any], grade: Grader) -> Decision:
    """Decide what the cut does next from one snapshot and a grader.

    The grader is called lazily and only for the shas the rule reaches, newest
    first, so a range with a green newest sha costs one grading.
    """

    if not isinstance(snapshot, dict):
        raise SelectionError("snapshot must be an object")
    version = _snapshot_field(snapshot, "version", str)
    if VERSION.fullmatch(version) is None:
        raise SelectionError(f"snapshot version {version!r} is not semver-shaped")
    shas = _snapshot_field(snapshot, "range", list)
    if not shas or any(_sha(sha) is None for sha in shas):
        raise SelectionError("snapshot range must be a non-empty list of 40-character shas")
    if len(set(shas)) != len(shas):
        raise SelectionError("snapshot range repeats a sha")
    tag_exists = _snapshot_field(snapshot, "tag_exists", bool)
    evidence = _snapshot_field(snapshot, "evidence", dict)
    candidate = snapshot.get("candidate")
    if candidate is not None and _sha(candidate) is None:
        raise SelectionError(f"snapshot candidate {candidate!r} is not a 40-character sha")
    rc_builds = _snapshot_field(snapshot, "rc_builds", list)
    branch = candidate_branch(version)
    tip = shas[0]

    if tag_exists:
        return Decision(
            STAND_DOWN,
            f"v{version} already exists; the cut is done and the train owns the next version",
            version,
            branch,
            details={"tip": tip},
        )

    def records(sha: str) -> set[str]:
        value = evidence.get(sha, [])
        if not isinstance(value, list):
            raise SelectionError(f"evidence for {sha} is not a list")
        return set(value)

    proven = [sha for sha in shas if {PREFLIGHT_RECORD, STRANGER_RECORD} <= records(sha)]
    if proven:
        return Decision(
            STAND_DOWN,
            f"{proven[0]} carries both proof records and awaits the mint",
            version,
            branch,
            candidate=proven[0],
            details={"proven": proven},
        )

    dead: dict[str, list[str]] = {}
    notes: list[str] = []
    if candidate is not None:
        if candidate not in shas:
            return Decision(
                REFUSE,
                f"{branch} points at {candidate}, which is not a reviewed {BASE_BRANCH} commit "
                f"carrying {version}; delete or move the branch by hand",
                version,
                branch,
                candidate=candidate,
            )
        if PREFLIGHT_RECORD in records(candidate):
            return Decision(
                STAND_DOWN,
                f"preflight is recorded for {candidate}; the stranger record is the missing half",
                version,
                branch,
                candidate=candidate,
                details={"stranger_command": stranger_command(version, candidate, _newest_usable_run(rc_builds, candidate))},
            )
        grade_of = grade(candidate)
        if grade_of.get("verdict") == PENDING:
            return Decision(
                STAND_DOWN,
                f"candidate {candidate} is being graded again: {'; '.join(grade_of.get('pending', []))}",
                version,
                branch,
                candidate=candidate,
            )
        if grade_of.get("verdict") == DEAD:
            dead[candidate] = list(grade_of.get("dead", []))
            notes.append(f"current candidate {candidate} died: {'; '.join(dead[candidate])}")
        else:
            builds = [build for build in rc_builds if build.get("head_sha") == candidate]
            active = [build for build in builds if build.get("status") != "completed"]
            if active:
                return Decision(
                    STAND_DOWN,
                    f"rc-build {active[0]['id']} is {active[0].get('status')} for {candidate}",
                    version,
                    branch,
                    candidate=candidate,
                    rc_run=active[0]["id"],
                )
            usable = [build for build in builds if _usable(build)]
            if usable:
                return Decision(
                    PROOF,
                    f"rc-build {usable[0]['id']} succeeded for {candidate} with the preflight leg records",
                    version,
                    branch,
                    candidate=candidate,
                    rc_run=usable[0]["id"],
                    details={"stranger_command": stranger_command(version, candidate, usable[0]["id"])},
                )
            spent = [f"{build['id']} ({build.get('conclusion') or 'no preflight legs'})" for build in builds]
            if len(spent) >= RC_BUILD_ATTEMPT_LIMIT:
                dead[candidate] = [f"rc-build attempts exhausted: {', '.join(spent)}"]
                notes.append(f"current candidate {candidate} died: {dead[candidate][0]}")
            else:
                return Decision(
                    ARM,
                    f"{candidate} is green with no usable rc-build yet"
                    + (f" (prior attempts: {', '.join(spent)})" if spent else ""),
                    version,
                    branch,
                    candidate=candidate,
                    move=MOVE_NONE,
                    details={"attempts": spent},
                )

    pending: dict[str, list[str]] = {}
    disqualified: dict[str, list[str]] = {}
    for sha in shas:
        if sha in dead:
            disqualified[sha] = dead[sha]
            continue
        grade_of = grade(sha)
        verdict = grade_of.get("verdict")
        if verdict == GREEN:
            if candidate is None:
                move = MOVE_CREATE
            elif candidate == sha:
                move = MOVE_NONE
            elif shas.index(sha) < shas.index(candidate):
                move = MOVE_FAST_FORWARD
            else:
                move = MOVE_RESET
            return Decision(
                ARM,
                f"{sha} is the newest reviewed {BASE_BRANCH} commit carrying {version} whose push "
                "runs concluded success with every required context present exactly once",
                version,
                branch,
                candidate=sha,
                move=move,
                details={
                    "notes": notes,
                    "skipped_pending": pending,
                    "disqualified": disqualified,
                    "previous_candidate": candidate,
                },
            )
        if verdict == PENDING:
            pending[sha] = list(grade_of.get("pending", []))
            continue
        if verdict != DEAD:
            raise SelectionError(f"grader answered {verdict!r} for {sha}")
        disqualified[sha] = list(grade_of.get("dead", []))

    if pending:
        return Decision(
            STAND_DOWN,
            f"no complete green sha carries {version} yet; {len(pending)} still being graded",
            version,
            branch,
            details={"notes": notes, "pending": pending, "disqualified": disqualified},
        )
    newest = shas[0]
    return Decision(
        REFUSE,
        f"no reviewed {BASE_BRANCH} commit carrying {version} qualifies; newest {newest}: "
        + "; ".join(disqualified.get(newest, ["not graded"])),
        version,
        branch,
        details={"notes": notes, "disqualified": disqualified},
    )


def _usable(build: dict[str, Any]) -> bool:
    if build.get("status") != "completed" or build.get("conclusion") != "success":
        return False
    names = set(build.get("artifacts") or [])
    return all(f"{PREFLIGHT_ARTIFACT_PREFIX}{artifact}" in names for artifact in PREFLIGHT_ARTIFACTS)


def _newest_usable_run(rc_builds: list[dict[str, Any]], sha: str) -> int | None:
    for build in rc_builds:
        if build.get("head_sha") == sha and _usable(build):
            return build["id"]
    return None


# ---------------------------------------------------------------------------
# Live gather.
# ---------------------------------------------------------------------------


def gather(repository: str, workspace: Path, fetch: Fetch | None = None) -> dict[str, Any]:
    read = gh_json if fetch is None else fetch
    tip = run_git(workspace, "rev-parse", f"refs/remotes/origin/{BASE_BRANCH}")
    if _sha(tip) is None:
        raise SelectionError(f"origin/{BASE_BRANCH} did not resolve to an exact sha")
    version = workspace_version(run_git(workspace, "show", f"{tip}:Cargo.toml"))
    shas = version_range(workspace, tip, version)
    branch = candidate_branch(version)
    return {
        "repository": repository,
        "version": version,
        "range": shas,
        "tag_exists": read_tag_exists(read, repository, version),
        "evidence": read_evidence(read, repository),
        "candidate": read_branch(read, repository, branch),
        "rc_builds": read_rc_builds(read, repository, branch),
    }


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)

    trigger = commands.add_parser("validate-trigger", help="admit the trigger from GitHub-owned context")
    trigger.add_argument("--event-file", required=True)
    trigger.add_argument("--event-name", required=True)
    trigger.add_argument("--event-action", default="")
    trigger.add_argument("--actor", required=True)
    trigger.add_argument("--repository", required=True)
    trigger.add_argument("--default-branch", required=True)
    trigger.add_argument("--ref", required=True)
    trigger.add_argument("--workflow-sha", required=True)

    select = commands.add_parser("select", help="decide what the cut does next")
    select.add_argument("--repository", default=EXPECTED_REPOSITORY)
    select.add_argument("--workspace", help="the protected-main checkout the range is read from")
    select.add_argument(
        "--snapshot",
        help="judge this snapshot document instead of reading GitHub; it carries the grades",
    )
    return parser.parse_args(argv)


def _emit(decision: Decision) -> int:
    document = decision.document()
    print(json.dumps(document, sort_keys=True))
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as handle:
            for key in ("decision", "version", "branch", "candidate", "rc_run", "move"):
                value = document.get(key)
                handle.write(f"{key}={'' if value is None else value}\n")
            handle.write(f"reason={decision.reason.replace(chr(10), ' ')}\n")
    if decision.decision == REFUSE:
        print(f"::error title=Release cut refused::{decision.reason}", file=sys.stderr)
        return 1
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    try:
        if args.command == "validate-trigger":
            with open(args.event_file, encoding="utf-8") as handle:
                event = json.load(handle)
            verdict = validate_trigger(
                event_name=args.event_name,
                event_action=args.event_action,
                actor=args.actor,
                repository=args.repository,
                default_branch=args.default_branch,
                ref=args.ref,
                workflow_sha=args.workflow_sha,
                event=event,
            )
            print(json.dumps(verdict, sort_keys=True))
            return 0
        if args.snapshot:
            with open(args.snapshot, encoding="utf-8") as handle:
                document = json.load(handle)
            grades = document.get("grades") if isinstance(document, dict) else None
            if not isinstance(grades, dict):
                raise SelectionError("a snapshot document must carry its grades")

            def grade(sha: str) -> dict[str, Any]:
                pages = grades.get(sha)
                if not isinstance(pages, dict):
                    raise SelectionError(f"snapshot carries no grade for {sha}")
                return grade_sha(sha, pages.get("check_runs"), pages.get("workflow_runs"))

            return _emit(judge(document, grade))
        if not args.workspace:
            raise SelectionError("select needs --workspace (or --snapshot)")
        if args.repository.count("/") != 1:
            raise SelectionError("repository must be owner/name")
        snapshot = gather(args.repository, Path(args.workspace))
        return _emit(judge(snapshot, lambda sha: grade_live(gh_json, args.repository, sha)))
    except SelectionError as exc:
        print(f"::error title=Release cut could not decide::{exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
