#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

"""Land the Kin registry dependency wave once its full check set is green.

The receiver opens and updates the wave pull request on
`automation/kin-registry-dependency-wave` and the attester binds its exact head
to a release-App attestation. Nothing landed it: `bin/kin-lane merge land`
refuses every automation/ head by design, GitHub auto-merge merges on the six
ruleset contexts alone while the fleet's rule is the FULL check set read by
name, and the v2 admission chain refuses any server-owned landing state on the
wave. So a captain squashed the wave by hand, or rebuilt its bytes in a lane
branch without the reserved marker.

This script is the landing. `judge` reads everything the verdict rests on and
decides `land`, `wait` or `refuse` with the reason; `land` re-judges and then
squash-merges through the release App, verifying the merge landed on protected
main. The judgment itself is a pure function over one snapshot document, so the
test feeds it fixture check-run sets and asserts the verdict without GitHub.

The landing rule, in the order it is applied:

1. A non-empty `KIN_MAIN_FROZEN` repository variable holds every landing.
2. Exactly one open pull request from the wave branch to main, opened by the
   release App, not a draft, with no auto-merge armed, whose branch tip on
   origin is still the head under judgment.
3. Its only commit is the receiver's bot commit: authored and committed by
   github-actions[bot] and carrying the reserved marker exactly once.
4. Its diff touches only the paths the receiver writes (Cargo.toml and
   Cargo.lock), as modifications, never an add, delete or rename.
5. Every check-run on the head has concluded and none failed, read over the
   full set with `per_page=100` and the listed length asserted against
   `total_count`, deduplicated per check name keeping the newest run (the
   attester's close-and-reopen retrigger leaves a cancelled first suite beside
   the green one), with skipped and neutral counted as green, and the six
   contexts the main ruleset requires all present.
6. GitHub reports the pull mergeable (a conflict refuses; an answer still being
   computed waits).
7. The release-App attestation for this exact head verifies.

The squash message is the pull title with its number and the pull body. It never
carries the marker line: the marker is the authorization to land, reserved for
receiver heads, and a marker on main without its pull is what the CI gate
refuses. It never carries a Co-authored-by line either, which the fleet's
history audit flags.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any, Callable, Sequence


EXPECTED_REPOSITORY = "firelock-ai/kin"
BOT_LOGIN = "github-actions[bot]"
BOT_ID = 41898282
BOT_EMAIL = "41898282+github-actions[bot]@users.noreply.github.com"
LOWER_SHA = re.compile(r"^[0-9a-f]{40}$")
GREEN_CONCLUSIONS = frozenset({"success", "skipped", "neutral"})
# Ruleset 19746451 "Require status checks on main", read on 2026-09-02 through
# repos/firelock-ai/kin/rules/branches/main. These have to be PRESENT on the
# head before a landing so an empty or half-arrived check set never reads as
# green. release-tag.yml's RULESET_REQUIRED_CHECKS mirror is a superset of this
# list by contract, and scripts/test-kin-registry-wave-landing.py holds the two
# together.
RULESET_REQUIRED_CONTEXTS = (
    "DCO Sign-off",
    "PR text hygiene",
    "cargo-deny",
    "gitleaks (full history)",
    "Fast gate lint and policy",
    "Fast gate build and tests",
)
# Pull states GitHub reports in `mergeable_state`. `dirty` is a conflict and
# terminal until the receiver rebuilds the wave; the rest resolve on their own.
CONFLICT_STATES = frozenset({"dirty"})
SETTLING_STATES = frozenset({"unknown", "blocked", "behind", "draft"})
LAND = "land"
WAIT = "wait"
REFUSE = "refuse"
ATTESTATION_VERIFIED = "verified"
ATTESTATION_PENDING = "pending"
# A cancelled check is what the receiver's re-push and the attester's reopen
# retrigger leave behind on a superseded suite; it is news about the clock, not
# about the tree, so it waits for the rerun instead of refusing.
CANCELLED_CONCLUSIONS = frozenset({"cancelled"})
# The typed manual kick and who may send it, mirroring release-tag.yml's
# break-glass shape: a repository_dispatch always runs this workflow from the
# default branch, and the actor is pinned to the captain and the release App.
KICK_ACTION = "kin-registry-wave-land"
KICK_ACTORS = frozenset({"troyjr4103", "kin-release-bot[bot]"})
KICK_REASON_LIMIT = 200
TRIGGER_KICK = "kick"
TRIGGER_COMPLETION = "completion"
TRIGGER_SWEEP = "sweep"
WAIT_POLL_SECONDS = 30.0


class LandingError(RuntimeError):
    """The wave could not be judged or landed on a trustworthy reading."""


def _load(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise LandingError(f"cannot load trusted helper {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


SCRIPT_DIR = Path(__file__).resolve().parent
guard = _load(
    "kin_registry_wave_landing_guard",
    SCRIPT_DIR / "verify-kin-registry-wave-head.py",
)
history = _load(
    "kin_registry_wave_landing_history",
    SCRIPT_DIR / "verify-protected-main-history.py",
)
WAVE_BRANCH = guard.WAVE_BRANCH
BASE_BRANCH = guard.EXPECTED_BASE
ALLOWED_PATHS = guard.ALLOWED_PATHS
COMMIT_MARKER = guard.COMMIT_MARKER
APP_LOGIN = guard.ATTESTATION_CREATOR
APP_ID = guard.ATTESTATION_CREATOR_ID


@dataclass(frozen=True)
class Verdict:
    decision: str
    reason: str
    pull: int | None = None
    head: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    # A transient wait resolves by itself (checks running, an attestation on
    # its way, a rerun after a cancel, GitHub still computing mergeability);
    # a judge given a wait budget re-reads until it does. A hold or an empty
    # branch is not transient, and returns at once.
    transient: bool = False

    def document(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "reason": self.reason,
            "pull": self.pull,
            "head": self.head,
            "details": self.details,
            "transient": self.transient,
        }


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
    """Validate GitHub-owned trigger context before anything reads the wave.

    Three shapes are admitted: the wave branch's own CI completion, the typed
    manual kick from an allowlisted actor, and the scheduled sweep. Everything
    is read from the trigger context GitHub owns, never from the payload a
    sender controls, and every shape has to come from protected main.
    """

    if repository != EXPECTED_REPOSITORY:
        raise LandingError(f"repository must be {EXPECTED_REPOSITORY!r}, got {repository!r}")
    if default_branch != BASE_BRANCH:
        raise LandingError(f"default branch must be {BASE_BRANCH!r}, got {default_branch!r}")
    if ref != f"refs/heads/{BASE_BRANCH}":
        raise LandingError(f"workflow ref must be refs/heads/{BASE_BRANCH}, got {ref!r}")
    if _sha(workflow_sha) is None:
        raise LandingError(f"workflow sha must be 40-character lowercase hex, got {workflow_sha!r}")
    if not isinstance(event, dict):
        raise LandingError("event document must be an object")
    if event_name == "repository_dispatch":
        if event_action != KICK_ACTION:
            raise LandingError(f"event action must be {KICK_ACTION!r}, got {event_action!r}")
        if event.get("action") != event_action:
            raise LandingError("event document action differs from the trigger context")
        if actor not in KICK_ACTORS:
            raise LandingError(f"actor {actor!r} may not kick the wave landing")
        payload = event.get("client_payload")
        if payload is None:
            payload = {}
        if not isinstance(payload, dict) or set(payload) - {"reason"}:
            raise LandingError("kick payload may carry a reason and nothing else")
        reason = payload.get("reason", "")
        if not isinstance(reason, str) or len(reason) > KICK_REASON_LIMIT:
            raise LandingError("kick reason must be text of at most 200 characters")
        return {"trigger": TRIGGER_KICK, "actor": actor, "reason": reason}
    if event_name == "workflow_run":
        if event_action != "completed":
            raise LandingError(f"workflow_run action must be 'completed', got {event_action!r}")
        run = event.get("workflow_run")
        if not isinstance(run, dict):
            raise LandingError("workflow_run event omitted its run")
        head_repository = run.get("head_repository")
        if run.get("head_branch") != WAVE_BRANCH:
            raise LandingError(
                f"workflow_run head branch {run.get('head_branch')!r} is not the wave"
            )
        if (
            not isinstance(head_repository, dict)
            or head_repository.get("full_name") != repository
        ):
            raise LandingError("workflow_run head repository is not first-party")
        if run.get("status") != "completed":
            raise LandingError("workflow_run is not completed")
        return {
            "trigger": TRIGGER_COMPLETION,
            "workflow": run.get("name"),
            "conclusion": run.get("conclusion"),
            "head_sha": run.get("head_sha"),
        }
    if event_name == "schedule":
        if event_action != "":
            raise LandingError(f"scheduled event action must be empty, got {event_action!r}")
        return {"trigger": TRIGGER_SWEEP}
    raise LandingError(
        f"event name must be workflow_run, repository_dispatch or schedule, got {event_name!r}"
    )


def run_gh(arguments: Sequence[str], *, token: str | None = None) -> str:
    env = os.environ.copy()
    if token is not None:
        env["GH_TOKEN"] = token
    result = subprocess.run(
        ["gh", *arguments],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "no output"
        raise LandingError(f"gh {' '.join(arguments)} failed: {detail}")
    return result.stdout


def gh_json(arguments: Sequence[str], *, token: str | None = None) -> Any:
    try:
        return json.loads(run_gh(arguments, token=token))
    except json.JSONDecodeError as exc:
        raise LandingError("GitHub returned malformed JSON") from exc


def _history_fetch(endpoint: str) -> Any:
    return gh_json(["api", endpoint])


def _flatten_pages(value: Any, label: str) -> list[Any]:
    """Flatten a `gh api --paginate --slurp` answer for a list endpoint."""

    if not isinstance(value, list):
        raise LandingError(f"{label} listing is not an array")
    if value and all(isinstance(page, list) for page in value):
        return [item for page in value for item in page]
    return value


def _check_run_pages(value: Any) -> list[dict[str, Any]]:
    """Normalize the check-runs answer into its page objects."""

    if isinstance(value, dict):
        return [value]
    if isinstance(value, list) and all(isinstance(page, dict) for page in value):
        return value
    raise LandingError("check-run listing is neither a page nor a list of pages")


# ---------------------------------------------------------------------------
# The pure judgment.
# ---------------------------------------------------------------------------


def _sha(value: Any) -> str | None:
    if isinstance(value, str) and LOWER_SHA.fullmatch(value) is not None:
        return value
    return None


def _count(value: Any) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return None


def judge_check_runs(pages: Any) -> dict[str, Any]:
    """Judge the full check-run set on one head.

    Returns the deduplicated set with the names still running, the names that
    failed and the required names not present. Raises LandingError when the
    listing cannot be trusted: a page count that disagrees with `total_count`
    is the paging trap that fails toward green, and a run without a name or an
    id cannot be keyed.
    """

    if not isinstance(pages, list) or not pages:
        raise LandingError("check-run listing is empty or not a list of pages")
    totals: set[int] = set()
    runs: list[dict[str, Any]] = []
    for page in pages:
        if not isinstance(page, dict):
            raise LandingError("check-run page is not an object")
        total = _count(page.get("total_count"))
        page_runs = page.get("check_runs")
        if total is None or not isinstance(page_runs, list):
            raise LandingError("check-run page lacks total_count or check_runs")
        totals.add(total)
        runs.extend(page_runs)
    if len(totals) != 1:
        raise LandingError(f"check-run pages disagree on total_count: {sorted(totals)}")
    total = totals.pop()
    if len(runs) != total:
        raise LandingError(
            f"check-run listing is incomplete: {len(runs)} listed of {total} reported"
        )

    newest: dict[str, dict[str, Any]] = {}
    for run in runs:
        if not isinstance(run, dict):
            raise LandingError("check-run entry is not an object")
        name = run.get("name")
        run_id = _count(run.get("id"))
        if not isinstance(name, str) or not name or run_id is None:
            raise LandingError("check-run entry lacks a name or an id")
        started = run.get("started_at") or run.get("completed_at") or ""
        if not isinstance(started, str):
            raise LandingError(f"check-run {name!r} has a malformed timestamp")
        key = (started, run_id)
        current = newest.get(name)
        if current is None or key > current["_key"]:
            newest[name] = {**run, "_key": key}

    pending: list[str] = []
    failed: list[str] = []
    cancelled: list[str] = []
    for name in sorted(newest):
        run = newest[name]
        conclusion = run.get("conclusion")
        if conclusion is None or conclusion == "":
            pending.append(name)
        elif conclusion in CANCELLED_CONCLUSIONS:
            cancelled.append(name)
        elif conclusion not in GREEN_CONCLUSIONS:
            failed.append(f"{name}={conclusion}")
    missing = [name for name in RULESET_REQUIRED_CONTEXTS if name not in newest]
    return {
        "total": total,
        "distinct": len(newest),
        "pending": pending,
        "cancelled": cancelled,
        "failed": failed,
        "missing_required": missing,
    }


def compose_squash_message(pull: dict[str, Any]) -> tuple[str, str]:
    """The squash title and message, refusing text main's history must not carry."""

    number = _count(pull.get("number"))
    title = pull.get("title")
    body = pull.get("body")
    if number is None or not isinstance(title, str) or not title.strip():
        raise LandingError("pull has no usable number or title for the squash")
    if body is None:
        body = ""
    if not isinstance(body, str):
        raise LandingError("pull body is not text")
    lines = [line.rstrip() for line in body.strip().splitlines()]
    if any(line.strip() == COMMIT_MARKER for line in lines):
        raise LandingError(
            "pull body carries the reserved dependency-wave marker; main's "
            "history must not"
        )
    if any(re.match(r"(?i)^\s*co-authored-by\s*:", line) for line in lines):
        raise LandingError("pull body carries a Co-authored-by line")
    if any(line.strip() == COMMIT_MARKER for line in title.splitlines()):
        raise LandingError("pull title carries the reserved dependency-wave marker")
    return f"{title.strip()} (#{number})", "\n".join(lines).strip()


def _pull_identity(pull: Any, expected_number: int) -> str | None:
    """The reason the pull is not the exact open first-party wave, or None."""

    if not isinstance(pull, dict):
        return "pull response is not an object"
    head = pull.get("head")
    base = pull.get("base")
    user = pull.get("user")
    if not isinstance(head, dict) or not isinstance(base, dict):
        return "pull response has no head or base"
    head_repo = head.get("repo")
    if pull.get("number") != expected_number:
        return f"pull number moved from {expected_number} to {pull.get('number')!r}"
    if pull.get("state") != "open":
        return f"pull is {pull.get('state')!r}, not open"
    if pull.get("draft") is True:
        return "pull is a draft"
    if pull.get("merged_at") is not None:
        return "pull already carries a merge"
    if "auto_merge" not in pull:
        return "pull response omitted server-side auto-merge state"
    if pull.get("auto_merge") is not None:
        return "pull has auto-merge armed, which the wave never carries"
    if head.get("ref") != WAVE_BRANCH:
        return f"pull head ref {head.get('ref')!r} is not {WAVE_BRANCH}"
    if not isinstance(head_repo, dict) or head_repo.get("full_name") != EXPECTED_REPOSITORY:
        return "pull head is not first-party"
    if base.get("ref") != BASE_BRANCH:
        return f"pull base ref {base.get('ref')!r} is not {BASE_BRANCH}"
    if _sha(head.get("sha")) is None or _sha(base.get("sha")) is None:
        return "pull head or base sha is malformed"
    if (
        not isinstance(user, dict)
        or user.get("login") != APP_LOGIN
        or user.get("id") != APP_ID
        or user.get("type") != "Bot"
    ):
        return "pull was not opened by the release App"
    return None


def _commit_identity(commit: Any, head: str) -> str | None:
    """The reason a pull commit is not the receiver's bot commit, or None."""

    if not isinstance(commit, dict):
        return "pull commit entry is not an object"
    if commit.get("sha") != head:
        return f"pull commit {commit.get('sha')!r} is not the head {head}"
    for role in ("author", "committer"):
        actor = commit.get(role)
        if (
            not isinstance(actor, dict)
            or actor.get("login") != BOT_LOGIN
            or actor.get("id") != BOT_ID
        ):
            return f"pull commit {role} is not {BOT_LOGIN}"
    inner = commit.get("commit")
    if not isinstance(inner, dict):
        return "pull commit lacks its git commit"
    for role in ("author", "committer"):
        actor = inner.get(role)
        if not isinstance(actor, dict) or actor.get("email") != BOT_EMAIL:
            return f"pull commit git {role} email is not the bot's"
    message = inner.get("message")
    if not isinstance(message, str):
        return "pull commit has no message"
    marker_lines = [line for line in message.splitlines() if line.strip() == COMMIT_MARKER]
    if len(marker_lines) != 1:
        return f"pull commit carries the reserved marker {len(marker_lines)} times, not once"
    return None


def judge(snapshot: dict[str, Any]) -> Verdict:
    """Decide land, wait or refuse from one snapshot. Pure."""

    freeze = snapshot.get("freeze")
    if isinstance(freeze, str) and freeze.strip():
        return Verdict(WAIT, f"landings are frozen by KIN_MAIN_FROZEN: {freeze.strip()}")
    if freeze not in (None, "") and not isinstance(freeze, str):
        return Verdict(REFUSE, "freeze value is not text")

    open_pulls = snapshot.get("open_pulls")
    if not isinstance(open_pulls, list):
        return Verdict(REFUSE, "open wave listing is not an array")
    if not open_pulls:
        return Verdict(WAIT, f"no open pull request from {WAVE_BRANCH}")
    if len(open_pulls) != 1:
        return Verdict(REFUSE, f"{len(open_pulls)} open pull requests from {WAVE_BRANCH}")
    listed = open_pulls[0]
    number = _count(listed.get("number")) if isinstance(listed, dict) else None
    if number is None or number < 1:
        return Verdict(REFUSE, "open wave listing has no valid pull number")

    pull = snapshot.get("pull")
    problem = _pull_identity(pull, number)
    if problem is not None:
        return Verdict(REFUSE, problem, pull=number)
    head = str(pull["head"]["sha"])
    base = str(pull["base"]["sha"])

    branch_tip = snapshot.get("branch_tip")
    if _sha(branch_tip) is None:
        return Verdict(
            WAIT,
            f"origin carries no readable {WAVE_BRANCH} tip yet",
            number,
            head,
            transient=True,
        )
    if branch_tip != head:
        # The receiver re-pushed: the pull request's head is about to move to
        # the branch tip, and every check on the old head is superseded. The
        # next pass judges the new head.
        return Verdict(
            WAIT,
            f"the wave moved: origin/{WAVE_BRANCH} is at {branch_tip}, not the "
            f"pull head {head}; the next pass judges the new head",
            number,
            head,
            transient=True,
        )

    commits = snapshot.get("commits")
    if not isinstance(commits, list):
        return Verdict(REFUSE, "pull commit listing is not an array", number, head)
    if pull.get("commits") != 1 or len(commits) != 1:
        return Verdict(
            REFUSE,
            f"pull carries {pull.get('commits')!r} commits ({len(commits)} listed); "
            "the receiver writes exactly one",
            number,
            head,
        )
    problem = _commit_identity(commits[0], head)
    if problem is not None:
        return Verdict(REFUSE, problem, number, head)

    files = snapshot.get("files")
    if not isinstance(files, list):
        return Verdict(REFUSE, "pull file listing is not an array", number, head)
    if pull.get("changed_files") != len(files) or not files:
        return Verdict(
            REFUSE,
            f"pull reports {pull.get('changed_files')!r} changed files, {len(files)} listed",
            number,
            head,
        )
    for entry in files:
        if not isinstance(entry, dict):
            return Verdict(REFUSE, "pull file entry is not an object", number, head)
        filename = entry.get("filename")
        if filename not in ALLOWED_PATHS:
            return Verdict(
                REFUSE,
                f"pull touches {filename!r}, outside the receiver's write set "
                f"{sorted(ALLOWED_PATHS)}",
                number,
                head,
            )
        if entry.get("status") != "modified" or entry.get("previous_filename"):
            return Verdict(
                REFUSE,
                f"pull {entry.get('status')!r} {filename!r}; the receiver only modifies",
                number,
                head,
            )

    try:
        checks = judge_check_runs(snapshot.get("check_run_pages"))
    except LandingError as exc:
        return Verdict(REFUSE, f"check-runs unreadable: {exc}", number, head)
    if checks["failed"]:
        return Verdict(
            REFUSE,
            "checks failed: " + ", ".join(checks["failed"]),
            number,
            head,
            checks,
        )
    if checks["pending"]:
        return Verdict(
            WAIT,
            "checks still running: " + ", ".join(checks["pending"]),
            number,
            head,
            checks,
            transient=True,
        )
    if checks["cancelled"]:
        return Verdict(
            WAIT,
            "checks cancelled, awaiting the rerun a re-push or reopen triggers: "
            + ", ".join(checks["cancelled"]),
            number,
            head,
            checks,
            transient=True,
        )
    if checks["missing_required"]:
        return Verdict(
            WAIT,
            "required contexts not yet reported: "
            + ", ".join(checks["missing_required"]),
            number,
            head,
            checks,
            transient=True,
        )

    state = pull.get("mergeable_state")
    if state in CONFLICT_STATES or pull.get("mergeable") is False:
        return Verdict(
            REFUSE,
            f"GitHub reports the pull {state!r}; the next receiver run rebuilds the wave",
            number,
            head,
            checks,
        )
    if state in SETTLING_STATES or state is None or pull.get("mergeable") is None:
        return Verdict(
            WAIT,
            f"GitHub reports the pull mergeable_state {state!r}",
            number,
            head,
            checks,
            transient=True,
        )

    attestation = snapshot.get("attestation")
    if attestation == ATTESTATION_PENDING:
        return Verdict(
            WAIT,
            "release-App attestation for this head has not arrived",
            number,
            head,
            checks,
            transient=True,
        )
    if attestation != ATTESTATION_VERIFIED:
        return Verdict(REFUSE, f"attestation: {attestation}", number, head, checks)

    try:
        compose_squash_message(pull)
    except LandingError as exc:
        return Verdict(REFUSE, str(exc), number, head, checks)

    return Verdict(
        LAND,
        f"every check on {head} concluded green ({checks['distinct']} distinct of "
        f"{checks['total']} check-runs) and the attestation verifies",
        number,
        head,
        {**checks, "base": base},
    )


# ---------------------------------------------------------------------------
# Gathering the snapshot from GitHub.
# ---------------------------------------------------------------------------


def _open_wave_pulls(repository: str) -> Any:
    owner = repository.split("/", 1)[0]
    return gh_json(
        [
            "api",
            "--method",
            "GET",
            f"repos/{repository}/pulls",
            "-f",
            "state=open",
            "-f",
            f"head={owner}:{WAVE_BRANCH}",
            "-f",
            f"base={BASE_BRANCH}",
            "-f",
            "per_page=100",
        ]
    )


def _branch_tip(repository: str) -> str | None:
    try:
        document = gh_json(["api", f"repos/{repository}/git/ref/heads/{WAVE_BRANCH}"])
    except LandingError:
        return None
    ref_object = document.get("object") if isinstance(document, dict) else None
    return _sha(ref_object.get("sha")) if isinstance(ref_object, dict) else None


def _attestation_state(
    workspace: Path,
    repository: str,
    number: int,
    head: str,
    base: str,
) -> str:
    try:
        guard.ensure_pull_head(workspace, number, head)
        guard.verify_attestation(
            workspace,
            repository,
            number,
            head,
            wait_seconds=0,
            expected_base=base,
        )
    except guard.PendingAttestation:
        return ATTESTATION_PENDING
    except guard.AdmissionError as exc:
        return f"refused: {exc}"
    return ATTESTATION_VERIFIED


def gather(repository: str, workspace: Path, freeze: str) -> dict[str, Any]:
    """Read everything `judge` decides on, in the order it decides."""

    snapshot: dict[str, Any] = {
        "freeze": freeze,
        "open_pulls": _open_wave_pulls(repository),
        "pull": None,
        "branch_tip": None,
        "commits": [],
        "files": [],
        "check_run_pages": [],
        "attestation": ATTESTATION_PENDING,
    }
    open_pulls = snapshot["open_pulls"]
    if not isinstance(open_pulls, list) or len(open_pulls) != 1:
        return snapshot
    listed = open_pulls[0]
    number = _count(listed.get("number")) if isinstance(listed, dict) else None
    if number is None or number < 1:
        return snapshot
    pull = gh_json(["api", f"repos/{repository}/pulls/{number}"])
    snapshot["pull"] = pull
    if _pull_identity(pull, number) is not None:
        return snapshot
    head = str(pull["head"]["sha"])
    base = str(pull["base"]["sha"])
    snapshot["branch_tip"] = _branch_tip(repository)
    snapshot["commits"] = _flatten_pages(
        gh_json(
            [
                "api",
                "--paginate",
                "--slurp",
                f"repos/{repository}/pulls/{number}/commits?per_page=100",
            ]
        ),
        "pull commit",
    )
    snapshot["files"] = _flatten_pages(
        gh_json(
            [
                "api",
                "--paginate",
                "--slurp",
                f"repos/{repository}/pulls/{number}/files?per_page=100",
            ]
        ),
        "pull file",
    )
    snapshot["check_run_pages"] = _check_run_pages(
        gh_json(
            [
                "api",
                "--paginate",
                "--slurp",
                f"repos/{repository}/commits/{head}/check-runs?per_page=100",
            ]
        )
    )
    snapshot["attestation"] = _attestation_state(workspace, repository, number, head, base)
    return snapshot


def judge_with_wait(
    repository: str,
    workspace: Path,
    freeze: str,
    *,
    wait_seconds: int,
    gather_snapshot: Callable[[str, Path, str], dict[str, Any]] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> tuple[Verdict, dict[str, Any]]:
    """Judge, and keep re-reading while the verdict is a transient wait.

    A cron GitHub does not fire and a completion event that arrives before the
    last check does are both real, so a judgment triggered once has to be able
    to outlast the checks it is waiting on. The budget is bounded and every
    pass re-reads the whole snapshot, so a wave the receiver re-pushes during
    the wait is judged on its new head.
    """

    if wait_seconds < 0:
        raise LandingError("wait budget cannot be negative")
    # Resolved at call time, not bound at definition time, so a replaced
    # module-level gather (a test's, or a future fixture reader's) is honoured.
    if gather_snapshot is None:
        gather_snapshot = gather
    deadline = clock() + wait_seconds
    passes = 0
    while True:
        snapshot = gather_snapshot(repository, workspace, freeze)
        verdict = judge(snapshot)
        passes += 1
        remaining = deadline - clock()
        if verdict.decision != WAIT or not verdict.transient or remaining <= 0:
            return Verdict(
                verdict.decision,
                verdict.reason,
                verdict.pull,
                verdict.head,
                {**verdict.details, "passes": passes},
                verdict.transient,
            ), snapshot
        print(f"::notice::wave landing waits ({int(remaining)}s left): {verdict.reason}", file=sys.stderr)
        sleep(min(WAIT_POLL_SECONDS, remaining))


def squash(
    repository: str,
    pull: dict[str, Any],
    head: str,
    *,
    merge_token: str,
) -> dict[str, Any]:
    """Squash the judged head onto main through the release App and prove it."""

    number = int(pull["number"])
    title, message = compose_squash_message(pull)
    response = gh_json(
        [
            "api",
            "--method",
            "PUT",
            f"repos/{repository}/pulls/{number}/merge",
            "-f",
            "merge_method=squash",
            "-f",
            f"sha={head}",
            "-f",
            f"commit_title={title}",
            "-f",
            f"commit_message={message}",
        ],
        token=merge_token,
    )
    if not isinstance(response, dict) or response.get("merged") is not True:
        raise LandingError(f"merge call did not report a merge: {response!r}")
    merged_sha = _sha(response.get("sha"))
    if merged_sha is None:
        raise LandingError("merge call returned no commit sha")
    after = gh_json(["api", f"repos/{repository}/pulls/{number}"], token=merge_token)
    if (
        not isinstance(after, dict)
        or after.get("merged") is not True
        or after.get("merge_commit_sha") != merged_sha
    ):
        raise LandingError("pull read back after the merge does not carry the squash")
    try:
        on_main = history.require_protected_history(
            repository, merged_sha, branch=BASE_BRANCH, fetch=_history_fetch
        )
    except history.HistoryError as exc:
        raise LandingError(f"squash {merged_sha} is not on protected main: {exc}") from exc
    return {
        "merged_sha": merged_sha,
        "title": title,
        "main_tip": on_main["tip"],
    }


# ---------------------------------------------------------------------------
# Command line.
# ---------------------------------------------------------------------------


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    subparsers = parser.add_subparsers(dest="command", required=True)
    fixture = subparsers.add_parser("judge-fixture", help="judge one snapshot document")
    fixture.add_argument("--fixture", type=Path, required=True)
    trigger = subparsers.add_parser("validate-trigger", help="validate the run's trigger")
    trigger.add_argument("--event-file", type=Path, required=True)
    trigger.add_argument("--event-name", required=True)
    trigger.add_argument("--event-action", default="")
    trigger.add_argument("--actor", required=True)
    trigger.add_argument("--repository", required=True)
    trigger.add_argument("--default-branch", required=True)
    trigger.add_argument("--ref", required=True)
    trigger.add_argument("--workflow-sha", required=True)
    for name in ("judge", "land"):
        command = subparsers.add_parser(name)
        command.add_argument("--repository", required=True)
        command.add_argument("--workspace", type=Path, required=True)
        command.add_argument("--freeze", default="")
        command.add_argument(
            "--wait-seconds",
            type=int,
            default=0,
            help="keep re-reading while the verdict is a transient wait, up to this budget",
        )
        if name == "land":
            command.add_argument("--pull", type=int, required=True)
            command.add_argument("--head", required=True)
            command.add_argument(
                "--merge-token-env",
                required=True,
                help="environment variable holding the release-App token for the merge",
            )
    return parser.parse_args(argv)


def _emit(verdict: Verdict) -> int:
    document = verdict.document()
    print(json.dumps(document, sort_keys=True))
    if verdict.decision == REFUSE:
        print(f"::error title=Kin registry wave refused::{verdict.reason}", file=sys.stderr)
        return 1
    if verdict.decision == WAIT:
        print(f"::notice::wave landing waits: {verdict.reason}", file=sys.stderr)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    try:
        if args.command == "judge-fixture":
            with args.fixture.open(encoding="utf-8") as stream:
                snapshot = json.load(stream)
            if not isinstance(snapshot, dict):
                raise LandingError("fixture is not an object")
            return _emit(judge(snapshot))
        if args.command == "validate-trigger":
            with args.event_file.open(encoding="utf-8") as stream:
                event = json.load(stream)
            trigger = validate_trigger(
                event_name=args.event_name,
                event_action=args.event_action,
                actor=args.actor,
                repository=args.repository,
                default_branch=args.default_branch,
                ref=args.ref,
                workflow_sha=args.workflow_sha,
                event=event,
            )
            print(json.dumps(trigger, sort_keys=True))
            return 0
        if args.repository != EXPECTED_REPOSITORY:
            raise LandingError(f"repository must be {EXPECTED_REPOSITORY}")
        verdict, snapshot = judge_with_wait(
            args.repository,
            args.workspace,
            args.freeze,
            wait_seconds=args.wait_seconds,
        )
        if args.command == "judge" or verdict.decision != LAND:
            return _emit(verdict)
        if verdict.pull != args.pull or verdict.head != args.head:
            return _emit(
                Verdict(
                    WAIT,
                    f"the wave moved since it was judged: pull {verdict.pull} head "
                    f"{verdict.head} is not the judged pull {args.pull} head {args.head}",
                    verdict.pull,
                    verdict.head,
                )
            )
        merge_token = os.environ.get(args.merge_token_env, "")
        if not merge_token:
            raise LandingError(f"{args.merge_token_env} is unset; no token to merge with")
        landed = squash(args.repository, snapshot["pull"], verdict.head, merge_token=merge_token)
        return _emit(
            Verdict(
                LAND,
                f"landed pull {verdict.pull} head {verdict.head} as {landed['merged_sha']}",
                verdict.pull,
                verdict.head,
                {**verdict.details, **landed},
            )
        )
    except (LandingError, OSError, json.JSONDecodeError) as exc:
        if args.command == "validate-trigger":
            print(f"::error title=Kin registry wave trigger refused::{exc}", file=sys.stderr)
            return 1
        return _emit(Verdict(REFUSE, str(exc)))


if __name__ == "__main__":
    raise SystemExit(main())
