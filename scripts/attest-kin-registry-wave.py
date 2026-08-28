#!/usr/bin/env python3
"""Validate a completed receiver run, then persist its exact App attestation."""

from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from types import ModuleType
from typing import Any, Sequence


EXPECTED_REPOSITORY = "firelock-ai/kin"
CI_WORKFLOW_NAME = "CI"
CI_WORKFLOW_PATH = ".github/workflows/ci.yml"
CI_REQUIRED_JOB = "Fast gate lint and policy"
RECHECK_STATUSES = frozenset(
    {"queued", "in_progress", "completed", "waiting", "pending", "requested"}
)


class AttesterError(RuntimeError):
    """The completed receiver or its live pull request is not attestable."""


def _load(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AttesterError(f"cannot load trusted helper {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


SCRIPT_DIR = Path(__file__).resolve().parent
artifact = _load(
    "kin_registry_wave_attester_artifact",
    SCRIPT_DIR / "kin-registry-wave-artifact.py",
)
guard = _load(
    "kin_registry_wave_attester_guard",
    SCRIPT_DIR / "verify-kin-registry-wave-head.py",
)
landing = _load(
    "kin_registry_wave_attester_landing",
    SCRIPT_DIR / "ensure-kin-registry-wave-no-automerge.py",
)


def run_gh(arguments: Sequence[str]) -> str:
    result = subprocess.run(
        ["gh", *arguments],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "no output"
        raise AttesterError(f"gh {' '.join(arguments)} failed: {detail}")
    return result.stdout


def gh_json(arguments: Sequence[str]) -> Any:
    try:
        return json.loads(run_gh(arguments))
    except json.JSONDecodeError as exc:
        raise AttesterError("GitHub returned malformed JSON") from exc


def _event(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AttesterError(f"cannot read workflow_run event: {exc}") from exc
    if not isinstance(value, dict):
        raise AttesterError("workflow_run event is not an object")
    return value


def validate_completed_run(
    *,
    event_file: Path,
    repository: str,
) -> dict[str, Any]:
    event = _event(event_file)
    workflow_run = event.get("workflow_run")
    if event.get("action") != "completed" or not isinstance(workflow_run, dict):
        raise AttesterError("event is not a completed workflow_run")
    run_id = workflow_run.get("id")
    run_attempt = workflow_run.get("run_attempt")
    policy_sha = workflow_run.get("head_sha")
    evidence = {
        "run_id": run_id,
        "run_attempt": run_attempt,
        "workflow_path": workflow_run.get("path"),
        "policy_sha": policy_sha,
        "base": policy_sha,
    }
    live_run = gh_json(
        [
            "api",
            f"repos/{repository}/actions/runs/{run_id}/attempts/{run_attempt}",
        ]
    )
    try:
        guard.validate_workflow_run(repository, evidence, live_run)
    except guard.AdmissionError as exc:
        raise AttesterError(str(exc)) from exc
    for field in (
        "id",
        "run_attempt",
        "name",
        "path",
        "status",
        "conclusion",
        "event",
        "head_branch",
        "head_sha",
    ):
        if workflow_run.get(field) != live_run.get(field):
            raise AttesterError(
                f"workflow_run event field {field} differs from the Actions API"
            )
    return live_run


def _load_admission(
    *,
    admission_file: Path,
    repository: str,
    policy_sha: str,
    run_id: int,
    run_attempt: int,
) -> dict[str, Any]:
    if admission_file.parent.is_symlink():
        raise AttesterError("admission artifact directory is a symlink")
    entries = frozenset(item.name for item in admission_file.parent.iterdir())
    if entries != {"result.json"}:
        raise AttesterError("receiver result contains entries outside its allowlist")
    try:
        return artifact.validate_result(
            result_file=admission_file,
            repository=repository,
            workflow_path=guard.RECEIVER_WORKFLOW_PATH,
            policy_sha=policy_sha,
            run_id=run_id,
            run_attempt=run_attempt,
        )
    except artifact.ArtifactError as exc:
        raise AttesterError(str(exc)) from exc


def _load_changed_admission(
    *,
    admission_file: Path,
    repository: str,
) -> dict[str, Any]:
    try:
        raw = artifact._read_json(admission_file)
        return artifact.validate_admission(
            admission_file=admission_file,
            repository=repository,
            workflow_path=guard.RECEIVER_WORKFLOW_PATH,
            policy_sha=str(raw.get("policy_sha")),
            run_id=int(raw.get("run_id")),
            run_attempt=int(raw.get("run_attempt")),
        )
    except (artifact.ArtifactError, TypeError, ValueError) as exc:
        raise AttesterError(str(exc)) from exc


def _paginated_items(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise AttesterError(f"{label} response is not an array")
    if value and all(isinstance(page, list) for page in value):
        return [item for page in value for item in page]
    return value


def _attestation_documents(
    repository: str,
    pull_number: int,
) -> tuple[list[Any], list[Any]]:
    reviews = _paginated_items(
        gh_json(
            [
                "api",
                "--paginate",
                "--slurp",
                f"repos/{repository}/pulls/{pull_number}/reviews?per_page=100",
            ]
        ),
        "pull review",
    )
    comments = _paginated_items(
        gh_json(
            [
                "api",
                "--paginate",
                "--slurp",
                f"repos/{repository}/issues/{pull_number}/comments?per_page=100",
            ]
        ),
        "pull comment",
    )
    return reviews, comments


def _existing_attestation(
    *,
    workspace: Path,
    repository: str,
    admission: dict[str, Any],
    verify_server_run: bool,
) -> dict[str, Any] | None:
    pull_number = int(admission["pull"])
    head = str(admission["head"])
    reviews, comments = _attestation_documents(repository, pull_number)
    try:
        guard.validate_attestation(
            workspace,
            repository,
            pull_number,
            head,
            reviews,
            comments,
            expected_base=str(admission["base"]),
            verify_server_run=verify_server_run,
        )
    except guard.PendingAttestation:
        return None
    except guard.AdmissionError as exc:
        raise AttesterError(str(exc)) from exc

    current: list[tuple[dict[str, Any], dict[str, str | int]]] = []
    for comment in comments:
        if not isinstance(comment, dict):
            continue
        body = comment.get("body")
        if not isinstance(body, str) or not body.startswith(guard.ATTESTATION_MARKER):
            continue
        if not guard._has_exact_attestation_app_identity(comment):
            continue
        evidence = guard._parse_comment_body(body)
        if evidence["head"] == head:
            current.append((comment, evidence))
    if not current:
        raise AttesterError("validated dependency attestation disappeared")
    comment, evidence = max(current, key=lambda item: int(item[0]["id"]))
    candidate_fields = (
        "repository",
        "pull",
        "head",
        "tree",
        "base",
        "delta_sha256",
        "package_version",
        "workspace_version",
        "workflow_path",
        "policy_sha",
    )
    expected = {
        "repository": repository,
        "pull": pull_number,
        **{field: admission[field] for field in candidate_fields if field not in {"repository", "pull"}},
    }
    observed = {field: evidence[field] for field in candidate_fields}
    if observed != expected:
        raise AttesterError(
            "existing App attestation differs from the immutable admission candidate"
        )
    created_at = comment.get("created_at")
    if not isinstance(created_at, str):
        raise AttesterError("existing App attestation has no creation timestamp")
    _timestamp(created_at, "attestation comment creation")
    return {
        "review_id": int(evidence["review_id"]),
        "comment_id": int(comment["id"]),
        "comment_created_at": created_at,
        "run_id": int(evidence["run_id"]),
        "run_attempt": int(evidence["run_attempt"]),
    }


def _timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise AttesterError(f"{label} is not a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise AttesterError(f"{label} is malformed") from exc
    if parsed.utcoffset() is None:
        raise AttesterError(f"{label} has no timezone")
    return parsed


def validate_live_admission(
    *,
    workspace: Path,
    repository: str,
    admission: dict[str, Any],
) -> None:
    pull_number = int(admission["pull"])
    head = str(admission["head"])
    policy_sha = str(admission["policy_sha"])
    current_ref = gh_json(
        ["api", f"repos/{repository}/git/ref/heads/{guard.EXPECTED_BASE}"]
    )
    ref_object = current_ref.get("object") if isinstance(current_ref, dict) else None
    if not isinstance(ref_object, dict) or ref_object.get("sha") != policy_sha:
        raise AttesterError("protected main moved after the completed receiver")

    pull = gh_json(["api", f"repos/{repository}/pulls/{pull_number}"])
    try:
        pull_evidence = guard.validate_pull(
            pull,
            repository=repository,
            expected_head=head,
            require_open=True,
        )
    except guard.AdmissionError as exc:
        raise AttesterError(str(exc)) from exc
    if pull_evidence.base != admission["base"]:
        raise AttesterError("live pull base differs from the completed admission")

    graphql_pull = landing._graphql_pull(repository, pull_number)
    try:
        _, auto_armed, queue_armed = landing._validate_graphql_pull(
            graphql_pull,
            repository=repository,
            branch=guard.WAVE_BRANCH,
            base=guard.EXPECTED_BASE,
            expected_number=pull_number,
            expected_head=head,
        )
    except landing.LandingStateError as exc:
        raise AttesterError(str(exc)) from exc
    if auto_armed or queue_armed:
        raise AttesterError("live dependency pull still has server-owned landing state")

    try:
        guard.ensure_pull_head(workspace, pull_number, head)
        evidence = guard.validate_delta(
            workspace,
            str(admission["base"]),
            head,
            require_marker=True,
        )
    except guard.AdmissionError as exc:
        raise AttesterError(str(exc)) from exc
    observed = {
        "tree": evidence.tree,
        "delta_sha256": evidence.delta_sha256,
        "package_version": evidence.package_version,
        "workspace_version": evidence.workspace_version,
    }
    expected = {key: admission[key] for key in observed}
    if observed != expected:
        raise AttesterError("live dependency pull differs from the completed admission")


def validate_for_attestation(
    *,
    event_file: Path,
    admission_file: Path,
    workspace: Path,
    repository: str,
) -> dict[str, Any]:
    run = validate_completed_run(event_file=event_file, repository=repository)
    admission = _load_admission(
        admission_file=admission_file,
        repository=repository,
        policy_sha=str(run["head_sha"]),
        run_id=int(run["id"]),
        run_attempt=int(run["run_attempt"]),
    )
    result = dict(admission)
    result["needs_attestation"] = False
    if admission["changed"] is True:
        validate_live_admission(
            workspace=workspace,
            repository=repository,
            admission=admission,
        )
        result["needs_attestation"] = (
            _existing_attestation(
                workspace=workspace,
                repository=repository,
                admission=admission,
                verify_server_run=True,
            )
            is None
        )
    return result


def _exact_review(review: Any, *, head: str, body: str) -> int:
    if not isinstance(review, dict):
        raise AttesterError("review creation response is not an object")
    review_id = review.get("id")
    user = review.get("user")
    if (
        not isinstance(review_id, int)
        or isinstance(review_id, bool)
        or review_id < 1
        or review.get("state") != "COMMENTED"
        or review.get("commit_id") != head
        or review.get("body") != body
        or not isinstance(user, dict)
        or user.get("id") != guard.ATTESTATION_CREATOR_ID
        or user.get("login") != guard.ATTESTATION_CREATOR
        or user.get("type") != "Bot"
    ):
        raise AttesterError("release App review did not bind the exact admitted head")
    return review_id


def _exact_comment(
    comment: Any,
    *,
    repository: str,
    pull_number: int,
    body: str,
) -> int:
    if not isinstance(comment, dict):
        raise AttesterError("comment creation response is not an object")
    comment_id = comment.get("id")
    app = comment.get("performed_via_github_app")
    owner = app.get("owner") if isinstance(app, dict) else None
    user = comment.get("user")
    if (
        not isinstance(comment_id, int)
        or isinstance(comment_id, bool)
        or comment_id < 1
        or comment.get("body") != body
        or comment.get("created_at") != comment.get("updated_at")
        or comment.get("issue_url")
        != f"https://api.github.com/repos/{repository}/issues/{pull_number}"
        or comment.get("html_url")
        != (
            f"https://github.com/{repository}/pull/{pull_number}"
            f"#issuecomment-{comment_id}"
        )
        or not isinstance(app, dict)
        or app.get("id") != guard.ATTESTATION_APP_ID
        or app.get("slug") != guard.ATTESTATION_APP_SLUG
        or not isinstance(owner, dict)
        or owner.get("id") != guard.ATTESTATION_APP_OWNER_ID
        or owner.get("login") != guard.ATTESTATION_APP_OWNER
        or not isinstance(user, dict)
        or user.get("id") != guard.ATTESTATION_CREATOR_ID
        or user.get("login") != guard.ATTESTATION_CREATOR
        or user.get("type") != "Bot"
    ):
        raise AttesterError("release App identity did not persist on the attestation")
    return comment_id


def post_attestation(
    *,
    admission_file: Path,
    workspace: Path,
    repository: str,
) -> dict[str, Any]:
    admission = _load_changed_admission(
        admission_file=admission_file,
        repository=repository,
    )
    validate_live_admission(
        workspace=workspace,
        repository=repository,
        admission=admission,
    )

    existing = _existing_attestation(
        workspace=workspace,
        repository=repository,
        admission=admission,
        verify_server_run=False,
    )
    if existing is not None:
        return {"created": False, **existing}

    pull_number = int(admission["pull"])
    head = str(admission["head"])
    body_args = (
        repository,
        pull_number,
        head,
        str(admission["tree"]),
        str(admission["base"]),
        str(admission["delta_sha256"]),
        str(admission["package_version"]),
        str(admission["workspace_version"]),
        str(admission["workflow_path"]),
        str(admission["policy_sha"]),
        int(admission["run_id"]),
        int(admission["run_attempt"]),
    )
    review_body = guard._review_body(*body_args)
    review = gh_json(
        [
            "api",
            "--method",
            "POST",
            f"repos/{repository}/pulls/{pull_number}/reviews",
            "-f",
            "event=COMMENT",
            "-f",
            f"commit_id={head}",
            "-f",
            f"body={review_body}",
        ]
    )
    review_id = _exact_review(review, head=head, body=review_body)
    comment_body = guard._comment_body(
        repository,
        pull_number,
        review_id,
        head,
        str(admission["tree"]),
        str(admission["base"]),
        str(admission["delta_sha256"]),
        str(admission["package_version"]),
        str(admission["workspace_version"]),
        str(admission["workflow_path"]),
        str(admission["policy_sha"]),
        int(admission["run_id"]),
        int(admission["run_attempt"]),
    )
    comment = gh_json(
        [
            "api",
            "--method",
            "POST",
            f"repos/{repository}/issues/{pull_number}/comments",
            "-f",
            f"body={comment_body}",
        ]
    )
    comment_id = _exact_comment(
        comment,
        repository=repository,
        pull_number=pull_number,
        body=comment_body,
    )
    persisted_review = gh_json(
        ["api", f"repos/{repository}/pulls/{pull_number}/reviews/{review_id}"]
    )
    persisted_comment = gh_json(
        ["api", f"repos/{repository}/issues/comments/{comment_id}"]
    )
    _exact_review(persisted_review, head=head, body=review_body)
    _exact_comment(
        persisted_comment,
        repository=repository,
        pull_number=pull_number,
        body=comment_body,
    )
    validate_live_admission(
        workspace=workspace,
        repository=repository,
        admission=admission,
    )
    created_at = persisted_comment.get("created_at")
    if not isinstance(created_at, str):
        raise AttesterError("persisted App attestation has no creation timestamp")
    _timestamp(created_at, "persisted App attestation creation")
    return {
        "created": True,
        "review_id": review_id,
        "comment_id": comment_id,
        "comment_created_at": created_at,
        "run_id": int(admission["run_id"]),
        "run_attempt": int(admission["run_attempt"]),
    }


def _workflow_run_pages(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        pages = [value]
    elif isinstance(value, list) and all(isinstance(page, dict) for page in value):
        pages = value
    else:
        raise AttesterError("CI workflow-run response is malformed")
    runs: list[dict[str, Any]] = []
    seen: set[int] = set()
    for page in pages:
        page_runs = page.get("workflow_runs")
        total = page.get("total_count")
        if (
            not isinstance(total, int)
            or isinstance(total, bool)
            or total < 0
            or not isinstance(page_runs, list)
        ):
            raise AttesterError("CI workflow-run page is malformed")
        for run in page_runs:
            run_id = run.get("id") if isinstance(run, dict) else None
            if (
                not isinstance(run, dict)
                or not isinstance(run_id, int)
                or isinstance(run_id, bool)
                or run_id < 1
                or run_id in seen
            ):
                raise AttesterError("CI workflow-run listing has an invalid run")
            seen.add(run_id)
            runs.append(run)
    return runs


def _is_recheck_run_candidate(
    run: dict[str, Any],
    *,
    repository: str,
    admission: dict[str, Any],
) -> bool:
    if run.get("head_sha") != admission["head"]:
        return False
    pulls = run.get("pull_requests")
    bound_to_admitted_pull = isinstance(pulls, list) and any(
        isinstance(pull, dict) and pull.get("number") == admission["pull"]
        for pull in pulls
    )
    if bound_to_admitted_pull:
        return True
    if isinstance(pulls, list) and pulls and all(
        isinstance(pull, dict)
        and isinstance(pull.get("number"), int)
        and not isinstance(pull.get("number"), bool)
        for pull in pulls
    ):
        return False
    head_repository = run.get("head_repository")
    first_party_wave = (
        run.get("head_branch") == guard.WAVE_BRANCH
        and isinstance(head_repository, dict)
        and head_repository.get("full_name") == repository
    )
    return first_party_wave


def _validate_recheck_pull(
    run: dict[str, Any],
    *,
    repository: str,
    admission: dict[str, Any],
) -> None:
    pulls = run.get("pull_requests")
    if not isinstance(pulls, list) or len(pulls) != 1:
        raise AttesterError("post-attestation CI run is not bound to one pull request")
    pull = pulls[0]
    head = pull.get("head") if isinstance(pull, dict) else None
    base = pull.get("base") if isinstance(pull, dict) else None
    head_repo = head.get("repo") if isinstance(head, dict) else None
    base_repo = base.get("repo") if isinstance(base, dict) else None
    repository_url = f"https://api.github.com/repos/{repository}"
    repository_name = repository.split("/", 1)[1]
    if (
        not isinstance(pull, dict)
        or pull.get("number") != admission["pull"]
        or not isinstance(head, dict)
        or head.get("ref") != guard.WAVE_BRANCH
        or head.get("sha") != admission["head"]
        or not isinstance(head_repo, dict)
        or head_repo.get("name") != repository_name
        or head_repo.get("url") != repository_url
        or not isinstance(base, dict)
        or base.get("ref") != guard.EXPECTED_BASE
        or base.get("sha") != admission["base"]
        or not isinstance(base_repo, dict)
        or base_repo.get("name") != repository_name
        or base_repo.get("url") != repository_url
    ):
        raise AttesterError(
            "post-attestation CI run is not bound to the exact admitted pull"
        )


def _validate_recheck_job(
    value: Any,
    *,
    repository: str,
    run_id: int,
    run_status: str,
) -> dict[str, Any] | None:
    """Return the run's required fast gate, or None while it is still arriving.

    A run's job listing is empty for the first seconds of its life, so an absent
    required job on a run that has not completed is news about the clock and not
    about the run's authority. Returning None keeps that case inside the caller's
    wait loop; raising would end the step before the wait it was given.
    """
    jobs = value.get("jobs") if isinstance(value, dict) else None
    total = value.get("total_count") if isinstance(value, dict) else None
    if (
        not isinstance(total, int)
        or isinstance(total, bool)
        or total < 0
        or not isinstance(jobs, list)
        or total != len(jobs)
    ):
        raise AttesterError("post-attestation CI job listing is malformed")
    required = [
        job
        for job in jobs
        if isinstance(job, dict) and job.get("name") == CI_REQUIRED_JOB
    ]
    if len(required) > 1:
        raise AttesterError(
            f"post-attestation CI run {run_id} publishes {len(required)} jobs named "
            f"{CI_REQUIRED_JOB!r}; the recheck requires exactly one"
        )
    if not required:
        if run_status != "completed":
            return None
        raise AttesterError(
            f"completed post-attestation CI run {run_id} publishes no job named "
            f"{CI_REQUIRED_JOB!r} among its {len(jobs)} jobs"
        )
    job = required[0]
    job_id = job.get("id")
    status = job.get("status")
    if (
        not isinstance(job_id, int)
        or isinstance(job_id, bool)
        or job_id < 1
        or status not in RECHECK_STATUSES
        or job.get("run_url")
        != f"https://api.github.com/repos/{repository}/actions/runs/{run_id}"
    ):
        raise AttesterError("post-attestation required fast gate is malformed")
    if status == "completed" and not isinstance(job.get("conclusion"), str):
        raise AttesterError("completed post-attestation fast gate has no conclusion")
    if status != "completed" and job.get("conclusion") is not None:
        raise AttesterError("pending post-attestation fast gate has a conclusion")
    return job


def _post_attestation_recheck(
    *,
    repository: str,
    admission: dict[str, Any],
    attestation: dict[str, Any],
) -> dict[str, Any]:
    """Report the newest validated recheck, plus the runs still arriving.

    The two are separate answers. A validated recheck ends the wait. A run whose
    required fast gate has not been listed yet is the reason to keep waiting, and
    is also the reason not to retrigger, since reopening the pull would cancel
    the run already in flight.
    """
    response = gh_json(
        [
            "api",
            "--paginate",
            "--slurp",
            "--method",
            "GET",
            f"repos/{repository}/actions/workflows/ci.yml/runs",
            "-f",
            "event=pull_request",
            "-f",
            f"head_sha={admission['head']}",
            "-f",
            f"branch={guard.WAVE_BRANCH}",
            "-f",
            "per_page=100",
        ]
    )
    cutoff = _timestamp(
        attestation["comment_created_at"],
        "attestation comment creation",
    )
    candidates: list[dict[str, Any]] = []
    arriving: list[dict[str, Any]] = []
    for run in _workflow_run_pages(response):
        if not _is_recheck_run_candidate(
            run,
            repository=repository,
            admission=admission,
        ):
            continue
        created_at = _timestamp(run.get("created_at"), "CI run creation")
        if created_at < cutoff:
            continue
        repository_doc = run.get("repository")
        head_repository = run.get("head_repository")
        run_attempt = run.get("run_attempt")
        run_status = run.get("status")
        if (
            run.get("name") != CI_WORKFLOW_NAME
            or run.get("path") != CI_WORKFLOW_PATH
            or run.get("event") != "pull_request"
            or run.get("head_branch") != guard.WAVE_BRANCH
            or run.get("head_sha") != admission["head"]
            or run_status not in RECHECK_STATUSES
            or not isinstance(repository_doc, dict)
            or repository_doc.get("full_name") != repository
            or not isinstance(head_repository, dict)
            or head_repository.get("full_name") != repository
            or not isinstance(run_attempt, int)
            or isinstance(run_attempt, bool)
            or run_attempt < 1
        ):
            raise AttesterError("post-attestation CI run has the wrong authority")
        _validate_recheck_pull(run, repository=repository, admission=admission)
        job_listing = gh_json(
            [
                "api",
                "--method",
                "GET",
                (
                    f"repos/{repository}/actions/runs/{run['id']}"
                    f"/attempts/{run_attempt}/jobs"
                ),
                "-f",
                "filter=all",
                "-f",
                "per_page=100",
            ]
        )
        job = _validate_recheck_job(
            job_listing,
            repository=repository,
            run_id=int(run["id"]),
            run_status=str(run_status),
        )
        if job is None:
            arriving.append(
                {
                    "run_id": int(run["id"]),
                    "run_status": str(run_status),
                    "job_count": len(job_listing["jobs"]),
                }
            )
            continue
        candidates.append(
            {
                "run_id": int(run["id"]),
                "run_attempt": run_attempt,
                "job_id": int(job["id"]),
                "job_status": str(job["status"]),
                "job_conclusion": job.get("conclusion"),
                "created_at": run["created_at"],
            }
        )
    return {
        "recheck": (
            max(candidates, key=lambda item: int(item["run_id"]))
            if candidates
            else None
        ),
        "arriving": sorted(arriving, key=lambda item: int(item["run_id"])),
    }


def _missing_recheck_message(
    *,
    head: str,
    arriving: list[dict[str, Any]],
    wait_seconds: int,
) -> str:
    """Say what the recheck looked for, where it looked, and what it found.

    The old message named none of the three, so the same sentence covered a run
    whose jobs had not been listed yet and a run that genuinely never published
    the gate.
    """
    where = f"{CI_WORKFLOW_PATH} runs on {guard.WAVE_BRANCH} at head {head}"
    if not arriving:
        return (
            f"no exact required CI recheck materialized after the App attestation: "
            f"looked for a job named {CI_REQUIRED_JOB!r} on {where} created after the "
            f"attestation comment, and found no such run within {wait_seconds}s"
        )
    described = ", ".join(
        f"run {item['run_id']} ({item['run_status']}, {item['job_count']} jobs listed)"
        for item in arriving
    )
    return (
        f"no exact required CI recheck materialized after the App attestation: "
        f"looked for a job named {CI_REQUIRED_JOB!r} on {where} created after the "
        f"attestation comment, and within {wait_seconds}s found only {described}"
    )


def recheck_status(
    *,
    admission_file: Path,
    workspace: Path,
    repository: str,
    wait_seconds: int,
    require_recheck: bool,
) -> dict[str, Any]:
    if not 0 <= wait_seconds <= 120:
        raise AttesterError("post-attestation CI wait must be between 0 and 120 seconds")
    admission = _load_changed_admission(
        admission_file=admission_file,
        repository=repository,
    )
    validate_live_admission(
        workspace=workspace,
        repository=repository,
        admission=admission,
    )
    attestation = _existing_attestation(
        workspace=workspace,
        repository=repository,
        admission=admission,
        verify_server_run=True,
    )
    if attestation is None:
        raise AttesterError("exact admitted head still has no App attestation")

    deadline = time.monotonic() + wait_seconds
    while True:
        observed = _post_attestation_recheck(
            repository=repository,
            admission=admission,
            attestation=attestation,
        )
        recheck = observed["recheck"]
        arriving = observed["arriving"]
        if recheck is not None:
            validate_live_admission(
                workspace=workspace,
                repository=repository,
                admission=admission,
            )
            return {
                "needs_retrigger": False,
                "attestation_comment_id": attestation["comment_id"],
                **recheck,
            }
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            if require_recheck:
                raise AttesterError(
                    _missing_recheck_message(
                        head=str(admission["head"]),
                        arriving=arriving,
                        wait_seconds=wait_seconds,
                    )
                )
            return {
                "needs_retrigger": not arriving,
                "attestation_comment_id": attestation["comment_id"],
            }
        time.sleep(min(2.0, remaining))


def _exact_pull_state(
    pull: Any,
    *,
    repository: str,
    admission: dict[str, Any],
    state: str,
) -> None:
    head = pull.get("head") if isinstance(pull, dict) else None
    base = pull.get("base") if isinstance(pull, dict) else None
    if (
        not isinstance(pull, dict)
        or pull.get("number") != admission["pull"]
        or pull.get("state") != state
        or pull.get("merged_at") is not None
        or pull.get("auto_merge") is not None
        or not isinstance(head, dict)
        or head.get("sha") != admission["head"]
        or head.get("ref") != guard.WAVE_BRANCH
        or not isinstance(head.get("repo"), dict)
        or head["repo"].get("full_name") != repository
        or not isinstance(base, dict)
        or base.get("sha") != admission["base"]
        or base.get("ref") != guard.EXPECTED_BASE
    ):
        raise AttesterError(f"pull {state} response differs from the exact admission")


def _reopen_pull(
    *,
    repository: str,
    pull_number: int,
) -> Any:
    errors: list[str] = []
    for _ in range(3):
        try:
            response = gh_json(
                [
                    "api",
                    "--method",
                    "PATCH",
                    f"repos/{repository}/pulls/{pull_number}",
                    "-f",
                    "state=open",
                ]
            )
            if (
                isinstance(response, dict)
                and response.get("number") == pull_number
                and response.get("state") == "open"
            ):
                return response
            errors.append("reopen response did not report the exact pull open")
        except AttesterError as exc:
            errors.append(str(exc))
        try:
            observed = gh_json(["api", f"repos/{repository}/pulls/{pull_number}"])
            if (
                isinstance(observed, dict)
                and observed.get("number") == pull_number
                and observed.get("state") == "open"
            ):
                return observed
            errors.append("pull remained closed after a reopen attempt")
        except AttesterError as exc:
            errors.append(str(exc))
    raise AttesterError(
        "dependency pull could not be reopened after CI retrigger: "
        + " | ".join(errors)
    )


def retrigger_pull(
    *,
    admission_file: Path,
    workspace: Path,
    repository: str,
) -> dict[str, Any]:
    admission = _load_changed_admission(
        admission_file=admission_file,
        repository=repository,
    )
    validate_live_admission(
        workspace=workspace,
        repository=repository,
        admission=admission,
    )
    if (
        _existing_attestation(
            workspace=workspace,
            repository=repository,
            admission=admission,
            verify_server_run=False,
        )
        is None
    ):
        raise AttesterError("cannot retrigger CI without an exact App attestation")

    pull_number = int(admission["pull"])
    close_error: AttesterError | None = None
    try:
        closed = gh_json(
            [
                "api",
                "--method",
                "PATCH",
                f"repos/{repository}/pulls/{pull_number}",
                "-f",
                "state=closed",
            ]
        )
        _exact_pull_state(
            closed,
            repository=repository,
            admission=admission,
            state="closed",
        )
    except AttesterError as exc:
        close_error = exc

    try:
        reopened = _reopen_pull(
            repository=repository,
            pull_number=pull_number,
        )
        _exact_pull_state(
            reopened,
            repository=repository,
            admission=admission,
            state="open",
        )
    except AttesterError as exc:
        raise AttesterError(
            "dependency pull could not be proven reopened after CI retrigger"
        ) from exc
    if close_error is not None:
        raise AttesterError(
            f"dependency pull was reopened after an invalid close response: {close_error}"
        )

    validate_live_admission(
        workspace=workspace,
        repository=repository,
        admission=admission,
    )
    if (
        _existing_attestation(
            workspace=workspace,
            repository=repository,
            admission=admission,
            verify_server_run=False,
        )
        is None
    ):
        raise AttesterError("App attestation disappeared across CI retrigger")
    return {"reopened": True, "pull": pull_number, "head": admission["head"]}


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument("--event-file", type=Path, required=True)
    for name in ("validate", "post", "recheck-status", "retrigger"):
        command = (
            validate_parser if name == "validate" else subparsers.add_parser(name)
        )
        command.add_argument("--admission-file", type=Path, required=True)
        command.add_argument("--workspace", type=Path, required=True)
        command.add_argument("--repository", required=True)
        if name == "recheck-status":
            command.add_argument("--wait-seconds", type=int, default=0)
            command.add_argument("--require-recheck", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        if args.repository != EXPECTED_REPOSITORY:
            raise AttesterError("attester repository is not firelock-ai/kin")
        if args.command == "validate":
            result = validate_for_attestation(
                event_file=args.event_file,
                admission_file=args.admission_file,
                workspace=args.workspace,
                repository=args.repository,
            )
        elif args.command == "post":
            result = post_attestation(
                admission_file=args.admission_file,
                workspace=args.workspace,
                repository=args.repository,
            )
        elif args.command == "recheck-status":
            result = recheck_status(
                admission_file=args.admission_file,
                workspace=args.workspace,
                repository=args.repository,
                wait_seconds=args.wait_seconds,
                require_recheck=args.require_recheck,
            )
        else:
            result = retrigger_pull(
                admission_file=args.admission_file,
                workspace=args.workspace,
                repository=args.repository,
            )
    except (AttesterError, OSError, UnicodeDecodeError) as exc:
        print(
            f"::error title=Invalid completed Kin registry admission::{exc}",
            file=sys.stderr,
        )
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
