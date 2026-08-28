#!/usr/bin/env python3
"""Verify every landable Kin registry dependency-wave head and delivery."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import time
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence


EXPECTED_REPOSITORY = "firelock-ai/kin"
EXPECTED_BASE = "main"
WAVE_BRANCH = "automation/kin-registry-dependency-wave"
ATTESTATION_MARKER = "<!-- kin-registry-dependency-admission:v2 -->"
ATTESTATION_APP_ID = 4370197
ATTESTATION_APP_SLUG = "kin-release-bot"
ATTESTATION_APP_OWNER = "firelock-ai"
ATTESTATION_APP_OWNER_ID = 69090636
ATTESTATION_CREATOR = "kin-release-bot[bot]"
ATTESTATION_CREATOR_ID = 308181894
COMMIT_MARKER = "Kin-Registry-Dependency-Wave: v1"
RECEIVER_WORKFLOW_NAME = "Kin Registry Release Receiver"
RECEIVER_WORKFLOW_PATH = ".github/workflows/kin-registry-release.yml"
ALLOWED_PATHS = frozenset({"Cargo.toml", "Cargo.lock"})
LOWER_SHA = re.compile(r"^[0-9a-f]{40}$")
VERSION_EVIDENCE = re.compile(r"^(?:absent|[0-9A-Za-z.+-]+)$")


class AdmissionError(RuntimeError):
    """A dependency-wave head or delivered delta is not admitted."""


class PendingAttestation(AdmissionError):
    """The exact App attestation may still be arriving from the receiver."""


@dataclass(frozen=True)
class DeltaEvidence:
    base: str
    head: str
    tree: str
    paths: frozenset[str]
    delta_sha256: str
    package_version: str
    workspace_version: str


@dataclass(frozen=True)
class PullEvidence:
    number: int
    base: str


def _run(
    command: Sequence[str],
    *,
    cwd: Path | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(
        list(command),
        cwd=cwd,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if check and result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        if not detail:
            detail = result.stdout.decode("utf-8", errors="replace").strip()
        raise AdmissionError(
            f"{' '.join(command)} failed: {detail or 'no error output'}"
        )
    return result


def git(workspace: Path, *arguments: str, check: bool = True) -> bytes:
    return _run(
        ["git", "-C", str(workspace), *arguments],
        check=check,
    ).stdout


def gh_json(arguments: Sequence[str]) -> Any:
    output = _run(["gh", *arguments]).stdout
    try:
        return json.loads(output)
    except json.JSONDecodeError as exc:
        raise AdmissionError("GitHub returned malformed JSON") from exc


def require_sha(label: str, value: Any) -> str:
    if not isinstance(value, str) or LOWER_SHA.fullmatch(value) is None:
        raise AdmissionError(f"{label} must be 40-character lowercase hex")
    return value


def _paths(output: bytes) -> frozenset[str]:
    return frozenset(
        value.decode("utf-8", errors="surrogateescape")
        for value in output.split(b"\0")
        if value
    )


def _version_fields(document: dict[str, object]) -> tuple[object, object]:
    package = document.get("package")
    package_version: object = None
    if isinstance(package, dict):
        package_version = package.get("version")
    workspace = document.get("workspace")
    workspace_version: object = None
    if isinstance(workspace, dict):
        workspace_package = workspace.get("package")
        if isinstance(workspace_package, dict):
            workspace_version = workspace_package.get("version")
    return package_version, workspace_version


def _toml_at(workspace: Path, revision: str, path: str) -> dict[str, object]:
    raw = git(workspace, "show", f"{revision}:{path}")
    try:
        value = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise AdmissionError(f"cannot parse {path} at {revision}: {exc}") from exc
    if not isinstance(value, dict):
        raise AdmissionError(f"{path} at {revision} is not a TOML object")
    return value


def exact_patch(workspace: Path, base: str, head: str) -> bytes:
    return git(
        workspace,
        "diff",
        "--binary",
        "--full-index",
        "--no-ext-diff",
        "--no-textconv",
        "--no-renames",
        base,
        head,
        "--",
        *sorted(ALLOWED_PATHS),
    )


def _version_evidence(value: object) -> str:
    if value is None:
        return "absent"
    if not isinstance(value, str) or VERSION_EVIDENCE.fullmatch(value) is None:
        raise AdmissionError(f"version field cannot be attested safely: {value!r}")
    return value


def is_ancestor(workspace: Path, base: str, head: str) -> bool:
    return (
        _run(
            ["git", "-C", str(workspace), "merge-base", "--is-ancestor", base, head],
            check=False,
        ).returncode
        == 0
    )


def ensure_pull_head(workspace: Path, pull_number: int, head: str) -> None:
    present = _run(
        ["git", "-C", str(workspace), "cat-file", "-e", f"{head}^{{commit}}"],
        check=False,
    ).returncode
    if present == 0:
        return
    _run(
        [
            "git",
            "-C",
            str(workspace),
            "fetch",
            "--no-tags",
            "origin",
            f"refs/pull/{pull_number}/head",
        ]
    )
    if (
        _run(
            ["git", "-C", str(workspace), "cat-file", "-e", f"{head}^{{commit}}"],
            check=False,
        ).returncode
        != 0
    ):
        raise AdmissionError(
            f"pull request {pull_number} ref did not contain expected head {head}"
        )


def validate_delta(
    workspace: Path,
    base: str,
    head: str,
    *,
    require_marker: bool,
) -> DeltaEvidence:
    base = require_sha("delta base", base)
    head = require_sha("delta head", head)
    for label, revision in (("base", base), ("head", head)):
        if (
            _run(
                ["git", "-C", str(workspace), "cat-file", "-e", f"{revision}^{{commit}}"],
                check=False,
            ).returncode
            != 0
        ):
            raise AdmissionError(f"{label} commit {revision} is absent from checkout")
    if not is_ancestor(workspace, base, head):
        raise AdmissionError(f"admission base {base} is not an ancestor of {head}")

    paths = _paths(
        git(
            workspace,
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            "--name-only",
            "-z",
            base,
            head,
            "--",
        )
    )
    if not paths:
        raise AdmissionError("dependency-wave delta is empty")
    unexpected = sorted(paths - ALLOWED_PATHS)
    if unexpected:
        raise AdmissionError(
            "dependency-wave changed non-admitted paths: " + ", ".join(unexpected)
        )
    summary = git(
        workspace,
        "diff",
        "--summary",
        "--no-renames",
        base,
        head,
        "--",
    ).decode("utf-8", errors="replace").strip()
    if summary:
        raise AdmissionError(
            "dependency-wave changed file identity or mode: " + summary
        )
    before_versions = _version_fields(_toml_at(workspace, base, "Cargo.toml"))
    after_versions = _version_fields(_toml_at(workspace, head, "Cargo.toml"))
    if before_versions != after_versions:
        raise AdmissionError("dependency-wave changed package or workspace version")
    if require_marker:
        body = git(workspace, "show", "-s", "--format=%B", head).decode(
            "utf-8", errors="replace"
        )
        if body.splitlines().count(COMMIT_MARKER) != 1:
            raise AdmissionError("dependency-wave head lacks its exact commit marker")
    tree = require_sha(
        "dependency-wave tree",
        git(workspace, "rev-parse", f"{head}^{{tree}}").decode("ascii").strip(),
    )
    patch = exact_patch(workspace, base, head)
    if not patch:
        raise AdmissionError("dependency-wave patch carries no content change")
    return DeltaEvidence(
        base=base,
        head=head,
        tree=tree,
        paths=paths,
        delta_sha256=hashlib.sha256(patch).hexdigest(),
        package_version=_version_evidence(after_versions[0]),
        workspace_version=_version_evidence(after_versions[1]),
    )


def validate_index_delta(
    workspace: Path,
    base: str,
    expected_tree: str,
) -> DeltaEvidence:
    """Validate and describe the exact staged tree before the PR writer runs."""

    base = require_sha("staged delta base", base)
    expected_tree = require_sha("staged dependency-wave tree", expected_tree)
    if (
        _run(
            ["git", "-C", str(workspace), "cat-file", "-e", f"{base}^{{commit}}"],
            check=False,
        ).returncode
        != 0
    ):
        raise AdmissionError(f"staged delta base {base} is absent from checkout")
    checked_out_head = git(workspace, "rev-parse", "HEAD").decode("ascii").strip()
    if checked_out_head != base:
        raise AdmissionError(
            f"staged dependency base {base} is not checked-out HEAD {checked_out_head}"
        )
    actual_tree = git(workspace, "write-tree").decode("ascii").strip()
    if actual_tree != expected_tree:
        raise AdmissionError(
            f"staged dependency tree {actual_tree} differs from admitted {expected_tree}"
        )
    paths = _paths(
        git(
            workspace,
            "diff",
            "--cached",
            "--no-renames",
            "--name-only",
            "-z",
            base,
            "--",
        )
    )
    if not paths:
        raise AdmissionError("staged dependency-wave delta is empty")
    unexpected = sorted(paths - ALLOWED_PATHS)
    if unexpected:
        raise AdmissionError(
            "staged dependency-wave changed non-admitted paths: "
            + ", ".join(unexpected)
        )
    summary = git(
        workspace,
        "diff",
        "--cached",
        "--summary",
        "--no-renames",
        base,
        "--",
    ).decode("utf-8", errors="replace").strip()
    if summary:
        raise AdmissionError(
            "staged dependency-wave changed file identity or mode: " + summary
        )
    before_versions = _version_fields(_toml_at(workspace, base, "Cargo.toml"))
    raw_manifest = git(workspace, "show", ":Cargo.toml")
    try:
        staged_document = tomllib.loads(raw_manifest.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise AdmissionError(f"cannot parse staged Cargo.toml: {exc}") from exc
    after_versions = _version_fields(staged_document)
    if before_versions != after_versions:
        raise AdmissionError("staged dependency-wave changed package or workspace version")
    patch = git(
        workspace,
        "diff",
        "--cached",
        "--binary",
        "--full-index",
        "--no-ext-diff",
        "--no-textconv",
        "--no-renames",
        base,
        "--",
        *sorted(ALLOWED_PATHS),
    )
    if not patch:
        raise AdmissionError("staged dependency-wave patch carries no content change")
    return DeltaEvidence(
        base=base,
        head="index",
        tree=expected_tree,
        paths=paths,
        delta_sha256=hashlib.sha256(patch).hexdigest(),
        package_version=_version_evidence(after_versions[0]),
        workspace_version=_version_evidence(after_versions[1]),
    )


def verify_delivery_tree(
    workspace: Path,
    admitted: DeltaEvidence,
    delivered: DeltaEvidence,
) -> None:
    """Apply the admitted patch to the actual delivery base and require its tree."""

    if not is_ancestor(workspace, admitted.base, delivered.base):
        raise AdmissionError(
            "classic-main delivery base does not descend from the admitted base"
        )
    expected_tree = git(
        workspace,
        "merge-tree",
        "--write-tree",
        delivered.base,
        admitted.head,
    ).decode("ascii").strip()
    require_sha("reconciled dependency-wave tree", expected_tree)
    if expected_tree != delivered.tree:
        raise AdmissionError(
            "classic-main delivery tree differs from applying the exact admitted delta"
        )


def verify_merge_group_dependency_tree(
    workspace: Path,
    base: str,
    group_head: str,
    admitted: DeltaEvidence,
) -> None:
    """Reject any queued peer that changes the admitted dependency paths."""

    if admitted.base != base:
        raise AdmissionError(
            "merge group base differs from the admitted dependency base"
        )
    expected_tree = git(
        workspace,
        "merge-tree",
        "--write-tree",
        base,
        admitted.head,
    ).decode("ascii").strip()
    require_sha("candidate-only merge-group tree", expected_tree)
    expected_entries = git(
        workspace,
        "ls-tree",
        "-z",
        expected_tree,
        "--",
        *sorted(ALLOWED_PATHS),
    )
    delivered_entries = git(
        workspace,
        "ls-tree",
        "-z",
        group_head,
        "--",
        *sorted(ALLOWED_PATHS),
    )
    if expected_entries != delivered_entries:
        raise AdmissionError(
            "merge group changes admitted dependency paths outside the wave"
        )


def _review_body(
    repository: str,
    pull_number: int,
    head: str,
    tree: str,
    base: str,
    delta_sha256: str,
    package_version: str,
    workspace_version: str,
    workflow_path: str,
    policy_sha: str,
    run_id: int,
    run_attempt: int,
) -> str:
    return "\n".join(
        (
            "Kin registry dependency admission review v2",
            f"repository={repository}",
            f"pull={pull_number}",
            f"head={head}",
            f"tree={tree}",
            f"base={base}",
            f"delta_sha256={delta_sha256}",
            f"package_version={package_version}",
            f"workspace_version={workspace_version}",
            f"workflow_path={workflow_path}",
            f"policy_sha={policy_sha}",
            f"run_id={run_id}",
            f"run_attempt={run_attempt}",
        )
    )


def _comment_body(
    repository: str,
    pull_number: int,
    review_id: int,
    head: str,
    tree: str,
    base: str,
    delta_sha256: str,
    package_version: str,
    workspace_version: str,
    workflow_path: str,
    policy_sha: str,
    run_id: int,
    run_attempt: int,
) -> str:
    return "\n".join(
        (
            ATTESTATION_MARKER,
            f"repository={repository}",
            f"pull={pull_number}",
            f"review_id={review_id}",
            f"head={head}",
            f"tree={tree}",
            f"base={base}",
            f"delta_sha256={delta_sha256}",
            f"package_version={package_version}",
            f"workspace_version={workspace_version}",
            f"workflow_path={workflow_path}",
            f"policy_sha={policy_sha}",
            f"run_id={run_id}",
            f"run_attempt={run_attempt}",
        )
    )


def _parse_comment_body(body: Any) -> dict[str, str | int]:
    if not isinstance(body, str):
        raise AdmissionError("dependency admission comment has no text body")
    match = re.fullmatch(
        re.escape(ATTESTATION_MARKER)
        + r"\nrepository=(firelock-ai/kin)"
        + r"\npull=([1-9][0-9]*)"
        + r"\nreview_id=([1-9][0-9]*)"
        + r"\nhead=([0-9a-f]{40})"
        + r"\ntree=([0-9a-f]{40})"
        + r"\nbase=([0-9a-f]{40})"
        + r"\ndelta_sha256=([0-9a-f]{64})"
        + r"\npackage_version=(absent|[0-9A-Za-z.+-]+)"
        + r"\nworkspace_version=(absent|[0-9A-Za-z.+-]+)"
        + r"\nworkflow_path=(\.github/workflows/kin-registry-release\.yml)"
        + r"\npolicy_sha=([0-9a-f]{40})"
        + r"\nrun_id=([1-9][0-9]*)"
        + r"\nrun_attempt=([1-9][0-9]*)",
        body.strip(),
    )
    if match is None:
        raise AdmissionError("dependency admission comment has malformed evidence")
    (
        repository,
        pull,
        review_id,
        head,
        tree,
        base,
        delta_sha256,
        package_version,
        workspace_version,
        workflow_path,
        policy_sha,
        run_id,
        run_attempt,
    ) = match.groups()
    return {
        "repository": repository,
        "pull": int(pull),
        "review_id": int(review_id),
        "head": head,
        "tree": tree,
        "base": base,
        "delta_sha256": delta_sha256,
        "package_version": package_version,
        "workspace_version": workspace_version,
        "workflow_path": workflow_path,
        "policy_sha": policy_sha,
        "run_id": int(run_id),
        "run_attempt": int(run_attempt),
    }


def _has_exact_attestation_app_identity(comment: dict[str, Any]) -> bool:
    app = comment.get("performed_via_github_app")
    owner = app.get("owner") if isinstance(app, dict) else None
    user = comment.get("user")
    return (
        isinstance(app, dict)
        and app.get("id") == ATTESTATION_APP_ID
        and app.get("slug") == ATTESTATION_APP_SLUG
        and isinstance(owner, dict)
        and owner.get("id") == ATTESTATION_APP_OWNER_ID
        and owner.get("login") == ATTESTATION_APP_OWNER
        and isinstance(user, dict)
        and user.get("id") == ATTESTATION_CREATOR_ID
        and user.get("login") == ATTESTATION_CREATOR
        and user.get("type") == "Bot"
    )


def validate_workflow_run(
    repository: str,
    evidence: dict[str, str | int],
    workflow_run: Any | None = None,
) -> None:
    run_id = evidence.get("run_id")
    run_attempt = evidence.get("run_attempt")
    policy_sha = evidence.get("policy_sha")
    workflow_path = evidence.get("workflow_path")
    if (
        not isinstance(run_id, int)
        or isinstance(run_id, bool)
        or run_id < 1
        or not isinstance(run_attempt, int)
        or isinstance(run_attempt, bool)
        or run_attempt < 1
        or workflow_path != RECEIVER_WORKFLOW_PATH
        or policy_sha != evidence.get("base")
    ):
        raise AdmissionError("dependency admission has invalid receiver run authority")
    if workflow_run is None:
        workflow_run = gh_json(
            [
                "api",
                f"repos/{repository}/actions/runs/{run_id}/attempts/{run_attempt}",
            ]
        )
    run_repository = (
        workflow_run.get("repository") if isinstance(workflow_run, dict) else None
    )
    head_repository = (
        workflow_run.get("head_repository")
        if isinstance(workflow_run, dict)
        else None
    )
    if (
        not isinstance(workflow_run, dict)
        or workflow_run.get("id") != run_id
        or workflow_run.get("run_attempt") != run_attempt
        or workflow_run.get("name") != RECEIVER_WORKFLOW_NAME
        or workflow_run.get("path") != RECEIVER_WORKFLOW_PATH
        or workflow_run.get("status") != "completed"
        or workflow_run.get("conclusion") != "success"
        or workflow_run.get("event") not in {"repository_dispatch", "schedule"}
        or workflow_run.get("head_branch") != EXPECTED_BASE
        or workflow_run.get("head_sha") != policy_sha
        or not isinstance(run_repository, dict)
        or run_repository.get("full_name") != repository
        or not isinstance(head_repository, dict)
        or head_repository.get("full_name") != repository
    ):
        raise AdmissionError(
            "dependency admission does not cite the exact successful receiver run"
        )


def validate_attestation(
    workspace: Path,
    repository: str,
    pull_number: int,
    head: str,
    reviews: Any,
    comments: Any,
    *,
    expected_base: str | None = None,
    workflow_run: Any | None = None,
    verify_server_run: bool = False,
) -> DeltaEvidence:
    if not isinstance(reviews, list) or not isinstance(comments, list):
        raise AdmissionError("dependency admission review or comment listing is malformed")
    reviews_by_id: dict[int, dict[str, Any]] = {}
    for review in reviews:
        if not isinstance(review, dict):
            raise AdmissionError("dependency admission review listing has a non-object")
        review_id = review.get("id")
        if isinstance(review_id, int) and not isinstance(review_id, bool):
            if review_id in reviews_by_id:
                raise AdmissionError("dependency admission review id is duplicated")
            reviews_by_id[review_id] = review

    current: list[tuple[dict[str, Any], dict[str, str | int]]] = []
    for comment in comments:
        if not isinstance(comment, dict):
            raise AdmissionError("dependency admission comment listing has a non-object")
        body = comment.get("body")
        if not isinstance(body, str) or not body.startswith(ATTESTATION_MARKER):
            continue
        if not _has_exact_attestation_app_identity(comment):
            continue
        evidence = _parse_comment_body(body)
        comment_id = comment.get("id")
        if (
            not isinstance(comment_id, int)
            or isinstance(comment_id, bool)
        ):
            raise AdmissionError("exact App admission comment has an invalid id")
        if comment.get("created_at") != comment.get("updated_at"):
            raise AdmissionError("dependency admission comment was edited")
        if comment.get("issue_url") != (
            f"https://api.github.com/repos/{repository}/issues/{pull_number}"
        ):
            raise AdmissionError("dependency admission comment belongs to another pull")
        if comment.get("html_url") != (
            f"https://github.com/{repository}/pull/{pull_number}"
            f"#issuecomment-{comment_id}"
        ):
            raise AdmissionError("dependency admission comment has an invalid canonical URL")
        if evidence["head"] == head:
            current.append((comment, evidence))

    if not current:
        raise PendingAttestation(
            "dependency-wave head has no exact release-App admission attestation"
        )
    evidence_shapes = {
        (
            item["repository"],
            item["pull"],
            item["head"],
            item["tree"],
            item["base"],
            item["delta_sha256"],
            item["package_version"],
            item["workspace_version"],
            item["workflow_path"],
            item["policy_sha"],
            item["run_id"],
            item["run_attempt"],
        )
        for _, item in current
    }
    if len(evidence_shapes) != 1:
        raise AdmissionError("dependency-wave head has conflicting App attestations")

    for comment, item in current:
        if item["repository"] != repository or item["pull"] != pull_number:
            raise AdmissionError("dependency admission payload names another pull")
        review = reviews_by_id.get(int(item["review_id"]))
        if review is None:
            raise AdmissionError("App attestation references a deleted or missing review")
        review_user = review.get("user")
        expected_review_body = _review_body(
            repository,
            pull_number,
            head,
            str(item["tree"]),
            str(item["base"]),
            str(item["delta_sha256"]),
            str(item["package_version"]),
            str(item["workspace_version"]),
            str(item["workflow_path"]),
            str(item["policy_sha"]),
            int(item["run_id"]),
            int(item["run_attempt"]),
        )
        if (
            review.get("state") != "COMMENTED"
            or review.get("commit_id") != head
            or review.get("body") != expected_review_body
            or not isinstance(review_user, dict)
            or review_user.get("id") != ATTESTATION_CREATOR_ID
            or review_user.get("login") != ATTESTATION_CREATOR
            or review_user.get("type") != "Bot"
        ):
            raise AdmissionError(
                "cross-linked dependency admission review is stale, edited, or dismissed"
            )
        submitted = review.get("submitted_at")
        created = comment.get("created_at")
        if not isinstance(submitted, str) or not isinstance(created, str) or submitted > created:
            raise AdmissionError("dependency admission review/comment ordering is invalid")

    _, latest = max(current, key=lambda item: item[0]["id"])
    if verify_server_run or workflow_run is not None:
        validate_workflow_run(repository, latest, workflow_run)
    expected_tree = str(latest["tree"])
    base = str(latest["base"])
    if expected_base is not None and base != expected_base:
        raise AdmissionError(
            f"dependency admission base {base} is not current pull base {expected_base}"
        )
    evidence = validate_delta(workspace, base, head, require_marker=True)
    if evidence.tree != expected_tree:
        raise AdmissionError(
            f"dependency head tree {evidence.tree} differs from admitted {expected_tree}"
        )
    if evidence.delta_sha256 != latest["delta_sha256"]:
        raise AdmissionError("dependency head delta differs from admitted fingerprint")
    if evidence.package_version != latest["package_version"]:
        raise AdmissionError("dependency head package version differs from admission")
    if evidence.workspace_version != latest["workspace_version"]:
        raise AdmissionError("dependency head workspace version differs from admission")
    if evidence.base != latest["policy_sha"]:
        raise AdmissionError("dependency admission policy differs from its exact base")
    return evidence


def validate_pull(
    pull: Any,
    *,
    repository: str,
    expected_head: str,
    require_open: bool,
) -> PullEvidence:
    if not isinstance(pull, dict):
        raise AdmissionError("pull response is not an object")
    number = pull.get("number")
    head = pull.get("head")
    base = pull.get("base")
    if (
        not isinstance(number, int)
        or isinstance(number, bool)
        or number < 1
        or not isinstance(head, dict)
        or not isinstance(base, dict)
        or not isinstance(head.get("repo"), dict)
    ):
        raise AdmissionError("pull response has malformed identity fields")
    if (
        head["repo"].get("full_name") != repository
        or head.get("ref") != WAVE_BRANCH
        or head.get("sha") != expected_head
        or base.get("ref") != EXPECTED_BASE
    ):
        raise AdmissionError("pull is not the exact first-party dependency wave")
    base_sha = require_sha("pull request base", base.get("sha"))
    if "auto_merge" not in pull:
        raise AdmissionError("pull response omitted server-side auto-merge state")
    if pull["auto_merge"] is not None:
        raise AdmissionError("dependency-wave pull request has auto-merge armed")
    if require_open and pull.get("state") != "open":
        raise AdmissionError("dependency-wave pull request is not open")
    if not require_open and not pull.get("merged_at"):
        raise AdmissionError("dependency-wave delivery is not associated with a merge")
    return PullEvidence(number=number, base=base_sha)


def _fresh_pull(repository: str, number: int) -> Any:
    return gh_json(["api", f"repos/{repository}/pulls/{number}"])


def _paginated_items(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise AdmissionError(f"{label} response is not an array")
    if value and all(isinstance(page, list) for page in value):
        return [item for page in value for item in page]
    return value


def _attestation_documents(repository: str, pull_number: int) -> tuple[list[Any], list[Any]]:
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


def verify_attestation(
    workspace: Path,
    repository: str,
    pull_number: int,
    head: str,
    *,
    wait_seconds: int,
    expected_base: str | None = None,
) -> DeltaEvidence:
    deadline = time.monotonic() + wait_seconds
    while True:
        reviews, comments = _attestation_documents(repository, pull_number)
        try:
            return validate_attestation(
                workspace,
                repository,
                pull_number,
                head,
                reviews,
                comments,
                expected_base=expected_base,
                verify_server_run=True,
            )
        except PendingAttestation:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise
            time.sleep(min(5.0, remaining))


def _open_wave_pulls(repository: str) -> list[Any]:
    owner = repository.split("/", 1)[0]
    value = gh_json(
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
            f"base={EXPECTED_BASE}",
            "-f",
            "per_page=100",
        ]
    )
    if not isinstance(value, list):
        raise AdmissionError("open dependency pull listing is not an array")
    if len(value) > 1:
        raise AdmissionError("fixed dependency branch has multiple open pulls")
    return value


def _associated_pulls(repository: str, commit: str) -> list[Any]:
    value = gh_json(["api", f"repos/{repository}/commits/{commit}/pulls"])
    if not isinstance(value, list):
        raise AdmissionError("associated pull listing is not an array")
    selected = []
    for pull in value:
        if not isinstance(pull, dict):
            continue
        head = pull.get("head")
        base = pull.get("base")
        if (
            isinstance(head, dict)
            and isinstance(base, dict)
            and isinstance(head.get("repo"), dict)
            and head["repo"].get("full_name") == repository
            and head.get("ref") == WAVE_BRANCH
            and base.get("ref") == EXPECTED_BASE
        ):
            selected.append(pull)
    if len(selected) > 1:
        raise AdmissionError("commit is associated with multiple dependency-wave pulls")
    return selected


def marked_commits(workspace: Path, base: str, head: str) -> list[str]:
    revisions = git(workspace, "rev-list", f"{base}..{head}").decode().splitlines()
    return [
        revision
        for revision in revisions
        if git(workspace, "show", "-s", "--format=%B", revision)
        .decode("utf-8", errors="replace")
        .splitlines()
        .count(COMMIT_MARKER)
        > 0
    ]


def verify_pull_request(
    workspace: Path,
    repository: str,
    event: dict[str, Any],
    *,
    wait_seconds: int,
) -> str:
    event_pull = event.get("pull_request")
    if not isinstance(event_pull, dict):
        raise AdmissionError("pull_request event omitted pull_request")
    event_head = event_pull.get("head")
    event_base = event_pull.get("base")
    if not isinstance(event_head, dict) or not isinstance(event_base, dict):
        raise AdmissionError("pull_request event omitted head or base")
    head = require_sha("pull request head", event_head.get("sha"))
    base = require_sha("pull request base", event_base.get("sha"))
    number = event_pull.get("number")
    if not isinstance(number, int) or isinstance(number, bool) or number < 1:
        raise AdmissionError("pull_request event has no valid number")
    ensure_pull_head(workspace, number, head)
    markers = marked_commits(workspace, base, head)
    if event_head.get("ref") != WAVE_BRANCH:
        if markers:
            raise AdmissionError(
                "non-wave pull request uses the reserved dependency-wave marker"
            )
        return "not a registry dependency-wave pull request"
    pull = _fresh_pull(repository, number)
    pull_evidence = validate_pull(
        pull,
        repository=repository,
        expected_head=head,
        require_open=True,
    )
    if pull_evidence.base != base:
        raise AdmissionError(
            "pull request base moved after the delivered pull_request event"
        )
    admitted = verify_attestation(
        workspace,
        repository,
        pull_evidence.number,
        head,
        wait_seconds=wait_seconds,
        expected_base=pull_evidence.base,
    )
    if markers != [head] or admitted.head != head:
        raise AdmissionError("dependency-wave pull marker is missing or ambiguous")
    return (
        f"verified dependency-wave pull request {pull_evidence.number} at {head}"
    )


def verify_merge_group(
    workspace: Path,
    repository: str,
    event: dict[str, Any],
    *,
    wait_seconds: int,
) -> str:
    group = event.get("merge_group")
    if not isinstance(group, dict):
        raise AdmissionError("merge_group event omitted merge_group")
    base = require_sha("merge-group base", group.get("base_sha"))
    head = require_sha("merge-group head", group.get("head_sha"))
    markers = marked_commits(workspace, base, head)
    pulls = _open_wave_pulls(repository)
    if not pulls:
        if markers:
            raise AdmissionError(
                "merge group contains a dependency-wave marker without its open pull"
            )
        return "merge group contains no registry dependency wave"
    candidate_summary = pulls[0]
    candidate_number = candidate_summary.get("number")
    if (
        not isinstance(candidate_number, int)
        or isinstance(candidate_number, bool)
        or candidate_number < 1
    ):
        raise AdmissionError("open dependency pull has no valid number")
    candidate = _fresh_pull(repository, candidate_number)
    candidate_head = require_sha(
        "dependency-wave pull head",
        candidate.get("head", {}).get("sha")
        if isinstance(candidate.get("head"), dict)
        else None,
    )
    if not is_ancestor(workspace, candidate_head, head):
        if markers:
            raise AdmissionError(
                "merge group contains stale dependency-wave bytes after its pull moved"
            )
        return "merge group does not contain the open registry dependency wave"
    if markers != [candidate_head]:
        raise AdmissionError("merge group dependency-wave marker is missing or ambiguous")
    pull_evidence = validate_pull(
        candidate,
        repository=repository,
        expected_head=candidate_head,
        require_open=True,
    )
    if pull_evidence.base != base:
        raise AdmissionError(
            "merge group base differs from the current dependency pull base"
        )
    admitted = verify_attestation(
        workspace,
        repository,
        pull_evidence.number,
        candidate_head,
        wait_seconds=wait_seconds,
        expected_base=pull_evidence.base,
    )
    verify_merge_group_dependency_tree(workspace, base, head, admitted)
    return (
        "verified dependency-wave pull request "
        f"{pull_evidence.number} in merge group"
    )


def verify_push(
    workspace: Path,
    repository: str,
    event: dict[str, Any],
    *,
    wait_seconds: int,
) -> str:
    if event.get("ref") != f"refs/heads/{EXPECTED_BASE}":
        return "push is not protected main"
    before = require_sha("push before", event.get("before"))
    head = require_sha("push head", event.get("after"))
    markers = marked_commits(workspace, before, head)
    pulls = _associated_pulls(repository, head)
    if not pulls:
        if markers:
            raise AdmissionError(
                "main delivery contains a dependency-wave marker without its pull"
            )
        return "main push is not a registry dependency-wave delivery"
    associated = pulls[0]
    number = associated.get("number")
    if not isinstance(number, int) or isinstance(number, bool) or number < 1:
        raise AdmissionError("associated dependency pull has no valid number")
    pull = _fresh_pull(repository, number)
    pull_head = require_sha(
        "delivered pull head",
        pull.get("head", {}).get("sha")
        if isinstance(pull, dict) and isinstance(pull.get("head"), dict)
        else None,
    )
    pull_evidence = validate_pull(
        pull,
        repository=repository,
        expected_head=pull_head,
        require_open=False,
    )
    ensure_pull_head(workspace, pull_evidence.number, pull_head)
    admitted = verify_attestation(
        workspace,
        repository,
        pull_evidence.number,
        pull_head,
        wait_seconds=wait_seconds,
    )
    delivered = validate_delta(
        workspace,
        before,
        head,
        require_marker=False,
    )
    verify_delivery_tree(workspace, admitted, delivered)
    return (
        "verified classic-main delivery of dependency-wave pull request "
        f"{pull_evidence.number}"
    )


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--event-file", type=Path, required=True)
    parser.add_argument("--event-name", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--ref", required=True)
    parser.add_argument("--workflow-sha", required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--attestation-wait-seconds", type=int, default=0)
    return parser.parse_args(argv)


def emit_index_evidence(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--base", required=True)
    parser.add_argument("--expected-tree", required=True)
    args = parser.parse_args(argv)
    try:
        evidence = validate_index_delta(
            args.workspace,
            args.base,
            args.expected_tree,
        )
    except AdmissionError as exc:
        print(
            f"::error title=Invalid staged Kin registry dependency delta::{exc}",
            file=sys.stderr,
        )
        return 1
    print(
        json.dumps(
            {
                "base": evidence.base,
                "tree": evidence.tree,
                "delta_sha256": evidence.delta_sha256,
                "package_version": evidence.package_version,
                "workspace_version": evidence.workspace_version,
            },
            sort_keys=True,
        )
    )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(argv or sys.argv[1:])
    if arguments[:1] == ["emit-index-evidence"]:
        return emit_index_evidence(arguments[1:])
    args = parse_args(arguments)
    try:
        if args.repository != EXPECTED_REPOSITORY:
            raise AdmissionError(
                f"repository must be {EXPECTED_REPOSITORY}, got {args.repository}"
            )
        if not 0 <= args.attestation_wait_seconds <= 300:
            raise AdmissionError("attestation wait must be between 0 and 300 seconds")
        require_sha("workflow sha", args.workflow_sha)
        with args.event_file.open(encoding="utf-8") as stream:
            event = json.load(stream)
        if not isinstance(event, dict):
            raise AdmissionError("event document is not an object")
        if args.event_name == "pull_request":
            message = verify_pull_request(
                args.workspace,
                args.repository,
                event,
                wait_seconds=args.attestation_wait_seconds,
            )
        elif args.event_name == "merge_group":
            message = verify_merge_group(
                args.workspace,
                args.repository,
                event,
                wait_seconds=args.attestation_wait_seconds,
            )
        elif args.event_name == "push":
            if args.ref != f"refs/heads/{EXPECTED_BASE}":
                raise AdmissionError("push workflow ref is not protected main")
            if event.get("after") != args.workflow_sha:
                raise AdmissionError("push event after does not match workflow sha")
            message = verify_push(
                args.workspace,
                args.repository,
                event,
                wait_seconds=args.attestation_wait_seconds,
            )
        else:
            message = f"event {args.event_name} carries no dependency-wave delivery"
    except (OSError, json.JSONDecodeError, AdmissionError) as exc:
        print(
            f"::error title=Invalid Kin registry dependency head::{exc}",
            file=sys.stderr,
        )
        return 1
    print(message)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
