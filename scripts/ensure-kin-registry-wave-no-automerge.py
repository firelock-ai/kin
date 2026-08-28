#!/usr/bin/env python3
"""Clear every server-owned landing arm on Kin's fixed dependency PR."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from typing import Any, Sequence


class LandingStateError(RuntimeError):
    """The fixed dependency PR is missing, ambiguous, or still landable."""


LOWER_SHA = re.compile(r"^[0-9a-f]{40}$")

PULL_QUERY = """
query($owner: String!, $name: String!, $number: Int!) {
  repository(owner: $owner, name: $name) {
    pullRequest(number: $number) {
      id
      number
      state
      headRefName
      headRefOid
      baseRefName
      headRepository { nameWithOwner }
      autoMergeRequest { enabledAt }
      mergeQueueEntry { id }
    }
  }
}
""".strip()

DEQUEUE_MUTATION = """
mutation($id: ID!) {
  dequeuePullRequest(input: {id: $id}) {
    mergeQueueEntry { id }
  }
}
""".strip()


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
        raise LandingStateError(f"gh {' '.join(arguments)} failed: {detail}")
    return result.stdout


def _json(arguments: Sequence[str]) -> Any:
    try:
        return json.loads(run_gh(arguments))
    except json.JSONDecodeError as exc:
        raise LandingStateError("GitHub returned malformed JSON") from exc


def _positive_number(value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise LandingStateError(f"pull request number is invalid: {value!r}")
    return value


def _validate_rest_pull(
    pull: Any,
    *,
    repository: str,
    branch: str,
    base: str,
    expected_number: int | None,
    expected_head: str | None,
) -> tuple[int, str]:
    if not isinstance(pull, dict):
        raise LandingStateError("GitHub pull response is not an object")
    number = _positive_number(pull.get("number"))
    head = pull.get("head")
    base_value = pull.get("base")
    if not isinstance(head, dict) or not isinstance(base_value, dict):
        raise LandingStateError("GitHub pull response has no head or base object")
    head_repo = head.get("repo")
    if not isinstance(head_repo, dict):
        raise LandingStateError("GitHub pull response has no head repository")
    head_sha = head.get("sha")
    if (
        pull.get("state") != "open"
        or head_repo.get("full_name") != repository
        or head.get("ref") != branch
        or base_value.get("ref") != base
    ):
        raise LandingStateError("pull request is not the exact open first-party wave")
    if not isinstance(head_sha, str) or LOWER_SHA.fullmatch(head_sha) is None:
        raise LandingStateError(f"pull request head is invalid: {head_sha!r}")
    if expected_number is not None and number != expected_number:
        raise LandingStateError(
            f"pull request number moved from {expected_number} to {number}"
        )
    if expected_head is not None and head_sha != expected_head:
        raise LandingStateError(
            f"pull request head moved from {expected_head} to {head_sha}"
        )
    return number, head_sha


def _graphql_pull(repository: str, number: int) -> Any:
    owner, name = repository.split("/", 1)
    response = _json(
        [
            "api",
            "graphql",
            "-f",
            f"query={PULL_QUERY}",
            "-f",
            f"owner={owner}",
            "-f",
            f"name={name}",
            "-F",
            f"number={number}",
        ]
    )
    if not isinstance(response, dict):
        raise LandingStateError("GitHub GraphQL response is not an object")
    data = response.get("data")
    repository_data = data.get("repository") if isinstance(data, dict) else None
    pull = (
        repository_data.get("pullRequest")
        if isinstance(repository_data, dict)
        else None
    )
    if not isinstance(pull, dict):
        raise LandingStateError("GitHub GraphQL response omitted the exact pull request")
    return pull


def _validate_graphql_pull(
    pull: Any,
    *,
    repository: str,
    branch: str,
    base: str,
    expected_number: int,
    expected_head: str,
) -> tuple[str, bool, bool]:
    if not isinstance(pull, dict):
        raise LandingStateError("GitHub GraphQL pull is not an object")
    head_repository = pull.get("headRepository")
    if (
        pull.get("number") != expected_number
        or pull.get("state") != "OPEN"
        or pull.get("headRefName") != branch
        or pull.get("headRefOid") != expected_head
        or pull.get("baseRefName") != base
        or not isinstance(head_repository, dict)
        or head_repository.get("nameWithOwner") != repository
    ):
        raise LandingStateError("GraphQL pull is not the exact open first-party wave")
    pull_id = pull.get("id")
    if not isinstance(pull_id, str) or not pull_id:
        raise LandingStateError("GraphQL pull omitted its node id")
    if "autoMergeRequest" not in pull or "mergeQueueEntry" not in pull:
        raise LandingStateError("GraphQL pull omitted landing-state fields")
    auto_armed = pull["autoMergeRequest"] is not None
    queue_armed = pull["mergeQueueEntry"] is not None
    return pull_id, auto_armed, queue_armed


def _read_state(
    *,
    repository: str,
    number: int,
    branch: str,
    base: str,
    head: str,
) -> tuple[str, bool, bool]:
    return _validate_graphql_pull(
        _graphql_pull(repository, number),
        repository=repository,
        branch=branch,
        base=base,
        expected_number=number,
        expected_head=head,
    )


def ensure_disabled(
    *,
    repository: str,
    branch: str,
    base: str,
    expected_number: int | None = None,
    expected_head: str | None = None,
) -> dict[str, object]:
    if repository.count("/") != 1:
        raise LandingStateError("repository must be owner/name")
    owner = repository.split("/", 1)[0]
    pulls = _json(
        [
            "api",
            "--method",
            "GET",
            f"repos/{repository}/pulls",
            "-f",
            "state=open",
            "-f",
            f"head={owner}:{branch}",
            "-f",
            f"base={base}",
            "-f",
            "per_page=100",
        ]
    )
    if not isinstance(pulls, list):
        raise LandingStateError("GitHub pull listing is not an array")
    if len(pulls) > 1:
        raise LandingStateError(
            f"fixed dependency branch has {len(pulls)} open pull requests"
        )
    if not pulls:
        if expected_number is not None or expected_head is not None:
            raise LandingStateError("expected fixed dependency pull request is missing")
        return {"found": False, "auto_merge": None, "merge_queue_entry": None}

    number, head_sha = _validate_rest_pull(
        pulls[0],
        repository=repository,
        branch=branch,
        base=base,
        expected_number=expected_number,
        expected_head=expected_head,
    )
    pull_id, auto_armed, queue_armed = _read_state(
        repository=repository,
        number=number,
        branch=branch,
        base=base,
        head=head_sha,
    )
    if auto_armed:
        run_gh(
            [
                "pr",
                "merge",
                str(number),
                "--repo",
                repository,
                "--disable-auto",
                "--match-head-commit",
                head_sha,
            ]
        )
        pull_id, auto_armed, queue_armed = _read_state(
            repository=repository,
            number=number,
            branch=branch,
            base=base,
            head=head_sha,
        )
    if queue_armed:
        _json(
            [
                "api",
                "graphql",
                "-f",
                f"query={DEQUEUE_MUTATION}",
                "-f",
                f"id={pull_id}",
            ]
        )
        pull_id, auto_armed, queue_armed = _read_state(
            repository=repository,
            number=number,
            branch=branch,
            base=base,
            head=head_sha,
        )
    if auto_armed or queue_armed:
        raise LandingStateError(
            f"pull request {number} still has server-owned landing state armed"
        )
    return {
        "found": True,
        "number": number,
        "head": head_sha,
        "auto_merge": None,
        "merge_queue_entry": None,
    }


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True)
    parser.add_argument("--branch", required=True)
    parser.add_argument("--base", required=True)
    parser.add_argument("--expected-number", type=int)
    parser.add_argument("--expected-head")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        result = ensure_disabled(
            repository=args.repository,
            branch=args.branch,
            base=args.base,
            expected_number=args.expected_number,
            expected_head=args.expected_head,
        )
    except LandingStateError as exc:
        print(
            f"::error title=Unsafe Kin dependency PR landing state::{exc}",
            file=sys.stderr,
        )
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
