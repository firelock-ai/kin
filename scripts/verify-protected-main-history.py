#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

"""Prove that a workflow's policy commit is protected main's own history.

A queued workflow runs the workflow file and scripts of GITHUB_SHA, the default
branch tip at the moment GitHub created the run. The receiver, the attester and
the wave landing used to require that sha to still EQUAL the tip of main at every
step, which is a property main cannot hold while lanes are landing every few
minutes: four receiver runs failed on 2026-09-02 between 05:30Z and 06:12Z on
"queued receiver policy <sha> is not protected main <sha>" while the branch
moved under them, and the pins only arrived once main happened to stand still.

The property those steps protect is narrower than equality: the policy that runs
must be protected main's, not a branch, a fork or a rewritten ref. That holds
whenever the policy sha is an ancestor of main's current tip, because a commit
that is still reachable from the protected tip cannot have been rewritten, and a
sha that GitHub resolved as the default branch tip cannot be a branch or a fork.
So this module reads the tip, and when the two differ it asks the compare API
for the relation between the policy sha and the tip. `identical` and `ahead`
(the tip is ahead of the policy sha, with nothing behind and the policy sha as
the merge base) are the two shapes that prove ancestry. `behind` and `diverged`
are exactly what a force-push or a wrong branch looks like, and both refuse.

The same proof serves a second question: whether a pull request's base sha is
protected main at or after an admitted base. That is `require_descendant`,
which proves the admitted base is an ancestor of the pull base and the pull base
is an ancestor of the tip.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from typing import Any, Callable, Sequence


LOWER_SHA = re.compile(r"^[0-9a-f]{40}$")
DEFAULT_BRANCH = "main"
# The two compare statuses that prove the compared base is an ancestor of the
# compared head. `behind` and `diverged` are the rewrite and wrong-branch shapes.
ANCESTOR_STATUSES = frozenset({"identical", "ahead"})

Fetch = Callable[[str], Any]
# `fetch` defaults resolve to gh_json at call time rather than at definition
# time, so a caller (or a test) that replaces the module's gh_json is honoured.


class HistoryError(RuntimeError):
    """The policy sha could not be proven to be protected main's history."""


def require_sha(label: str, value: Any) -> str:
    if not isinstance(value, str) or LOWER_SHA.fullmatch(value) is None:
        raise HistoryError(f"{label} must be 40-character lowercase hex, got {value!r}")
    return value


def judge_relation(base: str, head: str, compare: Any) -> dict[str, Any]:
    """Judge one compare document as proof that `base` is an ancestor of `head`.

    Pure: the caller fetched `compare` from `repos/<repo>/compare/<base>...<head>`
    and this decides. Every field the proof rests on is checked, so a truncated
    or malformed answer refuses instead of reading as green.
    """

    base = require_sha("compare base", base)
    head = require_sha("compare head", head)
    if not isinstance(compare, dict):
        raise HistoryError("compare response is not an object")
    status = compare.get("status")
    ahead_by = compare.get("ahead_by")
    behind_by = compare.get("behind_by")
    merge_base = compare.get("merge_base_commit")
    merge_base_sha = merge_base.get("sha") if isinstance(merge_base, dict) else None
    for label, value in (("ahead_by", ahead_by), ("behind_by", behind_by)):
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise HistoryError(f"compare {label} is not a count: {value!r}")
    if status not in ANCESTOR_STATUSES:
        raise HistoryError(
            f"{base} is not protected history of {head}: compare status is "
            f"{status!r} (ahead_by={ahead_by}, behind_by={behind_by})"
        )
    if behind_by != 0:
        raise HistoryError(
            f"{base} is not protected history of {head}: {behind_by} commit(s) "
            "behind, which is what a rewritten ref looks like"
        )
    if status == "identical" and ahead_by != 0:
        raise HistoryError("compare reports identical with a non-zero ahead count")
    if status == "ahead" and ahead_by == 0:
        raise HistoryError("compare reports ahead with a zero ahead count")
    if merge_base_sha != base:
        raise HistoryError(
            f"compare merge base {merge_base_sha!r} is not {base}, so the "
            "ancestry claim does not rest on this sha"
        )
    return {
        "base": base,
        "head": head,
        "relation": "identical" if status == "identical" else "ancestor",
        "ahead_by": ahead_by,
    }


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
        raise HistoryError(f"gh api {endpoint} failed: {detail}")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise HistoryError("GitHub returned malformed JSON") from exc


def _resolve(fetch: Fetch | None) -> Fetch:
    return gh_json if fetch is None else fetch


def read_tip(repository: str, branch: str, fetch: Fetch | None = None) -> str:
    document = _resolve(fetch)(f"repos/{repository}/git/ref/heads/{branch}")
    ref_object = document.get("object") if isinstance(document, dict) else None
    sha = ref_object.get("sha") if isinstance(ref_object, dict) else None
    return require_sha(f"protected {branch} tip", sha)


def prove_ancestor(
    repository: str,
    base: str,
    head: str,
    fetch: Fetch | None = None,
) -> dict[str, Any]:
    """Prove `base` is an ancestor of `head` (or the same commit)."""

    base = require_sha("ancestor", base)
    head = require_sha("descendant", head)
    if base == head:
        return {"base": base, "head": head, "relation": "identical", "ahead_by": 0}
    compare = _resolve(fetch)(f"repos/{repository}/compare/{base}...{head}")
    return judge_relation(base, head, compare)


def require_protected_history(
    repository: str,
    policy_sha: str,
    *,
    branch: str = DEFAULT_BRANCH,
    fetch: Fetch | None = None,
) -> dict[str, Any]:
    """Prove `policy_sha` is the tip of `branch` or reachable from it."""

    policy_sha = require_sha("policy sha", policy_sha)
    tip = read_tip(repository, branch, fetch)
    verdict = prove_ancestor(repository, policy_sha, tip, fetch)
    verdict["branch"] = branch
    verdict["tip"] = tip
    return verdict


def require_descendant(
    repository: str,
    ancestor: str,
    descendant: str,
    *,
    branch: str = DEFAULT_BRANCH,
    fetch: Fetch | None = None,
) -> dict[str, Any]:
    """Prove `descendant` is protected `branch` history at or after `ancestor`."""

    ancestor = require_sha("admitted base", ancestor)
    descendant = require_sha("pull base", descendant)
    forward = prove_ancestor(repository, ancestor, descendant, fetch)
    on_branch = require_protected_history(
        repository, descendant, branch=branch, fetch=fetch
    )
    return {
        "ancestor": ancestor,
        "descendant": descendant,
        "relation": forward["relation"],
        "ahead_by": forward["ahead_by"],
        "branch": branch,
        "tip": on_branch["tip"],
    }


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repository", required=True)
    parser.add_argument(
        "--policy-sha",
        required=True,
        help="the sha whose membership in protected history is being proven",
    )
    parser.add_argument("--branch", default=DEFAULT_BRANCH)
    parser.add_argument(
        "--descendant",
        help=(
            "prove this sha is protected history at or after --policy-sha "
            "instead of proving --policy-sha against the branch tip"
        ),
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    try:
        if args.repository.count("/") != 1:
            raise HistoryError("repository must be owner/name")
        if args.descendant is None:
            verdict = require_protected_history(
                args.repository, args.policy_sha, branch=args.branch
            )
        else:
            verdict = require_descendant(
                args.repository,
                args.policy_sha,
                args.descendant,
                branch=args.branch,
            )
    except HistoryError as exc:
        print(f"::error title=Policy is not protected main history::{exc}", file=sys.stderr)
        return 1
    print(json.dumps(verdict, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
