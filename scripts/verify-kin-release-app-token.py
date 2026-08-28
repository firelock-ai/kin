#!/usr/bin/env python3
"""Verify a Kin release App installation token without using GET /user."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from typing import Any, Sequence


EXPECTED_APP_SLUG = "kin-release-bot"
EXPECTED_BOT_LOGIN = "kin-release-bot[bot]"
EXPECTED_BOT_ID = 308181894
EXPECTED_REPOSITORY = "firelock-ai/kin"


class IdentityError(RuntimeError):
    """The token is not the exact repository-scoped Kin release installation."""


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
        raise IdentityError(f"gh {' '.join(arguments)} failed: {detail}")
    return result.stdout


def _json(arguments: Sequence[str]) -> Any:
    try:
        return json.loads(run_gh(arguments))
    except json.JSONDecodeError as exc:
        raise IdentityError("GitHub returned malformed JSON") from exc


def verify_identity(*, app_slug: str, repository: str) -> dict[str, object]:
    if app_slug != EXPECTED_APP_SLUG:
        raise IdentityError(
            f"token action resolved App slug {app_slug!r}, expected {EXPECTED_APP_SLUG!r}"
        )
    if repository != EXPECTED_REPOSITORY:
        raise IdentityError(
            f"token repository is {repository!r}, expected {EXPECTED_REPOSITORY!r}"
        )

    bot = _json(["api", f"users/{EXPECTED_BOT_LOGIN}"])
    if (
        not isinstance(bot, dict)
        or bot.get("id") != EXPECTED_BOT_ID
        or bot.get("login") != EXPECTED_BOT_LOGIN
        or bot.get("type") != "Bot"
    ):
        raise IdentityError("GitHub bot lookup did not resolve the exact release bot")

    installation = _json(
        ["api", "installation/repositories?per_page=100"]
    )
    repositories = (
        installation.get("repositories") if isinstance(installation, dict) else None
    )
    if (
        not isinstance(installation, dict)
        or installation.get("total_count") != 1
        or not isinstance(repositories, list)
        or len(repositories) != 1
        or not isinstance(repositories[0], dict)
        or repositories[0].get("full_name") != repository
    ):
        raise IdentityError(
            "installation token is not scoped to exactly firelock-ai/kin"
        )
    return {
        "app_slug": app_slug,
        "bot_id": EXPECTED_BOT_ID,
        "bot_login": EXPECTED_BOT_LOGIN,
        "repository": repository,
    }


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--app-slug", required=True)
    parser.add_argument("--repository", required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        result = verify_identity(
            app_slug=args.app_slug,
            repository=args.repository,
        )
    except IdentityError as exc:
        print(
            f"::error title=Invalid Kin release App installation token::{exc}",
            file=sys.stderr,
        )
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
