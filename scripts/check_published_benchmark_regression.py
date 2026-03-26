#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

"""Validate the published validated-popular-repos benchmark baseline.

This CI gate does not try to re-run the assistant-driven live benchmark sweep.
Instead it checks the checked-in benchmark artifact against the published
headline numbers and per-repo invariants so benchmark regressions in the
published baseline are caught automatically.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REPORT = ROOT / ".kin" / "bench" / "popular-validated-20260319-222916.json"

EXPECTED_REPOS = 10
EXPECTED_TASK_COMPARISONS = 70
EXPECTED_NATIVE_WINS = 69
EXPECTED_GIT_TOTAL_S = 1659.666357793
EXPECTED_KIN_NATIVE_TOTAL_S = 829.806541915
EXPECTED_GIT_TOTAL_TOKENS = 5_539_366
EXPECTED_KIN_NATIVE_TOTAL_TOKENS = 3_068_820
EXPECTED_MIN_DURATION_SAVINGS_PCT = 49.0
EXPECTED_MIN_TOKEN_SAVINGS_PCT = 44.0


def fail(message: str) -> int:
    print(f"benchmark regression check failed: {message}", file=sys.stderr)
    return 1


def load_report(path: Path) -> dict:
    if not path.exists():
        raise FileNotFoundError(path)
    return json.loads(path.read_text())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    args = parser.parse_args()

    try:
        report = load_report(args.report)
    except FileNotFoundError:
        return fail(f"report not found: {args.report}")

    repos = report.get("repos") or []
    if len(repos) != EXPECTED_REPOS:
        return fail(f"expected {EXPECTED_REPOS} repos, found {len(repos)}")

    total_task_comparisons = 0
    native_wins = 0
    all_best_native = True
    git_total_s = 0.0
    kin_native_total_s = 0.0
    git_total_tokens = 0
    kin_native_total_tokens = 0

    for repo in repos:
        if repo.get("best_arm") != "kin-native":
            all_best_native = False

        git_total_s += float(repo.get("git_total_s") or 0.0)
        kin_native_total_s += float(repo.get("kin_native_total_s") or 0.0)

        task_results = repo.get("task_results") or {}
        for task_name, runs in task_results.items():
            git = runs.get("git")
            native = runs.get("kin_native")
            if not git or not native:
                return fail(
                    f"repo {repo.get('repo_name')} task {task_name} is missing git or kin_native results"
                )
            total_task_comparisons += 1
            git_total_tokens += int(git.get("tokens") or 0)
            kin_native_total_tokens += int(native.get("tokens") or 0)
            if float(native.get("duration_ms") or 0.0) < float(git.get("duration_ms") or 0.0):
                native_wins += 1

    if total_task_comparisons != EXPECTED_TASK_COMPARISONS:
        return fail(
            f"expected {EXPECTED_TASK_COMPARISONS} task comparisons, found {total_task_comparisons}"
        )

    if native_wins != EXPECTED_NATIVE_WINS:
        return fail(f"expected {EXPECTED_NATIVE_WINS} native wins, found {native_wins}")

    if not all_best_native:
        return fail("at least one repo does not report kin-native as the best arm")

    if not math.isclose(git_total_s, EXPECTED_GIT_TOTAL_S, rel_tol=0.0, abs_tol=0.001):
        return fail(
            f"git total seconds drifted: expected {EXPECTED_GIT_TOTAL_S}, found {git_total_s:.3f}"
        )

    if not math.isclose(
        kin_native_total_s, EXPECTED_KIN_NATIVE_TOTAL_S, rel_tol=0.0, abs_tol=0.001
    ):
        return fail(
            f"kin-native total seconds drifted: expected {EXPECTED_KIN_NATIVE_TOTAL_S}, found {kin_native_total_s:.3f}"
        )

    if git_total_tokens != EXPECTED_GIT_TOTAL_TOKENS:
        return fail(
            f"git token total drifted: expected {EXPECTED_GIT_TOTAL_TOKENS}, found {git_total_tokens}"
        )

    if kin_native_total_tokens != EXPECTED_KIN_NATIVE_TOTAL_TOKENS:
        return fail(
            f"kin-native token total drifted: expected {EXPECTED_KIN_NATIVE_TOTAL_TOKENS}, found {kin_native_total_tokens}"
        )

    duration_savings_pct = (git_total_s - kin_native_total_s) / git_total_s * 100.0
    token_savings_pct = (
        (git_total_tokens - kin_native_total_tokens) / git_total_tokens * 100.0
    )

    if duration_savings_pct < EXPECTED_MIN_DURATION_SAVINGS_PCT:
        return fail(
            f"duration savings below threshold: {duration_savings_pct:.1f}% < {EXPECTED_MIN_DURATION_SAVINGS_PCT:.1f}%"
        )

    if token_savings_pct < EXPECTED_MIN_TOKEN_SAVINGS_PCT:
        return fail(
            f"token savings below threshold: {token_savings_pct:.1f}% < {EXPECTED_MIN_TOKEN_SAVINGS_PCT:.1f}%"
        )

    print("Published benchmark baseline validated:")
    print(f"  Report: {args.report}")
    print(f"  Repos: {len(repos)}")
    print(f"  Task comparisons: {total_task_comparisons}")
    print(f"  Native wins: {native_wins}/{total_task_comparisons}")
    print(f"  Git total: {git_total_s:.3f}s / {git_total_tokens:,} tokens")
    print(f"  Kin-native total: {kin_native_total_s:.3f}s / {kin_native_total_tokens:,} tokens")
    print(f"  Duration savings: {duration_savings_pct:.1f}%")
    print(f"  Token savings: {token_savings_pct:.1f}%")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
