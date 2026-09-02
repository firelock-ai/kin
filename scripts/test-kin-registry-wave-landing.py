#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

"""Deterministic contract tests for the Kin registry wave landing and binding.

Two scripts are under test. `verify-protected-main-history.py` proves a
workflow's policy sha is protected main's history through the compare API, and
`land-kin-registry-wave.py` judges the wave pull request against the fleet's
landing rule from one snapshot document. Both judgments are pure functions, so
every case here is a fixture and a verdict, with no GitHub in the loop. The
workflow contract tests pin the shape of the receiver's binding steps and the
landing workflow's two jobs, because a step that stops calling the proof reads
exactly like one that never needed it.
"""

from __future__ import annotations

import contextlib
import copy
import importlib.util
import io
import itertools
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
HISTORY_PATH = ROOT / "scripts" / "verify-protected-main-history.py"
LANDING_PATH = ROOT / "scripts" / "land-kin-registry-wave.py"
HEAD_GUARD_PATH = ROOT / "scripts" / "verify-kin-registry-wave-head.py"
ATTESTER_PATH = ROOT / "scripts" / "attest-kin-registry-wave.py"
RECEIVER_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "kin-registry-release.yml"
ATTEST_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "kin-registry-release-attest.yml"
LANDING_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "kin-registry-wave-land.yml"
RELEASE_TAG_PATH = ROOT / ".github" / "workflows" / "release-tag.yml"
CI_PATH = ROOT / ".github" / "workflows" / "ci.yml"
REPO = "firelock-ai/kin"
POLICY = "a" * 40
TIP = "b" * 40
HEAD = "c" * 40
BASE = "d" * 40
OTHER = "e" * 40
BETWEEN = "f" * 40


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


history = load_module("kin_wave_history_tests", HISTORY_PATH)
landing = load_module("kin_wave_landing_tests", LANDING_PATH)
head_guard = load_module("kin_wave_head_guard_tests", HEAD_GUARD_PATH)


def run_git(repo: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *arguments],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout.strip()


def manifest(dependency: str = "=0.7.67") -> str:
    return (
        "[workspace]\nmembers = []\n\n[workspace.package]\nversion = \"0.6.1\"\n\n"
        "[workspace.dependencies]\n"
        f'kin-db = {{ version = "{dependency}", registry = "kin" }}\n'
    )


def initialize_repo(repo: Path) -> str:
    run_git(repo, "init", "-q", "-b", "main")
    run_git(repo, "config", "user.name", "Kin Test")
    run_git(repo, "config", "user.email", "kin-test@example.com")
    run_git(repo, "config", "commit.gpgsign", "false")
    run_git(repo, "config", "core.hooksPath", "/dev/null")
    (repo / "Cargo.toml").write_text(manifest(), encoding="utf-8")
    (repo / "Cargo.lock").write_text("version = 4\nkin-db 0.7.67\n", encoding="utf-8")
    (repo / "README.md").write_text("base\n", encoding="utf-8")
    run_git(repo, "add", "-A")
    run_git(repo, "commit", "-q", "-m", "base")
    return run_git(repo, "rev-parse", "HEAD")


def write_pins(repo: Path, dependency: str, lock_version: str) -> None:
    (repo / "Cargo.toml").write_text(manifest(dependency), encoding="utf-8")
    (repo / "Cargo.lock").write_text(
        f"version = 4\nkin-db {lock_version}\n", encoding="utf-8"
    )


def commit_wave(repo: Path, dependency: str = "=0.7.69", lock_version: str = "0.7.69") -> str:
    write_pins(repo, dependency, lock_version)
    run_git(repo, "add", "-A")
    run_git(repo, "commit", "-q", "-m", f"dependency wave\n\n{head_guard.COMMIT_MARKER}")
    return run_git(repo, "rev-parse", "HEAD")


def advance_main(repo: Path, base: str, *, touch_lock: bool = False) -> str:
    run_git(repo, "switch", "-q", "--detach", base)
    (repo / "README.md").write_text("advanced\n", encoding="utf-8")
    if touch_lock:
        (repo / "Cargo.lock").write_text("version = 4\nkin-db 0.7.67\nextra\n", encoding="utf-8")
    run_git(repo, "add", "-A")
    run_git(repo, "commit", "-q", "-m", "advance main")
    return run_git(repo, "rev-parse", "HEAD")


def job_block(workflow: str, job_id: str) -> str:
    match = re.search(
        rf"(?ms)^  {re.escape(job_id)}:\n.*?(?=^  [A-Za-z0-9_-]+:\n|\Z)",
        workflow,
    )
    if match is None:
        raise AssertionError(f"workflow job {job_id!r} is missing")
    return match.group(0)


def step_block(workflow: str, step_name: str) -> str:
    match = re.search(
        rf"(?ms)^      - name: {re.escape(step_name)}\n.*?"
        r"(?=^      - (?:name|uses):|^  [A-Za-z0-9_-]+:\n|\Z)",
        workflow,
    )
    if match is None:
        raise AssertionError(f"workflow step {step_name!r} is missing")
    return match.group(0)


# ---------------------------------------------------------------------------
# Protected-history proof.
# ---------------------------------------------------------------------------


def ref_endpoint(branch: str = "main") -> str:
    return f"repos/{REPO}/git/ref/heads/{branch}"


def compare_endpoint(base: str, head: str) -> str:
    return f"repos/{REPO}/compare/{base}...{head}"


def ref_document(sha: Any) -> dict[str, Any]:
    return {"object": {"sha": sha}}


def compare_document(
    status: Any,
    ahead_by: Any = 0,
    behind_by: Any = 0,
    *,
    merge_base: Any = POLICY,
) -> dict[str, Any]:
    return {
        "status": status,
        "ahead_by": ahead_by,
        "behind_by": behind_by,
        "merge_base_commit": {"sha": merge_base},
    }


class Fetch:
    """Serve fixture documents by endpoint and record every read."""

    def __init__(self, answers: dict[str, Any]) -> None:
        self.answers = answers
        self.calls: list[str] = []

    def __call__(self, endpoint: str) -> Any:
        self.calls.append(endpoint)
        if endpoint not in self.answers:
            raise AssertionError(f"unexpected GitHub read: {endpoint}")
        return copy.deepcopy(self.answers[endpoint])


class ProtectedHistoryTests(unittest.TestCase):
    def test_identical_tip_is_proven_without_a_compare(self) -> None:
        fetch = Fetch({ref_endpoint(): ref_document(POLICY)})
        verdict = history.require_protected_history(REPO, POLICY, fetch=fetch)
        self.assertEqual(verdict["relation"], "identical")
        self.assertEqual(verdict["tip"], POLICY)
        self.assertEqual(fetch.calls, [ref_endpoint()])

    def test_tip_ahead_of_the_policy_is_protected_history(self) -> None:
        fetch = Fetch(
            {
                ref_endpoint(): ref_document(TIP),
                compare_endpoint(POLICY, TIP): compare_document("ahead", 3),
            }
        )
        verdict = history.require_protected_history(REPO, POLICY, fetch=fetch)
        self.assertEqual(verdict["relation"], "ancestor")
        self.assertEqual(verdict["ahead_by"], 3)
        self.assertEqual(verdict["tip"], TIP)
        self.assertEqual(fetch.calls, [ref_endpoint(), compare_endpoint(POLICY, TIP)])

    def test_behind_and_diverged_are_rewrites_and_refuse(self) -> None:
        for status, behind in (("behind", 2), ("diverged", 1)):
            with self.subTest(status=status):
                fetch = Fetch(
                    {
                        ref_endpoint(): ref_document(TIP),
                        compare_endpoint(POLICY, TIP): compare_document(status, 0, behind),
                    }
                )
                with self.assertRaisesRegex(history.HistoryError, status):
                    history.require_protected_history(REPO, POLICY, fetch=fetch)

    def test_ahead_with_a_foreign_merge_base_refuses(self) -> None:
        fetch = Fetch(
            {
                ref_endpoint(): ref_document(TIP),
                compare_endpoint(POLICY, TIP): compare_document(
                    "ahead", 1, merge_base=OTHER
                ),
            }
        )
        with self.assertRaisesRegex(history.HistoryError, "merge base"):
            history.require_protected_history(REPO, POLICY, fetch=fetch)

    def test_ahead_with_a_behind_count_refuses(self) -> None:
        fetch = Fetch(
            {
                ref_endpoint(): ref_document(TIP),
                compare_endpoint(POLICY, TIP): compare_document("ahead", 1, 1),
            }
        )
        with self.assertRaisesRegex(history.HistoryError, "behind"):
            history.require_protected_history(REPO, POLICY, fetch=fetch)

    def test_malformed_compare_answers_refuse(self) -> None:
        cases = {
            "not an object": ["ahead"],
            "count": compare_document("ahead", "3"),
            "status": compare_document(None, 1),
            "identical": compare_document("identical", 1),
            "zero ahead": compare_document("ahead", 0),
        }
        for label, document in cases.items():
            with self.subTest(label=label):
                with self.assertRaisesRegex(history.HistoryError, label):
                    history.judge_relation(POLICY, TIP, document)

    def test_malformed_shas_refuse(self) -> None:
        fetch = Fetch({ref_endpoint(): ref_document("not-a-sha")})
        with self.assertRaisesRegex(history.HistoryError, "tip must be"):
            history.require_protected_history(REPO, POLICY, fetch=fetch)
        with self.assertRaisesRegex(history.HistoryError, "policy sha must be"):
            history.require_protected_history(REPO, "abc", fetch=fetch)

    def test_descendant_needs_both_the_forward_and_the_branch_proof(self) -> None:
        on_branch = Fetch(
            {
                compare_endpoint(POLICY, BETWEEN): compare_document("ahead", 1),
                ref_endpoint(): ref_document(TIP),
                compare_endpoint(BETWEEN, TIP): compare_document(
                    "ahead", 2, merge_base=BETWEEN
                ),
            }
        )
        verdict = history.require_descendant(REPO, POLICY, BETWEEN, fetch=on_branch)
        self.assertEqual(verdict["relation"], "ancestor")
        self.assertEqual(verdict["tip"], TIP)
        self.assertEqual(
            on_branch.calls,
            [
                compare_endpoint(POLICY, BETWEEN),
                ref_endpoint(),
                compare_endpoint(BETWEEN, TIP),
            ],
        )

        off_branch = Fetch(
            {
                compare_endpoint(POLICY, BETWEEN): compare_document("ahead", 1),
                ref_endpoint(): ref_document(TIP),
                compare_endpoint(BETWEEN, TIP): compare_document(
                    "diverged", 2, 1, merge_base=POLICY
                ),
            }
        )
        with self.assertRaisesRegex(history.HistoryError, "diverged"):
            history.require_descendant(REPO, POLICY, BETWEEN, fetch=off_branch)

        not_forward = Fetch(
            {
                compare_endpoint(POLICY, BETWEEN): compare_document("behind", 0, 1),
            }
        )
        with self.assertRaisesRegex(history.HistoryError, "behind"):
            history.require_descendant(REPO, POLICY, BETWEEN, fetch=not_forward)

        same = Fetch({ref_endpoint(): ref_document(POLICY)})
        verdict = history.require_descendant(REPO, POLICY, POLICY, fetch=same)
        self.assertEqual(verdict["relation"], "identical")

    def test_cli_exit_codes_follow_the_proof(self) -> None:
        quiet = contextlib.ExitStack()
        quiet.enter_context(contextlib.redirect_stdout(io.StringIO()))
        quiet.enter_context(contextlib.redirect_stderr(io.StringIO()))
        self.addCleanup(quiet.close)
        green = Fetch(
            {
                ref_endpoint(): ref_document(TIP),
                compare_endpoint(POLICY, TIP): compare_document("ahead", 1),
            }
        )
        with mock.patch.object(history, "gh_json", side_effect=green):
            self.assertEqual(
                history.main(["--repository", REPO, "--policy-sha", POLICY]), 0
            )
        red = Fetch(
            {
                ref_endpoint(): ref_document(TIP),
                compare_endpoint(POLICY, TIP): compare_document("diverged", 1, 1),
            }
        )
        with mock.patch.object(history, "gh_json", side_effect=red):
            self.assertEqual(
                history.main(["--repository", REPO, "--policy-sha", POLICY]), 1
            )
        with mock.patch.object(history, "gh_json", side_effect=green):
            self.assertEqual(
                history.main(
                    ["--repository", "not-a-repository", "--policy-sha", POLICY]
                ),
                1,
            )


# ---------------------------------------------------------------------------
# Wave landing judgment.
# ---------------------------------------------------------------------------


_ids = itertools.count(1000)
EARLY = "2026-09-02T09:20:00Z"
LATE = "2026-09-02T09:31:00Z"


def check_run(
    name: str,
    conclusion: str | None = "success",
    *,
    status: str = "completed",
    started: str = LATE,
    app: str = "github-actions",
) -> dict[str, Any]:
    return {
        "id": next(_ids),
        "name": name,
        "status": status,
        "conclusion": conclusion,
        "started_at": started,
        "completed_at": started if conclusion else None,
        "head_sha": HEAD,
        "app": {"slug": app},
    }


EXTRA_GREEN_NAMES = (
    "Check & Test (ubuntu-latest)",
    "Windows installer + vector release build",
    "CodeQL",
)


def green_runs() -> list[dict[str, Any]]:
    runs = [check_run(name) for name in landing.RULESET_REQUIRED_CONTEXTS]
    runs.extend(check_run(name) for name in EXTRA_GREEN_NAMES)
    runs.append(check_run("Product Acceptance", "skipped"))
    runs.append(check_run("Code Coverage", "neutral"))
    return runs


def pages(runs: list[dict[str, Any]], total: int | None = None) -> list[dict[str, Any]]:
    return [{"total_count": len(runs) if total is None else total, "check_runs": runs}]


def bot_commit(
    sha: str = HEAD,
    *,
    login: str = landing.BOT_LOGIN,
    user_id: int = landing.BOT_ID,
    email: str = landing.BOT_EMAIL,
    marker_count: int = 1,
) -> dict[str, Any]:
    message = "chore(deps): refresh Kin registry pins after kin-db@0.7.85\n\n"
    message += "".join(f"{landing.COMMIT_MARKER}\n" for _ in range(marker_count))
    message += f"Signed-off-by: {landing.BOT_LOGIN} <{landing.BOT_EMAIL}>\n"
    return {
        "sha": sha,
        "author": {"login": login, "id": user_id},
        "committer": {"login": login, "id": user_id},
        "commit": {
            "author": {"email": email},
            "committer": {"email": email},
            "message": message,
        },
    }


def wave_file(name: str, status: str = "modified") -> dict[str, Any]:
    return {"filename": name, "status": status}


def wave_pull(**overrides: Any) -> dict[str, Any]:
    pull: dict[str, Any] = {
        "number": 1360,
        "state": "open",
        "draft": False,
        "merged_at": None,
        "auto_merge": None,
        "mergeable": True,
        "mergeable_state": "clean",
        "commits": 1,
        "changed_files": 2,
        "title": "chore(deps): refresh Kin registry pins after kin-db@0.7.85",
        "body": (
            "Automated Kin registry dependency wave.\n\n"
            "This PR updates the allowed root-manifest registry pins."
        ),
        "user": {"login": landing.APP_LOGIN, "id": landing.APP_ID, "type": "Bot"},
        "head": {"sha": HEAD, "ref": landing.WAVE_BRANCH, "repo": {"full_name": REPO}},
        "base": {"sha": BASE, "ref": "main"},
    }
    pull.update(overrides)
    return pull


def green_snapshot(**overrides: Any) -> dict[str, Any]:
    snapshot: dict[str, Any] = {
        "freeze": "",
        "open_pulls": [{"number": 1360}],
        "pull": wave_pull(),
        "branch_tip": HEAD,
        "commits": [bot_commit()],
        "files": [wave_file("Cargo.toml"), wave_file("Cargo.lock")],
        "check_run_pages": pages(green_runs()),
        "pins_on_main": {"tip": BASE, "changed": ["Cargo.lock", "Cargo.toml"]},
        "attestation": landing.ATTESTATION_VERIFIED,
    }
    snapshot.update(overrides)
    return snapshot


class WaveJudgeTests(unittest.TestCase):
    def assertVerdict(
        self,
        snapshot: dict[str, Any],
        decision: str,
        reason: str,
    ) -> landing.Verdict:
        verdict = landing.judge(snapshot)
        self.assertEqual(
            (verdict.decision, decision),
            (decision, decision),
            f"expected {decision}, got {verdict.decision}: {verdict.reason}",
        )
        self.assertRegex(verdict.reason, reason)
        return verdict

    def test_all_green_lands(self) -> None:
        verdict = self.assertVerdict(green_snapshot(), landing.LAND, "concluded green")
        self.assertEqual(verdict.pull, 1360)
        self.assertEqual(verdict.head, HEAD)
        self.assertEqual(verdict.details["pending"], [])
        self.assertEqual(verdict.details["failed"], [])
        self.assertEqual(verdict.details["base"], BASE)

    def test_one_failure_refuses(self) -> None:
        runs = green_runs() + [check_run("cargo-fuzz (parse_adapter)", "failure")]
        verdict = self.assertVerdict(
            green_snapshot(check_run_pages=pages(runs)),
            landing.REFUSE,
            r"checks failed: cargo-fuzz \(parse_adapter\)=failure",
        )
        self.assertEqual(verdict.pull, 1360)
        for conclusion in ("timed_out", "action_required", "stale", "startup_failure"):
            with self.subTest(conclusion=conclusion):
                runs = green_runs() + [check_run("Linux Daemon Smoke", conclusion)]
                self.assertVerdict(
                    green_snapshot(check_run_pages=pages(runs)),
                    landing.REFUSE,
                    f"checks failed: Linux Daemon Smoke={conclusion}",
                )

    def test_cancelled_by_a_repush_waits_instead_of_failing(self) -> None:
        # The receiver's re-push cancels the superseded suite and the attester's
        # reopen retrigger does the same; on 2026-09-02 a judgment read
        # "Fast gate lint and policy=cancelled" and painted the workflow red for
        # a check nothing could have kept green. It is a wait, and transient.
        runs = green_runs() + [check_run("Fast gate lint and policy", "cancelled", started="2026-09-02T09:40:00Z")]
        verdict = self.assertVerdict(
            green_snapshot(check_run_pages=pages(runs)),
            landing.WAIT,
            "checks cancelled, awaiting the rerun a re-push or reopen triggers: Fast gate lint and policy",
        )
        self.assertTrue(verdict.transient)
        self.assertEqual(verdict.details["cancelled"], ["Fast gate lint and policy"])

    def test_a_repushed_head_waits_for_the_next_pass(self) -> None:
        verdict = self.assertVerdict(
            green_snapshot(branch_tip=OTHER),
            landing.WAIT,
            f"the wave moved: origin/{landing.WAVE_BRANCH} is at {OTHER}, not the pull head {HEAD}",
        )
        self.assertTrue(verdict.transient)
        verdict = self.assertVerdict(
            green_snapshot(branch_tip=None), landing.WAIT, "no readable"
        )
        self.assertTrue(verdict.transient)

    def test_one_pending_waits(self) -> None:
        runs = green_runs() + [check_run("Linux Daemon Smoke", None, status="in_progress")]
        self.assertVerdict(
            green_snapshot(check_run_pages=pages(runs)),
            landing.WAIT,
            "checks still running: Linux Daemon Smoke",
        )
        runs = green_runs() + [check_run("Linux Daemon Smoke", None, status="queued")]
        self.assertVerdict(
            green_snapshot(check_run_pages=pages(runs)),
            landing.WAIT,
            "checks still running: Linux Daemon Smoke",
        )

    def test_incomplete_listing_refuses(self) -> None:
        runs = green_runs()
        self.assertVerdict(
            green_snapshot(check_run_pages=pages(runs, total=len(runs) + 5)),
            landing.REFUSE,
            f"incomplete: {len(runs)} listed of {len(runs) + 5} reported",
        )
        two_pages = [
            {"total_count": len(runs), "check_runs": runs[:3]},
            {"total_count": len(runs) + 1, "check_runs": runs[3:]},
        ]
        self.assertVerdict(
            green_snapshot(check_run_pages=two_pages),
            landing.REFUSE,
            "disagree on total_count",
        )
        self.assertVerdict(
            green_snapshot(check_run_pages=[]), landing.REFUSE, "empty or not a list"
        )
        self.assertVerdict(
            green_snapshot(check_run_pages=[{"total_count": 1}]),
            landing.REFUSE,
            "lacks total_count or check_runs",
        )

    def test_paged_listing_that_adds_up_lands(self) -> None:
        runs = green_runs()
        two_pages = [
            {"total_count": len(runs), "check_runs": runs[:4]},
            {"total_count": len(runs), "check_runs": runs[4:]},
        ]
        self.assertVerdict(
            green_snapshot(check_run_pages=two_pages), landing.LAND, "concluded green"
        )

    def test_non_bot_commit_refuses(self) -> None:
        human = bot_commit(login="troyjr4103", user_id=63249686)
        self.assertVerdict(
            green_snapshot(commits=[human]),
            landing.REFUSE,
            "pull commit author is not github-actions",
        )
        bot_by_login_only = bot_commit(user_id=1)
        self.assertVerdict(
            green_snapshot(commits=[bot_by_login_only]),
            landing.REFUSE,
            "pull commit author is not github-actions",
        )
        foreign_email = bot_commit(email="someone@example.com")
        self.assertVerdict(
            green_snapshot(commits=[foreign_email]),
            landing.REFUSE,
            "git author email is not the bot",
        )

    def test_marker_must_appear_exactly_once(self) -> None:
        for count in (0, 2):
            with self.subTest(count=count):
                self.assertVerdict(
                    green_snapshot(commits=[bot_commit(marker_count=count)]),
                    landing.REFUSE,
                    f"reserved marker {count} times",
                )

    def test_second_commit_refuses(self) -> None:
        snapshot = green_snapshot(
            commits=[bot_commit(sha=OTHER), bot_commit()],
            pull=wave_pull(commits=2),
        )
        self.assertVerdict(snapshot, landing.REFUSE, "exactly one")
        snapshot = green_snapshot(commits=[bot_commit(sha=OTHER)])
        self.assertVerdict(snapshot, landing.REFUSE, "is not the head")

    def test_off_scope_file_refuses(self) -> None:
        files = [wave_file("Cargo.toml"), wave_file("Cargo.lock"), wave_file("README.md")]
        self.assertVerdict(
            green_snapshot(files=files, pull=wave_pull(changed_files=3)),
            landing.REFUSE,
            "touches 'README.md', outside the receiver's write set",
        )
        self.assertVerdict(
            green_snapshot(files=files),
            landing.REFUSE,
            "reports 2 changed files, 3 listed",
        )
        added = [wave_file("Cargo.toml"), wave_file("Cargo.lock", "added")]
        self.assertVerdict(
            green_snapshot(files=added), landing.REFUSE, "the receiver only modifies"
        )
        renamed = [wave_file("Cargo.toml"), {**wave_file("Cargo.lock"), "previous_filename": "x"}]
        self.assertVerdict(
            green_snapshot(files=renamed), landing.REFUSE, "the receiver only modifies"
        )

    def test_superseded_cancelled_suite_lands_on_the_newest_run(self) -> None:
        # The attester's close-and-reopen retrigger leaves the first CI suite
        # cancelled beside the green one: kin#1360's head carried 87 check-runs
        # in exactly this shape. Newest per name is the fleet's rule.
        runs = green_runs()
        runs.append(check_run("Fast gate build and tests", "cancelled", started=EARLY))
        runs.append(check_run("Fast gate lint and policy", "cancelled", started=EARLY))
        self.assertVerdict(
            green_snapshot(check_run_pages=pages(runs)), landing.LAND, "concluded green"
        )

    def test_newer_failure_after_an_older_success_refuses(self) -> None:
        runs = green_runs()
        runs.append(check_run("cargo-deny", "failure", started="2026-09-02T09:40:00Z"))
        self.assertVerdict(
            green_snapshot(check_run_pages=pages(runs)),
            landing.REFUSE,
            "checks failed: cargo-deny=failure",
        )

    def test_missing_required_context_waits(self) -> None:
        runs = [run for run in green_runs() if run["name"] != "cargo-deny"]
        self.assertVerdict(
            green_snapshot(check_run_pages=pages(runs)),
            landing.WAIT,
            "required contexts not yet reported: cargo-deny",
        )

    def test_empty_check_set_never_lands(self) -> None:
        self.assertVerdict(
            green_snapshot(check_run_pages=pages([])),
            landing.WAIT,
            "required contexts not yet reported",
        )

    def test_freeze_holds_every_landing(self) -> None:
        verdict = self.assertVerdict(
            green_snapshot(freeze="release window, captain holds main"),
            landing.WAIT,
            "frozen by KIN_MAIN_FROZEN: release window",
        )
        self.assertIsNone(verdict.pull)
        self.assertVerdict(green_snapshot(freeze="   "), landing.LAND, "concluded green")

    def test_no_wave_waits_and_two_waves_refuse(self) -> None:
        self.assertVerdict(green_snapshot(open_pulls=[]), landing.WAIT, "no open pull")
        self.assertVerdict(
            green_snapshot(open_pulls=[{"number": 1360}, {"number": 1361}]),
            landing.REFUSE,
            "2 open pull requests",
        )
        self.assertVerdict(
            green_snapshot(open_pulls={"number": 1360}), landing.REFUSE, "not an array"
        )

    def test_pull_identity_refusals(self) -> None:
        cases = {
            "not open": wave_pull(state="closed"),
            "draft": wave_pull(draft=True),
            "auto-merge armed": wave_pull(auto_merge={"enabled_by": {"login": "x"}}),
            "omitted server-side auto-merge": {
                key: value for key, value in wave_pull().items() if key != "auto_merge"
            },
            "is not automation/kin-registry-dependency-wave": wave_pull(
                head={"sha": HEAD, "ref": "chore/lane-x", "repo": {"full_name": REPO}}
            ),
            "not first-party": wave_pull(
                head={"sha": HEAD, "ref": landing.WAVE_BRANCH, "repo": {"full_name": "fork/kin"}}
            ),
            "base ref 'release' is not main": wave_pull(base={"sha": BASE, "ref": "release"}),
            "not opened by the release App": wave_pull(
                user={"login": "troyjr4103", "id": 63249686, "type": "User"}
            ),
            "moved from 1360": wave_pull(number=1359),
            "already carries a merge": wave_pull(merged_at="2026-09-02T10:00:00Z"),
        }
        for reason, pull in cases.items():
            with self.subTest(reason=reason):
                self.assertVerdict(green_snapshot(pull=pull), landing.REFUSE, re.escape(reason))

    def test_pins_already_on_main_are_a_final_no_op(self) -> None:
        # kin#1384 landed =0.7.88 by hand at 16:28Z while #1360 carried the same
        # delta: nothing to merge, never an empty squash, never a red run.
        verdict = self.assertVerdict(
            green_snapshot(pins_on_main={"tip": OTHER, "changed": []}),
            landing.WAIT,
            f"pins are already on main at {OTHER}; nothing to merge",
        )
        self.assertFalse(verdict.transient)
        self.assertEqual((verdict.pull, verdict.head), (1360, HEAD))
        self.assertVerdict(
            green_snapshot(pins_on_main=None), landing.REFUSE, "pin comparison against main is unreadable"
        )
        self.assertVerdict(
            green_snapshot(pins_on_main={"tip": OTHER, "changed": ["Cargo.lock"]}),
            landing.LAND,
            "concluded green",
        )

    def test_pins_on_main_reads_the_workspace_tip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            base = initialize_repo(repo)
            head = commit_wave(repo)
            run_git(repo, "switch", "-q", "--detach", base)
            self.assertEqual(
                landing.pins_on_main(repo, head),
                {"tip": base, "changed": ["Cargo.lock", "Cargo.toml"]},
            )
            run_git(repo, "switch", "-q", "--detach", head)
            self.assertEqual(landing.pins_on_main(repo, head), {"tip": head, "changed": []})

    def test_transient_and_final_waits_are_told_apart(self) -> None:
        transient = (
            green_snapshot(check_run_pages=pages(green_runs() + [check_run("x", None, status="queued")])),
            green_snapshot(pull=wave_pull(mergeable_state="unknown")),
            green_snapshot(attestation=landing.ATTESTATION_PENDING),
            green_snapshot(check_run_pages=pages([run for run in green_runs() if run["name"] != "cargo-deny"])),
        )
        for snapshot in transient:
            verdict = landing.judge(snapshot)
            self.assertEqual(verdict.decision, landing.WAIT, verdict.reason)
            self.assertTrue(verdict.transient, verdict.reason)
        for snapshot in (green_snapshot(freeze="hold"), green_snapshot(open_pulls=[])):
            verdict = landing.judge(snapshot)
            self.assertEqual(verdict.decision, landing.WAIT, verdict.reason)
            self.assertFalse(verdict.transient, verdict.reason)

    def test_conflict_refuses_and_a_settling_state_waits(self) -> None:
        self.assertVerdict(
            green_snapshot(pull=wave_pull(mergeable=False, mergeable_state="dirty")),
            landing.REFUSE,
            "'dirty'",
        )
        for state in ("unknown", "blocked", "behind"):
            with self.subTest(state=state):
                self.assertVerdict(
                    green_snapshot(pull=wave_pull(mergeable_state=state)),
                    landing.WAIT,
                    f"mergeable_state '{state}'",
                )
        self.assertVerdict(
            green_snapshot(pull=wave_pull(mergeable=None, mergeable_state="clean")),
            landing.WAIT,
            "mergeable_state",
        )

    def test_attestation_pending_waits_and_refused_refuses(self) -> None:
        self.assertVerdict(
            green_snapshot(attestation=landing.ATTESTATION_PENDING),
            landing.WAIT,
            "attestation for this head has not arrived",
        )
        self.assertVerdict(
            green_snapshot(attestation="refused: dependency head tree differs"),
            landing.REFUSE,
            "attestation: refused: dependency head tree differs",
        )

    def test_squash_message_never_carries_the_marker(self) -> None:
        title, message = landing.compose_squash_message(wave_pull())
        self.assertEqual(
            title, "chore(deps): refresh Kin registry pins after kin-db@0.7.85 (#1360)"
        )
        self.assertNotIn(landing.COMMIT_MARKER, message)
        self.assertNotIn(landing.COMMIT_MARKER, title)
        self.assertIn("Automated Kin registry dependency wave.", message)
        body_with_marker = wave_pull(body=f"Automated wave.\n\n{landing.COMMIT_MARKER}\n")
        with self.assertRaisesRegex(landing.LandingError, "reserved dependency-wave marker"):
            landing.compose_squash_message(body_with_marker)
        self.assertVerdict(
            green_snapshot(pull=body_with_marker),
            landing.REFUSE,
            "reserved dependency-wave marker",
        )
        co_authored = wave_pull(body="wave\n\nCo-authored-by: github-actions[bot] <x@y>")
        with self.assertRaisesRegex(landing.LandingError, "Co-authored-by"):
            landing.compose_squash_message(co_authored)
        _, empty = landing.compose_squash_message(wave_pull(body=None))
        self.assertEqual(empty, "")

    def test_judge_fixture_cli_reports_the_verdict_and_exit_code(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / "green.json"
            fixture.write_text(json.dumps(green_snapshot()), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(LANDING_PATH), "judge-fixture", "--fixture", str(fixture)],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["decision"], landing.LAND)

            red = Path(directory) / "red.json"
            runs = green_runs() + [check_run("cargo-deny", "failure")]
            red.write_text(
                json.dumps(green_snapshot(check_run_pages=pages(runs))), encoding="utf-8"
            )
            result = subprocess.run(
                [sys.executable, str(LANDING_PATH), "judge-fixture", "--fixture", str(red)],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 1)
            self.assertEqual(json.loads(result.stdout)["decision"], landing.REFUSE)
            self.assertIn("::error title=Kin registry wave refused::", result.stderr)

            waiting = Path(directory) / "wait.json"
            waiting.write_text(json.dumps(green_snapshot(open_pulls=[])), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(LANDING_PATH), "judge-fixture", "--fixture", str(waiting)],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["decision"], landing.WAIT)
            self.assertIn("::notice::wave landing waits", result.stderr)

    def test_land_refuses_when_the_wave_moved_since_judgment(self) -> None:
        stdout = io.StringIO()
        with mock.patch.object(landing, "gather", return_value=green_snapshot()):
            with mock.patch.dict("os.environ", {"KIN_LAND_TOKEN": "t"}), \
                    contextlib.redirect_stdout(stdout), \
                    contextlib.redirect_stderr(io.StringIO()):
                code = landing.main(
                    [
                        "land",
                        "--repository",
                        REPO,
                        "--workspace",
                        ".",
                        "--pull",
                        "1360",
                        "--head",
                        OTHER,
                        "--merge-token-env",
                        "KIN_LAND_TOKEN",
                    ]
                )
        self.assertEqual(code, 0)
        verdict = json.loads(stdout.getvalue())
        self.assertEqual(verdict["decision"], landing.WAIT)
        self.assertIn("moved since it was judged", verdict["reason"])

    def test_land_squashes_only_the_judged_head_and_proves_it_landed(self) -> None:
        merged = "9" * 40
        calls: list[tuple[list[str], str | None]] = []

        def fake_gh(arguments: list[str], *, token: str | None = None) -> Any:
            calls.append((list(arguments), token))
            endpoint = next((item for item in arguments if item.startswith("repos/")), "")
            if endpoint.endswith("/merge"):
                return {"merged": True, "sha": merged, "message": "Pull Request successfully merged"}
            if endpoint == f"repos/{REPO}/pulls/1360":
                return {"merged": True, "merge_commit_sha": merged}
            if endpoint == ref_endpoint():
                return ref_document(merged)
            raise AssertionError(f"unexpected GitHub call: {arguments}")

        with mock.patch.object(landing, "gh_json", side_effect=fake_gh):
            landed = landing.squash(REPO, wave_pull(), HEAD, merge_token="app-token")
        self.assertEqual(landed["merged_sha"], merged)
        merge_call = next(args for args, _ in calls if any(a.endswith("/merge") for a in args))
        merge_token = next(token for args, token in calls if any(a.endswith("/merge") for a in args))
        self.assertEqual(merge_token, "app-token")
        self.assertIn("merge_method=squash", merge_call)
        self.assertIn(f"sha={HEAD}", merge_call)
        self.assertTrue(any(a.startswith("commit_title=") and a.endswith("(#1360)") for a in merge_call))
        self.assertFalse(any(landing.COMMIT_MARKER in a for a in merge_call))

        def disagreeing_gh(arguments: list[str], *, token: str | None = None) -> Any:
            endpoint = next((item for item in arguments if item.startswith("repos/")), "")
            if endpoint.endswith("/merge"):
                return {"merged": True, "sha": merged}
            if endpoint == f"repos/{REPO}/pulls/1360":
                return {"merged": True, "merge_commit_sha": OTHER}
            raise AssertionError(f"unexpected GitHub call: {arguments}")

        with mock.patch.object(landing, "gh_json", side_effect=disagreeing_gh):
            with self.assertRaisesRegex(landing.LandingError, "does not carry the squash"):
                landing.squash(REPO, wave_pull(), HEAD, merge_token="app-token")

    def test_ruleset_contexts_are_names_this_repository_produces(self) -> None:
        # The six live ruleset contexts have to be display names some workflow
        # here publishes, or the landing waits forever on a name nobody
        # produces. The mint's RULESET_REQUIRED_CHECKS mirror is a different
        # reviewed list (a superset of its release-critical set) and predates
        # the fast-gate contexts, so the producers are the authority here.
        produced: set[str] = set()
        for workflow in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
            produced.update(
                re.findall(r"(?m)^    name: (.+?)\s*$", workflow.read_text(encoding="utf-8"))
            )
        missing = sorted(set(landing.RULESET_REQUIRED_CONTEXTS) - produced)
        self.assertEqual(missing, [], f"no workflow job publishes {missing}")
        self.assertEqual(len(landing.RULESET_REQUIRED_CONTEXTS), 6)
        release_tag = RELEASE_TAG_PATH.read_text(encoding="utf-8")
        mint_required = re.search(
            r"(?m)^          REQUIRED_CHECKS: \|\n((?:            .+\n)+)", release_tag
        )
        self.assertIsNotNone(mint_required, "release-tag.yml no longer declares REQUIRED_CHECKS")
        mint = {line.strip() for line in mint_required.group(1).splitlines() if line.strip()}
        # Every context the mint vetoes on that a pull request produces is
        # also one the landing insists on; the rest of the mint's set is
        # main-push evidence the wave head cannot carry.
        for context in ("DCO Sign-off", "cargo-deny", "gitleaks (full history)"):
            self.assertIn(context, mint)
            self.assertIn(context, landing.RULESET_REQUIRED_CONTEXTS)

    def test_allowed_paths_are_exactly_the_receivers_write_set(self) -> None:
        writer = step_block(
            RECEIVER_WORKFLOW_PATH.read_text(encoding="utf-8"),
            "Open or update the dependency bump PR",
        )
        match = re.search(r"(?m)add-paths: \|\n((?:            .+\n)+)", writer)
        self.assertIsNotNone(match)
        written = {line.strip() for line in match.group(1).splitlines() if line.strip()}
        self.assertEqual(written, set(landing.ALLOWED_PATHS))


class WaitLoopTests(unittest.TestCase):
    def _loop(self, snapshots: list[dict[str, Any]], budget: int) -> tuple[Any, list[float], int]:
        supplied = list(snapshots)
        gathers = 0
        slept: list[float] = []
        clock = {"now": 0.0}

        def fake_gather(repository: str, workspace: Path, freeze: str) -> dict[str, Any]:
            nonlocal gathers
            gathers += 1
            return supplied.pop(0) if len(supplied) > 1 else supplied[0]

        def fake_sleep(seconds: float) -> None:
            slept.append(seconds)
            clock["now"] += seconds

        with contextlib.redirect_stderr(io.StringIO()):
            verdict, _ = landing.judge_with_wait(
                REPO,
                Path("."),
                "",
                wait_seconds=budget,
                gather_snapshot=fake_gather,
                sleep=fake_sleep,
                clock=lambda: clock["now"],
            )
        return verdict, slept, gathers

    def test_a_transient_wait_is_re_read_until_it_lands(self) -> None:
        pending = green_snapshot(check_run_pages=pages(green_runs() + [check_run("x", None, status="queued")]))
        verdict, slept, gathers = self._loop([pending, pending, green_snapshot()], 600)
        self.assertEqual(verdict.decision, landing.LAND)
        self.assertEqual(gathers, 3)
        self.assertEqual(slept, [30.0, 30.0])
        self.assertEqual(verdict.details["passes"], 3)

    def test_the_budget_bounds_the_wait(self) -> None:
        pending = green_snapshot(check_run_pages=pages(green_runs() + [check_run("x", None, status="queued")]))
        verdict, slept, gathers = self._loop([pending], 45)
        self.assertEqual(verdict.decision, landing.WAIT)
        self.assertEqual(slept, [30.0, 15.0])
        self.assertEqual(gathers, 3)
        verdict, slept, gathers = self._loop([pending], 0)
        self.assertEqual((verdict.decision, slept, gathers), (landing.WAIT, [], 1))

    def test_a_hold_and_a_refusal_return_at_once(self) -> None:
        verdict, slept, gathers = self._loop([green_snapshot(freeze="hold")], 600)
        self.assertEqual((verdict.decision, slept, gathers), (landing.WAIT, [], 1))
        red = green_snapshot(check_run_pages=pages(green_runs() + [check_run("cargo-deny", "failure")]))
        verdict, slept, gathers = self._loop([red], 600)
        self.assertEqual((verdict.decision, slept, gathers), (landing.REFUSE, [], 1))

    def test_a_repush_during_the_wait_is_judged_on_the_new_head(self) -> None:
        moved = green_snapshot(branch_tip=OTHER)
        verdict, slept, gathers = self._loop([moved, green_snapshot()], 600)
        self.assertEqual(verdict.decision, landing.LAND)
        self.assertEqual(gathers, 2)


def trigger_context(**overrides: Any) -> dict[str, Any]:
    context: dict[str, Any] = {
        "event_name": "repository_dispatch",
        "event_action": landing.KICK_ACTION,
        "actor": "troyjr4103",
        "repository": REPO,
        "default_branch": "main",
        "ref": "refs/heads/main",
        "workflow_sha": POLICY,
        "event": {"action": landing.KICK_ACTION, "client_payload": {"reason": "captain kick"}},
    }
    context.update(overrides)
    return context


def completion_event(**overrides: Any) -> dict[str, Any]:
    run: dict[str, Any] = {
        "name": "CI",
        "status": "completed",
        "conclusion": "success",
        "head_branch": landing.WAVE_BRANCH,
        "head_sha": HEAD,
        "head_repository": {"full_name": REPO},
    }
    run.update(overrides)
    return {"action": "completed", "workflow_run": run}


class TriggerValidationTests(unittest.TestCase):
    def test_kick_from_each_allowed_actor_is_admitted(self) -> None:
        for actor in sorted(landing.KICK_ACTORS):
            with self.subTest(actor=actor):
                verdict = landing.validate_trigger(**trigger_context(actor=actor))
                self.assertEqual(verdict["trigger"], landing.TRIGGER_KICK)
                self.assertEqual(verdict["reason"], "captain kick")
        bare = landing.validate_trigger(**trigger_context(event={"action": landing.KICK_ACTION}))
        self.assertEqual(bare["reason"], "")

    def test_kick_refusals(self) -> None:
        cases = {
            "may not kick": trigger_context(actor="outsider"),
            "event action must be": trigger_context(event_action="release_tag", event={"action": "release_tag"}),
            "differs from the trigger context": trigger_context(event={"action": "other"}),
            "workflow ref must be": trigger_context(ref="refs/heads/feature"),
            "default branch must be": trigger_context(default_branch="develop"),
            "repository must be": trigger_context(repository="fork/kin"),
            "workflow sha must be": trigger_context(workflow_sha="abc"),
            "a reason and nothing else": trigger_context(
                event={"action": landing.KICK_ACTION, "client_payload": {"reason": "x", "sha": POLICY}}
            ),
            "at most 200 characters": trigger_context(
                event={"action": landing.KICK_ACTION, "client_payload": {"reason": "r" * 201}}
            ),
        }
        for message, context in cases.items():
            with self.subTest(message=message):
                with self.assertRaisesRegex(landing.LandingError, message):
                    landing.validate_trigger(**context)

    def test_wave_completion_is_admitted_and_others_refused(self) -> None:
        verdict = landing.validate_trigger(
            **trigger_context(event_name="workflow_run", event_action="completed", actor="anyone", event=completion_event())
        )
        self.assertEqual(verdict["trigger"], landing.TRIGGER_COMPLETION)
        self.assertEqual(verdict["workflow"], "CI")
        cases = {
            "is not the wave": completion_event(head_branch="main"),
            "not first-party": completion_event(head_repository={"full_name": "fork/kin"}),
            "is not completed": completion_event(status="in_progress"),
            "omitted its run": {"action": "completed"},
        }
        for message, event in cases.items():
            with self.subTest(message=message):
                with self.assertRaisesRegex(landing.LandingError, message):
                    landing.validate_trigger(
                        **trigger_context(event_name="workflow_run", event_action="completed", actor="anyone", event=event)
                    )
        with self.assertRaisesRegex(landing.LandingError, "must be 'completed'"):
            landing.validate_trigger(
                **trigger_context(event_name="workflow_run", event_action="requested", actor="anyone", event=completion_event())
            )

    def test_sweep_and_unknown_events(self) -> None:
        verdict = landing.validate_trigger(
            **trigger_context(event_name="schedule", event_action="", actor="anyone", event={"schedule": "5,20,35,50 * * * *"})
        )
        self.assertEqual(verdict["trigger"], landing.TRIGGER_SWEEP)
        with self.assertRaisesRegex(landing.LandingError, "scheduled event action must be empty"):
            landing.validate_trigger(
                **trigger_context(event_name="schedule", event_action="x", actor="anyone", event={})
            )
        with self.assertRaisesRegex(landing.LandingError, "event name must be"):
            landing.validate_trigger(**trigger_context(event_name="workflow_dispatch", event={}))

    def test_cli_exit_codes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            event_path = Path(directory) / "event.json"
            event_path.write_text(json.dumps({"action": landing.KICK_ACTION}), encoding="utf-8")
            base = [
                sys.executable, str(LANDING_PATH), "validate-trigger",
                "--event-file", str(event_path), "--event-name", "repository_dispatch",
                "--event-action", landing.KICK_ACTION, "--repository", REPO,
                "--default-branch", "main", "--ref", "refs/heads/main", "--workflow-sha", POLICY,
            ]
            ok = subprocess.run(base + ["--actor", "kin-release-bot[bot]"], text=True, capture_output=True, check=False)
            self.assertEqual(ok.returncode, 0, ok.stderr)
            self.assertEqual(json.loads(ok.stdout)["trigger"], landing.TRIGGER_KICK)
            refused = subprocess.run(base + ["--actor", "outsider"], text=True, capture_output=True, check=False)
            self.assertEqual(refused.returncode, 1)
            self.assertIn("::error title=Kin registry wave trigger refused::", refused.stderr)


class AdmittedHeadTests(unittest.TestCase):
    def test_unmoved_main_is_the_old_equality(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            base = initialize_repo(repo)
            head = commit_wave(repo)
            admitted = head_guard.validate_delta(repo, base, head, require_marker=True)
            evidence = head_guard.validate_admitted_head(repo, base, admitted.tree, head, require_marker=True)
            self.assertEqual((evidence.base, evidence.admitted_base, evidence.tree), (base, base, admitted.tree))
            self.assertEqual(evidence.delta_sha256, admitted.delta_sha256)
            with self.assertRaisesRegex(head_guard.AdmissionError, "not the admitted"):
                head_guard.validate_admitted_head(repo, base, "0" * 40, head, require_marker=True)

    def test_a_head_rebased_onto_a_moved_main_carries_the_admitted_delta(self) -> None:
        # The pull-request action rebases the wave onto main's tip. kin#1360's
        # head a45f85aae had parent a6852aa04, not the writing run's policy
        # eeae72729, and the tree comparison refused it after the push.
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            base = initialize_repo(repo)
            admitted_head = commit_wave(repo)
            admitted = head_guard.validate_delta(repo, base, admitted_head, require_marker=True)
            tip = advance_main(repo, base)
            run_git(repo, "cherry-pick", admitted_head)
            rebased = run_git(repo, "rev-parse", "HEAD")
            self.assertEqual(head_guard.first_parent(repo, rebased), tip)
            self.assertNotEqual(run_git(repo, "rev-parse", f"{rebased}^{{tree}}"), admitted.tree)
            evidence = head_guard.validate_admitted_head(repo, base, admitted.tree, rebased, require_marker=True)
            self.assertEqual((evidence.base, evidence.admitted_base, evidence.head), (tip, base, rebased))
            self.assertEqual(evidence.delta_sha256, admitted.delta_sha256)
            self.assertEqual(evidence.paths, head_guard.ALLOWED_PATHS)
            with self.assertRaisesRegex(head_guard.AdmissionError, "does not descend"):
                head_guard.validate_admitted_head(repo, admitted_head, admitted.tree, rebased, require_marker=True)

    def test_main_touching_the_pin_files_refuses_the_rebuild(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            base = initialize_repo(repo)
            admitted_head = commit_wave(repo)
            admitted = head_guard.validate_delta(repo, base, admitted_head, require_marker=True)
            advance_main(repo, base, touch_lock=True)
            rebuilt = commit_wave(repo)
            with self.assertRaisesRegex(head_guard.AdmissionError, "changed admitted dependency paths"):
                head_guard.validate_admitted_head(repo, base, admitted.tree, rebuilt, require_marker=True)

    def test_a_different_delta_on_the_moved_main_is_not_the_admitted_tree(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            base = initialize_repo(repo)
            admitted_head = commit_wave(repo)
            admitted = head_guard.validate_delta(repo, base, admitted_head, require_marker=True)
            advance_main(repo, base)
            other = commit_wave(repo, dependency="=0.7.70", lock_version="0.7.70")
            with self.assertRaisesRegex(head_guard.AdmissionError, "not the admitted"):
                head_guard.validate_admitted_head(repo, base, admitted.tree, other, require_marker=True)

    def test_a_foreign_parent_refuses(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            base = initialize_repo(repo)
            admitted_head = commit_wave(repo)
            admitted = head_guard.validate_delta(repo, base, admitted_head, require_marker=True)
            run_git(repo, "switch", "-q", "--orphan", "unrelated")
            (repo / "Cargo.toml").write_text(manifest(), encoding="utf-8")
            (repo / "Cargo.lock").write_text("version = 4\nkin-db 0.7.67\n", encoding="utf-8")
            (repo / "README.md").write_text("unrelated\n", encoding="utf-8")
            run_git(repo, "add", "-A")
            run_git(repo, "commit", "-q", "-m", "unrelated root")
            foreign = commit_wave(repo)
            with self.assertRaisesRegex(head_guard.AdmissionError, "does not descend"):
                head_guard.validate_admitted_head(repo, base, admitted.tree, foreign, require_marker=True)

    def test_generated_head_cli(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            base = initialize_repo(repo)
            admitted_head = commit_wave(repo)
            admitted = head_guard.validate_delta(repo, base, admitted_head, require_marker=True)
            tip = advance_main(repo, base)
            run_git(repo, "cherry-pick", admitted_head)
            rebased = run_git(repo, "rev-parse", "HEAD")
            command = [
                sys.executable, str(HEAD_GUARD_PATH), "verify-generated-head",
                "--workspace", str(repo), "--pull", "77", "--head", rebased,
                "--admitted-base", base, "--expected-tree", admitted.tree,
            ]
            ok = subprocess.run(command, text=True, capture_output=True, check=False)
            self.assertEqual(ok.returncode, 0, ok.stderr)
            document = json.loads(ok.stdout)
            self.assertEqual((document["parent"], document["admitted_base"]), (tip, base))
            self.assertEqual(document["tree"], run_git(repo, "rev-parse", f"{rebased}^{{tree}}"))
            command[-1] = "0" * 40
            refused = subprocess.run(command, text=True, capture_output=True, check=False)
            self.assertEqual(refused.returncode, 1)
            self.assertIn("not the admitted delta", refused.stderr)


# ---------------------------------------------------------------------------
# Workflow contracts.
# ---------------------------------------------------------------------------


HISTORY_CALL = "python3 scripts/verify-protected-main-history.py"


class ReceiverBindingContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = RECEIVER_WORKFLOW_PATH.read_text(encoding="utf-8")
        cls.disarm_job = job_block(cls.workflow, "disarm-wave")
        cls.prepare_job = job_block(cls.workflow, "prepare-wave")
        cls.mutation_job = job_block(cls.workflow, "mutate-wave")

    def test_every_binding_proves_ancestry_instead_of_equality(self) -> None:
        policy_steps = (
            "Bind early disarm to the queued workflow policy",
            "Refuse protected-main rewrite before early-disarm token mint",
            "Bind preparation to the queued workflow policy",
            "Rebind the fresh mutation runner to queued policy",
        )
        admitted_steps = (
            "Refuse protected-main rewrite immediately before token mint",
            "Refuse protected-main rewrite before repository mutation",
        )
        for name in policy_steps:
            block = step_block(self.workflow, name)
            self.assertIn(HISTORY_CALL, block, name)
            self.assertIn('--policy-sha "$GITHUB_SHA"', block, name)
            self.assertIn('--branch "$BASE_BRANCH"', block, name)
        for name in admitted_steps:
            block = step_block(self.workflow, name)
            self.assertIn(HISTORY_CALL, block, name)
            self.assertIn('--policy-sha "$ADMITTED_BASE"', block, name)
        for name in ("Bind early disarm to the queued workflow policy",
                     "Bind preparation to the queued workflow policy",
                     "Rebind the fresh mutation runner to queued policy"):
            self.assertIn('echo "base_sha=$GITHUB_SHA"', step_block(self.workflow, name))
        # The one equality that stays: the mutation runner must be the admitted
        # base. Main's tip is never compared to github.sha by equality again.
        self.assertEqual(self.workflow.count('!= "$GITHUB_SHA"'), 1)
        self.assertIn(
            '[ "$ADMITTED_BASE" != "$GITHUB_SHA" ]',
            step_block(self.workflow, "Rebind the fresh mutation runner to queued policy"),
        )
        self.assertNotIn("protected-main movement", self.workflow)
        self.assertNotIn("git/ref/heads/${BASE_BRANCH}", self.workflow)

    def test_checkout_precedes_each_binding(self) -> None:
        pairs = (
            (self.disarm_job, "Checkout exact policy for early disarm",
             "Bind early disarm to the queued workflow policy"),
            (self.prepare_job, "Checkout exact queued protected main",
             "Bind preparation to the queued workflow policy"),
            (self.mutation_job, "Checkout exact protected main for trusted mutation code",
             "Rebind the fresh mutation runner to queued policy"),
        )
        for job, checkout, binding in pairs:
            self.assertLess(job.index(f"- name: {checkout}"), job.index(f"- name: {binding}"))
            self.assertIn("ref: ${{ github.sha }}", step_block(self.workflow, checkout))
            self.assertIn("persist-credentials: false", step_block(self.workflow, checkout))

    def test_generated_pull_base_is_proven_a_descendant(self) -> None:
        verifier = step_block(self.workflow, "Verify exact first-party generated PR")
        self.assertIn(HISTORY_CALL, verifier)
        self.assertIn('--policy-sha "$ADMITTED_BASE"', verifier)
        self.assertIn('--descendant "$(jq -r .base.sha <<<"$pull")"', verifier)
        self.assertNotIn('.base.sha <<<"$pull")" != "$ADMITTED_BASE"', verifier)

    def test_generated_head_is_proven_locally_not_compared_by_tree(self) -> None:
        verifier = step_block(self.workflow, "Verify exact first-party generated PR")
        self.assertIn("verify-kin-registry-wave-head.py verify-generated-head", verifier)
        self.assertIn('--admitted-base "$ADMITTED_BASE"', verifier)
        self.assertIn('--expected-tree "$EXPECTED_TREE"', verifier)
        self.assertIn('--head "$api_head"', verifier)
        self.assertIn('--pull "$PR"', verifier)
        self.assertIn('[ "$(jq -r .tree <<<"$verified")" != "$api_tree" ]', verifier)
        self.assertNotIn('[ "$api_tree" != "$EXPECTED_TREE" ]', verifier)

    def test_receiver_kicks_the_judge_once_after_writing(self) -> None:
        kick = step_block(self.workflow, "Kick the wave landing judge once")
        self.assertIn("if: needs.prepare-wave.outputs.changed == 'true'", kick)
        self.assertIn("GH_TOKEN: ${{ steps.app-token.outputs.token }}", kick)
        self.assertIn("-f event_type=kin-registry-wave-land", kick)
        self.assertIn("client_payload[reason]=receiver run", kick)
        self.assertEqual(
            self.mutation_job.rfind("- name:"),
            self.mutation_job.index("- name: Kick the wave landing judge once"),
        )
        self.assertLess(
            self.mutation_job.index("- name: Upload exact result for the post-completion attester"),
            self.mutation_job.index("- name: Kick the wave landing judge once"),
        )

    def test_attester_and_gate_accept_a_descendant_base(self) -> None:
        attester = ATTESTER_PATH.read_text(encoding="utf-8")
        self.assertIn('SCRIPT_DIR / "verify-protected-main-history.py"', attester)
        self.assertIn("history.require_protected_history(", attester)
        self.assertIn("history.require_descendant(", attester)
        self.assertNotIn("protected main moved after the completed receiver", attester)
        self.assertNotIn('base.get("sha") != admission["base"]', attester)
        guard = HEAD_GUARD_PATH.read_text(encoding="utf-8")
        self.assertIn("is_ancestor(workspace, base, expected_base)", guard)
        self.assertIn("ensure_commit(workspace, expected_base)", guard)
        self.assertNotIn("is not current pull base", guard)
        self.assertIn("is_ancestor(workspace, admitted.base, base)", guard)


class LandingWorkflowContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = LANDING_WORKFLOW_PATH.read_text(encoding="utf-8")
        cls.judge_job = job_block(cls.workflow, "judge-wave")
        cls.land_job = job_block(cls.workflow, "land-wave")

    def test_triggers_are_the_wave_ci_the_kick_and_the_sweep(self) -> None:
        trigger = self.workflow.split("\njobs:", 1)[0]
        self.assertIn("workflow_run:", trigger)
        self.assertIn("workflows: [CI]", trigger)
        self.assertIn("types: [completed]", trigger)
        self.assertIn("branches: [automation/kin-registry-dependency-wave]", trigger)
        for workflow in ("SAST", "Secret Scan", "DCO", "PR Text Hygiene", "CodeQL", "Fuzz"):
            self.assertNotIn(f"- {workflow}\n", trigger)
        self.assertIn("repository_dispatch:", trigger)
        self.assertIn("types: [kin-registry-wave-land]", trigger)
        self.assertIn('cron: "5,20,35,50 * * * *"', trigger)
        self.assertNotIn("workflow_dispatch", self.workflow)
        self.assertNotIn("pull_request", trigger)
        self.assertRegex(trigger, r"(?m)^permissions:\n  contents: read$")

    def test_trigger_is_validated_before_anything_reads_the_wave(self) -> None:
        validate = step_block(self.workflow, "Validate the landing trigger")
        self.assertIn("land-kin-registry-wave.py validate-trigger", validate)
        for argument in (
            '--event-file "$GITHUB_EVENT_PATH"',
            '--event-name "$GITHUB_EVENT_NAME"',
            '--event-action "$EVENT_ACTION"',
            '--actor "$GITHUB_ACTOR"',
            '--default-branch "$DEFAULT_BRANCH"',
            '--ref "$GITHUB_REF"',
            '--workflow-sha "$GITHUB_SHA"',
        ):
            self.assertIn(argument, validate)
        self.assertNotIn("GH_TOKEN", validate)
        self.assertIn("github.event_name == 'repository_dispatch'", self.judge_job)
        order = [
            self.judge_job.index(f"- name: {name}")
            for name in (
                "Checkout the queued landing policy",
                "Validate the landing trigger",
                "Bind the judgment to protected main history",
                "Judge the wave against its full check set",
            )
        ]
        self.assertEqual(order, sorted(order))
        judge = step_block(self.workflow, "Judge the wave against its full check set")
        self.assertIn("--wait-seconds 1500", judge)
        self.assertIn("timeout-minutes: 40", self.judge_job)
        source = LANDING_PATH.read_text(encoding="utf-8")
        self.assertIn('KICK_ACTION = "kin-registry-wave-land"', source)
        self.assertIn('KICK_ACTORS = frozenset({"troyjr4103", "kin-release-bot[bot]"})', source)

    def test_judge_reads_only_the_wave_and_binds_to_protected_history(self) -> None:
        self.assertIn(
            "github.event.workflow_run.head_branch == 'automation/kin-registry-dependency-wave'",
            self.judge_job,
        )
        self.assertIn(
            "github.event.workflow_run.head_repository.full_name == github.repository",
            self.judge_job,
        )
        self.assertIn("github.event_name == 'schedule'", self.judge_job)
        self.assertIn("cancel-in-progress: false", self.judge_job)
        self.assertIn("kin-registry-wave-judge-${{ github.repository }}", self.judge_job)
        self.assertIn("checks: read", self.judge_job)
        self.assertNotIn("write", self.judge_job)
        self.assertNotIn("environment:", self.judge_job)
        self.assertNotIn("create-github-app-token", self.judge_job)
        self.assertIn("KIN_MAIN_FROZEN: ${{ vars.KIN_MAIN_FROZEN }}", self.judge_job)
        bind = step_block(self.workflow, "Bind the judgment to protected main history")
        self.assertIn(HISTORY_CALL, bind)
        self.assertIn('--policy-sha "$GITHUB_SHA"', bind)
        judge = step_block(self.workflow, "Judge the wave against its full check set")
        self.assertIn("land-kin-registry-wave.py judge", judge)
        self.assertIn('--freeze "$KIN_MAIN_FROZEN"', judge)
        self.assertIn("GH_TOKEN: ${{ github.token }}", judge)
        checkout = step_block(self.workflow, "Checkout the queued landing policy")
        self.assertIn("ref: ${{ github.sha }}", checkout)
        self.assertIn("persist-credentials: false", checkout)
        self.assertIn("fetch-depth: 0", checkout)
        self.assertIn("decision: ${{ steps.judge.outputs.decision || 'wait' }}", self.judge_job)

    def test_land_runs_only_on_a_land_verdict_through_the_release_app(self) -> None:
        self.assertIn("needs: judge-wave", self.land_job)
        self.assertIn("if: needs.judge-wave.outputs.decision == 'land'", self.land_job)
        self.assertIn("environment: release-tag", self.land_job)
        self.assertIn("kin-registry-wave-land-${{ github.repository }}", self.land_job)
        self.assertIn("cancel-in-progress: false", self.land_job)
        token = step_block(self.workflow, "Mint repository-scoped landing token")
        self.assertIn("permission-contents: write", token)
        self.assertIn("permission-pull-requests: write", token)
        self.assertNotIn("permission-issues", token)
        self.assertNotIn("permission-actions", token)
        self.assertNotIn("permission-statuses", token)
        identity = step_block(self.workflow, "Verify exact landing App identity and scope")
        self.assertIn("verify-kin-release-app-token.py", identity)
        squash = step_block(self.workflow, "Squash the green wave onto protected main")
        self.assertIn("land-kin-registry-wave.py land", squash)
        self.assertIn("--merge-token-env KIN_LAND_TOKEN", squash)
        self.assertIn("KIN_LAND_TOKEN: ${{ steps.app-token.outputs.token }}", squash)
        self.assertIn("GH_TOKEN: ${{ github.token }}", squash)
        self.assertIn('--pull "$JUDGED_PULL"', squash)
        self.assertIn('--head "$JUDGED_HEAD"', squash)
        self.assertIn('--freeze "$KIN_MAIN_FROZEN"', squash)
        bind = step_block(self.workflow, "Bind the landing to protected main history")
        self.assertIn(HISTORY_CALL, bind)
        self.assertIn('[[ ! "$JUDGED_PULL" =~ ^[1-9][0-9]*$ ]]', bind)
        self.assertIn('[[ ! "$JUDGED_HEAD" =~ ^[0-9a-f]{40}$ ]]', bind)
        order = [
            self.land_job.index(f"- name: {name}")
            for name in (
                "Checkout the queued landing policy for the merge",
                "Bind the landing to protected main history",
                "Mint repository-scoped landing token",
                "Verify exact landing App identity and scope",
                "Squash the green wave onto protected main",
            )
        ]
        self.assertEqual(order, sorted(order))
        self.assertNotIn("gh pr merge", self.workflow)
        self.assertNotIn("--auto", self.workflow)

    def test_ci_runs_this_test(self) -> None:
        ci = CI_PATH.read_text(encoding="utf-8")
        self.assertIn("python3 ./scripts/test-kin-registry-wave-landing.py", ci)


if __name__ == "__main__":
    unittest.main()
