#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

"""Deterministic contract tests for the automatic release-candidate selection.

`scripts/select-release-candidate.py` decides which main commit the proof loop
proves next, and both of its judgments are pure functions over one snapshot, so
every case here is a fixture and a verdict with no GitHub in the loop. The
fixtures are shaped on real listings read on 2026-09-02:

  * 57228997f carried three check-runs per required name, because a CI push run
    was rerun to attempt 3, and a second `gitleaks (full history)` produced by a
    push to the candidate branch. That sha is what taught the fleet that a rerun
    is what makes a sha unmintable, whatever the copies concluded.
  * 59c2239c2's `Windows installer + vector release build` concluded cancelled
    at the 60-minute job cap while Acceptance passed, so a red required context
    has to disqualify a sha its Acceptance run says nothing about.
  * 390fbdc54 carried every required context exactly once and became v0.6.4.

The workflow contract tests pin the shape of release-cut.yml, because a step
that stops calling the selector reads exactly like one that never needed it.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SELECTOR_PATH = ROOT / "scripts" / "select-release-candidate.py"
CUT_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "release-cut.yml"
RELEASE_TAG_PATH = ROOT / ".github" / "workflows" / "release-tag.yml"
RC_BUILD_PATH = ROOT / ".github" / "workflows" / "rc-build.yml"
REPO = "firelock-ai/kin"
VERSION = "0.6.5"
NEWEST = "a" * 40
MIDDLE = "b" * 40
OLDEST = "c" * 40
FOREIGN = "d" * 40
CI_SUITE = 91_000_000_001
ACCEPTANCE_SUITE = 91_000_000_002
SAST_SUITE = 91_000_000_003
SECRET_SUITE = 91_000_000_004
CI_RUN = 33_000_000_001
ACCEPTANCE_RUN = 33_000_000_002
SAST_RUN = 33_000_000_003
SECRET_RUN = 33_000_000_004


def job_block(source: str, job: str) -> str:
    """One job's own YAML, from its two-space key to the next one.

    Both workflows carry more than one `artifact:` matrix, so a whole-file
    search reads rows from a job the assertion is not about: rc-build.yml's
    capability matrix carries a windows row the build matrix deliberately does
    not. Slicing by job is what keeps a contract test honest about its subject.
    """

    match = re.search(rf"(?ms)^  {re.escape(job)}:\n(.*?)(?=^  [a-z][a-z0-9_-]*:\n|\Z)", source)
    if match is None:
        raise AssertionError(f"no job named {job} in this workflow")
    return match.group(1)


def matrix_artifacts(block: str) -> list[str]:
    return re.findall(r"(?m)^ +artifact: ([A-Za-z0-9._-]+)$", block)


def job_names(source: str) -> list[str]:
    return re.findall(r"(?m)^  ([a-z][a-z0-9_-]*):\n", source)


def job_needs(block: str) -> list[str]:
    match = re.search(r"(?m)^    needs: (.+)$", block)
    if match is None:
        return []
    value = match.group(1).strip()
    if value.startswith("["):
        return [name.strip() for name in value.strip("[]").split(",") if name.strip()]
    return [value]


def job_if(block: str) -> str:
    """The job-level `if`, block scalar or inline, flattened to one line."""

    match = re.search(r"(?m)^    if: (.*)$", block)
    if match is None:
        return ""
    first = match.group(1).strip()
    if not first.startswith(">-") and not first.startswith("|"):
        return first
    body = block.split(match.group(0), 1)[1].splitlines()
    lines = []
    for line in body:
        if not line.strip():
            continue
        if not line.startswith("      "):
            break
        if line.strip().startswith("#"):
            continue
        lines.append(line.strip())
    return " ".join(lines)


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


selector = load_module("kin_release_candidate_selector", SELECTOR_PATH)


# ---------------------------------------------------------------------------
# Fixture builders for the two listings the grader reads.
# ---------------------------------------------------------------------------


def check_run(
    name: str,
    *,
    suite: int,
    status: str = "completed",
    conclusion: str | None = "success",
    app: tuple[int, str] = selector.GITHUB_ACTIONS_APP,
) -> dict[str, Any]:
    return {
        "name": name,
        "status": status,
        "conclusion": conclusion,
        "check_suite": {"id": suite},
        "app": {"id": app[0], "slug": app[1]},
    }


def workflow_run(
    path: str,
    *,
    run_id: int,
    suite: int,
    sha: str,
    workflow_id: int,
    event: str = "push",
    branch: str = "main",
    status: str = "completed",
    conclusion: str | None = "success",
) -> dict[str, Any]:
    return {
        "id": run_id,
        "workflow_id": workflow_id,
        "path": path,
        "event": event,
        "head_branch": branch,
        "head_sha": sha,
        "status": status,
        "conclusion": conclusion,
        "check_suite_id": suite,
    }


def pages(items: list[dict[str, Any]], key: str, total: int | None = None) -> list[dict[str, Any]]:
    return [{"total_count": len(items) if total is None else total, key: items}]


def green_checks(sha: str = NEWEST) -> list[dict[str, Any]]:
    suites = {
        ".github/workflows/ci.yml": CI_SUITE,
        ".github/workflows/sast.yml": SAST_SUITE,
        ".github/workflows/secret-scan.yml": SECRET_SUITE,
    }
    runs = []
    for name, _workflow_id, path in selector.REQUIRED_CONTEXTS:
        conclusion = "skipped" if name in selector.SKIPPABLE_REQUIRED else "success"
        runs.append(check_run(name, suite=suites[path], conclusion=conclusion))
    return runs


def green_workflow_runs(sha: str = NEWEST) -> list[dict[str, Any]]:
    return [
        workflow_run(".github/workflows/ci.yml", run_id=CI_RUN, suite=CI_SUITE, sha=sha, workflow_id=245803170),
        workflow_run(
            ".github/workflows/acceptance.yml",
            run_id=ACCEPTANCE_RUN,
            suite=ACCEPTANCE_SUITE,
            sha=sha,
            workflow_id=339594603,
        ),
        workflow_run(".github/workflows/sast.yml", run_id=SAST_RUN, suite=SAST_SUITE, sha=sha, workflow_id=251549972),
        workflow_run(
            ".github/workflows/secret-scan.yml",
            run_id=SECRET_RUN,
            suite=SECRET_SUITE,
            sha=sha,
            workflow_id=293452372,
        ),
    ]


def grade_pages(checks: list[dict[str, Any]], runs: list[dict[str, Any]]) -> dict[str, Any]:
    return {"check_runs": pages(checks, "check_runs"), "workflow_runs": pages(runs, "workflow_runs")}


def green_grade(sha: str = NEWEST) -> dict[str, Any]:
    return grade_pages(green_checks(sha), green_workflow_runs(sha))


def with_duplicate(grade: dict[str, Any], name: str, suite: int) -> dict[str, Any]:
    """Append a second check-run under one required name, total_count included.

    The total has to move with it. `flatten_pages` asserts the listed length
    against `total_count` precisely so a short page cannot read as a sha with
    fewer checks, and a fixture that appends without bumping the total tests
    that assertion rather than the duplication it meant to test.
    """

    grade = copy.deepcopy(grade)
    page = grade["check_runs"][0]
    page["check_runs"].append(check_run(name, suite=suite))
    page["total_count"] = len(page["check_runs"])
    return grade


def rc_build(
    sha: str,
    *,
    run_id: int = 34_000_000_001,
    status: str = "completed",
    conclusion: str | None = "success",
    artifacts: list[str] | None = None,
    created_at: str = "2026-09-02T20:00:00Z",
) -> dict[str, Any]:
    if artifacts is None:
        artifacts = list(selector.RC_BUILD_ARTIFACTS)
    return {
        "id": run_id,
        "head_sha": sha,
        "head_branch": selector.candidate_branch(VERSION),
        "event": "workflow_dispatch",
        "status": status,
        "conclusion": conclusion,
        "created_at": created_at,
        "artifacts": sorted(artifacts),
    }


def snapshot(**overrides: Any) -> dict[str, Any]:
    document = {
        "repository": REPO,
        "version": VERSION,
        "range": [NEWEST, MIDDLE, OLDEST],
        "tag_exists": False,
        "evidence": {},
        "candidate": None,
        "rc_builds": [],
    }
    document.update(overrides)
    return document


class Grader:
    """Serve a grade per sha and record which shas were actually graded."""

    def __init__(self, grades: dict[str, dict[str, Any]]) -> None:
        self.grades = grades
        self.calls: list[str] = []

    def __call__(self, sha: str) -> dict[str, Any]:
        self.calls.append(sha)
        if sha not in self.grades:
            raise AssertionError(f"unexpected grading of {sha}")
        return selector.grade_sha(sha, self.grades[sha]["check_runs"], self.grades[sha]["workflow_runs"])


# ---------------------------------------------------------------------------
# Grading one sha.
# ---------------------------------------------------------------------------


class GradeShaTests(unittest.TestCase):
    def grade(self, checks: list[dict[str, Any]], runs: list[dict[str, Any]], sha: str = NEWEST) -> dict[str, Any]:
        return selector.grade_sha(sha, pages(checks, "check_runs"), pages(runs, "workflow_runs"))

    def test_green_sha(self) -> None:
        verdict = self.grade(green_checks(), green_workflow_runs())
        self.assertEqual(verdict["verdict"], selector.GREEN, verdict)
        self.assertEqual(verdict["dead"], [])
        self.assertEqual(verdict["pending"], [])

    def test_a_rerun_duplicating_one_required_context_is_dead(self) -> None:
        """57228997f: a rerun claims the name twice and the mint calls that ambiguous."""

        checks = green_checks()
        checks.append(check_run("Falsify guards", suite=CI_SUITE))
        verdict = self.grade(checks, green_workflow_runs())
        self.assertEqual(verdict["verdict"], selector.DEAD)
        self.assertTrue(
            any("ambiguous required check: Falsify guards" in line for line in verdict["dead"]),
            verdict["dead"],
        )

    def test_a_red_required_context_is_dead(self) -> None:
        """59c2239c2: the Windows leg was cancelled at the job cap."""

        checks = [
            check_run(name, suite=CI_SUITE, conclusion="cancelled")
            if name == "Windows installer + vector release build"
            else run
            for name, run in ((entry["name"], entry) for entry in green_checks())
        ]
        verdict = self.grade(checks, green_workflow_runs())
        self.assertEqual(verdict["verdict"], selector.DEAD)
        self.assertIn(
            "required check not green: Windows installer + vector release build (conclusion=cancelled)",
            verdict["dead"],
        )

    def test_a_running_required_context_is_pending_not_dead(self) -> None:
        checks = green_checks()
        checks[0] = check_run(checks[0]["name"], suite=CI_SUITE, status="in_progress", conclusion=None)
        verdict = self.grade(checks, green_workflow_runs())
        self.assertEqual(verdict["verdict"], selector.PENDING)
        self.assertTrue(any("not completed" in line for line in verdict["pending"]))

    def test_a_missing_required_context_is_dead_once_its_producer_finished(self) -> None:
        checks = [entry for entry in green_checks() if entry["name"] != "cargo-deny"]
        verdict = self.grade(checks, green_workflow_runs())
        self.assertEqual(verdict["verdict"], selector.DEAD)
        self.assertTrue(any("missing required check: cargo-deny" in line for line in verdict["dead"]))

    def test_a_missing_required_context_waits_while_its_producer_runs(self) -> None:
        checks = [entry for entry in green_checks() if entry["name"] != "cargo-deny"]
        runs = [
            workflow_run(
                ".github/workflows/sast.yml",
                run_id=SAST_RUN,
                suite=SAST_SUITE,
                sha=NEWEST,
                workflow_id=251549972,
                status="in_progress",
                conclusion=None,
            )
            if run["path"] == ".github/workflows/sast.yml"
            else run
            for run in green_workflow_runs()
        ]
        verdict = self.grade(checks, runs)
        self.assertEqual(verdict["verdict"], selector.PENDING)

    def test_dco_may_be_skipped_but_nothing_else_may(self) -> None:
        checks = green_checks()
        for entry in checks:
            if entry["name"] == "Falsify guards":
                entry["conclusion"] = "skipped"
        verdict = self.grade(checks, green_workflow_runs())
        self.assertEqual(verdict["verdict"], selector.DEAD)
        self.assertTrue(any("Falsify guards" in line for line in verdict["dead"]))

    def test_a_red_ci_push_run_is_dead_even_with_green_contexts(self) -> None:
        runs = [
            workflow_run(
                ".github/workflows/ci.yml",
                run_id=CI_RUN,
                suite=CI_SUITE,
                sha=NEWEST,
                workflow_id=245803170,
                conclusion="cancelled",
            )
            if run["path"] == ".github/workflows/ci.yml"
            else run
            for run in green_workflow_runs()
        ]
        verdict = self.grade(green_checks(), runs)
        self.assertEqual(verdict["verdict"], selector.DEAD)
        self.assertTrue(any("CI push run" in line for line in verdict["dead"]))

    def test_a_red_acceptance_push_run_is_dead(self) -> None:
        """Acceptance grades main's push and nothing else, so a red one stops the cut."""

        runs = [
            workflow_run(
                ".github/workflows/acceptance.yml",
                run_id=ACCEPTANCE_RUN,
                suite=ACCEPTANCE_SUITE,
                sha=NEWEST,
                workflow_id=339594603,
                conclusion="failure",
            )
            if run["path"] == ".github/workflows/acceptance.yml"
            else run
            for run in green_workflow_runs()
        ]
        verdict = self.grade(green_checks(), runs)
        self.assertEqual(verdict["verdict"], selector.DEAD)
        self.assertTrue(any("Acceptance push run" in line for line in verdict["dead"]))

    def test_an_absent_acceptance_run_is_pending(self) -> None:
        runs = [run for run in green_workflow_runs() if run["path"] != ".github/workflows/acceptance.yml"]
        verdict = self.grade(green_checks(), runs)
        self.assertEqual(verdict["verdict"], selector.PENDING)
        self.assertTrue(any("no Acceptance push run" in line for line in verdict["pending"]))

    def test_a_context_from_another_app_is_dead(self) -> None:
        checks = green_checks()
        checks[0] = check_run(checks[0]["name"], suite=CI_SUITE, app=(99, "impostor"))
        verdict = self.grade(checks, green_workflow_runs())
        self.assertEqual(verdict["verdict"], selector.DEAD)
        self.assertTrue(any("claimed by another app" in line for line in verdict["dead"]))

    def test_a_candidate_branch_twin_is_discounted_not_counted(self) -> None:
        """57228997f carried a second gitleaks from the candidate branch's own push."""

        checks = green_checks()
        checks.append(check_run("gitleaks (full history)", suite=91_000_000_099))
        runs = green_workflow_runs()
        runs.append(
            workflow_run(
                ".github/workflows/secret-scan.yml",
                run_id=33_000_000_099,
                suite=91_000_000_099,
                sha=NEWEST,
                workflow_id=293452372,
                branch=f"release/v{VERSION}-candidate",
            )
        )
        verdict = self.grade(checks, runs)
        self.assertEqual(verdict["verdict"], selector.GREEN, verdict)

    def test_a_second_producer_of_a_required_name_on_main_is_dead(self) -> None:
        checks = green_checks()
        checks.append(check_run("Falsify guards", suite=91_000_000_098))
        runs = green_workflow_runs()
        runs.append(
            workflow_run(
                ".github/workflows/impostor.yml",
                run_id=33_000_000_098,
                suite=91_000_000_098,
                sha=NEWEST,
                workflow_id=999,
            )
        )
        verdict = self.grade(checks, runs)
        self.assertEqual(verdict["verdict"], selector.DEAD)
        self.assertTrue(any("provenance mismatch" in line for line in verdict["dead"]))

    def test_a_truncated_listing_refuses_rather_than_reading_as_green(self) -> None:
        checks = green_checks()
        with self.assertRaises(selector.SelectionError) as caught:
            selector.grade_sha(
                NEWEST,
                pages(checks, "check_runs", total=len(checks) + 5),
                pages(green_workflow_runs(), "workflow_runs"),
            )
        self.assertIn("incomplete", str(caught.exception))

    def test_a_loose_sha_refuses(self) -> None:
        with self.assertRaises(selector.SelectionError):
            selector.grade_sha("abc", pages([], "check_runs"), pages([], "workflow_runs"))


# ---------------------------------------------------------------------------
# The decision.
# ---------------------------------------------------------------------------


class ReadRcBuildsTests(unittest.TestCase):
    """The read that decides what `_usable` is allowed to see.

    `_usable` never sees an expired artifact, because the read filters them out
    before the judgment. That filter is the whole of the expiry refusal, so it
    is asserted here rather than assumed by a fixture that hands over an empty
    list.
    """

    BRANCH = f"release/v{VERSION}-candidate"

    def read(self, runs: list[dict[str, Any]], artifacts: dict[int, list[dict[str, Any]]]):
        def fetch(endpoint: str) -> Any:
            if endpoint == selector.rc_build_runs_endpoint(REPO, self.BRANCH, 1):
                return {"total_count": len(runs), "workflow_runs": runs}
            for run_id, listing in artifacts.items():
                if endpoint == selector.run_artifacts_endpoint(REPO, run_id, 1):
                    return {"total_count": len(listing), "artifacts": listing}
            raise AssertionError(f"unexpected endpoint {endpoint}")

        return selector.read_rc_builds(fetch, REPO, self.BRANCH)

    def run_row(self, run_id: int, *, status: str = "completed", conclusion: str | None = "success"):
        return {
            "id": run_id,
            "head_sha": MIDDLE,
            "head_branch": self.BRANCH,
            "event": "workflow_dispatch",
            "status": status,
            "conclusion": conclusion,
            "created_at": "2026-09-02T22:52:23Z",
        }

    def test_every_live_archive_is_read_and_the_run_is_usable(self) -> None:
        listing = [{"name": name, "expired": False} for name in selector.RC_BUILD_ARTIFACTS]
        builds = self.read([self.run_row(1)], {1: listing})
        self.assertEqual(builds[0]["artifacts"], sorted(selector.RC_BUILD_ARTIFACTS))
        self.assertTrue(selector._usable(builds[0]))

    def test_an_expired_archive_is_dropped_and_costs_the_run_its_usability(self) -> None:
        listing = [
            {"name": name, "expired": name == "kin-macos-aarch64"}
            for name in selector.RC_BUILD_ARTIFACTS
        ]
        builds = self.read([self.run_row(1)], {1: listing})
        self.assertNotIn("kin-macos-aarch64", builds[0]["artifacts"])
        self.assertFalse(selector._usable(builds[0]))

    def test_an_unsuccessful_run_costs_no_artifact_read_and_is_not_usable(self) -> None:
        for status, conclusion in (("completed", "failure"), ("in_progress", None)):
            with self.subTest(status=status, conclusion=conclusion):
                builds = self.read([self.run_row(1, status=status, conclusion=conclusion)], {})
                self.assertEqual(builds[0]["artifacts"], [])
                self.assertFalse(selector._usable(builds[0]))


class JudgeTests(unittest.TestCase):
    def assertDecision(self, decision: Any, expected: str, needle: str = "") -> None:
        self.assertEqual(decision.decision, expected, decision.reason)
        if needle:
            self.assertIn(needle, decision.reason)

    def test_a_finalized_tag_stands_the_cut_down(self) -> None:
        """Today's tree: main carries 0.6.4 and v0.6.4 exists, so there is nothing to cut."""

        grader = Grader({})
        decision = selector.judge(snapshot(tag_exists=True), grader)
        self.assertDecision(decision, selector.STAND_DOWN, "already exists")
        self.assertEqual(grader.calls, [], "a tagged version must cost no grading")

    def test_a_fully_evidenced_candidate_stands_the_cut_down(self) -> None:
        grader = Grader({})
        decision = selector.judge(
            snapshot(evidence={MIDDLE: [selector.PREFLIGHT_RECORD, selector.STRANGER_RECORD]}),
            grader,
        )
        self.assertDecision(decision, selector.STAND_DOWN, "awaits the mint")
        self.assertEqual(decision.candidate, MIDDLE)
        self.assertEqual(grader.calls, [])

    def test_a_half_evidenced_candidate_asks_for_the_stranger_and_names_its_archive(self) -> None:
        grader = Grader({})
        decision = selector.judge(
            snapshot(
                candidate=MIDDLE,
                evidence={MIDDLE: [selector.PREFLIGHT_RECORD]},
                rc_builds=[rc_build(MIDDLE)],
            ),
            grader,
        )
        self.assertDecision(decision, selector.STRANGER, "the stranger record is the missing half")
        # The rc-build run travels with the decision, because the stranger has
        # to run on the very bytes the published preflight judged.
        self.assertEqual(decision.rc_run, 34_000_000_001)
        command = decision.details["stranger_command"]
        self.assertIn("bin/kin-stranger prepare", command)
        self.assertIn("--arms green,brown,vcs", command)
        self.assertIn(f"--candidate-sha {MIDDLE}", command)
        self.assertEqual(grader.calls, [], "a filed preflight must cost no grading")

    def test_a_half_evidenced_candidate_whose_archives_expired_refuses(self) -> None:
        """The record names an archive sha256; a rebuild is not guaranteed to reproduce it."""

        decision = selector.judge(
            snapshot(candidate=MIDDLE, evidence={MIDDLE: [selector.PREFLIGHT_RECORD]}, rc_builds=[]),
            Grader({}),
        )
        self.assertDecision(decision, selector.REFUSE, "no rc-build still holds the archives it judged")
        self.assertEqual(decision.candidate, MIDDLE)

    def test_an_expired_rc_build_is_not_a_usable_archive_source(self) -> None:
        stale = rc_build(MIDDLE, artifacts=[])
        decision = selector.judge(
            snapshot(candidate=MIDDLE, evidence={MIDDLE: [selector.PREFLIGHT_RECORD]}, rc_builds=[stale]),
            Grader({}),
        )
        self.assertDecision(decision, selector.REFUSE, "no rc-build still holds")

    def test_one_expired_archive_costs_the_run_its_usability(self) -> None:
        """A partially aged-out run cannot feed the leg whose archive is gone."""

        survivor = rc_build(MIDDLE, artifacts=["kin-linux-aarch64", "kin-linux-x86_64"])
        self.assertFalse(selector._usable(survivor))
        grader = Grader({MIDDLE: green_grade(MIDDLE)})
        decision = selector.judge(snapshot(candidate=MIDDLE, rc_builds=[survivor]), grader)
        self.assertDecision(decision, selector.ARM)

    def test_both_records_beat_the_stranger_decision(self) -> None:
        """Once stranger.env lands the candidate belongs to the mint, not to another run."""

        decision = selector.judge(
            snapshot(
                candidate=MIDDLE,
                evidence={MIDDLE: [selector.PREFLIGHT_RECORD, selector.STRANGER_RECORD]},
                rc_builds=[rc_build(MIDDLE)],
            ),
            Grader({}),
        )
        self.assertDecision(decision, selector.STAND_DOWN, "awaits the mint")

    def test_the_newest_green_sha_is_armed(self) -> None:
        grader = Grader({NEWEST: green_grade(NEWEST)})
        decision = selector.judge(snapshot(), grader)
        self.assertDecision(decision, selector.ARM)
        self.assertEqual(decision.candidate, NEWEST)
        self.assertEqual(decision.move, selector.MOVE_CREATE)
        self.assertEqual(decision.branch, f"release/v{VERSION}-candidate")
        self.assertEqual(grader.calls, [NEWEST], "a green newest sha must cost exactly one grading")

    def test_an_older_green_sha_behind_a_red_newest_is_armed(self) -> None:
        red = with_duplicate(green_grade(NEWEST), "Falsify guards", CI_SUITE)
        grader = Grader({NEWEST: red, MIDDLE: green_grade(MIDDLE)})
        decision = selector.judge(snapshot(), grader)
        self.assertDecision(decision, selector.ARM)
        self.assertEqual(decision.candidate, MIDDLE)
        self.assertEqual(grader.calls, [NEWEST, MIDDLE])
        self.assertIn(NEWEST, decision.details["disqualified"])

    def test_a_pending_newest_is_skipped_rather_than_waited_for(self) -> None:
        """On a busy night the newest sha is always mid-grading; waiting never converges."""

        pending = green_grade(NEWEST)
        pending["check_runs"][0]["check_runs"][0]["status"] = "in_progress"
        pending["check_runs"][0]["check_runs"][0]["conclusion"] = None
        grader = Grader({NEWEST: pending, MIDDLE: green_grade(MIDDLE)})
        decision = selector.judge(snapshot(), grader)
        self.assertDecision(decision, selector.ARM)
        self.assertEqual(decision.candidate, MIDDLE)
        self.assertIn(NEWEST, decision.details["skipped_pending"])

    def test_no_green_sha_anywhere_refuses_and_names_the_newest(self) -> None:
        dead = {
            sha: with_duplicate(green_grade(sha), "Falsify guards", CI_SUITE)
            for sha in (NEWEST, MIDDLE, OLDEST)
        }
        decision = selector.judge(snapshot(), Grader(dead))
        self.assertDecision(decision, selector.REFUSE, "no reviewed main commit")
        self.assertIn(NEWEST, decision.reason)
        self.assertIn("ambiguous required check: Falsify guards", decision.reason)

    def test_every_sha_pending_stands_down_rather_than_refusing(self) -> None:
        waiting = {}
        for sha in (NEWEST, MIDDLE, OLDEST):
            grade = green_grade(sha)
            grade["check_runs"][0]["check_runs"][0]["status"] = "queued"
            grade["check_runs"][0]["check_runs"][0]["conclusion"] = None
            waiting[sha] = grade
        decision = selector.judge(snapshot(), Grader(waiting))
        self.assertDecision(decision, selector.STAND_DOWN, "still being graded")

    def test_a_green_candidate_with_no_rc_build_is_armed_without_moving_the_branch(self) -> None:
        grader = Grader({MIDDLE: green_grade(MIDDLE)})
        decision = selector.judge(snapshot(candidate=MIDDLE), grader)
        self.assertDecision(decision, selector.ARM)
        self.assertEqual(decision.candidate, MIDDLE)
        self.assertEqual(decision.move, selector.MOVE_NONE)

    def test_a_running_rc_build_stands_down(self) -> None:
        grader = Grader({MIDDLE: green_grade(MIDDLE)})
        decision = selector.judge(
            snapshot(candidate=MIDDLE, rc_builds=[rc_build(MIDDLE, status="in_progress", conclusion=None)]),
            grader,
        )
        self.assertDecision(decision, selector.STAND_DOWN, "in_progress")
        self.assertEqual(decision.rc_run, 34_000_000_001)

    def test_a_successful_rc_build_holding_every_archive_is_proof(self) -> None:
        grader = Grader({MIDDLE: green_grade(MIDDLE)})
        decision = selector.judge(snapshot(candidate=MIDDLE, rc_builds=[rc_build(MIDDLE)]), grader)
        self.assertDecision(decision, selector.PROOF)
        self.assertEqual(decision.rc_run, 34_000_000_001)
        self.assertIn("bin/kin-stranger run", decision.details["stranger_command"])

    def test_an_rc_build_missing_an_archive_is_not_proof(self) -> None:
        """The preflight downloads one archive per row; a run short of one cannot feed it."""

        partial = rc_build(MIDDLE, artifacts=["kin-macos-aarch64"])
        grader = Grader({MIDDLE: green_grade(MIDDLE)})
        decision = selector.judge(snapshot(candidate=MIDDLE, rc_builds=[partial]), grader)
        self.assertDecision(decision, selector.ARM)
        self.assertEqual(decision.candidate, MIDDLE)

    def test_a_failed_rc_build_holding_every_archive_is_not_proof(self) -> None:
        """A red run's artifacts are not evidence; only a successful build is."""

        failed = rc_build(MIDDLE, conclusion="failure")
        grader = Grader({MIDDLE: green_grade(MIDDLE)})
        decision = selector.judge(snapshot(candidate=MIDDLE, rc_builds=[failed]), grader)
        self.assertDecision(decision, selector.ARM)
        self.assertEqual(decision.candidate, MIDDLE)

    def test_the_deadlocked_shape_of_2026_09_02_is_usable(self) -> None:
        """Regression: run 33692452573 for febf5d851, the shape that burned the loop.

        The rc-build succeeded and carried exactly the three archive names, none
        expired. The selector asked for `kin-release-preflight-` prefixed names,
        which only release-cut.yml's own preflight job ever uploads and only on
        the `proof` decision this reading could never produce, so the loop armed
        a fresh build every cycle and killed the candidate at the attempt limit.
        These are the live names read from that run's artifacts endpoint.
        """

        live = rc_build(
            MIDDLE,
            run_id=33_692_452_573,
            artifacts=["kin-macos-aarch64", "kin-linux-x86_64", "kin-linux-aarch64"],
        )
        self.assertTrue(selector._usable(live), live["artifacts"])
        grader = Grader({MIDDLE: green_grade(MIDDLE)})
        decision = selector.judge(snapshot(candidate=MIDDLE, rc_builds=[live]), grader)
        self.assertDecision(decision, selector.PROOF, "still holds its archives")
        self.assertEqual(decision.rc_run, 33_692_452_573)

    def test_a_run_carrying_only_leg_record_names_is_not_usable(self) -> None:
        """The inverse control: leg-record names alone are not candidate archives.

        release-cut.yml uploads `kin-release-preflight-<artifact>` into its OWN
        run. If those names ever appear on an rc-build run, they are still not
        the archives the preflight downloads by bare name.
        """

        legs = rc_build(MIDDLE, artifacts=[f"kin-release-preflight-{name}" for name in selector.RC_BUILD_ARTIFACTS])
        self.assertFalse(selector._usable(legs))

    def test_exhausted_rc_build_attempts_kill_the_candidate_and_pick_the_next(self) -> None:
        spent = [
            rc_build(MIDDLE, run_id=1, conclusion="failure", created_at="2026-09-02T19:00:00Z"),
            rc_build(MIDDLE, run_id=2, conclusion="failure", created_at="2026-09-02T20:00:00Z"),
        ]
        grader = Grader({MIDDLE: green_grade(MIDDLE), NEWEST: green_grade(NEWEST)})
        decision = selector.judge(snapshot(candidate=MIDDLE, rc_builds=spent), grader)
        self.assertDecision(decision, selector.ARM)
        self.assertEqual(decision.candidate, NEWEST)
        self.assertEqual(decision.move, selector.MOVE_FAST_FORWARD)
        self.assertTrue(any("attempts exhausted" in note for note in decision.details["notes"]))

    def test_a_dead_candidate_is_replaced_by_the_newest_green_sha(self) -> None:
        dead = with_duplicate(green_grade(MIDDLE), "cargo-deny", SAST_SUITE)
        grader = Grader({MIDDLE: dead, NEWEST: green_grade(NEWEST)})
        decision = selector.judge(snapshot(candidate=MIDDLE), grader)
        self.assertDecision(decision, selector.ARM)
        self.assertEqual(decision.candidate, NEWEST)
        self.assertEqual(decision.move, selector.MOVE_FAST_FORWARD)

    def test_a_dead_candidate_replaced_by_an_older_sha_resets_rather_than_fast_forwards(self) -> None:
        dead = with_duplicate(green_grade(MIDDLE), "cargo-deny", SAST_SUITE)
        newest_dead = with_duplicate(green_grade(NEWEST), "cargo-deny", SAST_SUITE)
        grader = Grader({MIDDLE: dead, NEWEST: newest_dead, OLDEST: green_grade(OLDEST)})
        decision = selector.judge(snapshot(candidate=MIDDLE), grader)
        self.assertDecision(decision, selector.ARM)
        self.assertEqual(decision.candidate, OLDEST)
        self.assertEqual(decision.move, selector.MOVE_RESET)

    def test_a_candidate_off_the_version_range_refuses(self) -> None:
        decision = selector.judge(snapshot(candidate=FOREIGN), Grader({}))
        self.assertDecision(decision, selector.REFUSE, "is not a reviewed main commit")

    def test_a_pending_candidate_stands_down_without_replacing_it(self) -> None:
        pending = green_grade(MIDDLE)
        pending["check_runs"][0]["check_runs"][0]["status"] = "in_progress"
        pending["check_runs"][0]["check_runs"][0]["conclusion"] = None
        grader = Grader({MIDDLE: pending})
        decision = selector.judge(snapshot(candidate=MIDDLE), grader)
        self.assertDecision(decision, selector.STAND_DOWN, "being graded again")
        self.assertEqual(grader.calls, [MIDDLE])

    def test_malformed_snapshots_refuse(self) -> None:
        for broken, needle in (
            (snapshot(version="0.6"), "semver"),
            (snapshot(range=[]), "non-empty"),
            (snapshot(range=[NEWEST, NEWEST]), "repeats"),
            (snapshot(range=["nope"]), "40-character"),
            (snapshot(candidate="nope"), "not a 40-character"),
        ):
            with self.assertRaises(selector.SelectionError):
                selector.judge(broken, Grader({}))
        with self.assertRaises(selector.SelectionError):
            selector.judge("not an object", Grader({}))


# ---------------------------------------------------------------------------
# Trigger validation.
# ---------------------------------------------------------------------------


def trigger_context(**overrides: Any) -> dict[str, Any]:
    context = {
        "event_name": "schedule",
        "event_action": "",
        "actor": "troyjr4103",
        "repository": REPO,
        "default_branch": "main",
        "ref": "refs/heads/main",
        "workflow_sha": NEWEST,
        "event": {},
    }
    context.update(overrides)
    return context


def completion_event(**overrides: Any) -> dict[str, Any]:
    run = {
        "path": ".github/workflows/ci.yml",
        "event": "push",
        "head_branch": "main",
        "head_repository": {"full_name": REPO},
        "status": "completed",
        "conclusion": "success",
        "head_sha": NEWEST,
        "id": CI_RUN,
    }
    run.update(overrides)
    return {"workflow_run": run}


class TriggerTests(unittest.TestCase):
    def test_the_sweep_is_admitted(self) -> None:
        verdict = selector.validate_trigger(**trigger_context())
        self.assertEqual(verdict["trigger"], selector.TRIGGER_SWEEP)

    def test_a_ci_completion_for_a_main_push_is_admitted(self) -> None:
        verdict = selector.validate_trigger(
            **trigger_context(event_name="workflow_run", event_action="completed", event=completion_event())
        )
        self.assertEqual(verdict["trigger"], selector.TRIGGER_CI)

    def test_an_rc_build_completion_on_a_candidate_branch_is_admitted(self) -> None:
        verdict = selector.validate_trigger(
            **trigger_context(
                event_name="workflow_run",
                event_action="completed",
                event=completion_event(
                    path=".github/workflows/rc-build.yml",
                    event="workflow_dispatch",
                    head_branch=f"release/v{VERSION}-candidate",
                ),
            )
        )
        self.assertEqual(verdict["trigger"], selector.TRIGGER_RC_BUILD)
        self.assertEqual(verdict["run_id"], CI_RUN)

    def test_completions_that_are_not_occasions_refuse(self) -> None:
        for overrides, needle in (
            ({"head_branch": "chore/lane-x"}, "occasion only for a push to main"),
            ({"event": "pull_request"}, "occasion only for a push to main"),
            ({"head_repository": {"full_name": "someone/fork"}}, "first-party"),
            ({"status": "in_progress"}, "not completed"),
            ({"path": ".github/workflows/acceptance.yml"}, "is neither"),
        ):
            with self.assertRaises(selector.SelectionError) as caught:
                selector.validate_trigger(
                    **trigger_context(
                        event_name="workflow_run", event_action="completed", event=completion_event(**overrides)
                    )
                )
            self.assertIn(needle, str(caught.exception))

    def test_an_rc_build_completion_off_a_candidate_branch_refuses(self) -> None:
        with self.assertRaises(selector.SelectionError) as caught:
            selector.validate_trigger(
                **trigger_context(
                    event_name="workflow_run",
                    event_action="completed",
                    event=completion_event(path=".github/workflows/rc-build.yml", event="workflow_dispatch", head_branch="main"),
                )
            )
        self.assertIn("release/v<version>-candidate", str(caught.exception))

    def test_the_kick_is_admitted_only_from_the_allowlist(self) -> None:
        for actor in sorted(selector.KICK_ACTORS):
            verdict = selector.validate_trigger(
                **trigger_context(
                    event_name="repository_dispatch",
                    event_action=selector.KICK_ACTION,
                    actor=actor,
                    event={"action": selector.KICK_ACTION, "client_payload": {"reason": "cut it"}},
                )
            )
            self.assertEqual(verdict["trigger"], selector.TRIGGER_KICK)
            self.assertEqual(verdict["actor"], actor)
        with self.assertRaises(selector.SelectionError) as caught:
            selector.validate_trigger(
                **trigger_context(
                    event_name="repository_dispatch",
                    event_action=selector.KICK_ACTION,
                    actor="a-stranger",
                    event={"action": selector.KICK_ACTION},
                )
            )
        self.assertIn("may not kick", str(caught.exception))

    def test_kick_refusals(self) -> None:
        for overrides, event, needle in (
            ({"event_action": "release_something_else"}, {"action": "release_something_else"}, "event action must be"),
            ({}, {"action": "mismatch"}, "differs from the trigger context"),
            ({}, {"action": selector.KICK_ACTION, "client_payload": {"sha": NEWEST}}, "reason and nothing else"),
            ({}, {"action": selector.KICK_ACTION, "client_payload": {"reason": "x" * 201}}, "at most 200"),
        ):
            context = {
                "event_name": "repository_dispatch",
                "event_action": selector.KICK_ACTION,
                "event": event,
            }
            context.update(overrides)
            with self.assertRaises(selector.SelectionError) as caught:
                selector.validate_trigger(**trigger_context(**context))
            self.assertIn(needle, str(caught.exception))

    def test_context_that_is_not_protected_main_refuses(self) -> None:
        for overrides, needle in (
            ({"repository": "someone/kin"}, "repository must be"),
            ({"default_branch": "trunk"}, "default branch must be"),
            ({"ref": "refs/heads/chore/lane"}, "workflow ref must be"),
            ({"workflow_sha": "abc"}, "40-character"),
            ({"event_name": "push"}, "event name must be"),
            ({"event": []}, "event document must be an object"),
        ):
            with self.assertRaises(selector.SelectionError) as caught:
                selector.validate_trigger(**trigger_context(**overrides))
            self.assertIn(needle, str(caught.exception))


# ---------------------------------------------------------------------------
# Contracts against the mint and the workflow.
# ---------------------------------------------------------------------------


class ContractTests(unittest.TestCase):
    def test_the_required_contexts_match_the_mints_own_list(self) -> None:
        """A selector that picks a sha on a different list picks one the mint refuses."""

        source = RELEASE_TAG_PATH.read_text(encoding="utf-8")
        match = re.search(r"(?m)^          REQUIRED_CHECKS: \|\n((?:            .*\n)+)", source)
        self.assertIsNotNone(match, "release-tag.yml no longer declares REQUIRED_CHECKS as a block")
        # Only the block scalar's own 12-space body. Reading to the next key
        # would swallow the comment block between the two lists, which is how
        # this assertion first read eighteen prose lines as required contexts.
        mint = [line.strip() for line in match.group(1).splitlines() if line.strip()]
        self.assertEqual([name for name, _id, _path in selector.REQUIRED_CONTEXTS], mint)

    def test_the_provenance_table_matches_the_mints_own(self) -> None:
        source = RELEASE_TAG_PATH.read_text(encoding="utf-8")
        for name, workflow_id, path in selector.REQUIRED_CONTEXTS:
            pattern = (
                re.escape(f'"{name}": (')
                + r"\s*"
                + re.escape(f"{workflow_id:_}".replace("_", "_"))
                + r"?"
            )
            # The mint writes the id with underscore separators for the two
            # non-ci workflows and plain digits for ci.yml, so match either.
            plain = str(workflow_id)
            grouped = f"{workflow_id:,}".replace(",", "_")
            block = re.search(rf'(?ms)"{re.escape(name)}": \((.*?)\),\n', source)
            self.assertIsNotNone(block, f"release-tag.yml no longer binds {name}")
            body = block.group(1)
            self.assertTrue(
                plain in body or grouped in body,
                f"{name} is bound to a different workflow id in release-tag.yml: {body}",
            )
            self.assertIn(path, body, f"{name} is bound to a different workflow path")

    def test_the_usable_artifacts_are_the_names_rc_build_actually_uploads(self) -> None:
        """The deadlock, as an assertion.

        `_usable` judges an rc-build run, so the names it requires have to be
        the names that run uploads. They were once the leg-record names
        release-cut.yml uploads into its own run, which no rc-build can carry,
        so no candidate could ever be proven and the preflight that would have
        produced those records was gated on the decision they blocked.
        """

        source = RC_BUILD_PATH.read_text(encoding="utf-8")
        build = job_block(source, "build")
        self.assertEqual(
            sorted(matrix_artifacts(build)),
            sorted(selector.RC_BUILD_ARTIFACTS),
            "rc-build.yml's build matrix and the selector's usable set have drifted",
        )
        # The row value is only the artifact name if the upload step names it
        # unadorned. A prefix added here would make every row a different
        # artifact than the selector asks for, silently.
        self.assertIn("          name: ${{ matrix.artifact }}\n", build)

    def test_the_preflight_downloads_exactly_the_artifacts_the_selector_requires(self) -> None:
        """The consumer side: each leg pulls one archive from the run by bare name."""

        source = CUT_WORKFLOW_PATH.read_text(encoding="utf-8")
        preflight = job_block(source, "preflight")
        self.assertEqual(
            sorted(matrix_artifacts(preflight)),
            sorted(selector.RC_BUILD_ARTIFACTS),
            "release-cut.yml's preflight matrix and the selector's usable set have drifted",
        )
        self.assertIn('--name "$ARTIFACT"', preflight)

    def test_the_leg_records_are_uploaded_by_the_cut_not_by_the_candidate_build(self) -> None:
        """Where the prefixed names live, so nobody re-derives the wrong owner.

        A reader who believes rc-build.yml uploads the leg records writes the
        selector's usable set as the prefixed names again. rc-build.yml uploads
        one thing, and release-cut.yml's preflight job uploads the other.
        """

        cut = CUT_WORKFLOW_PATH.read_text(encoding="utf-8")
        self.assertIn("          name: kin-release-preflight-${{ matrix.artifact }}\n", cut)
        self.assertIn("          pattern: kin-release-preflight-*\n", cut)
        rc = RC_BUILD_PATH.read_text(encoding="utf-8")
        self.assertNotIn("name: kin-release-preflight-", rc)

    def test_every_job_downstream_of_a_skipped_arm_survives_that_skip(self) -> None:
        """The second deadlock, as an assertion.

        `arm` runs only on the `arm` decision, so it is skipped on the proof
        path, and a skip propagates along the dependency chain to every job
        that does not override it. `preflight` overrides it with `always()`;
        `publish`, one link further down, did not, so on 2026-09-03 run
        33699387471 decided `proof`, all three preflight legs passed and filed
        their leg records, and the publisher skipped at once with zero steps.
        It had never been evaluated before, because no cycle had ever reached
        `proof`.

        The rule this pins: any job that can be reached from `arm` through
        `needs` has to carry a status function, or an upstream skip decides it.
        """

        source = CUT_WORKFLOW_PATH.read_text(encoding="utf-8")
        blocks = {name: job_block(source, name) for name in job_names(source)}
        self.assertIn("arm", blocks, "release-cut.yml no longer has an arm job")
        self.assertIn(
            "needs.select.outputs.decision == 'arm'",
            job_if(blocks["arm"]),
            "arm is no longer the conditional job this rule is about",
        )

        downstream: set[str] = set()
        changed = True
        while changed:
            changed = False
            for name, block in blocks.items():
                if name in downstream or name == "arm":
                    continue
                if any(need == "arm" or need in downstream for need in job_needs(block)):
                    downstream.add(name)
                    changed = True

        self.assertTrue(downstream, "nothing needs arm, so this rule guards nothing")
        for name in sorted(downstream):
            self.assertIn(
                "always()",
                job_if(blocks[name]),
                f"job {name!r} is downstream of the conditional arm job without always(), "
                "so an arm skip skips it whatever its own condition says",
            )

    def test_the_publisher_still_refuses_a_preflight_that_did_not_pass(self) -> None:
        """`always()` must not become a gate that publishes anything.

        The publisher survives an unrelated upstream skip, and nothing more: it
        still has to read the preflight matrix's own result as success, and it
        still only runs on the proof decision.
        """

        condition = job_if(job_block(CUT_WORKFLOW_PATH.read_text(encoding="utf-8"), "publish"))
        self.assertIn("needs.preflight.result == 'success'", condition)
        self.assertIn("needs.select.outputs.decision == 'proof'", condition)

    def test_the_publisher_records_the_token_scope_before_it_decides(self) -> None:
        """A refusal has to name its own evidence, and cannot be caused by naming it.

        The publisher proves its token against GET /repos before writing, and
        the push half of that check reads a block reporting the authenticated
        USER's permissions. What an App installation token gets there was
        guessed wrong twice on 2026-09-03 while four cycles refused with a
        message naming the verdict and never the evidence. So the scope is
        recorded first, and the recording is barred from failing the job:
        a diagnostic that can break the thing it explains is worse than none.
        """

        publish = job_block(CUT_WORKFLOW_PATH.read_text(encoding="utf-8"), "publish")
        record = publish.find("- name: Record what the evidence token can do")
        write = publish.find("- name: Publish preflight.json for the candidate")
        self.assertNotEqual(record, -1, "the publish job no longer records the token scope")
        self.assertNotEqual(write, -1, "the publish job no longer publishes")
        self.assertLess(
            record,
            write,
            "the token scope is recorded after the write it exists to explain, so a refusal "
            "at the write leaves no record of what the token looked like",
        )
        diagnostic = publish[record:write]
        self.assertIn("if: always()", diagnostic)
        self.assertIn("exit 0", diagnostic)
        self.assertNotIn("set -euo pipefail", diagnostic)

    def test_the_workflow_calls_the_selector_and_binds_its_trigger(self) -> None:
        workflow = CUT_WORKFLOW_PATH.read_text(encoding="utf-8")
        for needle in (
            "python3 scripts/select-release-candidate.py validate-trigger",
            "python3 scripts/select-release-candidate.py select",
            "python3 scripts/verify-protected-main-history.py",
            "node scripts/release-proof/merge-preflight-records.mjs",
            "scripts/release-proof/bin/kin-evidence-publish",
        ):
            self.assertIn(needle, workflow, f"release-cut.yml must run {needle}")

    def test_the_stranger_is_gated_on_a_variable_rather_than_a_runner_query(self) -> None:
        """A job whose labels match no online runner queues; it does not skip.

        GITHUB_TOKEN cannot list runners (`administration` is not among the
        permissions a workflow token can hold) and the release App carries
        contents, issues and pull-requests only, so live availability is not
        readable from inside the run. The switch is therefore explicit, and
        every path has to be covered: one job when it is set, one when it is not.
        """

        workflow = CUT_WORKFLOW_PATH.read_text(encoding="utf-8")
        jobs = dict(re.findall(r"(?ms)^  ([a-z0-9-]+):\n(.*?)(?=^  [a-z0-9-]+:\n|\Z)", workflow))
        self.assertIn("stranger", jobs)
        self.assertIn("stranger-standby", jobs)
        self.assertIn("vars.KIN_STRANGER_RUNNER != ''", jobs["stranger"])
        self.assertIn("vars.KIN_STRANGER_RUNNER == ''", jobs["stranger-standby"])
        self.assertIn("runs-on: ${{ vars.KIN_STRANGER_RUNNER }}", jobs["stranger"])
        # The standby path is the one that keeps a release moving without a
        # runner, so it has to carry the whole command rather than a pointer.
        for needle in ("bin/kin-stranger prepare", "--arms green,brown,vcs", "--candidate-sha", "::warning::"):
            self.assertIn(needle, jobs["stranger-standby"], f"the standby path must print {needle}")

    def test_the_stranger_refuses_before_spending_an_arm_on_a_missing_credential(self) -> None:
        workflow = CUT_WORKFLOW_PATH.read_text(encoding="utf-8")
        jobs = dict(re.findall(r"(?ms)^  ([a-z0-9-]+):\n(.*?)(?=^  [a-z0-9-]+:\n|\Z)", workflow))
        stranger = jobs["stranger"]
        self.assertIn("KIN_STRANGER_ANTHROPIC_API_KEY", stranger)
        self.assertIn('if [ -z "${STRANGER_KEY:-}" ]; then', stranger)
        # An interrupted run resumes rather than re-preparing: `prepare` refuses
        # a reused container without --force because a reused container tests an
        # upgrade path, which is a different question.
        self.assertIn("bin/kin-stranger resume", stranger)
        # Read the executable lines only. A bare substring search cannot tell a
        # comment explaining why --force is wrong from a command using it, and
        # would fail on the explanation that keeps the decision reviewable.
        active = [
            line for line in stranger.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        self.assertFalse(
            [line for line in active if "--force" in line],
            "the stranger job must never force a reused container: that tests an upgrade path",
        )

    def test_the_stranger_never_publishes_and_the_publisher_never_drives(self) -> None:
        """The App key must not reach the machine running a Claude driver on candidate bytes."""

        workflow = CUT_WORKFLOW_PATH.read_text(encoding="utf-8")
        jobs = dict(re.findall(r"(?ms)^  ([a-z0-9-]+):\n(.*?)(?=^  [a-z0-9-]+:\n|\Z)", workflow))
        self.assertNotIn("KIN_RELEASE_BOT_PRIVATE_KEY", jobs["stranger"])
        self.assertNotIn("kin-evidence-publish", jobs["stranger"])
        self.assertNotIn("environment:", jobs["stranger"])
        self.assertIn("environment: release-tag", jobs["publish-stranger"])
        self.assertIn("kin-evidence-publish", jobs["publish-stranger"])
        self.assertNotIn("ANTHROPIC_API_KEY", jobs["publish-stranger"])
        # --require-archive is what binds the record to the bytes the preflight
        # judged, checked at write time rather than by the gate at release time.
        # Read the executable lines only: the comment above that step explains
        # the flag, and a bare substring search is satisfied by the explanation
        # alone, so removing the flag itself left this assertion green.
        publisher_active = [
            line for line in jobs["publish-stranger"].splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        self.assertTrue(
            [line for line in publisher_active if "--require-archive" in line],
            "the stranger record must be published with --require-archive, which binds it "
            "to an archive the published preflight actually judged",
        )

    def test_the_workflow_keeps_the_release_app_off_the_proof_runners(self) -> None:
        """The preflight job downloads and judges; only the publish job may write."""

        workflow = CUT_WORKFLOW_PATH.read_text(encoding="utf-8")
        jobs = dict(re.findall(r"(?ms)^  ([a-z0-9-]+):\n(.*?)(?=^  [a-z0-9-]+:\n|\Z)", workflow))
        self.assertIn("preflight", jobs)
        self.assertNotIn("KIN_RELEASE_BOT_PRIVATE_KEY", jobs["preflight"])
        self.assertNotIn("environment:", jobs["preflight"])
        for job in ("arm", "publish"):
            self.assertIn(job, jobs)
            self.assertIn("environment: release-tag", jobs[job])

    def test_the_workflow_declares_only_trusted_triggers(self) -> None:
        workflow = CUT_WORKFLOW_PATH.read_text(encoding="utf-8")
        header = re.search(r"(?ms)^on:\n(.*?)(?=^[a-z])", workflow)
        self.assertIsNotNone(header)
        self.assertNotIn("workflow_dispatch", header.group(1), "a dispatch could select branch-controlled code")
        self.assertNotIn("pull_request", header.group(1))
        for needle in ("workflow_run:", "repository_dispatch:", "schedule:", selector.KICK_ACTION):
            self.assertIn(needle, header.group(1))


class CommandLineTests(unittest.TestCase):
    def run_selector(self, *arguments: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(SELECTOR_PATH), *arguments],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def test_a_snapshot_is_judged_and_its_decision_printed(self) -> None:
        document = snapshot()
        document["grades"] = {NEWEST: green_grade(NEWEST)}
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            json.dump(document, handle)
            path = handle.name
        result = self.run_selector("select", "--snapshot", path)
        self.assertEqual(result.returncode, 0, result.stderr)
        decision = json.loads(result.stdout)
        self.assertEqual(decision["decision"], selector.ARM)
        self.assertEqual(decision["candidate"], NEWEST)

    def test_a_refusal_exits_one_and_a_broken_read_exits_two(self) -> None:
        """A refusal and an unreadable snapshot must not share an exit code."""

        document = snapshot()
        document["grades"] = {
            sha: with_duplicate(green_grade(sha), "Falsify guards", CI_SUITE)
            for sha in document["range"]
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            json.dump(document, handle)
            path = handle.name
        refusal = self.run_selector("select", "--snapshot", path)
        self.assertEqual(refusal.returncode, 1, refusal.stdout)
        self.assertIn("Release cut refused", refusal.stderr)

        document.pop("grades")
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            json.dump(document, handle)
            broken = handle.name
        unreadable = self.run_selector("select", "--snapshot", broken)
        self.assertEqual(unreadable.returncode, 2, unreadable.stdout)
        self.assertIn("could not decide", unreadable.stderr)

    def test_validate_trigger_exits_zero_only_on_an_admitted_trigger(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            json.dump(completion_event(), handle)
            event = handle.name
        admitted = self.run_selector(
            "validate-trigger",
            "--event-file", event,
            "--event-name", "workflow_run",
            "--event-action", "completed",
            "--actor", "troyjr4103",
            "--repository", REPO,
            "--default-branch", "main",
            "--ref", "refs/heads/main",
            "--workflow-sha", NEWEST,
        )
        self.assertEqual(admitted.returncode, 0, admitted.stderr)
        refused = self.run_selector(
            "validate-trigger",
            "--event-file", event,
            "--event-name", "workflow_run",
            "--event-action", "completed",
            "--actor", "troyjr4103",
            "--repository", REPO,
            "--default-branch", "main",
            "--ref", "refs/heads/chore/lane",
            "--workflow-sha", NEWEST,
        )
        self.assertEqual(refused.returncode, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
