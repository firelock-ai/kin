#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

"""Fixtures for the duplicate-release-run guard, and a mutation pass over it.

Every case is a snapshot document, so the decision is exercised with no GitHub
in the loop. The falsification pass at the end breaks the guard one rule at a
time and asserts that a NAMED case goes red for each break, because a test that
passes against a broken guard is not evidence.
"""

from __future__ import annotations

import copy
import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import importlib

guard = importlib.import_module("guard-duplicate-release-run")
decide = guard.decide


def run(
    run_id: int,
    number: int,
    conclusion: str | None = "success",
    status: str = "completed",
    branch: str = "v0.6.4",
    event: str = "push",
) -> dict:
    return {
        "id": run_id,
        "run_number": number,
        "status": status,
        "conclusion": conclusion,
        "head_branch": branch,
        "event": event,
    }


def snapshot(runs: list[dict] | None, **over) -> dict:
    base = {
        "tag": "v0.6.4",
        "run_id": 33674383157,
        "run_number": 148,
        "run_attempt": 1,
        "runs": runs,
        "total_count": len(runs) if isinstance(runs, list) else 0,
    }
    base.update(over)
    return base


# name -> (snapshot, expected duplicate, expected unreadable)
CASES: dict[str, tuple[dict, bool, bool]] = {
    # The run that actually happened: 148 arrives behind a successful 147.
    "v0_6_4_duplicate_delivery": (
        snapshot([run(33674370002, 147), run(33674383157, 148, None, "in_progress")]),
        True,
        False,
    ),
    # The first release run for a tag has nothing behind it.
    "first_run_for_tag": (
        snapshot([run(33674370002, 147, None, "in_progress")], run_id=33674370002, run_number=147),
        False,
        False,
    ),
    "no_runs_at_all": (snapshot([]), False, False),
    # A failed earlier run leaves the release undone, so the second delivery is
    # the only thing left that can finish it.
    "earlier_run_failed": (
        snapshot([run(33674370002, 147, "failure"), run(33674383157, 148, None, "in_progress")]),
        False,
        False,
    ),
    "earlier_run_cancelled": (
        snapshot([run(33674370002, 147, "cancelled")]),
        False,
        False,
    ),
    # Still in flight is not proof it will succeed.
    "earlier_run_in_progress": (
        snapshot([run(33674370002, 147, None, "in_progress")]),
        False,
        False,
    ),
    # A success on a different tag says nothing about this one.
    "success_on_other_tag": (
        snapshot([run(33674370002, 147, "success", branch="v0.6.3")]),
        False,
        False,
    ),
    # A later run must not silence the run it duplicated.
    "later_run_succeeded": (
        snapshot(
            [run(33674370002, 147, None, "in_progress"), run(33674383157, 148, "success")],
            run_id=33674370002,
            run_number=147,
        ),
        False,
        False,
    ),
    # A rerun is a deliberate act even when an earlier success exists.
    "deliberate_rerun": (
        snapshot([run(33674370002, 147)], run_attempt=2),
        False,
        False,
    ),
    # A short page reads exactly like "no earlier run", so it must not.
    "short_listing": (
        snapshot([run(33674370002, 147, None, "in_progress")], total_count=9),
        False,
        True,
    ),
    "listing_absent": (snapshot(None), False, True),
    "identity_incomplete": (snapshot([run(33674370002, 147)], run_id=None), False, True),
    # A non-push run (a dispatch, say) is not the duplicate this guards against.
    "earlier_run_not_push": (
        snapshot([run(33674370002, 147, "success", event="workflow_dispatch")]),
        False,
        False,
    ),
    # Judging against itself would refuse every run.
    "only_itself_listed": (
        snapshot([run(33674383157, 148, "success")]),
        False,
        False,
    ),
    # The two rows below violate the API's own invariants on purpose. A real
    # listing never carries them, which is exactly why they are here: each one
    # isolates a rule that a well-formed row lets a neighbouring rule catch
    # first, so without them those two rules would be untested and could be
    # deleted with every case still green.
    #
    # Our own run id, reported with a lower run number. Only the self-exclusion
    # stops this, because the run-number comparison now reads it as older.
    "self_row_claims_lower_number": (
        snapshot([run(33674383157, 1, "success")]),
        False,
        False,
    ),
    # A run still in flight that already claims success. Only the completion
    # check stops this, because the conclusion alone reads green.
    "incomplete_row_claims_success": (
        snapshot([run(33674370002, 147, "success", status="in_progress")]),
        False,
        False,
    ),
}


def check(name: str) -> None:
    snap, want_dup, want_unreadable = CASES[name]
    got = decide(copy.deepcopy(snap))
    if got.duplicate != want_dup:
        raise AssertionError(
            f"{name}: duplicate={got.duplicate}, wanted {want_dup} ({got.reason})"
        )
    if got.unreadable != want_unreadable:
        raise AssertionError(
            f"{name}: unreadable={got.unreadable}, wanted {want_unreadable} ({got.reason})"
        )
    if want_dup and got.prior_run_id is None:
        raise AssertionError(f"{name}: duplicate verdict named no prior run")


def run_cases() -> None:
    for name in CASES:
        check(name)
    print(f"ok: {len(CASES)} duplicate-guard cases")


# ---- falsification -------------------------------------------------------
#
# Each mutation removes exactly one rule. The named case MUST go red under it.
# A mutation that leaves every case green means the case for that rule is
# missing, not that the rule is safe.

MUTATIONS: list[tuple[str, str, str]] = [
    (
        "ignore the rerun exemption",
        "deliberate_rerun",
        "attempt is not None and attempt > 1",
    ),
    (
        "ignore the short-page assertion",
        "short_listing",
        "total is not None and total != len(runs)",
    ),
    (
        "stop excluding this run itself",
        "self_row_claims_lower_number",
        "other_id == run_id",
    ),
    (
        "stop excluding later runs",
        "later_run_succeeded",
        "other_number >= run_number",
    ),
    (
        "stop checking the tag",
        "success_on_other_tag",
        'run.get("head_branch") != tag',
    ),
    (
        "stop checking the conclusion",
        "earlier_run_failed",
        'run.get("conclusion") != "success"',
    ),
    (
        "stop checking completion",
        "incomplete_row_claims_success",
        'run.get("status") != "completed"',
    ),
    (
        "stop checking the event",
        "earlier_run_not_push",
        'run.get("event") != "push"',
    ),
]


def falsify() -> None:
    source = Path(__file__).resolve().parent / "guard-duplicate-release-run.py"
    original = source.read_text(encoding="utf-8")
    survivors: list[str] = []

    for index, (label, case_name, needle) in enumerate(MUTATIONS):
        if needle not in original:
            raise AssertionError(
                f"mutation '{label}' does not apply: its guard text is gone, so this "
                f"falsification is no longer checking anything. Needle: {needle}"
            )
        # Neutralise exactly one condition, leaving the rest of the guard intact.
        broken = original.replace(needle, "False", 1)
        # The mutant needs a real module entry: @dataclass resolves its own
        # class through sys.modules, and a bare exec namespace makes it raise
        # instead of building the Verdict type.
        name = f"guard_mutant_{index}"
        module = types.ModuleType(name)
        sys.modules[name] = module
        try:
            exec(compile(broken, str(source), "exec"), module.__dict__)  # noqa: S102
            mutant_decide = module.__dict__["decide"]
            snap, want_dup, want_unreadable = CASES[case_name]
            got = mutant_decide(copy.deepcopy(snap))
            if got.duplicate == want_dup and got.unreadable == want_unreadable:
                survivors.append(f"{label} (case {case_name})")
        finally:
            sys.modules.pop(name, None)

    if survivors:
        raise AssertionError(
            "mutations survived, so these rules are not actually tested:\n  "
            + "\n  ".join(survivors)
        )
    print(f"ok: {len(MUTATIONS)} mutations each turned their named case red")


# ---- the wiring ----------------------------------------------------------
#
# The decision above is worth nothing if release.yml stops consulting it, and
# that is a silent failure: the release still runs, so nothing goes red. These
# assertions read the workflow itself.

WORKFLOW = Path(__file__).resolve().parent.parent / ".github/workflows/release.yml"
GUARD_JOB = "duplicate_guard"
GATE = "needs.duplicate_guard.outputs.duplicate != 'true'"


def parse_jobs(text: str) -> dict[str, dict]:
    """Read job ids with their `needs` and job-level `if`.

    Hand-rolled because the runner image carries no YAML module, and because a
    single-line regex silently misses the `if: >-` block form that 14 of these
    jobs use.
    """
    import re

    lines = text.split("\n")
    start = next(i for i, l in enumerate(lines) if re.match(r"^jobs:\s*$", l))
    heads = [
        (i, re.match(r"^  ([A-Za-z0-9_-]+):\s*$", l).group(1))
        for i, l in enumerate(lines[start + 1 :], start + 1)
        if re.match(r"^  ([A-Za-z0-9_-]+):\s*$", l)
    ]
    heads.append((len(lines), None))
    graph: dict[str, dict] = {}
    for k in range(len(heads) - 1):
        begin, jid = heads[k]
        body = lines[begin + 1 : heads[k + 1][0]]
        needs: list[str] = []
        cond: list[str] = []
        i = 0
        while i < len(body):
            m = re.match(r"^    (needs|if):(.*)$", body[i])
            if not m:
                i += 1
                continue
            key, rest = m.group(1), m.group(2).strip()
            value = [rest] if rest else []
            j = i + 1
            while j < len(body) and (not body[j].strip() or body[j].startswith("      ")):
                if body[j].strip():
                    value.append(body[j].strip())
                j += 1
            if key == "needs":
                joined = " ".join(value)
                needs = (
                    [x.strip().strip("\"'") for x in joined.strip("[]").split(",") if x.strip()]
                    if joined.startswith("[")
                    else [x.lstrip("- ").strip().strip("\"'") for x in value if x.strip()]
                )
            else:
                cond = value
            i = j
        graph[jid] = {"needs": needs, "if": " ".join(cond)}
    return graph


def assert_wiring(text: str) -> None:
    graph = parse_jobs(text)
    if GUARD_JOB not in graph:
        raise AssertionError(f"release.yml has no {GUARD_JOB} job")

    roots = [j for j, v in graph.items() if not v["needs"]]
    if roots != [GUARD_JOB]:
        raise AssertionError(
            f"release.yml must have {GUARD_JOB} as its only root job, found {roots}. "
            "A second root would run the release without consulting the guard."
        )

    if GATE not in graph["config"]["if"]:
        raise AssertionError(f"config is not gated on the guard verdict: {graph['config']['if']!r}")

    def reaches(job: str, target: str, seen: set[str] | None = None) -> bool:
        seen = seen or set()
        if job in seen:
            return False
        seen.add(job)
        return any(
            n == target or reaches(n, target, seen) for n in graph.get(job, {}).get("needs", [])
        )

    stranded = [j for j in graph if j != GUARD_JOB and not reaches(j, GUARD_JOB)]
    if stranded:
        raise AssertionError(
            f"these jobs do not descend from {GUARD_JOB}, so a duplicate would still "
            f"run them: {stranded}"
        )


WIRING_MUTATIONS: list[tuple[str, str, str]] = [
    ("drop the gate on config", GATE, "true"),
    ("detach config from the guard", "needs: duplicate_guard", "needs: []"),
]


def check_wiring() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert_wiring(text)

    for label, needle, replacement in WIRING_MUTATIONS:
        if needle not in text:
            raise AssertionError(f"wiring mutation '{label}' no longer applies: {needle}")
        try:
            assert_wiring(text.replace(needle, replacement, 1))
        except AssertionError:
            continue
        raise AssertionError(f"wiring mutation survived, so it is untested: {label}")

    print(f"ok: release.yml wiring, {len(WIRING_MUTATIONS)} mutations red")


if __name__ == "__main__":
    run_cases()
    falsify()
    check_wiring()
    print("duplicate-release-run guard: fixtures, falsification and wiring green")
