#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

"""The mint's evaluate-now dispatch: authority, algorithm choice, and refusals.

release-tag.yml carries two repository_dispatch types. `release_tag` is break
glass: the caller names an exact tag and sha, and the sha must be current main
HEAD. `release_tag_evaluate` runs the scheduled algorithm on demand and names
nothing.

The second exists because the schedule cannot be the only route to the
automatic path. On 2026-09-02 GitHub's cron produced one scheduled mint run on
this repository between 09:58Z and 14:22Z, and the only manual trigger was break
glass, which correctly refused a proven candidate that was no longer main's tip.

What has to hold, and what this file proves:

1. Both types pass the SAME authority checks. A new trigger that widened who may
   mint would be a far worse defect than the one it fixes.
2. The evaluate type resolves `automatic=true`, so it takes the range selection
   and the reviewed-ancestor admission rather than the break-glass equality.
3. The break-glass type is untouched: still `automatic=false`, still equality
   against main HEAD.
4. The evaluate type REFUSES a payload carrying a tag or a sha. Ignoring one
   would tag a commit the caller did not choose while they believed otherwise.
5. An unknown dispatch action is still refused.

The two shell fragments are extracted from the workflow and run under `bash`
with the event environment set, so these are the real guards rather than a
paraphrase of them. Extraction is asserted, so a renamed step fails loudly
instead of silently testing nothing.
"""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "release-tag.yml"


def extract_step_run(workflow: str, step_name: str) -> str:
    """Pull one step's `run:` body out of the workflow, dedented."""
    anchor = f"      - name: {step_name}\n"
    if anchor not in workflow:
        raise AssertionError(
            f"step '{step_name}' is gone from release-tag.yml, so this test would "
            "prove nothing. Update the anchor deliberately."
        )
        # unreachable, kept explicit
    start = workflow.index(anchor)
    tail = workflow[start:]
    run_at = tail.index("\n        run: |\n") + len("\n        run: |\n")
    body_start = start + run_at
    # Cut at the next step only. A blank-line marker looks tempting and is
    # wrong: every line of a run body is indented, so a "blank line then
    # indentation" pattern matches inside the body and silently truncates it at
    # the first paragraph break.
    rest = workflow[body_start:]
    idx = rest.find("\n      - name:")
    end = body_start + idx if idx != -1 else len(workflow)
    body = workflow[body_start:end]
    lines = [l[10:] if l.startswith(" " * 10) else l for l in body.split("\n")]
    return "\n".join(lines).rstrip() + "\n"


def run_fragment(script: str, env: dict[str, str], cwd: Path | None = None):
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as fh:
        fh.write(script)
        path = fh.name
    try:
        return subprocess.run(
            ["bash", path],
            env={"PATH": "/usr/bin:/bin:/usr/local/bin", **env},
            capture_output=True,
            text=True,
            timeout=60,
            cwd=str(cwd) if cwd else None,
        )
    finally:
        Path(path).unlink(missing_ok=True)


# ---- 1. authority is identical for both types ----------------------------

GUARD_BASE = {
    "ACTOR": "troyjr4103",
    "REF": "refs/heads/main",
    "EVENT_SHA": "a" * 40,
    "DEFAULT_BRANCH": "main",
    "ALLOWED_ACTORS": "troyjr4103\nkin-release-bot[bot]\n",
}


def guard_cases(guard: str) -> None:
    def check(name: str, over: dict[str, str], want_rc: int) -> None:
        env = {"EVENT_NAME": "repository_dispatch", **GUARD_BASE, **over}
        got = run_fragment(guard, env)
        if (got.returncode == 0) != (want_rc == 0):
            raise AssertionError(
                f"guard {name}: rc={got.returncode}, wanted {'0' if want_rc == 0 else 'non-zero'}\n"
                f"stdout={got.stdout}\nstderr={got.stderr}"
            )

    # Both types admitted for an allowed actor on main.
    check("evaluate admitted", {"EVENT_ACTION": "release_tag_evaluate"}, 0)
    check("break glass admitted", {"EVENT_ACTION": "release_tag"}, 0)
    # An unknown action is still refused.
    check("unknown action refused", {"EVENT_ACTION": "release_tag_please"}, 1)
    check("empty action refused", {"EVENT_ACTION": ""}, 1)

    # The authority checks apply to the NEW type exactly as to the old one.
    # Each of these would be a widened mint if it passed.
    for action in ("release_tag", "release_tag_evaluate"):
        check(f"{action}: foreign actor", {"EVENT_ACTION": action, "ACTOR": "mallory"}, 1)
        check(
            f"{action}: off-main ref",
            {"EVENT_ACTION": action, "REF": "refs/heads/feature"},
            1,
        )
        check(
            f"{action}: non-hex sha",
            {"EVENT_ACTION": action, "EVENT_SHA": "not-a-sha"},
            1,
        )
        check(
            f"{action}: default branch not main",
            {"EVENT_ACTION": action, "DEFAULT_BRANCH": "trunk"},
            1,
        )

    # An automatic trigger short-circuits before any of it.
    for event in ("schedule", "workflow_run"):
        got = run_fragment(guard, {"EVENT_NAME": event, **GUARD_BASE, "EVENT_ACTION": ""})
        if got.returncode != 0:
            raise AssertionError(f"guard refused automatic trigger {event}: {got.stderr}")

    print("ok: trigger authority, both types under identical checks")


# ---- 2. the resolve arm picks the right algorithm ------------------------
#
# The resolve step's full body reaches for the network and the version range, so
# the arm under test is the case statement that sets `automatic` and `sha`. It
# is extracted from the workflow by its own markers rather than retyped.


def extract_dispatch_arm(resolve: str) -> str:
    """The case statement that sets `automatic` and `sha`, already dedented."""
    marker = 'case "$EVENT_NAME" in'
    if marker not in resolve:
        raise AssertionError(
            "the resolve step no longer opens with a case on $EVENT_NAME, so the "
            "arm under test cannot be located"
        )
    start = resolve.index(marker)
    end = resolve.index("\nesac", start) + len("\nesac")
    return resolve[start:end]


def resolve_cases(resolve: str) -> None:
    arm = extract_dispatch_arm(resolve)
    for needle in ("release_tag_evaluate", "RAW_TAG", "automatic=false"):
        if needle not in arm:
            raise AssertionError(f"resolve arm lost '{needle}', so this test proves nothing")

    # A stand-in for `git rev-parse refs/remotes/origin/main`, so the arm runs
    # with no repository. Everything else is the workflow's own text.
    head = "b" * 40
    harness = (
        "set -euo pipefail\n"
        "git() { if [ \"$1\" = rev-parse ]; then printf '%s\\n' \"$MAIN_HEAD\"; "
        "else return 0; fi; }\n"
        "automatic=true\n"
        "tag=\"\"\n"
        "sha=\"\"\n"
        + arm
        + "\nprintf 'automatic=%s tag=%s sha=%s\\n' \"$automatic\" \"$tag\" \"$sha\"\n"
    )

    def check(name: str, env: dict[str, str], want_rc: int, want: str | None) -> None:
        got = run_fragment(harness, {"MAIN_HEAD": head, "RAW_TAG": "", "RAW_SHA": "", **env})
        if (got.returncode == 0) != (want_rc == 0):
            raise AssertionError(
                f"resolve {name}: rc={got.returncode} wanted {want_rc}\n"
                f"stdout={got.stdout}\nstderr={got.stderr}"
            )
        if want is not None and want not in got.stdout:
            raise AssertionError(f"resolve {name}: wanted {want!r} in stdout, got {got.stdout!r}")

    # Evaluate runs the automatic algorithm against main HEAD, naming nothing.
    check(
        "evaluate is automatic",
        {"EVENT_NAME": "repository_dispatch", "EVENT_ACTION": "release_tag_evaluate"},
        0,
        f"automatic=true tag= sha={head}",
    )
    # Break glass is untouched.
    check(
        "break glass unchanged",
        {
            "EVENT_NAME": "repository_dispatch",
            "EVENT_ACTION": "release_tag",
            "RAW_TAG": "v0.6.4",
            "RAW_SHA": "C" * 40,
        },
        0,
        f"automatic=false tag=v0.6.4 sha={'c' * 40}",
    )
    # Evaluate refuses a named commit rather than ignoring it.
    check(
        "evaluate refuses a sha",
        {
            "EVENT_NAME": "repository_dispatch",
            "EVENT_ACTION": "release_tag_evaluate",
            "RAW_SHA": "d" * 40,
        },
        1,
        None,
    )
    check(
        "evaluate refuses a tag",
        {
            "EVENT_NAME": "repository_dispatch",
            "EVENT_ACTION": "release_tag_evaluate",
            "RAW_TAG": "v9.9.9",
        },
        1,
        None,
    )
    # The scheduled arm still reads main HEAD.
    check(
        "schedule is automatic",
        {"EVENT_NAME": "schedule", "EVENT_ACTION": ""},
        0,
        f"automatic=true tag= sha={head}",
    )
    print("ok: resolve picks the automatic algorithm for evaluate and leaves break glass alone")


# ---- 3. falsification ----------------------------------------------------


def falsify(workflow_text: str) -> None:
    """Break one rule at a time; the suite must go red for each."""
    guard_name = "Guard trigger authority"
    resolve_name = "Resolve exact coherent release commit"

    mutations = [
        (
            "admit the evaluate type without the actor allowlist",
            'release_tag|release_tag_evaluate) ;;',
            'release_tag) ;;\n            release_tag_evaluate) exit 0 ;;',
        ),
        (
            "let evaluate keep a caller-named sha",
            'if [ -n "$RAW_TAG" ] || [ -n "$RAW_SHA" ]; then',
            "if false; then",
        ),
        (
            "make evaluate take the break-glass algorithm",
            'if [ "$EVENT_ACTION" = release_tag_evaluate ]; then',
            "if false; then",
        ),
    ]

    for label, needle, replacement in mutations:
        if needle not in workflow_text:
            raise AssertionError(f"mutation '{label}' no longer applies: {needle}")
        broken = workflow_text.replace(needle, replacement, 1)
        try:
            guard_cases(extract_step_run(broken, guard_name))
            resolve_cases(extract_step_run(broken, resolve_name))
        except AssertionError:
            continue
        raise AssertionError(f"mutation survived, so it is untested: {label}")

    print(f"ok: {len(mutations)} workflow mutations each turned the suite red")


def main() -> int:
    text = WORKFLOW.read_text(encoding="utf-8")
    if "release_tag_evaluate" not in text:
        raise AssertionError("release-tag.yml declares no release_tag_evaluate dispatch")
    if "types: [release_tag, release_tag_evaluate]" not in text:
        raise AssertionError("the evaluate type is not declared on the repository_dispatch trigger")

    guard_cases(extract_step_run(text, "Guard trigger authority"))
    resolve_cases(extract_step_run(text, "Resolve exact coherent release commit"))
    falsify(text)
    print("release-tag evaluate dispatch: authority, algorithm and refusals hold")
    return 0


if __name__ == "__main__":
    sys.exit(main())
