#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

"""Fail a pull request that reintroduces a quietly-skipped Release Sentinel.

`release-sentinel-credential-alarm.py` and `release-rail-parked-alarm.py` each
falsify their own judgment logic against fixtures. Neither can prove the WORKFLOW
actually wires them the way this ticket requires: that the job which alarms on a
missing credential cannot itself be skipped by the same condition it exists to
report on, and that the mechanical patrol carries no dependency on the credential
job at all. A script's self-test cannot see its own workflow file, so this is a
separate, narrow check over `.github/workflows/release-sentinel.yml`'s raw text,
in the same spirit as `check-rc-build-drift.mjs`: no YAML library, just enough
line-based structure to answer four questions no amount of judge-logic testing
can:

  1. Do `preflight`, `credential-alarm`, `patrol` and `mechanical-patrol` all
     still exist as jobs?
  2. Does `credential-alarm` carry `if: always()` (so it cannot be skipped by
     `preflight`'s own conclusion, which is what let the original bug read as a
     skipped step rather than a failed job) and call the credential-alarm
     script, with no `continue-on-error` that would swallow its exit code?
  3. Does `patrol` still gate on `needs.preflight.outputs.enabled == 'true'`,
     unchanged, so it never runs the agent duties without a credential?
  4. Does `mechanical-patrol` call the parked-rail script while mentioning
     neither `preflight` nor anything Claude-credential-shaped anywhere in its
     own job body, so it truly cannot go dark for the reason the agent duties
     can?

Falsified with `--self-test` against small synthetic workflow-shaped text
fixtures, one good and one broken per question above, so each assertion is
proven to actually fire rather than being a check that cannot fail.
"""

import os
import sys

WORKFLOW_PATH = ".github/workflows/release-sentinel.yml"

REQUIRED_JOBS = ("preflight", "credential-alarm", "patrol", "mechanical-patrol")

# Anything in this list appearing anywhere in mechanical-patrol's own job body is a
# defect: that job must need no Claude credential and no output from preflight.
FORBIDDEN_IN_MECHANICAL_PATROL = (
    "preflight",
    "CLAUDE_CODE_OAUTH_TOKEN_TROY_FIRELOCK_AI",
    "claude_code_oauth_token",
    "anthropics/claude-code-action",
)


def repo_root():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def split_jobs(text):
    """Return {job_name: body_text} for every top-level job under `jobs:`.

    A job key is a two-space-indented identifier immediately followed by a colon
    with nothing else on the line, e.g. '  patrol:'. Scanning starts only AFTER
    the top-level 'jobs:' line, because 'on:' carries its own two-space-indented
    colon-only keys ('  schedule:', '  workflow_dispatch:') that are not jobs and
    would otherwise be misread as some.
    """
    lines = text.split("\n")
    try:
        jobs_at = lines.index("jobs:")
    except ValueError:
        return None

    starts = []
    for i in range(jobs_at + 1, len(lines)):
        line = lines[i]
        if line.startswith("  ") and not line.startswith("   ") and line.rstrip().endswith(":"):
            key = line.strip()[:-1]
            if key and (key[0].isalpha() or key[0] == "_"):
                starts.append((i, key))
    if not starts:
        return {}

    jobs = {}
    for idx, (start, key) in enumerate(starts):
        end = starts[idx + 1][0] if idx + 1 < len(starts) else len(lines)
        jobs[key] = "\n".join(lines[start:end])
    return jobs


def check(text):
    """Return a list of problems; empty means the shape holds."""
    jobs = split_jobs(text)
    if jobs is None:
        return ["no top-level 'jobs:' key found"]
    if not jobs:
        return ["'jobs:' exists but no job keys were found under it"]

    problems = [
        "expected job '%s' is missing" % name
        for name in REQUIRED_JOBS
        if name not in jobs
    ]
    if problems:
        # Can't meaningfully inspect a job body that does not exist.
        return problems

    cred_alarm = jobs["credential-alarm"]
    if "if: always()" not in cred_alarm:
        problems.append(
            "credential-alarm carries no 'if: always()': without it, a future edit "
            "(a needs: chain, a changed gate) can make this job skip exactly when it "
            "exists to report, reproducing the original silent-skip shape"
        )
    if "release-sentinel-credential-alarm.py" not in cred_alarm:
        problems.append("credential-alarm does not call release-sentinel-credential-alarm.py")
    if "continue-on-error" in cred_alarm:
        problems.append(
            "credential-alarm sets continue-on-error, which would keep the run green "
            "even when the alarm script fails, exactly the quiet-success shape this "
            "job exists to end"
        )

    patrol = jobs["patrol"]
    if "needs.preflight.outputs.enabled == 'true'" not in patrol:
        problems.append(
            "patrol no longer gates on needs.preflight.outputs.enabled == 'true'; it "
            "would run the agent duties with no credential, or never run them even "
            "with one"
        )

    mech = jobs["mechanical-patrol"]
    if "release-rail-parked-alarm.py" not in mech:
        problems.append("mechanical-patrol does not call release-rail-parked-alarm.py")
    for forbidden in FORBIDDEN_IN_MECHANICAL_PATROL:
        if forbidden in mech:
            problems.append(
                "mechanical-patrol's job body mentions %r; it must need no Claude "
                "credential and no output from preflight, or it can go dark for the "
                "same reason the agent duties can" % forbidden
            )

    return problems


# ─── Controls ───────────────────────────────────────────────────────────────

GOOD_FIXTURE = """\
name: Release Sentinel
on:
  schedule:
    - cron: "11,41 * * * *"
  workflow_dispatch:
permissions:
  contents: read
concurrency:
  group: kin-release-sentinel
  cancel-in-progress: false
jobs:
  preflight:
    name: Resolve sentinel credential
    runs-on: ubuntu-latest
    outputs:
      enabled: ${{ steps.credential.outputs.enabled }}
    steps:
      - run: echo resolve

  credential-alarm:
    name: Alarm when the sentinel has no credential to patrol with
    needs: preflight
    if: always()
    steps:
      - run: python3 scripts/release-sentinel-credential-alarm.py --self-test
      - run: python3 scripts/release-sentinel-credential-alarm.py --repo x --enabled y

  patrol:
    name: Patrol the release rail
    needs: preflight
    if: needs.preflight.outputs.enabled == 'true'
    steps:
      - run: echo patrol

  mechanical-patrol:
    name: Patrol the RC-Build-to-Release-Cut handoff mechanically
    steps:
      - run: python3 scripts/release-rail-parked-alarm.py --self-test
      - run: python3 scripts/release-rail-parked-alarm.py --repo x
"""


def _replace_once(text, old, new, label):
    if text.count(old) != 1:
        raise AssertionError("fixture setup %r matched %d times, expected 1" % (label, text.count(old)))
    return text.replace(old, new)


def self_test():
    failures = []

    def check_control(name, cond):
        print("CONTROL %s %s" % ("PASS" if cond else "FAIL", name))
        if not cond:
            failures.append(name)

    check_control("the good fixture has no problems", check(GOOD_FIXTURE) == [])

    missing_job = GOOD_FIXTURE.replace(
        "  mechanical-patrol:\n"
        "    name: Patrol the RC-Build-to-Release-Cut handoff mechanically\n"
        "    steps:\n"
        "      - run: python3 scripts/release-rail-parked-alarm.py --self-test\n"
        "      - run: python3 scripts/release-rail-parked-alarm.py --repo x\n",
        "",
    )
    problems = check(missing_job)
    check_control("a removed mechanical-patrol job is caught",
                   any("mechanical-patrol" in p and "missing" in p for p in problems))

    no_always = _replace_once(
        GOOD_FIXTURE, "    if: always()\n", "    if: needs.preflight.result == 'success'\n",
        "credential-alarm if: always()",
    )
    problems = check(no_always)
    check_control("credential-alarm losing 'if: always()' is caught",
                   any("if: always()" in p for p in problems))

    continue_on_error = _replace_once(
        GOOD_FIXTURE,
        "    needs: preflight\n    if: always()\n",
        "    needs: preflight\n    if: always()\n    continue-on-error: true\n",
        "credential-alarm continue-on-error insertion",
    )
    problems = check(continue_on_error)
    check_control("credential-alarm gaining continue-on-error is caught",
                   any("continue-on-error" in p for p in problems))

    no_script_call = _replace_once(
        GOOD_FIXTURE,
        "      - run: python3 scripts/release-sentinel-credential-alarm.py --self-test\n"
        "      - run: python3 scripts/release-sentinel-credential-alarm.py --repo x --enabled y\n",
        "      - run: echo nothing\n",
        "credential-alarm script calls",
    )
    problems = check(no_script_call)
    check_control("credential-alarm no longer calling the alarm script is caught",
                   any("does not call release-sentinel-credential-alarm.py" in p for p in problems))

    patrol_ungated = _replace_once(
        GOOD_FIXTURE,
        "    if: needs.preflight.outputs.enabled == 'true'\n",
        "    if: always()\n",
        "patrol gate",
    )
    problems = check(patrol_ungated)
    check_control("patrol losing its enabled == 'true' gate is caught",
                   any("patrol no longer gates" in p for p in problems))

    mech_needs_preflight = _replace_once(
        GOOD_FIXTURE,
        "  mechanical-patrol:\n"
        "    name: Patrol the RC-Build-to-Release-Cut handoff mechanically\n",
        "  mechanical-patrol:\n"
        "    name: Patrol the RC-Build-to-Release-Cut handoff mechanically\n"
        "    needs: preflight\n"
        "    if: needs.preflight.outputs.enabled == 'true'\n",
        "mechanical-patrol needs: preflight insertion",
    )
    problems = check(mech_needs_preflight)
    check_control("mechanical-patrol regaining a dependency on preflight is caught",
                   any("'preflight'" in p for p in problems))

    mech_uses_token = _replace_once(
        GOOD_FIXTURE,
        "      - run: python3 scripts/release-rail-parked-alarm.py --repo x\n",
        "      - run: python3 scripts/release-rail-parked-alarm.py --repo x\n"
        "      - env:\n"
        "          T: ${{ secrets.CLAUDE_CODE_OAUTH_TOKEN_TROY_FIRELOCK_AI }}\n"
        "        run: echo hi\n",
        "mechanical-patrol token insertion",
    )
    problems = check(mech_uses_token)
    check_control("mechanical-patrol referencing the Claude token is caught",
                   any("CLAUDE_CODE_OAUTH_TOKEN_TROY_FIRELOCK_AI" in p for p in problems))

    # THE REGRESSION this whole script exists for: the ORIGINAL shape (preflight
    # exits 0, patrol gated, nothing else) must be reported as missing jobs, never
    # silently accepted as "fine, nothing to alarm on".
    original_shape = """\
jobs:
  preflight:
    name: Resolve sentinel credential
    outputs:
      enabled: ${{ steps.credential.outputs.enabled }}
    steps:
      - run: echo resolve

  patrol:
    name: Patrol the release rail
    needs: preflight
    if: needs.preflight.outputs.enabled == 'true'
    steps:
      - run: echo patrol
"""
    problems = check(original_shape)
    check_control("THE REGRESSION: the pre-fix shape (no alarm, no mechanical patrol) is rejected",
                   len(problems) >= 2
                   and any("credential-alarm" in p for p in problems)
                   and any("mechanical-patrol" in p for p in problems))

    print("check-release-sentinel-shape: self-test %s"
          % ("PASSED" if not failures else "FAILED on %s" % ", ".join(failures)))
    return 1 if failures else 0


def main(argv):
    if "--self-test" in argv[1:]:
        return self_test()

    path = os.path.join(repo_root(), WORKFLOW_PATH)
    try:
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
    except OSError as exc:
        print("::error::could not read %s: %s" % (path, exc))
        return 1

    problems = check(text)
    if problems:
        for problem in problems:
            print("::error::%s" % problem)
        return 1
    print(
        "%s: shape holds (preflight, credential-alarm, patrol and mechanical-patrol "
        "all present and correctly wired)" % WORKFLOW_PATH
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
