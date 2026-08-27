#!/usr/bin/env python3
"""Enforce that no acceptance suite step can be mistaken for the verdict.

Every suite step in .github/workflows/acceptance.yml captures its own exit code
and ends green by design, so all suites run and allowance semantics stay with
the gate. That design has a reading hazard, and it fired: a green suite step
was cited as proof inside a failing job (relay-ci2-20260822.md). The workflow
answers it with naming, and this check makes the naming a rule a diff cannot
silently drop:

  1. Every step that runs an acceptance suite for real (a scripts/acceptance
     script writing --json into acceptance/) carries the suffix
     "(verdict comes from the gate step)" in its name.
  2. Every such step still captures its exit code (`|| rc=$?`) and carries a
     ::warning annotation that says the nonzero result is deferred to the
     verdict step. A suite step must not emit ::error or call itself failed,
     because an explicitly allowed UNREADABLE is not a failed gate.
  3. Exactly one step name begins with "Acceptance verdict", and its run block
     invokes scripts/acceptance/gate.py. The verdict has one home.

Self-test: --self-test drives the scanner over embedded mutants (a suite step
with the suffix missing, a second verdict-named step, a suite step without the
deferred warning, a suite step that emits a premature error, and a clean
control) and fails if any mutant passes or the control fails. Exit 0 all good,
1 a rule is violated, 2 the workflow could not be parsed, 64 usage.
"""
from __future__ import annotations

import re
import sys

SUFFIX = "(verdict comes from the gate step)"
VERDICT_PREFIX = "Acceptance verdict"
DEFERRED_PHRASE = "verdict deferred to the Acceptance verdict step"
WORKFLOW = ".github/workflows/acceptance.yml"

STEP_RE = re.compile(r"^      - name: (?P<name>.+?)\s*$", re.M)


def split_steps(text: str) -> list[tuple[str, str]]:
    """Return (name, body) for every step, body running to the next step."""
    steps = []
    matches = list(STEP_RE.finditer(text))
    if not matches:
        return steps
    for i, m in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        steps.append((m.group("name"), text[m.start():end]))
    return steps


def is_suite_step(body: str) -> bool:
    """A real suite run: an acceptance script writing --json into acceptance/.

    The falsify steps run the same scripts with --self-test and no --json, and
    the gate reads reports rather than writing one, so this shape selects
    exactly the eight run steps and nothing else.
    """
    return bool(
        re.search(r"scripts/acceptance/\w+\.py", body)
        and re.search(r"--json acceptance/", body)
    )


def check(text: str) -> list[str]:
    problems = []
    steps = split_steps(text)
    if not steps:
        return ["no steps parsed from the workflow, so nothing was checked"]
    verdict_steps = [(n, b) for n, b in steps if n.startswith(VERDICT_PREFIX)]
    if len(verdict_steps) != 1:
        problems.append(
            "exactly one step name must begin with %r; found %d"
            % (VERDICT_PREFIX, len(verdict_steps))
        )
    else:
        if "scripts/acceptance/gate.py" not in verdict_steps[0][1]:
            problems.append(
                "the %r step must invoke scripts/acceptance/gate.py" % VERDICT_PREFIX
            )
    suite_steps = [(n, b) for n, b in steps if is_suite_step(b)]
    if not suite_steps:
        problems.append(
            "no suite-run steps matched the scanner, so the rule guarded nothing"
        )
    for name, body in suite_steps:
        if not name.endswith(SUFFIX):
            problems.append(
                "suite step %r must end with %r so it cannot read as the verdict"
                % (name, SUFFIX)
            )
        if "|| rc=$?" not in body:
            problems.append(
                "suite step %r no longer captures its exit code; a raw exit would "
                "let an allowed UNREADABLE redden the job past the gate" % name
            )
        if "::warning title=" not in body or DEFERRED_PHRASE not in body:
            problems.append(
                "suite step %r carries no deferred ::warning annotation, so its "
                "nonzero result can be mistaken for the verdict" % name
            )
        if "::error" in body or "suite failed" in body.lower():
            problems.append(
                "suite step %r claims failure before the acceptance gate has "
                "applied its exact, reasoned UNREADABLE allowances" % name
            )
    return problems


def make_step(name: str, body_lines: list[str]) -> str:
    return "      - name: %s\n" % name + "".join("        %s\n" % l for l in body_lines)


def self_test() -> int:
    suite_body = [
        "run: |",
        "  python3 scripts/acceptance/example.py --json acceptance/example.json || rc=$?",
        '  echo "::warning title=Example suite nonzero::exit $rc; '
        + DEFERRED_PHRASE
        + '"',
    ]
    gate_body = ["run: python3 scripts/acceptance/gate.py --report x=acceptance/x.json"]
    control = (
        make_step("Example suite %s" % SUFFIX, suite_body)
        + make_step("Acceptance verdict, gated on the suite reports", gate_body)
    )
    failures = []
    if check(control):
        failures.append("control: a clean workflow was reported as violating")
    mutants = {
        "suffix missing": (
            make_step("Example suite", suite_body)
            + make_step("Acceptance verdict, gated", gate_body)
        ),
        "second verdict step": (
            make_step("Example suite %s" % SUFFIX, suite_body)
            + make_step("Acceptance verdict, gated", gate_body)
            + make_step("Acceptance verdict, again", gate_body)
        ),
        "deferred warning missing": (
            make_step(
                "Example suite %s" % SUFFIX,
                [
                    "run: |",
                    "  python3 scripts/acceptance/example.py --json acceptance/e.json || rc=$?",
                ],
            )
            + make_step("Acceptance verdict, gated", gate_body)
        ),
        "premature failure annotation": (
            make_step(
                "Example suite %s" % SUFFIX,
                [
                    "run: |",
                    "  python3 scripts/acceptance/example.py --json acceptance/e.json || rc=$?",
                    '  echo "::error title=Example suite failed::exit $rc"',
                    '  echo "::warning title=Example suite nonzero::exit $rc; '
                    + DEFERRED_PHRASE
                    + '"',
                ],
            )
            + make_step("Acceptance verdict, gated", gate_body)
        ),
        "verdict without gate.py": (
            make_step("Example suite %s" % SUFFIX, suite_body)
            + make_step("Acceptance verdict, gated", ["run: echo not the gate"])
        ),
    }
    for label, mutant in mutants.items():
        if not check(mutant):
            failures.append("mutant %r passed the check, so the rule cannot fail" % label)
    for f in failures:
        print("SELF-TEST FAIL: %s" % f)
    if failures:
        return 1
    print("self-test: control clean, all %d mutants caught" % len(mutants))
    return 0


def main() -> int:
    if "--self-test" in sys.argv[1:]:
        return self_test()
    if sys.argv[1:]:
        print("usage: test_workflow_step_visibility.py [--self-test]")
        return 64
    try:
        text = open(WORKFLOW).read()
    except OSError as exc:
        print("cannot read %s: %s" % (WORKFLOW, exc))
        return 2
    problems = check(text)
    for p in problems:
        print("VIOLATION: %s" % p)
    if problems:
        return 1
    print("workflow step visibility holds: every suite step defers to the one verdict step")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
