#!/usr/bin/env python3
"""Prove that every acceptance report reaches one authoritative verdict.

Every suite step in .github/workflows/acceptance.yml captures its process exit
and ends green by design, so all reports can reach the final gate. That split is
safe only when the workflow keeps these facts structurally bound:

  1. The reviewed inventory of report-producing suite commands is exact.
  2. Each command writes one literal JSON path, captures that same command's
     exit in ``rc``, and emits one deferred warning inside its ``rc != 0``
     branch. No suite step may emit a failure-level or dynamic annotation.
  3. Every suite runs before one ``if: always()`` verdict step. The verdict is
     one direct, unneutralized gate.py command and consumes the suite JSON paths
     one-for-one in the same order, with unique report names and paths.

This scanner deliberately enforces the workflow's current authoring grammar.
Acceptance steps use a literal ``run: |`` block, direct ``python3
scripts/acceptance/...`` commands, literal ``acceptance/*.json`` paths, ``rc``
as the capture variable, and a direct echo for the warning. A new spelling must
teach this guard how it preserves the same authority before CI accepts it.

``--self-test`` drives clean controls and adversarial mutants through the same
scanner. Exit 0 means every control passed and every mutant was rejected. Exit
1 means the proof failed, 2 means the workflow could not be read, and 64 is a
usage error.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
import shlex
import sys


SUFFIX = "(verdict comes from the gate step)"
VERDICT_PREFIX = "Acceptance verdict"
DEFERRED_PHRASE = "verdict deferred to the Acceptance verdict step"
WORKFLOW = ".github/workflows/acceptance.yml"


@dataclass(frozen=True)
class ExpectedSuite:
    script: str
    report_name: str
    report_path: str


EXPECTED_SUITES = (
    ExpectedSuite("scripts/acceptance/magic_repro.py", "magic", "acceptance/magic.json"),
    ExpectedSuite(
        "scripts/acceptance/brownfield_repro.py",
        "brownfield",
        "acceptance/brownfield.json",
    ),
    ExpectedSuite(
        "scripts/acceptance/response_budget_elisions.py",
        "response_budget",
        "acceptance/response_budget.json",
    ),
    ExpectedSuite(
        "scripts/acceptance/trace_spine_clipping_repro.py",
        "trace_spine",
        "acceptance/trace_spine.json",
    ),
    ExpectedSuite(
        "scripts/acceptance/parse_hole_repro.py",
        "parsehole",
        "acceptance/parsehole.json",
    ),
    ExpectedSuite(
        "scripts/acceptance/hydration_semantics_repro.py",
        "hydration_semantics",
        "acceptance/hydration_semantics.json",
    ),
    ExpectedSuite(
        "scripts/acceptance/same_owner_call_repro.py",
        "sameowner",
        "acceptance/sameowner.json",
    ),
    ExpectedSuite(
        "scripts/acceptance/memory_pressure_refusal.py",
        "memory_pressure",
        "acceptance/memory_pressure.json",
    ),
    ExpectedSuite(
        "scripts/acceptance/memory_pressure_refusal.py",
        "memory_footprint",
        "acceptance/memory_footprint.json",
    ),
    ExpectedSuite(
        "scripts/acceptance/init_memory_repro.py",
        "initmemory",
        "acceptance/initmemory.json",
    ),
    ExpectedSuite(
        "scripts/acceptance/registry_home_isolation.py",
        "registry_isolation",
        "acceptance/registry_isolation.json",
    ),
    ExpectedSuite(
        "scripts/acceptance/first_contact_honesty.py",
        "first_contact",
        "acceptance/first_contact.json",
    ),
    ExpectedSuite(
        "scripts/acceptance/eject_journal_repro.py",
        "eject_journal",
        "acceptance/eject_journal.json",
    ),
    ExpectedSuite(
        "scripts/acceptance/first_query_readiness_repro.py",
        "first_query",
        "acceptance/first_query.json",
    ),
    ExpectedSuite(
        "scripts/acceptance/verdict_limits_repro.py",
        "verdict_limits",
        "acceptance/verdict_limits.json",
    ),
    ExpectedSuite(
        "scripts/acceptance/working_copy_freshness_repro.py",
        "working_copy_freshness",
        "acceptance/working_copy_freshness.json",
    ),
    ExpectedSuite(
        "scripts/acceptance/vcs_read_surfaces_repro.py",
        "vcs_read_surfaces",
        "acceptance/vcs_read_surfaces.json",
    ),
    ExpectedSuite(
        "scripts/acceptance/init_budget_refusal.py",
        "init_budget",
        "acceptance/init_budget.json",
    ),
    ExpectedSuite(
        "scripts/acceptance/bridge_reach_repro.py",
        "bridge_reach",
        "acceptance/bridge_reach.json",
    ),
    ExpectedSuite(
        "scripts/acceptance/prose_query_parity_repro.py",
        "prose_parity",
        "acceptance/prose_parity.json",
    ),
)


STEP_RE = re.compile(r"^      - name:\s*(?P<name>.+?)\s*$", re.M)
TOP_KEY_RE = re.compile(r"^        (?P<key>[A-Za-z0-9_-]+):(?:\s*(?P<value>.*))?$")
SCRIPT_PATH_RE = re.compile(r"scripts/acceptance/[A-Za-z0-9_./-]+\.py")
ACTIVE_SCRIPT_RE = re.compile(
    r"(?m)^\s*(?:exec\s+)?python3\s+"
    r"(?P<script>scripts/acceptance/[A-Za-z0-9_./-]+\.py)(?=\s|\\|$)"
)
JSON_ARG_RE = re.compile(
    r"(?<![A-Za-z0-9_-])--json(?:=|\s+)"
    r"(?:\"(?P<double>[^\"]+)\"|'(?P<single>[^']+)'|(?P<plain>[^\s\\;|]+))"
)
RC_CAPTURE_RE = re.compile(r"\|\|\s*rc=\$\?\s*$")
NONZERO_IF_RE = re.compile(
    r'^if\s+\[\s+"\$rc"\s+-ne\s+0\s+\];\s+then$'
)


@dataclass
class Step:
    index: int
    name: str
    body: str
    values: dict[str, list[str]]
    run_style: str | None
    run_lines: list[str]


@dataclass
class ShellCommand:
    start: int
    end: int
    lines: list[str]

    @property
    def text(self) -> str:
        return "\n".join(self.lines)

    @property
    def collapsed(self) -> str:
        parts = []
        for line in self.lines:
            value = line.strip()
            if value.endswith("\\"):
                value = value[:-1].rstrip()
            if value:
                parts.append(value)
        return " ".join(parts)


@dataclass
class SuiteRun:
    step: Step
    script: str
    report_path: str


def decode_name(raw: str) -> str:
    raw = raw.strip()
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "\"'":
        return raw[1:-1]
    return raw


def parse_step(index: int, name: str, body: str) -> Step:
    values: dict[str, list[str]] = {}
    lines = body.splitlines()
    run_style = None
    run_lines: list[str] = []
    run_index = None
    for line_index, line in enumerate(lines[1:], start=1):
        match = TOP_KEY_RE.match(line)
        if not match:
            continue
        key = match.group("key")
        value = (match.group("value") or "").strip()
        values.setdefault(key, []).append(value)
        if key == "run" and run_index is None:
            run_index = line_index
            run_style = value
    if run_index is not None:
        if run_style in ("|", "|-", "|+"):
            for line in lines[run_index + 1:]:
                if TOP_KEY_RE.match(line):
                    break
                run_lines.append(line[10:] if line.startswith("          ") else line)
        elif run_style:
            run_lines = [run_style]
    return Step(index, decode_name(name), body, values, run_style, run_lines)


def split_steps(text: str) -> list[Step]:
    """Parse the acceptance job's supported six-space step grammar."""

    matches = list(STEP_RE.finditer(text))
    steps = []
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        steps.append(parse_step(index, match.group("name"), text[match.start():end]))
    return steps


def visible_shell_line(line: str, quote: str | None) -> tuple[str, str | None]:
    """Remove a shell comment while carrying quote state across physical lines."""

    output = []
    escaped = False
    for index, char in enumerate(line):
        if quote == "'":
            output.append(char)
            if char == "'":
                quote = None
            continue
        if escaped:
            output.append(char)
            escaped = False
            continue
        if char == "\\" and quote != "'":
            output.append(char)
            escaped = True
            continue
        if quote == '"':
            output.append(char)
            if char == '"':
                quote = None
            continue
        if char in "\"'":
            quote = char
            output.append(char)
            continue
        if char == "#" and (index == 0 or line[index - 1].isspace()):
            break
        output.append(char)
    return "".join(output).rstrip(), quote


def shell_commands(lines: list[str]) -> list[ShellCommand]:
    """Split the supported shell blocks into quote-aware logical commands."""

    commands = []
    current: list[str] = []
    start = 0
    quote = None
    for index, raw in enumerate(lines):
        visible, quote = visible_shell_line(raw, quote)
        if not visible.strip() and not current:
            continue
        if not current:
            start = index
        current.append(visible)
        continued = visible.rstrip().endswith("\\") and quote != "'"
        if quote is None and not continued:
            commands.append(ShellCommand(start, index, current))
            current = []
    if current:
        commands.append(ShellCommand(start, len(lines) - 1, current))
    return commands


def unquoted_projection(text: str) -> str:
    """Keep shell syntax outside quotes and blank quoted payloads."""

    output = []
    quote = None
    escaped = False
    for char in text:
        if quote == "'":
            output.append(" ")
            if char == "'":
                quote = None
            continue
        if escaped:
            output.append(" " if quote else char)
            escaped = False
            continue
        if char == "\\" and quote != "'":
            output.append(" " if quote else char)
            escaped = True
            continue
        if quote == '"':
            output.append(" ")
            if char == '"':
                quote = None
            continue
        if char in "\"'":
            quote = char
            output.append(" ")
        else:
            output.append(char)
    return "".join(output)


def has_control_operator(text: str) -> bool:
    projected = unquoted_projection(text)
    return bool(
        re.search(
            r"\|\||&&|;|(?<!\|)\|(?!\|)|(?<![>&])&(?![>&])",
            projected,
        )
    )


def split_unquoted_segments(text: str) -> list[str]:
    """Split commands at unquoted shell control operators for echo inspection."""

    segments = []
    current = []
    quote = None
    escaped = False
    index = 0
    while index < len(text):
        char = text[index]
        if quote == "'":
            current.append(char)
            if char == "'":
                quote = None
            index += 1
            continue
        if escaped:
            current.append(char)
            escaped = False
            index += 1
            continue
        if char == "\\" and quote != "'":
            current.append(char)
            escaped = True
            index += 1
            continue
        if quote == '"':
            current.append(char)
            if char == '"':
                quote = None
            index += 1
            continue
        if char in "\"'":
            quote = char
            current.append(char)
            index += 1
            continue
        operator = None
        for candidate in ("||", "&&", ";", "|"):
            if text.startswith(candidate, index):
                operator = candidate
                break
        if operator:
            if "".join(current).strip():
                segments.append("".join(current).strip())
            current = []
            index += len(operator)
            continue
        current.append(char)
        index += 1
    if "".join(current).strip():
        segments.append("".join(current).strip())
    return segments


def emitted_annotations(command: ShellCommand) -> list[str]:
    """Return echo or printf payload tokens that begin a workflow annotation."""

    payloads = []
    for segment in split_unquoted_segments(command.collapsed):
        try:
            words = shlex.split(segment)
        except ValueError:
            continue
        if not words:
            continue
        try:
            command_index = next(
                index for index, word in enumerate(words) if word in ("echo", "printf")
            )
        except StopIteration:
            continue
        for word in words[command_index + 1:]:
            if word.startswith("::"):
                payloads.append(word)
    return payloads


def extract_json_paths(command: ShellCommand) -> list[str]:
    paths = []
    for match in JSON_ARG_RE.finditer(command.text):
        paths.append(match.group("double") or match.group("single") or match.group("plain"))
    return paths


def workflow_json_paths(text: str) -> list[str]:
    """Find every literal --json path, including one outside a named step."""

    active = "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    )
    paths = []
    for match in JSON_ARG_RE.finditer(active):
        paths.append(match.group("double") or match.group("single") or match.group("plain"))
    return paths


def top_value(step: Step, key: str) -> str | None:
    values = step.values.get(key, [])
    return values[0] if len(values) == 1 else None


def inspect_suite_step(step: Step, command: ShellCommand) -> tuple[list[str], SuiteRun | None]:
    problems = []
    if step.run_style not in ("|", "|-", "|+"):
        problems.append("suite step %r must use a literal run block" % step.name)
    if step.values.get("continue-on-error"):
        problems.append("suite step %r must not use continue-on-error" % step.name)
    if not step.name.endswith(SUFFIX):
        problems.append(
            "suite step %r must end with %r so it cannot read as the verdict"
            % (step.name, SUFFIX)
        )

    active_scripts = ACTIVE_SCRIPT_RE.findall(command.text)
    all_scripts = SCRIPT_PATH_RE.findall(command.text)
    json_paths = extract_json_paths(command)
    if len(active_scripts) != 1 or len(all_scripts) != 1:
        problems.append(
            "suite step %r must contain one direct active acceptance script; "
            "found active=%r all=%r" % (step.name, active_scripts, all_scripts)
        )
    if len(json_paths) != 1:
        problems.append(
            "suite step %r must write one literal --json report; found %r"
            % (step.name, json_paths)
        )

    commands = shell_commands(step.run_lines)
    command_index = next(
        (
            i
            for i, value in enumerate(commands)
            if (value.start, value.end, value.text)
            == (command.start, command.end, command.text)
        ),
        None,
    )
    if command_index is None:
        problems.append("suite step %r lost its report command" % step.name)
    elif command_index == 0 or commands[command_index - 1].collapsed != "rc=0":
        problems.append(
            "suite step %r must initialize rc=0 immediately before its report command"
            % step.name
        )

    projected = unquoted_projection(command.collapsed).strip()
    capture = RC_CAPTURE_RE.search(projected)
    if not capture:
        problems.append(
            "suite step %r does not capture that report command with || rc=$?"
            % step.name
        )
    elif has_control_operator(projected[:capture.start()]):
        problems.append(
            "suite step %r has another shell control operator before its rc capture"
            % step.name
        )

    branch_indexes = [
        index for index, value in enumerate(commands)
        if NONZERO_IF_RE.match(value.collapsed)
    ]
    if len(branch_indexes) != 1:
        problems.append(
            "suite step %r must carry one if [ \"$rc\" -ne 0 ] warning branch; "
            "found %d" % (step.name, len(branch_indexes))
        )
        warning_index = None
    else:
        branch_index = branch_indexes[0]
        warning_index = branch_index + 1
        if command_index is not None and branch_index <= command_index:
            problems.append(
                "suite step %r warns before the report command it is meant to describe"
                % step.name
            )
        if warning_index >= len(commands) or branch_index + 2 >= len(commands):
            problems.append("suite step %r has an incomplete nonzero branch" % step.name)
            warning_index = None
        elif commands[branch_index + 2].collapsed != "fi":
            problems.append(
                "suite step %r must close the warning immediately after one emission"
                % step.name
            )
            warning_index = None

    annotations = []
    for index, value in enumerate(commands):
        for payload in emitted_annotations(value):
            annotations.append((index, payload))
    if warning_index is None or len(annotations) != 1 or annotations[0][0] != warning_index:
        problems.append(
            "suite step %r must emit exactly one annotation inside its nonzero branch; "
            "found %r" % (step.name, annotations)
        )
    elif not (
        annotations[0][1].startswith("::warning title=")
        and "$rc" in annotations[0][1]
        and DEFERRED_PHRASE in annotations[0][1]
    ):
        problems.append(
            "suite step %r must emit a literal deferred warning for the captured rc; got %r"
            % (step.name, annotations[0][1])
        )

    if len(active_scripts) == 1 and len(all_scripts) == 1 and len(json_paths) == 1:
        return problems, SuiteRun(step, active_scripts[0], json_paths[0])
    return problems, None


def report_invocations(step: Step) -> tuple[list[str], list[SuiteRun]]:
    problems = []
    found = []
    for command in shell_commands(step.run_lines):
        if "--json" not in command.text or not SCRIPT_PATH_RE.search(command.text):
            continue
        step_problems, suite = inspect_suite_step(step, command)
        problems.extend(step_problems)
        if suite:
            found.append(suite)
    if len(found) > 1:
        problems.append(
            "suite step %r contains %d report-producing commands; use one step per report"
            % (step.name, len(found))
        )
    return problems, found


def parse_gate_reports(command: ShellCommand) -> tuple[list[str], list[tuple[str, str]]]:
    problems = []
    try:
        words = shlex.split(command.collapsed)
    except ValueError as error:
        return ["the Acceptance verdict command does not parse: %s" % error], []
    if words[:2] != ["python3", "scripts/acceptance/gate.py"]:
        problems.append(
            "the Acceptance verdict must directly execute python3 scripts/acceptance/gate.py"
        )
        return problems, []
    reports = []
    index = 2
    while index < len(words):
        word = words[index]
        value = None
        if word == "--report":
            if index + 1 >= len(words):
                problems.append("the Acceptance verdict has --report with no value")
                break
            value = words[index + 1]
            index += 2
        elif word.startswith("--report="):
            value = word.split("=", 1)[1]
            index += 1
        else:
            index += 1
        if value is None:
            continue
        if "=" not in value:
            problems.append("the Acceptance verdict report is not NAME=PATH: %r" % value)
            continue
        name, path = value.split("=", 1)
        reports.append((name, path))
    names = [name for name, _ in reports]
    paths = [path for _, path in reports]
    if len(names) != len(set(names)):
        problems.append("the Acceptance verdict carries duplicate report names: %r" % names)
    if len(paths) != len(set(paths)):
        problems.append("the Acceptance verdict carries duplicate report paths: %r" % paths)
    return problems, reports


def inspect_verdict(step: Step) -> tuple[list[str], list[tuple[str, str]]]:
    problems = []
    if top_value(step, "if") not in ("always()", "${{ always() }}"):
        problems.append("the Acceptance verdict must carry if: always()")
    if step.values.get("continue-on-error"):
        problems.append("the Acceptance verdict must not use continue-on-error")
    if step.run_style not in ("|", "|-", "|+"):
        problems.append("the Acceptance verdict must use one literal run block")
    commands = shell_commands(step.run_lines)
    if len(commands) != 1:
        problems.append(
            "the Acceptance verdict run block must contain exactly one command; found %d"
            % len(commands)
        )
        return problems, []
    command = commands[0]
    if has_control_operator(command.collapsed):
        problems.append(
            "the Acceptance verdict command must not be piped, chained, or exit-neutralized"
        )
    gate_problems, reports = parse_gate_reports(command)
    problems.extend(gate_problems)
    return problems, reports


def duplicates(values: list[str]) -> list[str]:
    return sorted({value for value in values if values.count(value) > 1})


def check(text: str, expected: tuple[ExpectedSuite, ...] = EXPECTED_SUITES) -> list[str]:
    problems = []
    steps = split_steps(text)
    if not steps:
        return ["no steps parsed from the workflow, so nothing was checked"]

    verdict_steps = [step for step in steps if step.name.startswith(VERDICT_PREFIX)]
    if len(verdict_steps) != 1:
        problems.append(
            "exactly one step name must begin with %r; found %d"
            % (VERDICT_PREFIX, len(verdict_steps))
        )
        verdict = None
        gate_reports = []
    else:
        verdict = verdict_steps[0]
        verdict_problems, gate_reports = inspect_verdict(verdict)
        problems.extend(verdict_problems)

    suite_runs = []
    for step in steps:
        step_problems, found = report_invocations(step)
        problems.extend(step_problems)
        suite_runs.extend(found)
    if not suite_runs:
        problems.append("no report-producing suite commands were found")

    suite_paths = [suite.report_path for suite in suite_runs]
    all_json_paths = workflow_json_paths(text)
    if all_json_paths != suite_paths:
        problems.append(
            "literal workflow --json paths escaped the named suite inventory:\n"
            "  workflow=%r\n  suites=%r" % (all_json_paths, suite_paths)
        )
    duplicate_suite_paths = duplicates(suite_paths)
    if duplicate_suite_paths:
        problems.append("suite JSON paths are duplicated: %r" % duplicate_suite_paths)
    if verdict:
        late = [suite.step.name for suite in suite_runs if suite.step.index >= verdict.index]
        if late:
            problems.append("suite steps must precede the Acceptance verdict: %r" % late)

    actual_inventory = [(suite.script, suite.report_path) for suite in suite_runs]
    expected_inventory = [(suite.script, suite.report_path) for suite in expected]
    if actual_inventory != expected_inventory:
        problems.append(
            "report-producing suite inventory or order changed:\n  actual=%r\n  expected=%r"
            % (actual_inventory, expected_inventory)
        )

    expected_gate = [(suite.report_name, suite.report_path) for suite in expected]
    if gate_reports != expected_gate:
        problems.append(
            "Acceptance verdict report inventory or order changed:\n  actual=%r\n  expected=%r"
            % (gate_reports, expected_gate)
        )
    gate_paths = [path for _, path in gate_reports]
    if suite_paths != gate_paths:
        problems.append(
            "suite JSON outputs and gate report inputs are not one-to-one in order:\n"
            "  suites=%r\n  gate=%r" % (suite_paths, gate_paths)
        )
    return problems


def make_step(name: str, body_lines: list[str], quoted: bool = False) -> str:
    rendered_name = '"%s"' % name if quoted else name
    return "      - name: %s\n" % rendered_name + "".join(
        "        %s\n" % line for line in body_lines
    )


def suite_step(
    script: str = "scripts/acceptance/example.py",
    path: str = "acceptance/example.json",
    name: str = "Example suite %s" % SUFFIX,
    json_equals: bool = False,
    extra_lines: list[str] | None = None,
    quoted_name: bool = False,
) -> str:
    json_arg = "--json=%s" % path if json_equals else "--json %s" % path
    lines = [
        "run: |",
        "  rc=0",
        "  python3 %s %s >acceptance/example.log 2>&1 || rc=$?" % (script, json_arg),
    ]
    lines.extend(extra_lines or [])
    lines.extend(
        [
            '  if [ "$rc" -ne 0 ]; then',
            '    echo "::warning title=Example suite returned nonzero::exit $rc; %s"'
            % DEFERRED_PHRASE,
            "  fi",
        ]
    )
    return make_step(name, lines, quoted=quoted_name)


def gate_step(
    reports: list[tuple[str, str]] | None = None,
    condition: str | None = "always()",
    suffix: str = "",
    comment_only: bool = False,
    continue_on_error: bool = False,
) -> str:
    reports = reports if reports is not None else [("example", "acceptance/example.json")]
    lines = []
    if condition is not None:
        lines.append("if: %s" % condition)
    if continue_on_error:
        lines.append("continue-on-error: true")
    lines.append("run: |")
    prefix = "  # " if comment_only else "  "
    command = prefix + "python3 scripts/acceptance/gate.py"
    for name, path in reports:
        command += " --report %s=%s" % (name, path)
    command += suffix
    lines.append(command)
    return make_step("Acceptance verdict, gated on the suite reports", lines)


def self_test() -> int:
    expected = (
        ExpectedSuite(
            "scripts/acceptance/example.py", "example", "acceptance/example.json"
        ),
    )
    control = suite_step() + gate_step()
    supported = (
        suite_step(
            script="scripts/acceptance/nested/example-extra.py",
            path="acceptance/nested.json",
            json_equals=True,
            quoted_name=True,
            extra_lines=['  echo "prose mentions ::error but emits no workflow command"'],
        )
        + gate_step([("nested", "acceptance/nested.json")])
    )
    supported_expected = (
        ExpectedSuite(
            "scripts/acceptance/nested/example-extra.py",
            "nested",
            "acceptance/nested.json",
        ),
    )

    failures = []
    controls = (("canonical", control, expected), ("supported spellings", supported, supported_expected))
    for label, workflow, inventory in controls:
        found = check(workflow, inventory)
        if found:
            failures.append("control %r was rejected: %r" % (label, found))

    proper_warning = [
        '  if [ "$rc" -ne 0 ]; then',
        '    echo "::warning title=Example suite returned nonzero::exit $rc; %s"'
        % DEFERRED_PHRASE,
        "  fi",
    ]
    expected_two = (
        expected[0],
        ExpectedSuite(
            "scripts/acceptance/example-extra.py",
            "extra",
            "acceptance/extra.json",
        ),
    )
    two_suites = suite_step() + suite_step(
        script="scripts/acceptance/example-extra.py",
        path="acceptance/extra.json",
        name="Extra suite %s" % SUFFIX,
    )
    mutants = {
        "suffix missing": (suite_step(name="Example suite") + gate_step(), expected),
        "second verdict step": (control + gate_step(), expected),
        "suite omitted from gate": (
            suite_step() + gate_step([("other", "acceptance/other.json")]),
            expected,
        ),
        "extra gate report": (
            suite_step()
            + gate_step(
                [
                    ("example", "acceptance/example.json"),
                    ("other", "acceptance/other.json"),
                ]
            ),
            expected,
        ),
        "duplicate gate report name": (
            suite_step()
            + gate_step(
                [
                    ("example", "acceptance/example.json"),
                    ("example", "acceptance/other.json"),
                ]
            ),
            expected,
        ),
        "duplicate gate report path": (
            suite_step()
            + gate_step(
                [
                    ("example", "acceptance/example.json"),
                    ("other", "acceptance/example.json"),
                ]
            ),
            expected,
        ),
        "verdict before suite": (gate_step() + suite_step(), expected),
        "gate report order differs from suite order": (
            two_suites
            + gate_step(
                [
                    ("extra", "acceptance/extra.json"),
                    ("example", "acceptance/example.json"),
                ]
            ),
            expected_two,
        ),
        "gate path only in a comment": (
            suite_step() + gate_step(comment_only=True),
            expected,
        ),
        "gate path mentioned after echo": (
            suite_step()
            + make_step(
                "Acceptance verdict, gated on the suite reports",
                [
                    "if: always()",
                    "run: |",
                    "  echo pass # python3 scripts/acceptance/gate.py",
                ],
            ),
            expected,
        ),
        "gate exit neutralized": (suite_step() + gate_step(suffix=" || true"), expected),
        "gate sent to background": (suite_step() + gate_step(suffix=" &"), expected),
        "successful command follows gate": (
            suite_step()
            + make_step(
                "Acceptance verdict, gated on the suite reports",
                [
                    "if: always()",
                    "run: |",
                    "  python3 scripts/acceptance/gate.py --report example=acceptance/example.json",
                    "  echo pass",
                ],
            ),
            expected,
        ),
        "gate missing always": (suite_step() + gate_step(condition=None), expected),
        "gate false condition": (
            suite_step() + gate_step(condition="${{ false }}"),
            expected,
        ),
        "gate continue-on-error": (
            suite_step() + gate_step(continue_on_error=True),
            expected,
        ),
        "comment-only capture and warning": (
            make_step(
                "Example suite %s" % SUFFIX,
                [
                    "run: |",
                    "  rc=0",
                    "  python3 scripts/acceptance/example.py --json acceptance/example.json",
                    "  # || rc=$?",
                    "  # if [ \"$rc\" -ne 0 ]; then",
                    '  # echo "::warning title=Example::exit $rc; %s"'
                    % DEFERRED_PHRASE,
                    "  # fi",
                ],
            )
            + gate_step(),
            expected,
        ),
        "unrelated exit capture": (
            make_step(
                "Example suite %s" % SUFFIX,
                [
                    "run: |",
                    "  rc=0",
                    "  python3 scripts/acceptance/example.py --json acceptance/example.json",
                    "  echo unrelated || rc=$?",
                    *proper_warning,
                ],
            )
            + gate_step(),
            expected,
        ),
        "unconditional warning": (
            make_step(
                "Example suite %s" % SUFFIX,
                [
                    "run: |",
                    "  rc=0",
                    "  python3 scripts/acceptance/example.py --json acceptance/example.json || rc=$?",
                    '  echo "::warning title=Example::exit $rc; %s"'
                    % DEFERRED_PHRASE,
                ],
            )
            + gate_step(),
            expected,
        ),
        "warning bound to another variable": (
            make_step(
                "Example suite %s" % SUFFIX,
                [
                    "run: |",
                    "  rc=0",
                    "  python3 scripts/acceptance/example.py --json acceptance/example.json || rc=$?",
                    '  if [ "$other" -ne 0 ]; then',
                    '    echo "::warning title=Example::exit $rc; %s"'
                    % DEFERRED_PHRASE,
                    "  fi",
                ],
            )
            + gate_step(),
            expected,
        ),
        "dynamic error annotation": (
            suite_step(
                extra_lines=[
                    "  kind=error",
                    '  echo "::${kind} title=Premature::bad"',
                ]
            )
            + gate_step(),
            expected,
        ),
        "hyphenated extra suite": (
            suite_step()
            + suite_step(
                script="scripts/acceptance/example-extra.py",
                path="acceptance/extra.json",
                name="Extra suite %s" % SUFFIX,
            )
            + gate_step(),
            expected,
        ),
        "duplicate suite JSON path": (
            suite_step()
            + suite_step(
                script="scripts/acceptance/example-extra.py",
                path="acceptance/example.json",
                name="Duplicate suite %s" % SUFFIX,
            )
            + gate_step(),
            expected,
        ),
        "unnamed extra suite": (
            control
            + "      - run: |\n"
            + "          rc=0\n"
            + "          python3 scripts/acceptance/unnamed-extra.py "
            + "--json acceptance/unnamed.json || rc=$?\n",
            expected,
        ),
    }
    for label, (workflow, inventory) in mutants.items():
        if not check(workflow, inventory):
            failures.append("mutant %r passed the check" % label)
    for failure in failures:
        print("SELF-TEST FAIL: %s" % failure)
    if failures:
        return 1
    print(
        "self-test: all %d controls clean, all %d adversarial mutants caught"
        % (len(controls), len(mutants))
    )
    return 0


def main() -> int:
    if "--self-test" in sys.argv[1:]:
        return self_test()
    if sys.argv[1:]:
        print("usage: test_workflow_step_visibility.py [--self-test]")
        return 64
    try:
        text = open(WORKFLOW).read()
    except OSError as error:
        print("cannot read %s: %s" % (WORKFLOW, error))
        return 2
    problems = check(text)
    for problem in problems:
        print("VIOLATION: %s" % problem)
    if problems:
        return 1
    # Counted from the reviewed inventory rather than written out. A hardcoded
    # total drifts the moment a suite is added, and it drifts downward silently:
    # the guard keeps passing while its own summary understates what it graded.
    print(
        "workflow authority holds: %d suite reports reach one always-running verdict in order"
        % len(EXPECTED_SUITES)
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
