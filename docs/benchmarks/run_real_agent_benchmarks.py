#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable


ROOT = Path("/Users/troyfortinjr/GitHub/kin")
KIN_BIN = ROOT / "target" / "debug" / "kin"
CLAUDE_BIN = Path("/Users/troyfortinjr/.local/bin/claude")
CODEX_BIN = Path("/Applications/Codex.app/Contents/Resources/codex")
GEMINI_BIN = Path("/Users/troyfortinjr/.nvm/versions/node/v24.13.0/bin/gemini")
RESULTS_ROOT = ROOT / "docs" / "benchmarks" / "results" / "2026-03-10-real-agent-git-vs-kin"
WORK_ROOT = Path("/tmp/kin-real-agent-bench")


@dataclass
class TaskSpec:
    name: str
    repo_name: str
    repo_path: Path
    summary: str
    git_prompt: str
    kin_prompt: str
    validate: Callable[[Path], tuple[bool, str]]


@dataclass
class RunResult:
    task: str
    repo: str
    agent: str
    substrate: str
    workspace: str
    artifact_path: str
    final_output_path: str | None
    elapsed_ms: int
    input_tokens: int
    output_tokens: int
    total_tokens: int
    estimated_cost_usd: float | None
    validation_passed: bool
    validation_note: str
    files_touched: list[str]
    tool_calls: int
    model_name: str | None
    response_excerpt: str
    kin_commands_used: str | None


def run(
    args: list[str],
    *,
    cwd: Path,
    stdout_path: Path | None = None,
    stderr_path: Path | None = None,
    timeout: int = 900,
) -> tuple[int, int]:
    stdout_handle = open(stdout_path, "w") if stdout_path else subprocess.DEVNULL
    stderr_handle = open(stderr_path, "w") if stderr_path else subprocess.DEVNULL
    start = time.perf_counter()
    try:
        try:
            completed = subprocess.run(
                args,
                cwd=str(cwd),
                check=False,
                timeout=timeout,
                stdout=stdout_handle,
                stderr=stderr_handle,
                text=True,
                env=os.environ.copy(),
            )
            elapsed_ms = int((time.perf_counter() - start) * 1000)
            return completed.returncode, elapsed_ms
        except subprocess.TimeoutExpired:
            elapsed_ms = int((time.perf_counter() - start) * 1000)
            return 124, elapsed_ms
    finally:
        if stdout_path:
            stdout_handle.close()
        if stderr_path:
            stderr_handle.close()


def reset_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def copy_repo(src: Path, dest: Path) -> None:
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(src, dest, dirs_exist_ok=False)


def prepare_kin_repo(workspace: Path, agent: str) -> None:
    run([str(KIN_BIN), "init", str(workspace)], cwd=ROOT)
    run([str(KIN_BIN), "commit", "-m", "baseline import"], cwd=workspace, timeout=1200)
    run([str(KIN_BIN), "assistant", "configure", "--enable", "AGENTS.md"], cwd=workspace)

    target = None
    if agent == "claude":
        target = "CLAUDE.md"
    elif agent == "codex":
        target = "CODEX.md"
    elif agent == "gemini":
        target = "GEMINI.md"

    if target is not None:
        run([str(KIN_BIN), "assistant", "configure", "--enable", target], cwd=workspace)

    run([str(KIN_BIN), "assistant", "sync"], cwd=workspace)


def validate_snapdocs(workspace: Path) -> tuple[bool, str]:
    app_js = workspace / "js" / "app.js"
    module_js = workspace / "js" / "app.module.js"
    tests_dir = workspace / "tests"
    helper_name = "sortDocumentsNewestFirst"

    for file_path in [app_js, module_js]:
        check = subprocess.run(
            ["node", "--check", str(file_path)],
            cwd=str(workspace),
            check=False,
            capture_output=True,
            text=True,
        )
        if check.returncode != 0:
            return False, f"node --check failed for {file_path.name}: {check.stderr.strip()}"

    app_text = app_js.read_text()
    module_text = module_js.read_text()
    tests_text = "\n".join(path.read_text() for path in tests_dir.rglob("*.js"))

    if helper_name not in app_text:
        return False, f"{helper_name} missing from js/app.js"
    if helper_name not in module_text:
        return False, f"{helper_name} missing from js/app.module.js"
    if helper_name not in tests_text:
        return False, f"{helper_name} missing from tests"

    return True, "helper exists in both runtime files and tests; JavaScript parses cleanly"


def validate_coachai(workspace: Path) -> tuple[bool, str]:
    result_path = workspace / "benchmark_gameplan_flow.json"
    if not result_path.exists():
        return False, "benchmark_gameplan_flow.json was not created"

    try:
        data = json.loads(result_path.read_text())
    except json.JSONDecodeError as exc:
        return False, f"invalid JSON output: {exc}"

    payload = json.dumps(data)
    required_fragments = [
        "src/app/week/[weekId]/page.tsx",
        "src/app/api/game-plan/generate/route.ts",
        "src/app/api/game-plan/route.ts",
        "src/lib/db.ts",
        "src/lib/prompts.ts",
    ]
    missing = [fragment for fragment in required_fragments if fragment not in payload]
    if missing:
        return False, f"missing expected flow references: {', '.join(missing)}"
    return True, "JSON flow trace contains the expected UI, API, prompt, and persistence files"


TASKS = [
    TaskSpec(
        name="snapdocs_sort_helper",
        repo_name="snapdocs",
        repo_path=Path("/Users/troyfortinjr/GitHub/snapdocs"),
        summary="Extract newest-first gallery ordering into a reusable helper and cover it with a test.",
        git_prompt=(
            "You are in a disposable working copy of the snapdocs repo. "
            "Do not use Kin commands. Implement this change:\n"
            "- add a reusable helper named sortDocumentsNewestFirst that returns documents ordered newest-first by timestamp, "
            "falling back to id for deterministic ordering when timestamps match or are missing\n"
            "- use that helper in the gallery rendering path\n"
            "- keep js/app.js and js/app.module.js aligned\n"
            "- add or update one test so the helper ordering is covered\n"
            "Constraints:\n"
            "- do not install packages\n"
            "- do not start servers\n"
            "- keep edits minimal\n"
            "At the end, print lines exactly in this shape:\n"
            "RESULT: <success|failure>\n"
            "KIN_COMMANDS_USED: none\n"
            "FILES: <comma separated paths>\n"
        ),
        kin_prompt=(
            "You are in a disposable working copy of the snapdocs repo that is already initialized with Kin. "
            "Read the repo guidance files first if present (AGENTS.md plus any assistant-specific file), then use Kin to orient yourself. "
            "Prefer these commands over broad repo scans where useful:\n"
            f"- {KIN_BIN} support\n"
            f"- {KIN_BIN} search renderGallery\n"
            f"- {KIN_BIN} search loadDocuments\n"
            f"- {KIN_BIN} search createGalleryItem\n"
            "Then implement this change:\n"
            "- add a reusable helper named sortDocumentsNewestFirst that returns documents ordered newest-first by timestamp, "
            "falling back to id for deterministic ordering when timestamps match or are missing\n"
            "- use that helper in the gallery rendering path\n"
            "- keep js/app.js and js/app.module.js aligned\n"
            "- add or update one test so the helper ordering is covered\n"
            "Constraints:\n"
            "- do not install packages\n"
            "- do not start servers\n"
            "- keep edits minimal\n"
            "At the end, print lines exactly in this shape:\n"
            "RESULT: <success|failure>\n"
            "KIN_COMMANDS_USED: <comma separated Kin commands you actually used>\n"
            "FILES: <comma separated paths>\n"
        ),
        validate=validate_snapdocs,
    ),
    TaskSpec(
        name="coachai_gameplan_trace",
        repo_name="CoachAI",
        repo_path=Path("/Users/troyfortinjr/GitHub/CoachAI"),
        summary="Trace the game-plan generation flow into a structured JSON file.",
        git_prompt=(
            "You are in a disposable working copy of the CoachAI repo. "
            "Do not use Kin commands. Create a file named benchmark_gameplan_flow.json in the repo root. "
            "It must contain valid JSON with these keys: ui_entrypoints, api_routes, supporting_libs, prompts_or_tools, persistence, summary. "
            "Trace the end-to-end flow for generating a game plan, including the UI trigger, the API routes involved, the prompt builder, "
            "and the persistence layer used to save or load the plan.\n"
            "Constraints:\n"
            "- do not install packages\n"
            "- do not modify application code\n"
            "- only add the JSON file\n"
            "At the end, print lines exactly in this shape:\n"
            "RESULT: <success|failure>\n"
            "KIN_COMMANDS_USED: none\n"
            "FILES: benchmark_gameplan_flow.json\n"
        ),
        kin_prompt=(
            "You are in a disposable working copy of the CoachAI repo that is already initialized with Kin. "
            "Read the repo guidance files first if present (AGENTS.md plus any assistant-specific file), then use Kin to orient yourself. "
            "Prefer these commands over broad repo scans where useful:\n"
            f"- {KIN_BIN} support\n"
            f"- {KIN_BIN} search generateGamePlan\n"
            f"- {KIN_BIN} search GAME_PLAN_PROMPT\n"
            f"- {KIN_BIN} search upsertGamePlan\n"
            "Then create a file named benchmark_gameplan_flow.json in the repo root. "
            "It must contain valid JSON with these keys: ui_entrypoints, api_routes, supporting_libs, prompts_or_tools, persistence, summary. "
            "Trace the end-to-end flow for generating a game plan, including the UI trigger, the API routes involved, the prompt builder, "
            "and the persistence layer used to save or load the plan.\n"
            "Constraints:\n"
            "- do not install packages\n"
            "- do not modify application code\n"
            "- only add the JSON file\n"
            "At the end, print lines exactly in this shape:\n"
            "RESULT: <success|failure>\n"
            "KIN_COMMANDS_USED: <comma separated Kin commands you actually used>\n"
            "FILES: benchmark_gameplan_flow.json\n"
        ),
        validate=validate_coachai,
    ),
]


def parse_claude_output(path: Path) -> tuple[int, int, int, float | None, str | None, str, str | None]:
    data = json.loads(path.read_text())
    usage = data.get("usage", {})
    model_usage = data.get("modelUsage", {})
    model_name = next(iter(model_usage.keys()), None)
    input_tokens = int(
        usage.get("input_tokens", 0)
        + usage.get("cache_creation_input_tokens", 0)
        + usage.get("cache_read_input_tokens", 0)
    )
    output_tokens = int(usage.get("output_tokens", 0))
    response = data.get("result", "")
    kin_commands = extract_kin_commands(response)
    return (
        input_tokens,
        output_tokens,
        input_tokens + output_tokens,
        float(data.get("total_cost_usd", 0.0)),
        model_name,
        response,
        kin_commands,
    )


def parse_codex_output(path: Path, final_path: Path) -> tuple[int, int, int, float | None, str | None, list[str], int, str, str | None]:
    input_tokens = 0
    output_tokens = 0
    files: list[str] = []
    file_set = set()
    tool_calls = 0
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        payload = json.loads(line)
        line_type = payload.get("type")
        if line_type == "turn.completed":
            usage = payload.get("usage", {})
            input_tokens = int(usage.get("input_tokens", 0) + usage.get("cached_input_tokens", 0))
            output_tokens = int(usage.get("output_tokens", 0))
        item = payload.get("item", {})
        if item.get("type") == "file_change":
            for change in item.get("changes", []):
                change_path = change.get("path")
                if change_path and change_path not in file_set:
                    file_set.add(change_path)
                    files.append(change_path)
        if item.get("type") == "command_execution":
            tool_calls += 1

    response = final_path.read_text().strip() if final_path.exists() else ""
    kin_commands = extract_kin_commands(response)
    return (
        input_tokens,
        output_tokens,
        input_tokens + output_tokens,
        None,
        None,
        files,
        tool_calls,
        response,
        kin_commands,
    )


def parse_gemini_output(path: Path) -> tuple[int, int, int, float | None, str | None, int, str, str | None]:
    data = json.loads(path.read_text())
    models = data.get("stats", {}).get("models", {})
    model_name = ",".join(models.keys()) if models else None
    input_tokens = 0
    output_tokens = 0
    total_tokens = 0
    for stats in models.values():
        tokens = stats.get("tokens", {})
        input_tokens += int(tokens.get("input", 0))
        output_tokens += int(tokens.get("candidates", 0))
        total_tokens += int(tokens.get("total", 0))
    tool_calls = int(data.get("stats", {}).get("tools", {}).get("totalCalls", 0))
    response = data.get("response", "")
    kin_commands = extract_kin_commands(response)
    return (
        input_tokens,
        output_tokens,
        total_tokens or (input_tokens + output_tokens),
        None,
        model_name,
        tool_calls,
        response,
        kin_commands,
    )


def extract_kin_commands(response: str) -> str | None:
    marker = "KIN_COMMANDS_USED:"
    if marker not in response:
        return None
    tail = response.split(marker, 1)[1].strip()
    return tail.splitlines()[0].strip()


def create_workspace(task: TaskSpec, substrate: str, agent: str) -> Path:
    workspace = WORK_ROOT / task.name / f"{agent}-{substrate}"
    copy_repo(task.repo_path, workspace)
    if substrate == "kin":
        prepare_kin_repo(workspace, agent)
    return workspace


def run_claude(prompt: str, workspace: Path, out_dir: Path) -> RunResult:
    artifact = out_dir / "claude-result.json"
    stderr = out_dir / "claude.stderr.log"
    returncode, elapsed_ms = run(
        [
            str(CLAUDE_BIN),
            "-p",
            "--dangerously-skip-permissions",
            "--output-format",
            "json",
            prompt,
        ],
        cwd=workspace,
        stdout_path=artifact,
        stderr_path=stderr,
        timeout=1200,
    )
    input_tokens, output_tokens, total_tokens, cost, model_name, response, kin_commands = parse_claude_output(artifact)
    passed, note = CURRENT_TASK.validate(workspace)
    if returncode != 0:
        passed = False
        note = f"agent exited with code {returncode}"
    return RunResult(
        task=CURRENT_TASK.name,
        repo=CURRENT_TASK.repo_name,
        agent="claude",
        substrate=CURRENT_SUBSTRATE,
        workspace=str(workspace),
        artifact_path=str(artifact),
        final_output_path=None,
        elapsed_ms=elapsed_ms,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        total_tokens=total_tokens,
        estimated_cost_usd=cost,
        validation_passed=passed,
        validation_note=note,
        files_touched=[],
        tool_calls=0,
        model_name=model_name,
        response_excerpt=response[:400],
        kin_commands_used=kin_commands,
    )


def run_codex(prompt: str, workspace: Path, out_dir: Path) -> RunResult:
    artifact = out_dir / "codex-output.jsonl"
    final_output = out_dir / "codex-final.txt"
    stderr = out_dir / "codex.stderr.log"
    returncode, elapsed_ms = run(
        [
            str(CODEX_BIN),
            "exec",
            "--dangerously-bypass-approvals-and-sandbox",
            "--json",
            "-o",
            str(final_output),
            prompt,
        ],
        cwd=workspace,
        stdout_path=artifact,
        stderr_path=stderr,
        timeout=1200,
    )
    (
        input_tokens,
        output_tokens,
        total_tokens,
        cost,
        model_name,
        files_touched,
        tool_calls,
        response,
        kin_commands,
    ) = parse_codex_output(artifact, final_output)
    passed, note = CURRENT_TASK.validate(workspace)
    if returncode != 0:
        passed = False
        note = f"agent exited with code {returncode}"
    return RunResult(
        task=CURRENT_TASK.name,
        repo=CURRENT_TASK.repo_name,
        agent="codex",
        substrate=CURRENT_SUBSTRATE,
        workspace=str(workspace),
        artifact_path=str(artifact),
        final_output_path=str(final_output),
        elapsed_ms=elapsed_ms,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        total_tokens=total_tokens,
        estimated_cost_usd=cost,
        validation_passed=passed,
        validation_note=note,
        files_touched=files_touched,
        tool_calls=tool_calls,
        model_name=model_name,
        response_excerpt=response[:400],
        kin_commands_used=kin_commands,
    )


def run_gemini(prompt: str, workspace: Path, out_dir: Path) -> RunResult:
    artifact = out_dir / "gemini-result.json"
    stderr = out_dir / "gemini.stderr.log"
    returncode, elapsed_ms = run(
        [
            str(GEMINI_BIN),
            "-p",
            prompt,
            "--yolo",
            "--output-format",
            "json",
        ],
        cwd=workspace,
        stdout_path=artifact,
        stderr_path=stderr,
        timeout=1200,
    )
    (
        input_tokens,
        output_tokens,
        total_tokens,
        cost,
        model_name,
        tool_calls,
        response,
        kin_commands,
    ) = parse_gemini_output(artifact)
    passed, note = CURRENT_TASK.validate(workspace)
    if returncode != 0:
        passed = False
        note = f"agent exited with code {returncode}"
    return RunResult(
        task=CURRENT_TASK.name,
        repo=CURRENT_TASK.repo_name,
        agent="gemini",
        substrate=CURRENT_SUBSTRATE,
        workspace=str(workspace),
        artifact_path=str(artifact),
        final_output_path=None,
        elapsed_ms=elapsed_ms,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        total_tokens=total_tokens,
        estimated_cost_usd=cost,
        validation_passed=passed,
        validation_note=note,
        files_touched=[],
        tool_calls=tool_calls,
        model_name=model_name,
        response_excerpt=response[:400],
        kin_commands_used=kin_commands,
    )


RUNNERS = {
    "claude": run_claude,
    "codex": run_codex,
    "gemini": run_gemini,
}


CURRENT_TASK: TaskSpec
CURRENT_SUBSTRATE: str


def choose_prompt(task: TaskSpec, substrate: str) -> str:
    return task.kin_prompt if substrate == "kin" else task.git_prompt


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2))


def aggregate(results: list[RunResult]) -> dict:
    grouped: dict[tuple[str, str], dict[str, RunResult]] = {}
    for result in results:
        grouped.setdefault((result.task, result.agent), {})[result.substrate] = result

    comparisons = []
    for (task, agent), pair in sorted(grouped.items()):
        git = pair.get("git")
        kin = pair.get("kin")
        if not git or not kin:
            continue
        duration_delta_ms = git.elapsed_ms - kin.elapsed_ms
        token_delta = git.total_tokens - kin.total_tokens
        comparisons.append(
            {
                "task": task,
                "agent": agent,
                "git_elapsed_ms": git.elapsed_ms,
                "kin_elapsed_ms": kin.elapsed_ms,
                "duration_saved_ms_by_kin": duration_delta_ms,
                "duration_saved_pct_by_kin": round((duration_delta_ms / git.elapsed_ms) * 100, 2)
                if git.elapsed_ms
                else 0.0,
                "git_total_tokens": git.total_tokens,
                "kin_total_tokens": kin.total_tokens,
                "tokens_saved_by_kin": token_delta,
                "tokens_saved_pct_by_kin": round((token_delta / git.total_tokens) * 100, 2)
                if git.total_tokens
                else 0.0,
                "git_validation_passed": git.validation_passed,
                "kin_validation_passed": kin.validation_passed,
            }
        )

    return {
        "runs": [asdict(result) for result in results],
        "comparisons": comparisons,
    }


def write_report(results: list[RunResult], summary: dict) -> None:
    report_path = RESULTS_ROOT / "REPORT.md"
    lines = [
        "# Real Git vs Kin Agent Benchmarks",
        "",
        "These benchmarks compare the same task on plain Git workspaces vs Kin-initialized workspaces.",
        "Kin repo prep (`kin init` + baseline `kin commit`) was done before timing so the timings reflect task execution, not first-time setup.",
        "",
        "## Tasks",
        "",
    ]

    for task in TASKS:
        lines.append(f"- `{task.name}` on `{task.repo_name}`: {task.summary}")
    lines.extend(["", "## Git vs Kin by Agent", ""])

    for comparison in summary["comparisons"]:
        directly_comparable = (
            comparison["git_validation_passed"]
            and comparison["kin_validation_passed"]
            and comparison["git_total_tokens"] > 0
            and comparison["kin_total_tokens"] > 0
        )
        lines.extend(
            [
                f"### {comparison['task']} / {comparison['agent']}",
                "",
                f"- Git: `{comparison['git_elapsed_ms']} ms`, `{comparison['git_total_tokens']}` total tokens, validation `{comparison['git_validation_passed']}`",
                f"- Kin: `{comparison['kin_elapsed_ms']} ms`, `{comparison['kin_total_tokens']}` total tokens, validation `{comparison['kin_validation_passed']}`",
                (
                    f"- Kin delta: `{comparison['duration_saved_ms_by_kin']} ms` ({comparison['duration_saved_pct_by_kin']}%), "
                    f"`{comparison['tokens_saved_by_kin']}` tokens ({comparison['tokens_saved_pct_by_kin']}%)"
                    if directly_comparable
                    else "- Comparison caveat: at least one run failed validation or did not emit usable token data."
                ),
                "",
            ]
        )

    lines.extend(["## Raw Runs", ""])
    for result in results:
        lines.extend(
            [
                f"### {result.task} / {result.agent} / {result.substrate}",
                "",
                f"- Repo: `{result.repo}`",
                f"- Elapsed: `{result.elapsed_ms} ms`",
                f"- Tokens: `{result.input_tokens} in / {result.output_tokens} out / {result.total_tokens} total`",
                f"- Validation: `{result.validation_passed}`",
                f"- Note: {result.validation_note}",
                f"- Model: `{result.model_name}`" if result.model_name else "- Model: unavailable",
                f"- Cost: `${result.estimated_cost_usd:.4f}`" if result.estimated_cost_usd is not None else "- Cost: unavailable from artifact",
                f"- Tool calls: `{result.tool_calls}`",
                f"- Files touched: `{', '.join(result.files_touched)}`" if result.files_touched else "- Files touched: unavailable",
                f"- Kin commands used: `{result.kin_commands_used}`" if result.kin_commands_used else "- Kin commands used: not reported",
                "",
            ]
        )

    report_path.write_text("\n".join(lines))


def main() -> None:
    reset_dir(WORK_ROOT)
    RESULTS_ROOT.mkdir(parents=True, exist_ok=True)

    results: list[RunResult] = []
    for task in TASKS:
        for substrate in ["git", "kin"]:
            for agent, runner in RUNNERS.items():
                out_dir = RESULTS_ROOT / "artifacts" / task.name / f"{agent}-{substrate}"
                out_dir.mkdir(parents=True, exist_ok=True)

                workspace = create_workspace(task, substrate, agent)
                prompt = choose_prompt(task, substrate)

                global CURRENT_TASK, CURRENT_SUBSTRATE
                CURRENT_TASK = task
                CURRENT_SUBSTRATE = substrate

                result = runner(prompt, workspace, out_dir)
                results.append(result)
                write_json(out_dir / "run-summary.json", asdict(result))

    summary = aggregate(results)
    write_json(RESULTS_ROOT / "summary.json", summary)
    write_report(results, summary)


if __name__ == "__main__":
    main()
