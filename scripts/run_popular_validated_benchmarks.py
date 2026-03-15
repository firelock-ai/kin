#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
import os
import re
import statistics
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
KIN = ROOT / "target" / "release" / "kin"
OUTPUT_DIR = ROOT / ".kin" / "bench"

POPULAR_REPOS = [
    ("express", "https://github.com/expressjs/express.git"),
    ("axios", "https://github.com/axios/axios.git"),
    ("hono", "https://github.com/honojs/hono.git"),
    ("zod", "https://github.com/colinhacks/zod.git"),
    ("flask", "https://github.com/pallets/flask.git"),
    ("typer", "https://github.com/fastapi/typer.git"),
    ("requests", "https://github.com/psf/requests.git"),
    ("redux", "https://github.com/reduxjs/redux.git"),
    ("click", "https://github.com/pallets/click.git"),
    ("dayjs", "https://github.com/iamkun/dayjs.git"),
]

DEFAULT_ARMS = ["git", "kin-native"]
TASK_ORDER = [
    "count-real-callers",
    "find-dead-code",
    "find-planted-secret",
    "fix-planted-bug",
    "implement-stub",
    "trace-computation",
    "trace-type-imports",
]
REPORT_RE = re.compile(r"Report saved to:\s*(.+)")


@dataclass
class RepoSummary:
    repo_name: str
    repo_url: str
    report_path: str
    language: str
    entities: int
    files: int
    git_total_s: float
    kin_compat_total_s: float | None
    kin_native_total_s: float | None
    kin_native_cli_total_s: float | None
    best_arm: str | None
    best_total_s: float | None
    best_savings_pct: float | None
    best_wins: int
    native_wins: int
    compat_wins: int
    native_cli_wins: int
    validations: dict[str, int]
    task_results: dict[str, dict[str, dict[str, object]]]
    health: dict[str, object]


def run_benchmark(
    repo_name: str, repo_url: str, repeat: int, assistant: str, arms: list[str]
) -> Path:
    cmd = [
        str(KIN),
        "bench",
        "live",
        "--repo",
        repo_url,
        "--task-set",
        "validated",
        "--assistant",
        assistant,
        "--repeat",
        str(repeat),
        "--fresh-conversion",
    ]
    if assistant == "claude":
        cmd.append("--claude-disable-explore")
    for arm in arms:
        cmd.extend(["--arm", arm])

    print(f"\n=== {repo_name} ===", flush=True)
    print(" ".join(cmd), flush=True)
    proc = subprocess.run(
        cmd,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env={**os.environ, "PATH": f"{Path.home() / '.cargo' / 'bin'}:{os.environ.get('PATH', '')}"},
    )
    out = proc.stdout
    log_path = OUTPUT_DIR / f"matrix-{repo_name}.log"
    log_path.write_text(out)
    match = REPORT_RE.search(out)
    if proc.returncode != 0 or not match:
        raise RuntimeError(
            f"benchmark failed for {repo_name} (exit={proc.returncode}); see {log_path}"
        )
    report_path = Path(match.group(1).strip())
    if not report_path.exists():
        raise RuntimeError(f"report missing for {repo_name}: {report_path}")
    print(f"report: {report_path}", flush=True)
    return report_path


def summarize_report(repo_url: str, report_path: Path) -> RepoSummary:
    report = json.loads(report_path.read_text())
    per_task: dict[str, dict[str, dict[str, object]]] = defaultdict(dict)
    per_arm_total_ms: dict[str, float] = defaultdict(float)
    validations: dict[str, int] = defaultdict(int)

    for arm_result in report["arms"]:
        arm = arm_result["arm"]
        run = arm_result["run"]
        task = arm_result["task_name"]
        valid = bool(run["validation_passed"])
        per_task[task][arm] = {
            "duration_ms": run["duration_ms"],
            "tokens": run["total_tokens"],
            "cost": run["estimated_cost_usd"],
            "validated": valid,
            "success": run["first_pass_success"],
        }
        per_arm_total_ms[arm] += float(run["duration_ms"])
        if valid:
            validations[arm] += 1

    git_total_s = per_arm_total_ms["git"] / 1000.0
    kin_totals = {
        "kin-compat": per_arm_total_ms.get("kin_compat", math.inf) / 1000.0,
        "kin-native": per_arm_total_ms.get("kin_native", math.inf) / 1000.0,
        "kin-native-cli": per_arm_total_ms.get("kin_native_cli", math.inf) / 1000.0,
    }

    available = {k: v for k, v in kin_totals.items() if math.isfinite(v)}
    best_arm = min(available, key=available.get) if available else None
    best_total_s = available.get(best_arm) if best_arm else None
    best_savings_pct = (
        (git_total_s - best_total_s) / git_total_s * 100.0 if best_total_s and git_total_s else None
    )

    wins = {"kin-native": 0, "kin-compat": 0, "kin-native-cli": 0, "best": 0}
    for task in TASK_ORDER:
        task_runs = per_task.get(task, {})
        git_run = task_runs.get("git")
        if not git_run:
            continue
        git_ms = float(git_run["duration_ms"])
        best_ms = math.inf
        for arm, key in [
            ("kin-native", "kin_native"),
            ("kin-compat", "kin_compat"),
            ("kin-native-cli", "kin_native_cli"),
        ]:
            run = task_runs.get(key)
            if run:
                ms = float(run["duration_ms"])
                best_ms = min(best_ms, ms)
                if ms < git_ms:
                    wins[arm] += 1
        if best_ms < git_ms:
            wins["best"] += 1

    conversions = {c["arm"]: c for c in report["conversions"]}
    native_conv = conversions.get("kin-native") or conversions.get("kin-compat") or {}
    health = report.get("pre_run_health") or {}

    return RepoSummary(
        repo_name=report["repo_name"],
        repo_url=repo_url,
        report_path=str(report_path),
        language=report.get("planted", {}).get("language", "unknown"),
        entities=int(native_conv.get("entity_count", 0)),
        files=int(native_conv.get("file_count", 0)),
        git_total_s=git_total_s,
        kin_compat_total_s=None
        if not math.isfinite(kin_totals["kin-compat"])
        else kin_totals["kin-compat"],
        kin_native_total_s=None
        if not math.isfinite(kin_totals["kin-native"])
        else kin_totals["kin-native"],
        kin_native_cli_total_s=None
        if not math.isfinite(kin_totals["kin-native-cli"])
        else kin_totals["kin-native-cli"],
        best_arm=best_arm,
        best_total_s=best_total_s,
        best_savings_pct=best_savings_pct,
        best_wins=wins["best"],
        native_wins=wins["kin-native"],
        compat_wins=wins["kin-compat"],
        native_cli_wins=wins["kin-native-cli"],
        validations=dict(validations),
        task_results=per_task,
        health=health,
    )


def avg(values: list[float]) -> float | None:
    return None if not values else sum(values) / len(values)


def pct_savings(git_s: float, kin_s: float | None) -> float | None:
    if kin_s is None:
        return None
    return (git_s - kin_s) / git_s * 100.0


def build_summary(
    repos: list[RepoSummary], repeat: int, assistant: str, arms: list[str]
) -> dict[str, object]:
    arm_totals: dict[str, dict[str, list[float] | int]] = {
        "kin-native": {"wins": 0, "losses": 0, "durations": [], "token_deltas": []},
        "kin-compat": {"wins": 0, "losses": 0, "durations": [], "token_deltas": []},
        "kin-native-cli": {"wins": 0, "losses": 0, "durations": [], "token_deltas": []},
        "best": {"wins": 0, "losses": 0, "durations": [], "token_deltas": []},
    }
    task_totals: dict[str, dict[str, dict[str, list[float] | int]]] = {}
    for task in TASK_ORDER:
        task_totals[task] = {
            "kin-native": {"wins": 0, "durations": []},
            "best": {"wins": 0, "durations": []},
        }

    for repo in repos:
        for task in TASK_ORDER:
            runs = repo.task_results.get(task, {})
            git_run = runs.get("git")
            if not git_run:
                continue
            git_ms = float(git_run["duration_ms"])
            git_tokens = int(git_run["tokens"])
            best_ms = math.inf
            for label, key in [
                ("kin-native", "kin_native"),
                ("kin-compat", "kin_compat"),
                ("kin-native-cli", "kin_native_cli"),
            ]:
                run = runs.get(key)
                if not run:
                    continue
                ms = float(run["duration_ms"])
                tok = int(run["tokens"])
                arm_totals[label]["durations"].append((git_ms - ms) / git_ms * 100.0)
                arm_totals[label]["token_deltas"].append((git_tokens - tok) / git_tokens * 100.0)
                if ms < git_ms:
                    arm_totals[label]["wins"] += 1
                    if label == "kin-native":
                        task_totals[task]["kin-native"]["wins"] += 1
                else:
                    arm_totals[label]["losses"] += 1
                if label == "kin-native":
                    task_totals[task]["kin-native"]["durations"].append(
                        (git_ms - ms) / git_ms * 100.0
                    )
                best_ms = min(best_ms, ms)
            if best_ms < math.inf:
                arm_totals["best"]["durations"].append((git_ms - best_ms) / git_ms * 100.0)
                if best_ms < git_ms:
                    arm_totals["best"]["wins"] += 1
                    task_totals[task]["best"]["wins"] += 1
                else:
                    arm_totals["best"]["losses"] += 1
                task_totals[task]["best"]["durations"].append((git_ms - best_ms) / git_ms * 100.0)

    health_rows = []
    for repo in repos:
        health_rows.append(
            {
                "repo": repo.repo_name,
                "load_1m": repo.health.get("load_avg_1m"),
                "cpu_pct": repo.health.get("cpu_pct"),
                "swap_used_mb": (repo.health.get("swap_used_bytes") or 0) / (1024 * 1024),
                "competing": len(repo.health.get("competing_processes") or []),
                "clean": repo.health.get("clean"),
                "warnings": repo.health.get("warnings") or [],
            }
        )

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "assistant": assistant,
        "arms": arms,
        "repeat": repeat,
        "repos": [repo.__dict__ for repo in repos],
        "arm_summary": {
            arm: {
                "wins": int(values["wins"]),
                "losses": int(values["losses"]),
                "avg_duration_savings_pct": avg(list(values["durations"])),
                "median_duration_savings_pct": statistics.median(values["durations"])
                if values["durations"]
                else None,
                "avg_token_savings_pct": avg(list(values["token_deltas"]))
                if values["token_deltas"]
                else None,
            }
            for arm, values in arm_totals.items()
        },
        "task_summary": {
            task: {
                "kin_native_wins": int(values["kin-native"]["wins"]),
                "kin_native_avg_savings_pct": avg(list(values["kin-native"]["durations"])),
                "best_wins": int(values["best"]["wins"]),
                "best_avg_savings_pct": avg(list(values["best"]["durations"])),
            }
            for task, values in task_totals.items()
        },
        "health": health_rows,
    }


def md_table(headers: list[str], rows: list[list[str]]) -> str:
    out = ["| " + " | ".join(headers) + " |", "| " + " | ".join(["---"] * len(headers)) + " |"]
    out.extend("| " + " | ".join(row) + " |" for row in rows)
    return "\n".join(out)


def render_markdown(summary: dict[str, object]) -> str:
    repos = [RepoSummary(**repo) for repo in summary["repos"]]
    repo_count = len(repos)
    arm_summary = summary["arm_summary"]
    task_summary = summary["task_summary"]
    health = summary["health"]

    repo_rows = []
    for repo in repos:
        repo_rows.append(
            [
                repo.repo_name,
                repo.language,
                str(repo.entities),
                str(repo.files),
                f"{repo.git_total_s:.1f}s",
                f"{repo.kin_compat_total_s:.1f}s" if repo.kin_compat_total_s is not None else "-",
                f"{repo.kin_native_total_s:.1f}s" if repo.kin_native_total_s is not None else "-",
                f"{repo.kin_native_cli_total_s:.1f}s" if repo.kin_native_cli_total_s is not None else "-",
                repo.best_arm or "-",
                f"{repo.best_savings_pct:.1f}%" if repo.best_savings_pct is not None else "-",
                f"{repo.best_wins}/7",
            ]
        )

    arm_rows = []
    for arm in ["kin-native", "kin-compat", "kin-native-cli", "best"]:
        row = arm_summary[arm]
        total = row["wins"] + row["losses"]
        arm_rows.append(
            [
                arm,
                f"{row['wins']}/{total}",
                f"{row['avg_duration_savings_pct']:.1f}%" if row["avg_duration_savings_pct"] is not None else "-",
                f"{row['median_duration_savings_pct']:.1f}%"
                if row["median_duration_savings_pct"] is not None
                else "-",
                f"{row['avg_token_savings_pct']:.1f}%"
                if row["avg_token_savings_pct"] is not None
                else "-",
            ]
        )

    task_rows = []
    for task in TASK_ORDER:
        row = task_summary[task]
        task_rows.append(
            [
                task,
                f"{row['kin_native_wins']}/{repo_count}",
                f"{row['kin_native_avg_savings_pct']:.1f}%"
                if row["kin_native_avg_savings_pct"] is not None
                else "-",
                f"{row['best_wins']}/{repo_count}",
                f"{row['best_avg_savings_pct']:.1f}%"
                if row["best_avg_savings_pct"] is not None
                else "-",
            ]
        )

    health_rows = []
    for row in health:
        health_rows.append(
            [
                row["repo"],
                f"{row['load_1m']:.1f}" if row["load_1m"] is not None else "-",
                f"{row['swap_used_mb']:.0f}",
                str(row["competing"]),
                "clean" if row["clean"] else "contended",
            ]
        )

    lines = [
        "# Popular Repo Validated Benchmark Sweep",
        "",
        f"Generated at: {summary['generated_at']}",
        "",
        "## Repo Matrix",
        "",
        md_table(
            ["Repo", "Lang", "Entities", "Files", "Git", "Compat", "Native", "Native-CLI", "Best Arm", "Best Savings", "Best Wins"],
            repo_rows,
        ),
        "",
        "## Arm Summary",
        "",
        md_table(
            ["Arm", "Wins vs Git", "Avg Savings", "Median Savings", "Avg Token Savings"],
            arm_rows,
        ),
        "",
        "## Task Summary",
        "",
        md_table(
            ["Task", "Kin-native Wins", "Kin-native Avg Savings", "Best Arm Wins", "Best Arm Avg Savings"],
            task_rows,
        ),
        "",
        "## Run Health",
        "",
        md_table(["Repo", "Load (1m)", "Swap MB", "Competing Assistants", "Health"], health_rows),
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--assistant", default="claude")
    parser.add_argument("--repo", action="append", dest="repos")
    parser.add_argument("--arm", action="append", dest="arms")
    parser.add_argument("--skip-run", action="store_true")
    args = parser.parse_args()

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    reports: list[tuple[str, str, Path]] = []

    if args.skip_run:
        matrix_jsons = sorted(OUTPUT_DIR.glob("popular-validated-*.json"))
        if not matrix_jsons:
            raise SystemExit("no prior matrix JSON found in .kin/bench/")
        print(matrix_jsons[-1])
        return 0

    selected = POPULAR_REPOS
    if args.repos:
        wanted = {name.lower() for name in args.repos}
        selected = [(name, url) for name, url in POPULAR_REPOS if name.lower() in wanted]
        if not selected:
            raise SystemExit(f"no repos matched --repo: {', '.join(args.repos)}")

    arms = args.arms or DEFAULT_ARMS

    for repo_name, repo_url in selected:
        report_path = run_benchmark(repo_name, repo_url, args.repeat, args.assistant, arms)
        reports.append((repo_name, repo_url, report_path))

    summaries = [summarize_report(url, path) for _, url, path in reports]
    summary = build_summary(summaries, args.repeat, args.assistant, arms)

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    json_path = OUTPUT_DIR / f"popular-validated-{stamp}.json"
    md_path = OUTPUT_DIR / f"popular-validated-{stamp}.md"
    json_path.write_text(json.dumps(summary, indent=2))
    md_path.write_text(render_markdown(summary))

    print(f"matrix json: {json_path}")
    print(f"matrix md:   {md_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
