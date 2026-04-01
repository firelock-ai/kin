# Validated Popular Repo Benchmark Sweep (2026-03-20)

This document summarizes the latest checked benchmark matrix for Kin's primary workflow: `git` vs `kin-native`.

Command used:

```bash
cargo build --release -p kin-cli
python3 scripts/run_popular_validated_benchmarks.py --assistant codex
```

Configuration:

- Assistant: Codex CLI `0.114.0`
- Arms: `git`, `kin-native`
- Task set: `validated`
- Repetitions: `1`
- Repos: `express`, `axios`, `hono`, `zod`, `flask`, `typer`, `requests`, `redux`, `click`, `dayjs`
- Fresh conversion forced on every repo via `--fresh-conversion`
- Language coverage in this checked sweep: JavaScript, TypeScript, Python

Headline:

- `69/70` task comparisons won by `kin-native`
- `50.0%` less wall-clock time overall (`1659.7s` git vs `829.8s` kin-native)
- `44.6%` fewer tokens overall (`5,539,366` git vs `3,068,820` kin-native)

## Repo Matrix

| Repo | Lang | Entities | Files | Git | Native | Savings | Wins |
| --- | --- | --- | --- | --- | --- | --- | --- |
| express | javascript | 203 | 245 | 142.2s | 72.1s | 49.3% | 7/7 |
| axios | javascript | 546 | 390 | 156.2s | 74.1s | 52.5% | 7/7 |
| hono | typescript | 1847 | 501 | 170.6s | 82.1s | 51.9% | 7/7 |
| zod | typescript | 3199 | 582 | 174.4s | 80.3s | 53.9% | 7/7 |
| flask | python | 1018 | 269 | 194.4s | 124.4s | 36.0% | 7/7 |
| typer | python | 1663 | 766 | 192.4s | 102.2s | 46.9% | 6/7 |
| requests | python | 758 | 158 | 148.2s | 80.2s | 45.9% | 7/7 |
| redux | javascript | 257 | 483 | 158.7s | 76.2s | 52.0% | 7/7 |
| click | python | 1156 | 182 | 178.3s | 72.1s | 59.6% | 7/7 |
| dayjs | javascript | 193 | 413 | 144.2s | 66.1s | 54.2% | 7/7 |

## Task Summary

| Task | Kin-native Wins | Avg Savings |
| --- | --- | --- |
| count-real-callers | 9/10 | 37.4% |
| find-dead-code | 10/10 | 41.7% |
| find-planted-secret | 10/10 | 29.5% |
| fix-planted-bug | 10/10 | 45.2% |
| implement-stub | 10/10 | 46.6% |
| trace-computation | 10/10 | 67.5% |
| trace-type-imports | 10/10 | 62.0% |

## Loss Case

The single native loss in the 70-task matrix was:

- `typer` / `count-real-callers`: `42.0951s` git vs `50.0792s` native

## Fairness Notes

This benchmark is designed to be reviewable and hard to game:

- The harness injects randomized planted artifacts into the source tree once, before copying the repo into arm-specific workspaces.
- Every arm sees identical source files and identical task prompts. Only the available tools differ.
- Artifact names include random tags and the planted secret values are random UUIDs, so the assistant cannot memorize answers from training data.
- The planted files import real symbols from the repository and inject a real entry-point reference, forcing the benchmark through the repo's actual dependency graph.
- Output validation is automatic against planted ground truth. Slow runs and wrong answers stay in the totals; there is no manual grading.
- Kin conversion is forced fresh for each repo with `--fresh-conversion`, and conversion cost is reported separately from per-task execution.
- Arm order rotation is built into the harness, reducing simple order bias when repetitions are greater than one.
- Raw per-run reports are written to `.kin/bench/live-*.json`. The aggregate summary for this sweep was written locally to `.kin/bench/popular-validated-20260319-222916.json` and `.kin/bench/popular-validated-20260319-222916.md`.

## Environment Caveat

This sweep was not run on a lab-clean machine. Every repo in the checked matrix was recorded as `contended`. The harness recorded:

- load average range: `31.8` to `172.6`
- swap usage range: `30013 MB` to `35337 MB`
- competing assistant processes: `3` to `7` on every run

So the absolute times are noisy. The value of the matrix is in the breadth of the sweep: 10 repos and 70 validated task comparisons under one consistent procedure.

Rust is still excluded from the checked matrix. The current validated harness remains limited to the JavaScript, TypeScript, and Python repos listed above.
