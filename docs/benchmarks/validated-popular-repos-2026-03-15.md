# Validated Popular Repo Benchmark Sweep (2026-03-15)

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

Headline:

- `66/70` task comparisons won by `kin-native`
- `54.0%` less wall-clock time overall (`1416.1s` git vs `651.0s` kin-native)
- `41.3%` fewer tokens overall (`5,299,139` git vs `3,109,824` kin-native)

## Repo Matrix

| Repo | Lang | Entities | Files | Git | Native | Savings | Wins |
| --- | --- | --- | --- | --- | --- | --- | --- |
| express | javascript | 203 | 245 | 132.2s | 56.1s | 57.6% | 7/7 |
| axios | javascript | 546 | 371 | 128.2s | 56.1s | 56.2% | 7/7 |
| hono | typescript | 1847 | 501 | 150.2s | 58.1s | 61.3% | 7/7 |
| zod | typescript | 3199 | 582 | 138.2s | 58.1s | 58.0% | 7/7 |
| flask | python | 1018 | 269 | 134.2s | 60.1s | 55.2% | 6/7 |
| typer | python | 1663 | 766 | 124.2s | 58.1s | 53.2% | 7/7 |
| requests | python | 758 | 158 | 160.2s | 96.1s | 40.0% | 5/7 |
| redux | javascript | 257 | 483 | 144.2s | 64.1s | 55.6% | 7/7 |
| click | python | 1156 | 182 | 156.2s | 86.1s | 44.9% | 6/7 |
| dayjs | javascript | 191 | 413 | 148.2s | 58.1s | 60.8% | 7/7 |

## Task Summary

| Task | Kin-native Wins | Avg Savings |
| --- | --- | --- |
| count-real-callers | 8/10 | 31.6% |
| find-dead-code | 10/10 | 58.0% |
| find-planted-secret | 8/10 | 22.9% |
| fix-planted-bug | 10/10 | 51.1% |
| implement-stub | 10/10 | 47.2% |
| trace-computation | 10/10 | 72.6% |
| trace-type-imports | 10/10 | 66.7% |

## Loss Cases

The four native losses in the 70-task matrix were:

- `flask` / `find-planted-secret`: `10.0107s` git vs `10.0167s` native
- `requests` / `find-planted-secret`: `10.0176s` git vs `10.0213s` native
- `requests` / `count-real-callers`: `28.0446s` git vs `40.0530s` native
- `click` / `count-real-callers`: `22.0409s` git vs `42.0566s` native

Two of those four misses were effectively ties measured in milliseconds.

## Fairness Notes

This benchmark is designed to be reviewable and hard to game:

- The harness injects randomized planted artifacts into the source tree once, before copying the repo into arm-specific workspaces.
- Every arm sees identical source files and identical task prompts. Only the available tools differ.
- Artifact names include random tags and the planted secret values are random UUIDs, so the assistant cannot memorize answers from training data.
- The planted files import real symbols from the repository and inject a real entry-point reference, forcing the benchmark through the repo's actual dependency graph.
- Output validation is automatic against planted ground truth. Slow runs and wrong answers stay in the totals; there is no manual grading.
- Kin conversion is forced fresh for each repo with `--fresh-conversion`, and conversion cost is reported separately from per-task execution.
- Arm order rotation is built into the harness, reducing simple order bias when repetitions are greater than one.
- Raw per-run reports are written to `.kin/bench/live-*.json`. The aggregate summary for this sweep was written locally to `.kin/bench/popular-validated-20260315-10repo.json` and `.kin/bench/popular-validated-20260315-10repo.md`.

## Environment Caveat

This sweep was not run on a lab-clean machine. The harness recorded:

- load average range: `5.3` to `8.8`
- swap usage range: `2764 MB` to `2788 MB`
- competing assistant processes: `3` on every run

So the absolute times are noisy. The value of the matrix is in the breadth of the sweep: 10 repos and 70 validated task comparisons under one consistent procedure.
