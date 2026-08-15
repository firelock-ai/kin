#!/usr/bin/env bash
# validate-retrieval-mf16 — prepared A/B validation of the fused semantic_locate
# routing + accuracy profile against the frozen 16-task multi-file diagnostic.
#
# PREPARED, NOT SELF-STARTING: by default this prints the exact plan and exits.
# Nothing heavy (daemon, models, benchmark) starts without --run. Heavy runs
# contend for the one GPU/daemon slot, so the operator holding that slot
# executes this in a gated window.
#
# NON-CITABLE: this is an A/B diagnostic slice (paired same-task comparison,
# not a proof-gated run). Its output must never be quoted as a benchmark
# result or release evidence.
#
# What it compares (same 16 frozen tasks, same model config, temp0/seed0):
#   arm A  KIN_PROFILE=compat-v0:   pre-profile lever defaults
#   arm B  KIN_PROFILE=accuracy-v1: accuracy levers plus the conditional cross-encoder
# Routing is profile-independent: semantic_locate serves the fused pipeline in
# BOTH arms, exactly like kin locate, so this A/B isolates the lever sets. The
# cosine arm is reachable only per call via pipeline:"cosine".
#
# Metrics to read from the scorer output, A vs B:
#   - gold files surfaced %          (diagnostic north star: was 39%)
#   - retrieval_miss / traversal_pruned counts (was 28/31 of fixable misses)
#   - file precision / recall / F1, symbol R, line R
#   - declared-vs-surfaced conversion, total tokens per task
#   - per-hit `routing` field distribution (fused-v1 expected in BOTH arms;
#     cosine-v0 only where a call forced pipeline:"cosine") and `degradations`
#     frequencies
#
# Prerequisites the operator must satisfy first (fail-loud checks below):
#   1. Rebuild ALL binaries from the branch under test (CLI + daemon + bench
#      prep/eval), and refresh the bench binary stash — never mix stale builds.
#   2. Hold the GPU + daemon locks (kin-lane) for the duration.
#   3. The frozen task list json (not stored in this repo — benchmark data
#      lives with the bench harness) reachable at $MF16_TASKS.

set -euo pipefail

KIN_SRC="${KIN_SRC:-$(cd "$(dirname "$0")/.." && pwd)}"
MF16_TASKS="${MF16_TASKS:?set MF16_TASKS to the frozen_multifile16.json task list}"
CBO="${CONTEXTBENCH_OFFICIAL_ROOT:?set CONTEXTBENCH_OFFICIAL_ROOT (contextbench-official checkout)}"
ARM_DIR="${ARM_DIR:?set ARM_DIR to the agent-arm harness directory}"
OUTPUT_DIR="${OUTPUT_DIR:-$KIN_SRC/.kin-dev/NON_CITABLE/retrieval-mf16}"
RUN=0
[ "${1:-}" = "--run" ] && RUN=1

plan() { printf '%s\n' "$*"; }

plan "== validate-retrieval-mf16 (NON-CITABLE diagnostic) =="
plan ""
plan "[1/5] rebuild binaries from $KIN_SRC (fresh, no stale mixes):"
plan "      cargo build --release -p kin-cli -p kin-daemon"
plan "      rm -f ~/.cargo/bin/kin && cp target/release/kin ~/.cargo/bin/kin   # rm-then-cp, never cp-over-running"
plan "      export KIN_BIN=$KIN_SRC/target/release/kin"
plan "      export PATH=$KIN_SRC/target/release:\$PATH   # daemon resolution"
plan ""
plan "[2/5] environment pins (both arms identical except KIN_PROFILE):"
plan "      export KIN_BENCH_EMBED=1 KIN_BENCH_BUILD_TIMEOUT=14400"
plan "      unset KIN_MCP_TOOL_PROFILE KIN_AGENT_DUMP DYLD_INSERT_LIBRARIES LD_PRELOAD"
plan "      unset any ambient KIN_LOCATE_* / KIN_SEMLOC_* overrides (rerun-gate will assert)"
plan ""
plan "[3/5] arm A (baseline): KIN_PROFILE=compat-v0 over the 16 frozen tasks"
plan "      task list: $MF16_TASKS"
plan "      output:    $OUTPUT_DIR/mf16_compat_v0.jsonl (+ _turns/_results)"
plan ""
plan "[4/5] arm B (candidate): KIN_PROFILE=accuracy-v1, same tasks, same seed"
plan "      output:    $OUTPUT_DIR/mf16_accuracy_v1.jsonl (+ _turns/_results)"
plan ""
plan "[5/5] score both with the official scorer; read the paired deltas:"
plan "      gold-surfaced %, traversal_pruned count, file P/R/F1, symbol R,"
plan "      line R, conversion, tokens/task; check the per-hit routing field"
plan "      says fused-v1 in both arms; collect degradations[] frequencies."
plan ""
plan "optional per-call A/B without switching profiles: pass"
plan "      pipeline:\"cosine\" / pipeline:\"fused\" on semantic_locate calls."
plan "explain-mode prune attribution (per-stage ledger) for miss forensics:"
plan "      call semantic_locate with explain:true and read debug.prune_ledger."

if [ "$RUN" -ne 1 ]; then
    plan ""
    plan "DRY PLAN ONLY — rerun with --run inside a gated GPU/daemon window."
    exit 0
fi

command -v jq >/dev/null || { echo "jq required" >&2; exit 1; }
[ -f "$MF16_TASKS" ] || { echo "task list not found: $MF16_TASKS" >&2; exit 1; }
[ -x "$KIN_SRC/target/release/kin" ] || {
    echo "fresh kin binary missing — run the [1/5] rebuild first" >&2
    exit 1
}
mkdir -p "$OUTPUT_DIR"

IDS="$(jq -r '[.tasks[].instance_id] | join(",")' "$MF16_TASKS")"
export PATH="$KIN_SRC/target/release:$PATH"
export KIN_BENCH_EMBED=1 KIN_BENCH_BUILD_TIMEOUT=14400
export CONTEXTBENCH_OFFICIAL_ROOT="$CBO"
unset KIN_MCP_TOOL_PROFILE KIN_AGENT_DUMP DYLD_INSERT_LIBRARIES LD_PRELOAD || true

for arm in compat-v0 accuracy-v1; do
    tag="mf16_${arm//-/_}"
    echo "[arm $arm] $(date +%H:%M:%S) starting ${tag}"
    KIN_PROFILE="$arm" IDS_OVERRIDE="$IDS" \
        "$ARM_DIR/run_arm.sh" kin "$OUTPUT_DIR/$tag" 2>&1 |
        tee "$OUTPUT_DIR/$tag.log"
done

echo "runs complete — score with the official scorer, then compare:"
echo "  $OUTPUT_DIR/mf16_compat_v0_results.jsonl"
echo "  $OUTPUT_DIR/mf16_accuracy_v1_results.jsonl"
