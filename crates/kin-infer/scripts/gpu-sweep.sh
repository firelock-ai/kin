#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
#
# gpu-sweep.sh — make the GPU safe before any Metal gate or embed run.
#
# PURPOSE
#   Run this BEFORE any `cargo test -p kin-infer --features metal` gate (or any
#   `kin embed` / daemon embed). It is idempotent and safe to run repeatedly.
#
# ROOT CAUSE THIS DEFENDS AGAINST
#   A heavy GPU test (e.g. embed_scale_hang / embed_speed_profile) spawned by a
#   parent that was then killed leaves the test BINARY orphaned. The orphan keeps
#   submitting Metal command buffers and pins "Device Utilization %" near 100%,
#   so the NEXT gate measures a GPU that is already saturated by a zombie — its
#   numbers are junk and it may itself stall behind the busy queue.
#
#   This sweep is one of three layered defenses; the other two already live in
#   tests/embed_scale_hang.rs:
#     1. #[ignore]            — the scale-hang repro never runs in the default
#                              suite; it must be opted into explicitly.
#     2. KIN_SCALE_MAX_SECS   — a watchdog cap so even an opted-in run can never
#                              hold the device indefinitely (it aborts loudly).
#     3. THIS SWEEP           — kills any orphan that slipped past 1 & 2 and
#                              reports the GPU dropping back to idle.
#
# USAGE
#   kin-infer/scripts/gpu-sweep.sh
#
#   Exits 0 when the sweep completes (clean or after killing orphans). It only
#   lists and kills processes — it never runs a GPU test or embed itself.

set -uo pipefail

# --- GPU Device Utilization % reporter ----------------------------------------
# The value lives inside the IOAccelerator PerformanceStatistics dictionary, e.g.
#   ..."Device Utilization %"=20,...
# Extract just that field so the operator sees a single clean number.
gpu_utilization() {
  local raw
  raw=$(ioreg -r -d 1 -c IOAccelerator 2>/dev/null \
    | grep -o '"Device Utilization %"=[0-9]*' \
    | head -1 \
    | grep -o '[0-9]*$')
  if [[ -n "${raw}" ]]; then
    printf '%s%%' "${raw}"
  else
    printf 'unavailable'
  fi
}

echo "=== kin-infer GPU sweep ==="
echo "GPU Device Utilization (before): $(gpu_utilization)"

# --- orphan / leftover process patterns ---------------------------------------
# Compiled test binaries live at target/{debug,release}/deps/<name>-<hash>.
# The pkill -f patterns below match that full path prefix (and the bare name),
# plus any stray `cargo test --features metal` driver and leftover daemon/embed.
PATTERNS=(
  'target/(debug|release)/deps/embed_scale_hang'
  'target/(debug|release)/deps/embed_speed_profile'
  'target/(debug|release)/deps/metal_seq_len_regression'
  'target/(debug|release)/deps/swerank_self_retrieval'
  'target/(debug|release)/deps/embed_determinism_probe'
  'cargo test.*--features metal'
  'kin-daemon'
  'kin embed'
)

killed_any=0
for pat in "${PATTERNS[@]}"; do
  # List matches first (excluding this script itself) so the operator sees what
  # is about to die, then kill. pgrep/pkill -f match against the full argv.
  matches=$(pgrep -f -- "${pat}" 2>/dev/null | grep -v "^$$\$" || true)
  if [[ -n "${matches}" ]]; then
    echo "--- killing processes matching: ${pat}"
    # Show pid + command for the audit trail.
    while IFS= read -r pid; do
      [[ -z "${pid}" ]] && continue
      cmd=$(ps -p "${pid}" -o pid=,command= 2>/dev/null || true)
      [[ -n "${cmd}" ]] && echo "    ${cmd}"
    done <<< "${matches}"
    pkill -9 -f -- "${pat}" 2>/dev/null || true
    killed_any=1
  fi
done

if [[ "${killed_any}" -eq 0 ]]; then
  echo "No orphaned kin-infer GPU processes found."
fi

# Give the driver a moment to reclaim the queue, then report again.
sleep 1
echo "GPU Device Utilization (after):  $(gpu_utilization)"
echo "=== sweep complete (GPU safe for gate/embed) ==="

exit 0
