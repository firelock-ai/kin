#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
#
# Version-bump gate for kin-model (release/version source of truth).
#
# kin-model holds the canonical Kin types. The 'kin' cargo registry is IMMUTABLE
# per (name, version): a published version's bytes can never be replaced. So any
# API/behaviour change destined for the registry MUST carry a new version — you
# cannot ship a change under an already-published number. This gate enforces:
#
#   A. Regression guard (registry reachable): the Cargo.toml version must be
#      >= the newest published version. A release never moves backward.
#   B. Bump-on-source-change guard (base ref available): if anything under src/
#      changed versus the base branch, the Cargo.toml version must differ from
#      the base version — code changed, so the version must move.
#   C. Immutable-republish guard (base ref + registry): if src/ changed versus
#      base AND the Cargo.toml version is already published, fail — that change
#      can never reach consumers under the stale, immutable version.
#
# Pure-docs / CI-only / manifest-only PRs do NOT trigger B or C (no src change),
# so they are not forced to bump. Per README "Versioning & release policy":
# pre-1.0, an API-breaking change requires a MINOR bump (0.MINOR.x), an additive
# or fix change a PATCH bump.
#
# Inputs (all optional):
#   BASE_REF  git ref to diff against for B/C (e.g. origin/main). Skipped if unset
#             or not present in the checkout (degrade to A only; the publish-time
#             immutability guard remains the backstop).
# Registry reads are open; no token required.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

registry_url="${KINLAB_CARGO_REGISTRY_URL:-https://kinlab.ai}"
registry_url="${registry_url%/}"

read_version() { awk -F'"' '/^version[[:space:]]*=/{print $2; exit}' "$1"; }

crate_name="$(awk -F'"' '/^name[[:space:]]*=/{print $2; exit}' Cargo.toml)"
cargo_version="$(read_version Cargo.toml)"
if [[ -z "$crate_name" || -z "$cargo_version" ]]; then
  echo "could not read name/version from Cargo.toml" >&2
  exit 1
fi

# Cargo sparse-index path for a crate name (1/2/3/4+ char prefix sharding).
index_path_for() {
  local name="$1"
  local len=${#name}
  case "$len" in
    1) printf '1/%s' "$name" ;;
    2) printf '2/%s' "$name" ;;
    3) printf '3/%s/%s' "${name:0:1}" "$name" ;;
    *) printf '%s/%s/%s' "${name:0:2}" "${name:2:2}" "$name" ;;
  esac
}

# --- Gather registry state (best-effort) -----------------------------------
index_body="$(mktemp)"
trap 'rm -f "$index_body"' EXIT
index_url="${registry_url}/registry/cargo/$(index_path_for "$crate_name")"
index_code="$(curl -sS -o "$index_body" -w '%{http_code}' "$index_url" 2>/dev/null || echo 000)"
[[ "$index_code" == "200" ]] || : >"$index_body"  # 404/err -> empty => no published versions known

# --- Gather base state (best-effort) ---------------------------------------
base_ref="${BASE_REF:-}"
src_changed=""
base_version=""
if [[ -n "$base_ref" ]] && git rev-parse --verify -q "$base_ref" >/dev/null 2>&1; then
  if git diff --name-only "$base_ref"...HEAD -- src/ 2>/dev/null | grep -q .; then
    src_changed="yes"
  else
    src_changed="no"
  fi
  base_version="$(git show "$base_ref:Cargo.toml" 2>/dev/null | awk -F'"' '/^version[[:space:]]*=/{print $2; exit}')"
fi

echo "kin-model version-bump gate"
echo "  crate            : $crate_name"
echo "  Cargo version    : $cargo_version"
echo "  registry index   : HTTP $index_code"
echo "  base ref         : ${base_ref:-<none>}"
echo "  base version     : ${base_version:-<unknown>}"
echo "  src changed?     : ${src_changed:-<unknown>}"
echo ""

python3 - "$cargo_version" "$index_body" "${base_version:-}" "${src_changed:-}" <<'PY'
import json
import sys

version, index_path, base_version, src_changed = (
    sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
)


def parse(v):
    core = v.split("-", 1)[0].split("+", 1)[0]
    nums = []
    for p in core.split(".")[:3]:
        nums.append(int(p) if p.isdigit() else 0)
    while len(nums) < 3:
        nums.append(0)
    return tuple(nums)


published = []
try:
    with open(index_path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            if obj.get("yanked"):
                continue
            published.append(obj["vers"])
except FileNotFoundError:
    pass

newest = max(published, key=parse) if published else None
cur = parse(version)
failures = []

# A. Regression guard.
if newest is not None and cur < parse(newest):
    failures.append(
        f"version {version} is LOWER than the newest published {newest}; "
        "a release must move forward.")

# B/C only when we know the base + whether src changed.
if src_changed == "yes" and base_version:
    if version == base_version:
        failures.append(
            f"src/ changed but the version is unchanged ({version}); bump the "
            "version (pre-1.0: MINOR for breaking, PATCH for additive/fix).")
    elif version in published:
        failures.append(
            f"src/ changed and version {version} is ALREADY published "
            "(immutable); that change can never reach consumers — bump again.")

if failures:
    print("FAIL:")
    for f in failures:
        print(f"  - {f}")
    sys.exit(1)

notes = []
if newest is None:
    notes.append("no published versions yet (first publish)")
else:
    notes.append(f"newest published = {newest}")
if src_changed == "no":
    notes.append("no src/ change vs base — bump not required")
elif src_changed == "yes":
    notes.append("src/ changed and version moved appropriately")
print(f"OK: version {version} is publishable ({'; '.join(notes)}).")
PY
