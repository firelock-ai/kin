#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
#
# Downstream-pin compatibility gate for kin-model (version source of truth).
#
# kin-model holds the canonical Kin types; downstream crates (kin, kin-db,
# kin-bench, ...) pin it from the 'kin' registry. downstream-pins.json is the
# DECLARED compatibility contract — each entry records a downstream consumer and
# the version requirement it pins.
#
# This gate verifies that every declared `req` ACCEPTS the version kin-model is
# about to publish (the Cargo.toml version, by default). If a breaking bump
# would leave a declared pin unable to resolve the new version, the gate fails
# with the exact remediation: bump that downstream's pin (and re-run the
# fresh-cache consumer smoke against the new release). Updating Cargo.toml + the
# affected `req`s here in one change is the explicit, reviewable signal that the
# downstream repos must move.
#
# TARGET version precedence:
#   1) $1 (explicit arg)
#   2) $KIN_MODEL_TARGET_VERSION
#   3) the version in Cargo.toml (the version about to be published)
#
# Offline: caret/exact/wildcard matching is computed locally; no registry needed.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
manifest="${repo_root}/downstream-pins.json"
if [[ ! -f "$manifest" ]]; then
  echo "downstream-pins manifest not found: $manifest" >&2
  exit 1
fi

cargo_version="$(awk -F'"' '/^version[[:space:]]*=/{print $2; exit}' "$repo_root/Cargo.toml")"
target="${1:-${KIN_MODEL_TARGET_VERSION:-$cargo_version}}"
if [[ -z "$target" ]]; then
  echo "could not determine target kin-model version" >&2
  exit 1
fi

python3 - "$manifest" "$target" <<'PY'
import json
import re
import sys

manifest_path, target = sys.argv[1], sys.argv[2]


def parse(v):
    core = v.split("-", 1)[0].split("+", 1)[0]
    nums = []
    for p in core.split(".")[:3]:
        nums.append(int(p) if p.isdigit() else 0)
    while len(nums) < 3:
        nums.append(0)
    return tuple(nums)


def caret_upper(parts):
    # Cargo caret: bound is set by the left-most NON-ZERO component.
    major, minor, patch = parts
    if major != 0:
        return (major + 1, 0, 0)
    if minor != 0:
        return (0, minor + 1, 0)
    if patch != 0:
        return (0, 0, patch + 1)
    # ^0.0.0 -> any 0.0.z (degenerate); treat as < 0.1.0
    return (0, 1, 0)


def satisfies(req, ver):
    """Return (ok, reason). Supports cargo's common req forms used by Kin pins:
    caret (bare 'X', 'X.Y', 'X.Y.Z' or '^...'), exact '=X.Y.Z', wildcard '*'."""
    req = req.strip()
    v = parse(ver)
    if req in ("*", ""):
        return True, "wildcard"
    if req.startswith("="):
        lo = parse(req[1:])
        return (v == lo), f"exact =={req[1:]}"
    body = req[1:] if req.startswith("^") else req
    if not re.fullmatch(r"\d+(\.\d+){0,2}", body):
        return None, f"unsupported req syntax '{req}' (verify manually)"
    lo = parse(body)
    hi = caret_upper(lo)
    return (lo <= v < hi), f"caret >={'.'.join(map(str, lo))} <{'.'.join(map(str, hi))}"


with open(manifest_path, "r", encoding="utf-8") as fh:
    data = json.load(fh)

rows = data.get("downstream", [])
print(f"kin-model version-SoT check: target = {target}")
print(f"declared downstream consumers: {len(rows)}\n")

fail = False
unknown = False
for row in rows:
    req = str(row.get("req", "")).strip()
    label = f'{row.get("repo","?")} :: {row.get("consumer","?")} ({row.get("manifest","?")})'
    ok, reason = satisfies(req, target)
    if ok is True:
        print(f"  OK    pin '{req}' accepts {target}  [{reason}]  — {label}")
    elif ok is None:
        unknown = True
        print(f"  ????  pin '{req}': {reason}  — {label}")
    else:
        fail = True
        print(f"  FAIL  pin '{req}' does NOT accept {target}  [{reason}]  — {label}")
        print(f"        remediation: bump kin-model's '{req}' pin in {row.get('repo')} "
              f"to accept {target}, then re-run the fresh-cache consumer smoke.")

print()
if fail:
    print("Downstream pin check FAILED: one or more declared pins cannot consume "
          f"kin-model {target}. Update downstream-pins.json (and the downstream "
          "Cargo.toml it mirrors) in lockstep with the version bump.")
    sys.exit(1)
if unknown:
    print("Downstream pin check INCONCLUSIVE: an unsupported req syntax needs "
          "manual verification (see '????' rows above).")
    sys.exit(2)
print(f"Downstream pin check OK: all declared pins accept kin-model {target}.")
PY
