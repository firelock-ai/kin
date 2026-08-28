#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dockerfile="${1:-${repo_root}/Dockerfile}"
expected='--features kin-daemon/gcs,kin-daemon/firestore'

if [[ ! -f "${dockerfile}" ]]; then
  echo "docker feature contract: missing ${dockerfile}" >&2
  exit 1
fi

production_lines="$({
  grep -E 'cargo chef cook ' "${dockerfile}" || true
  grep -E 'cargo build .*--bin kin-daemon' "${dockerfile}" || true
})"
line_count="$(printf '%s\n' "${production_lines}" | awk 'NF { count += 1 } END { print count + 0 }')"
if [[ "${line_count}" -ne 3 ]]; then
  echo "docker feature contract: expected one cargo-chef and two kin-daemon build lines, found ${line_count}" >&2
  exit 1
fi

while IFS= read -r line; do
  [[ -n "${line}" ]] || continue
  feature_args="$(printf '%s\n' "${line}" | grep -oE -- '--features[[:space:]]+[^[:space:];\\]+' || true)"
  if [[ "${feature_args}" != "${expected}" ]] ||
    grep -Eq -- '(^|[[:space:]])(--all-features|-F)([=[:space:]]|$)' <<<"${line}"; then
    echo "docker feature contract: production invocation must use only ${expected}: ${line}" >&2
    exit 1
  fi
done <<<"${production_lines}"

echo "docker feature contract: PASS (${line_count} production invocations use kin-daemon/gcs,kin-daemon/firestore)"
