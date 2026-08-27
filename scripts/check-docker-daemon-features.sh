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

feature_lines="$({
  grep -E 'cargo chef cook .*--features' "${dockerfile}" || true
  grep -E 'cargo build .*--features .*--bin kin-daemon' "${dockerfile}" || true
})"
line_count="$(printf '%s\n' "${feature_lines}" | awk 'NF { count += 1 } END { print count + 0 }')"
if [[ "${line_count}" -ne 3 ]]; then
  echo "docker feature contract: expected one cargo-chef and two kin-daemon build feature lines, found ${line_count}" >&2
  exit 1
fi

while IFS= read -r line; do
  [[ -n "${line}" ]] || continue
  if [[ "${line}" != *"${expected}"* ]]; then
    echo "docker feature contract: production invocation lacks exact ${expected}: ${line}" >&2
    exit 1
  fi
done <<<"${feature_lines}"

if grep -Eq -- '--features[[:space:]]+(kin-daemon/)?gcs([[:space:];\\]|$)' "${dockerfile}"; then
  echo "docker feature contract: found a gcs-only production build" >&2
  exit 1
fi

if grep -Eq -- '--features[[:space:]]+(kin-daemon/)?firestore([[:space:];\\]|$)' "${dockerfile}"; then
  echo "docker feature contract: found a firestore-only production build" >&2
  exit 1
fi

echo "docker feature contract: PASS (${line_count} production invocations use kin-daemon/gcs,kin-daemon/firestore)"
