#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

set -euo pipefail

if [ "$#" -ne 5 ]; then
  echo "usage: $0 <package> <version> <package-dir> <expected-ref> <expected-commit>" >&2
  exit 2
fi

package="$1"
version="$2"
package_dir="$3"
expected_ref="$4"
expected_commit="$5"
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

if ! printf '%s\n' "$expected_commit" | grep -Eq '^[0-9a-f]{40}$'; then
  echo "error: expected commit must be a full lowercase 40-hex id" >&2
  exit 2
fi
case "$expected_ref" in
  refs/tags/v*) ;;
  *) echo "error: expected ref must be an exact version tag" >&2; exit 2 ;;
esac

tmp="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/kin-npm-proof.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/pack" "$tmp/audit-home" "$tmp/audit"
: > "$tmp/empty-npmrc"

pack_json="$(env -u NODE_AUTH_TOKEN -u NPM_TOKEN NPM_CONFIG_USERCONFIG="$tmp/empty-npmrc" \
  npm pack "$package_dir" --json --pack-destination "$tmp/pack")"
local_integrity="$(printf '%s\n' "$pack_json" | node -e '
  let input=""; process.stdin.on("data", chunk => input += chunk); process.stdin.on("end", () => {
    const records=JSON.parse(input); if (records.length !== 1 || !records[0].integrity) process.exit(2);
    process.stdout.write(records[0].integrity);
  });
')"

remote_dist=""
for attempt in $(seq 1 18); do
  remote_dist="$(env -u NODE_AUTH_TOKEN -u NPM_TOKEN NPM_CONFIG_USERCONFIG="$tmp/empty-npmrc" \
    npm view "${package}@${version}" dist --json 2>/dev/null || true)"
  if [ -n "$remote_dist" ] && [ "$remote_dist" != "null" ]; then
    break
  fi
  if [ "$attempt" -eq 18 ]; then
    echo "error: npm did not expose ${package}@${version} for identity verification" >&2
    exit 1
  fi
  sleep 10
done
remote_integrity="$(printf '%s\n' "$remote_dist" | node -e '
  let input=""; process.stdin.on("data", chunk => input += chunk); process.stdin.on("end", () => {
    const dist=JSON.parse(input); if (!dist.integrity) process.exit(2); process.stdout.write(dist.integrity);
  });
')"
if [ "$remote_integrity" != "$local_integrity" ]; then
  echo "error: ${package}@${version} registry integrity does not match the checked-out package" >&2
  echo "local:  $local_integrity" >&2
  echo "remote: $remote_integrity" >&2
  exit 1
fi

(
  cd "$tmp/audit"
  HOME="$tmp/audit-home" npm init -y >/dev/null
  env -u NODE_AUTH_TOKEN -u NPM_TOKEN HOME="$tmp/audit-home" NPM_CONFIG_USERCONFIG="$tmp/empty-npmrc" \
    npm install --ignore-scripts --no-audit --no-fund --save-exact "${package}@${version}" >/dev/null
)

for attempt in $(seq 1 18); do
  if (
    cd "$tmp/audit"
    env -u NODE_AUTH_TOKEN -u NPM_TOKEN HOME="$tmp/audit-home" NPM_CONFIG_USERCONFIG="$tmp/empty-npmrc" \
      npm audit signatures --json --include-attestations > "$tmp/audit.json" 2> "$tmp/audit.err"
  ) && node "$root/scripts/verify-npm-attestation.mjs" \
    "$tmp/audit.json" "$package" "$version" "$local_integrity" \
    "https://github.com/firelock-ai/kin" ".github/workflows/release.yml" \
    "$expected_ref" "$expected_commit"; then
    echo "Verified exact npm bytes and provenance for ${package}@${version}"
    exit 0
  fi
  if [ "$attempt" -eq 18 ]; then
    cat "$tmp/audit.err" >&2 || true
    echo "error: npm provenance for ${package}@${version} did not become verifiable" >&2
    exit 1
  fi
  sleep 10
done
