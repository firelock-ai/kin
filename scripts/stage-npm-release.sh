#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

# Submit exactly one Kin npm package to npm's human-approval staging area.
# Trusted Publishing supplies a short-lived OIDC credential only to the
# `npm stage publish` operation. It cannot list, view, approve, reject, or
# mutate tags, so every other registry read in this script is anonymous.

set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "usage: $0 <package-dir> <expected-ref> <expected-commit>" >&2
  exit 2
fi

package_dir="$1"
expected_ref="$2"
expected_commit="$3"
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd -- "$script_dir/.." && pwd)"
verify_script="${NPM_RELEASE_VERIFY_SCRIPT:-$script_dir/verify-npm-release.sh}"

if [ ! -f "$package_dir/package.json" ]; then
  echo "error: package manifest not found: $package_dir/package.json" >&2
  exit 2
fi
if ! printf '%s\n' "$expected_commit" | grep -Eq '^[0-9a-f]{40}$'; then
  echo "error: expected commit must be a full lowercase 40-hex id" >&2
  exit 2
fi
if [ "$(git -C "$root" rev-parse HEAD)" != "$expected_commit" ]; then
  echo "error: expected commit does not match the checked-out release source" >&2
  exit 2
fi

package="$(node -e '
  const manifest = require(process.argv[1]);
  if (typeof manifest.name !== "string") process.exit(2);
  process.stdout.write(manifest.name);
' "$(cd -- "$package_dir" && pwd)/package.json")"
version="$(node -e '
  const manifest = require(process.argv[1]);
  if (typeof manifest.version !== "string") process.exit(2);
  process.stdout.write(manifest.version);
' "$(cd -- "$package_dir" && pwd)/package.json")"

case "$package" in
  @kinlab/kin|@kinlab/kin-mcp) ;;
  *) echo "error: refusing to stage unexpected package $package" >&2; exit 2 ;;
esac
if [ "$expected_ref" != "refs/tags/v${version}" ]; then
  echo "error: package $package version $version does not match release ref $expected_ref" >&2
  exit 2
fi

channel="$(node "$script_dir/release-order.mjs" channel "$version")"
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  {
    echo "package=$package"
    echo "version=$version"
    echo "channel=$channel"
  } >> "$GITHUB_OUTPUT"
fi

tmp="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/kin-npm-stage.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/pack"
: > "$tmp/empty-npmrc"

public_version="$(env -u NODE_AUTH_TOKEN -u NPM_TOKEN \
  NPM_CONFIG_USERCONFIG="$tmp/empty-npmrc" \
  npm view "${package}@${version}" version 2>/dev/null || true)"
if [ -n "$public_version" ]; then
  if [ "$public_version" != "$version" ]; then
    echo "error: npm returned unexpected public identity ${package}@${public_version}" >&2
    exit 1
  fi
  env -u NODE_AUTH_TOKEN -u NPM_TOKEN "$verify_script" \
    "$package" "$version" "$package_dir" "$expected_ref" "$expected_commit"
  echo "${package}@${version} is already public; exact bytes and provenance verified before skipping staging."
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    echo "staged=false" >> "$GITHUB_OUTPUT"
  fi
  exit 0
fi

pack_json="$(env -u NODE_AUTH_TOKEN -u NPM_TOKEN \
  NPM_CONFIG_USERCONFIG="$tmp/empty-npmrc" \
  npm pack "$package_dir" --json --pack-destination "$tmp/pack")"
tarball="$(printf '%s\n' "$pack_json" | node -e '
  let input = "";
  process.stdin.on("data", (chunk) => { input += chunk; });
  process.stdin.on("end", () => {
    const records = JSON.parse(input);
    if (records.length !== 1 || typeof records[0].filename !== "string") process.exit(2);
    process.stdout.write(records[0].filename);
  });
')"
tarball="$tmp/pack/$tarball"
test -f "$tarball"

set +e
stage_output="$(env -u NODE_AUTH_TOKEN -u NPM_TOKEN \
  NPM_CONFIG_USERCONFIG="$tmp/empty-npmrc" \
  npm stage publish "$tarball" --access public --tag "$channel" \
    --provenance 2>&1)"
stage_status=$?
set -e
printf '%s\n' "$stage_output"
if [ "$stage_status" -ne 0 ]; then
  echo "::error::npm could not stage ${package}@${version} for ${channel}. If this exact version is already pending approval, npm's version-uniqueness rule causes this retry to fail and the OIDC identity cannot inspect staged packages. Approve it with 2FA in npm Staged Packages and rerun, or reject it there before retrying. GitHub Latest remains blocked." >&2
  exit "$stage_status"
fi

echo "Staged ${package}@${version} with immutable npm channel ${channel}; human 2FA approval is required before it becomes public."
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  echo "staged=true" >> "$GITHUB_OUTPUT"
fi
