#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

# Publish exactly one Kin npm package through npm Trusted Publishing. The
# protected tag workflow supplies a short-lived OIDC credential only to the
# `npm publish` operation. Every registry read is anonymous, and reruns verify
# immutable public bytes plus provenance before treating an existing version as
# success.

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
release_order_script="${NPM_RELEASE_ORDER_SCRIPT:-$script_dir/release-order.mjs}"

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
  *) echo "error: refusing to publish unexpected package $package" >&2; exit 2 ;;
esac
if [ "$expected_ref" != "refs/tags/v${version}" ]; then
  echo "error: package $package version $version does not match release ref $expected_ref" >&2
  exit 2
fi

channel="$(node "$release_order_script" channel "$version")"
tmp="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/kin-npm-publish.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/pack"
: > "$tmp/empty-npmrc"

pack_json="$(env -u NODE_AUTH_TOKEN -u NPM_TOKEN \
  NPM_CONFIG_USERCONFIG="$tmp/empty-npmrc" \
  npm pack "$package_dir" --json --pack-destination "$tmp/pack")"
pack_field() {
  printf '%s\n' "$pack_json" | node -e '
  let input = "";
  process.stdin.on("data", (chunk) => { input += chunk; });
  process.stdin.on("end", () => {
    const records = JSON.parse(input);
    const field = process.argv[1];
    if (records.length !== 1 || typeof records[0][field] !== "string") process.exit(2);
    process.stdout.write(records[0][field]);
  });
  ' "$1"
}
tarball_name="$(pack_field filename)"
integrity="$(pack_field integrity)"
shasum="$(pack_field shasum)"
tarball="$tmp/pack/$tarball_name"
test -f "$tarball"
case "$integrity" in
  sha512-*) ;;
  *) echo "error: npm pack returned an invalid SHA-512 integrity for ${package}@${version}" >&2; exit 1 ;;
esac
if ! printf '%s\n' "$shasum" | grep -Eq '^[0-9a-f]{40}$'; then
  echo "error: npm pack returned an invalid SHA-1 shasum for ${package}@${version}" >&2
  exit 1
fi
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  {
    echo "package=$package"
    echo "version=$version"
    echo "channel=$channel"
    echo "integrity=$integrity"
    echo "shasum=$shasum"
  } >> "$GITHUB_OUTPUT"
fi

npm_view_version() {
  env -u NODE_AUTH_TOKEN -u NPM_TOKEN \
    NPM_CONFIG_USERCONFIG="$tmp/empty-npmrc" \
    npm view "$1" version 2>/dev/null || true
}

read_channel() {
  env -u NODE_AUTH_TOKEN -u NPM_TOKEN \
    node "$release_order_script" npm-channel "$package" "$channel"
}

require_exact_channel() {
  phase="$1"
  set +e
  current="$(read_channel 2>&1)"
  read_status=$?
  set -e
  if [ "$read_status" -ne 0 ]; then
    printf '%s\n' "$current" >&2
    echo "::error::${package}@${version} is public, but npm ${package}@${channel} could not be re-read ${phase}. The immutable version cannot be rolled back; rerun this same release after registry recovery. GitHub Latest remains blocked." >&2
    return "$read_status"
  fi
  if [ "$current" != "$version" ]; then
    echo "::error::${package}@${version} is public, but npm ${package}@${channel} resolves to ${current}. Do not mutate tags manually or cut a newer release; rerun or investigate this same release. GitHub Latest remains blocked." >&2
    return 1
  fi
}

public_version="$(npm_view_version "${package}@${version}")"
if [ -n "$public_version" ]; then
  if [ "$public_version" != "$version" ]; then
    echo "error: npm returned unexpected public identity ${package}@${public_version}" >&2
    exit 1
  fi
  env -u NODE_AUTH_TOKEN -u NPM_TOKEN "$verify_script" \
    "$package" "$version" "$package_dir" "$expected_ref" "$expected_commit"
  require_exact_channel "while verifying an idempotent rerun"
  echo "${package}@${version} is already public; exact bytes, final channel, and provenance verified before skipping publication."
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    echo "published=false" >> "$GITHUB_OUTPUT"
  fi
  exit 0
fi

set +e
current="$(read_channel 2>&1)"
read_status=$?
set -e
if [ "$read_status" -ne 0 ]; then
  printf '%s\n' "$current" >&2
  echo "::error::npm ${package}@${channel} could not be re-read immediately before publishing ${version}; nothing was published." >&2
  exit "$read_status"
fi
env -u NODE_AUTH_TOKEN -u NPM_TOKEN \
  node "$release_order_script" assert-not-rollback \
    "$version" "$current" "npm ${package} ${channel}"

set +e
publish_output="$(env -u NODE_AUTH_TOKEN -u NPM_TOKEN \
  NPM_CONFIG_USERCONFIG="$tmp/empty-npmrc" \
  npm publish "$tarball" --access public --tag "$channel" \
    --provenance 2>&1)"
publish_status=$?
set -e
printf '%s\n' "$publish_output"

if [ "$publish_status" -ne 0 ]; then
  # A transport failure can occur after npm accepts the immutable version.
  # Recover only when anonymous public authority proves the exact version,
  # bytes, provenance, and final channel from this same release.
  accepted=""
  for attempt in 1 2 3 4 5 6; do
    accepted="$(npm_view_version "${package}@${version}")"
    if [ "$accepted" = "$version" ]; then
      break
    fi
    if [ "$attempt" -lt 6 ]; then
      sleep 5
    fi
  done
  if [ "$accepted" != "$version" ]; then
    echo "::error::npm could not publish ${package}@${version} to ${channel}, and the exact version did not become publicly verifiable. GitHub Latest remains blocked; rerun this same release after correcting the Trusted Publisher or registry failure." >&2
    exit "$publish_status"
  fi
  echo "::warning::npm returned failure after accepting ${package}@${version}; recovering from anonymous public authority."
fi

env -u NODE_AUTH_TOKEN -u NPM_TOKEN "$verify_script" \
  "$package" "$version" "$package_dir" "$expected_ref" "$expected_commit"
require_exact_channel "after publication"

echo "Published ${package}@${version} automatically through OIDC on immutable npm channel ${channel}; verified integrity=${integrity} shasum=${shasum}."
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  echo "published=true" >> "$GITHUB_OUTPUT"
fi
