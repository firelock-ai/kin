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
  *) echo "error: refusing to stage unexpected package $package" >&2; exit 2 ;;
esac
if [ "$expected_ref" != "refs/tags/v${version}" ]; then
  echo "error: package $package version $version does not match release ref $expected_ref" >&2
  exit 2
fi

channel="$(node "$release_order_script" channel "$version")"
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
    echo "integrity=$integrity"
    echo "shasum=$shasum"
  } >> "$GITHUB_OUTPUT"
fi

assert_channel_not_newer() {
  phase="$1"
  set +e
  current="$(env -u NODE_AUTH_TOKEN -u NPM_TOKEN \
    node "$release_order_script" npm-channel "$package" "$channel" 2>&1)"
  resolve_status=$?
  set -e
  if [ "$resolve_status" -ne 0 ]; then
    printf '%s\n' "$current" >&2
    if [ "$phase" = "after" ]; then
      echo "::error::npm accepted the ${package}@${version} stage, but ${package}@${channel} could not be re-read afterward. Treat ${version} as pending and reject it before any approval or newer release unless an authenticated maintainer verifies this same release immediately." >&2
    else
      echo "::error::npm ${package}@${channel} could not be re-read immediately before staging ${version}; no stage was submitted." >&2
    fi
    return "$resolve_status"
  fi

  set +e
  check_output="$(env -u NODE_AUTH_TOKEN -u NPM_TOKEN \
    node "$release_order_script" assert-not-rollback \
      "$version" "$current" "npm ${package} ${channel}" 2>&1)"
  check_status=$?
  set -e
  printf '%s\n' "$check_output"
  if [ "$check_status" -eq 0 ]; then
    return 0
  fi
  if [ "$phase" = "after" ]; then
    echo "::error::npm ${package}@${channel} advanced to ${current} while ${package}@${version} was being staged. Reject the newly pending ${version} stage before any approval or newer release; never approve it after the channel has advanced." >&2
  else
    echo "::error::npm ${package}@${channel} advanced to ${current} immediately before staging ${version}; no stage was submitted. Resolve every older pending stage before cutting or approving another release." >&2
  fi
  return "$check_status"
}

# The config job checks release order before long build/proof jobs. Re-read the
# anonymous registry authority at the last possible moment so a newer release
# cannot advance this channel during that gap and be rolled back by approval.
assert_channel_not_newer before

set +e
stage_output="$(env -u NODE_AUTH_TOKEN -u NPM_TOKEN \
  NPM_CONFIG_USERCONFIG="$tmp/empty-npmrc" \
  npm stage publish "$tarball" --access public --tag "$channel" \
    --provenance 2>&1)"
stage_status=$?
set -e
printf '%s\n' "$stage_output"
if [ "$stage_status" -ne 0 ]; then
  echo "::error::npm could not stage ${package}@${version} for ${channel}. If this exact version is already pending approval, npm's version-uniqueness rule causes this retry to fail and the OIDC identity cannot inspect staged packages. Approve it with 2FA only to finish this same release, or reject it there before retrying. Never cut or approve a newer release while this older stage remains pending. GitHub Latest remains blocked." >&2
  exit "$stage_status"
fi

# A competing release can still advance between the pre-stage read and npm's
# stage write. The stage is not public yet, so fail with an explicit rejection
# requirement before a human can accidentally approve an older pending version.
assert_channel_not_newer after

echo "Staged ${package}@${version} with immutable npm channel ${channel}; expected integrity=${integrity} shasum=${shasum}. Authenticated inspection and human 2FA approval are required before it becomes public."
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  echo "staged=true" >> "$GITHUB_OUTPUT"
fi
