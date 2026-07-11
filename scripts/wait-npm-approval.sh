#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

# Wait anonymously for both independently approved Kin packages. npm approvals
# are per-package and cannot be atomic: one version can become public before the
# other. That partial state is reported explicitly, while GitHub Latest remains
# blocked until both exact versions and both immutable staged channels agree.

set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <version>" >&2
  exit 2
fi

version="$1"
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
channel="$(node "$script_dir/release-order.mjs" channel "$version")"
attempts="${NPM_APPROVAL_ATTEMPTS:-90}"
delay_seconds="${NPM_APPROVAL_DELAY_SECONDS:-20}"
packages=("@kinlab/kin" "@kinlab/kin-mcp")

if ! printf '%s\n' "$attempts" | grep -Eq '^[1-9][0-9]*$'; then
  echo "error: NPM_APPROVAL_ATTEMPTS must be a positive integer" >&2
  exit 2
fi
if ! printf '%s\n' "$delay_seconds" | grep -Eq '^[0-9]+$'; then
  echo "error: NPM_APPROVAL_DELAY_SECONDS must be a non-negative integer" >&2
  exit 2
fi

tmp="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/kin-npm-approval.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT
: > "$tmp/empty-npmrc"

npm_view_version() {
  env -u NODE_AUTH_TOKEN -u NPM_TOKEN \
    NPM_CONFIG_USERCONFIG="$tmp/empty-npmrc" \
    npm view "$1" version 2>/dev/null || true
}

echo "Waiting for separate human 2FA approvals of both npm packages. A partial approval makes one package public, but cannot unblock GitHub Latest."

last_public=("<none>" "<none>")
last_channel=("<none>" "<none>")
for attempt in $(seq 1 "$attempts"); do
  approved=0
  public_count=0

  for index in "${!packages[@]}"; do
    package="${packages[$index]}"
    public_version="$(npm_view_version "${package}@${version}")"
    channel_version="$(npm_view_version "${package}@${channel}")"
    last_public[index]="${public_version:-<none>}"
    last_channel[index]="${channel_version:-<none>}"

    if [ -n "$channel_version" ] && [ "$channel_version" != "$version" ]; then
      comparison="$(node "$script_dir/release-order.mjs" compare "$channel_version" "$version")"
      if [ "$comparison" = "1" ]; then
        echo "::error::npm ${package}@${channel} is already newer at ${channel_version}; refusing to wait for or roll it back to ${version}. Reject every still-pending ${version} stage from this run before any approval or newer release, and never approve it after the channel has advanced. GitHub Latest remains blocked." >&2
        exit 1
      fi
    fi

    if [ "$public_version" = "$version" ]; then
      public_count=$((public_count + 1))
    fi
    if [ "$public_version" = "$version" ] && [ "$channel_version" = "$version" ]; then
      approved=$((approved + 1))
    fi
    printf 'npm approval %d/%d: %s public=%s %s=%s\n' \
      "$attempt" "$attempts" "$package" "${public_version:-<none>}" \
      "$channel" "${channel_version:-<none>}"
  done

  if [ "$approved" -eq "${#packages[@]}" ]; then
    echo "Both npm packages are public at ${version} with ${channel}=${version}."
    exit 0
  fi
  if [ "$public_count" -gt 0 ]; then
    echo "::warning::Partial npm approval detected (${public_count}/${#packages[@]} public). Approve the remaining staged package with 2FA; GitHub Latest is still blocked."
  fi
  if [ "$attempt" -lt "$attempts" ]; then
    sleep "$delay_seconds"
  fi
done

echo "::error::Timed out waiting for both npm approvals. @kinlab/kin public=${last_public[0]} ${channel}=${last_channel[0]}; @kinlab/kin-mcp public=${last_public[1]} ${channel}=${last_channel[1]}. Review npm Staged Packages and either finish this same release now or reject every still-pending ${version} stage before cutting or approving any newer release. Never leave an older stage pending across releases. Any already-approved package remains public; GitHub Latest was not promoted." >&2
exit 1
