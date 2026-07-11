#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

# Promote the canonical and compatibility npm packages as one recoverable
# release-channel transaction. npm has no cross-package atomic primitive, so
# every mutation is recorded before it is attempted and compensated on error.

set -Eeuo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <version>" >&2
  exit 2
fi
if [ -z "${NPM_TOKEN:-}" ]; then
  echo "error: NPM_TOKEN is required to promote proven npm versions" >&2
  exit 2
fi

VERSION="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CANDIDATE_TAG="release-candidate-$(printf '%s' "$VERSION" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g')"
FINAL_TAG="$(node "$SCRIPT_DIR/release-order.mjs" channel "$VERSION")"
VERIFY_ATTEMPTS="${NPM_PROMOTION_VERIFY_ATTEMPTS:-18}"
VERIFY_DELAY_SECONDS="${NPM_PROMOTION_VERIFY_DELAY_SECONDS:-10}"
packages=("@kinlab/kin" "@kinlab/kin-mcp")
originals=()
promoted=()

npm_channel() {
  node "$SCRIPT_DIR/release-order.mjs" npm-channel "$1" "$2"
}

verify_channel() {
  local package="$1"
  local tag="$2"
  local expected="$3"
  local resolved=""
  local attempt
  for attempt in $(seq 1 "$VERIFY_ATTEMPTS"); do
    resolved="$(env -u NODE_AUTH_TOKEN NPM_CONFIG_USERCONFIG=/dev/null \
      npm view "${package}@${tag}" version 2>/dev/null || true)"
    if [ "$resolved" = "$expected" ]; then
      return 0
    fi
    if [ "$attempt" -lt "$VERIFY_ATTEMPTS" ]; then
      sleep "$VERIFY_DELAY_SECONDS"
    fi
  done
  echo "error: anonymous npm lookup resolved ${package}@${tag} to ${resolved:-<none>}, expected $expected" >&2
  return 1
}

rollback_promotions() {
  local status="$1"
  local rollback_failed=0
  local package original resolved cursor index attempt
  trap - ERR INT TERM
  set +e
  if [ "$status" -eq 0 ]; then status=1; fi

  echo "warning: npm promotion failed; restoring every channel changed by this run" >&2
  for (( cursor=${#promoted[@]}-1; cursor>=0; cursor-- )); do
    index="${promoted[$cursor]}"
    package="${packages[$index]}"
    original="${originals[$index]}"
    if [ "$original" = "<none>" ]; then
      env NODE_AUTH_TOKEN="$NPM_TOKEN" \
        npm dist-tag rm "$package" "$FINAL_TAG" >/dev/null 2>&1 || true
    else
      env NODE_AUTH_TOKEN="$NPM_TOKEN" \
        npm dist-tag add "${package}@${original}" "$FINAL_TAG" \
        >/dev/null 2>&1 || true
    fi

    resolved=""
    for attempt in $(seq 1 "$VERIFY_ATTEMPTS"); do
      resolved="$(npm_channel "$package" "$FINAL_TAG" 2>/dev/null || true)"
      if [ "$resolved" = "$original" ]; then
        break
      fi
      if [ "$attempt" -lt "$VERIFY_ATTEMPTS" ]; then
        sleep "$VERIFY_DELAY_SECONDS"
      fi
    done
    if [ "$resolved" != "$original" ]; then
      echo "error: ROLLBACK REQUIRED: ${package}@${FINAL_TAG} is ${resolved:-<unknown>}, expected ${original}" >&2
      rollback_failed=1
    else
      echo "Restored ${package}@${FINAL_TAG} to ${original}" >&2
    fi
  done

  if [ "$rollback_failed" -ne 0 ]; then
    exit 1
  fi
  exit "$status"
}

abort_promotion() {
  echo "error: $*" >&2
  rollback_promotions 1
}

trap 'rollback_promotions $?' ERR
trap 'rollback_promotions 130' INT
trap 'rollback_promotions 143' TERM

# Establish both starting points and prove both candidates before any mutation.
for index in "${!packages[@]}"; do
  package="${packages[$index]}"
  current="$(npm_channel "$package" "$FINAL_TAG")"
  originals+=("$current")
  node "$SCRIPT_DIR/release-order.mjs" assert-not-rollback \
    "$VERSION" "$current" "npm ${package} ${FINAL_TAG}"
  candidate="$(env -u NODE_AUTH_TOKEN NPM_CONFIG_USERCONFIG=/dev/null \
    npm view "${package}@${CANDIDATE_TAG}" version 2>/dev/null || true)"
  if [ "$candidate" != "$VERSION" ]; then
    abort_promotion \
      "${package}@${CANDIDATE_TAG} resolved to ${candidate:-<none>}, expected $VERSION"
  fi
done

first_package="${packages[0]}"
second_package="${packages[1]}"
if [ "${originals[0]}" != "${originals[1]}" ]; then
  abort_promotion \
    "npm ${FINAL_TAG} is already split: ${first_package}=${originals[0]}, ${second_package}=${originals[1]}"
fi

for index in "${!packages[@]}"; do
  package="${packages[$index]}"
  current="$(npm_channel "$package" "$FINAL_TAG")"
  if [ "$current" != "${originals[$index]}" ]; then
    abort_promotion \
      "npm ${package} ${FINAL_TAG} moved from ${originals[$index]} to $current during promotion"
  fi
  if [ "$current" != "$VERSION" ]; then
    # Record intent before the write. A request may mutate the registry and lose
    # its response, so even a failed command must be included in compensation.
    promoted+=("$index")
    env NODE_AUTH_TOKEN="$NPM_TOKEN" \
      npm dist-tag add "${package}@${VERSION}" "$FINAL_TAG"
  fi
  if ! verify_channel "$package" "$FINAL_TAG" "$VERSION"; then
    abort_promotion \
      "anonymous npm proof failed for ${package}@${FINAL_TAG} after promotion"
  fi
done

# Both public channels are committed and anonymously verified. Provisional-tag
# cleanup is non-authoritative and must not roll back the final channel.
trap - ERR INT TERM
for package in "${packages[@]}"; do
  if ! env NODE_AUTH_TOKEN="$NPM_TOKEN" \
    npm dist-tag rm "$package" "$CANDIDATE_TAG"; then
    echo "warning: could not remove provisional ${package}@${CANDIDATE_TAG}; final ${FINAL_TAG} remains verified" >&2
  fi
done

echo "Promoted both npm packages to ${FINAL_TAG}=${VERSION}"
