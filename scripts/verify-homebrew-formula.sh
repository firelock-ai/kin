#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

# Verify the public Homebrew tap outcome for a Kin release. This deliberately
# uses the unauthenticated raw-content surface: release correctness must not
# depend on the optional token used to accelerate the tap update via dispatch.

set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <version-or-vtag>" >&2
  exit 2
fi

version="${1#v}"
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
  echo "error: expected a Kin semantic version or v-prefixed release tag, got '$1'" >&2
  exit 2
fi

formula_url="${KIN_HOMEBREW_FORMULA_URL:-https://raw.githubusercontent.com/firelock-ai/homebrew-kin/main/Formula/kin.rb}"
max_wait_seconds="${KIN_HOMEBREW_VERIFY_MAX_WAIT_SECONDS:-1800}"
max_attempts="${KIN_HOMEBREW_VERIFY_MAX_ATTEMPTS:-90}"
poll_seconds="${KIN_HOMEBREW_VERIFY_POLL_SECONDS:-20}"
curl_max_seconds="${KIN_HOMEBREW_VERIFY_CURL_MAX_SECONDS:-15}"

require_positive_integer() {
  local name="$1"
  local value="$2"
  if [[ ! "$value" =~ ^[1-9][0-9]*$ ]]; then
    echo "error: ${name} must be a positive integer, got '${value}'" >&2
    exit 2
  fi
}

require_nonnegative_integer() {
  local name="$1"
  local value="$2"
  if [[ ! "$value" =~ ^[0-9]+$ ]]; then
    echo "error: ${name} must be a non-negative integer, got '${value}'" >&2
    exit 2
  fi
}

require_positive_integer KIN_HOMEBREW_VERIFY_MAX_WAIT_SECONDS "$max_wait_seconds"
require_positive_integer KIN_HOMEBREW_VERIFY_MAX_ATTEMPTS "$max_attempts"
require_nonnegative_integer KIN_HOMEBREW_VERIFY_POLL_SECONDS "$poll_seconds"
require_positive_integer KIN_HOMEBREW_VERIFY_CURL_MAX_SECONDS "$curl_max_seconds"

deadline=$((SECONDS + max_wait_seconds))
checks=0

fail_verification() {
  echo "::error::Public firelock-ai/homebrew-kin Formula/kin.rb did not report version \"${version}\" after ${checks} checks (wall-clock limit ${max_wait_seconds}s). Dispatch is best-effort; the release cannot pass until the public formula matches. Check https://github.com/firelock-ai/homebrew-kin/actions." >&2
  exit 1
}

for ((attempt = 1; attempt <= max_attempts; attempt++)); do
  remaining=$((deadline - SECONDS))
  if ((remaining <= 0)); then
    fail_verification
  fi
  request_timeout="$curl_max_seconds"
  if ((request_timeout > remaining)); then
    request_timeout="$remaining"
  fi

  separator="?"
  if [[ "$formula_url" == *\?* ]]; then
    separator="&"
  fi
  cache_busted_url="${formula_url}${separator}kin_release=${version}&attempt=${attempt}"

  if formula="$(curl --fail --silent --show-error --location \
    --connect-timeout "$request_timeout" \
    --max-time "$request_timeout" \
    -H "Cache-Control: no-cache" \
    "$cache_busted_url")" && grep -qF "version \"${version}\"" <<<"$formula"; then
    echo "Confirmed public firelock-ai/homebrew-kin Formula/kin.rb is at version \"${version}\""
    exit 0
  fi
  checks="$attempt"

  if ((attempt >= max_attempts || SECONDS >= deadline)); then
    fail_verification
  fi

  remaining=$((deadline - SECONDS))
  sleep_for="$poll_seconds"
  if ((sleep_for > remaining)); then
    sleep_for="$remaining"
  fi
  echo "Waiting for public firelock-ai/homebrew-kin Formula/kin.rb to report version \"${version}\" (attempt ${attempt}/${max_attempts})..."
  if ((sleep_for > 0)); then
    sleep "$sleep_for"
  fi
done

echo "::error::Homebrew formula verification exhausted unexpectedly" >&2
exit 1
