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

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
validator="${script_dir}/validate-homebrew-formula.py"
if [[ ! -r "$validator" ]]; then
  echo "error: Homebrew formula validator is missing: ${validator}" >&2
  exit 2
fi

formula_url="${KIN_HOMEBREW_FORMULA_URL:-https://raw.githubusercontent.com/firelock-ai/homebrew-kin/main/Formula/kin.rb}"
release_base_url="${KIN_HOMEBREW_RELEASE_BASE_URL:-https://github.com/firelock-ai/kin/releases/download/v${version}}"
max_wait_seconds="${KIN_HOMEBREW_VERIFY_MAX_WAIT_SECONDS:-1800}"
max_attempts="${KIN_HOMEBREW_VERIFY_MAX_ATTEMPTS:-90}"
poll_seconds="${KIN_HOMEBREW_VERIFY_POLL_SECONDS:-20}"
curl_max_seconds="${KIN_HOMEBREW_VERIFY_CURL_MAX_SECONDS:-15}"
artifacts=(
  "kin-macos-aarch64.tar.gz"
  "kin-macos-x86_64.tar.gz"
  "kin-linux-aarch64.tar.gz"
  "kin-linux-x86_64.tar.gz"
)

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
last_error="verification did not run"

cache_busted_url() {
  local base_url="$1"
  local kind="$2"
  local attempt="$3"
  local separator="?"
  if [[ "$base_url" == *\?* ]]; then
    separator="&"
  fi
  printf '%s%skin_release=%s&attempt=%s&kind=%s' \
    "$base_url" "$separator" "$version" "$attempt" "$kind"
}

fetch_public() {
  local url="$1"
  local remaining request_timeout
  remaining=$((deadline - SECONDS))
  if ((remaining <= 0)); then
    return 124
  fi
  request_timeout="$curl_max_seconds"
  if ((request_timeout > remaining)); then
    request_timeout="$remaining"
  fi

  # --disable prevents a runner-local curlrc from injecting credentials. All
  # public proof reads are deliberately token-free and share the one deadline.
  curl --disable --fail --silent --show-error --location \
    --connect-timeout "$request_timeout" \
    --max-time "$request_timeout" \
    -H "Cache-Control: no-cache" \
    -H "Pragma: no-cache" \
    "$url"
}

fail_verification() {
  echo "::error::Public firelock-ai/homebrew-kin Formula/kin.rb did not exactly match Kin v${version} after ${checks} checks (wall-clock limit ${max_wait_seconds}s). Dispatch is best-effort; the release cannot pass until the public formula version, platform URLs, and SHA-256 values match the public release. Last validation error: ${last_error}. Check https://github.com/firelock-ai/homebrew-kin/actions." >&2
  exit 1
}

for ((attempt = 1; attempt <= max_attempts; attempt++)); do
  if ((SECONDS >= deadline)); then
    last_error="the shared wall-clock deadline expired before attempt ${attempt}"
    fail_verification
  fi
  checks="$attempt"

  formula_attempt_url="$(cache_busted_url "$formula_url" formula "$attempt")"

  formula=""
  sidecars=()
  if ! formula="$(fetch_public "$formula_attempt_url")"; then
    last_error="the token-free public formula request failed"
  else
    checksums_ready=true
    for artifact in "${artifacts[@]}"; do
      checksum_url="${release_base_url}/${artifact}.sha256"
      checksum_attempt_url="$(cache_busted_url "$checksum_url" "checksum-${artifact}" "$attempt")"
      sidecar=""
      if ! sidecar="$(fetch_public "$checksum_attempt_url")"; then
        last_error="the token-free public release checksum request failed for ${artifact}"
        checksums_ready=false
        break
      fi
      sidecars+=("$sidecar")
    done

    if [[ "$checksums_ready" == true ]]; then
      validation_error=""
      if validation_error="$({
        printf '%s\0' "$formula"
        for sidecar in "${sidecars[@]}"; do
          printf '%s\0' "$sidecar"
        done
      } | python3 "$validator" "$version" 2>&1)"; then
        echo "Confirmed public firelock-ai/homebrew-kin Formula/kin.rb exactly matches Kin v${version} and all four public release checksums"
        exit 0
      fi
      last_error="${validation_error:-the exact formula validator failed without a diagnostic}"
    fi
  fi

  if ((attempt >= max_attempts || SECONDS >= deadline)); then
    fail_verification
  fi

  remaining=$((deadline - SECONDS))
  sleep_for="$poll_seconds"
  if ((sleep_for > remaining)); then
    sleep_for="$remaining"
  fi
  echo "Waiting for the public Homebrew formula to exactly match Kin v${version} (attempt ${attempt}/${max_attempts}; ${last_error})..."
  if ((sleep_for > 0)); then
    sleep "$sleep_for"
  fi
done

echo "::error::Homebrew formula verification exhausted unexpectedly" >&2
exit 1
