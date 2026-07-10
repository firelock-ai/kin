#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

# Execute the daemon binary from a built/published container and bind its
# embedded source identity to the immutable image tag expected by the builder.

set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <image> <expected-40-hex-commit>" >&2
  exit 2
fi

image="$1"
expected_sha="$2"
if ! printf '%s\n' "$expected_sha" | grep -Eq '^[0-9a-f]{40}$'; then
  echo "error: expected commit must be a full lowercase 40-hex id" >&2
  exit 2
fi

payload="$(docker run --rm --entrypoint /usr/local/bin/kin-daemon \
  "$image" --compat-json)"
printf '%s\n' "$payload"

printf '%s\n' "$payload" | grep -Fq "\"sha\":\"${expected_sha}\""
printf '%s\n' "$payload" | grep -Fq '"dirty":false'
printf '%s\n' "$payload" | grep -Fq '"source_known":true'
printf '%s\n' "$payload" \
  | grep -Eq '"dependency_provenance":"[0-9a-f]{64}"'

if printf '%s\n' "$payload" | grep -Fq '"sha":"unknown"'; then
  echo "error: container embedded unknown source identity" >&2
  exit 1
fi

echo "Verified $image embeds clean source $expected_sha with locked dependency provenance"
