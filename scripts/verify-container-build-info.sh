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

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
printf '%s\n' "$payload" | python3 "$script_dir/verify-daemon-compat-json.py"

if [ ! -f Cargo.lock ]; then
  echo "error: Cargo.lock is required to verify container dependency provenance" >&2
  exit 2
fi
if command -v sha256sum >/dev/null 2>&1; then
  expected_lock="$(sha256sum Cargo.lock | awk '{print $1}')"
else
  expected_lock="$(shasum -a 256 Cargo.lock | awk '{print $1}')"
fi

printf '%s\n' "$payload" | grep -Fq "\"sha\":\"${expected_sha}\""
printf '%s\n' "$payload" | grep -Fq '"dirty":false'
printf '%s\n' "$payload" | grep -Fq '"source_known":true'
printf '%s\n' "$payload" \
  | grep -Fq "\"dependency_provenance\":\"${expected_lock}\""

if printf '%s\n' "$payload" | grep -Fq '"sha":"unknown"'; then
  echo "error: container embedded unknown source identity" >&2
  exit 1
fi

echo "Verified $image embeds clean source $expected_sha with locked dependency provenance"
