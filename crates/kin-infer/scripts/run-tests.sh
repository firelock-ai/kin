#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
#
# run-tests.sh — clean stale binaries/fingerprints and run Metal tests cleanly

set -euo pipefail

# 1. Kill any zombie GPU processes to ensure clean test environment
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${DIR}/gpu-sweep.sh" ]]; then
    "${DIR}/gpu-sweep.sh"
fi

# 2. Delete target test binaries and fingerprints to prevent stale binaries
echo "Cleaning stale test binaries and fingerprints..."

# Find all test files in tests/ and clean their compiled outputs & fingerprints
TEST_NAMES=()
if [[ -d "${DIR}/../tests" ]]; then
    for f in "${DIR}/../tests"/*.rs; do
        if [[ -f "$f" ]]; then
            basename=$(basename "$f" .rs)
            TEST_NAMES+=("$basename")
        fi
    done
fi

# Also clean library artifacts
TEST_NAMES+=("kin_infer" "kin-infer" "libkin_infer")

# Construct the find clean command
# We look under target/ for any files/dirs matching these test names
for name in "${TEST_NAMES[@]}"; do
    find "${DIR}/../target" \( -name "*${name}*" \) -exec rm -rf {} + 2>/dev/null || true
done

# 3. Run cargo test with CARGO_INCREMENTAL=0 to avoid incremental caching bugs
echo "Running tests..."
export CARGO_INCREMENTAL=0
cd "${DIR}/.."
cargo test --release --features metal "$@"
