#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
#
# Sign release artifacts for `kin update` verification.
#
# This script is called during CI release builds to:
# 1. Compute SHA-256 checksums for all release archives
# 2. Sign the checksums file with the Firelock ed25519 release key
# 3. Output checksums-sha256.txt and checksums-sha256.txt.sig
#
# Usage:
#   KIN_RELEASE_PRIVATE_KEY=<hex> ./scripts/release-sign.sh dist/kin-*.tar.gz dist/kin-*.zip
#
# Prerequisites:
#   - KIN_RELEASE_PRIVATE_KEY env var (hex-encoded 32-byte ed25519 seed)
#   - openssl with Ed25519 support (OpenSSL 1.1.1+)

set -euo pipefail

if [[ -z "${KIN_RELEASE_PRIVATE_KEY:-}" ]]; then
    echo "ERROR: KIN_RELEASE_PRIVATE_KEY env var is required" >&2
    exit 1
fi

if [[ $# -eq 0 ]]; then
    echo "Usage: $0 <archive1> [archive2] ..." >&2
    exit 1
fi

OUTDIR="${RELEASE_SIGN_OUTDIR:-.}"
CHECKSUMS="$OUTDIR/checksums-sha256.txt"
SIGNATURE="$OUTDIR/checksums-sha256.txt.sig"

# 1. Compute SHA-256 checksums (coreutils format: "hash  filename")
: > "$CHECKSUMS"
for archive in "$@"; do
    if [[ ! -f "$archive" ]]; then
        echo "WARNING: $archive not found, skipping" >&2
        continue
    fi
    basename=$(basename "$archive")
    hash=$(shasum -a 256 "$archive" | cut -d' ' -f1)
    echo "$hash  $basename" >> "$CHECKSUMS"
done

echo "Checksums:"
cat "$CHECKSUMS"
echo ""

# 2. Convert hex private key to DER format for openssl.
# Ed25519 private key DER: fixed prefix + 32-byte seed
DER_PREFIX="302e020100300506032b657004220420"
TMPDER=$(mktemp)
trap 'rm -f "$TMPDER"' EXIT

echo "${DER_PREFIX}${KIN_RELEASE_PRIVATE_KEY}" | xxd -r -p > "$TMPDER"

# 3. Sign the checksums file — produces raw 64-byte ed25519 signature.
openssl pkeyutl -sign \
    -inkey "$TMPDER" -keyform DER \
    -rawin \
    -in "$CHECKSUMS" \
    -out "$SIGNATURE"

SIG_SIZE=$(wc -c < "$SIGNATURE" | tr -d ' ')
echo "Signature: $SIGNATURE ($SIG_SIZE bytes)"
echo ""
echo "Upload both '$CHECKSUMS' and '$SIGNATURE' as release assets."
