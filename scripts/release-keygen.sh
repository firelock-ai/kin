#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
#
# Generate an ed25519 keypair for signing kin release artifacts.
#
# Output:
#   release-signing.key     — 32-byte private key (hex, KEEP SECRET)
#   release-signing.pub     — 32-byte public key (hex, embed in binary)
#
# Usage:
#   ./scripts/release-keygen.sh
#
# Then set the CI secret:
#   KIN_RELEASE_PUBLIC_KEY=<contents of release-signing.pub>
#   KIN_RELEASE_PRIVATE_KEY=<contents of release-signing.key>

set -euo pipefail

if ! command -v openssl &>/dev/null; then
    echo "ERROR: openssl is required" >&2
    exit 1
fi

OUTDIR="${1:-.}"

# Generate raw ed25519 keypair via openssl
TMPKEY=$(mktemp)
trap 'rm -f "$TMPKEY"' EXIT

openssl genpkey -algorithm Ed25519 -outform DER -out "$TMPKEY" 2>/dev/null

# Extract raw 32-byte private seed (bytes 16..48 of the DER-encoded private key)
# DER structure: SEQUENCE { SEQUENCE { OID }, OCTET_STRING { OCTET_STRING { 32-byte seed } } }
PRIVATE_HEX=$(openssl pkey -in "$TMPKEY" -inform DER -text -noout 2>/dev/null \
    | grep -A 4 'priv:' \
    | tail -n +2 \
    | tr -d ' :\n')

PUBLIC_HEX=$(openssl pkey -in "$TMPKEY" -inform DER -text -noout 2>/dev/null \
    | grep -A 3 'pub:' \
    | tail -n +2 \
    | tr -d ' :\n')

echo "$PRIVATE_HEX" > "$OUTDIR/release-signing.key"
echo "$PUBLIC_HEX"  > "$OUTDIR/release-signing.pub"

chmod 600 "$OUTDIR/release-signing.key"

echo "Generated release signing keypair:"
echo "  Private key: $OUTDIR/release-signing.key (KEEP SECRET)"
echo "  Public key:  $OUTDIR/release-signing.pub"
echo ""
echo "Set in CI:"
echo "  KIN_RELEASE_PUBLIC_KEY=$(cat "$OUTDIR/release-signing.pub")"
