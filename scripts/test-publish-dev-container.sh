#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

COMMIT="0123456789abcdef0123456789abcdef01234567"
DIGEST="sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
OTHER_DIGEST="sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
IMAGE="us-central1-docker.pkg.dev/kin-ecosystem/kin-dev/kin-daemon"
LOCK_SHA="$(sha256sum "$ROOT/Cargo.lock" 2>/dev/null | awk '{print $1}' || shasum -a 256 "$ROOT/Cargo.lock" | awk '{print $1}')"

mkdir -p "$TMP/bin" "$TMP/state"
cat > "$TMP/bin/git" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
if [ "$*" = "ls-remote origin refs/heads/main" ]; then
  printf '%s\trefs/heads/main\n' "$TEST_MAIN_SHA"
  exit 0
fi
echo "unexpected git command: $*" >&2
exit 92
SH
cat > "$TMP/bin/docker" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$TEST_LOG"

if [ "${1:-}" = buildx ] && [ "${2:-}" = imagetools ] && [ "${3:-}" = inspect ]; then
  ref="$4"
  case "$ref" in
    *:"${TEST_PUBLISH_TAG:-$TEST_COMMIT}") marker=source ;;
    *@sha256:*) printf '%s\n' "$TEST_DIGEST"; exit 0 ;;
    *) echo "unexpected inspect reference: $ref" >&2; exit 90 ;;
  esac
  if [ -f "$TEST_STATE/$marker" ]; then
    printf '%s\n' "${TEST_SOURCE_DIGEST:-$TEST_DIGEST}"
    exit 0
  fi
  echo "ERROR: ${ref}: not found" >&2
  exit 1
fi

if [ "${1:-}" = image ] && [ "${2:-}" = inspect ]; then exit 0; fi
if [ "${1:-}" = image ] && [ "${2:-}" = tag ]; then exit 0; fi
if [ "${1:-}" = push ]; then touch "$TEST_STATE/source"; exit 0; fi
if [ "${1:-}" = run ]; then
  printf '{"sha":"%s","dirty":false,"source_known":true,"dependency_provenance":"%s"}\n' \
    "${TEST_RUN_SHA:-$TEST_COMMIT}" "$TEST_LOCK_SHA"
  exit 0
fi
echo "unexpected docker command: $*" >&2
exit 91
SH
chmod +x "$TMP/bin/git" "$TMP/bin/docker"

export PATH="$TMP/bin:$PATH"
export TEST_LOG="$TMP/docker.log"
export TEST_STATE="$TMP/state"
export TEST_COMMIT="$COMMIT"
export TEST_DIGEST="$DIGEST"
export TEST_OTHER_DIGEST="$OTHER_DIGEST"
export TEST_LOCK_SHA="$LOCK_SHA"
export TEST_MAIN_SHA="$COMMIT"

cd "$ROOT"

echo "==> new full-commit tag is published once with no mutable aliases"
: > "$TEST_LOG"
rm -f "$TEST_STATE"/*
: > "$TMP/full.output"
GITHUB_OUTPUT="$TMP/full.output" bash scripts/publish-dev-container.sh \
  kin:ci "$IMAGE" "$COMMIT" "$COMMIT" | tee "$TMP/full.stdout"
grep -Fxq "push ${IMAGE}:${COMMIT}" "$TEST_LOG"
grep -Fxq "reference=${IMAGE}:${COMMIT}" "$TMP/full.output"
grep -Fxq "publication=published" "$TMP/full.output"
grep -Fxq "aliases_promoted=false" "$TMP/full.output"
grep -Fq "Published immutable development image: ${IMAGE}:${COMMIT}" \
  "$TMP/full.stdout"
if grep -Eq "imagetools create|:main|:staging-latest" "$TEST_LOG"; then
  echo "immutable full-SHA publish wrote a mutable alias" >&2
  exit 1
fi

echo "==> a fresh GitHub canary uses its own tag and never moves aliases"
: > "$TEST_LOG"
rm -f "$TEST_STATE"/*
CANARY_TAG="gha-canary-${COMMIT}"
: > "$TMP/canary.output"
TEST_PUBLISH_TAG="$CANARY_TAG" GITHUB_OUTPUT="$TMP/canary.output" \
  bash scripts/publish-dev-container.sh \
  kin:ci "$IMAGE" "$COMMIT" "$CANARY_TAG" | tee "$TMP/canary.stdout"
grep -Fxq "push ${IMAGE}:${CANARY_TAG}" "$TEST_LOG"
if grep -Eq "imagetools create|:main|:staging-latest" "$TEST_LOG"; then
  echo "GitHub canary moved mutable aliases" >&2
  exit 1
fi
grep -Fxq "reference=${IMAGE}:${CANARY_TAG}" "$TMP/canary.output"
grep -Fxq "publication=published" "$TMP/canary.output"
grep -Fxq "readback=true" "$TMP/canary.output"
grep -Fxq "embedded_sha=true" "$TMP/canary.output"
grep -Fq "Published immutable development image: ${IMAGE}:${CANARY_TAG}" \
  "$TMP/canary.stdout"

echo "==> arbitrary publish tags are rejected before registry access"
: > "$TEST_LOG"
if bash scripts/publish-dev-container.sh \
  kin:ci "$IMAGE" "$COMMIT" "mutable-main" \
  >"$TMP/arbitrary-tag.out" 2>&1; then
  echo "arbitrary mutable tag unexpectedly passed" >&2
  exit 1
fi
grep -Fq "publish tag must be the full commit" "$TMP/arbitrary-tag.out"
test ! -s "$TEST_LOG"

echo "==> an existing full-commit tag is verified and never overwritten"
: > "$TEST_LOG"
touch "$TEST_STATE/source"
bash scripts/publish-dev-container.sh kin:ci "$IMAGE" "$COMMIT" "$COMMIT"
if grep -Eq "^(push|image tag) " "$TEST_LOG"; then
  echo "existing immutable tag was overwritten" >&2
  exit 1
fi

echo "==> a moved legacy full-SHA tag is never claimed as a GitHub upload"
: > "$TEST_LOG"
touch "$TEST_STATE/source"
: > "$TMP/moved.output"
TEST_SOURCE_DIGEST="$OTHER_DIGEST" GITHUB_OUTPUT="$TMP/moved.output" \
  bash scripts/publish-dev-container.sh \
  kin:ci "$IMAGE" "$COMMIT" "$COMMIT"
grep -Fxq "digest=${OTHER_DIGEST}" "$TMP/moved.output"
grep -Fxq "publication=verified_existing" "$TMP/moved.output"
if grep -Eq "^(push|image tag) " "$TEST_LOG"; then
  echo "moved legacy tag was overwritten or claimed as freshly published" >&2
  exit 1
fi

echo "==> abbreviated commit is rejected before registry access"
: > "$TEST_LOG"
if bash scripts/publish-dev-container.sh kin:ci "$IMAGE" deadbeef deadbeef \
  >"$TMP/short.out" 2>&1; then
  echo "abbreviated commit unexpectedly passed" >&2
  exit 1
fi
grep -Fq "full lowercase 40-hex" "$TMP/short.out"
test ! -s "$TEST_LOG"

echo "publish-dev-container tests passed"
