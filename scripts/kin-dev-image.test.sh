#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

COMMIT="0123456789abcdef0123456789abcdef01234567"
LOCK_SHA="$(sha256sum "$ROOT/Cargo.lock" 2>/dev/null | awk '{print $1}' || shasum -a 256 "$ROOT/Cargo.lock" | awk '{print $1}')"
mkdir -p "$TMP/bin"

cat > "$TMP/bin/git" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$TEST_GIT_LOG"
args="$*"
case "$args" in
  *" rev-parse HEAD") printf '%s\n' "$TEST_COMMIT" ;;
  *" symbolic-ref --quiet --short HEAD") printf '%s\n' main ;;
  *" status --porcelain --untracked-files=all") printf '%s' "${TEST_DIRTY:-}" ;;
  *" remote get-url origin") printf '%s\n' "${TEST_ORIGIN:-https://github.com/firelock-ai/kin.git}" ;;
  *" fetch --quiet origin main") ;;
  *" rev-parse ${TEST_COMMIT}^{commit}") printf '%s\n' "$TEST_COMMIT" ;;
  *" merge-base --is-ancestor ${TEST_COMMIT} origin/main") exit "${TEST_ANCESTOR_STATUS:-0}" ;;
  *) echo "unexpected git command: $args" >&2; exit 90 ;;
esac
SH

cat > "$TMP/bin/docker" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$TEST_DOCKER_LOG"
if [ "${1:-}" = buildx ] && [ "${2:-}" = build ]; then exit 0; fi
if [ "${1:-}" = run ]; then
  printf '{"sha":"%s","dirty":false,"source_known":true,"dependency_provenance":"%s"}\n' \
    "$TEST_COMMIT" "$TEST_LOCK_SHA"
  exit 0
fi
echo "unexpected docker command: $*" >&2
exit 91
SH

cat > "$TMP/bin/gh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$TEST_GH_LOG"
case "$*" in
  "run list "*"--json databaseId --jq "*)
    [ ! -f "$TEST_GH_STATE" ] || printf '%s\n' 123
    ;;
  "workflow run docker.yml "*)
    touch "$TEST_GH_STATE"
    ;;
  "run list "*"--json databaseId,displayTitle,url,status "*)
    [ ! -f "$TEST_GH_STATE" ] || printf '123\tDev image %s %s\thttps://github.com/firelock-ai/kin/actions/runs/123\tqueued\n' "$TEST_MODE" "$TEST_COMMIT"
    ;;
  "run watch 123 "*)
    exit "${TEST_WATCH_STATUS:-0}"
    ;;
  "run view 123 "*" --log")
    if [ "${TEST_NO_PROOF:-0}" != 1 ]; then
      publication="${TEST_PUBLICATION:-published}"
      printf 'publish\tKIN_DEV_IMAGE_PROOF mode=%s source=%s reference=us-central1-docker.pkg.dev/kin-ecosystem/kin-dev/kin-daemon:%s digest=sha256:%064d publication=%s aliases_promoted=%s readback=true embedded_sha=true transport=github-hosted\n' \
        "$TEST_MODE" "$TEST_COMMIT" "$TEST_REFERENCE_TAG" 0 "$publication" "$TEST_ALIASES"
    fi
    ;;
  *) echo "unexpected gh command: $*" >&2; exit 92 ;;
esac
SH
cat > "$TMP/bin/sleep" <<'SH'
#!/usr/bin/env bash
exit 0
SH
chmod +x "$TMP/bin/git" "$TMP/bin/docker" "$TMP/bin/gh" "$TMP/bin/sleep"

export TEST_COMMIT="$COMMIT"
export TEST_LOCK_SHA="$LOCK_SHA"
export TEST_GIT_LOG="$TMP/git.log"
export TEST_DOCKER_LOG="$TMP/docker.log"
export TEST_GH_LOG="$TMP/gh.log"
export TEST_GH_STATE="$TMP/gh.state"
export TEST_MODE=canary
export TEST_REFERENCE_TAG="gha-canary-${COMMIT}"
export TEST_ALIASES=false
export PATH="$TMP/bin:$PATH"
export KIN_DEV_IMAGE_GIT="$TMP/bin/git"
export KIN_DEV_IMAGE_DOCKER="$TMP/bin/docker"
export KIN_DEV_IMAGE_GH="$TMP/bin/gh"

cd "$ROOT"

echo "==> clean local build carries exact identity and thin LTO"
: > "$TEST_GIT_LOG"; : > "$TEST_DOCKER_LOG"
TEST_DIRTY= bash scripts/kin-dev-image local kin:test
grep -Fq -- "--build-arg KIN_BUILD_GIT_SHA=${COMMIT}" "$TEST_DOCKER_LOG"
grep -Fq -- "--build-arg KIN_BUILD_DIRTY=false" "$TEST_DOCKER_LOG"
grep -Fq -- "--build-arg KIN_LTO=thin" "$TEST_DOCKER_LOG"

echo "==> dirty local build cannot claim a clean source identity"
: > "$TEST_DOCKER_LOG"
TEST_DIRTY=' M src/lib.rs' bash scripts/kin-dev-image local kin:dirty
if grep -Fq "KIN_BUILD_GIT_SHA=" "$TEST_DOCKER_LOG"; then
  echo "dirty local build received a trusted source override" >&2
  exit 1
fi

echo "==> canary proves a fresh namespaced upload for one exact commit"
: > "$TEST_GIT_LOG"; : > "$TEST_GH_LOG"
rm -f "$TEST_GH_STATE"
bash scripts/kin-dev-image canary "$COMMIT"
grep -Fxq "workflow run docker.yml --repo firelock-ai/kin --ref main -f commit=${COMMIT} -f mode=canary" "$TEST_GH_LOG"
grep -Fq "merge-base --is-ancestor ${COMMIT} origin/main" "$TEST_GIT_LOG"
grep -Fq "run watch 123 --repo firelock-ai/kin --exit-status" "$TEST_GH_LOG"

echo "==> an existing canary cannot masquerade as fresh cutover proof"
: > "$TEST_GH_LOG"
rm -f "$TEST_GH_STATE"
if TEST_PUBLICATION=verified_existing bash scripts/kin-dev-image canary "$COMMIT" \
  >"$TMP/existing-canary.out" 2>&1; then
  echo "existing canary unexpectedly passed as a fresh publication" >&2
  exit 1
fi
grep -Fq "without a fresh GitHub canary publication proof" \
  "$TMP/existing-canary.out"

echo "==> hosted publish uses the full-SHA tag and accepts proven replay"
: > "$TEST_GH_LOG"
rm -f "$TEST_GH_STATE"
TEST_MODE=publish TEST_REFERENCE_TAG="$COMMIT" TEST_ALIASES=false \
  TEST_PUBLICATION=verified_existing \
  bash scripts/kin-dev-image hosted "$COMMIT"
grep -Fxq "workflow run docker.yml --repo firelock-ai/kin --ref main -f commit=${COMMIT} -f mode=publish" "$TEST_GH_LOG"

echo "==> non-main commit is refused before GitHub dispatch"
: > "$TEST_GH_LOG"
if TEST_ANCESTOR_STATUS=1 bash scripts/kin-dev-image hosted "$COMMIT" \
  >"$TMP/non-main.out" 2>&1; then
  echo "non-main commit unexpectedly dispatched" >&2
  exit 1
fi
grep -Fq "not reachable from origin/main" "$TMP/non-main.out"
test ! -s "$TEST_GH_LOG"

echo "==> abbreviated commit and non-canonical origin are refused"
if bash scripts/kin-dev-image hosted deadbeef >"$TMP/short.out" 2>&1; then
  echo "abbreviated commit unexpectedly dispatched" >&2
  exit 1
fi
grep -Fq "full lowercase 40-hex" "$TMP/short.out"
if TEST_ORIGIN=https://github.com/example/fork.git bash scripts/kin-dev-image hosted "$COMMIT" \
  >"$TMP/origin.out" 2>&1; then
  echo "fork origin unexpectedly dispatched upstream" >&2
  exit 1
fi
grep -Fq "not the canonical firelock-ai/kin" "$TMP/origin.out"

echo "==> a green run without digest proof is refused"
: > "$TEST_GH_LOG"
rm -f "$TEST_GH_STATE"
if TEST_NO_PROOF=1 bash scripts/kin-dev-image canary "$COMMIT" \
  >"$TMP/no-proof.out" 2>&1; then
  echo "proofless hosted run unexpectedly passed" >&2
  exit 1
fi
grep -Fq "without a fresh GitHub canary publication proof" "$TMP/no-proof.out"

echo "kin-dev-image tests passed"
