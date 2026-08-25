#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
#
# FIR-2668's acceptance, run against a real emulator on a clean runner.
#
# The ticket asks for exactly this: a daemon started with KIN_STORAGE=gcs, the
# endpoint lever pointed at a fake-gcs-server container, and a seeded bucket,
# serving with zero real Google Cloud Storage traffic; then the falsification,
# stop the emulator and watch the daemon fail loud rather than fall back.
#
# It runs the shipped image rather than a cargo test on purpose. The image is
# already built with `--features gcs` by the job that calls this, so this
# exercises the same bytes an operator would run, and it needs no Rust
# toolchain in the Docker job.
#
# Bucket seeding goes through the emulator's JSON API. Creating a directory
# inside an already-running container does NOT register a bucket: fake-gcs-server
# reads its data directory at process start, and under `-backend memory` that
# tree is not the authority at all. Arm 0 proves the bucket exists before any
# arm depends on it, so a seeding failure names itself instead of arriving later
# disguised as a broken endpoint lever.
#
# Usage: scripts/test-gcs-emulator-endpoint.sh <image-ref>

set -uo pipefail

IMAGE="${1:?usage: test-gcs-emulator-endpoint.sh <image-ref>}"
GCS_IMAGE="${FAKE_GCS_IMAGE:-fsouza/fake-gcs-server:latest}"
NET="kin-gcs-net-$$"
GCS_CID=""
KIN_CID=""
BUCKET="kin-emulator-test"

cleanup() {
  [ -n "${KIN_CID}" ] && docker rm -f "${KIN_CID}" >/dev/null 2>&1
  [ -n "${GCS_CID}" ] && docker rm -f "${GCS_CID}" >/dev/null 2>&1
  docker network rm "${NET}" >/dev/null 2>&1
  KIN_CID=""; GCS_CID=""
  return 0
}
trap cleanup EXIT

fail() { echo "::error::$1" >&2; exit 1; }

contains() {
  case "$1" in
    *"$2"*) return 0 ;;
    *) return 1 ;;
  esac
}

dump_kin() {
  echo "---- kin-daemon logs ----"
  [ -n "${KIN_CID}" ] && docker logs "${KIN_CID}" 2>&1 | tail -40
  return 0
}

# Run the daemon in GCS mode against the emulator. Argv is branched rather than
# assembled in an array, because bash 3.2 aborts expanding an empty one under
# `set -u`.
start_kin() {
  local emulator_host="$1"
  KIN_CID="$(docker run -d --network "${NET}" \
    -e KIN_STORAGE=gcs \
    -e "KIN_GCS_BUCKET=${BUCKET}" \
    -e "STORAGE_EMULATOR_HOST=${emulator_host}" \
    -e KIN_DISABLE_SPINE=1 \
    "${IMAGE}" --port 4219)"
}

# Wait for either the listening line or container exit. Echoes "listening",
# "exited", or "timeout".
await_kin() {
  local i logs
  for i in $(seq 1 90); do
    logs="$(docker logs "${KIN_CID}" 2>&1 || true)"
    if contains "${logs}" "daemon API server listening"; then echo "listening"; return 0; fi
    if [ "$(docker inspect -f '{{.State.Running}}' "${KIN_CID}" 2>/dev/null || echo false)" != "true" ]; then
      echo "exited"; return 0
    fi
    sleep 1
  done
  echo "timeout"
}

echo "==> [setup] network and emulator"
docker network create "${NET}" >/dev/null || fail "could not create docker network"
GCS_CID="$(docker run -d --network "${NET}" --network-alias fake-gcs "${GCS_IMAGE}" \
  -scheme http -port 4443 -backend memory -public-host fake-gcs:4443)" \
  || fail "could not start ${GCS_IMAGE}"

# ---------------------------------------------------------------------------
# 0. Seed the bucket through the JSON API, and prove it took. Everything below
#    depends on this, so it is asserted rather than assumed.
# ---------------------------------------------------------------------------
echo "==> [seed] create bucket ${BUCKET} through the emulator's JSON API"
seeded=""
for _ in $(seq 1 30); do
  if docker run --rm --network "${NET}" --entrypoint curl "${IMAGE}" -sS -f \
      -X POST "http://fake-gcs:4443/storage/v1/b?project=kin-test" \
      -H 'Content-Type: application/json' \
      -d "{\"name\":\"${BUCKET}\"}" >/dev/null 2>&1; then
    seeded=1; break
  fi
  sleep 2
done
[ -n "${seeded}" ] || fail "could not create bucket ${BUCKET} through the emulator JSON API"

listing="$(docker run --rm --network "${NET}" --entrypoint curl "${IMAGE}" -sS \
  "http://fake-gcs:4443/storage/v1/b/${BUCKET}" 2>/dev/null || true)"
contains "${listing}" "${BUCKET}" \
  || fail "bucket ${BUCKET} does not read back from the emulator after creation; got: ${listing}"
echo "==> [seed] OK (bucket present)"

# ---------------------------------------------------------------------------
# 1. The acceptance. A daemon in GCS mode, pointed at the emulator by the
#    lever alone, must reach serving state. No GCP credentials exist in this
#    container, and the base URL never names googleapis.com, so reaching
#    serving state is reaching it through the emulator.
# ---------------------------------------------------------------------------
echo "==> [serves] daemon with KIN_STORAGE=gcs against the emulator"
start_kin "http://fake-gcs:4443"
state="$(await_kin)"
logs="$(docker logs "${KIN_CID}" 2>&1 || true)"

if [ "${state}" != "listening" ]; then
  dump_kin
  fail "daemon did not reach serving state against the emulator (state=${state}); FIR-2668's acceptance is NOT met"
fi

contains "${logs}" "GCS storage redirected to" \
  || { dump_kin; fail "daemon served but never logged the endpoint redirect, so the lever may not be what routed it"; }
contains "${logs}" "no real Google Cloud Storage traffic" \
  || { dump_kin; fail "redirect line is missing its no-real-GCP claim"; }

code="$(docker exec "${KIN_CID}" sh -c \
  "curl -o /dev/null -sS --max-time 5 -w '%{http_code}' http://127.0.0.1:4219/readiness" 2>/dev/null || true)"
[ -n "${code}" ] && [ "${code}" != "000" ] \
  || { dump_kin; fail "daemon reached listening but /readiness did not answer"; }
echo "==> [serves] OK (listening, redirect logged, /readiness http ${code})"
docker rm -f "${KIN_CID}" >/dev/null 2>&1; KIN_CID=""

# ---------------------------------------------------------------------------
# 2. The falsification the ticket names, in the two shapes an outage actually
#    takes. Without this arm, arm 1 would pass just as well for a lever being
#    ignored entirely.
#
#    They are separate because they fail differently. A closed port resolves and
#    refuses the connection. A REMOVED container also takes its network alias
#    with it, so the endpoint stops resolving at all, and asserting "nothing is
#    listening" there would be asserting on the wrong cause. Both must refuse to
#    start, and neither may fall back to real GCS or to local storage.
# ---------------------------------------------------------------------------
# assert_refused <label> <extra-substring-or-empty>
assert_refused() {
  local label="$1"
  local expect="$2"
  local state exit_code logs
  state="$(await_kin)"
  logs="$(docker logs "${KIN_CID}" 2>&1 || true)"

  [ "${state}" = "exited" ] \
    || { dump_kin; fail "${label}: daemon did not exit (state=${state}); a silent fallback is exactly what must not happen"; }

  exit_code="$(docker inspect -f '{{.State.ExitCode}}' "${KIN_CID}" 2>/dev/null || echo unknown)"
  [ "${exit_code}" != "0" ] \
    || { dump_kin; fail "${label}: daemon exited 0; the refusal must be an error"; }

  contains "${logs}" "Refusing to start" \
    || { dump_kin; fail "${label}: refusal did not say it declined to start rather than falling back"; }
  contains "${logs}" "STORAGE_EMULATOR_HOST" \
    || { dump_kin; fail "${label}: refusal did not name the variable to fix"; }
  if [ -n "${expect}" ]; then
    contains "${logs}" "${expect}" \
      || { dump_kin; fail "${label}: refusal did not name the cause (expected ${expect})"; }
  fi
  # Nothing may suggest it reached, or fell back to, another backend.
  contains "${logs}" "daemon API server listening" \
    && { dump_kin; fail "${label}: daemon reached serving state despite an unusable storage endpoint"; }
  echo "==> [${label}] OK (exit ${exit_code})"
  docker rm -f "${KIN_CID}" >/dev/null 2>&1; KIN_CID=""
  return 0
}

echo "==> [fails-loud-closed-port] emulator up, lever points at a closed port"
start_kin "http://fake-gcs:4444"
assert_refused "fails-loud-closed-port" "nothing is listening there"

echo "==> [fails-loud-emulator-gone] emulator removed entirely"
docker rm -f "${GCS_CID}" >/dev/null 2>&1; GCS_CID=""
start_kin "http://fake-gcs:4443"
assert_refused "fails-loud-emulator-gone" ""

echo "==> GCS emulator endpoint acceptance passed for ${IMAGE}"
