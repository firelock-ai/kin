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
# GCS mode is an admitted mode, not just a storage selector. A daemon started
# with KIN_STORAGE=gcs refuses without an exact image identity, a fleet
# allowlist that contains the id it serves, and two distinct API credentials,
# because those are what fence hosted graph publication. So this smoke supplies
# all of them the way a hosted deployment does, and arm 1b removes the image
# identity again to prove the requirement is still live in these bytes rather
# than satisfied by something else.
#
# Bucket seeding goes through the emulator's JSON API. Creating a directory
# inside an already-running container does NOT register a bucket: fake-gcs-server
# reads its data directory at process start, and under `-backend memory` that
# tree is not the authority at all. Arm 0 proves the bucket exists before any
# arm depends on it, so a seeding failure names itself instead of arriving later
# disguised as a broken endpoint lever.
#
# Arm 1a is FIR-3059's acceptance on these same bytes. The daemon arm 1 starts
# bootstraps the GCS publication-control record before it serves, and the lease
# in that record is the window its first hosted rollout runs under. On
# 2026-09-02 that window was 300 s and nothing renewed it, so production's first
# Firestore rollout died with every write done and none of the credit kept. The
# arm reads the record back out of the emulator, the way a real record is read,
# and grades the window against the value the daemon owns; the grader is
# falsified first against the pre-fix shape, so a grader that accepts anything
# cannot pass.
#
# Usage: scripts/test-gcs-emulator-endpoint.sh <image-ref>

set -uo pipefail

IMAGE="${1:?usage: test-gcs-emulator-endpoint.sh <image-ref>}"
GCS_IMAGE="${FAKE_GCS_IMAGE:-fsouza/fake-gcs-server:latest}"
NET="kin-gcs-net-$$"
GCS_CID=""
KIN_CID=""
BUCKET="kin-emulator-test"

# The entrypoint runs `kin init`, which mints a fresh UUID v4 repo id into the
# manifest on every container start, and `served_repo_key_space` refuses to
# start a GCS daemon whose KIN_REPO_IDS omits the id it will advertise. Pin the
# served id and the fleet allowlist to one value so the two agree by
# construction instead of by whatever that start happened to mint. It is a real
# UUID v4 because a minted repo identity is one.
REPO_ID="8f1c0e64-2b7a-4d59-9a3e-6c5b1f0d7a42"
# GCS mode also refuses without an ordinary daemon credential and a DISTINCT
# administrator credential for the publication-control API. Distinct is the
# point: the daemon rejects a shared value outright.
DAEMON_TOKEN="emulator-daemon-token"
PUBLICATION_TOKEN="emulator-publication-admin-token"

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

# The exact image identity the daemon admits itself under in GCS mode.
#
# `create_state` refuses GCS mode without KIN_RELEASE_DAEMON_DIGEST_INTERNAL,
# and `validate_image_identity` in crates/kin-daemon/src/publication_lease.rs
# admits exactly `sha256:` followed by 64 lowercase hex characters. Production
# passes the pinned REGISTRY digest of the image the pod runs (kin-infra
# compute/workloads.ts). This job never pushes, so no registry digest for these
# bytes exists anywhere, and `.RepoDigests` is not a stand-in: depending on the
# image store it is either empty or a restatement of the local digest.
# `--format '{{.Id}}'` is the honest source. It is the image's own
# content-addressed identity, it is always present, and it already carries the
# shape the daemon admits. Asserting that shape here means a docker that
# answered with something else says so by name rather than arriving later
# disguised as an admission failure.
IMAGE_IDENTITY="$(docker image inspect --format '{{.Id}}' "${IMAGE}" 2>/dev/null || true)"
printf '%s' "${IMAGE_IDENTITY}" | grep -Eq '^sha256:[0-9a-f]{64}$' \
  || fail "docker image inspect gave no sha256:<64 lowercase hex> identity for ${IMAGE} (got '${IMAGE_IDENTITY}'); the daemon's validate_image_identity admits nothing else"

# Run the daemon in GCS mode against the emulator.
#
# start_kin <emulator-host> [omit-identity]
#
# There is ONE argv here rather than a copy per arm: a second copy is only ever
# wrong in a way that looks like a passing run, because the arm that lost a
# variable cannot fail on it. The identity is the only argument that varies, so
# it is the only one held in an array, and bash 3.2 aborts expanding an EMPTY
# array under `set -u`, so it is expanded through the `${arr[@]+...}` guard.
start_kin() {
  local emulator_host="$1"
  local identity_mode="${2:-with-identity}"
  local identity_env=(-e "KIN_RELEASE_DAEMON_DIGEST_INTERNAL=${IMAGE_IDENTITY}")
  [ "${identity_mode}" = "omit-identity" ] && identity_env=()
  KIN_CID="$(docker run -d --network "${NET}" \
    -e KIN_STORAGE=gcs \
    -e "KIN_GCS_BUCKET=${BUCKET}" \
    -e "STORAGE_EMULATOR_HOST=${emulator_host}" \
    -e KIN_DISABLE_SPINE=1 \
    -e "KIN_REPO_ID=${REPO_ID}" \
    -e "KIN_REPO_IDS=${REPO_ID}" \
    -e "KIN_DAEMON_AUTH_TOKEN=${DAEMON_TOKEN}" \
    -e "KIN_PUBLICATION_CONTROL_AUTH_TOKEN=${PUBLICATION_TOKEN}" \
    ${identity_env[@]+"${identity_env[@]}"} \
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

# ---------------------------------------------------------------------------
# 1a. The startup rollout lease these bytes mint (FIR-3059). See the header.
#     The grader is a function so it can be run against fixtures before it is
#     run against the record; a grader that only ever sees the live record
#     cannot show it would have refused the shape that failed production.
# ---------------------------------------------------------------------------
# grade_lease_window <record-json>: prints one PASS, FAIL or UNREADABLE line;
# exits 0 on PASS, 1 on FAIL, 2 when the record carries no readable lease.
grade_lease_window() {
  python3 - "$1" <<'PY'
import json
import re
import sys
from datetime import datetime

EXPECTED_SECONDS = 1800


def parse(stamp):
    # chrono writes nanoseconds; Python's parser wants at most six digits.
    stamp = re.sub(r"(\.\d{1,6})\d*", r"\1", stamp).replace("Z", "+00:00")
    return datetime.fromisoformat(stamp)


try:
    lease = json.loads(sys.argv[1])["active_lease"]
    window = int((parse(lease["expires_at"]) - parse(lease["acquired_at"])).total_seconds())
    holder = lease.get("holder")
    fence = lease.get("fence")
except (ValueError, KeyError, TypeError) as err:
    print(f"UNREADABLE the control record carries no readable startup lease: {err!r}")
    sys.exit(2)
if window != EXPECTED_SECONDS:
    print(f"FAIL startup rollout lease window is {window} s, expected {EXPECTED_SECONDS} s (holder {holder}, fence {fence})")
    sys.exit(1)
print(f"PASS startup rollout lease window is {window} s (holder {holder}, fence {fence})")
PY
}

echo "==> [lease-window/self-test] the grader must refuse the pre-fix window and accept the fixed one"
prefix_record='{"active_lease":{"holder":"kin-daemon-startup-bootstrap","fence":1,"acquired_at":"2026-09-02T08:20:00.712345678Z","expires_at":"2026-09-02T08:25:00.712345678Z"}}'
grade_lease_window "${prefix_record}" >/dev/null 2>&1
rc=$?
[ "${rc}" -eq 1 ] || fail "lease-window self-test: the grader answered ${rc} to the pre-fix 300 s window instead of failing it, so it grades nothing"
fixed_record='{"active_lease":{"holder":"kin-daemon-startup-bootstrap","fence":1,"acquired_at":"2026-09-02T08:20:00.712345678Z","expires_at":"2026-09-02T08:50:00.712345678Z"}}'
grade_lease_window "${fixed_record}" >/dev/null 2>&1
rc=$?
[ "${rc}" -eq 0 ] || fail "lease-window self-test: the grader refused an 1800 s window (rc ${rc})"
grade_lease_window '{"active_lease":null}' >/dev/null 2>&1
rc=$?
[ "${rc}" -eq 2 ] || fail "lease-window self-test: a record with no lease must be unreadable, not a pass or a fail (rc ${rc})"
echo "==> [lease-window/self-test] OK"

echo "==> [lease-window] read the publication-control record the daemon bootstrapped"
# No KIN_GCS_PREFIX is passed above, so the record sits at the bucket root
# under the name ObjectStorePublicationControlStore writes.
record_object=".kin-graph-publication-control.json"
record="$(docker run --rm --network "${NET}" --entrypoint curl "${IMAGE}" -sS -f \
  "http://fake-gcs:4443/storage/v1/b/${BUCKET}/o/${record_object}?alt=media" 2>/dev/null || true)"
[ -n "${record}" ] \
  || { dump_kin; fail "lease-window: the daemon served but no publication-control record exists at ${BUCKET}/${record_object}; the startup bootstrap wrote nothing to grade"; }
verdict="$(grade_lease_window "${record}")"
rc=$?
echo "==> [lease-window] ${verdict}"
[ "${rc}" -eq 0 ] || { dump_kin; fail "lease-window: ${verdict}"; }
docker rm -f "${KIN_CID}" >/dev/null 2>&1; KIN_CID=""

# ---------------------------------------------------------------------------
# 1b. The control for arm 1's image identity. Same emulator, same network, same
#     everything else: the ONE difference is that
#     KIN_RELEASE_DAEMON_DIGEST_INTERNAL is not passed. The daemon must refuse
#     on that requirement by name.
#
#     Without this arm, arm 1 would keep passing if the requirement were ever
#     removed or exempted for CI, which is exactly how this smoke went red in
#     the first place: FIR-2941, where the daemon grew the requirement and the
#     smoke that never set it read as a broken emulator. It runs here rather
#     than after the fails-loud arms because those remove the emulator, and a
#     control whose refusal could be caused by two different things is not a
#     control.
# ---------------------------------------------------------------------------
echo "==> [identity-required] the same daemon without KIN_RELEASE_DAEMON_DIGEST_INTERNAL must refuse"
start_kin "http://fake-gcs:4443" omit-identity
state="$(await_kin)"
logs="$(docker logs "${KIN_CID}" 2>&1 || true)"

[ "${state}" = "exited" ] \
  || { dump_kin; fail "identity-required: daemon did not exit without an image identity (state=${state}); the admission requirement is not live in these bytes"; }
contains "${logs}" "daemon API server listening" \
  && { dump_kin; fail "identity-required: daemon reached serving state with no image identity"; }
identity_exit="$(docker inspect -f '{{.State.ExitCode}}' "${KIN_CID}" 2>/dev/null || echo unknown)"
[ "${identity_exit}" != "0" ] \
  || { dump_kin; fail "identity-required: daemon exited 0; the refusal must be an error"; }

# The refusal string has TWO producers in one container log. `kin init` in the
# entrypoint spawns a daemon of its own before the exec, and it walks the same
# admission path, so it prints the same line. The three assertions above already
# pin the container's MAIN daemon, since only that process can exit the
# container, but a message match against the whole log would not: reorder
# `create_state` so the main daemon refuses on some other lever first, and the
# init step's line would still satisfy it while this arm reported a green
# control over the wrong refusal. So scope the message to the log after the
# entrypoint's own start marker, and refuse loudly when that marker is missing
# rather than matching against an empty string, which would pass nothing and
# look like a failed assertion for the wrong reason.
main_daemon_logs="$(printf '%s\n' "${logs}" | sed -n '/\[entrypoint\] Starting kin-daemon/,$p')"
[ -n "${main_daemon_logs}" ] \
  || { dump_kin; fail "identity-required: the entrypoint's own start marker is absent, so no refusal in this log can be attributed to the container's main daemon"; }
contains "${main_daemon_logs}" "KIN_RELEASE_DAEMON_DIGEST_INTERNAL is required for GCS graph publication admission" \
  || { dump_kin; fail "identity-required: the main daemon did not refuse by naming KIN_RELEASE_DAEMON_DIGEST_INTERNAL, so this arm proves nothing about the identity"; }
echo "==> [identity-required] OK (exit ${identity_exit}, refusal names the variable)"
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
