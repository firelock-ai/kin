#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
#
# Entrypoint contract for a workspace that has a volume mounted INSIDE `.kin`.
#
# The kin-registry Deployment mounts its published-crates disk at
# `<repo>/.kin/packages`, so the entrypoint's re-init branch runs `rm -rf` over a
# directory containing a live mount. `rm -rf` unlinks the volume's contents and
# only then fails EBUSY on the mount point itself, which loses data first and
# crashloops second.
#
# The existing entrypoint smoke boots the daemon with nothing mounted under
# `.kin`, so it models the kin-daemon pod and never the registry pod. That gap is
# where a regression that silently emptied the published-crates disk survived: the
# completeness test required `.kin/HEAD`, `.kin/objects` and `.kin/kindb/graph.kndb`,
# which the pre-authority layout created and the current layout does not, so the
# test was unconditionally true and every start took the destructive branch.
#
# Usage: scripts/test-entrypoint-workspace-mount.sh <image-ref>

set -euo pipefail

IMAGE="${1:?usage: test-entrypoint-workspace-mount.sh <image-ref>}"
PAYLOAD="published-crate-payload"
WORKSPACE_VOLUME=""
PACKAGES_VOLUME=""
CID=""

cleanup() {
  [ -n "${CID}" ] && docker rm -f "${CID}" >/dev/null 2>&1 || true
  [ -n "${WORKSPACE_VOLUME}" ] && docker volume rm -f "${WORKSPACE_VOLUME}" >/dev/null 2>&1 || true
  [ -n "${PACKAGES_VOLUME}" ] && docker volume rm -f "${PACKAGES_VOLUME}" >/dev/null 2>&1 || true
  CID=""; WORKSPACE_VOLUME=""; PACKAGES_VOLUME=""
}
trap cleanup EXIT

# Substring test that never routes the decision through a pipeline's exit status.
contains() {
  case "$1" in
    *"$2"*) return 0 ;;
    *) return 1 ;;
  esac
}

# Fresh workspace + packages volumes, with the packages volume seeded so its
# destruction is observable. Returns via the globals above.
new_fixture() {
  WORKSPACE_VOLUME="kin-entrypoint-ws-${RANDOM}-$$"
  PACKAGES_VOLUME="kin-entrypoint-pkgs-${RANDOM}-$$"
  docker volume create "${WORKSPACE_VOLUME}" >/dev/null
  docker volume create "${PACKAGES_VOLUME}" >/dev/null
  # Volumes start root-owned; the image runs as uid 999.
  docker run --rm --user 0:0 \
    -v "${WORKSPACE_VOLUME}:/w" -v "${PACKAGES_VOLUME}:/p" \
    --entrypoint /bin/sh "${IMAGE}" -c \
    "chmod 1777 /w; printf '%s\n' '${PAYLOAD}' > /p/kin-db-0.0.0.crate; chown -R 999:999 /p"
}

# Prepare the repository the way the pod's init container does: workspace volume
# only, no packages volume mounted yet. `break_layout` removes one file that every
# layout version creates, which is what an interrupted init leaves behind.
prepare_repo() {
  local break_layout="${1:-no}"
  local script='set -eu
mkdir -p /w/repo
kin init /w/repo >/dev/null 2>&1'
  if [ "${break_layout}" = "break" ]; then
    script="${script}
rm -f /w/repo/.kin/manifest.json"
  fi
  docker run --rm --user 999:999 -v "${WORKSPACE_VOLUME}:/w" \
    --entrypoint /bin/sh "${IMAGE}" -c "${script}"
}

payload_survived() {
  local seen
  seen="$(docker run --rm -v "${PACKAGES_VOLUME}:/p" --entrypoint /bin/sh "${IMAGE}" \
    -c 'cat /p/kin-db-0.0.0.crate 2>/dev/null || true')"
  contains "${seen}" "${PAYLOAD}"
}

fail() { echo "::error::$1" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 1. A materialized repository with the packages volume mounted inside `.kin`
#    must boot untouched. This is the running registry pod.
# ---------------------------------------------------------------------------
echo "==> [mounted-intact] boot a prepared repo with a volume mounted inside .kin"
new_fixture
prepare_repo
CID="$(docker run -d --user 999:999 \
  -v "${WORKSPACE_VOLUME}:/w" -v "${PACKAGES_VOLUME}:/w/repo/.kin/packages" \
  -e KIN_WORKSPACE_DIR=/w/repo -e KIN_STORAGE=local -e KIN_DISABLE_SPINE=1 \
  "${IMAGE}" --port 4219)"
started=""
for _ in $(seq 1 30); do
  logs="$(docker logs "${CID}" 2>&1 || true)"
  if contains "${logs}" "Starting kin-daemon"; then started=1; break; fi
  if [ "$(docker inspect -f '{{.State.Running}}' "${CID}" 2>/dev/null || echo false)" != "true" ]; then break; fi
  sleep 1
done
logs="$(docker logs "${CID}" 2>&1 || true)"
docker rm -f "${CID}" >/dev/null 2>&1 || true; CID=""
[ -n "${started}" ] || { echo "${logs}"; fail "prepared repo did not reach daemon start with a volume mounted inside .kin"; }
payload_survived || fail "entrypoint DESTROYED the mounted volume's contents on a prepared repository"
echo "==> [mounted-intact] OK"
cleanup

# ---------------------------------------------------------------------------
# 2. An INCOMPLETE repository with a volume mounted inside `.kin` must refuse
#    loudly and leave the volume alone, never `rm -rf` through the mount.
# ---------------------------------------------------------------------------
echo "==> [mounted-incomplete] refuse to re-initialize over a mounted volume"
new_fixture
prepare_repo break
set +e
out="$(docker run --rm --user 999:999 \
  -v "${WORKSPACE_VOLUME}:/w" -v "${PACKAGES_VOLUME}:/w/repo/.kin/packages" \
  -e KIN_WORKSPACE_DIR=/w/repo -e KIN_STORAGE=local -e KIN_DISABLE_SPINE=1 \
  "${IMAGE}" --port 4219 2>&1)"
rc=$?
set -e
echo "${out}"
[ "${rc}" -ne 0 ] || fail "entrypoint exited 0 on an incomplete layout wrapping a mounted volume"
contains "${out}" "mounted inside it" || fail "refusal did not name the mount as the reason"
contains "${out}" "Refusing to re-initialize" || fail "refusal did not state what it declined to do"
payload_survived || fail "entrypoint DESTROYED the mounted volume's contents before refusing"
echo "==> [mounted-incomplete] OK"
cleanup

# ---------------------------------------------------------------------------
# 3. An incomplete repository with NOTHING mounted inside `.kin` must still
#    re-initialize, so the refusal above cannot be implemented by never
#    re-initializing at all.
# ---------------------------------------------------------------------------
echo "==> [unmounted-incomplete] still re-initializes when no volume is at risk"
new_fixture
prepare_repo break
CID="$(docker run -d --user 999:999 -v "${WORKSPACE_VOLUME}:/w" \
  -e KIN_WORKSPACE_DIR=/w/repo -e KIN_STORAGE=local -e KIN_DISABLE_SPINE=1 \
  "${IMAGE}" --port 4219)"
started=""
for _ in $(seq 1 30); do
  logs="$(docker logs "${CID}" 2>&1 || true)"
  if contains "${logs}" "Starting kin-daemon"; then started=1; break; fi
  if [ "$(docker inspect -f '{{.State.Running}}' "${CID}" 2>/dev/null || echo false)" != "true" ]; then break; fi
  sleep 1
done
logs="$(docker logs "${CID}" 2>&1 || true)"
restored=""
docker exec "${CID}" sh -c 'test -f /w/repo/.kin/manifest.json' >/dev/null 2>&1 && restored=1
docker rm -f "${CID}" >/dev/null 2>&1 || true; CID=""
[ -n "${started}" ] || { echo "${logs}"; fail "incomplete unmounted layout did not reach daemon start"; }
[ -n "${restored}" ] || fail "incomplete unmounted layout was not re-initialized"
echo "==> [unmounted-incomplete] OK"

echo "==> entrypoint workspace-mount contract passed for ${IMAGE}"
