#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
#
# The published daemon port must answer from OUTSIDE the container's network
# namespace.
#
# `docker-compose.yml` maps 4219:4219, and Docker publishes a port by forwarding
# to the container's EXTERNAL address. The daemon defaults to 127.0.0.1
# (kin-daemon/src/api.rs::resolve_bind_host), so without KIN_DAEMON_BIND_HOST it
# listens only on the container's loopback and the published mapping reaches
# nothing. Nobody noticed because the compose healthcheck curls localhost from
# INSIDE that same namespace, where a loopback-bound daemon answers perfectly:
# a check that cannot fail for the one bug class it looks like it covers.
#
# So this script probes from the host, and runs the broken arm first. Arm 1 is
# the negative control: unset the variable and the published port must NOT
# answer, while the in-namespace probe must still succeed. Without that second
# half arm 1 would pass for the wrong reason every time the daemon failed to
# start at all, which is precisely how the original bug stayed invisible.
#
# Reachability, not readiness, is what is under test. An empty repo can still be
# warming, and /readiness answers 503 until it is open; 503 is a REACHED daemon.
# The arms therefore assert on whether an HTTP response came back at all, never
# on its status code, so a slow open cannot read as a bind regression.
#
# Usage: scripts/test-compose-published-port.sh <image-ref> [host-port]

set -euo pipefail

IMAGE="${1:?usage: test-compose-published-port.sh <image-ref> [host-port]}"
HOST_PORT="${2:-14219}"
COMPOSE_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/docker-compose.yml"
CID=""

cleanup() {
  [ -n "${CID}" ] && docker rm -f "${CID}" >/dev/null 2>&1 || true
  CID=""
}
trap cleanup EXIT

fail() { echo "::error::$1" >&2; exit 1; }

contains() {
  case "$1" in
    *"$2"*) return 0 ;;
    *) return 1 ;;
  esac
}

# Start the image with 4219 published to HOST_PORT, optionally setting the bind
# host, and wait for the daemon to report that it is listening. The listening
# line is the same deterministic, offline signal docker.yml's entrypoint smoke
# already gates on, and it is emitted after the bind, so reaching it means the
# socket exists whatever address it ended up on.
#
# The argv is branched rather than assembled in an array. bash 3.2, which is
# /bin/bash on macOS, aborts on "${arr[@]}" for an EMPTY array under `set -u`,
# and arm 1 passes no bind host, so the empty case is the first thing this
# script does. CI runs bash 5 and would never have shown it.
start_daemon() {
  local bind_host="$1"
  if [ -n "${bind_host}" ]; then
    CID="$(docker run -d -p "127.0.0.1:${HOST_PORT}:4219" \
      -e KIN_STORAGE=local -e KIN_DISABLE_SPINE=1 \
      -e "KIN_DAEMON_BIND_HOST=${bind_host}" "${IMAGE}" --port 4219)"
  else
    CID="$(docker run -d -p "127.0.0.1:${HOST_PORT}:4219" \
      -e KIN_STORAGE=local -e KIN_DISABLE_SPINE=1 "${IMAGE}" --port 4219)"
  fi
  local logs=""
  for _ in $(seq 1 60); do
    logs="$(docker logs "${CID}" 2>&1 || true)"
    if contains "${logs}" "daemon API server listening"; then return 0; fi
    if [ "$(docker inspect -f '{{.State.Running}}' "${CID}" 2>/dev/null || echo false)" != "true" ]; then break; fi
    sleep 1
  done
  echo "${logs}"
  fail "kin-daemon never reached its listening line (bind_host='${bind_host:-unset}')"
}

# Did an HTTP response come back from the published port, on the HOST, outside
# the container's namespace? Any status counts; a refused connection does not.
# `curl -f` is deliberately NOT used: it turns a reachable-but-warming 503 into
# the same failure as a dead port, which is the distinction under test.
published_port_answers() {
  local code
  code="$(curl -o /dev/null -sS --max-time 5 -w '%{http_code}' \
    "http://127.0.0.1:${HOST_PORT}/readiness" 2>/dev/null || true)"
  [ -n "${code}" ] && [ "${code}" != "000" ]
}

# The same question asked from INSIDE the namespace, where a loopback-bound
# daemon is perfectly reachable. This is the control that proves a failure of
# `published_port_answers` means "not published", not "not running".
in_namespace_answers() {
  local code
  code="$(docker exec "${CID}" sh -c \
    "curl -o /dev/null -sS --max-time 5 -w '%{http_code}' http://127.0.0.1:4219/readiness" 2>/dev/null || true)"
  [ -n "${code}" ] && [ "${code}" != "000" ]
}

# ---------------------------------------------------------------------------
# 1. Negative control. With no KIN_DAEMON_BIND_HOST the daemon binds loopback,
#    so the published port must NOT answer while the in-namespace probe still
#    does. If this arm ever goes quiet in both halves, the arm is broken, not
#    the product.
# ---------------------------------------------------------------------------
echo "==> [unset-bind-host] published port must be unreachable, daemon still alive"
start_daemon ""
in_namespace_answers || fail "control failed: daemon did not answer INSIDE its own namespace, so arm 1 proves nothing"
if published_port_answers; then
  fail "published port answered with KIN_DAEMON_BIND_HOST unset; this check can no longer detect a loopback bind"
fi
echo "==> [unset-bind-host] OK (in-namespace: reachable, published: refused)"
cleanup

# ---------------------------------------------------------------------------
# 2. The fix. Binding 0.0.0.0 must make the published mapping answer from the
#    host. The daemon requires an auth token to bind non-loopback and
#    auto-provisions one at .kin/daemon.token, so no credential is configured
#    here; a regression in that provisioning shows up as a daemon that never
#    reaches its listening line.
# ---------------------------------------------------------------------------
echo "==> [bind-0.0.0.0] published port must answer from the host"
start_daemon "0.0.0.0"
published_port_answers || fail "published port did not answer with KIN_DAEMON_BIND_HOST=0.0.0.0"
echo "==> [bind-0.0.0.0] OK (published: reachable)"
cleanup

# ---------------------------------------------------------------------------
# 3. Tie the runtime proof to the shipped artifact. Arms 1 and 2 prove what the
#    variable does; only this proves docker-compose.yml actually ships it, so a
#    regression here turns the check red instead of leaving two green arms
#    describing a fix nobody ships.
#
#    It reads the RESOLVED config, not the raw file. A substring search over the
#    file text also matches inside a `#` comment, so commenting the line out
#    (the likeliest regression, and likelier than deletion since it is what
#    someone does to reproduce the old bug) left all three arms green: arms 1
#    and 2 build their own containers and never read this file at all.
#    `docker compose config` renders the merged services with comments already
#    gone; the fallback strips comment text before matching so the guard still
#    cannot be satisfied by a commented-out line.
# ---------------------------------------------------------------------------
echo "==> [compose-carries-it] docker-compose.yml must ship the bind host and a loopback mapping"
[ -f "${COMPOSE_FILE}" ] || fail "docker-compose.yml not found at ${COMPOSE_FILE}"

resolved=""
if docker compose -f "${COMPOSE_FILE}" config >/dev/null 2>&1; then
  resolved="$(docker compose -f "${COMPOSE_FILE}" config 2>/dev/null)"
  source_desc="docker compose config"
else
  # No compose plugin, or a build context this checkout cannot resolve. Strip
  # comment text so a commented-out setting cannot satisfy the match.
  resolved="$(sed -e 's/[[:space:]]*#.*$//' "${COMPOSE_FILE}")"
  source_desc="comment-stripped docker-compose.yml"
fi
echo "    (read from ${source_desc})"

contains "${resolved}" "KIN_DAEMON_BIND_HOST" && contains "${resolved}" "0.0.0.0" \
  || fail "docker-compose.yml does not effectively set KIN_DAEMON_BIND_HOST=0.0.0.0; its published 4219 mapping is dead"

# The shipped mapping must be the one arms 1 and 2 exercised. A bare 4219:4219
# publishes on every interface, and the 0.0.0.0 bind above turns the daemon's
# Host allowlist off rather than widening it, so the unauthenticated /health
# surface would answer any peer on the network.
contains "${resolved}" "127.0.0.1" \
  || fail "docker-compose.yml publishes 4219 on every interface; scope it to 127.0.0.1 so /health is not exposed to the LAN"
echo "==> [compose-carries-it] OK"

echo "==> compose published-port contract passed for ${IMAGE}"
