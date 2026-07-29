#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: $0 <current-kin> <current-daemon> <base-kin> <base-daemon>" >&2
  exit 64
fi

absolute_executable() {
  local candidate=$1
  if [[ ! -x "$candidate" ]]; then
    echo "not executable: $candidate" >&2
    exit 66
  fi
  local directory
  directory=$(cd "$(dirname "$candidate")" && pwd -P)
  printf '%s/%s\n' "$directory" "$(basename "$candidate")"
}

CURRENT_KIN=$(absolute_executable "$1")
CURRENT_DAEMON=$(absolute_executable "$2")
BASE_KIN=$(absolute_executable "$3")
BASE_DAEMON=$(absolute_executable "$4")
MATRIX_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/kin-supervisor-compat.XXXXXX")

stop_recorded_supervisor() {
  local state=$1
  local pid_file="$state/supervisor.pid"
  if [[ -f "$pid_file" ]]; then
    local pid
    pid=$(tr -dc '0-9' <"$pid_file")
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      kill -TERM "$pid" 2>/dev/null || true
      for _ in $(seq 1 50); do
        kill -0 "$pid" 2>/dev/null || return 0
        sleep 0.1
      done
      echo "supervisor $pid did not terminate" >&2
      return 1
    fi
  fi
}

cleanup() {
  local state
  for state in "$MATRIX_ROOT"/*; do
    [[ -d "$state" ]] && stop_recorded_supervisor "$state" || true
  done
  if [[ "${KIN_KEEP_COMPAT_MATRIX:-0}" == "1" ]]; then
    echo "matrix artifacts retained at $MATRIX_ROOT" >&2
  else
    rm -rf -- "$MATRIX_ROOT"
  fi
}
trap cleanup EXIT

run_registry_probe() {
  local kin_bin=$1
  local daemon_bin=$2
  local state=$3
  local idle_timeout=${4:-1}
  local startup_timeout=${5:-5}
  mkdir -p "$state"
  (
    cd "$state"
    env \
      -u KIN_SUPERVISOR_URL \
      -u KIN_SUPERVISOR_STARTUP_GENERATION \
      -u KIN_KEEP_COMPAT_MATRIX \
      -u KIN_VFS_WORKSPACE \
      -u DYLD_INSERT_LIBRARIES \
      -u LD_PRELOAD \
      KIN_REGISTRY_PATH="$state/registry.toml" \
      KIN_DAEMON_BIN="$daemon_bin" \
      KIN_DAEMON_READY_TIMEOUT_SECS=5 \
      KIN_DAEMON_STARTUP_LOCK_TIMEOUT_SECS="$startup_timeout" \
      KIN_SUPERVISOR_IDLE_TIMEOUT_SECS="$idle_timeout" \
      "$kin_bin" registry daemons --json
  )
}

run_registry_probe_bounded() {
  local wall_timeout=$1
  shift
  run_registry_probe "$@" &
  local probe_pid=$!
  local deadline=$((SECONDS + wall_timeout))
  while kill -0 "$probe_pid" 2>/dev/null; do
    if ((SECONDS >= deadline)); then
      kill -TERM "$probe_pid" 2>/dev/null || true
      sleep 0.2
      kill -KILL "$probe_pid" 2>/dev/null || true
      wait "$probe_pid" 2>/dev/null || true
      return 124
    fi
    sleep 0.1
  done
  local probe_status=0
  wait "$probe_pid" || probe_status=$?
  return "$probe_status"
}

current_current="$MATRIX_ROOT/current-cli-current-daemon"
run_registry_probe "$CURRENT_KIN" "$CURRENT_DAEMON" "$current_current" 10 \
  >"$current_current.stdout" 2>"$current_current.stderr"
[[ -d "$current_current/supervisor.start.lock" ]]
compgen -G "$current_current/supervisor.start.lock/records-v2/adopt-*.json" >/dev/null

run_registry_probe "$BASE_KIN" "$CURRENT_DAEMON" "$current_current" 10 \
  >"$current_current.base-live.stdout" 2>"$current_current.base-live.stderr"
grep -F '"supervisor_url"' "$current_current.base-live.stdout" >/dev/null
[[ -f "$current_current/supervisor.pid" ]]
[[ -f "$current_current/supervisor.port" ]]
[[ -d "$current_current/supervisor.start.lock" ]]
stop_recorded_supervisor "$current_current"

# The immutable base stale threshold has a hard 10-second floor. Let the
# current-state residue age past that floor before invoking exact-base
# CLI+daemon. The outer sentinel's verified future mtime must keep the old
# client's failed remove_file(directory) branch unreachable, so its own
# configured one-second startup deadline rejects boundedly. The independent
# watchdog turns the historical busy loop into a deterministic matrix failure.
sleep 11
rollback_started=$SECONDS
if run_registry_probe_bounded 5 \
  "$BASE_KIN" "$BASE_DAEMON" "$current_current" 1 1 \
  >"$current_current.base-rollback.stdout" \
  2>"$current_current.base-rollback.stderr"; then
  echo "immutable base CLI unexpectedly crossed the permanent current authority" >&2
  exit 1
else
  rollback_status=$?
fi
if [[ "$rollback_status" -eq 124 ]]; then
  echo "immutable base CLI exceeded the rollback wall-clock bound" >&2
  exit 1
fi
rollback_elapsed=$((SECONDS - rollback_started))
if ((rollback_elapsed > 4)); then
  echo "immutable base CLI rejected too slowly after current-state residue" >&2
  exit 1
fi
grep -F "timed out waiting for supervisor startup lock" \
  "$current_current.base-rollback.stderr" >/dev/null
[[ -d "$current_current/supervisor.start.lock" ]]
[[ -f "$current_current/supervisor.start.lock/authority.lock" ]]
[[ -d "$current_current/supervisor.start.lock/records-v2" ]]

base_current="$MATRIX_ROOT/base-cli-current-daemon"
if run_registry_probe "$BASE_KIN" "$CURRENT_DAEMON" "$base_current" \
  >"$base_current.stdout" 2>"$base_current.stderr"; then
  echo "immutable base CLI unexpectedly launched the current daemon" >&2
  exit 1
fi
grep -F "legacy launcher marker detected" "$base_current/supervisor.log" >/dev/null
[[ ! -e "$base_current/supervisor.pid" ]]
[[ ! -e "$base_current/supervisor.port" ]]
[[ ! -e "$base_current/supervisor.lock" ]]
[[ ! -e "$base_current/supervisor.start.lock" ]]

current_base="$MATRIX_ROOT/current-cli-base-daemon"
if run_registry_probe "$CURRENT_KIN" "$BASE_DAEMON" "$current_base" \
  >"$current_base.stdout" 2>"$current_base.stderr"; then
  echo "current CLI unexpectedly launched a daemon without adoption acknowledgement" >&2
  exit 1
fi
grep -F "does not acknowledge supervisor startup protocol" \
  "$current_base.stderr" >/dev/null
[[ ! -e "$current_base/supervisor.pid" ]]
[[ ! -e "$current_base/supervisor.port" ]]
[[ ! -e "$current_base/supervisor.start.lock" ]]

echo "supervisor startup compatibility matrix: PASS"
echo "  current CLI -> current daemon: adopted generation and served"
echo "  immutable base CLI -> live current daemon: connected through published endpoint"
echo "  immutable base CLI + daemon after aged current residue: rejected in ${rollback_elapsed}s"
echo "  immutable base CLI -> current daemon: rejected before singleton/publication"
echo "  current CLI -> immutable base daemon: rejected by compat handshake before startup"
