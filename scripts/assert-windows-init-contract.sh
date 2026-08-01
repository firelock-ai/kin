#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
#
# The native Windows `kin init` admission contract.
#
# Exact Git import and an empty native repository must both publish complete
# graph authority. A populated non-Git directory must still fail closed: Kin
# never derives authority from filesystem bytes it was not given exactly.
#
# Both CI jobs that own a native Windows executable run this same script. The
# pull-request job makes the behavior reviewable; the landing installer job
# proves the release-profile binary from the exact commit used by release.
#
# Usage: assert-windows-init-contract.sh <kin executable> <scratch directory>

set -euo pipefail

usage() {
  echo "usage: assert-windows-init-contract.sh <kin executable> <scratch directory>" >&2
  exit 2
}

kin_bin="${1-}"
scratch="${2-}"
if [ -z "$kin_bin" ] || [ -z "$scratch" ]; then
  usage
fi
if [ ! -x "$kin_bin" ]; then
  echo "::error::not an executable kin binary: $kin_bin"
  exit 1
fi

# Every assertion runs from inside a fixture directory, so both arguments have
# to survive the `cd`.
kin_bin="$(cd "$(dirname "$kin_bin")" && pwd)/$(basename "$kin_bin")"
mkdir -p "$scratch"
scratch="$(cd "$scratch" && pwd)"

# Admission opens no daemon of its own, but reap one rather than leaving a
# runner process behind if that ever changes.
trap 'taskkill.exe /F /IM kin-daemon.exe >/dev/null 2>&1 || true' EXIT

NON_EMPTY_REFUSAL="requires an empty directory"
failures=0

fail() {
  local message="$1"
  local log="$2"
  failures=$((failures + 1))
  echo "::error::$message"
  echo "--- captured kin init output: $log ---"
  cat "$log" || true
  echo "--- end $log ---"
}

occurrences() {
  grep -Fc -- "$1" "$2" || true
}

require_text() {
  local label="$1"
  local needle="$2"
  local log="$3"
  if [ "$(occurrences "$needle" "$log")" -eq 0 ]; then
    fail "$label did not report: $needle" "$log"
  fi
}

# Deliberately not `find`: on a Windows runner that name also belongs to
# `System32\\find.exe`, whose arguments mean something else. An unmatched glob
# stays literal because `nullglob` is off, and the `-e` test rejects it.
count_matching() {
  local directory="$1"
  local pattern="$2"
  local matches=0
  local entry
  for entry in "$directory"/$pattern; do
    if [ -e "$entry" ]; then
      matches=$((matches + 1))
    fi
  done
  echo "$matches"
}

require_no_stage_residue() {
  local label="$1"
  local dir="$2"
  local log="$3"
  local parent
  parent="$(dirname "$dir")"
  local staged
  staged="$(count_matching "$parent" '.kin.init-*')"
  if [ "$staged" != "0" ]; then
    fail "$label left $staged unpublished stage entries in $parent" "$log"
  fi
}

require_admitted() {
  local label="$1"
  local dir="$2"
  local log="$3"
  if ! (cd "$dir" && "$kin_bin" init) > "$log" 2>&1; then
    fail "$label failed" "$log"
  fi
  if [ ! -d "$dir/.kin" ]; then
    fail "$label returned success without publishing $dir/.kin" "$log"
  fi
  require_no_stage_residue "$label" "$dir" "$log"
}

require_non_empty_refused() {
  local label="$1"
  local dir="$2"
  local log="$3"
  if (cd "$dir" && "$kin_bin" init) > "$log" 2>&1; then
    fail "$label unexpectedly succeeded" "$log"
  fi
  if [ -e "$dir/.kin" ]; then
    fail "$label published authority at $dir/.kin" "$log"
  fi
  require_no_stage_residue "$label" "$dir" "$log"
  require_text "$label" "$NON_EMPTY_REFUSAL" "$log"
}

# Distinguish an admission result from a binary that never started. Windows
# gives the main thread a smaller default stack than Unix, which has regressed
# this command tree before.
startup_log="$scratch/kin-version.txt"
if ! "$kin_bin" --version > "$startup_log" 2>&1; then
  fail "kin --version did not run, so nothing below reports on admission" "$startup_log"
fi

git_boundary="$scratch/exact-git/repo"
git_log="$scratch/kin-init-exact-git.txt"
mkdir -p "$git_boundary"
(
  cd "$git_boundary"
  git init -q
  git config user.email ci@firelock.ai
  git config user.name ci
  printf 'fn probe() {}\n' > probe.rs
  git add probe.rs
  # Hooks and signing are neutralized for this invocation without persisting a
  # local compatibility blocker in the fixture.
  git -c core.hooksPath= -c commit.gpgsign=false commit -qm probe
)
require_admitted "Windows exact-Git admission" "$git_boundary" "$git_log"

native_boundary="$scratch/native-unborn/repo"
native_log="$scratch/kin-init-native-unborn.txt"
mkdir -p "$native_boundary"
require_admitted "Windows native-unborn bootstrap" "$native_boundary" "$native_log"

populated_boundary="$scratch/native-populated/repo"
populated_log="$scratch/kin-init-native-populated.txt"
mkdir -p "$populated_boundary"
printf 'untracked\n' > "$populated_boundary/stray.txt"
require_non_empty_refused \
  "Windows non-empty native boundary" \
  "$populated_boundary" \
  "$populated_log"

if [ "$failures" -ne 0 ]; then
  echo "::error::Windows admission violated its shipped contract ($failures check(s) failed)"
  exit 1
fi
echo "Windows admitted exact Git and native-empty repositories, published complete authority without stage residue, and refused the non-empty native boundary."
