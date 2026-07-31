#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
#
# What `kin init` refuses on Windows, stated once.
#
# Both CI legs that own a Windows `kin` executable run this script: the
# pull-request authority job and the landing-push installer proof. They cannot
# disagree, because there is only one set of assertions. That matters because
# the installer leg is off the pull-request path, so an admission change that
# moved the refusal used to be unreviewable until it had already failed a
# required check on a release commit.
#
# Usage: assert-windows-init-refusals.sh <kin executable> <scratch directory>

set -euo pipefail

usage() {
  echo "usage: assert-windows-init-refusals.sh <kin executable> <scratch directory>" >&2
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

# Admission refuses before it publishes anything, so no daemon should start.
# Reap one anyway rather than leaving a runner process behind if that changes.
trap 'taskkill.exe /F /IM kin-daemon.exe >/dev/null 2>&1 || true' EXIT

# Publishing repository config is where both admission boundaries stop today.
# Exact-Git admission proves executable modes from the Git index and link
# targets from what `core.symlinks` says the worktree holds, so it runs past
# the mutable-source proof and reaches this writer; native-unborn admission
# reaches the same writer with no Git work in front of it.
CONFIG_REFUSAL="cannot publish repository config"
CONFIG_CAUSE="an atomic exchanging or no-replace directory rename"
# Naming the mutable-source proof would mean exact-Git admission stopped in
# front of the config writer, which is the behavior platform-resolved
# materialization replaced.
SOURCE_PROOF_STAGE="prove mutable Git workspace"

# Every assertion reports and the script exits once at the end. One CI round on
# a Windows runner is expensive, so a run that stops at the first failure buys a
# second round to learn what the second boundary did.
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

# `grep -c` exits 1 on zero matches, which `set -e` would otherwise treat as a
# fatal error rather than the answer.
occurrences() {
  grep -Fc -- "$1" "$2" || true
}

require_text() {
  local label="$1"
  local needle="$2"
  local log="$3"
  if [ "$(occurrences "$needle" "$log")" -eq 0 ]; then
    fail "$label did not report its refusal: $needle" "$log"
  fi
}

refute_text() {
  local label="$1"
  local needle="$2"
  local log="$3"
  if [ "$(occurrences "$needle" "$log")" -ne 0 ]; then
    fail "$label stopped at an earlier gate: $needle" "$log"
  fi
}

require_refused() {
  local label="$1"
  local dir="$2"
  local log="$3"
  if (cd "$dir" && "$kin_bin" init) > "$log" 2>&1; then
    fail "$label unexpectedly succeeded" "$log"
  fi
  # Both boundaries stage into a sibling `.kin.init-<uuid>` and publish only
  # at the end, so a `.kin` of any shape means a refusal published authority
  # anyway. This subsumes probing the authority store inside it.
  if [ -e "$dir/.kin" ]; then
    fail "$label left a half-created repository at $dir/.kin" "$log"
  fi
}

# What a command refuses means nothing until it can start. Windows gives the
# main thread a 1 MiB stack where Unix gives 8 MiB, and this repository already
# records that the CLI's own command tree needs more room than a 2 MiB thread
# gives it, so "the binary died before it reached admission" is a real and
# distinct outcome that must not be read as a missing refusal.
startup_log="$scratch/kin-version.txt"
if ! "$kin_bin" --version > "$startup_log" 2>&1; then
  fail "kin --version did not run, so nothing below reports on admission" "$startup_log"
fi

git_boundary="$scratch/exact-git"
git_log="$scratch/kin-init-exact-git.txt"
mkdir -p "$git_boundary"
(
  cd "$git_boundary"
  git init -q
  git config user.email ci@firelock.ai
  git config user.name ci
  printf 'fn probe() {}\n' > probe.rs
  git add probe.rs
  # Hooks and signing are neutralized for this one invocation and NOT written
  # into the fixture's config. A recorded `core.hooksPath` is itself a local
  # compatibility blocker that admission refuses on before it ever reaches the
  # config writer, so persisting one would prove a different refusal than the
  # one under test.
  git -c core.hooksPath= -c commit.gpgsign=false commit -qm probe
)
require_refused "Windows exact-Git admission" "$git_boundary" "$git_log"
refute_text "Windows exact-Git admission" "$SOURCE_PROOF_STAGE" "$git_log"
require_text "Windows exact-Git admission" "$CONFIG_REFUSAL" "$git_log"
require_text "Windows exact-Git admission" "$CONFIG_CAUSE" "$git_log"

native_boundary="$scratch/native-unborn"
native_log="$scratch/kin-init-native-unborn.txt"
mkdir -p "$native_boundary"
require_refused "Windows native-unborn bootstrap" "$native_boundary" "$native_log"
require_text "Windows native-unborn bootstrap" "$CONFIG_REFUSAL" "$native_log"
require_text "Windows native-unborn bootstrap" "$CONFIG_CAUSE" "$native_log"

if [ "$failures" -ne 0 ]; then
  echo "::error::Windows admission did not behave as asserted ($failures check(s) failed)"
  exit 1
fi
echo "Windows admission refused on both boundaries and published no repository."
