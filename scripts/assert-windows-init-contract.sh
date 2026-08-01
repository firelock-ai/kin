#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
#
# What `kin init` refuses on Windows and why, stated once.
#
# Both boundaries reach the graph authority store now, one whole transaction
# further than they used to, and stop there. The value of asserting it this
# precisely is that the refusal names WHICH capability is missing, so a change
# that moves the boundary has to come here and say so.
#
# Both CI legs that own a Windows `kin` executable run this script: the
# pull-request authority job and the landing-push installer proof. They cannot
# disagree, because there is only one set of assertions. That matters because
# the installer leg is off the pull-request path, so an admission change that
# moved the outcome used to be unreviewable until it had already failed a
# required check on a release commit.
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

# Publishing repository config is where both admission boundaries stopped until
# Windows gained a capability-owned atomic replacement. Naming it now would
# mean the writer went back to refusing, so it is refuted rather than required.
CONFIG_REFUSAL="cannot publish repository config"
# Naming the mutable-source proof would mean exact-Git admission stopped in
# front of the config writer, which is the behavior platform-resolved
# materialization replaced.
SOURCE_PROOF_STAGE="prove mutable Git workspace"
# Where both boundaries stop today, one transaction further on. The graph store
# flushes a directory the way Unix does, by reopening it and syncing, and
# Windows refuses that open with ERROR_ACCESS_DENIED unless it carries
# FILE_FLAG_BACKUP_SEMANTICS. Admission therefore reaches the authority store
# and fails there, which is a different component and a different cause from
# the config writer, and is required by name so the next change to move this
# boundary has to say so.
DURABLE_FLUSH_GAP="for durable metadata flush"
# The one `kin init` refusal that is not about platform capability at all: Kin
# never derives authority from filesystem contents it was not given exactly.
NON_EMPTY_REFUSAL="requires an empty directory"
# User-facing support wording lives beside the executable refusal contract so
# docs and installers cannot describe a larger product than this script proves.
# scripts/test-release-workflow-authority.py requires every public copy to stay
# byte-for-byte equal to this binding.
PUBLIC_SUPPORT_NOTICE="Native Windows x86_64 can install and run repository-free CLI diagnostics, but repository admission is currently unavailable: kin init fails closed, so graph, lexical, daemon, repository setup, MCP, and review workflows are unsupported. Use WSL2 for usable Kin repositories."

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
    fail "$label did not report: $needle" "$log"
  fi
}

refute_text() {
  local label="$1"
  local needle="$2"
  local log="$3"
  if [ "$(occurrences "$needle" "$log")" -ne 0 ]; then
    fail "$label stopped at a gate this platform no longer has: $needle" "$log"
  fi
}

# Count the direct children of a directory matching one glob.
#
# Deliberately not `find`: on a Windows runner that name also belongs to
# `System32\find.exe`, whose arguments mean something else entirely, and a
# PATH order that resolved to it would make this report zero for every input
# rather than fail. A shell glob has no such twin. An unmatched glob stays
# literal here because `nullglob` is off, and the `-e` test rejects it.
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

require_refused() {
  local label="$1"
  local dir="$2"
  local log="$3"
  local expected_residue="$4"
  if (cd "$dir" && "$kin_bin" init) > "$log" 2>&1; then
    fail "$label unexpectedly succeeded" "$log"
  fi
  # A refusal publishes nothing. Both boundaries stage into a
  # `.kin.init-<uuid>` and only move it into place at the end, so a `.kin` of
  # any shape means a refusal published authority anyway, and a surviving stage
  # means it did not clean up after itself.
  if [ -e "$dir/.kin" ]; then
    fail "$label left a half-created repository at $dir/.kin" "$log"
  fi
  # WINDOWS CLEANUP GAP, asserted rather than assumed.
  #
  # The stage is a sibling of the admitted directory, not a child of it:
  # crates/kin-core/src/git_init.rs derives it from the source's parent and
  # crates/kin-core/src/init.rs from the working directory's, so a count taken
  # inside the admitted directory can never see one and would report zero on
  # every input. Each boundary therefore owns a private parent holding nothing
  # but the directory under test, which keeps a survivor attributable to the
  # boundary that left it.
  #
  # Counted where they actually appear, the two boundaries that reach the graph
  # store DO leave their unpublished stage and its `.owner` marker behind,
  # which is two entries each. This is post-refusal residue measured before any
  # reaper could run: each boundary owns a freshly created parent and sees one
  # `kin init`, and recover_orphaned_repository_stages runs against that parent
  # before the stage exists, so it finds nothing to reap on any platform. What
  # moves the count is refusal-time cleanup, or the transaction-layer port
  # fixing cleanup_owned_staging_root on the failing path, where removal is
  # best-effort against the same open handles that refuse the admission.
  # Proving the off-unix reaper arm instead needs a second init against a parent
  # already holding residue, which is a different fixture from this one. That is
  # a real defect and it was invisible for as long as the count looked in the
  # wrong place. It is asserted by exact count in both directions, so whatever
  # finally drives it to zero trips this and has to come here and say so,
  # exactly as a restored admission trips the refusal assertion above.
  local parent
  parent="$(dirname "$dir")"
  local staged
  staged="$(count_matching "$parent" '.kin.init-*')"
  if [ "$staged" != "$expected_residue" ]; then
    fail "$label left $staged stage entries in $parent, expected $expected_residue" "$log"
  fi
}

# What a command admits means nothing until it can start. Windows gives the
# main thread a 1 MiB stack where Unix gives 8 MiB, and this repository already
# records that the CLI's own command tree needs more room than a 2 MiB thread
# gives it, so "the binary died before it reached admission" is a real and
# distinct outcome that must not be read as a missing repository.
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
  # Hooks and signing are neutralized for this one invocation and NOT written
  # into the fixture's config. A recorded `core.hooksPath` is itself a local
  # compatibility blocker that admission refuses on before it ever reaches the
  # config writer, so persisting one would prove a different outcome than the
  # one under test.
  git -c core.hooksPath= -c commit.gpgsign=false commit -qm probe
)
require_refused "Windows exact-Git admission" "$git_boundary" "$git_log" 2
refute_text "Windows exact-Git admission" "$SOURCE_PROOF_STAGE" "$git_log"
refute_text "Windows exact-Git admission" "$CONFIG_REFUSAL" "$git_log"
require_text "Windows exact-Git admission" "$DURABLE_FLUSH_GAP" "$git_log"

native_boundary="$scratch/native-unborn/repo"
native_log="$scratch/kin-init-native-unborn.txt"
mkdir -p "$native_boundary"
require_refused "Windows native-unborn bootstrap" "$native_boundary" "$native_log" 2
refute_text "Windows native-unborn bootstrap" "$CONFIG_REFUSAL" "$native_log"
require_text "Windows native-unborn bootstrap" "$DURABLE_FLUSH_GAP" "$native_log"

# A capability Windows now has must not become permission to derive authority
# from whatever happens to be lying in the directory.
populated_boundary="$scratch/native-populated/repo"
populated_log="$scratch/kin-init-native-populated.txt"
mkdir -p "$populated_boundary"
printf 'untracked\n' > "$populated_boundary/stray.txt"
require_refused "Windows non-empty native boundary" "$populated_boundary" "$populated_log" 0
require_text "Windows non-empty native boundary" "$NON_EMPTY_REFUSAL" "$populated_log"

if [ "$failures" -ne 0 ]; then
  echo "::error::Windows admission did not behave as asserted ($failures check(s) failed)"
  exit 1
fi
echo "Windows admission refused every boundary at the cause it names, published no authority, and left exactly the unreaped stage residue this platform is known to leave."
echo "$PUBLIC_SUPPORT_NOTICE"
