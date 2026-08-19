#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
#
# Shared invocation helpers for the native Windows authority CI legs.
#
# Every helper below fails closed on an EMPTY test selection. A `cargo test`
# whose filter matches nothing exits 0 and prints a passing summary, so a leg
# that only ran `cargo test <filter>` would report success for a test that had
# been renamed away, moved behind a cfg, or deleted. Each helper therefore
# lists the target's tests first and asserts the selection is non-empty, or
# exactly one, before running anything.
#
# The helpers live here rather than inline in ci.yml because three jobs now run
# these legs. Duplicating them per job is how the three copies would drift, and
# a drifted copy of an emptiness guard is a guard that stops guarding one leg
# while still reading as present in the other two. The invocations themselves
# stay in ci.yml on purpose: which tests a Windows leg is required to run is
# reviewable workflow policy, and the release authority test asserts against it
# there.
#
# BUILD ONCE, DRIVE THE BINARY. Every helper used to enter cargo twice, once for
# `cargo test -- --list` and again for the filtered run, and the three jobs
# between them made 51 cargo entries to execute 39 seconds of tests. On
# windows-latest each entry costs roughly a minute of freshness and link
# accounting even when nothing recompiles: one sampled CLI job spent 23.5 min in
# 16 entries whose test binary hash was identical every time, against a
# rust-cache reporting a full hit. So the compilation unit is resolved once per
# distinct argument vector through `cargo test --no-run`, memoised, and both the
# listing and the run are then driven from the compiled test binary. Repeating a
# leg against a unit already built costs a process, not a cargo entry.
#
# What that preserves, deliberately:
#
#   - The cargo invocation shape is unchanged. `--no-run` takes the same
#     arguments the run used to take, so feature resolution, target selection,
#     and the built binary are the same ones the old form produced. Grouping
#     several packages into one cargo entry would be faster still and is NOT
#     done here, because a wider `-p` selection unifies features across the
#     selected packages and would change what each leg proves.
#   - The listing is the same listing. `<binary> --list` is what
#     `cargo test -- --list` shells out to, so the emptiness and exactness
#     guards read identical text.
#   - The binary runs the way cargo runs it: working directory at the package
#     root, `CARGO_MANIFEST_DIR` exported, and the artifact directory ahead of
#     PATH so a colocated dependency resolves. Cargo sets those, a bare
#     execution does not, and a test that reads any of them would otherwise
#     change behaviour for a reason having nothing to do with the test.
#
# Source this file from a `bash` step that has already set `-euo pipefail`.

# `cargo test --no-run` reports every artifact it built, including the package
# binaries an integration test links against through CARGO_BIN_EXE_*. Those
# carry an `executable` too, so selecting on `executable` alone picks up a
# `kin.exe` beside the test harness. Only a test-harness artifact carries
# `"test":true` INSIDE its profile object, which is what this selects on: the
# profile object holds scalars only, so `[^}]*` cannot run past its closing
# brace into the rest of the record. Verified against real cargo output for a
# package with a lib, a bin and an integration test: three artifact records, one
# match.
_leg_test_executables() {
  sed -n 's/.*"profile":{[^}]*"test":true}.*"executable":"\([^"]*\)".*/\1/p' \
    | sed 's|\\\\|/|g'
}

_leg_test_manifests() {
  sed -n 's/.*"manifest_path":"\([^"]*\)".*"profile":{[^}]*"test":true}.*"executable":"[^"]*".*/\1/p' \
    | sed 's|\\\\|/|g'
}

_leg_count_lines() {
  awk 'NF { count += 1 } END { print count + 0 }'
}

# A memo keyed on the argument vector, held in files rather than an associative
# array so the script still parses and runs under the bash 3.2 a developer may
# have locally. Non-alphanumeric bytes collapse to underscores, which is
# injective enough here: two legs collide only if their arguments differ solely
# in punctuation, and such a pair would name the same compilation unit anyway.
#
# The working directory is part of the key and the key carries a fixed prefix.
# Cargo resolves a package selection against the manifest it finds from the
# current directory, so the same arguments in two directories are two units; and
# without the prefix an empty argument vector keys the cache DIRECTORY itself,
# which `-s` reports as non-empty and `cat` then reads as a resolved unit.
#
# Where the directory is created is what decides whether the memo works at all.
# A command substitution runs in a subshell, so an export made inside one is
# discarded the moment it returns. The first version of this returned the
# directory on stdout and every caller read it as `$(_leg_cache_dir)`, so each
# call minted a FRESH mktemp directory the next call could not see. The memo
# missed every time, the helpers fell back to one cargo entry per leg, and the
# job stayed green while giving the saving back. Measured on run 32276720780:
# eight `Finished test profile` lines in a job whose eight legs name a single
# compilation unit. This is why the initialiser sets a variable instead of
# printing one, and why the bottom of this file calls it at source time, in the
# shell that sourced it.
_leg_cache_dir_init() {
  if [ -z "${KIN_WINDOWS_LEG_CACHE_DIR:-}" ]; then
    KIN_WINDOWS_LEG_CACHE_DIR="$(mktemp -d)"
    export KIN_WINDOWS_LEG_CACHE_DIR
  fi
}

_leg_cache_key() {
  local joined="$PWD|$*"
  printf '%s\n' "unit-${joined//[^A-Za-z0-9]/_}"
}

# Resolve one compilation unit to "<executable>\t<package root>", building it at
# most once per distinct argument vector. Diagnostics are rendered to stderr by
# `json-render-diagnostics` rather than folded into the JSON on stdout, so a
# compile failure under `-D warnings` still reports itself as compiler output
# instead of being swallowed by the capture.
resolve_leg_unit() {
  local cache artifacts executables manifests count
  _leg_cache_dir_init
  cache="$KIN_WINDOWS_LEG_CACHE_DIR/$(_leg_cache_key "$@")"
  if [ -f "$cache" ] && [ -s "$cache" ]; then
    cat "$cache"
    return 0
  fi

  artifacts="$(cargo test --no-run --message-format=json-render-diagnostics "$@")"
  executables="$(printf '%s\n' "$artifacts" | _leg_test_executables)"
  manifests="$(printf '%s\n' "$artifacts" | _leg_test_manifests)"
  # These annotations go to stderr, not stdout. Callers read this function
  # through a command substitution, which captures stdout, so an `::error` line
  # written there would be swallowed into the caller's variable and never reach
  # the log. GitHub reads workflow commands off either stream.
  count="$(printf '%s\n' "$executables" | _leg_count_lines)"
  if [ "$count" -ne 1 ]; then
    echo "::error title=Ambiguous native Windows test binary::cargo test --no-run built $count test binaries for: $*" >&2
    echo "Each Windows authority leg must name exactly one compilation unit, because" >&2
    echo "the leg then drives that binary directly. Narrow the target selection." >&2
    printf '%s\n' "$executables" >&2
    exit 1
  fi
  count="$(printf '%s\n' "$manifests" | _leg_count_lines)"
  if [ "$count" -ne 1 ]; then
    echo "::error title=Unresolvable native Windows package root::cargo test --no-run reported $count manifests for: $*" >&2
    exit 1
  fi

  printf '%s\t%s\n' \
    "$(printf '%s\n' "$executables" | head -n 1)" \
    "$(dirname "$(printf '%s\n' "$manifests" | head -n 1)")" \
    > "$cache"
  cat "$cache"
}

# Run a resolved unit's binary the way cargo would have run it.
#
# The artifact directory goes on PATH through `cygpath -u` where that exists.
# PATH is a COLON-separated list, and a `D:/a/kin/...` component in one is
# ambiguous to the MSYS conversion that runs when bash spawns a native Windows
# process: the drive letter can be read as its own entry. A single path argument
# has no such ambiguity, which is why the executable and the package root are
# passed through as they are and only the list is converted.
_leg_exec() {
  local unit="$1"
  shift
  local executable package_root artifact_dir
  executable="${unit%%$'\t'*}"
  package_root="${unit#*$'\t'}"
  artifact_dir="$(dirname "$executable")"
  if command -v cygpath > /dev/null 2>&1; then
    artifact_dir="$(cygpath -u "$artifact_dir")"
  fi
  (
    cd "$package_root" || exit 1
    CARGO_MANIFEST_DIR="$package_root" \
    PATH="$artifact_dir:$PATH" \
      "$executable" "$@"
  )
}

# The listing a leg's guards read. It is the same text `cargo test -- --list`
# produced, because that is what cargo shells out to. `tr -d` strips the CRs a
# native Windows binary writes, so the awk matches below see plain lines.
_leg_listing() {
  _leg_exec "$1" --list | tr -d '\r'
}

assert_nonempty_listing() {
  local label="$1"
  local listing="$2"
  local count
  count="$(printf '%s\n' "$listing" \
    | awk '/: test$/ { count += 1 } END { print count + 0 }')"
  if [[ "$count" -eq 0 ]]; then
    echo "::error title=Missing native Windows tests::$label listed zero tests"
    printf '%s\n' "$listing"
    exit 1
  fi
  echo "$label: listed $count test(s)"
}

run_nonempty_target() {
  local label="$1"
  shift
  local unit
  local listing
  unit="$(resolve_leg_unit "$@")"
  listing="$(_leg_listing "$unit")"
  assert_nonempty_listing "$label" "$listing"
  _leg_exec "$unit" --test-threads=1
}

run_required_filter() {
  local label="$1"
  local filter="$2"
  shift 2
  local unit
  local listing
  local matches
  unit="$(resolve_leg_unit "$@")"
  listing="$(_leg_listing "$unit")"
  matches="$(printf '%s\n' "$listing" \
    | awk -v needle="$filter" \
      'index($0, needle) > 0 && /: test$/ { count += 1 } END { print count + 0 }')"
  if [[ "$matches" -eq 0 ]]; then
    echo "::error title=Missing native Windows tests::$label filter '$filter' matched zero listed tests"
    printf '%s\n' "$listing"
    exit 1
  fi
  echo "$label: filter '$filter' matched $matches test(s)"
  _leg_exec "$unit" "$filter" --test-threads=1
}

run_required_exact() {
  local label="$1"
  local test_name="$2"
  shift 2
  local unit
  local listing
  local matches
  unit="$(resolve_leg_unit "$@")"
  listing="$(_leg_listing "$unit")"
  matches="$(printf '%s\n' "$listing" \
    | awk -v expected="$test_name: test" \
      '$0 == expected { count += 1 } END { print count + 0 }')"
  if [[ "$matches" -ne 1 ]]; then
    echo "::error title=Missing native Windows test::$label expected exactly one '$test_name', found $matches"
    printf '%s\n' "$listing"
    exit 1
  fi
  _leg_exec "$unit" "$test_name" --exact --test-threads=1
}

run_required_target() {
  local label="$1"
  local required_test="$2"
  shift 2
  local unit
  local listing
  local matches
  unit="$(resolve_leg_unit "$@")"
  listing="$(_leg_listing "$unit")"
  assert_nonempty_listing "$label" "$listing"
  matches="$(printf '%s\n' "$listing" \
    | awk -v expected="$required_test: test" \
      '$0 == expected { count += 1 } END { print count + 0 }')"
  if [[ "$matches" -ne 1 ]]; then
    echo "::error title=Missing native Windows test::$label expected exactly one '$required_test', found $matches"
    printf '%s\n' "$listing"
    exit 1
  fi
  _leg_exec "$unit" --test-threads=1
}

compile_required_target() {
  local label="$1"
  local required_test="$2"
  shift 2
  local unit
  local listing
  local matches
  unit="$(resolve_leg_unit "$@")"
  listing="$(_leg_listing "$unit")"
  assert_nonempty_listing "$label" "$listing"
  matches="$(printf '%s\n' "$listing" \
    | awk -v expected="$required_test: test" \
      '$0 == expected { count += 1 } END { print count + 0 }')"
  if [[ "$matches" -ne 1 ]]; then
    echo "::error title=Missing native Windows compile target::$label expected exactly one '$required_test', found $matches"
    printf '%s\n' "$listing"
    exit 1
  fi
  echo "$label: compiled and listed required test '$required_test'"
}

# Initialise the memo HERE, at source time, in the shell that sourced this file.
# `resolve_leg_unit` is always reached through a command substitution, because
# every helper reads its stdout, and an export made inside a substitution dies
# with the subshell that made it. Initialising there produced a fresh directory
# per call and a memo that missed every time, which is invisible: the helpers
# fall back to one cargo entry per leg and the job stays green. A `source` runs
# in the caller's shell, so this is the one place the export survives.
_leg_cache_dir_init
