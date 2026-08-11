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
# Source this file from a `bash` step that has already set `-euo pipefail`.

list_tests() {
  CARGO_TERM_COLOR=never cargo test "$@" -- --list | tr -d '\r'
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
  local listing
  listing="$(list_tests "$@")"
  assert_nonempty_listing "$label" "$listing"
  cargo test "$@" -- --test-threads=1
}

run_required_filter() {
  local label="$1"
  local filter="$2"
  shift 2
  local listing
  local matches
  listing="$(list_tests "$@")"
  matches="$(printf '%s\n' "$listing" \
    | awk -v needle="$filter" \
      'index($0, needle) > 0 && /: test$/ { count += 1 } END { print count + 0 }')"
  if [[ "$matches" -eq 0 ]]; then
    echo "::error title=Missing native Windows tests::$label filter '$filter' matched zero listed tests"
    printf '%s\n' "$listing"
    exit 1
  fi
  echo "$label: filter '$filter' matched $matches test(s)"
  cargo test "$@" "$filter" -- --test-threads=1
}

run_required_exact() {
  local label="$1"
  local test_name="$2"
  shift 2
  local listing
  local matches
  listing="$(list_tests "$@")"
  matches="$(printf '%s\n' "$listing" \
    | awk -v expected="$test_name: test" \
      '$0 == expected { count += 1 } END { print count + 0 }')"
  if [[ "$matches" -ne 1 ]]; then
    echo "::error title=Missing native Windows test::$label expected exactly one '$test_name', found $matches"
    printf '%s\n' "$listing"
    exit 1
  fi
  cargo test "$@" "$test_name" -- --exact --test-threads=1
}

run_required_target() {
  local label="$1"
  local required_test="$2"
  shift 2
  local listing
  local matches
  listing="$(list_tests "$@")"
  assert_nonempty_listing "$label" "$listing"
  matches="$(printf '%s\n' "$listing" \
    | awk -v expected="$required_test: test" \
      '$0 == expected { count += 1 } END { print count + 0 }')"
  if [[ "$matches" -ne 1 ]]; then
    echo "::error title=Missing native Windows test::$label expected exactly one '$required_test', found $matches"
    printf '%s\n' "$listing"
    exit 1
  fi
  cargo test "$@" -- --test-threads=1
}

compile_required_target() {
  local label="$1"
  local required_test="$2"
  shift 2
  local listing
  local matches
  listing="$(list_tests "$@")"
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
