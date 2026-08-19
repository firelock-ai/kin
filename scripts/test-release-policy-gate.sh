#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
#
# Falsify scripts/release-policy-gate.sh.
#
# The gate decides whether a failing release-policy validator turns a required
# context red. Both of its mistakes are silent. Routed too softly, a real
# release regression lands behind a warning nobody reads, and the next tag is
# the one that finds out. Routed too harshly, the gate is what it replaced and
# the next repo-global break ejects the queue again.
#
# So every arm is driven here, in both directions: the soft path is proven to
# exist, and it is proven NOT to exist for a release-touching change, for the
# release pull request, for a push, or for a diff the gate could not read. The
# routing decision is a pure function precisely so it can be driven without a
# network, and the end-to-end arms replace `changed_paths` after sourcing rather
# than giving the production script an injection point that a workflow edit
# could aim at itself.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GATE="$ROOT/scripts/release-policy-gate.sh"

if [ ! -f "$GATE" ]; then
  echo "missing gate under test: $GATE" >&2
  exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

export KIN_POLICY_BACKOFF=0
export KIN_POLICY_ATTEMPTS=3

# shellcheck source=scripts/release-policy-gate.sh
source "$GATE"

failures=0

report() { echo "  $1"; }

fail() {
  echo "FAIL: $1" >&2
  failures=$((failures + 1))
}

expect_equal() {
  local label="$1"
  local want="$2"
  local got="$3"
  if [ "$want" = "$got" ]; then
    report "$label"
  else
    fail "$label: wanted '$want', got '$got'"
  fi
}

echo "path classification"

for path in \
  ".github/workflows/ci.yml" \
  ".github/workflows/release.yml" \
  "scripts/check-rc-build-drift.mjs" \
  "scripts/abandoned-release-tags.json" \
  "Cargo.toml" \
  "Cargo.lock" \
  "rust-toolchain.toml" \
  "crates/kin-cli/Cargo.toml" \
  "packages/kin/package.json" \
  "CHANGELOG.md" \
  "docs/release-bot.md"; do
  expect_equal "release path '$path' classifies as touched" \
    "touched" "$(printf '%s\n' "$path" | classify_paths)"
done

for path in \
  "crates/kin-cli/src/commands/setup.rs" \
  "crates/kin-core/src/init.rs" \
  "README.md" \
  "docs/architecture.md" \
  "src/main.rs"; do
  expect_equal "unrelated path '$path' classifies as untouched" \
    "untouched" "$(printf '%s\n' "$path" | classify_paths)"
done

expect_equal "one release path among many decides the whole diff" \
  "touched" \
  "$(printf '%s\n' "crates/kin-core/src/init.rs" "README.md" "Cargo.lock" | classify_paths)"

expect_equal "an empty path list is unknown, not untouched" \
  "unknown" "$(printf '' | classify_paths)"

echo "routing decision"

expect_equal "a merge-queue entry touching release machinery hard-fails" \
  "hard" "$(release_policy_severity merge_group "" touched)"
expect_equal "a merge-queue entry touching nothing release-related fails soft" \
  "soft" "$(release_policy_severity merge_group "" untouched)"
expect_equal "a pull request touching nothing release-related fails soft" \
  "soft" "$(release_policy_severity pull_request "some/branch" untouched)"
expect_equal "a pull request touching release machinery hard-fails" \
  "hard" "$(release_policy_severity pull_request "some/branch" touched)"
expect_equal "the release pull request hard-fails even on an unrelated diff" \
  "hard" "$(release_policy_severity pull_request "automation/release-next" untouched)"
expect_equal "a push to main hard-fails" \
  "hard" "$(release_policy_severity push "" untouched)"
expect_equal "a repository_dispatch hard-fails" \
  "hard" "$(release_policy_severity repository_dispatch "" untouched)"
expect_equal "an unreadable diff hard-fails" \
  "hard" "$(release_policy_severity merge_group "" unknown)"

echo "transient classification"

for text in \
  "curl: (6) Could not resolve host: github.com" \
  "Error: connect ETIMEDOUT 140.82.121.6:443" \
  "read ECONNRESET" \
  "HTTP 503 Service Unavailable" \
  "API rate limit exceeded for 1.2.3.4"; do
  if transient_failure "$text"; then
    report "retryable: ${text:0:40}"
  else
    fail "did not classify as transient: $text"
  fi
done

for text in \
  "AssertionError: rc-build.yml no longer mirrors release.yml" \
  "not ok 27 - the workflows in the tree agree" \
  "assertion reachability gate failed: missing call site"; do
  if transient_failure "$text"; then
    fail "classified a deterministic failure as transient: $text"
  else
    report "not retryable: ${text:0:40}"
  fi
done

echo "end to end"

COUNTER="$WORK/attempts"

# `main` is invoked in a subshell so its EXIT trap and its exit status stay its
# own. Output is captured whole; nothing here is judged through a pipe.
drive() {
  local label="$1"
  local want_status="$2"
  local want_needle="$3"
  local commands="$4"
  local want_paths="$5"
  local event="$6"
  local head_ref="$7"

  : > "$COUNTER"
  local output
  local status=0
  output="$(
    changed_paths() { printf '%s\n' $want_paths; }
    KIN_POLICY_EVENT="$event" KIN_POLICY_HEAD_REF="$head_ref" \
      main "$commands" 2>&1
  )" || status=$?

  if [ "$status" -ne "$want_status" ]; then
    fail "$label: wanted exit $want_status, got $status"
    printf '%s\n' "$output" >&2
    return
  fi
  case "$output" in
    *"$want_needle"*) report "$label" ;;
    *)
      fail "$label: output did not carry '$want_needle'"
      printf '%s\n' "$output" >&2
      ;;
  esac
}

cat > "$WORK/passing.sh" <<EOF
printf 'x' >> "$COUNTER"
echo "all validators agree"
EOF

cat > "$WORK/deterministic.sh" <<EOF
printf 'x' >> "$COUNTER"
echo "AssertionError: rc-build.yml no longer mirrors release.yml" >&2
exit 1
EOF

cat > "$WORK/transient-then-passing.sh" <<EOF
printf 'x' >> "$COUNTER"
if [ "\$(wc -c < "$COUNTER" | tr -d ' ')" -lt 3 ]; then
  echo "curl: (6) Could not resolve host: github.com" >&2
  exit 1
fi
echo "all validators agree on the third attempt"
EOF

attempts() { wc -c < "$COUNTER" | tr -d ' '; }

drive "passing validators exit clean" 0 "release policy validators passed" \
  "$WORK/passing.sh" "README.md" merge_group ""
expect_equal "a passing run costs one attempt" "1" "$(attempts)"

drive "a real failure on a release-touching entry is an error" 1 \
  "::error title=Automatic release policy" \
  "$WORK/deterministic.sh" "Cargo.lock" merge_group ""

drive "a real failure on an unrelated entry is a warning" 0 \
  "::warning title=Automatic release policy" \
  "$WORK/deterministic.sh" "crates/kin-core/src/init.rs" merge_group ""
expect_equal "a deterministic failure is not retried" "1" "$(attempts)"

drive "the failure text is still printed on the soft path" 0 \
  "rc-build.yml no longer mirrors release.yml" \
  "$WORK/deterministic.sh" "crates/kin-core/src/init.rs" merge_group ""

drive "the release pull request never takes the soft path" 1 \
  "::error title=Automatic release policy" \
  "$WORK/deterministic.sh" "crates/kin-core/src/init.rs" \
  pull_request "automation/release-next"

drive "a push to main never takes the soft path" 1 \
  "::error title=Automatic release policy" \
  "$WORK/deterministic.sh" "crates/kin-core/src/init.rs" push ""

drive "a transient refusal is retried and then passes" 0 \
  "release policy validators passed" \
  "$WORK/transient-then-passing.sh" "crates/kin-core/src/init.rs" merge_group ""
expect_equal "the transient arm took three attempts" "3" "$(attempts)"

# An unreadable diff must not become a soft pass. `changed_paths` returning
# non-zero is what the real one does when the compare call or its inputs fail.
: > "$COUNTER"
unreadable_status=0
unreadable_output="$(
  changed_paths() { return 1; }
  KIN_POLICY_EVENT=merge_group KIN_POLICY_HEAD_REF="" \
    main "$WORK/deterministic.sh" 2>&1
)" || unreadable_status=$?
if [ "$unreadable_status" -eq 1 ]; then
  case "$unreadable_output" in
    *"::error title=Automatic release policy"*)
      report "an unreadable diff hard-fails end to end" ;;
    *)
      fail "an unreadable diff failed without the error annotation"
      printf '%s\n' "$unreadable_output" >&2 ;;
  esac
else
  fail "an unreadable diff did not hard-fail (exit $unreadable_status)"
  printf '%s\n' "$unreadable_output" >&2
fi

if [ "$failures" -ne 0 ]; then
  echo "release policy gate: $failures assertion(s) failed" >&2
  exit 1
fi

echo "release policy gate: routing, retry, and both failure directions hold"
