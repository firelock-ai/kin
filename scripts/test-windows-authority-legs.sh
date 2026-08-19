#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
#
# Drive scripts/windows-authority-legs.sh against a real cargo package.
#
# The helpers under test decide what the three native Windows authority jobs
# prove, and they now resolve a compilation unit once and execute the compiled
# test binary for every leg after that. Two classes of breakage are invisible
# without this file. A memo that silently misses re-enters cargo for every leg
# and gives back the minutes the change was made to save, while reporting a
# perfectly green job. An emptiness guard that stops firing reports success for
# a test that was renamed away, which is the exact condition the helpers were
# written to catch.
#
# So this runs both arms. It proves the helpers pass a real selection, and it
# proves each guard still FAILS on the input it exists to reject. It also counts
# cargo entries through a PATH shim, because "built once" is a claim about
# process count that no assertion on the test result can see.
#
# The fixture is a throwaway package outside the repository: a lib with unit
# tests, a bin, and an integration test. That shape is what makes the artifact
# selector falsifiable, because `cargo test --no-run` for an integration test
# also builds the package binary and that binary carries an `executable` of its
# own.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HELPERS="$ROOT/scripts/windows-authority-legs.sh"

if [ ! -f "$HELPERS" ]; then
  echo "missing helpers under test: $HELPERS" >&2
  exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

FIXTURE="$WORK/legfixture"
mkdir -p "$FIXTURE/src" "$FIXTURE/tests" "$WORK/bin"

cat > "$FIXTURE/Cargo.toml" <<'EOF'
[package]
name = "legfixture"
version = "0.1.0"
edition = "2021"

[lib]
name = "legfixture"
path = "src/lib.rs"

[[bin]]
name = "legfixture"
path = "src/main.rs"
EOF

# `runs_where_cargo_would_run_it` is the cwd and environment assertion. Cargo
# runs a test binary with the working directory at the package root and
# CARGO_MANIFEST_DIR exported; a bare execution from the repository root does
# neither, and a test reading either would change behaviour for a reason having
# nothing to do with the test.
cat > "$FIXTURE/src/lib.rs" <<'EOF'
pub fn add(a: i32, b: i32) -> i32 {
    a + b
}

#[cfg(test)]
mod tests {
    #[test]
    fn unit_addition() {
        assert_eq!(super::add(1, 1), 2);
    }

    #[test]
    fn unit_identity() {
        assert_eq!(super::add(2, 0), 2);
    }

    #[test]
    fn runs_where_cargo_would_run_it() {
        let cwd = std::env::current_dir().expect("a working directory");
        assert!(
            cwd.join("Cargo.toml").is_file(),
            "working directory is not the package root: {cwd:?}"
        );
        let manifest_dir =
            std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is exported");
        let manifest_dir =
            std::fs::canonicalize(manifest_dir).expect("CARGO_MANIFEST_DIR resolves");
        let cwd = std::fs::canonicalize(cwd).expect("the working directory resolves");
        assert_eq!(manifest_dir, cwd);
    }
}
EOF

cat > "$FIXTURE/src/main.rs" <<'EOF'
fn main() {
    println!("legfixture");
}
EOF

cat > "$FIXTURE/tests/integration.rs" <<'EOF'
#[test]
fn integration_reaches_the_library() {
    assert_eq!(legfixture::add(3, 4), 7);
}
EOF

CARGO_BIN="$(command -v cargo)"
CALLS="$WORK/cargo-calls"
: > "$CALLS"

cat > "$WORK/bin/cargo" <<EOF
#!/usr/bin/env bash
printf 'x' >> "$CALLS"
exec "$CARGO_BIN" "\$@"
EOF
chmod +x "$WORK/bin/cargo"

export PATH="$WORK/bin:$PATH"
export CARGO_TARGET_DIR="$WORK/target"

# KIN_WINDOWS_LEG_CACHE_DIR is deliberately NOT set. Pinning it here was how the
# memo's own assertion came to prove nothing: the helpers create the directory
# themselves when the variable is empty, that is the path CI takes, and an
# earlier version created a fresh one per call and missed every time. A test
# that supplies the directory exercises neither. The override is covered
# separately at the end.
unset KIN_WINDOWS_LEG_CACHE_DIR

cd "$FIXTURE"

# shellcheck source=scripts/windows-authority-legs.sh
source "$HELPERS"

failures=0

report() {
  echo "  $1"
}

fail() {
  echo "FAIL: $1" >&2
  failures=$((failures + 1))
}

cargo_entries() {
  wc -c < "$CALLS" | tr -d ' '
}

# Every helper call runs in a subshell, positive arm included, because the
# helpers `exit` rather than return. A bare call that trips a guard would take
# this file down with it, and the run would end mid-arm having reported nothing
# about which assertion was reached: exit 1 with a truncated log reads the same
# whether the guard fired correctly or the harness broke. Output is captured
# whole and printed on an unexpected result. A pipeline's status is its last
# stage's, so nothing here is judged through `head`, `tail`, or a pipe.
LAST_OUTPUT=""

# The positive arm calls the helpers DIRECTLY, in this shell, because that is
# how ci.yml calls them and because the memo depends on it: the helpers export
# their cache directory, and an export made inside a command substitution dies
# with the subshell. Running the positive arm through substitutions is what let
# a memo that missed every single time read as a passing assertion. The cost is
# that a helper's hard `exit` takes this file with it, so the label is printed
# BEFORE the call and the run's last line names where it stopped.
expect_pass() {
  local label="$1"
  shift
  echo "  running: $label"
  local status=0
  "$@" > "$WORK/last.log" 2>&1 || status=$?
  LAST_OUTPUT="$(cat "$WORK/last.log")"
  if [ "$status" -ne 0 ]; then
    fail "$label did not pass (exit $status)"
    cat "$WORK/last.log" >&2
    return 1
  fi
  report "$label"
  return 0
}

expect_refusal() {
  local label="$1"
  local needle="$2"
  shift 2
  local output
  local status=0
  output="$( "$@" 2>&1 )" || status=$?
  if [ "$status" -eq 0 ]; then
    fail "$label was accepted; the guard cannot fire"
    printf '%s\n' "$output" >&2
    return
  fi
  case "$output" in
    *"$needle"*) report "refused $label" ;;
    *)
      fail "$label was refused for the wrong reason (wanted '$needle')"
      printf '%s\n' "$output" >&2
      ;;
  esac
}

echo "positive arm"

before="$(cargo_entries)"
if expect_pass "ran a filtered library leg" \
  run_required_filter "fixture library units" "unit_" --lib; then
  case "$LAST_OUTPUT" in
    *"filter 'unit_' matched 2 test(s)"*) : ;;
    *)
      fail "the filtered leg did not report its match count"
      printf '%s\n' "$LAST_OUTPUT" >&2
      ;;
  esac
fi
after_first="$(cargo_entries)"
if [ "$((after_first - before))" -ne 1 ]; then
  fail "resolving one unit took $((after_first - before)) cargo entries, expected 1"
fi

# The cwd and environment assertion lives in the fixture's own test, so a
# regression there fails the run rather than this file's bookkeeping.
expect_pass "ran the compiled binary the way cargo runs it" \
  run_required_exact "cargo-equivalent execution" \
  "tests::runs_where_cargo_would_run_it" --lib || true

after_second="$(cargo_entries)"
if [ "$after_second" -ne "$after_first" ]; then
  fail "a second leg on the same unit entered cargo again ($after_first -> $after_second)"
else
  report "a second leg on the same unit entered cargo zero more times"
fi

# A different argument vector is a different compilation unit and must build.
expect_pass "ran a whole integration target" \
  run_required_target "fixture integration binary" \
  "integration_reaches_the_library" --test integration || true
after_third="$(cargo_entries)"
if [ "$((after_third - after_second))" -ne 1 ]; then
  fail "a distinct unit took $((after_third - after_second)) cargo entries, expected 1"
fi

# `cargo test --no-run --test integration` also builds the package binary, and
# that binary carries an `executable` of its own. Resolving to it instead of the
# harness would run the fixture's main and report success having tested nothing.
if expect_pass "resolved a single integration unit" \
  resolve_leg_unit --test integration; then
  resolved="${LAST_OUTPUT%%$'\t'*}"
  case "$(basename "$resolved")" in
    integration-*) report "selected the test harness, not the package binary" ;;
    *) fail "resolved the wrong artifact: $resolved" ;;
  esac
fi

expect_pass "compiled and listed without running" \
  compile_required_target "fixture compile-only" \
  "integration_reaches_the_library" --test integration || true

echo "falsification arm"

expect_refusal "a filter matching nothing" \
  "matched zero listed tests" \
  run_required_filter "renamed away" "no_such_test_name" --lib

expect_refusal "an exact name that does not exist" \
  "expected exactly one" \
  run_required_exact "renamed away" "tests::no_such_test" --lib

expect_refusal "a required name absent from a whole target" \
  "expected exactly one" \
  run_required_target "renamed away" "no_such_test" --test integration

expect_refusal "a compile target whose required test is gone" \
  "expected exactly one" \
  compile_required_target "renamed away" "no_such_test" --test integration

# No target selector at all builds the lib harness AND the integration harness,
# so the leg names two compilation units and cannot say which one it drives.
expect_refusal "a selection naming more than one test binary" \
  "Ambiguous native Windows test binary" \
  resolve_leg_unit

# An empty listing is the condition the original guards were written for: a
# target that builds and lists nothing must not read as a passing leg.
mkdir -p "$WORK/emptyfixture/src"
cat > "$WORK/emptyfixture/Cargo.toml" <<'EOF'
[package]
name = "emptyfixture"
version = "0.1.0"
edition = "2021"

[lib]
name = "emptyfixture"
path = "src/lib.rs"
EOF
cat > "$WORK/emptyfixture/src/lib.rs" <<'EOF'
pub fn add(a: i32, b: i32) -> i32 {
    a + b
}
EOF
cd "$WORK/emptyfixture"
expect_refusal "a target that lists zero tests" \
  "listed zero tests" \
  run_nonempty_target "no tests at all" --lib
cd "$FIXTURE"

echo "cache directory arm"

# The helpers must have created the directory themselves, in THIS shell, which
# is what makes the memo survive between legs. If they created it inside a
# command substitution the variable would be unset here and every leg would have
# built its own.
if [ -n "${KIN_WINDOWS_LEG_CACHE_DIR:-}" ] && [ -d "$KIN_WINDOWS_LEG_CACHE_DIR" ]; then
  report "the helpers created and exported one cache directory"
else
  fail "no cache directory survived the legs; the memo cannot persist"
fi

entries="$(find "$KIN_WINDOWS_LEG_CACHE_DIR" -type f | wc -l | tr -d ' ')"
if [ "$entries" -ge 2 ]; then
  report "the cache holds $entries resolved units"
else
  fail "the cache holds $entries entries after several distinct units"
fi

# The override still works, and a caller-supplied directory is used rather than
# a fresh one.
override="$WORK/explicit-cache"
mkdir -p "$override"
(
  export KIN_WINDOWS_LEG_CACHE_DIR="$override"
  run_required_filter "override cache" "unit_" --lib > /dev/null 2>&1
)
if [ "$(find "$override" -type f | wc -l | tr -d ' ')" -ge 1 ]; then
  report "an explicit cache directory is honoured"
else
  fail "an explicit KIN_WINDOWS_LEG_CACHE_DIR was ignored"
fi

if [ "$failures" -ne 0 ]; then
  echo "windows authority leg helpers: $failures assertion(s) failed" >&2
  exit 1
fi

echo "windows authority leg helpers: positive and falsification arms both hold"
