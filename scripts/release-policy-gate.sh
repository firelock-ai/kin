#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
#
# Run the automatic release-policy validators, and decide who a failure belongs
# to before turning it into a red required context.
#
# These validators police repo-global invariants: that rc-build.yml still
# mirrors release.yml's build job, that the version files agree, that the mint's
# authority tables match the workflow that produces them. A break in any of
# them is a property of the tree, not of the change under test, so the identical
# failure appears on every open pull request and every merge-queue entry at
# once. On 2026-08-19 one such break, a kin-vfs pin that had drifted between
# release.yml and rc-build.yml, failed this step 70 times and ejected 32 queue
# entries in a morning. Four of the seven pull requests it ejected touched
# nothing release-related, could not have caused the drift, and could not have
# fixed it. Each ejection cost a full requeue, and the queue lost roughly
# thirteen hours of serialized wall clock to a defect none of those changes
# introduced.
#
# So the failure is routed rather than softened:
#
#   - A change that touches release machinery still HARD-FAILS. Workflows,
#     version manifests, the changelog, the abandoned-tag ledger, and the
#     scripts these validators read are exactly where a real regression comes
#     from, and the release pull request itself is always in this class.
#   - Any event that is not a pull request or a merge-queue entry HARD-FAILS.
#     The push build on main is the one release-tag.yml reads for provenance, so
#     a broken invariant must be red there and must stop a mint.
#   - Anything else fails SOFT: the validators still run, the failure is still
#     printed in full and raised as a warning annotation, and the entry is not
#     ejected for a defect it did not bring.
#
# Everything unknown resolves to HARD. An unreadable diff, an unclassifiable
# event, a missing input: each of those is the state where the gate cannot prove
# the change is unrelated, and the safe reading of "cannot prove" is the
# behaviour this step had before.
#
# Transient refusals get a bounded retry ahead of that decision, because a
# network stumble inside a validator is neither a real break nor a reason to
# eject. The retry is keyed on the failure text: a deterministic assertion
# reproduces identically and is never retried past its first attempt beyond the
# bounded count, which costs seconds and cannot mask anything.
#
# Usage: release-policy-gate.sh [commands-file]
# With no argument the commands are read from stdin, which is how ci.yml passes
# them: the validator invocations stay visible in the workflow, where the
# assertion-reachability gate can see that they run.

set -euo pipefail

RELEASE_POLICY_ATTEMPTS="${KIN_POLICY_ATTEMPTS:-3}"
RELEASE_POLICY_BACKOFF="${KIN_POLICY_BACKOFF:-10}"
RELEASE_BRANCH="automation/release-next"

# Paths whose change can plausibly cause, or fix, one of these validators.
# Deliberately wide: over-including a path costs the old behaviour, which is a
# hard failure, while under-including one lets a real release regression land
# behind a warning. `*` matches `/` in a bash case pattern, so a directory
# prefix covers its whole subtree.
release_relevant_path() {
  case "$1" in
    .github/*) return 0 ;;
    scripts/*) return 0 ;;
    packages/*) return 0 ;;
    Cargo.toml | Cargo.lock | rust-toolchain.toml) return 0 ;;
    crates/*/Cargo.toml) return 0 ;;
    CHANGELOG.md) return 0 ;;
    docs/release-bot.md) return 0 ;;
    *) return 1 ;;
  esac
}

# Read paths on stdin, print `touched` or `untouched`. Blank input is not
# "untouched": a diff that produced no paths is a diff this gate failed to read.
classify_paths() {
  local seen=0
  local path
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    seen=1
    if release_relevant_path "$path"; then
      printf 'touched\n'
      return 0
    fi
  done
  if [ "$seen" -eq 0 ]; then
    printf 'unknown\n'
    return 0
  fi
  printf 'untouched\n'
}

# The whole routing decision, as one pure function so it can be driven directly
# by the falsification test. `relevance` is touched / untouched / unknown.
release_policy_severity() {
  local event="$1"
  local head_ref="$2"
  local relevance="$3"

  if [ "$head_ref" = "$RELEASE_BRANCH" ]; then
    printf 'hard\n'
    return 0
  fi
  case "$event" in
    pull_request | merge_group) ;;
    *)
      printf 'hard\n'
      return 0
      ;;
  esac
  if [ "$relevance" = "untouched" ]; then
    printf 'soft\n'
    return 0
  fi
  printf 'hard\n'
}

# A failure worth trying again. Matched against the validators' own output, so
# a deterministic assertion never matches and never spends the budget.
transient_failure() {
  case "$1" in
    *"Could not resolve host"*) return 0 ;;
    *"Temporary failure in name resolution"*) return 0 ;;
    *"EAI_AGAIN"*) return 0 ;;
    *"ECONNRESET"*) return 0 ;;
    *"ETIMEDOUT"*) return 0 ;;
    *"Connection reset"*) return 0 ;;
    *"Connection timed out"*) return 0 ;;
    *"TLS connect error"*) return 0 ;;
    *"502 Bad Gateway"*) return 0 ;;
    *"503 Service Unavailable"*) return 0 ;;
    *"504 Gateway"*) return 0 ;;
    *"rate limit exceeded"*) return 0 ;;
    *"secondary rate limit"*) return 0 ;;
    *"server error"*) return 0 ;;
    *) return 1 ;;
  esac
}

# The changed-path list for this event, or nothing at all. The compare endpoint
# caps `files` at 300 and says nothing when it truncates, so a diff at the cap
# is reported as unreadable rather than as a partial answer that could classify
# a release-touching change as unrelated.
changed_paths() {
  local repo="${KIN_POLICY_REPOSITORY:-}"
  local base="${KIN_POLICY_BASE_SHA:-}"
  local head="${KIN_POLICY_HEAD_SHA:-}"
  if [ -z "$repo" ] || [ -z "$base" ] || [ -z "$head" ]; then
    return 1
  fi

  local attempt=1
  local response=""
  local status=0
  while [ "$attempt" -le "$RELEASE_POLICY_ATTEMPTS" ]; do
    status=0
    response="$(gh api "repos/$repo/compare/$base...$head" 2>&1)" || status=$?
    if [ "$status" -eq 0 ]; then
      break
    fi
    echo "release-policy gate: compare attempt $attempt failed" >&2
    printf '%s\n' "$response" >&2
    attempt=$((attempt + 1))
    if [ "$attempt" -le "$RELEASE_POLICY_ATTEMPTS" ]; then
      sleep "$RELEASE_POLICY_BACKOFF"
    fi
  done
  if [ "$status" -ne 0 ]; then
    return 1
  fi

  local count
  count="$(printf '%s' "$response" | jq '.files | length')" || return 1
  if [ "$count" -ge 300 ]; then
    echo "release-policy gate: compare returned $count files and may be truncated" >&2
    return 1
  fi
  printf '%s' "$response" | jq -r '.files[].filename'
}

resolve_relevance() {
  local paths
  if ! paths="$(changed_paths)"; then
    printf 'unknown\n'
    return 0
  fi
  printf '%s\n' "$paths" | classify_paths
}

run_validators() {
  local commands="$1"
  local attempt=1
  local status=0
  local output=""
  while [ "$attempt" -le "$RELEASE_POLICY_ATTEMPTS" ]; do
    status=0
    output="$(bash -euo pipefail "$commands" 2>&1)" || status=$?
    printf '%s\n' "$output"
    if [ "$status" -eq 0 ]; then
      return 0
    fi
    if ! transient_failure "$output"; then
      break
    fi
    echo "release-policy gate: attempt $attempt failed on a transient refusal" >&2
    attempt=$((attempt + 1))
    if [ "$attempt" -le "$RELEASE_POLICY_ATTEMPTS" ]; then
      sleep "$RELEASE_POLICY_BACKOFF"
    fi
  done
  return "${status:-1}"
}

main() {
  local commands
  local cleanup=""
  if [ "$#" -ge 1 ]; then
    commands="$1"
  else
    commands="$(mktemp)"
    cleanup="$commands"
    cat > "$commands"
  fi
  # shellcheck disable=SC2064
  [ -z "$cleanup" ] || trap "rm -f '$cleanup'" EXIT

  # Printed on EVERY run, not only a failing one. The routing inputs are read
  # from event payloads that differ per event type, and if one of them arrives
  # empty the gate resolves the diff as unreadable and hard-fails, which is
  # indistinguishable from the behaviour this step had before. That is the safe
  # direction, and it is also invisible: the soft path would simply never fire
  # and nobody would learn why. This line is what makes the wiring checkable
  # from a green run.
  echo "release-policy gate: event=${KIN_POLICY_EVENT:-unset}" \
    "head_ref=${KIN_POLICY_HEAD_REF:-none}" \
    "base_sha=${KIN_POLICY_BASE_SHA:-unset}" \
    "head_sha=${KIN_POLICY_HEAD_SHA:-unset}"

  if run_validators "$commands"; then
    echo "release policy validators passed"
    return 0
  fi

  local event="${KIN_POLICY_EVENT:-}"
  local head_ref="${KIN_POLICY_HEAD_REF:-}"
  local relevance
  relevance="$(resolve_relevance)"
  local severity
  severity="$(release_policy_severity "$event" "$head_ref" "$relevance")"

  echo "release-policy gate: event=$event head_ref=${head_ref:-<none>} release-paths=$relevance severity=$severity" >&2

  if [ "$severity" = "hard" ]; then
    echo "::error title=Automatic release policy::the release-policy validators failed on a change that reaches release machinery"
    return 1
  fi

  echo "::warning title=Automatic release policy::the release-policy validators are failing on a repository-wide invariant this change does not touch. The failure is real and is reported above; it is not attributed to this entry, which is why this check is not red. Fix it in a change that touches release machinery, where this gate hard-fails."
  return 0
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  main "$@"
fi
