#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
#
# Prove the container base images the release image is built FROM are still
# served, at the exact digests the Dockerfile pins, by both registries the
# build can reach.
#
# The build resolves docker.io through a mirror and falls back to the canonical
# registry, which only removes the single point of failure while both doors
# stay open. Nothing in the build reports which door answered, so a mirror that
# silently stopped carrying a pinned digest would look identical to a healthy
# build right up to the outage it was supposed to survive. This asserts each
# door independently.
#
# Three outcomes, deliberately distinct, because the caller acts differently on
# each and because reporting one as another is how a prover lies:
#
#   0  every pin verified from both registries
#   1  a pin is DEFINITIVELY gone or wrong at a registry
#   2  verification could not be completed (throttled or otherwise transient)
#
# A registry throttle is not a missing digest. Docker Hub's anonymous manifest
# limit is per IP and hosted runners share heavily used egress, so treating an
# exhausted retry as "no longer serves" would raise a false alarm far more often
# than a true one. release.yml's own inspect_digest retries against the same
# reality; this mirrors that rather than inventing a second policy.
#
# Upstream tag drift is reported, never failed, and a drift lookup that does not
# answer must not stop the remaining pins from being checked.

set -euo pipefail

dockerfile="${1:-Dockerfile}"
canonical_registry="docker.io"
mirror_registry="mirror.gcr.io"

if [ ! -f "$dockerfile" ]; then
  echo "::error::no Dockerfile at $dockerfile"
  exit 1
fi

# resolve_digest runs inside a command substitution, so anything it assigns to a
# variable dies with that subshell. The diagnostic has to survive in a file for
# the caller to be able to say WHY a lookup did not answer.
resolve_error_file="$(mktemp)"
trap 'rm -f "$resolve_error_file"' EXIT

# Resolve one reference to the digest its registry reports.
#
#   0   digest printed on stdout
#   44  the registry answered definitively that it does not have it
#   2   no usable answer within the retry budget
#
# Distinguishing 44 from 2 is the point: only 44 justifies claiming a registry
# no longer serves a pin.
resolve_digest() {
  local reference="$1"
  local output=""
  local attempt
  : > "$resolve_error_file"
  for attempt in 1 2 3; do
    # Each call is wall-clock bounded. A registry outage is exactly when a
    # connect hangs rather than refusing, and this job's whole reason to exist
    # is registry outages, so an unbounded call would let the job run past its
    # timeout during the one event it is watching for. A job that exceeds
    # timeout-minutes concludes `cancelled`, which the release sweep treats as
    # non-green just like `failure`.
    if output="$(timeout 20 docker buildx imagetools inspect "$reference" \
      --format '{{.Manifest.Digest}}' 2>&1)"; then
      printf '%s\n' "$output"
      return 0
    fi
    printf '%s' "$output" > "$resolve_error_file"
    # Match an HTTP status token or a whole phrase, never a bare "404". The
    # error text embeds the reference, so the pinned digest is part of what is
    # searched, and roughly one digest in seventy contains "404" somewhere in
    # its hex. A bare substring match would turn any error, a throttle
    # included, into "the registry answered definitively that it does not have
    # it" for those digests, which is the exact false alarm the three-state
    # design exists to prevent.
    case "$output" in
      *": not found"* | *"404 Not Found"* | *"status 404"* \
        | *MANIFEST_UNKNOWN* | *"manifest unknown"*)
        return 44
        ;;
    esac
    if [ "$attempt" -lt 3 ]; then
      sleep $(( attempt * 5 ))
    fi
  done
  return 2
}

summary() {
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    printf '%s\n' "$1" >> "$GITHUB_STEP_SUMMARY"
  fi
}

# Probe one door. Reports through a global rather than stdout so its own log
# lines cannot be captured into the state it is reporting, and always returns 0
# so a probe result can never terminate the caller under errexit.
probe_state=""
probe_registry() {
  local registry="$1"
  local path="$2"
  local pinned_digest="$3"
  local resolved=""
  local status=0

  resolved="$(resolve_digest "${registry}/${path}@${pinned_digest}")" || status=$?
  if [ "$status" -eq 0 ]; then
    if [ "$resolved" = "$pinned_digest" ]; then
      probe_state=ok
    else
      echo "::error::${registry} served ${path} as ${resolved}, not the pinned ${pinned_digest}"
      probe_state=mismatch
    fi
    return 0
  fi
  if [ "$status" -eq 44 ]; then
    echo "::error::${registry} no longer serves ${path} at ${pinned_digest}: $(cat "$resolve_error_file")"
    probe_state=gone
    return 0
  fi
  echo "::warning::${registry} did not answer for ${path} at ${pinned_digest} within the retry budget; this is not a claim that it is gone: $(cat "$resolve_error_file")"
  probe_state=unverified
  return 0
}

pins_found=0
broken=0
unverified=0
drifted=0

summary "## Base image pins"
summary ""
summary "| image | pinned digest | ${canonical_registry} | ${mirror_registry} | upstream tag |"
summary "| --- | --- | --- | --- | --- |"

# Read FROM lines from the Dockerfile itself so the pins cannot be checked
# against a second copy that drifts from the one the build uses.
while IFS= read -r from_line; do
  # `FROM` accepts flags before the reference (`--platform=`) and a trailing
  # `AS <stage>` after it. Take the first token that is neither.
  reference=""
  for token in $from_line; do
    case "$token" in
      FROM | --*) continue ;;
      *) reference="$token"; break ;;
    esac
  done
  if [ -z "$reference" ]; then
    echo "::error::could not read a base image reference from: ${from_line}"
    broken=$((broken + 1))
    continue
  fi

  case "$reference" in
    *@sha256:*) ;;
    *)
      echo "::error::base image is not digest-pinned: ${reference}"
      broken=$((broken + 1))
      continue
      ;;
  esac

  pins_found=$((pins_found + 1))
  pinned_digest="${reference##*@}"
  name_with_tag="${reference%@*}"

  # Split the tag off only when the colon follows the last slash: a registry
  # host may carry a port, and a reference may be pinned with no tag at all.
  repository="$name_with_tag"
  tag=""
  case "${name_with_tag##*/}" in
    *:*)
      tag="${name_with_tag##*:}"
      repository="${name_with_tag%:*}"
      ;;
  esac

  case "$repository" in
    "${canonical_registry}/"*)
      path="${repository#"${canonical_registry}/"}"
      ;;
    *)
      echo "::error::base image must name ${canonical_registry} explicitly so the mirror rewrite is reviewable: ${reference}"
      broken=$((broken + 1))
      continue
      ;;
  esac

  probe_registry "$canonical_registry" "$path" "$pinned_digest"
  canonical_state="$probe_state"
  probe_registry "$mirror_registry" "$path" "$pinned_digest"
  mirror_state="$probe_state"
  for state in "$canonical_state" "$mirror_state"; do
    case "$state" in
      gone | mismatch) broken=$((broken + 1)) ;;
      unverified) unverified=$((unverified + 1)) ;;
    esac
  done

  tag_state="untagged"
  if [ -n "$tag" ]; then
    upstream_digest=""
    tag_state="unresolved"
    if upstream_digest="$(resolve_digest "${canonical_registry}/${path}:${tag}")"; then
      if [ "$upstream_digest" = "$pinned_digest" ]; then
        tag_state="current"
      else
        tag_state="moved to ${upstream_digest}"
        drifted=$((drifted + 1))
        echo "::warning::${path}:${tag} has moved past the pin; bump the Dockerfile digest to ${upstream_digest}"
      fi
    fi
  fi

  echo "${path}:${tag} pinned=${pinned_digest} ${canonical_registry}=${canonical_state} ${mirror_registry}=${mirror_state} tag=${tag_state}"
  summary "| \`${path}:${tag}\` | \`${pinned_digest}\` | ${canonical_state} | ${mirror_state} | ${tag_state} |"
done < <(grep -E '^FROM[[:space:]]' "$dockerfile")

if [ "$pins_found" -eq 0 ]; then
  echo "::error::no digest-pinned base image was found in ${dockerfile}; this check would pass an unpinned build"
  exit 1
fi

summary ""
summary "${pins_found} pinned base image(s): ${broken} unreachable or wrong, ${unverified} unverified, ${drifted} behind the upstream tag."

if [ "$broken" -gt 0 ]; then
  echo "::error::${broken} base image pin check(s) failed definitively"
  exit 1
fi
if [ "$unverified" -gt 0 ]; then
  echo "::warning::${unverified} base image pin check(s) could not be completed; no conclusion is being drawn about them"
  exit 2
fi

echo "all ${pins_found} base image pin(s) resolve from ${canonical_registry} and ${mirror_registry}"
