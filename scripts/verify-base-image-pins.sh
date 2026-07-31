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
# Drift is reported, not failed. The pinned digest going stale relative to the
# upstream tag is a maintenance signal a human acts on; the pinned digest
# becoming unreachable is the failure.

set -euo pipefail

dockerfile="${1:-Dockerfile}"
canonical_registry="docker.io"
mirror_registry="mirror.gcr.io"

if [ ! -f "$dockerfile" ]; then
  echo "::error::no Dockerfile at $dockerfile" >&2
  exit 1
fi

# Resolve one reference to the digest its registry reports, or print nothing.
resolve_digest() {
  docker buildx imagetools inspect "$1" --format '{{.Manifest.Digest}}' 2>/dev/null
}

summary() {
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    printf '%s\n' "$1" >> "$GITHUB_STEP_SUMMARY"
  fi
}

pins_found=0
failures=0
drifted=0

summary "## Base image pins"
summary ""
summary "| image | pinned digest | ${canonical_registry} | ${mirror_registry} | upstream tag |"
summary "| --- | --- | --- | --- | --- |"

# Read FROM lines from the Dockerfile itself so the pins cannot be checked
# against a second copy that drifts from the one the build uses.
while IFS= read -r from_line; do
  reference="$(printf '%s\n' "$from_line" | awk '{print $2}')"

  case "$reference" in
    *@sha256:*) ;;
    *)
      echo "::error::base image is not digest-pinned: ${reference}" >&2
      failures=$((failures + 1))
      continue
      ;;
  esac

  pins_found=$((pins_found + 1))
  pinned_digest="${reference##*@}"
  name_with_tag="${reference%@*}"
  repository="${name_with_tag%%:*}"
  tag="${name_with_tag##*:}"

  case "$repository" in
    "${canonical_registry}/"*)
      path="${repository#"${canonical_registry}/"}"
      ;;
    *)
      echo "::error::base image must name ${canonical_registry} explicitly so the mirror rewrite is reviewable: ${reference}" >&2
      failures=$((failures + 1))
      continue
      ;;
  esac

  canonical_state=fail
  if [ "$(resolve_digest "${canonical_registry}/${path}@${pinned_digest}")" = "$pinned_digest" ]; then
    canonical_state=ok
  else
    echo "::error::${canonical_registry} no longer serves ${path} at ${pinned_digest}" >&2
    failures=$((failures + 1))
  fi

  mirror_state=fail
  if [ "$(resolve_digest "${mirror_registry}/${path}@${pinned_digest}")" = "$pinned_digest" ]; then
    mirror_state=ok
  else
    echo "::error::${mirror_registry} no longer serves ${path} at ${pinned_digest}; the build has lost its second registry" >&2
    failures=$((failures + 1))
  fi

  upstream_digest="$(resolve_digest "${canonical_registry}/${path}:${tag}")"
  tag_state="unresolved"
  if [ -n "$upstream_digest" ]; then
    if [ "$upstream_digest" = "$pinned_digest" ]; then
      tag_state="current"
    else
      tag_state="moved to ${upstream_digest}"
      drifted=$((drifted + 1))
      echo "::warning::${path}:${tag} has moved past the pin; bump the Dockerfile digest to ${upstream_digest}"
    fi
  fi

  echo "${path}:${tag} pinned=${pinned_digest} ${canonical_registry}=${canonical_state} ${mirror_registry}=${mirror_state} tag=${tag_state}"
  summary "| \`${path}:${tag}\` | \`${pinned_digest}\` | ${canonical_state} | ${mirror_state} | ${tag_state} |"
done < <(grep -E '^FROM[[:space:]]' "$dockerfile")

if [ "$pins_found" -eq 0 ]; then
  echo "::error::no digest-pinned base image was found in ${dockerfile}; this check would pass an unpinned build" >&2
  exit 1
fi

summary ""
summary "${pins_found} pinned base image(s), ${drifted} behind the upstream tag."

if [ "$failures" -gt 0 ]; then
  echo "::error::${failures} base image pin check(s) failed" >&2
  exit 1
fi

echo "all ${pins_found} base image pin(s) resolve from ${canonical_registry} and ${mirror_registry}"
