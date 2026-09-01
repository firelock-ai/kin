#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

# Publish one already-tested local image to the development Artifact Registry.
# A main push owns the full commit tag. A manual cutover canary owns the separate
# gha-canary-<commit> namespace so a Cloud Build tag from the migration overlap
# cannot masquerade as proof that GitHub published its locally smoked bytes.

set -euo pipefail

if [ "$#" -ne 4 ]; then
  echo "usage: $0 <local-image> <registry-image> <40-hex-commit> <publish-tag>" >&2
  exit 2
fi

local_image="$1"
registry_image="${2%:}"
commit="$3"
publish_tag="$4"
verifier="${KIN_DEV_IMAGE_VERIFIER:-scripts/verify-container-build-info.sh}"

if [ -z "$local_image" ] || [ -z "$registry_image" ]; then
  echo "error: local and registry image names must not be empty" >&2
  exit 2
fi
if ! printf '%s\n' "$commit" | grep -Eq '^[0-9a-f]{40}$'; then
  echo "error: commit must be a full lowercase 40-hex id" >&2
  exit 2
fi
canary_tag="gha-canary-${commit}"
if [ "$publish_tag" != "$commit" ] && [ "$publish_tag" != "$canary_tag" ]; then
  echo "error: publish tag must be the full commit or its gha-canary-<commit> identity" >&2
  exit 2
fi

source_ref="${registry_image}:${publish_tag}"

inspect_digest() {
  local reference="$1"
  local output
  local attempt
  for attempt in 1 2 3 4 5; do
    if output="$(docker buildx imagetools inspect "$reference" \
      --format '{{.Manifest.Digest}}' 2>&1)"; then
      printf '%s\n' "$output"
      return 0
    fi
    if [ "$output" = "ERROR: ${reference}: not found" ]; then
      return 44
    fi
    if [ "$attempt" -eq 5 ]; then
      printf '%s\n' "$output" >&2
      echo "error: could not establish registry state for $reference" >&2
      return 1
    fi
    sleep $(( attempt * 2 ))
  done
}

if source_digest="$(inspect_digest "$source_ref")"; then
  # Never overwrite an exact identity. Cloud Build may already have moved the
  # legacy full-SHA tag during migration overlap, while a canary retry may see
  # its own earlier success. Both are verification, not proof this run pushed.
  bash "$verifier" \
    "${registry_image}@${source_digest}" "$commit"
  publication="verified_existing"
else
  inspect_status=$?
  if [ "$inspect_status" -ne 44 ]; then
    exit "$inspect_status"
  fi

  docker image inspect "$local_image" >/dev/null
  docker image tag "$local_image" "$source_ref"
  docker push "$source_ref"
  source_digest="$(inspect_digest "$source_ref")"
  publication="published"
fi

if ! printf '%s\n' "$source_digest" | grep -Eq '^sha256:[0-9a-f]{64}$'; then
  echo "error: $source_ref did not resolve to an immutable sha256 digest" >&2
  exit 1
fi

references=("$source_ref")

for reference in "${references[@]}"; do
  actual_digest="$(inspect_digest "$reference")"
  if [ "$actual_digest" != "$source_digest" ]; then
    echo "error: $reference resolved to $actual_digest, expected $source_digest" >&2
    exit 1
  fi
done

# Pull and execute by digest after the registry writes. This is the served
# Artifact Registry object, not merely the local image that passed smoke.
bash "$verifier" \
  "${registry_image}@${source_digest}" "$commit"

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  {
    echo "digest=$source_digest"
    echo "aliases_promoted=false"
    echo "reference=$source_ref"
    echo "publication=$publication"
    echo "readback=true"
    echo "embedded_sha=true"
  } >> "$GITHUB_OUTPUT"
fi

if [ "$publication" = published ]; then
  action="Published"
else
  action="Verified existing"
fi
echo "$action immutable development image: ${source_ref}"
echo "Published no mutable aliases; consume ${registry_image}@${source_digest}"
