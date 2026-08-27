#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
guard="${repo_root}/scripts/check-docker-daemon-features.sh"
fixture_dir="$(mktemp -d)"
trap 'rm -rf "${fixture_dir}"' EXIT

"${guard}" "${repo_root}/Dockerfile" >/dev/null

sed 's/--features kin-daemon\/gcs,kin-daemon\/firestore/--features kin-daemon\/gcs/g' \
  "${repo_root}/Dockerfile" >"${fixture_dir}/gcs-only.Dockerfile"
if "${guard}" "${fixture_dir}/gcs-only.Dockerfile" >/dev/null 2>&1; then
  echo "docker feature contract test: gcs-only mutant escaped" >&2
  exit 1
fi

sed 's/--features kin-daemon\/gcs,kin-daemon\/firestore/--features kin-daemon\/firestore/g' \
  "${repo_root}/Dockerfile" >"${fixture_dir}/firestore-only.Dockerfile"
if "${guard}" "${fixture_dir}/firestore-only.Dockerfile" >/dev/null 2>&1; then
  echo "docker feature contract test: firestore-only mutant escaped" >&2
  exit 1
fi

echo "docker feature contract tests: PASS"
