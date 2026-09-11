#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

registry_url="${KINLAB_CARGO_REGISTRY_URL:-https://kinlab.ai}"
registry_url="${registry_url%/}"
# The kin cargo registry now REQUIRES this token to publish: the daemon fails
# closed (rejects publishes) when its KIN_REGISTRY_CARGO_TOKEN is unset, and the
# token sent here must match it. Reads remain open. Provided in CI via secret.
registry_token="${KINLAB_CARGO_TOKEN:-${KINLAB_TOKEN:-}}"
dry_run="${DRY_RUN:-0}"

# Version source of truth is Cargo.toml (cargo metadata), so a version-bump
# merge to main auto-publishes without a git tag. TAG_NAME / a tag-typed
# GITHUB_REF_NAME is accepted as an OPTIONAL consistency check: when invoked
# from a tag push it must match the Cargo version.
tag_name="${TAG_NAME:-}"
if [[ -z "$tag_name" && "${GITHUB_REF_TYPE:-}" == "tag" ]]; then
  tag_name="${GITHUB_REF_NAME:-}"
fi

expected_version=""
if [[ -n "$tag_name" ]]; then
  if [[ "$tag_name" != v* ]]; then
    echo "Release tag must start with 'v' (got: $tag_name)" >&2
    exit 1
  fi
  expected_version="${tag_name#v}"
fi

if command -v cargo >/dev/null 2>&1; then
  cargo_bin="$(command -v cargo)"
elif [[ -x "${HOME}/.cargo/bin/cargo" ]]; then
  cargo_bin="${HOME}/.cargo/bin/cargo"
else
  echo "cargo was not found in PATH or ~/.cargo/bin/cargo" >&2
  exit 1
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
metadata_json="$tmpdir/metadata.json"
"$cargo_bin" metadata --no-deps --format-version 1 >"$metadata_json"

resolve_version() {
  local package_name="$1"
  python3 - "$metadata_json" "$package_name" <<'PY'
import json
import sys

metadata_path, package_name = sys.argv[1], sys.argv[2]
with open(metadata_path, "r", encoding="utf-8") as fh:
    metadata = json.load(fh)

for package in metadata["packages"]:
    if package["name"] == package_name:
        print(package["version"])
        raise SystemExit(0)

raise SystemExit(f"package not found in cargo metadata: {package_name}")
PY
}

# Cargo sparse-index path for a crate name (1/2/3/4+ char prefix sharding).
index_path_for() {
  local name="$1"
  local len=${#name}
  case "$len" in
    1) printf '1/%s' "$name" ;;
    2) printf '2/%s' "$name" ;;
    3) printf '3/%s/%s' "${name:0:1}" "$name" ;;
    *) printf '%s/%s/%s' "${name:0:2}" "${name:2:2}" "$name" ;;
  esac
}

# Immutability guard. The kin cargo registry is append-only per (name, version):
# a published version's bytes must NEVER be replaced. Before packaging or POSTing
# we read the published sparse index and, if this exact version is already
# present, the publish is a no-op. This keeps the client from ever ATTEMPTING an
# overwrite POST — protection that does not depend on the server returning 409
# (the 409 path below stays as a backstop for the publish-race window). Reads are
# open, so this runs without the token. Returns 0 when the version is present.
registry_has_version() {
  local name="$1" version="$2"
  local url="${registry_url}/registry/cargo/$(index_path_for "$name")"
  local body code
  body="$(curl -sS -w $'\n%{http_code}' "$url" 2>/dev/null || true)"
  code="${body##*$'\n'}"
  body="${body%$'\n'*}"
  # 404 → crate not yet published (publish proceeds). Non-200/404 → treat as
  # unknown and let the publish proceed (the 409 backstop still protects bytes).
  [[ "$code" == "200" ]] || return 1
  grep -q "\"vers\":\"${version}\"" <<<"$body"
}

publish_package() {
  local package_name="$1"
  local package_version
  package_version="$(resolve_version "$package_name")"

  if [[ -n "$expected_version" && "$package_version" != "$expected_version" ]]; then
    echo "Version mismatch for $package_name: tag expects $expected_version but Cargo metadata resolved $package_version" >&2
    exit 1
  fi

  # Never attempt to overwrite an already-published, immutable version.
  if registry_has_version "$package_name" "$package_version"; then
    echo "$package_name@$package_version already present in registry index; skipping publish (immutable — no overwrite attempted)"
    return
  fi

  local crate_file="target/package/${package_name}-${package_version}.crate"
  local package_log="$tmpdir/${package_name}.package.log"
  echo "Packaging $package_name@$package_version"
  if ! "$cargo_bin" package -p "$package_name" --allow-dirty --no-verify 2>&1 | tee "$package_log"; then
    if [[ -f "$crate_file" ]]; then
      echo "cargo package reported a registry verification error after producing $crate_file; continuing with the packaged crate"
    else
      echo "cargo package failed for $package_name before producing $crate_file" >&2
      exit 1
    fi
  fi

  if [[ ! -f "$crate_file" ]]; then
    echo "Expected packaged crate not found: $crate_file" >&2
    exit 1
  fi

  if [[ "$dry_run" == "1" || "$dry_run" == "true" ]]; then
    echo "[dry-run] Would publish $package_name@$package_version to ${registry_url}"
    return
  fi

  local response_file="$tmpdir/${package_name}.response"
  local url="${registry_url}/registry/cargo/api/v1/crates/publish?name=${package_name}&version=${package_version}"
  local curl_args=(
    -sS
    -o "$response_file"
    -w "%{http_code}"
    -X POST "$url"
    -H "content-type: application/octet-stream"
    --data-binary "@${crate_file}"
  )

  if [[ -n "$registry_token" ]]; then
    curl_args+=(-H "authorization: Bearer ${registry_token}")
  fi

  local http_code
  http_code="$(curl "${curl_args[@]}")"

  case "$http_code" in
    200|201|204)
      echo "Published $package_name@$package_version"
      ;;
    409)
      echo "$package_name@$package_version is already published; continuing"
      ;;
    *)
      echo "Publish failed for $package_name@$package_version (HTTP $http_code)" >&2
      cat "$response_file" >&2 || true
      exit 1
      ;;
  esac
}

publish_package "kin-model"
