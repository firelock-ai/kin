#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
#
# Fresh-cache, registry-only CONSUMER smoke.
#
# Proves that a brand-new downstream consumer can resolve, download, and build
# THIS crate purely from the published kin cargo registry:
#   * a throwaway consumer crate that lives outside this repo,
#   * a .cargo/config.toml carrying ONLY the registry alias — no [patch.*]
#     redirects to sibling checkouts,
#   * an EMPTY cargo cache (a fresh CARGO_HOME), so resolution + download are
#     exercised for real rather than served from a warm local cache.
#
# This is the guard that a *published* version is actually consumable, not just
# that it packaged. Registry reads are open, so no token is required.
#
# Usage:
#   registry-consumer-smoke.sh [VERSION]
#     VERSION  exact published version to require (e.g. 0.2.0). The consumer pins
#              `=VERSION`, so the build fails loudly if that exact version does
#              not resolve from the registry. Use this AFTER a publish to prove
#              the just-published version is consumable.
#     (omitted) or `latest` — pin `*` and let cargo resolve the newest published
#              version. Use this on PRs (before the new version is published) to
#              prove the registry is consumable from a clean cache.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

registry_url="${KINLAB_CARGO_REGISTRY_URL:-https://kinlab.ai}"
registry_url="${registry_url%/}"
registry_index="sparse+${registry_url}/registry/cargo/"

# Crate under test: explicit override wins, else the [package] name in Cargo.toml.
crate_name="${CRATE_NAME:-$(awk -F'"' '/^name[[:space:]]*=/{print $2; exit}' "$repo_root/Cargo.toml")}"
if [[ -z "$crate_name" ]]; then
  echo "could not determine crate name from $repo_root/Cargo.toml" >&2
  exit 1
fi

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

requested="${1:-latest}"
if [[ "$requested" == "latest" || -z "$requested" ]]; then
  req='*'
  mode_desc="latest published"
  # First-publish guard: in latest mode there may be no published version yet.
  # A 404 on the crate's index means nothing to consume — skip cleanly so the
  # very first PR is not red; the post-publish exact-version smoke covers it.
  index_status="$(curl -sS -o /dev/null -w '%{http_code}' \
    "${registry_url}/registry/cargo/$(index_path_for "$crate_name")" 2>/dev/null || echo 000)"
  if [[ "$index_status" == "404" ]]; then
    echo "Consumer smoke: '$crate_name' has no published version yet (index 404); skipping latest-mode smoke (post-publish exact-version smoke covers it)."
    exit 0
  fi
else
  req="=$requested"
  mode_desc="exact $requested"
fi

if command -v cargo >/dev/null 2>&1; then
  cargo_bin="$(command -v cargo)"
elif [[ -x "${HOME}/.cargo/bin/cargo" ]]; then
  cargo_bin="${HOME}/.cargo/bin/cargo"
else
  echo "cargo was not found in PATH or ~/.cargo/bin/cargo" >&2
  exit 1
fi

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

consumer="$workdir/consumer"
mkdir -p "$consumer/src" "$consumer/.cargo"

# Fresh, empty cargo cache: forces a real resolve + download from the registry.
export CARGO_HOME="$workdir/cargo-home"
mkdir -p "$CARGO_HOME"

cat >"$consumer/.cargo/config.toml" <<EOF
[registries.kin]
index = "$registry_index"
EOF

cat >"$consumer/Cargo.toml" <<EOF
[package]
name = "kin-registry-consumer-smoke"
version = "0.0.0"
edition = "2021"
publish = false

[dependencies]
$crate_name = { version = "$req", registry = "kin" }
EOF

cat >"$consumer/src/main.rs" <<'EOF'
// Declaring the dependency is enough: `cargo build` compiles every crate in the
// resolved graph, so the registry crate is fetched and built even without an
// explicit reference here.
fn main() {}
EOF

echo "Consumer smoke: building '$crate_name' ($mode_desc) from $registry_url"
echo "  fresh CARGO_HOME=$CARGO_HOME (empty cache)"
echo "  registry-only .cargo/config.toml (no [patch.*]):"
sed 's/^/    /' "$consumer/.cargo/config.toml"

(
  cd "$consumer"
  "$cargo_bin" generate-lockfile
  echo "Resolved $crate_name version:"
  "$cargo_bin" tree --quiet -p "$crate_name" --depth 0 2>/dev/null || true
  "$cargo_bin" build
)

echo "Consumer smoke OK: '$crate_name' ($mode_desc) resolves and builds from the published kin registry."
