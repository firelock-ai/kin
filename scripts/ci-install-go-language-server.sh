#!/usr/bin/env bash
# Provision the Go toolchain and gopls the Go reference-enrichment proof needs.
#
# `crates/kin-daemon/tests/lsp_reference_enrichment.rs` runs gopls against a
# two-package module and asserts that a call through an interface is not a
# caller of the concrete method behind it. gopls loads every workspace through
# the `go` command, and without one it starts, answers `initialize`, and then
# answers every query with nothing ("go command required, not found"). On a
# runner whose image carried gopls and no `go`, the proof failed after polling a
# minute for an answer that could never come.
#
# So the job provisions both here, from pinned sources, rather than trusting
# whatever the runner happens to hold:
#
# - Go is pinned to one release and its archive is checked against the sha256
#   go.dev publishes for it. A tarball that does not match is refused.
# - gopls is pinned to one release and built with that Go. The module download
#   is verified by the Go checksum database, as every `go install` is.
#
# Unlike ci-install-language-servers.sh this fails the step when it cannot
# provision. The job it serves is the one that must actually run the Go proof,
# and a proof that skips there is a green that proved nothing. It also sets
# KIN_CI_GO_LANGUAGE_SERVER_INSTALLED, which makes the proof fail rather than
# skip if either binary is missing when it runs.
#
# The install is kept under the runner's tool cache, keyed by both pins and the
# architecture, and reused only when both binaries still answer with the pinned
# versions. That spares a persistent runner the download, and nothing about the
# result depends on it: a missing or damaged cache is installed again.
set -euo pipefail

GO_VERSION="1.27.1"
GOPLS_VERSION="v0.23.0"

fail() {
  echo "::error::$*" >&2
  exit 1
}

[ "$(uname -s)" = "Linux" ] || fail "the Go language server is provisioned for Linux runners only"
# The sha256 go.dev publishes for each archive, from https://go.dev/dl/?mode=json.
case "$(uname -m)" in
  aarch64 | arm64)
    arch=arm64
    go_sha256=3450b45a3f9ee8568792736a5c5e70a1f2e9b36c35a8f74958c03e51d7d92bec
    ;;
  x86_64 | amd64)
    arch=amd64
    go_sha256=63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445
    ;;
  *) fail "no pinned Go archive for architecture $(uname -m)" ;;
esac

for tool in curl sha256sum tar; do
  command -v "$tool" >/dev/null 2>&1 || fail "\`$tool\` is required to provision Go and is not on PATH"
done

# Bounded where GNU timeout exists, so a stalled mirror cannot hold the job to
# its own timeout; every Linux runner this serves ships coreutils.
TIMEOUT=()
if command -v timeout >/dev/null 2>&1 && timeout --version 2>/dev/null | grep -q GNU; then
  TIMEOUT=(timeout "${KIN_CI_GO_INSTALL_BOUND:-600}")
fi

cache_root="${RUNNER_TOOL_CACHE:-${RUNNER_TEMP:-/tmp}}/kin-go-language-server"
dir="$cache_root/go${GO_VERSION}-gopls-${GOPLS_VERSION}-linux-${arch}"
go="$dir/go/bin/go"
gopls="$dir/bin/gopls"

answers_pinned_versions() {
  [ -f "$dir/.complete" ] || return 1
  "$go" version 2>/dev/null | grep -q "^go version go${GO_VERSION} linux/${arch}\$" || return 1
  GOTOOLCHAIN=local "$gopls" version 2>/dev/null | grep -q "golang.org/x/tools/gopls ${GOPLS_VERSION}\$" || return 1
}

if answers_pinned_versions; then
  echo "reusing Go ${GO_VERSION} and gopls ${GOPLS_VERSION} at $dir"
else
  rm -rf "$dir"
  mkdir -p "$dir"
  archive="$dir/go${GO_VERSION}.linux-${arch}.tar.gz"
  url="https://go.dev/dl/go${GO_VERSION}.linux-${arch}.tar.gz"
  "${TIMEOUT[@]}" curl --fail --silent --show-error --location \
    --retry 3 --retry-delay 5 --retry-all-errors \
    --output "$archive" "$url" || fail "could not download $url"
  echo "${go_sha256}  ${archive}" | sha256sum --check --strict - \
    || fail "$url does not match the sha256 go.dev publishes for it"
  tar -C "$dir" -xzf "$archive"
  rm -f "$archive"

  # The module cache and build cache stay inside this install, so the build
  # neither reads nor writes anything the runner kept from another job.
  installed=""
  for attempt in 1 2 3; do
    if GOBIN="$dir/bin" GOPATH="$dir/gopath" GOMODCACHE="$dir/gopath/pkg/mod" \
      GOCACHE="$dir/gocache" GOTOOLCHAIN=local GOFLAGS=-modcacherw \
      "${TIMEOUT[@]}" "$go" install "golang.org/x/tools/gopls@${GOPLS_VERSION}"; then
      installed=yes
      break
    fi
    echo "gopls ${GOPLS_VERSION} build attempt $attempt of 3 failed" >&2
    sleep $((attempt * 10))
  done
  [ -n "$installed" ] || fail "could not build gopls ${GOPLS_VERSION} with Go ${GO_VERSION}"
  touch "$dir/.complete"
  answers_pinned_versions || fail "the provisioned go or gopls does not answer with its pinned version"
fi

"$go" version
GOTOOLCHAIN=local "$gopls" version

# Ahead of anything the runner already carries, so the proof runs against the
# pinned pair and never against a gopls the image shipped without its `go`.
echo "$dir/bin" >>"${GITHUB_PATH:-/dev/null}"
echo "$dir/go/bin" >>"${GITHUB_PATH:-/dev/null}"
{
  # A go.mod asking for a newer Go must not send the command off to download one.
  echo "GOTOOLCHAIN=local"
  # Read by the proof: set only after both binaries answered with their pins.
  echo "KIN_CI_GO_LANGUAGE_SERVER_INSTALLED=1"
} >>"${GITHUB_ENV:-/dev/null}"
echo "Go ${GO_VERSION} and gopls ${GOPLS_VERSION} are provisioned at $dir"
