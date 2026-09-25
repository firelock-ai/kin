#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
#
# Rebuild published-0.7.21-stores.tar.gz, the fixture tests/store_upgrade.rs
# upgrades.
#
# The stores are written by the published 0.7.21 release, not by this build
# aged by hand, because what `kin upgrade` has to carry is exactly what that
# release wrote. The archive is downloaded from the v0.7.21 GitHub release and
# refused unless its SHA-256 is the digest pinned below for the platform.
#
# Two stores, packed as `clean/` and `dirty/`. Each holds imported Git history,
# a Git-only branch (`topic`), a native commit on `main`, a Kin branch
# `feature` with its own native commit, a review with a note, a thread and an
# approval, and a spec. `dirty/` also holds an uncommitted edit to
# web/lib.mjs that the published daemon admitted.
#
# Usage: published-0.7.21-stores.sh [output.tar.gz]
#   PUBLISHED_ARCHIVE=<path>  use an already downloaded archive; it is checked
#                             against the same pinned digest.
set -euo pipefail

VERSION=0.7.21
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) ASSET=kin-macos-aarch64.tar.gz
    SHA256=48336290b92e633235f393b6c811f498c99bc53f83fcd1056ff21eb9209466c7 ;;
  Darwin-x86_64) ASSET=kin-macos-x86_64.tar.gz
    SHA256=6a18d7c176ad9950ca6615d9e36f4681d5fa724955575dd969c657c4fc4e3c4e ;;
  Linux-aarch64) ASSET=kin-linux-aarch64.tar.gz
    SHA256=a4c5291c97fa53b0eb19aa490c489662e8516f74deedf149bcd60f05966b9f8e ;;
  Linux-x86_64) ASSET=kin-linux-x86_64.tar.gz
    SHA256=c6dd7caa442594487578adbd45ec794622d1fb1353bb32c4d542e62291cfdb0d ;;
  *) echo "no pinned $VERSION archive for $(uname -s)-$(uname -m)" >&2; exit 2 ;;
esac

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${1:-$HERE/published-$VERSION-stores.tar.gz}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/kin-published-stores.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

ARCHIVE="${PUBLISHED_ARCHIVE:-$WORK/$ASSET}"
if [ -z "${PUBLISHED_ARCHIVE:-}" ]; then
  curl -fsSL -o "$ARCHIVE" \
    "https://github.com/firelock-ai/kin/releases/download/v$VERSION/$ASSET"
fi
actual="$(sha256_of "$ARCHIVE")"
if [ "$actual" != "$SHA256" ]; then
  echo "$ARCHIVE has SHA-256 $actual, not the pinned $SHA256 of the $VERSION $ASSET" >&2
  exit 1
fi
mkdir -p "$WORK/release"
tar -xzf "$ARCHIVE" -C "$WORK/release"
BIN="$(dirname "$(find "$WORK/release" -type f -name kin -perm -u+x | head -1)")"
"$BIN/kin" --version | grep -q "^kin $VERSION" || {
  echo "the archive's kin does not report $VERSION" >&2
  exit 1
}

# Everything the published binary reads is isolated from this machine.
export KIN_DAEMON_BIN="$BIN/kin-daemon"
export KIN_DAEMON_AUTO_EMBED=0 KIN_EMBED_BACKEND=cpu KIN_VFS_DISABLE=1 KIN_DAEMON_DISABLE_LSP=1
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
export USER=kin-fixture LOGNAME=kin-fixture
export KIN_HOME="$WORK/home"
mkdir -p "$KIN_HOME"
unset KIN_MCP_REPO KIN_DIR KIN_DAEMON_URL || true
G="git -c core.hooksPath=/dev/null -c commit.gpgsign=false"

make_store() {
  local repo="$1" dirty="$2"
  mkdir -p "$repo/src" "$repo/pkg" "$repo/web" "$repo/shapes"
  (
    cd "$repo"
    $G init -q --initial-branch=main
    git config user.name "Kin Fixture"
    git config user.email "fixture@example.invalid"
    printf '[package]\nname = "fixture"\nversion = "0.1.0"\nedition = "2021"\n' > Cargo.toml
    printf 'mod util;\n\npub use util::helper;\n\npub fn entry(value: u32) -> u32 {\n    helper(value) + 1\n}\n' > src/lib.rs
    printf 'pub fn helper(value: u32) -> u32 {\n    value * 2\n}\n' > src/util.rs
    : > pkg/__init__.py
    printf 'def double(value):\n    return value * 2\n' > pkg/b.py
    printf 'export function triple(value) {\n  return value * 3;\n}\n' > web/lib.mjs
    printf '// nothing is declared in this file\n' > web/quiet.js
    $G add --all
    $G commit -q -m "Start the fixture"
    # A branch that exists only in Git, imported as it stands.
    $G branch topic
    printf 'from pkg.b import (\n    double,\n)\n\n\ndef run(value):\n    return double(value) + 1\n' > pkg/a.py
    printf "import { triple } from './lib.mjs';\n\nexport function main() {\n  return triple(2);\n}\n" > web/index.mjs
    printf 'module example.com/fixture\n\ngo 1.21\n' > go.mod
    printf 'package shapes\n\ntype Base struct{}\n\nfunc (b Base) Describe() string {\n\treturn "base"\n}\n\ntype Circle struct {\n\tBase\n\tRadius float64\n}\n\nfunc Use(c Circle) string {\n\treturn c.Describe()\n}\n' > shapes/shapes.go
    $G add --all
    $G commit -q -m "Call across files in four languages"

    "$BIN/kin" init >/dev/null 2>&1 || true
    "$BIN/kin" graph status >/dev/null
    # A native change on main.
    printf '\npub fn triple(value: u32) -> u32 {\n    value * 3\n}\n' >> src/util.rs
    "$BIN/kin" commit -m "Add a native triple helper" >/dev/null
    # A Kin branch with its own native change.
    "$BIN/kin" branch create feature >/dev/null
    "$BIN/kin" branch switch feature >/dev/null
    printf '\n\ndef quadruple(value):\n    return double(double(value))\n' >> pkg/b.py
    "$BIN/kin" commit -m "Add quadruple on the feature branch" >/dev/null
    "$BIN/kin" branch switch main >/dev/null
    review=$("$BIN/kin" review create --title "Review the feature branch" --base main \
      --head feature --description "native review that must survive the upgrade" \
      | sed -n 's/^Created review //p')
    "$BIN/kin" review note "$review" --body "A note recorded before the upgrade" >/dev/null
    "$BIN/kin" review discuss "$review" --body "A thread started before the upgrade" >/dev/null
    "$BIN/kin" review decide "$review" --state approved --comment "Approved before the upgrade" >/dev/null
    "$BIN/kin" spec create "An upgrade keeps every native record" >/dev/null
    if [ "$dirty" = dirty ]; then
      printf '\nexport function sextuple(value) {\n  return triple(value) * 2;\n}\n' >> web/lib.mjs
      "$BIN/kin" status >/dev/null || true
    fi
    "$BIN/kin" daemon stop >/dev/null
    grep -q '"created_under":11' .kin/kindb/hydration-semantics || {
      echo "the published store in $repo does not record hydration semantics 11" >&2
      exit 1
    }
  )
}

make_store "$WORK/pack/clean" clean
make_store "$WORK/pack/dirty" dirty
# KIN_HOME is this script's own scratch home, so this stops the supervisor the
# published build started for it and nothing any other home runs.
"$BIN/kin" daemon stop --all >/dev/null
if pgrep -f "$WORK/release/" >/dev/null; then
  echo "a daemon this script started is still running; nothing was packed" >&2
  exit 1
fi
for repo in "$WORK/pack/clean" "$WORK/pack/dirty"; do
  # What a daemon leaves behind at runtime is not part of the store, and
  # neither are Git's sample hooks, description and reflogs.
  rm -rf "$repo"/.kin/daemon.* "$repo"/.kin/daemon-footprint \
    "$repo"/.kin/daemon-boot-cost.json "$repo"/.kin/logs \
    "$repo"/.git/hooks "$repo"/.git/description "$repo"/.git/info "$repo"/.git/logs
done
# Owned by nobody in particular, so unpacking never needs this machine's user.
if tar --version 2>/dev/null | grep -q 'GNU tar'; then
  owner=(--owner=0 --group=0 --numeric-owner)
else
  owner=(--uid 0 --gid 0 --uname root --gname wheel)
fi
tar -czf "$OUT" -C "$WORK/pack" "${owner[@]}" clean dirty
echo "wrote $OUT ($(sha256_of "$OUT"))"
