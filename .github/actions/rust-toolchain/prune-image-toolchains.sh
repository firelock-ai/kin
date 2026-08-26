#!/usr/bin/env bash
# Remove the toolchains the runner image shipped, keeping only the ones this repository
# names, so the set of installed toolchains is a function of files we control.
#
# Why this exists. `Swatinem/rust-cache` builds half its key from `getRustVersions`, which
# hashes EVERY entry of `rustup toolchain list`, not the one the repository pins. Two
# ubuntu-latest jobs sixty-five seconds apart in run 32961965498 drew images carrying
# 1.97.1 and 1.98.0, hashed to 8374e8ea and 6ea01539 against the same Cargo.lock, and could
# not restore each other's cache. Nothing in this repository chose either version, and a
# restore key cannot fall back past that segment because it is a prefix of it. macOS was
# immune only because its image happened to carry one toolchain.
#
# The fix is not to drop the segment. `add-rust-environment-hash-key: false` gates BOTH
# halves of the key in that action's source, so turning it off left `Lockfiles considered`
# empty and the key frozen at its bare prefix, which is a worse defect than the one being
# fixed. That was measured on run 32976932775 and is why kin#1158 is a draft.
#
# So the unstable INPUT is removed instead. After this runs, every installed toolchain is
# one this repository named: the one the action was asked to install, and the channel in
# rust-toolchain.toml. Both come from files in the tree, so the hash comes from the tree.
#
# Usage: prune-image-toolchains.sh <resolved-toolchain> <preinstalled-list-file> [repo-pin]
#
# The preinstalled list must be captured BEFORE the install, because afterwards nothing can
# tell an image's toolchain from the one we just added. The repo pin is kept as well as the
# resolved toolchain because a job may install one and still shell out to the other:
# fuzz.yml installs a pinned nightly and then runs a bare `cargo install`, which
# rust-toolchain.toml resolves to the stable pin. Pruning that would trade a cache-key bug
# for a toolchain download on every fuzz run.
set -euo pipefail

resolved="${1:?resolved toolchain required}"
before_file="${2:?preinstalled list file required}"
repo_pin="${3:-}"

# A `rustup toolchain list` line is a name, optionally followed by ` (default)` or
# ` (override)`. Take the name and nothing else.
toolchain_names() { # <file> -> one bare name per line
  sed -e 's/[[:space:]]*(.*)$//' -e 's/[[:space:]]*$//' "$1" | grep -v '^$' || true
}

# A channel matches an installed name when the name IS the channel or is the channel plus a
# host triple. Substring matching would be wrong in both directions: `1.9` must not keep
# `1.96.0`, and `nightly` must not keep `nightly-2026-06-17` when only the dated one is
# named.
matches_channel() { # <installed-name> <channel>
  [ -n "$2" ] || return 1
  [ "$1" = "$2" ] || case "$1" in "$2"-*) return 0 ;; *) return 1 ;; esac
}

kept_by_this_repo() { # <installed-name>
  matches_channel "$1" "$resolved" && return 0
  matches_channel "$1" "$repo_pin" && return 0
  return 1
}

echo "resolved toolchain: $resolved"
echo "rust-toolchain.toml channel: ${repo_pin:-<none>}"
echo "preinstalled on this image:"
toolchain_names "$before_file" | sed 's/^/  /'

started=$SECONDS
removed=0
while IFS= read -r name; do
  [ -n "$name" ] || continue
  if kept_by_this_repo "$name"; then
    echo "keeping $name, named by this repository"
    continue
  fi
  echo "removing $name, shipped by the runner image"
  # Loud on purpose. A failed uninstall that is swallowed leaves a third toolchain in the
  # list, which reintroduces exactly this defect under a green run, and the next person
  # measures a cache miss with no cause in the log.
  if ! rustup toolchain uninstall "$name"; then
    echo "::error::could not uninstall $name; the cache key would carry a toolchain this repository never chose" >&2
    exit 1
  fi
  removed=$((removed + 1))
done < <(toolchain_names "$before_file")

# The assertion is the whole point, and it is what makes this a check rather than a hope.
# The original falsification was "wait for two jobs to draw different images and compare",
# which is luck, not a check. This holds on every run on every image: if what remains is a
# function of this repository's files, then two jobs on the same platform agree by
# construction and there is nothing left to wait for.
after_file="$(mktemp)"
trap 'rm -f "$after_file"' EXIT
rustup toolchain list > "$after_file"
echo "installed after pruning:"
toolchain_names "$after_file" | sed 's/^/  /'

straggler=""
while IFS= read -r name; do
  [ -n "$name" ] || continue
  kept_by_this_repo "$name" || straggler="$straggler $name"
done < <(toolchain_names "$after_file")

if [ -n "$straggler" ]; then
  echo "::error::toolchains this repository never named survived the prune:$straggler" >&2
  exit 1
fi

if ! toolchain_names "$after_file" | grep -q .; then
  echo "::error::pruning left no toolchain installed at all" >&2
  exit 1
fi

echo "pruned $removed image toolchain(s) in $((SECONDS - started))s; every remaining toolchain is named by this repository"
