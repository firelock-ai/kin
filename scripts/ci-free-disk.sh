#!/usr/bin/env bash
# Reclaim preinstalled runner disk before a build that will not otherwise fit.
#
# A GitHub-hosted ubuntu runner ships tens of gigabytes of toolchains for
# languages this repository does not build: the Android SDK and NDK, .NET, GHC
# and ghcup, the CodeQL bundles, Swift, PowerShell, and a set of preloaded
# Docker images. None of it is on any kin build path, and none of it is worth
# the two ways a full disk ends a job.
#
# Both ways are silent about their cause. `rust-lld` mmaps its output file, so
# an allocation that fails after `ftruncate` succeeded arrives as SIGBUS during
# the link and reads as a compiler crash: "ld terminated with signal 7 [Bus
# error]". If the disk instead runs out while the runner's own worker is
# writing its diagnostic log, that worker dies with an unhandled
# `System.IO.IOException: No space left on device` and the job is marked failed
# with no failed step in it.
#
# Printing `df` on both sides is the point as much as the removal is. A job
# that fills the disk again should say by how much it missed, in its own log,
# rather than leave the next reader to infer a cause from a linker signal.
#
# This never fails its caller. A removal that does not apply on some future
# image is not a reason to stop a build, and the `df` line after the sweep is
# what says whether the space actually arrived.
set -uo pipefail

# Refuse to touch a machine the fleet owns. `runs-on` for the callers here is
# `${{ vars.KIN_HEAVY_RUNNER || 'ubuntu-latest' }}`, so setting that variable to
# a self-hosted label would otherwise point these removals at a persistent host
# and delete another lane's toolchains along with the sweep's own targets.
if [ "${RUNNER_ENVIRONMENT:-}" != "github-hosted" ]; then
  echo "ci-free-disk: RUNNER_ENVIRONMENT=${RUNNER_ENVIRONMENT:-unset} is not github-hosted; nothing removed"
  exit 0
fi

if [ "$(uname -s)" != "Linux" ]; then
  echo "ci-free-disk: $(uname -s) is not Linux; nothing removed"
  exit 0
fi

# Bound every removal. The Android tree alone is millions of small files, and a
# stalled unlink on a degraded runner disk must cost a bounded number of
# seconds rather than the job's whole budget.
REMOVE_BOUND=${CI_FREE_DISK_REMOVE_BOUND:-120}

avail_kb() {
  df -Pk / | awk 'NR == 2 { print $4 }'
}

before_kb="$(avail_kb)"
echo "ci-free-disk: before"
df -h /

# Ordered by what these images actually carry, largest first, so the sweep has
# already paid for itself if a later entry is missing on a newer image.
for path in \
  /usr/local/lib/android \
  /opt/hostedtoolcache/CodeQL \
  /usr/share/dotnet \
  /opt/ghc \
  /usr/local/.ghcup \
  /usr/share/swift \
  /usr/local/share/powershell \
  /usr/local/share/chromium \
  /usr/local/lib/node_modules \
  /opt/az \
  /usr/local/share/boost; do
  [ -e "$path" ] || continue
  timeout "$REMOVE_BOUND" sudo rm -rf "$path"
  rc=$?
  case "$rc" in
    0) echo "ci-free-disk: removed $path" ;;
    124) echo "ci-free-disk: $path did not finish removing within ${REMOVE_BOUND}s; continuing" ;;
    *) echo "ci-free-disk: could not remove $path (rc=$rc); continuing" ;;
  esac
done

# The preloaded images are never pulled by anything in this repository's CI.
if command -v docker >/dev/null 2>&1; then
  timeout "$REMOVE_BOUND" sudo docker image prune --all --force >/dev/null 2>&1
  rc=$?
  case "$rc" in
    0) echo "ci-free-disk: pruned docker images" ;;
    124) echo "ci-free-disk: docker prune did not finish within ${REMOVE_BOUND}s; continuing" ;;
    *) echo "ci-free-disk: could not prune docker images (rc=$rc); continuing" ;;
  esac
fi

after_kb="$(avail_kb)"
echo "ci-free-disk: after"
df -h /

if [ -n "$before_kb" ] && [ -n "$after_kb" ]; then
  awk -v b="$before_kb" -v a="$after_kb" \
    'BEGIN { printf "ci-free-disk: reclaimed %.1f GiB (%.1f GiB free before, %.1f GiB free after)\n", (a - b) / 1048576, b / 1048576, a / 1048576 }'
fi

exit 0
