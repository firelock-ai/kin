#!/usr/bin/env bash
# Bounded apt install for CI runners.
#
# A stalled package mirror used to hold a job until the runner's one-hour
# timeout, and on a merge-group run that timeout ejects the queue entry
# without marking the pull request. Every apt call here runs under `timeout`
# with per-fetch network bounds and is retried a fixed number of times, so a
# mirror stall fails the step in minutes with its own error line instead of
# consuming the whole job budget.
set -uo pipefail

if [ $# -eq 0 ]; then
  echo "usage: $0 <package>..." >&2
  exit 2
fi

APT_OPTS=(
  -o Acquire::http::Timeout=30
  -o Acquire::https::Timeout=30
  -o Acquire::Retries=3
  -o Dpkg::Use-Pty=0
)
UPDATE_BOUND=${CI_APT_UPDATE_BOUND:-120}
INSTALL_BOUND=${CI_APT_INSTALL_BOUND:-240}

# On the second attempt onward, stop asking the runner's Azure mirror. The
# hosted mirrorlist puts azure.archive.ubuntu.com first, and a stall there
# trickles bytes slowly enough that no per-fetch timeout fires; the primary
# archive answers the same packages. The rewrite is idempotent and only
# touches the mirror lines the runner image ships.
drop_azure_mirror() {
  local f
  for f in /etc/apt/apt-mirrors.txt /etc/apt/sources.list; do
    [ -f "$f" ] || continue
    sudo sed -i 's|http://azure\.archive\.ubuntu\.com/ubuntu|http://archive.ubuntu.com/ubuntu|g' "$f"
  done
  if [ -d /etc/apt/sources.list.d ]; then
    sudo find /etc/apt/sources.list.d -type f \( -name '*.list' -o -name '*.sources' \) \
      -exec sed -i 's|http://azure\.archive\.ubuntu\.com/ubuntu|http://archive.ubuntu.com/ubuntu|g' {} +
  fi
}

# The runner image preinstalls a Google Chrome apt source this script never needs, and it can
# ship as either sources.list.d/google-chrome.list (classic one-line form) or
# google-chrome.sources (DEB822);
# drop_azure_mirror below already treats both extensions as live on this runner fleet. When
# dl.google.com regenerates its Release file mid-fetch, every mirror serves a stale,
# hash-mismatched Packages.gz through whichever form is present, and no attempt or mirror swap
# below clears it, so match and drop it by content once before the first update. A hardcoded
# filename here (tried first, and it did not clear a live failure on kin#1651's own run) is a
# guess about which form the image ships; matching content is not.
chrome_matches=$(grep -l 'dl\.google\.com' /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources /etc/apt/sources.list 2>/dev/null || true)
if [ -n "$chrome_matches" ]; then
  echo "dropping the Chrome apt source(s), matched by content:" >&2
  printf '%s\n' "$chrome_matches" >&2
  printf '%s\n' "$chrome_matches" | xargs -r sudo rm -f
  echo "sources.list.d after removal:" >&2
  ls -la /etc/apt/sources.list.d/ >&2
else
  echo "no sources.list.d/sources.list file matched dl.google.com by content; listing what is there so the next attempt starts from a fact, not a guess:" >&2
  ls -la /etc/apt/sources.list.d/ >&2
  grep -r 'dl\.google\.com' /etc/apt >&2 2>/dev/null || echo "grep -r dl.google.com /etc/apt found nothing" >&2
fi

for attempt in 1 2 3; do
  if [ "$attempt" -ge 2 ]; then
    echo "apt attempt $attempt: dropping the azure mirror in favour of archive.ubuntu.com" >&2
    drop_azure_mirror
  fi
  if timeout "$UPDATE_BOUND" sudo apt-get "${APT_OPTS[@]}" update \
    && timeout "$INSTALL_BOUND" sudo apt-get "${APT_OPTS[@]}" install --yes "$@"; then
    exit 0
  fi
  echo "apt attempt $attempt of 3 failed for: $*" >&2
  sleep $((attempt * 10))
done

echo "::error::apt could not install after 3 bounded attempts: $*" >&2
exit 1
