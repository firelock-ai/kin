#!/usr/bin/env bash
# Retry a cargo invocation when kin's private registry resets the connection
# during the TLS handshake, and never for any other reason.
#
# FIR-2950. Three CI shards died in under 200 ms with
# `[35] SSL connect error (Recv failure: Connection reset by peer)` while
# fetching the sparse index, before a single test ran, and in every case
# sibling shards starting the same second against the same registry resolved
# fine: main 33270307105 at 19:13:46Z, kin #1249 33277299552 at 21:55:58Z, and
# kin #1250 33284158820 at 00:48:46Z.
#
# Do NOT reach for `CARGO_NET_RETRY` or `[net] retry` here. Cargo does not
# classify curl 35 as retryable, measured on cargo 1.96.0 against a listener
# that resets during the handshake: default and `CARGO_NET_RETRY=5` each made
# exactly ONE connection attempt, while the same lever against an HTTP 500
# moved 4 attempts to 6. The lever works and does not cover this class, which
# is why the retry has to wrap the invocation rather than configure it.
#
# This retries a TRANSPORT failure that happens before the suite starts. It
# never tolerates a test failure or a compile error: any output that does not
# carry the needle is re-emitted verbatim and the original exit status is
# returned unchanged.
set -uo pipefail

NEEDLE='[35] SSL connect error'
ATTEMPTS="${REGISTRY_RETRY_ATTEMPTS:-3}"
BACKOFF="${REGISTRY_RETRY_BACKOFF_SECS:-3}"

if [ "$#" -eq 0 ]; then
  echo "usage: ${0##*/} <command> [args...]" >&2
  exit 64
fi

log="$(mktemp "${TMPDIR:-/tmp}/retry-registry.XXXXXX")"
trap 'rm -f "$log"' EXIT INT TERM

attempt=1
while :; do
  # STDOUT is left completely alone, because every caller here redirects it to a
  # file (`cargo metadata ... > metadata.json`, `cargo nextest list ... >
  # listing.json`). Merging stderr into it would write warnings into the JSON
  # and the parse would fail for a reason that has nothing to do with the
  # registry. Only stderr is captured, and it is re-emitted verbatim after.
  "$@" 2>"$log"
  rc=$?
  cat "$log" >&2

  if [ "$rc" -eq 0 ]; then
    exit 0
  fi

  if grep -qF -- "$NEEDLE" "$log" && [ "$attempt" -lt "$ATTEMPTS" ]; then
    echo "::warning title=Registry reset::attempt ${attempt} of ${ATTEMPTS} hit '${NEEDLE}' from the kin registry (FIR-2950); retrying in ${BACKOFF}s" >&2
    attempt=$((attempt + 1))
    sleep "$BACKOFF"
    continue
  fi

  # Either a real failure or a reset that outlived its retries. The output is
  # already on the log above; say which case this is and hand back the
  # command's own status so nothing is masked.
  if grep -qF -- "$NEEDLE" "$log"; then
    echo "::error title=Registry reset::the kin registry reset the connection on all ${ATTEMPTS} attempts (FIR-2950)" >&2
  fi
  exit "$rc"
done
