#!/usr/bin/env bash
# Provision the language servers the reference-enrichment proof needs.
#
# `crates/kin-daemon/tests/lsp_reference_enrichment.rs` starts a real language
# server and asserts that a cross-file call resolves to the right one of two
# same-named entities. Without a server on PATH those tests skip, so this script
# is what makes the proof actually run on a hosted runner.
#
# Three deliberate choices:
#
# Versions are pinned. An unpinned `npm install -g` resolves whatever the
# registry serves that morning, so a server-side behaviour change would land as
# a red gate on an unrelated pull request with no diff to explain it.
#
# The install is bounded and retried, for the same reason `ci-apt-install.sh`
# is: a stalled registry that holds a job to the runner's one-hour timeout
# ejects a merge-group entry without marking the pull request it ejected. The
# bound needs GNU timeout, and where a host has none the install runs unbounded
# and says so, because not installing at all is the worse failure; the block
# above the retry loop carries what that cost.
#
# A failure warns and exits 0 rather than failing the gate. A registry outage is
# not a defect in the change under review, and blocking the whole fleet on npm's
# availability trades one silent failure for a louder wrong one. The proof does
# not vanish quietly when that happens: this script emits a GitHub warning
# annotation that shows on the run summary, and each live test prints its own
# skip line naming the binary it looked for.
#
# Installs into a local prefix rather than the global one, so nothing depends on
# whether the runner's npm prefix is writable without sudo.
set -uo pipefail

# Pinned. Bump deliberately, never by re-resolving.
PYRIGHT_VERSION="${KIN_CI_PYRIGHT_VERSION:-1.1.406}"
TS_LANGSERVER_VERSION="${KIN_CI_TS_LANGSERVER_VERSION:-5.0.0}"
TYPESCRIPT_VERSION="${KIN_CI_TYPESCRIPT_VERSION:-5.9.3}"

PREFIX="${KIN_CI_LSP_PREFIX:-${RUNNER_TEMP:-/tmp}/kin-language-servers}"
INSTALL_BOUND="${KIN_CI_LSP_INSTALL_BOUND:-300}"

if ! command -v npm >/dev/null 2>&1; then
  echo "::warning::no npm on this runner, so the language-server enrichment proof will skip" >&2
  exit 0
fi

# The bound above needs GNU timeout, and a macOS runner ships none, so a bare
# `timeout` there is not an unbounded install: it is no install at all. On
# release-cut.yml run 34395244305, job "Preflight kin-macos-aarch64", all three
# attempts died on `line 46: timeout: command not found` between 19:28:56Z and
# 19:29:26Z, this script warned that "3 bounded attempts" had failed when none
# of them had started, and the leg then ran its whole acceptance suite with no
# language server. magic-repro case 16 (FIR-2524) reads that host as one where
# Kin can never produce a Python cross-file Calls edge, refuses to certify the
# absence on both surfaces exactly as it should, and the release cut failed on
# a correct answer three times in a row.
#
# So resolve the binary the way scripts/release-proof/bin/kin-release-preflight
# already does, and check for GNU rather than trusting the name: macOS carries
# no `timeout` at all today, but a BSD one appearing later would take different
# arguments and fail just as quietly.
TIMEOUT_BIN=""
for candidate in timeout gtimeout; do
  if command -v "$candidate" >/dev/null 2>&1 \
    && "$candidate" --version 2>/dev/null | grep -q GNU; then
    TIMEOUT_BIN="$(command -v "$candidate")"
    break
  fi
done

# With no GNU timeout, install unbounded rather than not at all. That is the
# same trade `bounded()` in kin-release-preflight already makes, and it is the
# right one here: an unbounded install risks holding the job, while no install
# guarantees the enrichment proof does not run. The warning says which happened
# so a reader never has to infer it, and ATTEMPT_KIND keeps the failure line
# below from claiming a bound that was never applied.
ATTEMPT_KIND=bounded
if [ -z "$TIMEOUT_BIN" ]; then
  ATTEMPT_KIND=unbounded
  echo "::warning::no GNU timeout on this runner, so the language-server install runs \
unbounded; install coreutils before this step to restore the bound" >&2
fi

bounded_npm() { # <npm args...>: run under GNU timeout when this host has one
  if [ -n "$TIMEOUT_BIN" ]; then
    "$TIMEOUT_BIN" "$INSTALL_BOUND" npm "$@"
  else
    npm "$@"
  fi
}

mkdir -p "$PREFIX"

for attempt in 1 2 3; do
  if bounded_npm install \
    --prefix "$PREFIX" \
    --no-fund --no-audit --no-progress \
    "pyright@${PYRIGHT_VERSION}" \
    "typescript-language-server@${TS_LANGSERVER_VERSION}" \
    "typescript@${TYPESCRIPT_VERSION}"; then
    BIN="$PREFIX/node_modules/.bin"
    # Both binaries have to be reachable, not just installed. An npm run that
    # exits zero having written a prefix nobody put on PATH is the success that
    # leaves the gap open, which is the same case `kin doctor --fix` re-probes
    # for rather than trusting an exit code.
    missing=""
    for binary in pyright-langserver typescript-language-server; do
      [ -x "$BIN/$binary" ] || missing="$missing $binary"
    done
    if [ -n "$missing" ]; then
      echo "::warning::npm succeeded but these servers are not executable:$missing" >&2
      exit 0
    fi
    echo "$BIN" >>"${GITHUB_PATH:-/dev/null}"
    # Only set after both binaries are proven executable above. The proof reads
    # it and turns a skip into a hard failure, so the tests cannot quietly stop
    # running on a runner that was provisioned for them: nextest captures a
    # passing test's stderr, so a skip reads as a fast pass and nobody notices.
    echo "KIN_CI_LANGUAGE_SERVERS_INSTALLED=1" >>"${GITHUB_ENV:-/dev/null}"
    echo "language servers installed at $BIN"
    "$BIN/typescript-language-server" --version
    exit 0
  fi
  echo "npm attempt $attempt of 3 failed for the language servers" >&2
  sleep $((attempt * 10))
done

echo "::warning::could not install language servers after 3 ${ATTEMPT_KIND} attempts; the \
reference-enrichment proof will skip and say so per test" >&2
exit 0
