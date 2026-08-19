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
# ejects a merge-group entry without marking the pull request it ejected.
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

mkdir -p "$PREFIX"

for attempt in 1 2 3; do
  if timeout "$INSTALL_BOUND" npm install \
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

echo "::warning::could not install language servers after 3 bounded attempts; the \
reference-enrichment proof will skip and say so per test" >&2
exit 0
