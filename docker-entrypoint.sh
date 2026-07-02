#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
set -e

# Resolve the on-disk workspace that backs the daemon's Kin repo layout. Both
# storage modes need a real, writable `.kin/` tree: local mode keeps its graph
# objects there, and GCS mode still needs a valid repo layout on disk so
# sidecars and health checks never observe a half-initialized tree. Default to
# an in-image tmp path that a plain emptyDir volume can back identically in
# either mode; override with KIN_WORKSPACE_DIR (for example a volume mounted at
# /workspace on legacy deployments).
WORKSPACE_DIR="${KIN_WORKSPACE_DIR:-/tmp/kin-workspace}"

# Fail with an actionable message instead of dying on a bare mkdir when the
# resolved path is not writable for the container's runtime user — e.g. an
# image-root path such as /workspace with no volume mounted over it.
if ! mkdir -p "${WORKSPACE_DIR}/.kin" 2>/dev/null || [ ! -w "${WORKSPACE_DIR}/.kin" ]; then
    echo "[entrypoint] FATAL: workspace '${WORKSPACE_DIR}' is not writable for uid $(id -u)." >&2
    echo "[entrypoint] Mount a writable volume there, or set KIN_WORKSPACE_DIR to a writable path (an emptyDir-backed /tmp/kin-workspace is the default)." >&2
    exit 1
fi

# Materialize a real Kin repo layout. Re-init only when the tree is missing or
# incomplete so an existing repo on a persistent volume is never clobbered.
if [ ! -f "${WORKSPACE_DIR}/.kin/manifest.json" ] || [ ! -f "${WORKSPACE_DIR}/.kin/config.toml" ] || [ ! -f "${WORKSPACE_DIR}/.kin/HEAD" ] || [ ! -d "${WORKSPACE_DIR}/.kin/objects" ] || [ ! -f "${WORKSPACE_DIR}/.kin/kindb/graph.kndb" ]; then
    rm -rf "${WORKSPACE_DIR}/.kin"
    kin init "${WORKSPACE_DIR}"
fi

# Start kin-daemon. Let K8s handle restarts via restartPolicy. Using exec so the
# daemon is PID 1 and receives signals (SIGTERM) directly for a clean shutdown.
# kin-daemon parses --repo last-wins, so appending the resolved workspace keeps
# the prepared directory authoritative regardless of any --repo carried by the
# image CMD or pod args; configure the workspace via KIN_WORKSPACE_DIR instead.
echo "[entrypoint] Starting kin-daemon (storage=${KIN_STORAGE:-local}, workspace=${WORKSPACE_DIR})..."
exec /usr/local/bin/kin-daemon "$@" --repo "${WORKSPACE_DIR}"
