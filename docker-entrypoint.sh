#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
set -e

# In GCS storage mode, no local workspace is needed — the daemon loads
# graph snapshots from GCS. In local mode, ensure the workspace exists.
if [ "${KIN_STORAGE}" != "gcs" ]; then
    mkdir -p /workspace/.kin/objects /workspace/.kin/refs
fi

# In GCS mode the daemon still needs a real Kin repo layout so sidecars and
# health checks do not inherit a half-initialized `.kin/` tree.
if [ "${KIN_STORAGE}" = "gcs" ]; then
    mkdir -p /tmp/kin-workspace
    if [ ! -f /tmp/kin-workspace/.kin/manifest.json ] || [ ! -f /tmp/kin-workspace/.kin/config.toml ] || [ ! -f /tmp/kin-workspace/.kin/HEAD ] || [ ! -d /tmp/kin-workspace/.kin/objects ] || [ ! -f /tmp/kin-workspace/.kin/kindb/graph.kndb ]; then
        rm -rf /tmp/kin-workspace/.kin
        kin init /tmp/kin-workspace
    fi
    REPO_ARG="--repo /tmp/kin-workspace"
else
    REPO_ARG="--repo /workspace"
fi

# Start kin-daemon. Let K8s handle restarts via restartPolicy.
# Using exec so the daemon receives signals (SIGTERM) directly.
echo "[entrypoint] Starting kin-daemon (storage=${KIN_STORAGE:-local})..."
exec /usr/local/bin/kin-daemon ${REPO_ARG} "$@"
