#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
set -e

# In GCS storage mode, no local workspace is needed — the daemon loads
# graph snapshots from GCS. In local mode, ensure the workspace exists.
if [ "${KIN_STORAGE}" != "gcs" ]; then
    mkdir -p /workspace/.kin/objects /workspace/.kin/refs
fi

# Use /tmp as a minimal .kin location for GCS mode (daemon needs a layout)
if [ "${KIN_STORAGE}" = "gcs" ]; then
    mkdir -p /tmp/kin-workspace/.kin/objects /tmp/kin-workspace/.kin/refs
    REPO_ARG="--repo /tmp/kin-workspace"
else
    REPO_ARG="--repo /workspace"
fi

# Start kin-daemon. Let K8s handle restarts via restartPolicy.
# Using exec so the daemon receives signals (SIGTERM) directly.
echo "[entrypoint] Starting kin-daemon (storage=${KIN_STORAGE:-local})..."
exec /usr/local/bin/kin-daemon ${REPO_ARG} "$@"
