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

KIN_DIR="${WORKSPACE_DIR}/.kin"

# Paths every layout version creates. HEAD, objects/ and kindb/graph.kndb were
# git-shaped artifacts of the pre-authority layout and are NOT produced by a
# current `kin init`, so testing for them was unconditionally true and turned the
# branch below into an unconditional wipe on every start. These four are present
# in both the pre-authority and the current layout, so an existing repository of
# either vintage is left alone and the daemon decides whether it can open it.
layout_is_materialized() {
    [ -f "${KIN_DIR}/manifest.json" ] \
        && [ -f "${KIN_DIR}/config.toml" ] \
        && [ -f "${KIN_DIR}/version" ] \
        && [ -d "${KIN_DIR}/kindb" ]
}

# Refuse to delete a tree that has a filesystem mounted inside it. The registry
# pod mounts its published-crates volume at .kin/packages, and `rm -rf` unlinks
# the volume's contents before it fails EBUSY on the mount point itself, so the
# destructive path loses data first and crashloops second.
kin_dir_contains_mount() {
    [ -r /proc/self/mountinfo ] || return 1
    while read -r _ _ _ _ mount_point _; do
        case "${mount_point}" in
            "${KIN_DIR}" | "${KIN_DIR}"/*) return 0 ;;
        esac
    done < /proc/self/mountinfo
    return 1
}

# Materialize a real Kin repo layout. Re-init only when the tree is missing or
# incomplete so an existing repo on a persistent volume is never clobbered.
if ! layout_is_materialized; then
    if kin_dir_contains_mount; then
        echo "[entrypoint] FATAL: '${KIN_DIR}' is not a materialized Kin layout, but a filesystem is mounted inside it." >&2
        echo "[entrypoint] Refusing to re-initialize, because that deletes the mounted volume's contents before it fails on the mount point." >&2
        echo "[entrypoint] Prepare the repository before anything is mounted under .kin, or mount that volume outside the repository." >&2
        exit 1
    fi
    rm -rf "${KIN_DIR}"
    kin init "${WORKSPACE_DIR}"
fi

# Start kin-daemon. Let K8s handle restarts via restartPolicy. Using exec so the
# daemon is PID 1 and receives signals (SIGTERM) directly for a clean shutdown.
# kin-daemon parses --repo last-wins, so appending the resolved workspace keeps
# the prepared directory authoritative regardless of any --repo carried by the
# image CMD or pod args; configure the workspace via KIN_WORKSPACE_DIR instead.
echo "[entrypoint] Starting kin-daemon (storage=${KIN_STORAGE:-local}, workspace=${WORKSPACE_DIR})..."
exec /usr/local/bin/kin-daemon "$@" --repo "${WORKSPACE_DIR}"
