#!/bin/sh
# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Firelock, LLC
set -e

# Ensure workspace directory exists with correct structure
mkdir -p /workspace/.kin/objects /workspace/.kin/refs

# Start kin-daemon with restart on clean exit
# The daemon may exit with code 0 on empty workspaces
while true; do
    echo "[entrypoint] Starting kin-daemon..."
    /usr/local/bin/kin-daemon "$@" || true
    echo "[entrypoint] kin-daemon exited, restarting in 5s..."
    sleep 5
done
