# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
#
# The Linux leg of kin-release-preflight: Debian 12 (bookworm, glibc 2.36),
# which is the oldest distribution the published Linux archive must start on
# and the one whose loader refused v0.5.38's kin-vfs. node:22-bookworm is
# Debian 12 with node, git, gcc and binutils already present; the leg needs
# ps (procps) for the VFS proof's daemon-stop wait and a non-root user so the
# VFS negative control (a mode-000 file must be unreadable) can mean anything.
FROM node:22-bookworm

ARG UID=1001
ARG GID=1001

RUN apt-get update \
    && apt-get install -y --no-install-recommends procps python3 python3-venv \
    && rm -rf /var/lib/apt/lists/*

RUN (getent group "$GID" >/dev/null || groupadd -o -g "$GID" dev) \
    && useradd -m -o -u "$UID" -g "$GID" -s /bin/bash dev

USER dev
WORKDIR /home/dev
ENV HOME=/home/dev
