# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
#
# The Linux leg of kin-release-preflight: Debian 12 (bookworm, glibc 2.36),
# which is the oldest distribution the published Linux archive must start on
# and the one whose loader refused v0.5.38's kin-vfs. node:22-bookworm is
# Debian 12 with node, git, gcc and binutils already present; the leg needs
# ps (procps) for the VFS proof's daemon-stop wait and a non-root user so the
# VFS negative control (a mode-000 file must be unreadable) can mean anything.
#
# pyright and typescript-language-server are pinned to the same versions
# scripts/ci-install-language-servers.sh installs in kin's acceptance.yml, and
# go through npm's default global prefix (/usr/local on this base image,
# already on PATH) rather than a project-local one, because the container
# leg's `docker run` in kin-release-preflight sets no PATH of its own: it
# inherits whatever this image puts there (FLOW_PATH, the host leg's hermetic
# allowlist, does not reach the container). gopls has no CI step to match
# (kin's acceptance.yml does not install it); its version below is this
# image's own pin. It is built in a throwaway Go stage and copied in as one
# static binary so the shipped image does not carry a full Go toolchain.
#
# Without these three on PATH the daemon this leg starts finds no language
# server for Python, TypeScript, or Go, and every enrichment-readiness check
# that needs one (magic-repro 10, 11, 16 among them) reads UNREADABLE instead
# of a verdict.
FROM golang:1.26-bookworm AS gopls-builder
# Pinned. Bump deliberately by choosing a new released version, never by
# re-resolving against @latest.
ARG GOPLS_VERSION=v0.23.0
RUN go install "golang.org/x/tools/gopls@${GOPLS_VERSION}"

FROM node:22-bookworm

ARG UID=1001
ARG GID=1001

RUN apt-get update \
    && apt-get install -y --no-install-recommends procps python3 python3-venv \
    && rm -rf /var/lib/apt/lists/*

# Pinned to the defaults scripts/ci-install-language-servers.sh in kin's
# acceptance.yml installs (KIN_CI_PYRIGHT_VERSION / KIN_CI_TS_LANGSERVER_VERSION
# / KIN_CI_TYPESCRIPT_VERSION, read 2026-09-18). Bump together with that
# script's defaults, never independently of them.
ARG PYRIGHT_VERSION=1.1.406
ARG TS_LANGSERVER_VERSION=5.0.0
ARG TYPESCRIPT_VERSION=5.9.3
RUN npm install -g --no-fund --no-audit --no-progress \
    "pyright@${PYRIGHT_VERSION}" \
    "typescript-language-server@${TS_LANGSERVER_VERSION}" \
    "typescript@${TYPESCRIPT_VERSION}"

COPY --from=gopls-builder /go/bin/gopls /usr/local/bin/gopls

RUN (getent group "$GID" >/dev/null || groupadd -o -g "$GID" dev) \
    && useradd -m -o -u "$UID" -g "$GID" -s /bin/bash dev

USER dev
WORKDIR /home/dev
ENV HOME=/home/dev
