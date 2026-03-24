#!/usr/bin/env sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
#
# Kin installer — one command to install the full semantic development environment.
#
# Usage:
#   curl -fsSL https://kinlab.dev/install | sh
#
# Options (via env vars):
#   KIN_VERSION=0.1.0    Pin a specific version (default: latest)
#   KIN_DIR=~/.kin        Install directory (default: ~/.kin)
#   KIN_NO_SETUP=1        Skip interactive setup after install

set -eu

# ── Config ──────────────────────────────────────────────────────────────

KIN_DIR="${KIN_DIR:-$HOME/.kin}"
KIN_BIN="$KIN_DIR/bin"
KIN_LIB="$KIN_DIR/lib"
GITHUB_ORG="firelock-ai"
GITHUB_REPO="kin"
BASE_URL="https://github.com/$GITHUB_ORG/$GITHUB_REPO/releases"

# ── Helpers ─────────────────────────────────────────────────────────────

info() { printf '  \033[36m→\033[0m %s\n' "$*"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
err()  { printf '  \033[31m✗\033[0m %s\n' "$*" >&2; }
bold() { printf '\033[1m%s\033[0m' "$*"; }

detect_os() {
    case "$(uname -s)" in
        Linux*)  echo "linux" ;;
        Darwin*) echo "macos" ;;
        CYGWIN*|MINGW*|MSYS*) echo "windows" ;;
        *) err "Unsupported OS: $(uname -s)"; exit 1 ;;
    esac
}

detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)  echo "x86_64" ;;
        aarch64|arm64) echo "aarch64" ;;
        *) err "Unsupported architecture: $(uname -m)"; exit 1 ;;
    esac
}

has_cmd() { command -v "$1" >/dev/null 2>&1; }

# ── Detect platform ────────────────────────────────────────────────────

OS="$(detect_os)"
ARCH="$(detect_arch)"
TARGET="${OS}-${ARCH}"

printf '\n'
printf '  \033[1;36mKin Installer\033[0m\n'
printf '  Semantic development environment\n'
printf '\n'

info "Platform: $OS ($ARCH)"

# ── Resolve version ────────────────────────────────────────────────────

if [ -n "${KIN_VERSION:-}" ]; then
    VERSION="$KIN_VERSION"
    info "Version: $VERSION (pinned)"
else
    info "Fetching latest version..."
    if has_cmd curl; then
        VERSION=$(curl -fsSL "https://api.github.com/repos/$GITHUB_ORG/$GITHUB_REPO/releases/latest" | grep '"tag_name"' | sed 's/.*"v\(.*\)".*/\1/')
    elif has_cmd wget; then
        VERSION=$(wget -qO- "https://api.github.com/repos/$GITHUB_ORG/$GITHUB_REPO/releases/latest" | grep '"tag_name"' | sed 's/.*"v\(.*\)".*/\1/')
    else
        err "Neither curl nor wget found. Install one and retry."
        exit 1
    fi

    if [ -z "$VERSION" ]; then
        err "Could not determine latest version. Set KIN_VERSION manually."
        exit 1
    fi
    info "Version: $VERSION (latest)"
fi

# ── Download ────────────────────────────────────────────────────────────

ARCHIVE="kin-v${VERSION}-${TARGET}.tar.gz"
URL="$BASE_URL/download/v${VERSION}/${ARCHIVE}"

info "Downloading $ARCHIVE..."

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

if has_cmd curl; then
    curl -fsSL "$URL" -o "$TMPDIR/$ARCHIVE"
elif has_cmd wget; then
    wget -q "$URL" -O "$TMPDIR/$ARCHIVE"
fi

# ── Extract ─────────────────────────────────────────────────────────────

info "Installing to $KIN_DIR..."

mkdir -p "$KIN_BIN" "$KIN_LIB"

tar xzf "$TMPDIR/$ARCHIVE" -C "$TMPDIR"

# Move binaries
for bin in kin kin-vfs; do
    if [ -f "$TMPDIR/$bin" ]; then
        mv "$TMPDIR/$bin" "$KIN_BIN/$bin"
        chmod +x "$KIN_BIN/$bin"
    fi
done

# Move shim library
for lib in libkin_vfs_shim.so libkin_vfs_shim.dylib; do
    if [ -f "$TMPDIR/$lib" ]; then
        mv "$TMPDIR/$lib" "$KIN_LIB/$lib"
    fi
done

ok "Binaries installed"

# ── PATH setup ──────────────────────────────────────────────────────────

add_to_path() {
    local rc_file="$1"
    local line="export PATH=\"$KIN_BIN:\$PATH\""

    if [ -f "$rc_file" ] && grep -q "kin/bin" "$rc_file" 2>/dev/null; then
        return 0  # Already configured
    fi

    printf '\n# Kin\n%s\n' "$line" >> "$rc_file"
    ok "Added $KIN_BIN to PATH in $rc_file"
}

case "$OS" in
    macos)
        if [ -f "$HOME/.zshrc" ] || [ "$(basename "$SHELL")" = "zsh" ]; then
            add_to_path "$HOME/.zshrc"
        fi
        if [ -f "$HOME/.bashrc" ]; then
            add_to_path "$HOME/.bashrc"
        fi
        ;;
    linux)
        if [ -f "$HOME/.bashrc" ]; then
            add_to_path "$HOME/.bashrc"
        fi
        if [ -f "$HOME/.zshrc" ]; then
            add_to_path "$HOME/.zshrc"
        fi
        ;;
esac

# ── Verify ──────────────────────────────────────────────────────────────

export PATH="$KIN_BIN:$PATH"

if has_cmd "$KIN_BIN/kin"; then
    ok "kin $(\"$KIN_BIN/kin\" --version 2>/dev/null || echo 'installed')"
else
    err "Installation failed — kin binary not found"
    exit 1
fi

# ── Run setup ───────────────────────────────────────────────────────────

if [ "${KIN_NO_SETUP:-}" = "1" ]; then
    printf '\n'
    info "Skipping setup (KIN_NO_SETUP=1). Run 'kin setup' when ready."
else
    printf '\n'
    "$KIN_BIN/kin" setup
fi

printf '\n'
ok "Done! Restart your shell to get started."
printf '\n'
