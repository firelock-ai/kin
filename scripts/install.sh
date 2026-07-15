#!/usr/bin/env sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
#
# Kin installer — one command to install the full semantic development environment.
#
# Usage:
#   curl -fsSL https://get.kinlab.dev/install | sh
#
# Options (via env vars):
#   KIN_VERSION=0.1.0    Pin a specific version (default: latest)
#   KIN_HOME=~/.kin       Install directory (preferred; default: ~/.kin)
#   KIN_DIR=~/.kin        Install directory compatibility alias
#   KIN_NO_SETUP=1        Skip interactive setup after install

set -eu

# ── Config ──────────────────────────────────────────────────────────────

KIN_DIR="${KIN_HOME:-${KIN_DIR:-$HOME/.kin}}"
KIN_BIN="$KIN_DIR/bin"
KIN_LIB="$KIN_DIR/lib"
export KIN_HOME="$KIN_DIR"
export KIN_DIR="$KIN_DIR"
GITHUB_ORG="firelock-ai"
GITHUB_REPO="kin"
# Override KIN_BASE_URL to install from a mirror or a local `file://` path
# (offline/airgapped installs and CI smoke tests).
BASE_URL="${KIN_BASE_URL:-https://github.com/$GITHUB_ORG/$GITHUB_REPO/releases}"

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

# ── Detect an existing install (reinstall / upgrade) ──────────────────

PREVIOUS_VERSION=""
if [ -x "$KIN_BIN/kin" ]; then
    PREVIOUS_VERSION=$("$KIN_BIN/kin" --version 2>/dev/null | awk '{print $2}')
    if [ -n "$PREVIOUS_VERSION" ]; then
        info "Existing install found: kin $PREVIOUS_VERSION (will be replaced)"
    else
        info "Existing install found in $KIN_DIR (will be replaced)"
    fi
fi

# ── Resolve version ────────────────────────────────────────────────────

if [ -n "${KIN_VERSION:-}" ]; then
    VERSION="$KIN_VERSION"
    info "Version: $VERSION (pinned)"
else
    info "Fetching latest version..."
    # Resolve the latest tag via the `releases/latest` REDIRECT
    # (Location -> .../releases/tag/vX.Y.Z) instead of api.github.com, whose
    # 60-requests/hour ANONYMOUS rate limit is trivially hit from a shared,
    # NAT'd, corporate, or CI IP and returns 403.
    LATEST_URL="https://github.com/$GITHUB_ORG/$GITHUB_REPO/releases/latest"
    if has_cmd curl; then
        RESOLVED=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "$LATEST_URL")
    elif has_cmd wget; then
        RESOLVED=$(wget -q -S -O /dev/null "$LATEST_URL" 2>&1 | sed -n 's/.*[Ll]ocation: *//p' | tail -1)
    else
        err "Neither curl nor wget found. Install one and retry."
        exit 1
    fi
    VERSION=$(printf '%s' "$RESOLVED" | sed -n 's#.*/releases/tag/v\([^/[:space:]]*\).*#\1#p')

    if [ -z "$VERSION" ]; then
        err "Could not determine latest version. Set KIN_VERSION manually."
        exit 1
    fi
    info "Version: $VERSION (latest)"
fi

# ── Download ────────────────────────────────────────────────────────────

ARCHIVE="kin-${TARGET}.tar.gz"
URL="$BASE_URL/download/v${VERSION}/${ARCHIVE}"
CHECKSUM_URL="${URL}.sha256"

info "Downloading $ARCHIVE..."

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

# Download the archive and its per-artifact checksum. The release workflow
# publishes "<archive>.sha256" next to every archive (shasum -a 256 format:
# "<hash>  <filename>"). Both downloads must succeed.
if has_cmd curl; then
    curl -fsSL "$URL" -o "$TMPDIR/$ARCHIVE"
    # Tolerate a failed checksum fetch here so the explicit, friendly error
    # below fires (instead of a bare curl error under `set -e`).
    curl -fsSL "$CHECKSUM_URL" -o "$TMPDIR/$ARCHIVE.sha256" 2>/dev/null || true
elif has_cmd wget; then
    wget -q "$URL" -O "$TMPDIR/$ARCHIVE"
    wget -q "$CHECKSUM_URL" -O "$TMPDIR/$ARCHIVE.sha256" 2>/dev/null || true
fi

# ── Verify checksum ───────────────────────────────────────────────────

if [ ! -s "$TMPDIR/$ARCHIVE.sha256" ]; then
    err "Could not download checksum file: $CHECKSUM_URL"
    err "Refusing to install an unverified download. Aborting."
    exit 1
fi

EXPECTED=$(cut -d' ' -f1 "$TMPDIR/$ARCHIVE.sha256")
if [ -z "$EXPECTED" ]; then
    err "Checksum file was empty or malformed: $CHECKSUM_URL"
    err "Refusing to install an unverified download. Aborting."
    exit 1
fi

if has_cmd shasum; then
    ACTUAL=$(shasum -a 256 "$TMPDIR/$ARCHIVE" | cut -d' ' -f1)
elif has_cmd sha256sum; then
    ACTUAL=$(sha256sum "$TMPDIR/$ARCHIVE" | cut -d' ' -f1)
else
    err "No SHA-256 tool (shasum or sha256sum) found."
    err "Cannot verify the download integrity. Install one and retry. Aborting."
    exit 1
fi

if [ "$ACTUAL" != "$EXPECTED" ]; then
    err "SHA-256 checksum mismatch!"
    err "Expected: $EXPECTED"
    err "Got:      $ACTUAL"
    err "The download may be corrupted or tampered with. Aborting."
    exit 1
fi
ok "SHA-256 checksum verified"

# ── Extract ─────────────────────────────────────────────────────────────

info "Installing to $KIN_DIR..."

mkdir -p "$KIN_BIN" "$KIN_LIB"

tar xzf "$TMPDIR/$ARCHIVE" -C "$TMPDIR"

# Find the extracted directory (archive contains a subdirectory)
EXTRACT_DIR=$(find "$TMPDIR" -maxdepth 1 -type d -name "kin-*" | head -1)
if [ -z "$EXTRACT_DIR" ]; then
    EXTRACT_DIR="$TMPDIR"
fi

# kin-daemon is mandatory — `kin status`/`kin search` and the MCP server all
# require it. Assert it is present in the extracted archive BEFORE moving
# anything, so a daemon-less archive (e.g. a stale build) aborts cleanly instead
# of leaving a half-installed, daemon-less environment.
if [ ! -f "$EXTRACT_DIR/kin-daemon" ]; then
    err "kin-daemon missing from the downloaded archive."
    err "kin status/search and the MCP server require it. Refusing a daemon-less install. Aborting."
    exit 1
fi

# Move binaries. kin-daemon is mandatory (asserted above); kin-vfs is the
# optional filesystem-projection client.
HAVE_VFS=0
for bin in kin kin-daemon kin-vfs; do
    if [ -f "$EXTRACT_DIR/$bin" ]; then
        mv "$EXTRACT_DIR/$bin" "$KIN_BIN/$bin"
        chmod +x "$KIN_BIN/$bin"
        [ "$bin" = "kin-vfs" ] && HAVE_VFS=1
    fi
done

# Move the projection shim library if the archive bundled it (Linux .so /
# macOS .dylib). It is consumed by the shell hooks via $KIN_DIR/lib.
HAVE_SHIM=0
for lib in libkin_vfs_shim.so libkin_vfs_shim.dylib; do
    if [ -f "$EXTRACT_DIR/$lib" ]; then
        mv "$EXTRACT_DIR/$lib" "$KIN_LIB/$lib"
        HAVE_SHIM=1
    fi
done

ok "Binaries installed (kin, kin-daemon)"

if [ "$HAVE_VFS" = "1" ] && [ "$HAVE_SHIM" = "1" ]; then
    # The release archive can contain a projection built for a different libc
    # than the host. In particular, the static-musl Kin core runs on Alpine,
    # while today's kin-vfs and shim are glibc-linked. Test the installed CLI
    # before claiming the optional projection is usable, and do not leave a
    # command behind that the host loader cannot execute.
    if "$KIN_BIN/kin-vfs" --help >/dev/null 2>&1; then
        ok "Filesystem projection installed (kin-vfs + shim)"
    else
        rm -f "$KIN_BIN/kin-vfs" \
            "$KIN_LIB/libkin_vfs_shim.so" \
            "$KIN_LIB/libkin_vfs_shim.dylib"
        info "Filesystem projection is unavailable on this platform; core CLI and daemon are fully functional without it."
    fi
else
    info "Filesystem projection (kin-vfs) not bundled in this archive — core CLI and daemon are fully functional without it."
fi

# ── PATH setup ──────────────────────────────────────────────────────────

add_to_path() {
    local rc_file="$1"
    local line="export PATH=\"$KIN_BIN:\$PATH\""

    if [ -f "$rc_file" ] && grep -F -q "$KIN_BIN" "$rc_file" 2>/dev/null; then
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
    INSTALLED_VERSION=$("$KIN_BIN/kin" --version 2>/dev/null | awk '{print $2}')
    if [ -n "$PREVIOUS_VERSION" ] && [ -n "$INSTALLED_VERSION" ] && [ "$PREVIOUS_VERSION" != "$INSTALLED_VERSION" ]; then
        ok "kin upgraded: $PREVIOUS_VERSION → $INSTALLED_VERSION"
    else
        ok "kin ${INSTALLED_VERSION:-installed}"
    fi
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
    # Setup is a best-effort post-install convenience — the binaries are already
    # installed and verified above, so a non-zero exit from `kin setup` (e.g. no
    # agent clients to configure on a bare CI/Docker host) must NOT fail the
    # install under `set -e`.
    set +e
    # When piped (curl | sh), stdin is consumed by the pipe.
    # Reopen /dev/tty so the interactive wizard can read keyboard input.
    if [ -t 0 ]; then
        # Already in a TTY — run directly
        "$KIN_BIN/kin" setup
    elif [ -e /dev/tty ] && ( : < /dev/tty ) 2>/dev/null; then
        # Piped but a usable controlling TTY is available — read keyboard input
        # from it. The `( : < /dev/tty )` probe confirms the device can actually
        # be OPENED — on CI/Docker /dev/tty often exists but has no controlling
        # terminal, so opening it errors ("cannot open /dev/tty") and the bare
        # `[ -e /dev/tty ]` check is not enough. The probe runs in a SUBSHELL:
        # a redirection failure on the `:` special built-in exits its shell, so
        # in a bare brace group it would terminate the whole non-interactive
        # installer (POSIX dash) before the fallback below can run.
        "$KIN_BIN/kin" setup < /dev/tty
    else
        # No usable TTY (CI, Docker, piped without a controlling terminal) —
        # run non-interactive so the install never exits non-zero here.
        "$KIN_BIN/kin" setup --no-interactive
    fi
    set -e
fi

printf '\n'
ok "Done! Restart your shell to get started."
printf '\n'
