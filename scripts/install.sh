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
#   KIN_REGISTRY_REPAIR=1 Explicitly repair safe registry modes to 0600

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
is_truthy() {
    normalized=$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]' | awk '{$1=$1};1')
    case "$normalized" in
        1|true|yes|on) return 0 ;;
        *) return 1 ;;
    esac
}

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

# ── Declare the one host tool Kin needs but does not install ──────────

# Installing Kin needs no git, and Kin reads a repository's Git history itself
# rather than shelling out for it. The host binary is still required in two
# places a first-run user reaches immediately: `kin setup` validates workspace
# MCP authority through git when it runs inside a Git repository, and adopting
# an existing project means committing it to Git first, which `kin init` asks
# for. Declaring that here beats letting the first real command fail on it.
if ! has_cmd git; then
    info 'git not found. Kin installs and runs without it, but `kin setup` inside a Git repository and adopting an existing project both require it.'
fi

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

# Download the archive and its per-artifact checksum. Interactive terminals get
# the downloader's live byte/percent meter for the large archive; piped and CI
# installs stay quiet. The checksum fetch remains quiet in both modes. The
# release workflow publishes "<archive>.sha256" next to every archive (shasum
# -a 256 format: "<hash>  <filename>"). Both downloads must succeed.
if has_cmd curl; then
    if [ -t 2 ]; then
        curl -fL "$URL" -o "$TMPDIR/$ARCHIVE"
    else
        curl -fsSL "$URL" -o "$TMPDIR/$ARCHIVE"
    fi
    # Tolerate a failed checksum fetch here so the explicit, friendly error
    # below fires (instead of a bare curl error under `set -e`).
    curl -fsSL "$CHECKSUM_URL" -o "$TMPDIR/$ARCHIVE.sha256" 2>/dev/null || true
elif has_cmd wget; then
    if [ -t 2 ]; then
        wget "$URL" -O "$TMPDIR/$ARCHIVE"
    else
        wget -q "$URL" -O "$TMPDIR/$ARCHIVE"
    fi
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

# Everything under $KIN_DIR must end owned by the user doing the install. GNU
# tar restores the uid/gid recorded in the archive when it runs as root, and
# release archives are built by CI under an unrelated uid, so a root install
# otherwise lands foreign-owned binaries and a foreign-owned projection shim in
# the user's own home. Kin then refuses to verify the shim it just installed
# ("managed config is not owned by the current user") and `kin doctor` reports
# the install ledger STALE on a perfectly good install.
#
# --no-same-owner is the fix, but it is not universal: busybox tar spells it -o
# and rejects the long option. Fall back to a plain extraction and repair the
# ownership directly, which is the only case where the chown has anything to do.
if ! tar --no-same-owner -xzf "$TMPDIR/$ARCHIVE" -C "$TMPDIR" 2>/dev/null; then
    tar xzf "$TMPDIR/$ARCHIVE" -C "$TMPDIR"
fi

# Find the extracted directory (archive contains a subdirectory)
EXTRACT_DIR=$(find "$TMPDIR" -maxdepth 1 -type d -name "kin-*" | head -1)
if [ -z "$EXTRACT_DIR" ]; then
    EXTRACT_DIR="$TMPDIR"
fi

# Only root can be handed foreign ownership by tar, and only root can repair it.
# Every file below is moved, not copied, so fixing the extracted tree here is
# what makes the installed tree caller-owned.
if [ "$(id -u)" = "0" ]; then
    chown -R "$(id -u):$(id -g)" "$EXTRACT_DIR" 2>/dev/null || true
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

# The notification identity is part of every macOS release contract. Validate
# its minimal launchable shape before replacing any installed binary so a
# malformed archive cannot leave a new CLI paired with an old notifier bundle.
if [ "$OS" = "macos" ]; then
    NOTIFIER_ROOT="$EXTRACT_DIR/KinNotifier.app"
    NOTIFIER_EXEC="$NOTIFIER_ROOT/Contents/MacOS/KinNotifier"
    NOTIFIER_PLIST="$NOTIFIER_ROOT/Contents/Info.plist"
    if [ -L "$NOTIFIER_ROOT" ] || [ ! -d "$NOTIFIER_ROOT" ]; then
        err "KinNotifier.app missing or unsafe in the downloaded macOS archive."
        err "No installed binary or notification bundle was replaced."
        exit 1
    fi
    # `test -f/-d` follows intermediate symlink components, so leaf checks
    # alone would accept `Contents -> Payload`. Walk the complete extracted
    # tree without following links and admit only real directories and regular
    # files before any live path is changed. FIFOs, devices, sockets, and every
    # symlink (including a directory ancestor) fail this boundary.
    if ! NOTIFIER_UNSAFE_ENTRY=$(find "$NOTIFIER_ROOT" ! \( -type d -o -type f \) -print -quit 2>/dev/null); then
        err "KinNotifier.app could not be inspected safely in the downloaded macOS archive."
        err "No installed binary or notification bundle was replaced."
        exit 1
    fi
    if [ -n "$NOTIFIER_UNSAFE_ENTRY" ]; then
        err "KinNotifier.app contains a symlink or special entry: $NOTIFIER_UNSAFE_ENTRY"
        err "No installed binary or notification bundle was replaced."
        exit 1
    fi
    if [ -L "$NOTIFIER_EXEC" ] || [ ! -f "$NOTIFIER_EXEC" ] || [ ! -s "$NOTIFIER_EXEC" ] || [ ! -x "$NOTIFIER_EXEC" ]; then
        err "KinNotifier.app/Contents/MacOS/KinNotifier is missing, unsafe, empty, or not executable."
        err "No installed binary or notification bundle was replaced."
        exit 1
    fi
    if [ -L "$NOTIFIER_PLIST" ] || [ ! -f "$NOTIFIER_PLIST" ] || [ ! -s "$NOTIFIER_PLIST" ]; then
        err "KinNotifier.app/Contents/Info.plist is missing, unsafe, or empty."
        err "No installed binary or notification bundle was replaced."
        exit 1
    fi
fi

# The freshly downloaded binary owns the registry-authority contract used by
# `kin doctor` and `kin update`. Run its content-free check before replacing
# any installed binary. Unsafe existing state is never silently chmodded or
# overwritten; the operator must explicitly repair it and rerun the installer.
chmod +x "$EXTRACT_DIR/kin"
if is_truthy "${KIN_REGISTRY_REPAIR:-}"; then
    REGISTRY_AUTHORITY_STATUS=0
    "$EXTRACT_DIR/kin" registry authority --fix --initialize || REGISTRY_AUTHORITY_STATUS=$?
else
    REGISTRY_AUTHORITY_STATUS=0
    "$EXTRACT_DIR/kin" registry authority --initialize || REGISTRY_AUTHORITY_STATUS=$?
fi
if [ "$REGISTRY_AUTHORITY_STATUS" -ne 0 ]; then
    err "Unsafe local registry authority blocks installation."
    err "No installed binary or registry authority file was replaced."
    err "Inspect the paths above. For permission-only drift, rerun with KIN_REGISTRY_REPAIR=1."
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

# Move the notification bundle if the archive carries it (macOS only). macOS
# reads a notification's sender name, icon, and grouping from the posting
# process's bundle; without this, Kin's notifications are credited to Script
# Editor. Replaced whole rather than merged so a stale executable can never be
# left inside a newer bundle.
HAVE_NOTIFIER=0
if [ -d "$EXTRACT_DIR/KinNotifier.app" ]; then
    rm -rf "$KIN_LIB/KinNotifier.app"
    mv "$EXTRACT_DIR/KinNotifier.app" "$KIN_LIB/KinNotifier.app"
    chmod +x "$KIN_LIB/KinNotifier.app/Contents/MacOS/KinNotifier" 2>/dev/null || true
    HAVE_NOTIFIER=1
fi

ok "Binaries installed (kin, kin-daemon)"

if [ "$HAVE_NOTIFIER" = "1" ]; then
    # Registering with LaunchServices is what lets the notification daemon
    # validate the bundle; an unregistered app is refused outright. Authorization
    # itself is NOT requested here: an unanswered prompt is recorded as a
    # permanent denial, so it must be raised interactively by `kin setup`.
    LSREGISTER="/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"
    [ -x "$LSREGISTER" ] && "$LSREGISTER" -f "$KIN_LIB/KinNotifier.app" >/dev/null 2>&1 || true
    ok "Notification identity installed (KinNotifier.app)"
elif [ "$OS" = "macos" ]; then
    # Every macOS release archive is supposed to carry the bundle. Without it
    # Kin still runs, but every notification is credited to Script Editor, and
    # that downgrade is invisible unless it is said out loud here.
    err "This archive carries no KinNotifier.app; notifications will post as Script Editor, not as Kin"
fi

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
    info "Filesystem projection (kin-vfs) not bundled in this archive. The core CLI and daemon are fully functional without it."
fi

# ── PATH setup ──────────────────────────────────────────────────────────

add_to_path() (
    rc_file="$1"
    line="export PATH=\"$KIN_BIN:\$PATH\""

    if [ -f "$rc_file" ] && grep -F -q "$KIN_BIN" "$rc_file" 2>/dev/null; then
        return 0  # Already configured
    fi

    printf '\n# Kin\n%s\n' "$line" >> "$rc_file"
    ok "Added $KIN_BIN to PATH in $rc_file"
)

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
    err "Installation failed: kin binary not found"
    exit 1
fi

# ── Run setup ───────────────────────────────────────────────────────────

if is_truthy "${KIN_NO_SETUP:-}"; then
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
