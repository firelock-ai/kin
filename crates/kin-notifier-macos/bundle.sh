#!/bin/bash
# Assemble KinNotifier.app around an already-built KinNotifier binary.
#
# The bundle is the entire point of this crate. macOS reads a notification's
# sender name, icon, and Notification Center grouping from the posting process's
# bundle; without one the same code is credited to Script Editor. The bundle
# identifier is also what user notification settings are keyed to, so it is
# stable and must not change casually.
#
#   bundle.sh <path-to-KinNotifier-binary> <output-dir> [version]
#
# Signing is deliberately NOT done here: the release workflow signs and
# notarizes as one step across all macOS artifacts, and a locally assembled
# bundle is unsigned on purpose so it is never mistaken for a shippable one.
set -euo pipefail

BINARY="${1:?usage: bundle.sh <binary> <output-dir> [version]}"
OUTDIR="${2:?usage: bundle.sh <binary> <output-dir> [version]}"
VERSION="${3:-0.0.0}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP="$OUTDIR/KinNotifier.app"

test -f "$BINARY" || { echo "no such binary: $BINARY" >&2; exit 1; }

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BINARY" "$APP/Contents/MacOS/KinNotifier"
chmod 755 "$APP/Contents/MacOS/KinNotifier"
cp "$HERE/resources/Kin.icns" "$APP/Contents/Resources/Kin.icns"

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>
    <string>Kin</string>
    <key>CFBundleDisplayName</key>
    <string>Kin</string>
    <key>CFBundleIdentifier</key>
    <string>ai.kinlab.kin</string>
    <key>CFBundleExecutable</key>
    <string>KinNotifier</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>$VERSION</string>
    <key>CFBundleVersion</key>
    <string>$VERSION</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleIconFile</key>
    <string>Kin</string>
    <key>LSMinimumSystemVersion</key>
    <string>11.0</string>
    <!-- Agent app: no Dock tile, no menu bar. It holds the notification
         identity and is never launched by a person. -->
    <key>LSUIElement</key>
    <true/>
    <key>NSHumanReadableCopyright</key>
    <string>Copyright 2026 Firelock, LLC</string>
</dict>
</plist>
PLIST

plutil -lint "$APP/Contents/Info.plist" >/dev/null
echo "$APP"
