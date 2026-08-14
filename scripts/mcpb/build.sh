#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
#
# Build the Claude Desktop extension bundle (.mcpb) that wraps the published
# @kinlab/kin-mcp launcher.
#
# Run this by hand. No release job packs the bundle yet, so nothing here is
# release evidence and nothing here may be cited as a shipped channel.
set -euo pipefail

here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${here}/../.." && pwd)"
icon_source="${repo_root}/assets/mcp/icon-512.png"
icon_target="${here}/icon.png"

if [ ! -f "$icon_source" ]; then
  echo "error: the extension icon is missing: ${icon_source}" >&2
  echo "manifest.json declares icon.png and Claude Desktop renders it on the extension card, so a bundle built without it ships an extension with no icon. Create that file as a 512x512 PNG with transparency, then rerun this script." >&2
  exit 1
fi

cp -- "$icon_source" "$icon_target"
echo "icon: ${icon_source} -> ${icon_target}"

cd -- "$here"
exec npx -y @anthropic-ai/mcpb pack
