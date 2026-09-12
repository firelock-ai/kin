#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
#
# Build a local Kin MCPB candidate from the published-package topology. The
# source manifest is a template: this script derives the bundle version from
# the two lockstep npm packages and pins the launcher to that exact version.
#
# This is intentionally a manual candidate builder. It does not publish an
# MCPB, create a release asset, or prove that its target npm/native release is
# available yet.
set -euo pipefail

here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${here}/../.." && pwd)"
icon_source="${repo_root}/assets/mcp/icon-512.png"
mcp_package="${repo_root}/packages/kin-mcp/package.json"
kin_package="${repo_root}/packages/kin/package.json"
bundle="${KIN_MCPB_OUTPUT:-${here}/kin.mcpb}"
stage="$(mktemp -d "${TMPDIR:-/tmp}/kin-mcpb.XXXXXX")"

cleanup() {
  rm -rf -- "$stage"
}
trap cleanup EXIT

if [ ! -f "$icon_source" ]; then
  echo "error: the extension icon is missing: ${icon_source}" >&2
  exit 1
fi

version="$({
  node - "$mcp_package" "$kin_package" <<'NODE'
const fs = require('node:fs');
const [mcpPackagePath, kinPackagePath] = process.argv.slice(2);
const mcpPackage = JSON.parse(fs.readFileSync(mcpPackagePath, 'utf8'));
const kinPackage = JSON.parse(fs.readFileSync(kinPackagePath, 'utf8'));
if (typeof mcpPackage.version !== 'string' || typeof kinPackage.version !== 'string') {
  throw new Error('Kin MCPB package version is not a string');
}
if (mcpPackage.version !== kinPackage.version) {
  throw new Error(`@kinlab/kin-mcp ${mcpPackage.version} does not match @kinlab/kin ${kinPackage.version}`);
}
if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(mcpPackage.version)) {
  throw new Error(`unsupported package version ${mcpPackage.version}`);
}
process.stdout.write(mcpPackage.version);
NODE
})"

mkdir -p "$stage/server"
cp -- "$icon_source" "$stage/icon.png"
cp -- "$here/server/index.js" "$stage/server/index.js"

node - "$here/manifest.json" "$stage/manifest.json" "$stage/release-identity.json" "$version" <<'NODE'
const fs = require('node:fs');
const [templatePath, manifestPath, identityPath, version] = process.argv.slice(2);
const manifest = JSON.parse(fs.readFileSync(templatePath, 'utf8'));
if (manifest.version !== '0.0.0') {
  throw new Error(`MCPB source manifest must remain the 0.0.0 template, found ${manifest.version}`);
}
manifest.version = version;
fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
fs.writeFileSync(identityPath, `${JSON.stringify({
  schema: 'kin.mcpb.package-identity.v1',
  launcher: `@kinlab/kin-mcp@${version}`,
  native_release_tag: `v${version}`,
  source_package: '@kinlab/kin-mcp',
  source_version: version,
}, null, 2)}\n`);
NODE

# Name the output explicitly. Without an output argument the CLI uses the
# staging-directory name, which has no stable relationship to Kin's release.
npx -y @anthropic-ai/mcpb pack "$stage" "$bundle"
echo "bundle: ${bundle}"
echo "launcher: @kinlab/kin-mcp@${version}"
