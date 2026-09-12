// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

// Entry point for the Claude Desktop extension. It runs the published,
// version-pinned @kinlab/kin-mcp launcher through npx from the workspace the
// user chose. The bundle manifest is the release identity authority, so a
// bundle never silently follows npm's moving latest tag.
//
// An MCPB mcp_config carries command, args, env, and platform overrides, but
// no working directory. The launcher decides which repository it serves from
// its working directory and refuses every extra argument. Setting the child's
// cwd here is what binds the selected workspace to the MCP server.

'use strict';

const { spawn } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const workspace = process.env.KIN_MCP_REPO;

if (!workspace) {
  process.stderr.write(
    'Kin: no workspace is configured. Open the Kin extension settings and choose the Kin repository to serve.\n'
  );
  process.exit(2);
}

let stats;
try {
  stats = fs.statSync(workspace);
} catch (error) {
  process.stderr.write(`Kin: the configured workspace ${workspace} could not be read (${error.message}).\n`);
  process.exit(2);
}

if (!stats.isDirectory()) {
  process.stderr.write(`Kin: the configured workspace ${workspace} is not a directory.\n`);
  process.exit(2);
}

const manifestPath = path.join(__dirname, '..', 'manifest.json');
let version;
try {
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  version = manifest.version;
} catch (error) {
  process.stderr.write(`Kin: could not read the bundle release identity (${error.message}).\n`);
  process.exit(2);
}

if (typeof version !== 'string' || !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(version)) {
  process.stderr.write(`Kin: bundle manifest declares an invalid release version (${String(version)}).\n`);
  process.exit(2);
}

const npx = process.platform === 'win32' ? 'npx.cmd' : 'npx';
const launcher = `@kinlab/kin-mcp@${version}`;
const child = spawn(npx, ['-y', launcher], {
  cwd: workspace,
  stdio: 'inherit',
  env: process.env
});

child.on('error', (error) => {
  process.stderr.write(`Kin: ${npx} could not be started (${error.message}).\n`);
  process.exit(1);
});

child.on('exit', (code, signal) => {
  process.exit(signal ? 1 : code === null ? 1 : code);
});

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => {
    child.kill(signal);
  });
}
