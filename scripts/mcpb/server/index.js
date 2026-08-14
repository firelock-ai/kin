// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

// Entry point for the Claude Desktop extension. It runs the published
// @kinlab/kin-mcp launcher through npx, from the workspace the user chose.
//
// The indirection is load-bearing in two ways that are invisible from the
// manifest. An MCPB `mcp_config` carries command, args, env, and
// platform_overrides, and no working directory. The launcher decides which
// repository it serves from its own working directory and refuses every extra
// argument, so neither an argument nor an environment variable alone can point
// it at the workspace. Setting the child's cwd here is what binds the two.

'use strict';

const { spawn } = require('node:child_process');
const fs = require('node:fs');

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

const npx = process.platform === 'win32' ? 'npx.cmd' : 'npx';
const child = spawn(npx, ['-y', '@kinlab/kin-mcp'], {
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
