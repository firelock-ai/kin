#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

// `kin-mcp` — compatibility launcher for Kin's MCP server.
//
// MCP is one included mode of Kin, not a separate product. This bin exists so
// existing `@kinlab/kin-mcp` users keep a working `kin-mcp` entrypoint; it
// provisions the managed release like the `kin` launcher and starts
// `kin mcp start`, forwarding any extra argv. Progress and failures go to
// stderr only — stdout belongs to the MCP stdio protocol.

import os from 'node:os';
import { spawnSync } from 'node:child_process';

import { packageVersion, targetKinVersion, notProvisionedMessage } from '../lib/resolve.mjs';
import { ensureProvisioned } from '../lib/provision.mjs';

const argv = process.argv.slice(2);

if (argv.includes('--version') || argv.includes('-V')) {
  process.stdout.write(
    `@kinlab/kin ${packageVersion()} (kin-mcp compatibility launcher; provisions kin ${targetKinVersion()})\n`,
  );
  process.exit(0);
}

let binary = null;
let provisionError = null;
try {
  binary = await ensureProvisioned();
} catch (error) {
  provisionError = error;
}

if (!binary) {
  // The error message is already complete and actionable (e.g. a declined
  // downgrade names the binary that IS present) — printing the generic
  // not-provisioned message on top of it would contradict it.
  if (provisionError) {
    process.stderr.write(`kin-mcp: provisioning failed: ${provisionError.message}\n`);
  } else {
    process.stderr.write(`${notProvisionedMessage('kin')}\n`);
  }
  process.exit(1);
}

const result = spawnSync(binary, ['mcp', 'start', ...argv], { stdio: 'inherit' });
if (result.error) {
  process.stderr.write(`kin-mcp: failed to launch managed binary: ${result.error.message}\n`);
  process.exit(1);
}
if (result.signal) {
  process.exit(128 + (os.constants.signals[result.signal] ?? 0));
}
process.exit(result.status ?? 0);
