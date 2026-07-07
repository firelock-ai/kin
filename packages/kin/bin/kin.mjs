#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

// `kin` — canonical launcher/passthrough for the Kin CLI.
//
// Provisions the managed native `kin` (+ `kin-daemon`) release on first run,
// then forwards argv straight to it and mirrors its exit. `--version` therefore
// proves provisioning end-to-end: it answers with the real binary's version.
// When provisioning is unavailable (offline, disabled), it fails loud with an
// actionable message — it never pretends to run.

import os from 'node:os';
import { spawnSync } from 'node:child_process';

import { packageVersion, targetKinVersion, notProvisionedMessage } from '../lib/resolve.mjs';
import { ensureProvisioned } from '../lib/provision.mjs';

const argv = process.argv.slice(2);
const wantsVersion = argv.includes('--version') || argv.includes('-V');

function launcherVersionLine(note) {
  return `@kinlab/kin ${packageVersion()} (launcher; provisions kin ${targetKinVersion()}${note})\n`;
}

let binary = null;
let provisionError = null;
try {
  binary = await ensureProvisioned();
} catch (error) {
  provisionError = error;
}

if (!binary) {
  if (provisionError) {
    // The error message is already complete and actionable (e.g. a declined
    // downgrade names the binary that IS present) — printing the generic
    // not-provisioned message on top of it would contradict it.
    process.stderr.write(`kin: provisioning failed: ${provisionError.message}\n`);
    if (wantsVersion) {
      process.stdout.write(launcherVersionLine(', provisioning failed'));
    }
    process.exit(1);
  }
  if (wantsVersion) {
    // Honest launcher identity; success only when provisioning was explicitly
    // disabled rather than broken.
    process.stdout.write(launcherVersionLine(', not installed'));
    process.exit(0);
  }
  process.stderr.write(`${notProvisionedMessage('kin')}\n`);
  process.exit(1);
}

const result = spawnSync(binary, argv, { stdio: 'inherit' });
if (result.error) {
  process.stderr.write(`kin: failed to launch managed binary: ${result.error.message}\n`);
  process.exit(1);
}
if (result.signal) {
  // Mirror signal deaths honestly instead of reporting success.
  process.exit(128 + (os.constants.signals[result.signal] ?? 0));
}
process.exit(result.status ?? 0);
