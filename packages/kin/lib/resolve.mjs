// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

// Managed-binary resolution for the @kinlab/kin launcher.
//
// This package is the canonical install surface for Kin: `npm i -g @kinlab/kin`
// gives you the `kin` and `kin-mcp` bins. The bins are thin launchers over a
// *managed* native binary (the real `kin` + `kin-daemon` release). This module
// owns the pure, side-effect-free part of that story — computing the platform
// target, where the managed binary is expected to live, and which release the
// launcher pins — so it is unit testable without spawning or touching the
// network. Downloading and installing live in ./provision.mjs.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));

/** This package's own version, read from its package.json (single source). */
export function packageVersion() {
  const manifest = JSON.parse(fs.readFileSync(path.join(HERE, '..', 'package.json'), 'utf8'));
  return manifest.version;
}

/**
 * The Kin release this launcher provisions. It tracks the package version: the
 * canonical package is versioned in lockstep with the `kin` + `kin-daemon`
 * release it installs (the release workflow asserts package version == tag).
 */
export function targetKinVersion() {
  return packageVersion();
}

/**
 * Map a Node platform+arch pair to the Rust target triple of the managed
 * binary. Pure and injectable so it is testable for every supported host.
 */
export function platformTarget(platform = process.platform, arch = process.arch) {
  const targets = {
    'darwin:arm64': 'aarch64-apple-darwin',
    'darwin:x64': 'x86_64-apple-darwin',
    'linux:arm64': 'aarch64-unknown-linux-gnu',
    'linux:x64': 'x86_64-unknown-linux-gnu',
    'win32:x64': 'x86_64-pc-windows-msvc',
    'win32:arm64': 'aarch64-pc-windows-msvc',
  };
  const key = `${platform}:${arch}`;
  const triple = targets[key];
  if (!triple) {
    throw new Error(
      `unsupported platform "${key}" for @kinlab/kin; supported: ${Object.keys(targets).join(', ')}`,
    );
  }
  return triple;
}

/** Executable file name for a bin on the host platform (adds .exe on Windows). */
export function binaryName(name, platform = process.platform) {
  return platform === 'win32' ? `${name}.exe` : name;
}

/** Root of Kin's managed install, honoring $KIN_HOME (default ~/.kin). */
export function kinHome(env = process.env, home = os.homedir()) {
  return env.KIN_HOME && env.KIN_HOME.trim() ? env.KIN_HOME : path.join(home, '.kin');
}

/**
 * Absolute path where the managed `name` binary is expected. An explicit
 * $KIN_MANAGED_BIN overrides the whole computation (an explicit user pin;
 * provisioning never writes through it); otherwise it is
 * <kinHome>/bin/<name>[.exe] — the same directory the shell installer
 * (scripts/install.sh) populates, so either lane satisfies the other.
 */
export function managedBinaryPath(name = 'kin', env = process.env, platform = process.platform) {
  if (env.KIN_MANAGED_BIN && env.KIN_MANAGED_BIN.trim()) {
    return env.KIN_MANAGED_BIN;
  }
  return path.join(kinHome(env), 'bin', binaryName(name, platform));
}

/**
 * Resolve the managed `name` binary to an absolute path if it exists on disk,
 * else null. Never fabricates a path that is not really present.
 */
export function resolveManagedBinary(name = 'kin', env = process.env, platform = process.platform) {
  const candidate = managedBinaryPath(name, env, platform);
  try {
    return fs.existsSync(candidate) ? candidate : null;
  } catch {
    return null;
  }
}

/**
 * Path of the launcher's version stamp: which Kin release this launcher last
 * provisioned into <kinHome>/bin. Lets the normal launch path skip a
 * `kin --version` probe; a binary installed by other means (install.sh) has no
 * stamp and is probed instead of being silently trusted or clobbered.
 */
export function launcherStampPath(env = process.env) {
  return path.join(kinHome(env), 'bin', '.kinlab-kin-version');
}

/** The stamped provisioned version, or null when absent/unreadable. */
export function readLauncherStamp(env = process.env) {
  try {
    const text = fs.readFileSync(launcherStampPath(env), 'utf8').trim();
    return text.length ? text : null;
  } catch {
    return null;
  }
}

/** Record `version` as the provisioned release (directory must exist). */
export function writeLauncherStamp(version, env = process.env) {
  fs.writeFileSync(launcherStampPath(env), `${version}\n`);
}

/** Human-readable, honest explanation for when the managed binary is absent. */
export function notProvisionedMessage(name = 'kin', env = process.env, platform = process.platform) {
  const expected = managedBinaryPath(name, env, platform);
  const triple = (() => {
    try {
      return platformTarget();
    } catch {
      return 'unknown-target';
    }
  })();
  return [
    `kin: managed "${name}" binary not found (expected at ${expected}).`,
    `Host target: ${triple}. @kinlab/kin ${packageVersion()} provisions the managed Kin`,
    'release on first run; if you are seeing this, provisioning failed or was disabled',
    '(KIN_NO_PROVISION=1). Re-run with network access, set KIN_MANAGED_BIN to an existing',
    'kin binary, or install via https://github.com/firelock-ai/kin (scripts/install.sh).',
  ].join('\n');
}
