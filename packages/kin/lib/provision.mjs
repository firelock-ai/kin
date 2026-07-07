// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

// Binary provisioning for the @kinlab/kin launcher.
//
// Downloads the platform archive of the pinned Kin release from GitHub
// Releases, verifies it against the per-artifact SHA-256 published next to it,
// and installs the binaries into <kinHome>/bin — the same directory and the
// same refusal semantics as scripts/install.sh, so the two install lanes are
// interchangeable. kin-daemon is mandatory (status/search/MCP require it): a
// daemon-less archive aborts before anything is moved rather than leaving a
// half-installed environment. Network, spawning, and the environment are all
// injectable so every decision here is unit testable offline.

import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

import {
  binaryName,
  kinHome,
  managedBinaryPath,
  readLauncherStamp,
  resolveManagedBinary,
  targetKinVersion,
  writeLauncherStamp,
} from './resolve.mjs';

/**
 * Release-artifact file name for a host. Follows the release workflow's
 * naming (kin-{macos|linux|windows}-{x86_64|aarch64}); Windows ships as .zip.
 * There is no native windows-aarch64 artifact — fail honestly rather than
 * fabricate a URL (Windows-on-ARM can run the x64 build under emulation).
 */
export function artifactName(platform = process.platform, arch = process.arch) {
  const artifacts = {
    'darwin:arm64': 'kin-macos-aarch64.tar.gz',
    'darwin:x64': 'kin-macos-x86_64.tar.gz',
    'linux:arm64': 'kin-linux-aarch64.tar.gz',
    'linux:x64': 'kin-linux-x86_64.tar.gz',
    'win32:x64': 'kin-windows-x86_64.zip',
  };
  const key = `${platform}:${arch}`;
  const file = artifacts[key];
  if (!file) {
    const supported = Object.keys(artifacts).join(', ');
    throw new Error(
      key === 'win32:arm64'
        ? 'no native windows-aarch64 Kin release artifact exists; use an x64 Node ' +
          'under emulation (the x86_64 build runs on Windows-on-ARM), or build from source.'
        : `no Kin release artifact for "${key}"; supported: ${supported}`,
    );
  }
  return file;
}

/** Download URL of a file attached to the v<version> GitHub release. */
export function releaseDownloadUrl(version, file) {
  return `https://github.com/firelock-ai/kin/releases/download/v${version}/${file}`;
}

/**
 * Extract the hex digest from a `shasum -a 256` style checksum file
 * ("<hex>  <name>"). Refuses anything that does not look like SHA-256.
 */
export function parseSha256File(text) {
  const token = String(text).trim().split(/\s+/)[0] ?? '';
  if (!/^[0-9a-f]{64}$/i.test(token)) {
    throw new Error(`malformed .sha256 file (expected a 64-hex digest, got "${token.slice(0, 80)}")`);
  }
  return token.toLowerCase();
}

/** SHA-256 hex digest of a buffer. */
export function sha256Hex(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

async function fetchBuffer(url, fetchImpl) {
  const res = await fetchImpl(url);
  if (!res.ok) {
    throw new Error(`download failed (${res.status}) for ${url}`);
  }
  return Buffer.from(await res.arrayBuffer());
}

/**
 * Locate the extraction root: release archives contain a kin-* subdirectory;
 * tolerate a flat archive the way install.sh does.
 */
function extractionRoot(tmp) {
  const sub = fs
    .readdirSync(tmp, { withFileTypes: true })
    .find((e) => e.isDirectory() && e.name.startsWith('kin-'));
  return sub ? path.join(tmp, sub.name) : tmp;
}

/** Replace-then-move a binary into place (never overwrite in place: replacing
 * a running executable's inode causes launch deadlocks on macOS). */
function installFile(src, dest, mode) {
  fs.rmSync(dest, { force: true });
  fs.copyFileSync(src, dest);
  fs.chmodSync(dest, mode);
}

/**
 * Download, verify, and install the pinned Kin release. Returns the installed
 * managed `kin` path. Mirrors scripts/install.sh: kin + kin-daemon are
 * mandatory, kin-vfs and the projection shim library are optional extras.
 */
export async function provision(version, opts = {}) {
  const {
    env = process.env,
    platform = process.platform,
    arch = process.arch,
    fetchImpl = fetch,
    log = (line) => process.stderr.write(`${line}\n`),
  } = opts;

  const file = artifactName(platform, arch);
  const url = releaseDownloadUrl(version, file);
  log(`kin: provisioning managed kin ${version} (${file})...`);

  const [archive, shaText] = await Promise.all([
    fetchBuffer(url, fetchImpl),
    fetchBuffer(`${url}.sha256`, fetchImpl),
  ]);
  const expected = parseSha256File(shaText.toString('utf8'));
  const actual = sha256Hex(archive);
  if (actual !== expected) {
    throw new Error(
      `SHA-256 mismatch for ${file}: expected ${expected}, got ${actual}. ` +
        'The download may be corrupted or tampered with; refusing to install.',
    );
  }

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'kinlab-kin-'));
  try {
    const archivePath = path.join(tmp, file);
    fs.writeFileSync(archivePath, archive);
    // bsdtar reads both .tar.gz and .zip with -xf, on macOS, Linux, and
    // Windows 10+ (tar.exe ships in System32).
    const tar = spawnSync('tar', ['-xf', archivePath, '-C', tmp], { encoding: 'utf8' });
    if (tar.status !== 0) {
      throw new Error(`archive extraction failed: ${tar.stderr || tar.error?.message || 'tar exited non-zero'}`);
    }

    const root = extractionRoot(tmp);
    const kinSrc = path.join(root, binaryName('kin', platform));
    const daemonSrc = path.join(root, binaryName('kin-daemon', platform));
    if (!fs.existsSync(kinSrc) || !fs.existsSync(daemonSrc)) {
      throw new Error(
        'kin-daemon (or kin) missing from the downloaded archive. kin status/search and ' +
          'the MCP server require the daemon; refusing a daemon-less install.',
      );
    }

    const binDir = path.join(kinHome(env), 'bin');
    const libDir = path.join(kinHome(env), 'lib');
    fs.mkdirSync(binDir, { recursive: true });

    installFile(kinSrc, path.join(binDir, binaryName('kin', platform)), 0o755);
    installFile(daemonSrc, path.join(binDir, binaryName('kin-daemon', platform)), 0o755);

    const vfsSrc = path.join(root, binaryName('kin-vfs', platform));
    if (fs.existsSync(vfsSrc)) {
      installFile(vfsSrc, path.join(binDir, binaryName('kin-vfs', platform)), 0o755);
    }
    for (const lib of ['libkin_vfs_shim.so', 'libkin_vfs_shim.dylib']) {
      const libSrc = path.join(root, lib);
      if (fs.existsSync(libSrc)) {
        fs.mkdirSync(libDir, { recursive: true });
        installFile(libSrc, path.join(libDir, lib), 0o644);
      }
    }

    writeLauncherStamp(version, env);
    log(`kin: managed kin ${version} installed at ${binDir}`);
    return path.join(binDir, binaryName('kin', platform));
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

/** First line of `<binary> --version`, or null if it cannot be run. */
export function probeBinaryVersion(binary, spawnImpl = spawnSync) {
  const res = spawnImpl(binary, ['--version'], { encoding: 'utf8' });
  if (res.error || res.status !== 0) return null;
  const m = String(res.stdout).match(/^kin\s+(\S+)/);
  return m ? m[1] : null;
}

/**
 * Ensure the managed `kin` binary matching this launcher's pinned release is
 * present, provisioning (or re-provisioning) when needed. Returns the binary
 * path, or null when nothing usable exists and provisioning is unavailable.
 *
 * Policy, in order:
 *   - $KIN_MANAGED_BIN is an explicit user pin: use it as-is, never provision.
 *   - $KIN_NO_PROVISION=1: resolve-only, no network.
 *   - launcher stamp == target and the binary exists: run it (no probe cost).
 *   - stamp differs or binary missing: provision the pinned release.
 *   - no stamp but a binary exists (foreign install, e.g. install.sh): probe
 *     its version; adopt on match. On mismatch respect the foreign install —
 *     run it with a one-line notice — unless $KIN_LAUNCHER_ADOPT=1 opts into
 *     re-provisioning. Never silently downgrade someone else's install.
 */
export async function ensureProvisioned(opts = {}) {
  const {
    env = process.env,
    platform = process.platform,
    arch = process.arch,
    fetchImpl = fetch,
    log = (line) => process.stderr.write(`${line}\n`),
    spawnImpl = spawnSync,
  } = opts;

  const target = targetKinVersion();

  if (env.KIN_MANAGED_BIN && env.KIN_MANAGED_BIN.trim()) {
    return resolveManagedBinary('kin', env, platform);
  }
  const existing = resolveManagedBinary('kin', env, platform);
  if (env.KIN_NO_PROVISION === '1') {
    return existing;
  }

  const doProvision = () => provision(target, { env, platform, arch, fetchImpl, log });

  if (!existing) {
    return doProvision();
  }

  const stamp = readLauncherStamp(env);
  if (stamp === target) {
    return existing;
  }
  if (stamp !== null) {
    return doProvision();
  }

  const probed = probeBinaryVersion(existing, spawnImpl);
  if (probed === target) {
    writeLauncherStamp(target, env);
    return existing;
  }
  if (env.KIN_LAUNCHER_ADOPT === '1') {
    return doProvision();
  }
  log(
    `kin: using existing managed kin ${probed ?? 'unknown'} at ${managedBinaryPath('kin', env, platform)} ` +
      `(this @kinlab/kin pins ${target}; set KIN_LAUNCHER_ADOPT=1 to re-provision).`,
  );
  return existing;
}
