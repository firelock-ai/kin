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
  compareVersions,
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

/** Compact, stable byte count for first-install progress. */
export function formatByteCount(bytes) {
  const value = Math.max(0, Number(bytes) || 0);
  const units = ['B', 'KiB', 'MiB', 'GiB'];
  let amount = value;
  let unit = 0;
  while (amount >= 1024 && unit < units.length - 1) {
    amount /= 1024;
    unit += 1;
  }
  const digits = unit === 0 ? 0 : 1;
  return `${amount.toFixed(digits)} ${units[unit]}`;
}

/** Pure rendering helper so progress wording remains testable without a TTY. */
export function formatDownloadProgress(file, received, total = null) {
  const transferred = formatByteCount(received);
  if (Number.isFinite(total) && total > 0) {
    const percent = Math.min(100, Math.floor((received * 100) / total));
    return `kin: downloading ${file}: ${percent}% (${transferred} / ${formatByteCount(total)})`;
  }
  return `kin: downloading ${file}: ${transferred} received`;
}

export function createDownloadProgress(file, stream = process.stderr) {
  let lastAt = 0;
  let lastBytes = 0;
  let lastPercent = -1;
  let active = false;
  return ({ received, total, done = false, failed = false }) => {
    if (failed) {
      if (active) stream.write('\r\x1b[2K\n');
      active = false;
      return;
    }
    const now = Date.now();
    const percent = Number.isFinite(total) && total > 0 ? Math.floor((received * 100) / total) : null;
    if (!done) {
      if (percent !== null && percent === lastPercent && now - lastAt < 250) return;
      if (percent === null && received - lastBytes < 1024 * 1024 && now - lastAt < 250) return;
    }
    stream.write(`\r\x1b[2K${formatDownloadProgress(file, received, total)}${done ? '\n' : ''}`);
    active = !done;
    lastAt = now;
    lastBytes = received;
    lastPercent = percent;
  };
}

async function fetchBuffer(url, fetchImpl) {
  const res = await fetchImpl(url);
  if (!res.ok) {
    throw new Error(`download failed (${res.status}) for ${url}`);
  }

  return Buffer.from(await res.arrayBuffer());
}

/**
 * Download one response directly into a staging file while hashing it. The
 * streaming path consumes and writes one chunk before requesting the next, so
 * archive-sized data is never accumulated in JavaScript memory. Lightweight
 * injected fetches that expose only arrayBuffer() retain their existing one-
 * buffer contract.
 */
export async function downloadToFile(url, destination, fetchImpl, onProgress = null) {
  let received = 0;
  let total = null;
  try {
    const res = await fetchImpl(url);
    if (!res.ok) {
      throw new Error(`download failed (${res.status}) for ${url}`);
    }

    const contentLength = Number(res.headers?.get?.('content-length'));
    total = Number.isFinite(contentLength) && contentLength > 0 ? contentLength : null;
    const hash = crypto.createHash('sha256');

    if (res.body && typeof res.body[Symbol.asyncIterator] === 'function') {
      const fd = fs.openSync(destination, 'w', 0o600);
      try {
        for await (const chunk of res.body) {
          const bytes = ArrayBuffer.isView(chunk)
            ? new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength)
            : Buffer.from(chunk);
          let offset = 0;
          while (offset < bytes.byteLength) {
            const written = fs.writeSync(fd, bytes, offset, bytes.byteLength - offset);
            if (written <= 0) throw new Error(`archive staging made no progress for ${url}`);
            offset += written;
          }
          hash.update(bytes);
          received += bytes.byteLength;
          onProgress?.({ received, total, done: false });
        }
      } finally {
        fs.closeSync(fd);
      }
    } else {
      // Preserve offline/injected fetch compatibility without adding a second
      // archive-sized allocation: Buffer.from(ArrayBuffer) is a shared view.
      const bytes = Buffer.from(await res.arrayBuffer());
      fs.writeFileSync(destination, bytes, { mode: 0o600 });
      hash.update(bytes);
      received = bytes.length;
    }

    if (total !== null && received !== total) {
      throw new Error(`download truncated for ${url}: expected ${total} bytes, received ${received}`);
    }

    onProgress?.({ received, total: total ?? received, done: true });
    return { bytes: received, sha256: hash.digest('hex') };
  } catch (error) {
    try {
      onProgress?.({ received, total, done: true, failed: true });
    } catch {
      // Progress cleanup is best-effort and must not hide the download error.
    }
    throw error;
  }
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
    onProgress,
  } = opts;

  const file = artifactName(platform, arch);
  const url = releaseDownloadUrl(version, file);
  log(`kin: provisioning managed kin ${version} (${file})...`);

  // Interactive first runs show live bytes/percent; redirected/non-TTY npm
  // invocations stay line-oriented. An injected callback keeps streaming fully
  // testable without coupling fake fetch implementations to terminal behavior.
  const archiveProgress =
    onProgress === undefined && fetchImpl === globalThis.fetch && process.stderr.isTTY
      ? createDownloadProgress(file)
      : onProgress;

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'kinlab-kin-'));
  try {
    const archivePath = path.join(tmp, file);
    // Wait for both concurrent fetches to settle before removing the staging
    // directory. Promise.all would race cleanup against an archive stream when
    // the small checksum request fails first.
    const [archiveResult, checksumResult] = await Promise.allSettled([
      downloadToFile(url, archivePath, fetchImpl, archiveProgress),
      fetchBuffer(`${url}.sha256`, fetchImpl),
    ]);
    if (archiveResult.status === 'rejected') throw archiveResult.reason;
    if (checksumResult.status === 'rejected') throw checksumResult.reason;

    const expected = parseSha256File(checksumResult.value.toString('utf8'));
    const actual = archiveResult.value.sha256;
    if (actual !== expected) {
      throw new Error(
        `SHA-256 mismatch for ${file}: expected ${expected}, got ${actual}. ` +
          'The download may be corrupted or tampered with; refusing to install.',
      );
    }

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
 * Throws when an installed release outranks the pin and the caller has not
 * opted into a downgrade — this function never returns a value while quietly
 * declining to honor the pin.
 *
 * Policy, in order:
 *   - $KIN_MANAGED_BIN is an explicit user pin: use it as-is, never provision.
 *   - $KIN_NO_PROVISION=1: resolve-only, no network.
 *   - $KIN_LAUNCHER_ADOPT=1: always (re-)provision the pinned release,
 *     regardless of what is already installed.
 *   - nothing installed yet: provision the pinned release.
 *   - installed version is known — from the launcher stamp when this package
 *     provisioned it (no probe needed), otherwise by probing a foreign
 *     install's `--version` once:
 *       - installed == pinned: reuse it (a foreign match adopts the stamp).
 *       - installed < pinned: the pin is an upgrade — provision it
 *         automatically with a one-line notice. Never a silent no-op.
 *       - installed > pinned: the pin would downgrade a newer install — fail
 *         loud with an actionable message instead of running anything.
 *   - installed version unparseable (foreign binary that will not report a
 *     version): can't prove direction, so respect it — notice and reuse.
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

  if (env.KIN_LAUNCHER_ADOPT === '1') {
    return doProvision();
  }
  if (!existing) {
    return doProvision();
  }

  const installedPath = managedBinaryPath('kin', env, platform);
  const stamp = readLauncherStamp(env);
  const installed = stamp ?? probeBinaryVersion(existing, spawnImpl);

  if (installed === null) {
    log(
      `kin: using existing managed kin (version unknown) at ${installedPath} ` +
        `(this @kinlab/kin pins ${target}; set KIN_LAUNCHER_ADOPT=1 to re-provision).`,
    );
    return existing;
  }

  const cmp = compareVersions(target, installed);
  if (cmp === 0) {
    if (stamp === null) writeLauncherStamp(target, env);
    return existing;
  }
  if (cmp > 0) {
    log(`kin: managed kin ${installed} is older than the pinned ${target}; upgrading automatically.`);
    return doProvision();
  }
  throw new Error(
    `refusing to downgrade managed kin ${installed} to the pinned ${target} (at ${installedPath}). ` +
      'This @kinlab/kin would replace a newer managed install with an older one; nothing was run. ' +
      'Set KIN_LAUNCHER_ADOPT=1 to force it if the downgrade is intended.',
  );
}
