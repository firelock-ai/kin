// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';

import {
  artifactName,
  releaseDownloadUrl,
  parseSha256File,
  sha256Hex,
  provision,
  probeBinaryVersion,
  ensureProvisioned,
} from '../lib/provision.mjs';
import { readLauncherStamp, writeLauncherStamp } from '../lib/resolve.mjs';

test('artifactName maps every released host and matches release.yml naming', () => {
  assert.equal(artifactName('darwin', 'arm64'), 'kin-macos-aarch64.tar.gz');
  assert.equal(artifactName('darwin', 'x64'), 'kin-macos-x86_64.tar.gz');
  assert.equal(artifactName('linux', 'arm64'), 'kin-linux-aarch64.tar.gz');
  assert.equal(artifactName('linux', 'x64'), 'kin-linux-x86_64.tar.gz');
  assert.equal(artifactName('win32', 'x64'), 'kin-windows-x86_64.zip');
});

test('artifactName is honest about windows-aarch64 having no artifact', () => {
  assert.throws(() => artifactName('win32', 'arm64'), /no native windows-aarch64/);
});

test('releaseDownloadUrl pins the tag and file', () => {
  assert.equal(
    releaseDownloadUrl('1.2.3', 'kin-macos-aarch64.tar.gz'),
    'https://github.com/firelock-ai/kin/releases/download/v1.2.3/kin-macos-aarch64.tar.gz',
  );
});

test('parseSha256File accepts shasum output and rejects junk', () => {
  const hex = 'a'.repeat(64);
  assert.equal(parseSha256File(`${hex}  kin-macos-aarch64.tar.gz\n`), hex);
  assert.equal(parseSha256File(`${hex.toUpperCase()}  x`), hex);
  assert.throws(() => parseSha256File('not-a-digest  file'), /malformed \.sha256/);
  assert.throws(() => parseSha256File(''), /malformed \.sha256/);
});

// ── offline provision fixture ──────────────────────────────────────────────
//
// Builds a real tar.gz in a tempdir (via the same `tar` the provisioner uses)
// containing the archive layout install.sh documents: a kin-* subdirectory
// with kin + kin-daemon. The fake fetch serves those bytes; no network.

function makeFixture({ withDaemon = true, notifier = 'complete', notifierBody = 'notifier-v1' } = {}) {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'kin-prov-fixture-'));
  const stage = path.join(work, 'kin-macos-aarch64');
  fs.mkdirSync(stage, { recursive: true });
  fs.writeFileSync(path.join(stage, 'kin'), '#!/bin/sh\necho "kin 9.9.9 (test)"\n');
  if (withDaemon) {
    fs.writeFileSync(path.join(stage, 'kin-daemon'), '#!/bin/sh\necho daemon\n');
  }
  if (notifier !== 'absent') {
    const bundle = path.join(stage, 'KinNotifier.app');
    fs.mkdirSync(path.join(bundle, 'Contents', 'MacOS'), { recursive: true });
    fs.mkdirSync(path.join(bundle, 'Contents', 'Resources'), { recursive: true });
    const executable = path.join(bundle, 'Contents', 'MacOS', 'KinNotifier');
    fs.writeFileSync(executable, `#!/bin/sh\necho ${notifierBody}\n`);
    fs.chmodSync(executable, 0o755);
    fs.writeFileSync(path.join(bundle, 'Contents', 'Resources', 'Kin.icns'), 'icns');
    if (notifier === 'complete') {
      fs.writeFileSync(path.join(bundle, 'Contents', 'Info.plist'), '<plist/>');
    }
  }
  const archivePath = path.join(work, 'kin-macos-aarch64.tar.gz');
  const tar = spawnSync('tar', ['-czf', archivePath, '-C', work, 'kin-macos-aarch64'], {
    encoding: 'utf8',
  });
  assert.equal(tar.status, 0, tar.stderr);
  const bytes = fs.readFileSync(archivePath);
  const sha = `${sha256Hex(bytes)}  kin-macos-aarch64.tar.gz\n`;
  const fetchImpl = async (url) => {
    const body = url.endsWith('.sha256') ? Buffer.from(sha) : bytes;
    return {
      ok: true,
      status: 200,
      arrayBuffer: async () => body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength),
    };
  };
  return { work, bytes, sha, fetchImpl };
}

test('provision verifies, installs kin + kin-daemon, and stamps the version', async () => {
  const { work, fetchImpl } = makeFixture();
  const home = path.join(work, 'kin-home');
  const env = { KIN_HOME: home };
  const installed = await provision('9.9.9', {
    env,
    platform: 'darwin',
    arch: 'arm64',
    fetchImpl,
    log: () => {},
  });
  assert.equal(installed, path.join(home, 'bin', 'kin'));
  assert.ok(fs.existsSync(path.join(home, 'bin', 'kin')));
  assert.ok(fs.existsSync(path.join(home, 'bin', 'kin-daemon')));
  assert.equal(fs.statSync(installed).mode & 0o111 && true, true);
  assert.equal(readLauncherStamp(env), '9.9.9');
  fs.rmSync(work, { recursive: true, force: true });
});

test('provision installs the macOS notification bundle so notifications post as Kin', async () => {
  const { work, fetchImpl } = makeFixture();
  const home = path.join(work, 'kin-home');
  await provision('9.9.9', {
    env: { KIN_HOME: home },
    platform: 'darwin',
    arch: 'arm64',
    fetchImpl,
    log: () => {},
  });
  const executable = path.join(home, 'lib', 'KinNotifier.app', 'Contents', 'MacOS', 'KinNotifier');
  assert.ok(fs.existsSync(executable), 'the bundle must reach $KIN_HOME/lib');
  assert.ok(fs.existsSync(path.join(home, 'lib', 'KinNotifier.app', 'Contents', 'Info.plist')));
  assert.ok(fs.statSync(executable).mode & 0o111, 'a notifier without +x cannot be launched');
  fs.rmSync(work, { recursive: true, force: true });
});

test('provision replaces a stale bundle whole rather than merging into it', async () => {
  const { work, fetchImpl } = makeFixture({ notifierBody: 'notifier-v2' });
  const home = path.join(work, 'kin-home');
  // A previous release's bundle, carrying a file the new one does not have.
  const dest = path.join(home, 'lib', 'KinNotifier.app');
  fs.mkdirSync(path.join(dest, 'Contents', 'MacOS'), { recursive: true });
  fs.writeFileSync(path.join(dest, 'Contents', 'MacOS', 'KinNotifier'), 'stale');
  fs.writeFileSync(path.join(dest, 'Contents', 'Stale.txt'), 'left over');

  await provision('9.9.9', {
    env: { KIN_HOME: home },
    platform: 'darwin',
    arch: 'arm64',
    fetchImpl,
    log: () => {},
  });
  assert.match(
    fs.readFileSync(path.join(dest, 'Contents', 'MacOS', 'KinNotifier'), 'utf8'),
    /notifier-v2/,
  );
  assert.ok(
    !fs.existsSync(path.join(dest, 'Contents', 'Stale.txt')),
    'a merged bundle keeps files the new release removed, breaking its signature seal',
  );
  fs.rmSync(work, { recursive: true, force: true });
});

test('provision says so when a macOS archive carries no bundle', async () => {
  const { work, fetchImpl } = makeFixture({ notifier: 'absent' });
  const home = path.join(work, 'kin-home');
  const lines = [];
  await provision('9.9.9', {
    env: { KIN_HOME: home },
    platform: 'darwin',
    arch: 'arm64',
    fetchImpl,
    log: (line) => lines.push(line),
  });
  // The CLI still installs: a missing bundle degrades notifications, it does
  // not break Kin. It must not degrade quietly, though.
  assert.ok(fs.existsSync(path.join(home, 'bin', 'kin')));
  const warning = lines.find((line) => line.includes('KinNotifier.app'));
  assert.ok(warning, `expected a warning naming the bundle, got: ${lines.join(' | ')}`);
  assert.match(warning, /Script Editor/);
  fs.rmSync(work, { recursive: true, force: true });
});

test('provision refuses a bundle that has nothing to post under', async () => {
  const { work, fetchImpl } = makeFixture({ notifier: 'no-plist' });
  const home = path.join(work, 'kin-home');
  await assert.rejects(
    provision('9.9.9', {
      env: { KIN_HOME: home },
      platform: 'darwin',
      arch: 'arm64',
      fetchImpl,
      log: () => {},
    }),
    /Info\.plist/,
  );
  fs.rmSync(work, { recursive: true, force: true });
});

test('provision installs no bundle on a platform that has no notification bundle', async () => {
  const { work, fetchImpl } = makeFixture();
  const home = path.join(work, 'kin-home');
  const lines = [];
  await provision('9.9.9', {
    env: { KIN_HOME: home },
    platform: 'linux',
    arch: 'x64',
    fetchImpl,
    log: (line) => lines.push(line),
  });
  assert.ok(!fs.existsSync(path.join(home, 'lib', 'KinNotifier.app')));
  assert.ok(
    !lines.some((line) => line.includes('KinNotifier.app')),
    'a platform with no bundle concept has nothing to warn about',
  );
  fs.rmSync(work, { recursive: true, force: true });
});

test('provision refuses a checksum mismatch without installing', async () => {
  const { work, bytes } = makeFixture();
  const home = path.join(work, 'kin-home');
  const badSha = `${'0'.repeat(64)}  kin-macos-aarch64.tar.gz\n`;
  const fetchImpl = async (url) => {
    const body = url.endsWith('.sha256') ? Buffer.from(badSha) : bytes;
    return {
      ok: true,
      status: 200,
      arrayBuffer: async () => body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength),
    };
  };
  await assert.rejects(
    provision('9.9.9', { env: { KIN_HOME: home }, platform: 'darwin', arch: 'arm64', fetchImpl, log: () => {} }),
    /SHA-256 mismatch/,
  );
  assert.ok(!fs.existsSync(path.join(home, 'bin', 'kin')));
  fs.rmSync(work, { recursive: true, force: true });
});

test('provision refuses a daemon-less archive before moving anything', async () => {
  const { work, fetchImpl } = makeFixture({ withDaemon: false });
  const home = path.join(work, 'kin-home');
  await assert.rejects(
    provision('9.9.9', { env: { KIN_HOME: home }, platform: 'darwin', arch: 'arm64', fetchImpl, log: () => {} }),
    /daemon-less/,
  );
  assert.ok(!fs.existsSync(path.join(home, 'bin', 'kin')));
  fs.rmSync(work, { recursive: true, force: true });
});

test('provision surfaces a failed download loudly', async () => {
  const fetchImpl = async () => ({ ok: false, status: 404, arrayBuffer: async () => new ArrayBuffer(0) });
  await assert.rejects(
    provision('9.9.9', { env: { KIN_HOME: '/nonexistent-home' }, platform: 'darwin', arch: 'arm64', fetchImpl, log: () => {} }),
    /download failed \(404\)/,
  );
});

test('probeBinaryVersion parses the kin version line and null on failure', () => {
  const okSpawn = () => ({ status: 0, stdout: 'kin 1.2.3 (abc detached)\n' });
  const badSpawn = () => ({ status: 1, stdout: '', stderr: 'boom' });
  assert.equal(probeBinaryVersion('/any', okSpawn), '1.2.3');
  assert.equal(probeBinaryVersion('/any', badSpawn), null);
});

test('ensureProvisioned respects KIN_MANAGED_BIN and never provisions over it', async () => {
  const real = process.execPath;
  const result = await ensureProvisioned({
    env: { KIN_MANAGED_BIN: real },
    fetchImpl: async () => {
      throw new Error('network must not be touched');
    },
    log: () => {},
  });
  assert.equal(result, real);
});

test('ensureProvisioned is resolve-only under KIN_NO_PROVISION', async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'kin-noprov-'));
  const result = await ensureProvisioned({
    env: { KIN_HOME: home, KIN_NO_PROVISION: '1' },
    fetchImpl: async () => {
      throw new Error('network must not be touched');
    },
    log: () => {},
  });
  assert.equal(result, null);
  fs.rmSync(home, { recursive: true, force: true });
});

test('ensureProvisioned runs a stamped current install without probing or network', async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'kin-stamped-'));
  const env = { KIN_HOME: home };
  const binDir = path.join(home, 'bin');
  fs.mkdirSync(binDir, { recursive: true });
  const { targetKinVersion } = await import('../lib/resolve.mjs');
  fs.writeFileSync(path.join(binDir, 'kin'), '#!/bin/sh\n');
  writeLauncherStamp(targetKinVersion(), env);
  const result = await ensureProvisioned({
    env,
    platform: process.platform,
    fetchImpl: async () => {
      throw new Error('network must not be touched');
    },
    spawnImpl: () => {
      throw new Error('probe must not run');
    },
    log: () => {},
  });
  assert.equal(result, path.join(binDir, 'kin'));
  fs.rmSync(home, { recursive: true, force: true });
});

// ── mismatch matrix ─────────────────────────────────────────────────────────
//
// ensureProvisioned's pin-vs-installed policy, exercised on both the stamped
// (this package provisioned it before; no probe needed) and foreign (probed
// via `--version`) code paths: an older install upgrades automatically, a
// newer install is refused loudly, an equal install just runs, and
// KIN_LAUNCHER_ADOPT=1 forces a re-provision regardless.

test('ensureProvisioned auto-provisions over an older foreign install (no ADOPT needed)', async () => {
  const { work, fetchImpl } = makeFixture();
  const home = path.join(work, 'kin-home');
  const env = { KIN_HOME: home };
  const binDir = path.join(home, 'bin');
  fs.mkdirSync(binDir, { recursive: true });
  fs.writeFileSync(path.join(binDir, 'kin'), '#!/bin/sh\n');
  const notices = [];
  const result = await ensureProvisioned({
    env,
    platform: 'darwin',
    arch: 'arm64',
    fetchImpl,
    spawnImpl: () => ({ status: 0, stdout: 'kin 0.0.1-foreign (x)\n' }),
    log: (line) => notices.push(line),
  });
  const { targetKinVersion } = await import('../lib/resolve.mjs');
  assert.equal(result, path.join(binDir, 'kin'));
  assert.match(fs.readFileSync(result, 'utf8'), /9\.9\.9/);
  assert.equal(readLauncherStamp(env), targetKinVersion());
  assert.ok(notices.some((l) => l.includes('older') && l.includes('upgrading automatically')));
  fs.rmSync(work, { recursive: true, force: true });
});

test('ensureProvisioned auto-provisions when a stamped install is older than the pin', async () => {
  const { work, fetchImpl } = makeFixture();
  const home = path.join(work, 'kin-home');
  const env = { KIN_HOME: home };
  const binDir = path.join(home, 'bin');
  fs.mkdirSync(binDir, { recursive: true });
  fs.writeFileSync(path.join(binDir, 'kin'), '#!/bin/sh\n');
  writeLauncherStamp('0.0.1', env);
  const notices = [];
  const result = await ensureProvisioned({
    env,
    platform: 'darwin',
    arch: 'arm64',
    fetchImpl,
    spawnImpl: () => {
      throw new Error('a stamped install must not be probed');
    },
    log: (line) => notices.push(line),
  });
  const { targetKinVersion } = await import('../lib/resolve.mjs');
  assert.equal(result, path.join(binDir, 'kin'));
  assert.match(fs.readFileSync(result, 'utf8'), /9\.9\.9/);
  assert.equal(readLauncherStamp(env), targetKinVersion());
  assert.ok(notices.some((l) => l.includes('older') && l.includes('upgrading automatically')));
  fs.rmSync(work, { recursive: true, force: true });
});

test('ensureProvisioned refuses to downgrade a newer foreign install (fail loud, no ADOPT)', async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'kin-newer-foreign-'));
  const env = { KIN_HOME: home };
  const binDir = path.join(home, 'bin');
  fs.mkdirSync(binDir, { recursive: true });
  fs.writeFileSync(path.join(binDir, 'kin'), '#!/bin/sh\n');
  await assert.rejects(
    ensureProvisioned({
      env,
      platform: process.platform,
      fetchImpl: async () => {
        throw new Error('must not provision when refusing a downgrade');
      },
      spawnImpl: () => ({ status: 0, stdout: 'kin 99.0.0 (newer)\n' }),
      log: () => {},
    }),
    /refusing to downgrade.*KIN_LAUNCHER_ADOPT=1/s,
  );
  assert.equal(readLauncherStamp(env), null);
  assert.ok(fs.existsSync(path.join(binDir, 'kin')), 'the existing binary must be left in place');
  fs.rmSync(home, { recursive: true, force: true });
});

test('ensureProvisioned refuses to downgrade when the stamp itself is newer than the pin', async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'kin-newer-stamped-'));
  const env = { KIN_HOME: home };
  const binDir = path.join(home, 'bin');
  fs.mkdirSync(binDir, { recursive: true });
  fs.writeFileSync(path.join(binDir, 'kin'), '#!/bin/sh\n');
  writeLauncherStamp('99.0.0', env);
  await assert.rejects(
    ensureProvisioned({
      env,
      platform: process.platform,
      fetchImpl: async () => {
        throw new Error('must not provision when refusing a downgrade');
      },
      spawnImpl: () => {
        throw new Error('a stamped install must not be probed');
      },
      log: () => {},
    }),
    /refusing to downgrade.*KIN_LAUNCHER_ADOPT=1/s,
  );
  assert.equal(readLauncherStamp(env), '99.0.0');
  fs.rmSync(home, { recursive: true, force: true });
});

test('ensureProvisioned adopts a foreign install when its version already matches the pin', async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'kin-foreign-equal-'));
  const env = { KIN_HOME: home };
  const binDir = path.join(home, 'bin');
  fs.mkdirSync(binDir, { recursive: true });
  fs.writeFileSync(path.join(binDir, 'kin'), '#!/bin/sh\n');
  const { targetKinVersion } = await import('../lib/resolve.mjs');
  const result = await ensureProvisioned({
    env,
    platform: process.platform,
    fetchImpl: async () => {
      throw new Error('must not provision when the foreign install already matches');
    },
    spawnImpl: () => ({ status: 0, stdout: `kin ${targetKinVersion()} (foreign)\n` }),
    log: () => {},
  });
  assert.equal(result, path.join(binDir, 'kin'));
  assert.equal(readLauncherStamp(env), targetKinVersion());
  fs.rmSync(home, { recursive: true, force: true });
});

test('KIN_LAUNCHER_ADOPT=1 forces re-provisioning even when the stamped version already matches', async () => {
  const { work, fetchImpl } = makeFixture();
  const home = path.join(work, 'kin-home');
  const env = { KIN_HOME: home, KIN_LAUNCHER_ADOPT: '1' };
  const binDir = path.join(home, 'bin');
  fs.mkdirSync(binDir, { recursive: true });
  fs.writeFileSync(path.join(binDir, 'kin'), '#!/bin/sh\n');
  const { targetKinVersion } = await import('../lib/resolve.mjs');
  writeLauncherStamp(targetKinVersion(), env);
  const result = await ensureProvisioned({
    env,
    platform: 'darwin',
    arch: 'arm64',
    fetchImpl,
    spawnImpl: () => {
      throw new Error('ADOPT must skip the probe and provision unconditionally');
    },
    log: () => {},
  });
  assert.equal(result, path.join(binDir, 'kin'));
  // Reprovisioned from the fixture archive, not the pre-existing stub.
  assert.match(fs.readFileSync(result, 'utf8'), /9\.9\.9/);
  fs.rmSync(work, { recursive: true, force: true });
});

test('KIN_LAUNCHER_ADOPT=1 forces the downgrade it would otherwise refuse', async () => {
  const { work, fetchImpl } = makeFixture();
  const home = path.join(work, 'kin-home');
  const env = { KIN_HOME: home, KIN_LAUNCHER_ADOPT: '1' };
  const binDir = path.join(home, 'bin');
  fs.mkdirSync(binDir, { recursive: true });
  fs.writeFileSync(path.join(binDir, 'kin'), '#!/bin/sh\n');
  writeLauncherStamp('99.0.0', env);
  const result = await ensureProvisioned({
    env,
    platform: 'darwin',
    arch: 'arm64',
    fetchImpl,
    spawnImpl: () => {
      throw new Error('ADOPT must skip the probe and provision unconditionally');
    },
    log: () => {},
  });
  assert.equal(result, path.join(binDir, 'kin'));
  assert.match(fs.readFileSync(result, 'utf8'), /9\.9\.9/);
  fs.rmSync(work, { recursive: true, force: true });
});
