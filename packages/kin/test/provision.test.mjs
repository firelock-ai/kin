// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';

import {
  archiveExtraction,
  artifactName,
  releaseDownloadUrl,
  parseSha256File,
  sha256Hex,
  formatByteCount,
  formatDownloadProgress,
  createDownloadProgress,
  downloadToFile,
  provision,
  probeBinaryVersion,
  ensureProvisioned,
  isTruthyEnv,
  persistentPathAdvice,
} from '../lib/provision.mjs';
import { binaryName, readLauncherStamp, writeLauncherStamp } from '../lib/resolve.mjs';

// The native Windows job must execute the package suite, but NTFS does not
// expose the POSIX execute bits required to falsify a macOS app bundle. Those
// bundle-only assertions remain authoritative on macOS/Linux; Windows runs the
// native ZIP path and all platform-neutral provisioning policy below.
const macArchiveModeTest = process.platform === 'win32' ? test.skip : test;

// The archive layout is a property of the target; the extractor is a property
// of the host. Reading `process.platform` inside the target branch conflated
// them, and the native Windows leg went red on three tests that unpack a darwin
// archive on a Windows runner, where /usr/bin/tar does not exist. All four
// combinations are asserted here rather than only the two a single runner can
// reach, so neither leg has to be the place this is discovered.
test('the extractor is chosen by the host and the layout by the target', () => {
  const winEnv = { SystemRoot: 'C:\\Windows' };
  const sys32Tar = path.win32.join('C:\\Windows', 'System32', 'tar.exe');

  assert.deepEqual(archiveExtraction('win32', winEnv, 'a.zip', 'win32'), {
    executable: sys32Tar,
    args: ['-xf', 'a.zip', '-C', '.'],
  });
  assert.deepEqual(archiveExtraction('win32', {}, 'a.zip', 'darwin'), {
    executable: '/usr/bin/unzip',
    args: ['-q', 'a.zip', '-d', '.'],
  });

  // Unix target on a Windows host: the cross-target case, which must not reach
  // for /usr/bin.
  assert.deepEqual(archiveExtraction('darwin', winEnv, 'a.tar.gz', 'win32'), {
    executable: sys32Tar,
    args: ['-xf', 'a.tar.gz', '-C', '.'],
  });

  if (process.platform !== 'win32') {
    const unix = archiveExtraction('darwin', {}, 'a.tar.gz', 'darwin');
    assert.ok(
      unix.executable === '/usr/bin/tar' || unix.executable === '/bin/tar',
      `expected an absolute system tar, got ${unix.executable}`,
    );
    assert.deepEqual(unix.args, ['-xf', 'a.tar.gz', '-C', '.']);
  }
});

test('artifactName maps every released host and matches release.yml naming', () => {
  assert.equal(artifactName('darwin', 'arm64'), 'kin-macos-aarch64.tar.gz');
  assert.equal(artifactName('darwin', 'x64'), 'kin-macos-x86_64.tar.gz');
  assert.equal(artifactName('linux', 'arm64'), 'kin-linux-aarch64.tar.gz');
  assert.equal(artifactName('linux', 'x64'), 'kin-linux-x86_64.tar.gz');
  assert.equal(artifactName('win32', 'x64'), 'kin-windows-x86_64.zip');
});

test('launcher booleans accept the complete generated env-contract vocabulary', () => {
  for (const token of ['1', 'true', 'TRUE', 'TrUe', 'yes', 'YES', 'on', 'ON', ' on ']) {
    assert.equal(isTruthyEnv(token), true, token);
  }
  for (const token of ['', '0', 'false', 'no', 'off', 'truthy']) {
    assert.equal(isTruthyEnv(token), false, token);
  }
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

test('download progress reports stable bytes and percent', () => {
  assert.equal(formatByteCount(0), '0 B');
  assert.equal(formatByteCount(1536), '1.5 KiB');
  assert.equal(
    formatDownloadProgress('kin-test.tar.gz', 524288, 1048576),
    'kin: downloading kin-test.tar.gz: 50% (512.0 KiB / 1.0 MiB)',
  );
  assert.equal(
    formatDownloadProgress('kin-test.tar.gz', 1536),
    'kin: downloading kin-test.tar.gz: 1.5 KiB received',
  );
});

test('downloadToFile writes each chunk before pulling the next and never buffers the archive', async () => {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'kin-download-bounded-'));
  try {
    const destination = path.join(work, 'archive.tar.gz');
    const chunkSize = 64 * 1024;
    const chunkCount = 16;
    const expectedHash = crypto.createHash('sha256');
    const fetchImpl = async () => ({
      ok: true,
      status: 200,
      headers: { get: () => String(chunkSize * chunkCount) },
      body: (async function* boundedFixture() {
        for (let index = 0; index < chunkCount; index += 1) {
          const stagedBytes = fs.existsSync(destination) ? fs.statSync(destination).size : 0;
          assert.equal(
            stagedBytes,
            index * chunkSize,
            'the prior chunk must be flushed before the next pull',
          );
          const chunk = Buffer.alloc(chunkSize, index);
          expectedHash.update(chunk);
          yield chunk;
        }
      })(),
      arrayBuffer: async () => {
        throw new Error('streaming archive must not be accumulated through arrayBuffer()');
      },
    });

    const originalBufferFrom = Buffer.from;
    let result;
    try {
      Buffer.from = function rejectStreamChunkCopy(value, ...args) {
        if (ArrayBuffer.isView(value)) {
          throw new Error('stream chunks must be staged without an archive-sized copy');
        }
        return Reflect.apply(originalBufferFrom, this, [value, ...args]);
      };
      result = await downloadToFile('https://example.test/archive', destination, fetchImpl);
    } finally {
      Buffer.from = originalBufferFrom;
    }
    assert.equal(result.bytes, chunkSize * chunkCount);
    assert.equal(result.sha256, expectedHash.digest('hex'));
    assert.equal(fs.statSync(destination).size, chunkSize * chunkCount);
  } finally {
    fs.rmSync(work, { recursive: true, force: true });
  }
});

// ── offline provision fixture ──────────────────────────────────────────────
//
// Builds a real tar.gz in a tempdir (via the same `tar` the provisioner uses)
// containing the archive layout install.sh documents: a kin-* subdirectory
// with kin + kin-daemon. The fake fetch serves those bytes; no network.

function environmentValue(env, name) {
  const key = Object.keys(env).find(
    (candidate) => candidate.toLowerCase() === name.toLowerCase(),
  );
  return key === undefined ? undefined : env[key];
}

function windowsSystemTarPath(env = process.env) {
  const systemRoot = environmentValue(env, 'SystemRoot');
  assert.ok(systemRoot, 'native Windows ZIP fixtures require SystemRoot');
  return path.win32.join(systemRoot, 'System32', 'tar.exe');
}

function environmentWithHostileTar(work, overrides = {}) {
  const hostileBin = path.join(work, 'hostile-path');
  fs.mkdirSync(hostileBin, { recursive: true });
  const hostileTar = path.join(hostileBin, process.platform === 'win32' ? 'tar.exe' : 'tar');
  if (process.platform === 'win32') {
    fs.copyFileSync(process.execPath, hostileTar);
  } else {
    fs.writeFileSync(hostileTar, '#!/bin/sh\nexit 97\n', { mode: 0o755 });
  }

  const env = { ...process.env, ...overrides };
  const originalPath = environmentValue(env, 'PATH') || '';
  for (const name of Object.keys(env)) {
    if (name.toLowerCase() === 'path') delete env[name];
  }
  env.PATH = [hostileBin, originalPath].filter(Boolean).join(path.delimiter);
  return env;
}

function makeFixture({
  withDaemon = true,
  streamArchive = false,
  notifier = 'complete',
  notifierBody = 'notifier-v1',
} = {}) {
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
  const tar = spawnSync('tar', ['-czf', path.basename(archivePath), 'kin-macos-aarch64'], {
    cwd: work,
    encoding: 'utf8',
  });
  assert.equal(tar.status, 0, tar.stderr);
  const bytes = fs.readFileSync(archivePath);
  const sha = `${sha256Hex(bytes)}  kin-macos-aarch64.tar.gz\n`;
  const fetchImpl = async (url) => {
    const body = url.endsWith('.sha256') ? Buffer.from(sha) : bytes;
    if (streamArchive && !url.endsWith('.sha256')) {
      const split = Math.floor(body.length / 2);
      return {
        ok: true,
        status: 200,
        headers: {
          get: (name) => (name.toLowerCase() === 'content-length' ? String(body.length) : null),
        },
        body: (async function* streamFixture() {
          yield body.subarray(0, split);
          yield body.subarray(split);
        })(),
        arrayBuffer: async () => {
          throw new Error('streaming archive must not be buffered through arrayBuffer()');
        },
      };
    }
    return {
      ok: true,
      status: 200,
      arrayBuffer: async () => body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength),
    };
  };
  return { work, bytes, sha, fetchImpl };
}

function makeWindowsFixture({ streamArchive = false } = {}) {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'kin-prov-windows-fixture-'));
  const stage = path.join(work, 'stage');
  const archiveName = 'kin-windows-x86_64.zip';
  const archivePath = path.join(work, archiveName);
  const kinBytes = Buffer.from('native windows kin fixture 9.9.9');
  const daemonBytes = Buffer.from('native windows daemon fixture');
  fs.mkdirSync(stage, { recursive: true });
  fs.writeFileSync(path.join(stage, 'kin.exe'), kinBytes);
  fs.writeFileSync(path.join(stage, 'kin-daemon.exe'), daemonBytes);

  if (process.platform === 'win32') {
    const zipped = spawnSync(
      windowsSystemTarPath(),
      ['-a', '-c', '-f', `../${archiveName}`, 'kin.exe', 'kin-daemon.exe'],
      { cwd: stage, encoding: 'utf8' },
    );
    assert.equal(zipped.status, 0, zipped.stderr);
  } else {
    const zipped = spawnSync(
      '/usr/bin/zip',
      ['-q', `../${archiveName}`, 'kin.exe', 'kin-daemon.exe'],
      { cwd: stage, encoding: 'utf8' },
    );
    assert.equal(zipped.status, 0, zipped.stderr);
  }

  const bytes = fs.readFileSync(archivePath);
  assert.equal(bytes.subarray(0, 4).toString('hex'), '504b0304');
  const sha = `${sha256Hex(bytes)}  ${archiveName}\n`;
  const fetchImpl = async (url) => {
    const body = url.endsWith('.sha256') ? Buffer.from(sha) : bytes;
    if (streamArchive && !url.endsWith('.sha256')) {
      const split = Math.floor(body.length / 2);
      return {
        ok: true,
        status: 200,
        headers: {
          get: (name) => (name.toLowerCase() === 'content-length' ? String(body.length) : null),
        },
        body: (async function* streamFixture() {
          yield body.subarray(0, split);
          yield body.subarray(split);
        })(),
        arrayBuffer: async () => {
          throw new Error('streaming archive must not be buffered through arrayBuffer()');
        },
      };
    }
    return {
      ok: true,
      status: 200,
      arrayBuffer: async () => body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength),
    };
  };
  return { work, bytes, fetchImpl, kinBytes, daemonBytes };
}

function makeHostProvisionFixture(options = {}) {
  if (process.platform === 'win32') {
    return {
      ...makeWindowsFixture(options),
      platform: 'win32',
      arch: 'x64',
    };
  }
  return {
    ...makeFixture(options),
    platform: 'darwin',
    arch: 'arm64',
  };
}

test('provision verifies, installs kin + kin-daemon, and stamps the version', async () => {
  const { work, fetchImpl, platform, arch } = makeHostProvisionFixture();
  const home = path.join(work, 'kin-home');
  const env = { KIN_HOME: home };
  const installed = await provision('9.9.9', {
    env,
    platform,
    arch,
    fetchImpl,
    log: () => {},
  });
  assert.equal(installed, path.join(home, 'bin', binaryName('kin', platform)));
  assert.ok(fs.existsSync(path.join(home, 'bin', binaryName('kin', platform))));
  assert.ok(fs.existsSync(path.join(home, 'bin', binaryName('kin-daemon', platform))));
  if (process.platform !== 'win32') {
    assert.equal(fs.statSync(installed).mode & 0o111 && true, true);
  }
  assert.equal(readLauncherStamp(env), '9.9.9');
  fs.rmSync(work, { recursive: true, force: true });
});

test('provision uses deterministic Windows ZIP extraction under a hostile PATH', async () => {
  const { work, fetchImpl, kinBytes, daemonBytes } = makeWindowsFixture();
  const home = path.join(work, 'kin-home');
  const env = environmentWithHostileTar(work, { KIN_HOME: home });
  try {
    const installed = await provision('9.9.9', {
      env,
      platform: 'win32',
      arch: 'x64',
      fetchImpl,
      log: () => {},
    });
    assert.equal(installed, path.join(home, 'bin', 'kin.exe'));
    assert.deepEqual(fs.readFileSync(installed), kinBytes);
    assert.deepEqual(fs.readFileSync(path.join(home, 'bin', 'kin-daemon.exe')), daemonBytes);
    assert.equal(readLauncherStamp(env), '9.9.9');
  } finally {
    fs.rmSync(work, { recursive: true, force: true });
  }
});

// The Unix arm of the rule the Windows test above proves. `tar` was resolved
// through PATH, so a planted `tar` unpacked the archive whose SHA-256 had just
// been verified: the integrity check protected bytes an attacker's program
// then read. The hostile `tar` here exits 97, so this test is red against a
// PATH lookup and green against an absolute one.
macArchiveModeTest(
  'provision unpacks the Unix archive with an absolute tar under a hostile PATH',
  async () => {
    const { work, fetchImpl } = makeFixture();
    const home = path.join(work, 'kin-home');
    const env = environmentWithHostileTar(work, { KIN_HOME: home });
    try {
      const installed = await provision('9.9.9', {
        env,
        platform: 'darwin',
        arch: 'arm64',
        fetchImpl,
        log: () => {},
      });
      assert.equal(installed, path.join(home, 'bin', 'kin'));
      assert.ok(fs.existsSync(path.join(home, 'bin', 'kin-daemon')));
      assert.equal(readLauncherStamp(env), '9.9.9');
    } finally {
      fs.rmSync(work, { recursive: true, force: true });
    }
  },
);

test('provision streams live archive byte and percent progress without touching checksum semantics', async () => {
  const { work, bytes, fetchImpl, platform, arch } = makeHostProvisionFixture({
    streamArchive: true,
  });
  const home = path.join(work, 'kin-home');
  const progress = [];
  await provision('9.9.9', {
    env: { KIN_HOME: home },
    platform,
    arch,
    fetchImpl,
    log: () => {},
    onProgress: (event) => progress.push({ ...event }),
  });

  assert.ok(
    progress.some((event) => !event.done && event.received > 0 && event.received < bytes.length),
  );
  assert.deepEqual(progress.at(-1), {
    received: bytes.length,
    total: bytes.length,
    done: true,
  });
  fs.rmSync(work, { recursive: true, force: true });
});

test('a mid-stream failure clears and terminates the active TTY progress line', async () => {
  const { work, bytes, sha } = makeFixture();
  const home = path.join(work, 'kin-home');
  const writes = [];
  const progress = createDownloadProgress('kin-macos-aarch64.tar.gz', {
    write: (value) => writes.push(String(value)),
  });
  const fetchImpl = async (url) => {
    if (url.endsWith('.sha256')) {
      const body = Buffer.from(sha);
      return {
        ok: true,
        status: 200,
        arrayBuffer: async () => body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength),
      };
    }
    return {
      ok: true,
      status: 200,
      headers: { get: () => String(bytes.length) },
      body: (async function* failingFixture() {
        yield bytes.subarray(0, Math.max(1, Math.floor(bytes.length / 2)));
        throw new Error('simulated connection reset');
      })(),
      arrayBuffer: async () => {
        throw new Error('failing stream must not use arrayBuffer()');
      },
    };
  };

  await assert.rejects(
    provision('9.9.9', {
      env: { KIN_HOME: home },
      platform: 'darwin',
      arch: 'arm64',
      fetchImpl,
      log: () => {},
      onProgress: progress,
    }),
    /simulated connection reset/,
  );

  assert.match(writes[0], /kin: downloading kin-macos-aarch64\.tar\.gz:/);
  assert.equal(writes.at(-1), '\r\x1b[2K\n');
  const launcherOutput = `${writes.join('')}kin: provisioning failed: simulated connection reset\n`;
  assert.match(launcherOutput, /\r\x1b\[2K\nkin: provisioning failed:/);
  assert.ok(!fs.existsSync(path.join(home, 'bin', 'kin')));
  fs.rmSync(work, { recursive: true, force: true });
});

macArchiveModeTest('provision installs the macOS notification bundle so notifications post as Kin', async () => {
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

macArchiveModeTest('provision replaces a stale bundle whole rather than merging into it', async () => {
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

function seedExistingManagedInstall(home) {
  const env = { KIN_HOME: home };
  const binDir = path.join(home, 'bin');
  const bundle = path.join(home, 'lib', 'KinNotifier.app');
  fs.mkdirSync(path.join(bundle, 'Contents', 'MacOS'), { recursive: true });
  fs.mkdirSync(binDir, { recursive: true });
  fs.writeFileSync(path.join(binDir, 'kin'), 'old-kin');
  fs.writeFileSync(path.join(binDir, 'kin-daemon'), 'old-daemon');
  fs.writeFileSync(path.join(bundle, 'Contents', 'Info.plist'), '<plist>old</plist>');
  fs.writeFileSync(path.join(bundle, 'Contents', 'MacOS', 'KinNotifier'), 'old-notifier');
  writeLauncherStamp('8.8.8', env);
  return env;
}

async function assertMalformedBundleUpgradeIsPreflightOnly(notifier, expectedError) {
  const { work, fetchImpl } = makeFixture({ notifier });
  const home = path.join(work, 'kin-home');
  const env = seedExistingManagedInstall(home);

  await assert.rejects(
    provision('9.9.9', {
      env,
      platform: 'darwin',
      arch: 'arm64',
      fetchImpl,
      log: () => {},
    }),
    expectedError,
  );

  assert.equal(fs.readFileSync(path.join(home, 'bin', 'kin'), 'utf8'), 'old-kin');
  assert.equal(fs.readFileSync(path.join(home, 'bin', 'kin-daemon'), 'utf8'), 'old-daemon');
  assert.equal(
    fs.readFileSync(
      path.join(home, 'lib', 'KinNotifier.app', 'Contents', 'MacOS', 'KinNotifier'),
      'utf8',
    ),
    'old-notifier',
  );
  assert.equal(readLauncherStamp(env), '8.8.8');
  fs.rmSync(work, { recursive: true, force: true });
}

test('provision refuses an absent macOS bundle before mutating a previous install', async () => {
  await assertMalformedBundleUpgradeIsPreflightOnly('absent', /carries no KinNotifier\.app/);
});

macArchiveModeTest('provision refuses an incomplete macOS bundle before mutating a previous install', async () => {
  await assertMalformedBundleUpgradeIsPreflightOnly('no-plist', /missing Contents\/Info\.plist/);
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
  const kinName = binaryName('kin', process.platform);
  fs.mkdirSync(binDir, { recursive: true });
  const { targetKinVersion } = await import('../lib/resolve.mjs');
  fs.writeFileSync(path.join(binDir, kinName), '#!/bin/sh\n');
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
  assert.equal(result, path.join(binDir, kinName));
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
  const { work, fetchImpl, platform, arch } = makeHostProvisionFixture();
  const home = path.join(work, 'kin-home');
  const env = { KIN_HOME: home };
  const binDir = path.join(home, 'bin');
  const kinName = binaryName('kin', platform);
  fs.mkdirSync(binDir, { recursive: true });
  fs.writeFileSync(path.join(binDir, kinName), '#!/bin/sh\n');
  const notices = [];
  const result = await ensureProvisioned({
    env,
    platform,
    arch,
    fetchImpl,
    spawnImpl: () => ({ status: 0, stdout: 'kin 0.0.1-foreign (x)\n' }),
    log: (line) => notices.push(line),
  });
  const { targetKinVersion } = await import('../lib/resolve.mjs');
  assert.equal(result, path.join(binDir, kinName));
  assert.match(fs.readFileSync(result, 'utf8'), /9\.9\.9/);
  assert.equal(readLauncherStamp(env), targetKinVersion());
  assert.ok(notices.some((l) => l.includes('older') && l.includes('upgrading automatically')));
  fs.rmSync(work, { recursive: true, force: true });
});

test('ensureProvisioned auto-provisions when a stamped install is older than the pin', async () => {
  const { work, fetchImpl, platform, arch } = makeHostProvisionFixture();
  const home = path.join(work, 'kin-home');
  const env = { KIN_HOME: home };
  const binDir = path.join(home, 'bin');
  const kinName = binaryName('kin', platform);
  fs.mkdirSync(binDir, { recursive: true });
  fs.writeFileSync(path.join(binDir, kinName), '#!/bin/sh\n');
  writeLauncherStamp('0.0.1', env);
  const notices = [];
  const result = await ensureProvisioned({
    env,
    platform,
    arch,
    fetchImpl,
    spawnImpl: () => {
      throw new Error('a stamped install must not be probed');
    },
    log: (line) => notices.push(line),
  });
  const { targetKinVersion } = await import('../lib/resolve.mjs');
  assert.equal(result, path.join(binDir, kinName));
  assert.match(fs.readFileSync(result, 'utf8'), /9\.9\.9/);
  assert.equal(readLauncherStamp(env), targetKinVersion());
  assert.ok(notices.some((l) => l.includes('older') && l.includes('upgrading automatically')));
  fs.rmSync(work, { recursive: true, force: true });
});

test('ensureProvisioned refuses to downgrade a newer foreign install (fail loud, no ADOPT)', async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'kin-newer-foreign-'));
  const env = { KIN_HOME: home };
  const binDir = path.join(home, 'bin');
  const kinName = binaryName('kin', process.platform);
  fs.mkdirSync(binDir, { recursive: true });
  fs.writeFileSync(path.join(binDir, kinName), '#!/bin/sh\n');
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
  assert.ok(
    fs.existsSync(path.join(binDir, kinName)),
    'the existing binary must be left in place',
  );
  fs.rmSync(home, { recursive: true, force: true });
});

test('ensureProvisioned refuses to downgrade when the stamp itself is newer than the pin', async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'kin-newer-stamped-'));
  const env = { KIN_HOME: home };
  const binDir = path.join(home, 'bin');
  const kinName = binaryName('kin', process.platform);
  fs.mkdirSync(binDir, { recursive: true });
  fs.writeFileSync(path.join(binDir, kinName), '#!/bin/sh\n');
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
  const kinName = binaryName('kin', process.platform);
  fs.mkdirSync(binDir, { recursive: true });
  fs.writeFileSync(path.join(binDir, kinName), '#!/bin/sh\n');
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
  assert.equal(result, path.join(binDir, kinName));
  assert.equal(readLauncherStamp(env), targetKinVersion());
  fs.rmSync(home, { recursive: true, force: true });
});

test('KIN_LAUNCHER_ADOPT=1 forces re-provisioning even when the stamped version already matches', async () => {
  const { work, fetchImpl, platform, arch } = makeHostProvisionFixture();
  const home = path.join(work, 'kin-home');
  const env = { KIN_HOME: home, KIN_LAUNCHER_ADOPT: '1' };
  const binDir = path.join(home, 'bin');
  const kinName = binaryName('kin', platform);
  fs.mkdirSync(binDir, { recursive: true });
  fs.writeFileSync(path.join(binDir, kinName), '#!/bin/sh\n');
  const { targetKinVersion } = await import('../lib/resolve.mjs');
  writeLauncherStamp(targetKinVersion(), env);
  const result = await ensureProvisioned({
    env,
    platform,
    arch,
    fetchImpl,
    spawnImpl: () => {
      throw new Error('ADOPT must skip the probe and provision unconditionally');
    },
    log: () => {},
  });
  assert.equal(result, path.join(binDir, kinName));
  // Reprovisioned from the fixture archive, not the pre-existing stub.
  assert.match(fs.readFileSync(result, 'utf8'), /9\.9\.9/);
  fs.rmSync(work, { recursive: true, force: true });
});

test('KIN_LAUNCHER_ADOPT=1 forces the downgrade it would otherwise refuse', async () => {
  const { work, fetchImpl, platform, arch } = makeHostProvisionFixture();
  const home = path.join(work, 'kin-home');
  const env = { KIN_HOME: home, KIN_LAUNCHER_ADOPT: '1' };
  const binDir = path.join(home, 'bin');
  const kinName = binaryName('kin', platform);
  fs.mkdirSync(binDir, { recursive: true });
  fs.writeFileSync(path.join(binDir, kinName), '#!/bin/sh\n');
  writeLauncherStamp('99.0.0', env);
  const result = await ensureProvisioned({
    env,
    platform,
    arch,
    fetchImpl,
    spawnImpl: () => {
      throw new Error('ADOPT must skip the probe and provision unconditionally');
    },
    log: () => {},
  });
  assert.equal(result, path.join(binDir, kinName));
  assert.match(fs.readFileSync(result, 'utf8'), /9\.9\.9/);
  fs.rmSync(work, { recursive: true, force: true });
});

// FIR-2628. `npm install -g` dies with EACCES on a root-owned global prefix,
// and the death happens inside npm before this package is unpacked, so nothing
// here can intercept it. The recovery Kin can offer is the install that needs
// no prefix at all, and this is the one moment its own code runs to say so.
test('a first provision names the persistent no-root install when PATH cannot see it', async () => {
  const { work, fetchImpl, platform, arch } = makeHostProvisionFixture();
  const home = path.join(work, 'kin-home');
  const lines = [];
  await provision('9.9.9', {
    env: { KIN_HOME: home, PATH: '/usr/bin:/bin' },
    platform,
    arch,
    fetchImpl,
    log: (line) => lines.push(line),
  });
  const said = lines.join('\n');
  const binDir = path.join(home, 'bin');

  // Positive control: the install line itself must be there, or this test is
  // asserting about a provision that never ran.
  assert.match(said, /managed kin 9\.9\.9 installed at/);

  assert.ok(said.includes(binDir), `the advice must name the directory: ${said}`);
  assert.match(said, /export PATH=/);
  assert.match(said, /needs no root and no writable npm prefix/);
  assert.match(said, /kin setup/);
  fs.rmSync(work, { recursive: true, force: true });
});

test('a provision into a directory already on PATH says nothing extra', async () => {
  const { work, fetchImpl, platform, arch } = makeHostProvisionFixture();
  const home = path.join(work, 'kin-home');
  const binDir = path.join(home, 'bin');
  const lines = [];
  await provision('9.9.9', {
    env: { KIN_HOME: home, PATH: `/usr/bin${path.delimiter}${binDir}` },
    platform,
    arch,
    fetchImpl,
    log: (line) => lines.push(line),
  });
  const said = lines.join('\n');
  assert.match(said, /managed kin 9\.9\.9 installed at/);
  assert.equal(/export PATH=/.test(said), false, `no advice was needed: ${said}`);
  fs.rmSync(work, { recursive: true, force: true });
});

test('persistentPathAdvice compares resolved paths, not spellings', () => {
  const dir = path.join(os.tmpdir(), 'kin-advice-fixture', 'bin');
  assert.deepEqual(persistentPathAdvice(dir, { PATH: dir }), []);
  assert.deepEqual(
    persistentPathAdvice(dir, { PATH: path.join(dir, '..', 'bin') }),
    [],
    'a path that resolves to the same directory is the same directory',
  );
  assert.ok(
    persistentPathAdvice(dir, { PATH: '/usr/bin' }).length > 0,
    'a PATH that does not carry it must produce advice',
  );
  assert.ok(
    persistentPathAdvice(dir, {}).length > 0,
    'an absent PATH is not evidence the directory is reachable',
  );
});
