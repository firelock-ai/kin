import assert from 'node:assert/strict';
import cp from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  ensureKinBinary,
  resolveCachedBinaryPath,
  resolveReleaseAsset,
  resolveReleaseTag,
  runKinMcp
} from '../src/index.js';

async function exists(filePath) {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

test('resolveReleaseAsset maps supported targets', () => {
  assert.deepEqual(resolveReleaseAsset('darwin', 'arm64'), {
    assetName: 'kin-macos-aarch64',
    archiveName: 'kin-macos-aarch64.tar.gz',
    binaryName: 'kin'
  });
  assert.deepEqual(resolveReleaseAsset('darwin', 'x64'), {
    assetName: 'kin-macos-x86_64',
    archiveName: 'kin-macos-x86_64.tar.gz',
    binaryName: 'kin'
  });
  assert.deepEqual(resolveReleaseAsset('linux', 'x64'), {
    assetName: 'kin-linux-x86_64',
    archiveName: 'kin-linux-x86_64.tar.gz',
    binaryName: 'kin'
  });
  assert.deepEqual(resolveReleaseAsset('linux', 'arm64'), {
    assetName: 'kin-linux-aarch64',
    archiveName: 'kin-linux-aarch64.tar.gz',
    binaryName: 'kin'
  });
});

test('resolveReleaseAsset rejects unsupported targets', () => {
  assert.throws(
    () => resolveReleaseAsset('win32', 'x64'),
    /does not have a published Kin binary/
  );
});

test('resolveReleaseTag prefixes versions with v', () => {
  assert.equal(resolveReleaseTag('0.1.0'), 'v0.1.0');
  assert.equal(resolveReleaseTag('v0.1.0-alpha.1'), 'v0.1.0-alpha.1');
});

test('ensureKinBinary downloads and verifies a release asset', async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'kin-mcp-download-'));
  const assetName = 'kin-linux-x86_64';
  const assetBytes = Buffer.from('#!/bin/sh\necho kin\n', 'utf8');
  const packageDir = path.join(tmpDir, assetName);
  const archivePath = path.join(tmpDir, `${assetName}.tar.gz`);
  const version = '9.9.9-test';

  await fs.mkdir(packageDir);
  await fs.writeFile(path.join(packageDir, 'kin'), assetBytes, { mode: 0o755 });
  cp.execFileSync('tar', ['-czf', archivePath, '-C', tmpDir, assetName]);

  const archiveBytes = await fs.readFile(archivePath);
  const checksum = crypto.createHash('sha256').update(archiveBytes).digest('hex');

  const server = http.createServer((req, res) => {
    if (req.url === `/v${version}/${assetName}.tar.gz`) {
      res.writeHead(200, { 'content-type': 'application/octet-stream' });
      res.end(archiveBytes);
      return;
    }

    if (req.url === `/v${version}/${assetName}.tar.gz.sha256`) {
      res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
      res.end(`${checksum}  ${assetName}.tar.gz\n`);
      return;
    }

    res.writeHead(404);
    res.end('not found');
  });

  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;
  const env = {
    KIN_MCP_CACHE_DIR: tmpDir,
    KIN_MCP_RELEASE_BASE_URL: baseUrl
  };

  try {
    const binaryPath = await ensureKinBinary({
      env,
      platform: 'linux',
      arch: 'x64',
      version
    });

    assert.equal(
      binaryPath,
      resolveCachedBinaryPath({
        env,
        platform: 'linux',
        arch: 'x64',
        version
      })
    );
    assert.equal(await fs.readFile(binaryPath, 'utf8'), assetBytes.toString('utf8'));
  } finally {
    await new Promise(resolve => server.close(resolve));
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});

test('runKinMcp invokes kin mcp start', async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'kin-mcp-run-'));
  const binaryPath = path.join(tmpDir, 'kin');
  const argsPath = path.join(tmpDir, 'args.txt');
  const script = `#!/bin/sh
printf '%s\\n' "$@" > "${argsPath}"
`;

  await fs.writeFile(binaryPath, script, { mode: 0o755 });
  // Pre-create .kin/ so auto-init is skipped
  await fs.mkdir(path.join(tmpDir, '.kin'));

  try {
    const discard = { write() {} };
    const exitCode = await runKinMcp([], {
      env: { KIN_MCP_KIN_BINARY: binaryPath },
      cwd: tmpDir,
      stdout: discard,
      stderr: discard,
      stdio: 'ignore'
    });

    assert.equal(exitCode, 0);
    assert.equal(await fs.readFile(argsPath, 'utf8'), 'mcp\nstart\n');
  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});

test('runKinMcp refuses implicit init when .kin/ is missing', async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'kin-mcp-no-autoinit-'));
  const binaryPath = path.join(tmpDir, 'kin');
  await fs.writeFile(binaryPath, '#!/bin/sh\nexit 0\n', { mode: 0o755 });

  try {
    let stderr = '';
    const exitCode = await runKinMcp([], {
      env: { KIN_MCP_KIN_BINARY: binaryPath },
      cwd: tmpDir,
      stderr: { write(chunk) { stderr += chunk; } },
      stdio: 'ignore'
    });

    assert.equal(exitCode, 2);
    assert.match(stderr, /Run `kin init \.` first/);
    assert.equal(await exists(path.join(tmpDir, '.kin')), false);
  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});

test('runKinMcp auto-inits when explicitly allowed', async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'kin-mcp-autoinit-'));
  const binaryPath = path.join(tmpDir, 'kin');
  const logPath = path.join(tmpDir, 'calls.txt');
  await fs.writeFile(
    binaryPath,
    [
      '#!/bin/sh',
      `printf '%s\\n' "$@" >> "${logPath}"`,
      `if [ "$1" = "init" ]; then mkdir -p "${tmpDir}/.kin"; fi`,
      ''
    ].join('\n'),
    { mode: 0o755 }
  );

  try {
    const exitCode = await runKinMcp([], {
      env: { KIN_MCP_KIN_BINARY: binaryPath, KIN_MCP_AUTO_INIT: '1' },
      cwd: tmpDir,
      stdio: 'ignore'
    });

    assert.equal(exitCode, 0);
    const calls = await fs.readFile(logPath, 'utf8');
    const initPos = calls.indexOf('init\n.');
    const mcpPos = calls.indexOf('mcp\nstart');
    assert.ok(initPos >= 0, 'expected kin init . call');
    assert.ok(mcpPos >= 0, 'expected kin mcp start call');
    assert.ok(initPos < mcpPos, 'init should run before mcp start');
  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});
