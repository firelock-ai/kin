import assert from 'node:assert/strict';
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

test('resolveReleaseAsset maps supported targets', () => {
  assert.deepEqual(resolveReleaseAsset('darwin', 'arm64'), {
    assetName: 'kin-macos-aarch64',
    binaryName: 'kin'
  });
  assert.deepEqual(resolveReleaseAsset('darwin', 'x64'), {
    assetName: 'kin-macos-x86_64',
    binaryName: 'kin'
  });
  assert.deepEqual(resolveReleaseAsset('linux', 'x64'), {
    assetName: 'kin-linux-x86_64',
    binaryName: 'kin'
  });
});

test('resolveReleaseAsset rejects unsupported targets', () => {
  assert.throws(
    () => resolveReleaseAsset('linux', 'arm64'),
    /does not have a published Kin binary/
  );
});

test('resolveReleaseTag prefixes versions with v', () => {
  assert.equal(resolveReleaseTag('0.1.0'), 'v0.1.0');
  assert.equal(resolveReleaseTag('v0.1.0-alpha.1'), 'v0.1.0-alpha.1');
});

test('ensureKinBinary downloads and verifies a release asset', async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'kin-mcp-download-'));
  const assetBytes = Buffer.from('#!/bin/sh\necho kin\n', 'utf8');
  const checksum = crypto.createHash('sha256').update(assetBytes).digest('hex');
  const version = '9.9.9-test';

  const server = http.createServer((req, res) => {
    if (req.url === `/v${version}/kin-linux-x86_64`) {
      res.writeHead(200, { 'content-type': 'application/octet-stream' });
      res.end(assetBytes);
      return;
    }

    if (req.url === `/v${version}/kin-linux-x86_64.sha256`) {
      res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
      res.end(`${checksum}  kin-linux-x86_64\n`);
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

  try {
    const exitCode = await runKinMcp([], {
      env: { KIN_MCP_KIN_BINARY: binaryPath },
      stdio: 'ignore'
    });

    assert.equal(exitCode, 0);
    assert.equal(await fs.readFile(argsPath, 'utf8'), 'mcp\nstart\n');
  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});
