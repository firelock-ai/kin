// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

import cp from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const packageJson = require('../package.json');

export const PACKAGE_VERSION = packageJson.version;
export const DEFAULT_RELEASE_BASE_URL =
  'https://github.com/firelock-ai/kin/releases/download';

export function resolveReleaseTag(version = PACKAGE_VERSION) {
  return version.startsWith('v') ? version : `v${version}`;
}

export function resolveReleaseAsset(platform = process.platform, arch = process.arch) {
  if (platform === 'darwin' && arch === 'arm64') {
    return { assetName: 'kin-macos-aarch64', binaryName: 'kin' };
  }
  if (platform === 'darwin' && arch === 'x64') {
    return { assetName: 'kin-macos-x86_64', binaryName: 'kin' };
  }
  if (platform === 'linux' && arch === 'x64') {
    return { assetName: 'kin-linux-x86_64', binaryName: 'kin' };
  }

  throw new Error(
    `kin-mcp does not have a published Kin binary for ${platform}/${arch} yet`
  );
}

export function resolveCacheRoot(
  env = process.env,
  platform = process.platform,
  homeDir = os.homedir()
) {
  if (env.KIN_MCP_CACHE_DIR) {
    return path.resolve(env.KIN_MCP_CACHE_DIR);
  }

  if (platform === 'darwin') {
    return path.join(homeDir, 'Library', 'Caches', 'kin-mcp');
  }

  if (platform === 'win32') {
    const localAppData = env.LOCALAPPDATA || path.join(homeDir, 'AppData', 'Local');
    return path.join(localAppData, 'kin-mcp', 'Cache');
  }

  const xdgCacheHome = env.XDG_CACHE_HOME || path.join(homeDir, '.cache');
  return path.join(xdgCacheHome, 'kin-mcp');
}

export function resolveCachedBinaryPath({
  env = process.env,
  platform = process.platform,
  arch = process.arch,
  version = PACKAGE_VERSION,
  homeDir = os.homedir(),
  cacheRoot
} = {}) {
  const { assetName, binaryName } = resolveReleaseAsset(platform, arch);
  const root = cacheRoot || resolveCacheRoot(env, platform, homeDir);
  return path.join(root, resolveReleaseTag(version), assetName, binaryName);
}

export async function ensureKinBinary({
  env = process.env,
  platform = process.platform,
  arch = process.arch,
  version = PACKAGE_VERSION,
  homeDir = os.homedir(),
  cacheRoot
} = {}) {
  const configuredBinary = env.KIN_MCP_KIN_BINARY || env.KIN_BINARY_PATH;
  if (configuredBinary) {
    const resolved = path.resolve(configuredBinary);
    await assertRunnable(resolved, platform);
    return resolved;
  }

  const binaryPath = resolveCachedBinaryPath({
    env,
    platform,
    arch,
    version,
    homeDir,
    cacheRoot
  });

  if (await isRunnable(binaryPath, platform)) {
    return binaryPath;
  }

  await installKinBinary({ binaryPath, env, platform, arch, version });
  return binaryPath;
}

export async function runKinMcp(argv = [], options = {}) {
  const stdout = options.stdout || process.stdout;
  const stderr = options.stderr || process.stderr;

  if (argv.includes('--help') || argv.includes('-h')) {
    stdout.write(renderHelp());
    return 0;
  }

  if (argv.includes('--version') || argv.includes('-v')) {
    stdout.write(`${PACKAGE_VERSION}\n`);
    return 0;
  }

  if (argv.includes('--print-bin')) {
    const binaryPath = await ensureKinBinary(options);
    stdout.write(`${binaryPath}\n`);
    return 0;
  }

  if (argv.length > 0) {
    stderr.write(
      'kin-mcp does not accept subcommands. It always runs `kin mcp start`.\n'
    );
    return 2;
  }

  const binaryPath = await ensureKinBinary(options);
  return spawnKin(binaryPath, ['mcp', 'start'], options);
}

function renderHelp() {
  return `kin-mcp ${PACKAGE_VERSION}

Usage:
  kin-mcp
  kin-mcp --print-bin
  kin-mcp --version

This wrapper downloads a matching Kin release binary on demand, caches it
locally, and then runs:

  kin mcp start

Environment:
  KIN_MCP_KIN_BINARY   Use a specific kin binary
  KIN_BINARY_PATH      Alias for KIN_MCP_KIN_BINARY
  KIN_MCP_CACHE_DIR    Override the cache directory
  KIN_MCP_RELEASE_BASE_URL
                       Override the release download base URL
`;
}

async function installKinBinary({ binaryPath, env, platform, arch, version }) {
  const { assetName } = resolveReleaseAsset(platform, arch);
  const tag = resolveReleaseTag(version);
  const baseUrl = (env.KIN_MCP_RELEASE_BASE_URL || DEFAULT_RELEASE_BASE_URL).replace(
    /\/$/,
    ''
  );
  const assetUrl = `${baseUrl}/${tag}/${assetName}`;
  const checksumUrl = `${assetUrl}.sha256`;

  await fsp.mkdir(path.dirname(binaryPath), { recursive: true });

  const checksumText = await fetchText(checksumUrl);
  const expectedSha = parseChecksum(checksumText);
  const binaryBytes = await fetchBytes(assetUrl);
  const actualSha = sha256(binaryBytes);

  if (actualSha !== expectedSha) {
    throw new Error(
      `checksum mismatch for ${assetName}: expected ${expectedSha}, got ${actualSha}`
    );
  }

  const tmpPath = `${binaryPath}.download`;
  try {
    await fsp.writeFile(tmpPath, binaryBytes, { mode: 0o755 });
    if (platform !== 'win32') {
      await fsp.chmod(tmpPath, 0o755);
    }
    await fsp.rename(tmpPath, binaryPath);
  } catch (error) {
    await fsp.unlink(tmpPath).catch(() => {});
    throw error;
  }
}

async function fetchText(url) {
  const response = await fetch(url, {
    headers: { 'user-agent': `kin-mcp/${PACKAGE_VERSION}` },
    signal: AbortSignal.timeout(60_000)
  });

  if (!response.ok) {
    throw new Error(`failed to download ${url}: ${response.status} ${response.statusText}`);
  }

  return response.text();
}

async function fetchBytes(url) {
  const response = await fetch(url, {
    headers: { 'user-agent': `kin-mcp/${PACKAGE_VERSION}` },
    signal: AbortSignal.timeout(120_000)
  });

  if (!response.ok) {
    throw new Error(`failed to download ${url}: ${response.status} ${response.statusText}`);
  }

  return Buffer.from(await response.arrayBuffer());
}

function parseChecksum(text) {
  const match = text.trim().match(/\b([a-fA-F0-9]{64})\b/);
  if (!match) {
    throw new Error('failed to parse SHA256 checksum from release metadata');
  }
  return match[1].toLowerCase();
}

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

async function assertRunnable(filePath, platform) {
  if (!(await isRunnable(filePath, platform))) {
    throw new Error(`kin binary not found or not executable: ${filePath}`);
  }
}

async function isRunnable(filePath, platform) {
  try {
    const mode = platform === 'win32' ? fs.constants.F_OK : fs.constants.X_OK;
    await fsp.access(filePath, mode);
    return true;
  } catch {
    return false;
  }
}

function spawnKin(binaryPath, args, options) {
  const env = options.env || process.env;

  return new Promise((resolve, reject) => {
    const child = cp.spawn(binaryPath, args, {
      cwd: options.cwd || process.cwd(),
      env,
      stdio: options.stdio || 'inherit'
    });

    const handlers = new Map();
    for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
      const handler = () => {
        if (!child.killed) {
          child.kill(signal);
        }
      };
      handlers.set(signal, handler);
      process.on(signal, handler);
    }

    const cleanup = () => {
      for (const [signal, handler] of handlers.entries()) {
        process.off(signal, handler);
      }
    };

    child.on('error', error => {
      cleanup();
      reject(error);
    });

    child.on('exit', (code, signal) => {
      cleanup();
      if (signal) {
        resolve(1);
        return;
      }
      resolve(code ?? 1);
    });
  });
}
