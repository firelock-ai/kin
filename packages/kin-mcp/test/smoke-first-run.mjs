// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

// End-to-end first-run proof for the @kinlab/kin-mcp wrapper.
//
// Stages release `kin` + `kin-daemon` binaries into a wrapper-style cache (no
// pre-existing daemon, no dev PATH state), initializes a throwaway repo, runs
// the wrapper, and drives the MCP stdio protocol far enough to call one safe
// Kin semantic tool (`kin_graph_status`). Exits non-zero on any failure.
//
// Usage:
//   node test/smoke-first-run.mjs                 # auto-locate target/release
//   KIN_BIN=/path/kin KIN_DAEMON_BIN=/path/kin-daemon node test/smoke-first-run.mjs
//
// The script is intentionally not part of `npm test`: it requires built Kin
// binaries and spawns a real daemon, so it runs on demand / in release CI.

import cp from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { resolveCachedBinaryPath, resolveReleaseAsset } from '../src/index.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const packageDir = path.dirname(here);
const repoRoot = path.resolve(packageDir, '..', '..');

function log(message) {
  process.stderr.write(`[smoke] ${message}\n`);
}

function productEnv() {
  const env = { ...process.env };
  delete env.KIN_BIN;
  delete env.KIN_DAEMON_BIN;
  return env;
}

function gitFixtureEnv() {
  const env = {
    ...process.env,
    GIT_CONFIG_GLOBAL: os.devNull,
    GIT_CONFIG_NOSYSTEM: '1'
  };
  for (const key of [
    'GIT_ALTERNATE_OBJECT_DIRECTORIES',
    'GIT_COMMON_DIR',
    'GIT_DIR',
    'GIT_INDEX_FILE',
    'GIT_OBJECT_DIRECTORY',
    'GIT_WORK_TREE'
  ]) {
    delete env[key];
  }
  return env;
}

function runGit(repoDir, args) {
  cp.execFileSync('git', args, {
    cwd: repoDir,
    env: gitFixtureEnv(),
    stdio: 'inherit'
  });
}

function initializeGitFixture(repoDir) {
  runGit(repoDir, ['init', '--initial-branch=main', '.']);
  runGit(repoDir, ['config', '--local', 'user.name', 'Kin MCP Smoke']);
  runGit(repoDir, ['config', '--local', 'user.email', 'kin-mcp-smoke@localhost']);
  runGit(repoDir, ['config', '--local', 'commit.gpgSign', 'false']);
  runGit(repoDir, ['config', '--local', 'core.autocrlf', 'false']);
  runGit(repoDir, ['add', '--', 'main.rs']);
  runGit(repoDir, ['commit', '-m', 'Seed Kin MCP smoke fixture']);
}

async function isFile(candidate) {
  try {
    const stat = await fs.stat(candidate);
    return stat.isFile();
  } catch {
    return false;
  }
}

async function locateBinary(envKey, name) {
  const explicit = process.env[envKey];
  if (explicit) {
    if (!(await isFile(explicit))) {
      throw new Error(`${envKey}=${explicit} is not a file`);
    }
    return explicit;
  }
  for (const profile of ['release', 'debug']) {
    const candidate = path.join(repoRoot, 'target', profile, name);
    if (await isFile(candidate)) {
      return candidate;
    }
  }
  throw new Error(
    `could not find ${name}; build it (cargo build --release -p kin-cli -p kin-daemon) ` +
      `or set ${envKey}`
  );
}

async function stageCache(cacheRoot, kinBin, daemonBin) {
  const { assetName } = resolveReleaseAsset();
  const cachedKin = resolveCachedBinaryPath({
    env: { KIN_MCP_CACHE_DIR: cacheRoot }
  });
  const assetDir = path.dirname(cachedKin);
  await fs.mkdir(assetDir, { recursive: true });
  await fs.copyFile(kinBin, cachedKin);
  await fs.chmod(cachedKin, 0o755);
  const cachedDaemon = path.join(assetDir, 'kin-daemon');
  await fs.copyFile(daemonBin, cachedDaemon);
  await fs.chmod(cachedDaemon, 0o755);
  log(`staged cache: ${assetName}/{kin,kin-daemon}`);
  return cachedKin;
}

function framedRequest(id, method, params) {
  return `${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`;
}

class JsonRpcReader {
  constructor() {
    this.buffer = '';
    this.waiters = new Map();
  }

  feed(chunk) {
    this.buffer += chunk;
    let newline;
    while ((newline = this.buffer.indexOf('\n')) >= 0) {
      const line = this.buffer.slice(0, newline).trim();
      this.buffer = this.buffer.slice(newline + 1);
      if (!line) {
        continue;
      }
      let message;
      try {
        message = JSON.parse(line);
      } catch {
        continue;
      }
      if (message.id != null && this.waiters.has(message.id)) {
        const { resolve } = this.waiters.get(message.id);
        this.waiters.delete(message.id);
        resolve(message);
      }
    }
  }

  await(id, timeoutMs) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.waiters.delete(id);
        reject(new Error(`timed out waiting for response id=${id}`));
      }, timeoutMs);
      this.waiters.set(id, {
        resolve: message => {
          clearTimeout(timer);
          resolve(message);
        }
      });
    });
  }
}

function killPid(pid) {
  if (Number.isInteger(pid) && pid > 0) {
    try {
      process.kill(pid, 'SIGTERM');
    } catch {
      // already gone
    }
  }
}

async function killTree(child, kinRoot, cacheRoot) {
  try {
    const pidText = await fs.readFile(path.join(kinRoot, 'daemon.pid'), 'utf8');
    killPid(Number.parseInt(pidText.trim(), 10));
  } catch {
    // no daemon.pid; nothing to clean
  }

  // Tear down the supervisor (and any other daemon) this run spawned from the
  // throwaway cache so the smoke leaves no background processes behind.
  try {
    const listing = cp.execFileSync('ps', ['-Ao', 'pid=,command='], {
      encoding: 'utf8'
    });
    for (const line of listing.split('\n')) {
      const match = line.trim().match(/^(\d+)\s+(.*)$/);
      if (match && match[2].includes(cacheRoot)) {
        killPid(Number.parseInt(match[1], 10));
      }
    }
  } catch {
    // ps unavailable; idle timeout will reap the supervisor
  }

  if (!child.killed) {
    child.kill('SIGTERM');
  }
}

async function main() {
  const kinBin = await locateBinary('KIN_BIN', 'kin');
  const daemonBin = await locateBinary('KIN_DAEMON_BIN', 'kin-daemon');
  log(`kin: ${kinBin}`);
  log(`kin-daemon: ${daemonBin}`);

  const workRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'kin-mcp-smoke-'));
  const cacheRoot = path.join(workRoot, 'cache');
  const repoDir = path.join(workRoot, 'repo');
  await fs.mkdir(repoDir, { recursive: true });
  await fs.writeFile(
    path.join(repoDir, 'main.rs'),
    'fn greet() -> &\'static str {\n    "hello kin"\n}\n'
  );
  initializeGitFixture(repoDir);

  await stageCache(cacheRoot, kinBin, daemonBin);

  // Explicit first-run init (no silent init): use the cached kin directly.
  const cachedKin = resolveCachedBinaryPath({
    env: { KIN_MCP_CACHE_DIR: cacheRoot }
  });
  log('kin init . (explicit first-run)');
  cp.execFileSync(cachedKin, ['init', '.'], {
    cwd: repoDir,
    env: productEnv(),
    stdio: 'inherit'
  });

  const wrapperBin = path.join(packageDir, 'bin', 'kin-mcp.js');
  const env = {
    ...productEnv(),
    KIN_MCP_CACHE_DIR: cacheRoot,
    KIN_DAEMON_IDLE_TIMEOUT_SECS: '30',
    KIN_SUPERVISOR_IDLE_TIMEOUT_SECS: '30'
  };
  // Prove no reliance on a stale PATH binary or pre-existing daemon: scrub
  // any daemon discovery hints the wrapper would otherwise inherit.
  delete env.KIN_DAEMON_BIN;
  delete env.KIN_DAEMON_URL;
  delete env.KIN_SUPERVISOR_URL;
  delete env.KIN_MCP_KIN_BINARY;
  delete env.KIN_BINARY_PATH;

  log('starting wrapper (kin-mcp -> kin mcp start), auto-spawning daemon...');
  const child = cp.spawn(process.execPath, [wrapperBin], {
    cwd: repoDir,
    env,
    stdio: ['pipe', 'pipe', 'inherit']
  });

  const reader = new JsonRpcReader();
  child.stdout.setEncoding('utf8');
  child.stdout.on('data', chunk => reader.feed(chunk));

  let exitInfo = null;
  child.on('exit', (code, signal) => {
    exitInfo = { code, signal };
  });

  const timeoutMs = 180_000;
  try {
    child.stdin.write(
      framedRequest(1, 'initialize', {
        protocolVersion: '2024-11-05',
        capabilities: {},
        clientInfo: { name: 'kin-mcp-smoke', version: '0.0.0' }
      })
    );
    const initResponse = await reader.await(1, timeoutMs);
    if (initResponse.error) {
      throw new Error(`initialize failed: ${JSON.stringify(initResponse.error)}`);
    }
    log('initialize ok');

    child.stdin.write(framedRequest(2, 'tools/list', {}));
    const listResponse = await reader.await(2, timeoutMs);
    const tools = listResponse.result?.tools ?? [];
    const toolNames = tools.map(tool => tool.name).sort();
    log(`tools/list returned ${toolNames.length} tools (agent-default profile expected)`);
    if (!toolNames.includes('kin_graph_status')) {
      throw new Error(`kin_graph_status missing from tools/list: ${toolNames.join(', ')}`);
    }
    if (toolNames.length > 20) {
      throw new Error(
        `expected the small agent-default surface, got ${toolNames.length} tools`
      );
    }

    child.stdin.write(
      framedRequest(3, 'tools/call', { name: 'kin_graph_status', arguments: {} })
    );
    const callResponse = await reader.await(3, timeoutMs);
    if (callResponse.error) {
      throw new Error(`kin_graph_status failed: ${JSON.stringify(callResponse.error)}`);
    }
    const content = callResponse.result?.content ?? [];
    const text = content.map(part => part.text ?? '').join('\n');
    if (callResponse.result?.isError) {
      throw new Error(`kin_graph_status returned an error result: ${text}`);
    }
    log('tools/call kin_graph_status ok');
    log(`status payload (first 400 chars): ${text.slice(0, 400)}`);

    process.stdout.write('SMOKE PASS: kin-mcp first-run reached a safe semantic tool\n');
    process.stdout.write(
      `SMOKE DETAIL: tools=${toolNames.length} sample=${toolNames.slice(0, 5).join(',')}\n`
    );
  } finally {
    await killTree(child, path.join(repoDir, '.kin'), cacheRoot);
    await fs.rm(workRoot, { recursive: true, force: true }).catch(() => {});
    void exitInfo;
  }
}

main().catch(error => {
  process.stderr.write(`SMOKE FAIL: ${error.message}\n`);
  process.exit(1);
});
