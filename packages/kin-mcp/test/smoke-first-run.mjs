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
import { constants as fsConstants, mkdtempSync, writeFileSync } from 'node:fs';
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

function envNameEquals(actual, expected, platform = process.platform) {
  return platform === 'win32'
    ? actual.toLowerCase() === expected.toLowerCase()
    : actual === expected;
}

function envNameStartsWith(actual, expected, platform = process.platform) {
  if (platform === 'win32') {
    return actual.slice(0, expected.length).toLowerCase() === expected.toLowerCase();
  }
  return actual.startsWith(expected);
}

function readEnv(env, name, platform = process.platform) {
  if (Object.hasOwn(env, name)) {
    return env[name];
  }
  const match = Object.keys(env).find(key => envNameEquals(key, name, platform));
  return match === undefined ? undefined : env[match];
}

function isInheritedAuthority(name, platform = process.platform) {
  return (
    envNameStartsWith(name, 'GIT_', platform) ||
    envNameStartsWith(name, 'KIN_', platform) ||
    envNameStartsWith(name, '_KIN_', platform) ||
    envNameStartsWith(name, 'DYLD_', platform) ||
    envNameStartsWith(name, 'LD_', platform) ||
    envNameEquals(name, 'EMAIL', platform) ||
    envNameEquals(name, 'SSH_ASKPASS', platform) ||
    envNameEquals(name, 'SSH_ASKPASS_REQUIRE', platform) ||
    envNameEquals(name, 'SSH_AUTH_SOCK', platform) ||
    envNameEquals(name, 'PATH', platform) ||
    envNameEquals(name, 'HOME', platform) ||
    envNameEquals(name, 'USERPROFILE', platform) ||
    envNameEquals(name, 'XDG_CONFIG_HOME', platform)
  );
}

export function absoluteHostPath({
  env = process.env,
  cwd = process.cwd(),
  platform = process.platform
} = {}) {
  const pathApi = platform === 'win32' ? path.win32 : path.posix;
  const delimiter = platform === 'win32' ? ';' : ':';
  const raw =
    readEnv(env, 'KIN_ORIGINAL_PATH', platform) ||
    readEnv(env, 'PATH', platform) ||
    '';
  return raw
    .split(delimiter)
    .map(entry => {
      const candidate = entry || '.';
      return pathApi.isAbsolute(candidate)
        ? pathApi.normalize(candidate)
        : pathApi.resolve(cwd, candidate);
    })
    .join(delimiter);
}

let windowsEmptyGlobalGitConfig = null;

/**
 * Path to bind to `GIT_CONFIG_GLOBAL` so Git resolves the global configuration
 * scope to no configuration at all.
 *
 * Off Windows this is `os.devNull` — `/dev/null`, which Git opens and reads as
 * an empty file. On Windows `os.devNull` is the reserved `NUL` device rather
 * than a file, and Git refuses it with
 * `fatal: unable to access 'NUL': Invalid argument`, failing every Git command
 * the boundary was meant to isolate. Git accepts any readable file, so Windows
 * gets one real empty file instead, created once per process and reused after
 * that so it outlives any single child.
 *
 * `platform` is a parameter rather than a read of `process.platform` so tests
 * can exercise the Windows branch — and therefore really create and check the
 * file — on any host.
 */
export function emptyGlobalGitConfig(platform = process.platform) {
  if (platform !== 'win32') {
    return os.devNull;
  }
  if (windowsEmptyGlobalGitConfig === null) {
    const directory = mkdtempSync(path.join(os.tmpdir(), 'kin-empty-global-gitconfig-'));
    windowsEmptyGlobalGitConfig = path.join(directory, 'gitconfig');
    writeFileSync(windowsEmptyGlobalGitConfig, '');
  }
  return windowsEmptyGlobalGitConfig;
}

export function hermeticSmokeEnv({
  sourceEnv = process.env,
  hostPath,
  homeDir,
  xdgDir,
  platform = process.platform
}) {
  const env = {};
  for (const [name, value] of Object.entries(sourceEnv)) {
    if (!isInheritedAuthority(name, platform)) {
      env[name] = value;
    }
  }

  Object.assign(env, {
    GIT_CONFIG_GLOBAL: emptyGlobalGitConfig(platform),
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_ATTR_NOSYSTEM: '1',
    GIT_TERMINAL_PROMPT: '0',
    GIT_PAGER: 'cat',
    GIT_ALLOW_PROTOCOL: 'file',
    GIT_PROTOCOL_FROM_USER: '0',
    PATH: hostPath,
    KIN_VFS_DISABLE: '1',
    HOME: homeDir,
    USERPROFILE: homeDir,
    XDG_CONFIG_HOME: xdgDir
  });
  return env;
}

async function isExecutableFile(candidate, platform) {
  try {
    const stat = await fs.stat(candidate);
    if (!stat.isFile()) {
      return false;
    }
    if (platform !== 'win32') {
      await fs.access(candidate, fsConstants.X_OK);
    }
    return true;
  } catch {
    return false;
  }
}

export async function resolveHostGit({
  hostPath,
  cwd = process.cwd(),
  platform = process.platform
}) {
  const pathApi = platform === 'win32' ? path.win32 : path.posix;
  const delimiter = platform === 'win32' ? ';' : ':';
  const executableNames = platform === 'win32' ? ['git.exe', 'git'] : ['git'];
  for (const entry of hostPath.split(delimiter)) {
    if (!entry) {
      continue;
    }
    for (const executableName of executableNames) {
      const candidate = pathApi.resolve(cwd, entry, executableName);
      if (await isExecutableFile(candidate, platform)) {
        return fs.realpath(candidate);
      }
    }
  }
  throw new Error(`could not locate an executable host Git in PATH=${hostPath}`);
}

export async function createSmokeFixtureContext({
  workRoot,
  sourceEnv = process.env,
  cwd = process.cwd(),
  platform = process.platform
}) {
  const homeDir = path.join(workRoot, 'home');
  const xdgDir = path.join(workRoot, 'xdg');
  const hooksDir = path.join(workRoot, 'hooks');
  const templateDir = path.join(workRoot, 'template');
  await Promise.all(
    [homeDir, xdgDir, hooksDir, templateDir].map(directory =>
      fs.mkdir(directory, { recursive: true })
    )
  );

  const hostPath = absoluteHostPath({ env: sourceEnv, cwd, platform });
  const gitBinary = await resolveHostGit({ hostPath, cwd, platform });
  const env = hermeticSmokeEnv({
    sourceEnv,
    hostPath,
    homeDir,
    xdgDir,
    platform
  });
  Object.assign(env, {
    GIT_AUTHOR_NAME: 'Kin MCP Smoke',
    GIT_AUTHOR_EMAIL: 'kin-mcp-smoke@localhost',
    GIT_AUTHOR_DATE: '2000-01-01T00:00:00Z',
    GIT_COMMITTER_NAME: 'Kin MCP Smoke',
    GIT_COMMITTER_EMAIL: 'kin-mcp-smoke@localhost',
    GIT_COMMITTER_DATE: '2000-01-01T00:00:00Z'
  });
  return { env, gitBinary, hooksDir, templateDir };
}

function gitArgs(context, args) {
  return [
    '-c',
    `core.hooksPath=${context.hooksDir}`,
    '-c',
    'maintenance.auto=false',
    '-c',
    'gc.auto=0',
    '-c',
    'protocol.file.allow=always',
    ...args
  ];
}

export function runGit(context, repoDir, args, { stdio = 'inherit' } = {}) {
  return cp.execFileSync(context.gitBinary, gitArgs(context, args), {
    cwd: repoDir,
    env: context.env,
    stdio
  });
}

export function initializeGitFixture(context, repoDir) {
  runGit(context, repoDir, [
    'init',
    '--initial-branch=main',
    `--template=${context.templateDir}`,
    '.'
  ]);
  runGit(context, repoDir, ['config', '--local', 'commit.gpgSign', 'false']);
  runGit(context, repoDir, ['config', '--local', 'core.autocrlf', 'false']);
  runGit(context, repoDir, ['add', '--', 'main.rs']);
  runGit(context, repoDir, ['commit', '-m', 'Seed Kin MCP smoke fixture']);
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
  const explicit = readEnv(process.env, envKey);
  if (explicit) {
    const explicitPath = path.resolve(explicit);
    if (!(await isFile(explicitPath))) {
      throw new Error(`${envKey}=${explicit} is not a file`);
    }
    return explicitPath;
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
    const listing = cp.execFileSync('/bin/ps', ['-Ao', 'pid=,command='], {
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
  const fixtureContext = await createSmokeFixtureContext({ workRoot });
  await fs.writeFile(
    path.join(repoDir, 'main.rs'),
    'fn greet() -> &\'static str {\n    "hello kin"\n}\n'
  );
  initializeGitFixture(fixtureContext, repoDir);

  await stageCache(cacheRoot, kinBin, daemonBin);

  // Explicit first-run init (no silent init): use the cached kin directly.
  const cachedKin = resolveCachedBinaryPath({
    env: { KIN_MCP_CACHE_DIR: cacheRoot }
  });
  log('kin init . (explicit first-run)');
  cp.execFileSync(cachedKin, ['init', '.'], {
    cwd: repoDir,
    env: fixtureContext.env,
    stdio: 'inherit'
  });

  const wrapperBin = path.join(packageDir, 'bin', 'kin-mcp.js');
  const env = {
    ...fixtureContext.env,
    KIN_MCP_CACHE_DIR: cacheRoot,
    KIN_DAEMON_IDLE_TIMEOUT_SECS: '30',
    KIN_SUPERVISOR_IDLE_TIMEOUT_SECS: '30'
  };

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

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : null;
if (invokedPath === fileURLToPath(import.meta.url)) {
  main().catch(error => {
    process.stderr.write(`SMOKE FAIL: ${error.message}\n`);
    process.exit(1);
  });
}
