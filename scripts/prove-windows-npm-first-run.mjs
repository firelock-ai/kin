#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

// Offline first-run integration proof for Kin's two public npm surfaces.
//
// The Windows authority job builds the real kin.exe + kin-daemon.exe and
// passes their absolute paths through KIN_NPM_PROOF_{KIN,DAEMON}_BIN. This
// script copies those exact bytes into each package's real managed layout and
// drives:
//
//   @kinlab/kin       Git admission -> daemon-backed status/search -> MCP call
//   @kinlab/kin-mcp   wrapper-owned auto-init -> MCP call
//
// No download or fake product process participates. In the canonical leg, the
// managed bin directory is deliberately removed from PATH and KIN_DAEMON_BIN
// is absent. The absolute managed kin.exe therefore has to discover its real
// sibling kin-daemon.exe itself.

import assert from 'node:assert/strict';
import cp from 'node:child_process';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  binaryName,
  managedBinaryPath,
  targetKinVersion,
  writeLauncherStamp,
} from '../packages/kin/lib/resolve.mjs';
import {
  resolveCachedBinaryPath,
  resolveDaemonBinaryPath,
} from '../packages/kin-mcp/src/index.js';
import { emptyGlobalGitConfig } from '../packages/kin-mcp/test/smoke-first-run.mjs';

const scriptPath = fileURLToPath(import.meta.url);
const repoRoot = path.dirname(path.dirname(scriptPath));
const canonicalKinLauncher = path.join(repoRoot, 'packages', 'kin', 'bin', 'kin.mjs');
const canonicalMcpLauncher = path.join(repoRoot, 'packages', 'kin', 'bin', 'kin-mcp.mjs');
const compatibilityMcpLauncher = path.join(
  repoRoot,
  'packages',
  'kin-mcp',
  'bin',
  'kin-mcp.js',
);
const commandTimeoutMs = 180_000;

function log(message) {
  process.stderr.write(`[windows-npm-proof] ${message}\n`);
}

function envNameEquals(actual, expected) {
  return process.platform === 'win32'
    ? actual.toLowerCase() === expected.toLowerCase()
    : actual === expected;
}

function deleteEnv(env, name) {
  for (const candidate of Object.keys(env)) {
    if (envNameEquals(candidate, name)) {
      delete env[candidate];
    }
  }
}

function setEnv(env, name, value) {
  deleteEnv(env, name);
  env[name] = value;
}

function readEnv(env, name) {
  const candidate = Object.keys(env).find((key) => envNameEquals(key, name));
  return candidate === undefined ? undefined : env[candidate];
}

function normalizePath(candidate) {
  let normalized;
  try {
    normalized = fs.realpathSync(candidate);
  } catch {
    normalized = path.resolve(candidate);
  }
  return process.platform === 'win32' ? normalized.toLowerCase() : normalized;
}

function pathWithoutDirectory(originalPath, forbiddenDirectory) {
  const forbidden = normalizePath(forbiddenDirectory);
  return String(originalPath || '')
    .split(path.delimiter)
    .filter(Boolean)
    .filter((entry) => normalizePath(entry) !== forbidden)
    .join(path.delimiter);
}

function assertPathExcludes(env, forbiddenDirectory, label) {
  const forbidden = normalizePath(forbiddenDirectory);
  const present = String(readEnv(env, 'PATH') || '')
    .split(path.delimiter)
    .filter(Boolean)
    .some((entry) => normalizePath(entry) === forbidden);
  assert.equal(present, false, `${label}: managed binary directory remained on PATH`);
}

function findHostExecutable(name) {
  const candidates = process.platform === 'win32'
    ? [`${name}.exe`, `${name}.cmd`, `${name}.bat`, name]
    : [name];
  for (const directory of String(readEnv(process.env, 'PATH') || '').split(path.delimiter)) {
    if (!directory) continue;
    for (const candidate of candidates) {
      const fullPath = path.resolve(directory, candidate);
      try {
        if (fs.statSync(fullPath).isFile()) return fs.realpathSync(fullPath);
      } catch {
        // Continue searching the host PATH.
      }
    }
  }
  throw new Error(`could not resolve host executable ${name} from PATH`);
}

function requireBuiltBinary(envName, expectedName) {
  const configured = readEnv(process.env, envName);
  if (!configured) {
    throw new Error(`${envName} must name the built ${expectedName}`);
  }
  const resolved = path.resolve(configured);
  const stat = fs.statSync(resolved);
  if (!stat.isFile() || stat.size === 0) {
    throw new Error(`${envName}=${resolved} is not a non-empty regular file`);
  }
  if (process.platform === 'win32' && path.basename(resolved).toLowerCase() !== expectedName) {
    throw new Error(`${envName} must end in ${expectedName} on Windows: ${resolved}`);
  }
  return resolved;
}

function hermeticEnv({ root, managedBinDir }) {
  const env = {};
  for (const [name, value] of Object.entries(process.env)) {
    const upper = name.toUpperCase();
    if (
      upper.startsWith('KIN_') ||
      upper.startsWith('_KIN_') ||
      upper.startsWith('GIT_') ||
      upper.startsWith('DYLD_') ||
      upper.startsWith('LD_') ||
      ['HOME', 'USERPROFILE', 'LOCALAPPDATA', 'APPDATA', 'XDG_CONFIG_HOME', 'XDG_CACHE_HOME']
        .includes(upper)
    ) {
      continue;
    }
    env[name] = value;
  }

  const home = path.join(root, 'home');
  const localAppData = path.join(root, 'local-app-data');
  const appData = path.join(root, 'app-data');
  const xdgConfig = path.join(root, 'xdg-config');
  const xdgCache = path.join(root, 'xdg-cache');
  for (const directory of [home, localAppData, appData, xdgConfig, xdgCache]) {
    fs.mkdirSync(directory, { recursive: true });
  }

  setEnv(env, 'HOME', home);
  setEnv(env, 'USERPROFILE', home);
  setEnv(env, 'LOCALAPPDATA', localAppData);
  setEnv(env, 'APPDATA', appData);
  setEnv(env, 'XDG_CONFIG_HOME', xdgConfig);
  setEnv(env, 'XDG_CACHE_HOME', xdgCache);
  setEnv(env, 'GIT_CONFIG_GLOBAL', emptyGlobalGitConfig());
  setEnv(env, 'GIT_CONFIG_NOSYSTEM', '1');
  setEnv(env, 'GIT_ATTR_NOSYSTEM', '1');
  setEnv(env, 'GIT_TERMINAL_PROMPT', '0');
  setEnv(env, 'GIT_PAGER', 'cat');
  setEnv(env, 'GIT_AUTHOR_NAME', 'Kin Windows npm Proof');
  setEnv(env, 'GIT_AUTHOR_EMAIL', 'kin-windows-npm-proof@localhost');
  setEnv(env, 'GIT_AUTHOR_DATE', '2000-01-01T00:00:00Z');
  setEnv(env, 'GIT_COMMITTER_NAME', 'Kin Windows npm Proof');
  setEnv(env, 'GIT_COMMITTER_EMAIL', 'kin-windows-npm-proof@localhost');
  setEnv(env, 'GIT_COMMITTER_DATE', '2000-01-01T00:00:00Z');
  setEnv(env, 'KIN_REGISTRY_PATH', path.join(root, 'registry.toml'));
  setEnv(env, 'KIN_VFS_DISABLE', '1');
  setEnv(env, 'KIN_DAEMON_IDLE_TIMEOUT_SECS', '30');
  setEnv(env, 'KIN_SUPERVISOR_IDLE_TIMEOUT_SECS', '30');

  // Deliberately inject and then remove the managed directory. This prevents a
  // vacuous pass where the proof merely assumes the directory was never on PATH.
  const hostilePath = [managedBinDir, readEnv(process.env, 'PATH') || '']
    .filter(Boolean)
    .join(path.delimiter);
  setEnv(env, 'PATH', pathWithoutDirectory(hostilePath, managedBinDir));
  deleteEnv(env, 'KIN_DAEMON_BIN');
  assert.equal(readEnv(env, 'KIN_DAEMON_BIN'), undefined);
  assertPathExcludes(env, managedBinDir, root);
  return env;
}

function runChecked(executable, args, { cwd, env, label, timeout = commandTimeoutMs }) {
  const result = cp.spawnSync(executable, args, {
    cwd,
    env,
    encoding: 'utf8',
    timeout,
    windowsHide: true,
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.error || result.status !== 0) {
    throw new Error(
      `${label} failed (status=${result.status}, signal=${result.signal}): ` +
        `${result.error?.message || ''}\nstdout:\n${result.stdout || ''}\nstderr:\n${result.stderr || ''}`,
    );
  }
  return result;
}

function initializeGitFixture({ gitBinary, repoDir, env, fixtureRoot }) {
  const templateDir = path.join(fixtureRoot, 'git-template');
  const hooksDir = path.join(fixtureRoot, 'git-hooks');
  fs.mkdirSync(repoDir, { recursive: true });
  fs.mkdirSync(templateDir, { recursive: true });
  fs.mkdirSync(hooksDir, { recursive: true });
  fs.writeFileSync(
    path.join(repoDir, 'main.rs'),
    'pub fn greet() -> &\'static str {\n    "hello from the Windows npm proof"\n}\n',
  );
  const git = (args, label) => runChecked(
    gitBinary,
    [
      '-c',
      `core.hooksPath=${hooksDir}`,
      '-c',
      'maintenance.auto=false',
      '-c',
      'gc.auto=0',
      ...args,
    ],
    { cwd: repoDir, env, label },
  );
  git(['init', '--initial-branch=main', `--template=${templateDir}`, '.'], 'git init');
  git(['config', '--local', 'commit.gpgSign', 'false'], 'disable commit signing');
  git(['config', '--local', 'core.autocrlf', 'false'], 'disable autocrlf');
  git(['add', '--', 'main.rs'], 'git add');
  git(['commit', '-m', 'Seed Windows npm first-run proof'], 'git commit');
}

async function copyExecutable(source, destination) {
  await fsp.mkdir(path.dirname(destination), { recursive: true });
  await fsp.copyFile(source, destination);
  if (process.platform !== 'win32') {
    await fsp.chmod(destination, 0o755);
  }
}

class JsonRpcReader {
  constructor() {
    this.buffer = '';
    this.responses = new Map();
    this.waiters = new Map();
  }

  feed(chunk) {
    this.buffer += chunk;
    let newline;
    while ((newline = this.buffer.indexOf('\n')) >= 0) {
      const line = this.buffer.slice(0, newline).trim();
      this.buffer = this.buffer.slice(newline + 1);
      if (!line.startsWith('{')) continue;
      let message;
      try {
        message = JSON.parse(line);
      } catch {
        continue;
      }
      if (message.id == null) continue;
      const waiter = this.waiters.get(message.id);
      if (waiter) {
        this.waiters.delete(message.id);
        clearTimeout(waiter.timer);
        waiter.resolve(message);
      } else {
        this.responses.set(message.id, message);
      }
    }
  }

  await(id, timeoutMs) {
    if (this.responses.has(id)) {
      const response = this.responses.get(id);
      this.responses.delete(id);
      return Promise.resolve(response);
    }
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.waiters.delete(id);
        reject(new Error(`timed out waiting for MCP response id=${id}`));
      }, timeoutMs);
      this.waiters.set(id, { resolve, reject, timer });
    });
  }

  fail(error) {
    for (const waiter of this.waiters.values()) {
      clearTimeout(waiter.timer);
      waiter.reject(error);
    }
    this.waiters.clear();
  }
}

function request(child, id, method, params) {
  child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`);
}

function notification(child, method, params) {
  child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method, params })}\n`);
}

function waitForExit(child, timeoutMs) {
  return new Promise((resolve, reject) => {
    if (child.exitCode !== null || child.signalCode !== null) {
      resolve({ code: child.exitCode, signal: child.signalCode });
      return;
    }
    const timer = setTimeout(() => {
      reject(new Error(`MCP launcher pid ${child.pid} did not exit after stdin closed`));
    }, timeoutMs);
    child.once('exit', (code, signal) => {
      clearTimeout(timer);
      resolve({ code, signal });
    });
    child.once('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
  });
}

async function proveMcp({ launcher, repoDir, env, label }) {
  const child = cp.spawn(process.execPath, [launcher], {
    cwd: repoDir,
    env,
    stdio: ['pipe', 'pipe', 'pipe'],
    windowsHide: true,
  });
  const reader = new JsonRpcReader();
  let stdout = '';
  let stderr = '';
  child.stdout.setEncoding('utf8');
  child.stderr.setEncoding('utf8');
  child.stdout.on('data', (chunk) => {
    stdout += chunk;
    reader.feed(chunk);
  });
  child.stderr.on('data', (chunk) => {
    stderr += chunk;
  });
  child.once('error', (error) => reader.fail(error));
  child.once('exit', (code, signal) => {
    if (code !== 0) {
      reader.fail(
        new Error(`${label} exited early (code=${code}, signal=${signal}): ${stderr}`),
      );
    }
  });

  try {
    request(child, 1, 'initialize', {
      protocolVersion: '2024-11-05',
      capabilities: {},
      clientInfo: { name: 'kin-windows-npm-proof', version: '1.0.0' },
    });
    const initialized = await reader.await(1, commandTimeoutMs);
    assert.equal(initialized.error, undefined, `${label}: initialize returned an error`);
    assert.ok(initialized.result, `${label}: initialize result is missing`);
    notification(child, 'notifications/initialized', {});

    request(child, 2, 'tools/list', {});
    const listed = await reader.await(2, commandTimeoutMs);
    const toolNames = (listed.result?.tools || []).map((tool) => tool.name);
    assert.ok(toolNames.includes('semantic_search'), `${label}: semantic_search is missing`);

    request(child, 3, 'tools/call', {
      name: 'semantic_search',
      arguments: { query: 'greet', compact: true, limit: 5 },
    });
    const searched = await reader.await(3, commandTimeoutMs);
    assert.equal(searched.error, undefined, `${label}: semantic_search returned an RPC error`);
    assert.notEqual(searched.result?.isError, true, `${label}: semantic_search returned isError`);
    const rendered = JSON.stringify(searched.result || {});
    assert.match(rendered, /greet/i, `${label}: semantic_search omitted greet`);
    assert.match(rendered, /main\.rs/i, `${label}: semantic_search omitted main.rs`);

    child.stdin.end();
    const exited = await waitForExit(child, 30_000);
    if (exited.code !== 0) {
      throw new Error(
        `${label} exited nonzero (code=${exited.code}, signal=${exited.signal})\n` +
          `stdout:\n${stdout}\nstderr:\n${stderr}`,
      );
    }
    log(`${label}: real semantic_search returned the committed greet entity`);
  } finally {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill('SIGTERM');
    }
  }
}

function stopIsolatedDaemons({ kinBinary, repoDir, env, label }) {
  if (!fs.existsSync(path.join(repoDir, '.kin'))) return;
  runChecked(kinBinary, ['daemon', 'stop', '--all', '--json'], {
    cwd: repoDir,
    env,
    label: `${label} daemon cleanup`,
    timeout: 60_000,
  });
}

async function proveCanonical({ workRoot, builtKin, builtDaemon, gitBinary }) {
  const root = path.join(workRoot, 'canonical');
  const kinHome = path.join(root, 'kin-home');
  const managedKin = managedBinaryPath('kin', { KIN_HOME: kinHome }, process.platform);
  const managedDaemon = managedBinaryPath(
    'kin-daemon',
    { KIN_HOME: kinHome },
    process.platform,
  );
  await copyExecutable(builtKin, managedKin);
  await copyExecutable(builtDaemon, managedDaemon);
  writeLauncherStamp(targetKinVersion(), { KIN_HOME: kinHome });

  const env = hermeticEnv({ root, managedBinDir: path.dirname(managedKin) });
  setEnv(env, 'KIN_HOME', kinHome);
  setEnv(env, 'KIN_NO_PROVISION', '1');
  setEnv(env, 'KIN_MCP_TOOL_PROFILE', 'agent-default');
  deleteEnv(env, 'KIN_DAEMON_BIN');
  assert.equal(readEnv(env, 'KIN_DAEMON_BIN'), undefined);
  assertPathExcludes(env, path.dirname(managedKin), '@kinlab/kin');
  assert.ok(path.isAbsolute(managedKin), '@kinlab/kin managed binary must be absolute');
  if (process.platform === 'win32') {
    assert.equal(path.basename(managedKin).toLowerCase(), 'kin.exe');
    assert.equal(path.basename(managedDaemon).toLowerCase(), 'kin-daemon.exe');
  }

  const repoDir = path.join(root, 'repo');
  initializeGitFixture({ gitBinary, repoDir, env, fixtureRoot: root });

  let failure = null;
  try {
    runChecked(process.execPath, [canonicalKinLauncher, 'init', '.'], {
      cwd: repoDir,
      env,
      label: '@kinlab/kin init',
    });
    const status = runChecked(process.execPath, [canonicalKinLauncher, 'status', '--json'], {
      cwd: repoDir,
      env,
      label: '@kinlab/kin repository status',
    });
    const statusJson = JSON.parse(status.stdout);
    assert.equal(statusJson.schema, 'kin.status.v3');
    assert.equal(statusJson.authority, 'repository-v6');
    assert.equal(statusJson.repository?.source_cas_verified, true);

    const search = runChecked(
      process.execPath,
      [canonicalKinLauncher, 'search', 'greet', '--json'],
      { cwd: repoDir, env, label: '@kinlab/kin graph-backed search' },
    );
    assert.match(search.stdout, /greet/i, '@kinlab/kin search omitted greet');
    assert.match(search.stdout, /main\.rs/i, '@kinlab/kin search omitted main.rs');

    await proveMcp({
      launcher: canonicalMcpLauncher,
      repoDir,
      env,
      label: '@kinlab/kin kin-mcp entrypoint',
    });
    log('@kinlab/kin: absolute managed binary passed PATH-free daemon CLI + MCP proof');
  } catch (error) {
    failure = error;
  }

  try {
    stopIsolatedDaemons({ kinBinary: managedKin, repoDir, env, label: '@kinlab/kin' });
  } catch (cleanupError) {
    if (failure) {
      failure.message += `\ncleanup also failed: ${cleanupError.message}`;
    } else {
      failure = cleanupError;
    }
  }
  if (failure) throw failure;
}

async function proveCompatibility({ workRoot, builtKin, builtDaemon, gitBinary }) {
  const root = path.join(workRoot, 'compatibility');
  const cacheRoot = path.join(root, 'cache');
  const provisionalEnv = { KIN_MCP_CACHE_DIR: cacheRoot };
  const cachedKin = resolveCachedBinaryPath({
    env: provisionalEnv,
    platform: process.platform,
    arch: process.arch,
  });
  const cachedDaemon = resolveDaemonBinaryPath(cachedKin);
  await copyExecutable(builtKin, cachedKin);
  await copyExecutable(builtDaemon, cachedDaemon);

  const env = hermeticEnv({ root, managedBinDir: path.dirname(cachedKin) });
  setEnv(env, 'KIN_MCP_CACHE_DIR', cacheRoot);
  setEnv(env, 'KIN_MCP_AUTO_INIT', '1');
  setEnv(env, 'KIN_MCP_RELEASE_BASE_URL', 'http://127.0.0.1:9/kin-offline-proof');
  deleteEnv(env, 'KIN_DAEMON_BIN');
  deleteEnv(env, 'KIN_MCP_KIN_BINARY');
  deleteEnv(env, 'KIN_BINARY_PATH');
  assertPathExcludes(env, path.dirname(cachedKin), '@kinlab/kin-mcp');
  if (process.platform === 'win32') {
    assert.equal(path.basename(cachedKin).toLowerCase(), 'kin.exe');
    assert.equal(path.basename(cachedDaemon).toLowerCase(), 'kin-daemon.exe');
  }

  const repoDir = path.join(root, 'repo');
  initializeGitFixture({ gitBinary, repoDir, env, fixtureRoot: root });

  let failure = null;
  try {
    assert.equal(fs.existsSync(path.join(repoDir, '.kin')), false);
    await proveMcp({
      launcher: compatibilityMcpLauncher,
      repoDir,
      env,
      label: '@kinlab/kin-mcp compatibility wrapper',
    });
    assert.equal(
      fs.statSync(path.join(repoDir, '.kin')).isDirectory(),
      true,
      '@kinlab/kin-mcp did not perform its opted-in first-run init',
    );
    log('@kinlab/kin-mcp: cache-owned auto-init + real MCP proof passed');
  } catch (error) {
    failure = error;
  }

  try {
    stopIsolatedDaemons({ kinBinary: cachedKin, repoDir, env, label: '@kinlab/kin-mcp' });
  } catch (cleanupError) {
    if (failure) {
      failure.message += `\ncleanup also failed: ${cleanupError.message}`;
    } else {
      failure = cleanupError;
    }
  }
  if (failure) throw failure;
}

async function main() {
  const hostOverride = readEnv(process.env, 'KIN_NPM_PROOF_ALLOW_HOST') === '1';
  if (process.platform !== 'win32' && !hostOverride) {
    throw new Error(
      'this is a native Windows proof; set KIN_NPM_PROOF_ALLOW_HOST=1 only for a non-citable host logic smoke',
    );
  }
  const expectedKinName = binaryName('kin', process.platform).toLowerCase();
  const expectedDaemonName = binaryName('kin-daemon', process.platform).toLowerCase();
  const builtKin = requireBuiltBinary('KIN_NPM_PROOF_KIN_BIN', expectedKinName);
  const builtDaemon = requireBuiltBinary('KIN_NPM_PROOF_DAEMON_BIN', expectedDaemonName);
  const gitBinary = findHostExecutable('git');
  const workRoot = await fsp.mkdtemp(path.join(os.tmpdir(), 'kin-windows-npm-proof-'));

  log(`platform=${process.platform}/${process.arch}`);
  log(`kin=${builtKin}`);
  log(`kin-daemon=${builtDaemon}`);
  try {
    await proveCanonical({ workRoot, builtKin, builtDaemon, gitBinary });
    await proveCompatibility({ workRoot, builtKin, builtDaemon, gitBinary });
  } finally {
    await fsp.rm(workRoot, { recursive: true, force: true }).catch(() => {});
  }

  if (process.platform === 'win32') {
    process.stdout.write(
      'WINDOWS NPM PROOF PASS: canonical and compatibility surfaces reached real graph-backed MCP\n',
    );
  } else {
    process.stdout.write(
      'HOST LOGIC SMOKE PASS (NON-CITABLE): Windows npm proof harness completed on a non-Windows host\n',
    );
  }
}

main().catch((error) => {
  process.stderr.write(`WINDOWS NPM PROOF FAIL: ${error.stack || error.message}\n`);
  process.exit(1);
});
