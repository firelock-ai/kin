import assert from 'node:assert/strict';
import cp from 'node:child_process';
import crypto from 'node:crypto';
import { existsSync } from 'node:fs';
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  assertSecureReleaseBaseUrl,
  childEnv,
  DEFAULT_RELEASE_BASE_URL,
  ensureKinBinary,
  resolveCachedBinaryPath,
  resolveDaemonBinaryPath,
  resolveReleaseAsset,
  resolveReleaseTag,
  runKinMcp,
  isTruthyEnv
} from '../src/index.js';

test('MCP auto-init boolean accepts the generated env-contract vocabulary', () => {
  for (const token of ['1', 'true', 'TRUE', 'TrUe', 'yes', 'YES', 'on', 'ON', ' on ']) {
    assert.equal(isTruthyEnv(token), true, token);
  }
  for (const token of ['', '0', 'false', 'no', 'off', 'truthy']) {
    assert.equal(isTruthyEnv(token), false, token);
  }
});
import {
  absoluteHostPath,
  createSmokeFixtureContext,
  emptyGlobalGitConfig,
  hermeticSmokeEnv,
  initializeGitFixture,
  runGit
} from './smoke-first-run.mjs';

test('the empty global Git config resolves to no configuration on every platform', () => {
  // Off Windows, `/dev/null` is the path Git already reads as an empty config.
  assert.equal(emptyGlobalGitConfig('linux'), os.devNull);
  assert.equal(emptyGlobalGitConfig('darwin'), os.devNull);

  // On Windows `os.devNull` is the reserved `NUL` device rather than a file,
  // and Git refuses it outright, so that branch names a path under an absent
  // parent: reads resolve to nothing and a `--global` write fails loudly.
  const windows = emptyGlobalGitConfig('win32');
  assert.notEqual(windows, 'NUL');
  assert.equal(path.isAbsolute(windows), true, `${windows} is not absolute`);
  // Nothing is created: the absent parent is what makes a `--global` write fail
  // loudly instead of persisting into a file every later Git launch would read.
  assert.equal(existsSync(windows), false, `${windows} should not exist`);
  assert.equal(
    existsSync(path.dirname(windows)),
    false,
    `${path.dirname(windows)} should not exist`
  );

  // Deterministic, so repeated boundary applications agree.
  assert.equal(emptyGlobalGitConfig('win32'), windows);
});

async function exists(filePath) {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

const fakeKinPreload = [
  "const fs = require('node:fs');",
  "const path = require('node:path');",
  "const command = path.basename(process.argv[1] || '');",
  "if (command === 'init' || command === 'mcp') {",
  "  const args = [command, ...process.argv.slice(2)];",
  "  if (process.env.KIN_MCP_FAKE_LOG) {",
  "    fs.appendFileSync(process.env.KIN_MCP_FAKE_LOG, `${args.join('\\n')}\\n`);",
  "  }",
  "  if (command === 'init') {",
  "    if (process.env.KIN_MCP_FAKE_INIT_STDOUT) process.stdout.write(process.env.KIN_MCP_FAKE_INIT_STDOUT);",
  "    if (process.env.KIN_MCP_FAKE_INIT_STDERR) process.stderr.write(process.env.KIN_MCP_FAKE_INIT_STDERR);",
  "    if (process.env.KIN_MCP_FAKE_REPO) {",
  "      fs.mkdirSync(path.join(process.env.KIN_MCP_FAKE_REPO, '.kin'), { recursive: true });",
  "    }",
  "  }",
  "  if (command === 'mcp' && process.env.KIN_MCP_FAKE_ECHO_INITIALIZE) {",
  "    let request = '';",
  "    try { request = fs.readFileSync(0, 'utf8'); } catch (error) { request = ''; }",
  "    const method = /\"method\"\\s*:\\s*\"([^\"]+)\"/.exec(request);",
  "    const payload = JSON.stringify({",
  "      jsonrpc: '2.0',",
  "      id: 1,",
  "      result: { served: method ? method[1] : 'nothing-arrived', cwd: process.cwd() }",
  "    });",
  "    process.stdout.write(`Content-Length: ${Buffer.byteLength(payload)}\\r\\n\\r\\n${payload}`);",
  "    process.exit(0);",
  "  }",
  "  if (command === 'mcp') {",
  "    if (process.env.KIN_MCP_FAKE_PROFILE) {",
  "      fs.writeFileSync(process.env.KIN_MCP_FAKE_PROFILE, process.env.KIN_MCP_TOOL_PROFILE || '');",
  "    }",
  "    if (process.env.KIN_MCP_FAKE_PROTOCOL_BASE64) {",
  "      process.stdout.write(Buffer.from(process.env.KIN_MCP_FAKE_PROTOCOL_BASE64, 'base64'));",
  "    }",
  "  }",
  "  process.exit(0);",
  "}",
  ""
].join('\n');

async function fakeKinEnvironment(tmpDir, overrides = {}) {
  const preloadName = 'fake-kin-preload.cjs';
  await fs.writeFile(path.join(tmpDir, preloadName), fakeKinPreload);
  const env = {
    ...process.env,
    NODE_OPTIONS: `--require=./${preloadName}`,
    KIN_MCP_KIN_BINARY: process.execPath,
    KIN_MCP_FAKE_REPO: tmpDir,
    ...overrides
  };
  delete env.KIN_DAEMON_BIN;
  return env;
}

function environmentValue(env, name) {
  const key = Object.keys(env).find(candidate => candidate.toLowerCase() === name.toLowerCase());
  return key === undefined ? undefined : env[key];
}

function windowsSystemTarPath(env = process.env) {
  const systemRoot = environmentValue(env, 'SystemRoot');
  assert.ok(systemRoot, 'native Windows ZIP fixtures require SystemRoot');
  return path.win32.join(systemRoot, 'System32', 'tar.exe');
}

async function environmentWithHostileTar(tmpDir, overrides = {}) {
  const hostileBin = path.join(tmpDir, 'hostile-path');
  await fs.mkdir(hostileBin, { recursive: true });
  const hostileTar = path.join(
    hostileBin,
    process.platform === 'win32' ? 'tar.exe' : 'tar'
  );
  if (process.platform === 'win32') {
    await fs.copyFile(process.execPath, hostileTar);
  } else {
    await fs.writeFile(hostileTar, '#!/bin/sh\nexit 97\n', { mode: 0o755 });
  }

  const env = { ...process.env, ...overrides };
  const originalPath = environmentValue(env, 'PATH') || '';
  for (const name of Object.keys(env)) {
    if (name.toLowerCase() === 'path') delete env[name];
  }
  env.PATH = [hostileBin, originalPath].filter(Boolean).join(path.delimiter);
  return env;
}

test('first-run smoke scrubs ambient Git, VFS, loader, and binary authority', () => {
  const env = hermeticSmokeEnv({
    sourceEnv: {
      PATH: '/shadow/bin',
      KIN_ORIGINAL_PATH: '/host/bin:/usr/bin',
      GIT_CONFIG_COUNT: '1',
      GIT_CONFIG_KEY_0: 'core.hooksPath',
      GIT_CONFIG_VALUE_0: '/hostile/hooks',
      GIT_TEMPLATE_DIR: '/hostile/template',
      GIT_EXEC_PATH: '/hostile/git-core',
      KIN_VFS_ROOT: '/hostile/vfs',
      KIN_DAEMON_BIN: '/hostile/daemon',
      KIN_MCP_KIN_BINARY: '/hostile/kin',
      KIN_BINARY_PATH: '/hostile/kin',
      LD_PRELOAD: '/hostile/preload.so',
      DYLD_INSERT_LIBRARIES: '/hostile/preload.dylib',
      SSH_ASKPASS: '/hostile/askpass',
      SAFE_SENTINEL: 'preserved'
    },
    hostPath: '/host/bin:/usr/bin',
    homeDir: '/fixture/home',
    xdgDir: '/fixture/xdg',
    platform: 'linux'
  });

  assert.equal(env.SAFE_SENTINEL, 'preserved');
  assert.equal(env.PATH, '/host/bin:/usr/bin');
  assert.equal(env.HOME, '/fixture/home');
  assert.equal(env.XDG_CONFIG_HOME, '/fixture/xdg');
  assert.equal(env.GIT_CONFIG_GLOBAL, os.devNull);
  assert.equal(env.GIT_CONFIG_NOSYSTEM, '1');
  assert.equal(env.GIT_ATTR_NOSYSTEM, '1');
  assert.equal(env.GIT_TERMINAL_PROMPT, '0');
  assert.equal(env.KIN_VFS_DISABLE, '1');
  for (const name of [
    'GIT_CONFIG_COUNT',
    'GIT_CONFIG_KEY_0',
    'GIT_CONFIG_VALUE_0',
    'GIT_TEMPLATE_DIR',
    'GIT_EXEC_PATH',
    'KIN_ORIGINAL_PATH',
    'KIN_VFS_ROOT',
    'KIN_DAEMON_BIN',
    'KIN_MCP_KIN_BINARY',
    'KIN_BINARY_PATH',
    'LD_PRELOAD',
    'DYLD_INSERT_LIBRARIES',
    'SSH_ASKPASS'
  ]) {
    assert.equal(Object.hasOwn(env, name), false, `${name} should be scrubbed`);
  }
});

test('first-run smoke scrubs mixed-case Windows authority names', () => {
  const env = hermeticSmokeEnv({
    sourceEnv: {
      Path: 'C:\\shadow',
      git_config_count: '1',
      Git_Template_Dir: 'C:\\hostile\\template',
      Kin_Daemon_Bin: 'C:\\hostile\\daemon.exe',
      kin_mcp_kin_binary: 'C:\\hostile\\kin.exe',
      kIn_VfS_rOoT: 'C:\\hostile\\vfs',
      DyLd_Insert_Libraries: 'C:\\hostile\\loader.dll',
      ld_preload: 'C:\\hostile\\loader.dll',
      Safe_Sentinel: 'preserved'
    },
    hostPath: 'C:\\Git\\cmd;C:\\Windows\\System32',
    homeDir: 'C:\\fixture\\home',
    xdgDir: 'C:\\fixture\\xdg',
    platform: 'win32'
  });

  assert.equal(env.Safe_Sentinel, 'preserved');
  assert.equal(env.PATH, 'C:\\Git\\cmd;C:\\Windows\\System32');
  // `NUL` is a reserved Windows device, not a file: Git refuses it with
  // `fatal: unable to access 'NUL': Invalid argument` and every isolated Git
  // command fails. Assert the property Git actually needs rather than pinning a
  // spelling: an absolute path that resolves to no configuration.
  assert.notEqual(env.GIT_CONFIG_GLOBAL, 'NUL');
  assert.equal(path.isAbsolute(env.GIT_CONFIG_GLOBAL), true);
  assert.equal(env.GIT_CONFIG_GLOBAL, emptyGlobalGitConfig('win32'));
  assert.equal(env.KIN_VFS_DISABLE, '1');
  const inheritedNames = Object.keys(env).map(name => name.toLowerCase());
  for (const name of [
    'path',
    'git_config_count',
    'git_template_dir',
    'kin_daemon_bin',
    'kin_mcp_kin_binary',
    'kin_vfs_root',
    'dyld_insert_libraries',
    'ld_preload'
  ]) {
    const matches = inheritedNames.filter(candidate => candidate === name);
    assert.equal(matches.length, name === 'path' ? 1 : 0, `${name} should be controlled`);
  }
});

test(
  'first-run Git fixture ignores hostile command-scope config and hooks',
  { skip: process.platform === 'win32' },
  async () => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'kin-mcp-hostile-git-'));
    const repoDir = path.join(tmpDir, 'repo');
    const hostileHooks = path.join(tmpDir, 'hostile-hooks');
    const hostileTemplate = path.join(tmpDir, 'hostile-template');
    const marker = path.join(tmpDir, 'hostile-hook-ran');
    await Promise.all([
      fs.mkdir(repoDir),
      fs.mkdir(hostileHooks),
      fs.mkdir(hostileTemplate)
    ]);
    await fs.writeFile(path.join(repoDir, 'main.rs'), 'fn main() {}\n');
    await fs.writeFile(
      path.join(hostileHooks, 'pre-commit'),
      `#!/bin/sh\nprintf ran > '${marker.replaceAll("'", "'\\''")}'\nexit 1\n`,
      { mode: 0o755 }
    );
    await fs.writeFile(
      path.join(hostileTemplate, 'config'),
      `[core]\n\thooksPath = ${hostileHooks}\n`
    );

    try {
      const sourceEnv = {
        ...process.env,
        KIN_ORIGINAL_PATH: process.env.KIN_ORIGINAL_PATH || process.env.PATH,
        GIT_CONFIG_COUNT: '1',
        GIT_CONFIG_KEY_0: 'core.hooksPath',
        GIT_CONFIG_VALUE_0: hostileHooks,
        GIT_TEMPLATE_DIR: hostileTemplate
      };
      const context = await createSmokeFixtureContext({
        workRoot: path.join(tmpDir, 'fixture'),
        sourceEnv
      });
      initializeGitFixture(context, repoDir);

      assert.equal(await exists(marker), false);
      const head = runGit(context, repoDir, ['rev-parse', '--verify', 'HEAD'], {
        stdio: ['ignore', 'pipe', 'pipe']
      })
        .toString('utf8')
        .trim();
      assert.match(head, /^[0-9a-f]{40,64}$/);
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  }
);

test('absoluteHostPath prefers the captured host path and normalizes entries', () => {
  assert.equal(
    absoluteHostPath({
      env: {
        PATH: '/shadow',
        KIN_ORIGINAL_PATH: 'bin:/usr/bin'
      },
      cwd: '/fixture',
      platform: 'linux'
    }),
    '/fixture/bin:/usr/bin'
  );
  assert.equal(
    absoluteHostPath({
      env: {
        Path: 'C:\\shadow',
        kin_original_path: 'Git\\cmd;C:\\Windows\\System32'
      },
      cwd: 'C:\\fixture',
      platform: 'win32'
    }),
    'C:\\fixture\\Git\\cmd;C:\\Windows\\System32'
  );
});

test('resolveReleaseAsset maps supported targets', () => {
  assert.deepEqual(resolveReleaseAsset('darwin', 'arm64'), {
    assetName: 'kin-macos-aarch64',
    archiveName: 'kin-macos-aarch64.tar.gz',
    binaryName: 'kin',
    daemonBinaryName: 'kin-daemon'
  });
  assert.deepEqual(resolveReleaseAsset('darwin', 'x64'), {
    assetName: 'kin-macos-x86_64',
    archiveName: 'kin-macos-x86_64.tar.gz',
    binaryName: 'kin',
    daemonBinaryName: 'kin-daemon'
  });
  assert.deepEqual(resolveReleaseAsset('linux', 'x64'), {
    assetName: 'kin-linux-x86_64',
    archiveName: 'kin-linux-x86_64.tar.gz',
    binaryName: 'kin',
    daemonBinaryName: 'kin-daemon'
  });
  assert.deepEqual(resolveReleaseAsset('linux', 'arm64'), {
    assetName: 'kin-linux-aarch64',
    archiveName: 'kin-linux-aarch64.tar.gz',
    binaryName: 'kin',
    daemonBinaryName: 'kin-daemon'
  });
  assert.deepEqual(resolveReleaseAsset('win32', 'x64'), {
    assetName: 'kin-windows-x86_64',
    archiveName: 'kin-windows-x86_64.zip',
    binaryName: 'kin.exe',
    daemonBinaryName: 'kin-daemon.exe'
  });
});

test('resolveReleaseAsset rejects unsupported targets', () => {
  assert.throws(
    () => resolveReleaseAsset('win32', 'arm64'),
    /does not have a published Kin binary/
  );
});

test('resolveReleaseTag prefixes versions with v', () => {
  assert.equal(resolveReleaseTag('0.1.0'), 'v0.1.0');
  assert.equal(resolveReleaseTag('v0.1.0-alpha.1'), 'v0.1.0-alpha.1');
});

async function buildReleaseArchive(
  tmpDir,
  assetName,
  { includeDaemon = true, platform = 'linux' } = {}
) {
  const kinBytes = Buffer.from('#!/bin/sh\necho kin\n', 'utf8');
  const daemonBytes = Buffer.from('#!/bin/sh\necho kin-daemon\n', 'utf8');
  const packageDir = path.join(tmpDir, assetName);
  const archiveName = platform === 'win32' ? `${assetName}.zip` : `${assetName}.tar.gz`;
  const archivePath = path.join(tmpDir, archiveName);
  const binaryName = platform === 'win32' ? 'kin.exe' : 'kin';
  const daemonBinaryName = platform === 'win32' ? 'kin-daemon.exe' : 'kin-daemon';

  await fs.mkdir(packageDir);
  await fs.writeFile(path.join(packageDir, binaryName), kinBytes, { mode: 0o755 });
  if (includeDaemon) {
    await fs.writeFile(path.join(packageDir, daemonBinaryName), daemonBytes, {
      mode: 0o755
    });
  }
  if (platform === 'win32') {
    const members = [binaryName];
    if (includeDaemon) {
      members.push(daemonBinaryName);
    }
    if (process.platform === 'win32') {
      cp.execFileSync(
        windowsSystemTarPath(),
        ['-a', '-c', '-f', `../${archiveName}`, ...members],
        { cwd: packageDir }
      );
    } else {
      cp.execFileSync('/usr/bin/zip', ['-q', `../${archiveName}`, ...members], {
        cwd: packageDir
      });
    }
  } else {
    cp.execFileSync('tar', ['-czf', archiveName, assetName], { cwd: tmpDir });
  }
  await fs.rm(packageDir, { recursive: true, force: true });

  const archiveBytes = await fs.readFile(archivePath);
  if (platform === 'win32') {
    assert.equal(archiveBytes.subarray(0, 4).toString('hex'), '504b0304');
  }
  await fs.rm(archivePath, { force: true });
  const checksum = crypto.createHash('sha256').update(archiveBytes).digest('hex');
  return { archiveBytes, archiveName, checksum, kinBytes, daemonBytes };
}

function startReleaseServer(version, archiveName, archiveBytes, checksum) {
  const server = http.createServer((req, res) => {
    if (req.url === `/v${version}/${archiveName}`) {
      res.writeHead(200, { 'content-type': 'application/octet-stream' });
      res.end(archiveBytes);
      return;
    }
    if (req.url === `/v${version}/${archiveName}.sha256`) {
      res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
      res.end(`${checksum}  ${archiveName}\n`);
      return;
    }
    res.writeHead(404);
    res.end('not found');
  });
  return server;
}

test('ensureKinBinary downloads kin and its daemon from a release asset', async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'kin-mcp-download-'));
  const assetName = 'kin-linux-x86_64';
  const version = '9.9.9-test';
  const { archiveBytes, archiveName, checksum, kinBytes, daemonBytes } =
    await buildReleaseArchive(tmpDir, assetName);
  const server = startReleaseServer(version, archiveName, archiveBytes, checksum);

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
    assert.equal(await fs.readFile(binaryPath, 'utf8'), kinBytes.toString('utf8'));

    const daemonPath = resolveDaemonBinaryPath(binaryPath);
    assert.equal(await exists(daemonPath), true);
    assert.equal(await fs.readFile(daemonPath, 'utf8'), daemonBytes.toString('utf8'));
  } finally {
    await new Promise(resolve => server.close(resolve));
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});

test('ensureKinBinary installs the flat native Windows zip and .exe pair', async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'kin-mcp-windows-download-'));
  const assetName = 'kin-windows-x86_64';
  const version = '9.9.9-test';
  const { archiveBytes, archiveName, checksum, kinBytes, daemonBytes } =
    await buildReleaseArchive(tmpDir, assetName, { platform: 'win32' });
  const server = startReleaseServer(version, archiveName, archiveBytes, checksum);

  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;
  const env = await environmentWithHostileTar(tmpDir, {
    KIN_MCP_CACHE_DIR: tmpDir,
    KIN_MCP_RELEASE_BASE_URL: baseUrl
  });

  try {
    const binaryPath = await ensureKinBinary({
      env,
      platform: 'win32',
      arch: 'x64',
      version
    });

    assert.equal(path.basename(binaryPath), 'kin.exe');
    assert.equal(await fs.readFile(binaryPath, 'utf8'), kinBytes.toString('utf8'));

    const daemonPath = resolveDaemonBinaryPath(binaryPath);
    assert.equal(path.basename(daemonPath), 'kin-daemon.exe');
    assert.equal(await fs.readFile(daemonPath, 'utf8'), daemonBytes.toString('utf8'));
  } finally {
    await new Promise(resolve => server.close(resolve));
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});

// The Unix arm of the same rule the Windows test above proves. `tar` was
// resolved through PATH, so a planted `tar` unpacked the archive whose SHA-256
// had just been verified: the integrity check protected bytes an attacker's
// program then read. The hostile `tar` here exits 97, so this test is red
// against a PATH lookup and green against an absolute one.
test(
  'ensureKinBinary unpacks the Unix archive with an absolute tar under a hostile PATH',
  { skip: process.platform === 'win32' },
  async () => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'kin-mcp-hostile-tar-'));
    const assetName = 'kin-linux-x86_64';
    const version = '9.9.9-test';
    const { archiveBytes, archiveName, checksum, kinBytes, daemonBytes } =
      await buildReleaseArchive(tmpDir, assetName);
    const server = startReleaseServer(version, archiveName, archiveBytes, checksum);

    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const address = server.address();
    const baseUrl = `http://127.0.0.1:${address.port}`;
    const env = await environmentWithHostileTar(tmpDir, {
      KIN_MCP_CACHE_DIR: tmpDir,
      KIN_MCP_RELEASE_BASE_URL: baseUrl
    });

    try {
      const binaryPath = await ensureKinBinary({
        env,
        platform: 'linux',
        arch: 'x64',
        version
      });

      assert.equal(await fs.readFile(binaryPath, 'utf8'), kinBytes.toString('utf8'));
      const daemonPath = resolveDaemonBinaryPath(binaryPath);
      assert.equal(await fs.readFile(daemonPath, 'utf8'), daemonBytes.toString('utf8'));
    } finally {
      await new Promise(resolve => server.close(resolve));
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  }
);

test('ensureKinBinary fails with a precise message when the archive omits kin-daemon', async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'kin-mcp-nodaemon-'));
  const assetName = 'kin-linux-x86_64';
  const version = '9.9.9-test';
  const { archiveBytes, archiveName, checksum } = await buildReleaseArchive(
    tmpDir,
    assetName,
    { includeDaemon: false }
  );
  const server = startReleaseServer(version, archiveName, archiveBytes, checksum);

  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}`;
  const env = {
    KIN_MCP_CACHE_DIR: tmpDir,
    KIN_MCP_RELEASE_BASE_URL: baseUrl
  };

  try {
    await assert.rejects(
      ensureKinBinary({ env, platform: 'linux', arch: 'x64', version }),
      /kin-daemon/
    );
  } finally {
    await new Promise(resolve => server.close(resolve));
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});

test('runKinMcp invokes kin mcp start', async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'kin-mcp-run-'));
  const argsPath = path.join(tmpDir, 'args.txt');
  const env = await fakeKinEnvironment(tmpDir, { KIN_MCP_FAKE_LOG: argsPath });
  // Pre-create .kin/ so auto-init is skipped
  await fs.mkdir(path.join(tmpDir, '.kin'));

  try {
    const discard = { write() {} };
    const exitCode = await runKinMcp([], {
      env,
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

// Coldwalk finding 5. The install page hands every client
// `{"command":"npx","args":["-y","@kinlab/kin-mcp"]}`, and this wrapper used to
// exit 2 before `kin mcp start` ever ran when the launch directory held no
// `.kin/`. Measured on 2026-08-28: EOF on `initialize`, process gone in 862 ms,
// against `kin mcp start` in the same directory serving `initialize` in 6 ms
// with 20 tools listed. So the advertised agent-setup path died on first
// contact for exactly the user it exists for, the one who has not run
// `kin init` yet.
test('runKinMcp starts the server when the launch directory is no Kin repository', async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'kin-mcp-no-autoinit-'));
  const argsPath = path.join(tmpDir, 'args.txt');
  const env = await fakeKinEnvironment(tmpDir, { KIN_MCP_FAKE_LOG: argsPath });
  delete env.KIN_MCP_AUTO_INIT;
  // fakeKinEnvironment points the fake `kin init` at tmpDir, and this test is
  // about the path where init must not run at all.
  delete env.KIN_MCP_FAKE_REPO;

  try {
    let stderr = '';
    const exitCode = await runKinMcp([], {
      env,
      cwd: tmpDir,
      stderr: { write(chunk) { stderr += chunk; } },
      stdio: 'ignore'
    });

    assert.equal(exitCode, 0, 'a directory with no .kin/ must not be fatal');
    assert.equal(
      await fs.readFile(argsPath, 'utf8'),
      'mcp\nstart\n',
      'the wrapper must reach `kin mcp start`, and must not run `kin init` unasked'
    );
    assert.match(stderr, /Run `kin init \.`/);
    assert.match(stderr, /Starting anyway/);
    assert.equal(
      await exists(path.join(tmpDir, '.kin')),
      false,
      'starting unbound must not initialize a repository behind the user'
    );
  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});

// The end-to-end half of finding 5: a real `initialize` request written to the
// wrapper's stdin in an empty directory must reach the server and be answered.
// The fixture reports the method it actually received, so a server that started
// but was handed nothing answers `nothing-arrived` rather than passing.
test('initialize is served through the wrapper in an empty directory', async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'kin-mcp-initialize-'));
  const env = await fakeKinEnvironment(tmpDir, {
    KIN_MCP_FAKE_ECHO_INITIALIZE: '1'
  });
  delete env.KIN_MCP_AUTO_INIT;
  delete env.KIN_MCP_FAKE_REPO;

  const request = JSON.stringify({
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: { protocolVersion: '2024-11-05', capabilities: {} }
  });

  try {
    const result = cp.spawnSync(
      process.execPath,
      [fileURLToPath(new URL('../bin/kin-mcp.js', import.meta.url))],
      {
        cwd: tmpDir,
        encoding: 'utf8',
        env,
        input: `Content-Length: ${Buffer.byteLength(request)}\r\n\r\n${request}`
      }
    );

    assert.equal(result.status, 0, result.stderr);
    const framed = /Content-Length: \d+\r\n\r\n(\{.*\})$/.exec(result.stdout);
    assert.ok(framed, `expected one framed response, got: ${JSON.stringify(result.stdout)}`);
    const response = JSON.parse(framed[1]);
    assert.equal(
      response.result.served,
      'initialize',
      'the initialize request must reach the server, not die with the wrapper'
    );
    assert.doesNotMatch(
      result.stdout,
      /no \.kin\/ found/i,
      'the notice belongs on stderr; a byte of prose on stdout corrupts the first frame'
    );
    assert.match(result.stderr, /Run `kin init \.`/);
    assert.equal(await exists(path.join(tmpDir, '.kin')), false);
  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});

test('childEnv defaults the agent-default tool profile and daemon binary', () => {
  const kinBinary = path.join(path.sep, 'cache', 'v1', 'kin-linux-x86_64', 'kin');
  const next = childEnv({}, kinBinary, 'linux');
  assert.equal(next.KIN_MCP_TOOL_PROFILE, 'agent-default');
  assert.equal(
    next.KIN_DAEMON_BIN,
    path.join(path.dirname(kinBinary), 'kin-daemon')
  );
});

test('childEnv respects an explicit tool profile and daemon override', () => {
  const kinBinary = '/cache/v1/kin-linux-x86_64/kin';
  const next = childEnv(
    { KIN_MCP_TOOL_PROFILE: 'benchmark', KIN_DAEMON_BIN: '/opt/kin-daemon' },
    kinBinary,
    'linux'
  );
  assert.equal(next.KIN_MCP_TOOL_PROFILE, 'benchmark');
  assert.equal(next.KIN_DAEMON_BIN, '/opt/kin-daemon');
});

test('childEnv does not pin the daemon when a user supplies their own kin binary', () => {
  const next = childEnv(
    { KIN_MCP_KIN_BINARY: '/usr/local/bin/kin' },
    '/usr/local/bin/kin',
    'linux'
  );
  assert.equal(next.KIN_MCP_TOOL_PROFILE, 'agent-default');
  assert.equal(next.KIN_DAEMON_BIN, undefined);
});

test('runKinMcp forwards the agent-default profile to kin mcp start', async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'kin-mcp-profile-'));
  const profilePath = path.join(tmpDir, 'profile.txt');
  const env = await fakeKinEnvironment(tmpDir, {
    KIN_MCP_FAKE_PROFILE: profilePath
  });
  await fs.mkdir(path.join(tmpDir, '.kin'));

  try {
    const discard = { write() {} };
    const exitCode = await runKinMcp([], {
      env,
      cwd: tmpDir,
      stdout: discard,
      stderr: discard,
      stdio: 'ignore'
    });

    assert.equal(exitCode, 0);
    assert.equal(await fs.readFile(profilePath, 'utf8'), 'agent-default');
  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});

test('runKinMcp emits a guided fix when no binary can be provisioned', async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'kin-mcp-guided-'));
  let stderr = '';
  try {
    const exitCode = await runKinMcp([], {
      env: {
        KIN_MCP_CACHE_DIR: tmpDir,
        KIN_MCP_RELEASE_BASE_URL: 'http://127.0.0.1:1'
      },
      platform: 'linux',
      arch: 'x64',
      version: '9.9.9-test',
      cwd: tmpDir,
      stderr: { write(chunk) { stderr += chunk; } },
      stdio: 'ignore'
    });

    assert.equal(exitCode, 1);
    assert.match(stderr, /could not provision a runnable Kin/);
    assert.match(stderr, /kin setup/);
  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});

test('runKinMcp auto-inits when explicitly allowed', async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'kin-mcp-autoinit-'));
  const logPath = path.join(tmpDir, 'calls.txt');
  const env = await fakeKinEnvironment(tmpDir, {
    KIN_MCP_AUTO_INIT: '1',
    KIN_MCP_FAKE_LOG: logPath
  });

  try {
    const exitCode = await runKinMcp([], {
      env,
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

test('auto-init keeps MCP stdout protocol-only from process start', async () => {
  const tmpDir = await fs.mkdtemp(
    path.join(os.tmpdir(), 'kin-mcp-autoinit-protocol-')
  );
  const protocolPayload = JSON.stringify({
    jsonrpc: '2.0',
    id: 1,
    result: { protocolVersion: '2024-11-05' }
  });
  const protocolFrame =
    `Content-Length: ${Buffer.byteLength(protocolPayload)}\r\n\r\n${protocolPayload}`;
  const env = await fakeKinEnvironment(tmpDir, {
    KIN_MCP_AUTO_INIT: '1',
    KIN_MCP_FAKE_INIT_STDOUT: 'init stdout must leave the protocol channel\n',
    KIN_MCP_FAKE_INIT_STDERR: 'init stderr remains diagnostic\n',
    KIN_MCP_FAKE_PROTOCOL_BASE64: Buffer.from(protocolFrame).toString('base64')
  });

  try {
    const result = cp.spawnSync(
      process.execPath,
      [fileURLToPath(new URL('../bin/kin-mcp.js', import.meta.url))],
      {
        cwd: tmpDir,
        encoding: 'utf8',
        env
      }
    );

    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, protocolFrame);
    assert.doesNotMatch(result.stdout, /init stdout/);
    assert.match(result.stderr, /init stdout must leave the protocol channel/);
    assert.match(result.stderr, /init stderr remains diagnostic/);
  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});

test('the release base URL must be https, or loopback for a local mirror', () => {
  // The shipped default and any https mirror are fine.
  assert.equal(
    assertSecureReleaseBaseUrl(DEFAULT_RELEASE_BASE_URL),
    DEFAULT_RELEASE_BASE_URL
  );
  assert.equal(
    assertSecureReleaseBaseUrl('https://mirror.example/kin'),
    'https://mirror.example/kin'
  );

  // A loopback mirror has no network path to sit on, so plain http is allowed
  // there and only there. The wrapper's own tests drive one.
  for (const loopback of [
    'http://127.0.0.1:1',
    'http://127.0.0.1:8080/kin',
    'http://localhost:8080',
    'http://[::1]:8080'
  ]) {
    assert.equal(assertSecureReleaseBaseUrl(loopback), loopback);
  }

  // The archive and its checksum come from this same base URL, so plain http
  // to anywhere else means the integrity check grades the attacker's bytes
  // against the attacker's digest, and what lands is chmod 0755 and executed.
  for (const insecure of [
    'http://mirror.example/kin',
    'http://127.0.0.1.attacker.example/kin',
    'http://localhost.attacker.example/kin',
    'ftp://127.0.0.1/kin'
  ]) {
    assert.throws(
      () => assertSecureReleaseBaseUrl(insecure),
      /refusing to download the Kin release over/,
      insecure
    );
  }

  assert.throws(
    () => assertSecureReleaseBaseUrl('not a url'),
    /is not a URL/
  );
});
