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
  archiveExtraction,
  assertSecureReleaseBaseUrl,
  childEnv,
  DEFAULT_RELEASE_BASE_URL,
  ensureKinBinary,
  PACKAGE_VERSION,
  resolveCachedBinaryPath,
  resolveDaemonBinaryPath,
  resolveReleaseAsset,
  resolveReleaseTag,
  renderFootprint,
  runKinMcp,
  isTruthyEnv,
  findKinRepository,
  noRepositoryNotice,
  enclosingRepositoryNotice,
  profileServesInit,
  servedToolProfile
} from '../src/index.js';
import {
  createFrameReader,
  encodeFrame,
  INSTRUCTIONS_BY_NAME,
  instructionsForProfile,
  MCP_PROTOCOL_VERSION,
  STARTUP_STATUS_TOOL
} from '../src/first-launch.js';
import { PassThrough } from 'node:stream';

test('removal suggestions preserve special paths as shell literals', () => {
  const targets = [
    '/tmp/Kin cache $NAME',
    '/tmp/$(printf expanded)`printf expanded`',
    `/tmp/it's "Kin"; printf expanded`,
    '-leading-option[glob]*?'
  ];
  for (const target of targets) {
    const entries = [{ path: target, bytes: 0, what: 'fixture' }];
    const posix = renderFootprint(entries, 'linux').split('\n')
      .find(line => line.startsWith('  rm -rf -- ')).trim();
    const literal = posix.slice('rm -rf -- '.length);
    // Only printf is executed. Never execute a displayed deletion command.
    if (process.platform !== 'win32') {
      const result = cp.spawnSync('/bin/sh', ['-c', `printf '%s' ${literal}`], { encoding: 'utf8' });
      assert.equal(result.status, 0, result.stderr);
      assert.equal(result.stdout, target);
    }

    const windows = renderFootprint(entries, 'win32').split('\n')
      .find(line => line.startsWith('  Remove-Item ')).trim();
    const psLiteral = windows.slice('Remove-Item -Recurse -Force -LiteralPath '.length);
    // PowerShell's single-quoted literal grammar: a quote inside is doubled;
    // dollar signs, backticks and wildcard characters have no expansion here.
    assert.match(psLiteral, /^'(?:[^']|'')*'$/);
    assert.equal(psLiteral.slice(1, -1).replaceAll("''", "'"), target);
    if (process.platform === 'win32') {
      const result = cp.spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command',
        `[Console]::Write(${psLiteral})`], { encoding: 'utf8' });
      assert.equal(result.status, 0, result.stderr);
      assert.equal(result.stdout, target);
    }
  }
});

// The archive layout is a property of the target; the extractor is a property
// of the host. Reading `process.platform` inside the target branch conflated
// them, and the native Windows leg went red on three tests that unpack a Unix
// archive on a Windows runner, where /usr/bin/tar does not exist. All four
// combinations are asserted here rather than only the two a single runner can
// reach, so neither leg has to be the place this is discovered.
test('the extractor is chosen by the host and the layout by the target', () => {
  const winEnv = { SystemRoot: 'C:\\Windows' };
  const sys32Tar = path.win32.join('C:\\Windows', 'System32', 'tar.exe');

  // Windows target.
  assert.deepEqual(archiveExtraction('win32', winEnv, 'a.zip', 'win32'), {
    executable: sys32Tar,
    args: ['-xf', 'a.zip', '-C', '.']
  });
  assert.deepEqual(archiveExtraction('win32', {}, 'a.zip', 'linux'), {
    executable: '/usr/bin/unzip',
    args: ['-q', 'a.zip', '-d', '.']
  });

  // Unix target. On a Windows host this is the cross-target case, and it must
  // not reach for /usr/bin.
  assert.deepEqual(archiveExtraction('linux', winEnv, 'a.tar.gz', 'win32'), {
    executable: sys32Tar,
    args: ['-xf', 'a.tar.gz', '-C', '.']
  });

  // On a Unix host it is an absolute system tar, never a bare name PATH would
  // resolve. Asserted as a property so the test does not care which of the two
  // trusted directories this machine keeps tar in.
  if (process.platform !== 'win32') {
    const unix = archiveExtraction('linux', {}, 'a.tar.gz', 'linux');
    assert.ok(
      unix.executable === '/usr/bin/tar' || unix.executable === '/bin/tar',
      `expected an absolute system tar, got ${unix.executable}`
    );
    assert.deepEqual(unix.args, ['-xf', 'a.tar.gz', '-C', '.']);
  }
});

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
  "if (command === 'init' || command === 'mcp' || command === 'daemon') {",
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

function mockReleaseFetch(t, version, archiveName, archiveBytes, checksum) {
  const baseUrl = 'https://releases.example.invalid';
  t.mock.method(globalThis, 'fetch', async url => {
    if (url === `${baseUrl}/v${version}/${archiveName}`) {
      return new Response(archiveBytes, { headers: { 'content-type': 'application/octet-stream' } });
    }
    if (url === `${baseUrl}/v${version}/${archiveName}.sha256`) {
      return new Response(`${checksum}  ${archiveName}\n`);
    }
    return new Response('not found', { status: 404, statusText: 'Not Found' });
  });
  return baseUrl;
}

test('ensureKinBinary downloads kin and its daemon from a release asset', async t => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'kin-mcp-download-'));
  const assetName = 'kin-linux-x86_64';
  const version = '9.9.9-test';
  const { archiveBytes, archiveName, checksum, kinBytes, daemonBytes } =
    await buildReleaseArchive(tmpDir, assetName);
  const baseUrl = mockReleaseFetch(t, version, archiveName, archiveBytes, checksum);
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
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});

test('ensureKinBinary installs the flat native Windows zip and .exe pair', async t => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'kin-mcp-windows-download-'));
  const assetName = 'kin-windows-x86_64';
  const version = '9.9.9-test';
  const { archiveBytes, archiveName, checksum, kinBytes, daemonBytes } =
    await buildReleaseArchive(tmpDir, assetName, { platform: 'win32' });
  const baseUrl = mockReleaseFetch(t, version, archiveName, archiveBytes, checksum);
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
  async t => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'kin-mcp-hostile-tar-'));
    const assetName = 'kin-linux-x86_64';
    const version = '9.9.9-test';
    const { archiveBytes, archiveName, checksum, kinBytes, daemonBytes } =
      await buildReleaseArchive(tmpDir, assetName);
    const baseUrl = mockReleaseFetch(t, version, archiveName, archiveBytes, checksum);
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
        await fs.rm(tmpDir, { recursive: true, force: true });
    }
  }
);

test('ensureKinBinary fails with a precise message when the archive omits kin-daemon', async t => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'kin-mcp-nodaemon-'));
  const assetName = 'kin-linux-x86_64';
  const version = '9.9.9-test';
  const { archiveBytes, archiveName, checksum } = await buildReleaseArchive(
    tmpDir,
    assetName,
    { includeDaemon: false }
  );
  const baseUrl = mockReleaseFetch(t, version, archiveName, archiveBytes, checksum);
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
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});

test('ensureKinBinary rejects a failed archive response', async t => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'kin-mcp-http-error-'));
  t.mock.method(globalThis, 'fetch', async () =>
    new Response('not found', { status: 404, statusText: 'Not Found' }));
  try {
    await assert.rejects(ensureKinBinary({
      env: { KIN_MCP_CACHE_DIR: tmpDir }, platform: 'linux', arch: 'x64', version: '9.9.9-test'
    }), /failed to download .*404 Not Found/);
  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});

test('ensureKinBinary rejects archive bytes that disagree with the checksum', async t => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'kin-mcp-corrupt-'));
  const version = '9.9.9-test';
  const { archiveBytes, archiveName } = await buildReleaseArchive(tmpDir, 'kin-linux-x86_64');
  const baseUrl = mockReleaseFetch(t, version, archiveName, archiveBytes, '0'.repeat(64));
  try {
    await assert.rejects(ensureKinBinary({
      env: { KIN_MCP_CACHE_DIR: tmpDir, KIN_MCP_RELEASE_BASE_URL: baseUrl },
      platform: 'linux', arch: 'x64', version
    }), /checksum mismatch/i);
    assert.equal(await exists(resolveCachedBinaryPath({
      env: { KIN_MCP_CACHE_DIR: tmpDir }, platform: 'linux', arch: 'x64', version
    })), false);
  } finally {
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
    // Commands the reader has: the MCP tool, and the npx form of this
    // release, since a registry install puts no `kin` on PATH.
    assert.match(stderr, /call kin_init/);
    assert.match(stderr, /npx -y @kinlab\/kin@\S+ init \./);
    assert.doesNotMatch(stderr, /Run `kin init \.`/);
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
    assert.match(result.stderr, /call kin_init/);
    assert.equal(await exists(path.join(tmpDir, '.kin')), false);
  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});

test('the notices name commands a registry user has, pinned to this release', () => {
  const notice = noRepositoryNotice('/work/app', '9.9.9');
  assert.match(notice, /\/work\/app is not a Kin repository/);
  assert.match(notice, /call kin_init/);
  assert.match(notice, /`npx -y @kinlab\/kin@9\.9\.9 init \.`/);
  assert.ok(noRepositoryNotice('/w').includes(`@kinlab/kin@${PACKAGE_VERSION} init`));
  const enclosing = enclosingRepositoryNotice('/work/repo/app', '/work/repo');
  assert.match(enclosing, /\/work\/repo\/app is not a Kin repository of its own/);
  assert.match(enclosing, /serves the Kin repository at\n?\s*\/work\/repo/);
  assert.match(enclosing, /kin_init/);
  assert.doesNotMatch(notice + enclosing, /\u2014/);
});

// Setting a folder up is a write, so a read-only profile never offers kin_init,
// and names the command a person runs instead.
test('only a profile that writes is told to call kin_init', () => {
  for (const profile of ['agent-default', 'agent-routed', 'full', undefined]) {
    assert.equal(profileServesInit(profile), true, String(profile));
    assert.match(noRepositoryNotice('/w', '9.9.9', { profile }), /call kin_init/);
    assert.match(enclosingRepositoryNotice('/w/app', '/w', { profile }), /call kin_init/);
  }
  for (const profile of ['agent-query', 'agent-search', 'agent-routed-query', 'benchmark', 'context-bench']) {
    assert.equal(profileServesInit(profile), false, profile);
    const unbound = noRepositoryNotice('/w', '9.9.9', { profile });
    const nested = enclosingRepositoryNotice('/w/app', '/w', { profile, version: '9.9.9' });
    assert.doesNotMatch(unbound + nested, /kin_init/, profile);
    assert.match(unbound, /To set this folder up, run\n`npx -y @kinlab\/kin@9\.9\.9 init \.`/, profile);
    assert.match(nested, /`npx -y @kinlab\/kin@9\.9\.9 init \.` in it\./, profile);
  }
});

// `kin mcp start` trims the profile it is handed, reads it in any case, and
// serves agent-default when the value is empty or names no profile, so the
// notice decides the same way and offers kin_init exactly when it is served.
test('profileServesInit resolves a profile the way kin mcp start does', () => {
  for (const profile of ['AGENT-ROUTED', ' Full ', 'Agent-Default', '', '   ', null, 'agent-defualt']) {
    assert.equal(profileServesInit(profile), true, JSON.stringify(profile));
  }
  for (const profile of ['AGENT-QUERY', ' agent-routed-query ', 'Context-Bench', 'Agent-Search']) {
    assert.equal(profileServesInit(profile), false, profile);
    assert.doesNotMatch(noRepositoryNotice('/w', '9.9.9', { profile }), /kin_init/, profile);
  }
});

// The walk `kin mcp start` makes, so the notice names the repository that
// will actually answer.
test('findKinRepository walks up the way kin mcp start does', async () => {
  const tmpDir = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'kin-mcp-walk-')));
  const home = path.join(tmpDir, 'home');
  try {
    const repo = path.join(tmpDir, 'repo');
    const nested = path.join(repo, 'packages', 'app');
    await fs.mkdir(path.join(repo, '.kin'), { recursive: true });
    await fs.mkdir(nested, { recursive: true });
    await fs.mkdir(home, { recursive: true });
    const options = { env: {}, homeDir: home };

    assert.equal(await findKinRepository(repo, options), repo);
    assert.equal(await findKinRepository(nested, options), repo, 'a plain nested folder is served by the repository above it');

    // A nested Git repository with no store of its own is a boundary.
    await fs.mkdir(path.join(nested, '.git'));
    assert.equal(await findKinRepository(nested, options), null);
    assert.equal(
      await findKinRepository(nested, { env: { KIN_ALLOW_PARENT_STORE: '1' }, homeDir: home }),
      repo
    );

    // Kin's own install root is never a repository.
    const outside = path.join(home, 'projects', 'x');
    await fs.mkdir(outside, { recursive: true });
    await fs.mkdir(path.join(home, '.kin', 'bin'), { recursive: true });
    await fs.writeFile(path.join(home, '.kin', 'registry.toml'), '');
    assert.equal(await findKinRepository(outside, options), null);
  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});

// The walkthrough's shape: a folder with no repository of its own inside one that
// has a store. The wrapper names the repository that will answer, and even an
// explicit KIN_MCP_AUTO_INIT does not initialize over it.
test('runKinMcp names the enclosing repository instead of saying none is bound', async () => {
  const tmpDir = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'kin-mcp-nested-')));
  const nested = path.join(tmpDir, 'scratch', 'walkthrough');
  await fs.mkdir(path.join(tmpDir, '.kin'), { recursive: true });
  await fs.mkdir(nested, { recursive: true });
  const logPath = path.join(tmpDir, 'calls.txt');
  // The fake's preload is required relative to the launch directory.
  const env = await fakeKinEnvironment(nested, {
    KIN_MCP_AUTO_INIT: '1',
    KIN_MCP_FAKE_LOG: logPath
  });
  delete env.KIN_MCP_FAKE_REPO;

  try {
    let stderr = '';
    const exitCode = await runKinMcp([], {
      env,
      cwd: nested,
      stderr: { write(chunk) { stderr += chunk; } },
      stdio: 'ignore'
    });
    assert.equal(exitCode, 0);
    assert.match(stderr, /is not a Kin repository of its own/);
    assert.ok(stderr.includes(tmpDir), stderr);
    assert.doesNotMatch(stderr, /neither is any folder above it/);
    assert.equal(await fs.readFile(logPath, 'utf8'), 'mcp\nstart\n', 'no kin init over an enclosing repository');
    assert.equal(await exists(path.join(nested, '.kin')), false);
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

// Removing `kin` from a client's config stops nothing, so the wrapper owns a
// stop: it reaches the daemons through the Kin it already cached, stops only
// the ones nothing is using, and says what stays on disk and how to remove it.
test('--stop stops idle daemons through the cached kin and names what stays on disk', async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'kin-mcp-stop-'));
  const argsPath = path.join(tmpDir, 'args.txt');
  const home = path.join(tmpDir, 'home');
  const kinHome = path.join(home, '.kin');
  const cache = path.join(tmpDir, 'cache');
  const model = path.join(
    home,
    '.cache',
    'huggingface',
    'hub',
    'models--nomic-ai--nomic-embed-text-v1.5'
  );
  await fs.mkdir(kinHome, { recursive: true });
  await fs.mkdir(cache, { recursive: true });
  await fs.mkdir(model, { recursive: true });
  await fs.writeFile(path.join(model, 'model.safetensors'), Buffer.alloc(3 * 1024 * 1024));
  const env = await fakeKinEnvironment(tmpDir, {
    KIN_MCP_FAKE_LOG: argsPath,
    KIN_HOME: kinHome,
    KIN_MCP_CACHE_DIR: cache
  });

  try {
    let stdout = '';
    const exitCode = await runKinMcp(['--stop'], {
      env,
      cwd: tmpDir,
      homeDir: home,
      stdout: { write(chunk) { stdout += chunk; } },
      stderr: { write() {} },
      stdio: 'ignore'
    });

    assert.equal(exitCode, 0);
    assert.equal(
      await fs.readFile(argsPath, 'utf8'),
      'daemon\nstop\n--all\n--when-unused\n',
      'the stop must never take a daemon out from under a client still using it'
    );
    assert.match(stdout, /What stays on this machine/);
    for (const entry of [cache, kinHome, model]) {
      assert.ok(stdout.includes(entry), `missing ${entry} in:\n${stdout}`);
    }
    assert.match(stdout, /3 MB/, stdout);
    assert.match(stdout, /embedding model/, stdout);
    assert.match(stdout, /\.kin directory beside its code/, stdout);
    if (process.platform !== 'win32') {
      assert.ok(stdout.includes(`rm -rf -- '${model.replaceAll("'", "'\\''")}'`), stdout);
    }
  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});

test('--stop never downloads a Kin just to stop daemons', async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'kin-mcp-stop-nocache-'));
  try {
    let stdout = '';
    const exitCode = await runKinMcp(['--stop'], {
      env: {
        KIN_MCP_CACHE_DIR: path.join(tmpDir, 'empty-cache'),
        KIN_MCP_RELEASE_BASE_URL: 'http://127.0.0.1:1',
        KIN_HOME: path.join(tmpDir, 'kin-home')
      },
      platform: 'linux',
      arch: 'x64',
      version: '9.9.9-test',
      homeDir: tmpDir,
      cwd: tmpDir,
      stdout: { write(chunk) { stdout += chunk; } },
      stderr: { write() {} },
      stdio: 'ignore'
    });

    assert.equal(exitCode, 0);
    assert.match(stdout, /no Kin binary is cached here/);
    assert.equal(await exists(path.join(tmpDir, 'empty-cache')), false, 'nothing was fetched');
  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
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

// ---------------------------------------------------------------------------
// First launch: the handshake is answered while the release downloads.
// ---------------------------------------------------------------------------

// How long a first launch may take to answer `initialize` and `tools/list`.
// Before the fix the wrapper answered neither until the release archive had
// finished downloading, and the download in these tests never finishes, so any
// bound fails the old behavior. This one leaves room for a slow CI host while
// staying well inside the startup timeouts MCP clients apply.
const HANDSHAKE_BOUND_MS = 5_000;
const MIB = 1024 * 1024;

const wrapperBin = fileURLToPath(new URL('../bin/kin-mcp.js', import.meta.url));

/** The wrapper's environment with every way around a download removed. */
function firstLaunchEnv(tmpDir, overrides = {}) {
  const env = { ...process.env };
  for (const name of Object.keys(env)) {
    const upper = name.toUpperCase();
    if (
      upper.startsWith('KIN_') ||
      upper === 'NODE_OPTIONS' ||
      upper === 'NODE_USE_ENV_PROXY' ||
      upper.endsWith('_PROXY')
    ) {
      delete env[name];
    }
  }
  const home = path.join(tmpDir, 'home');
  return {
    ...env,
    HOME: home,
    USERPROFILE: home,
    KIN_HOME: path.join(home, '.kin'),
    KIN_MCP_CACHE_DIR: path.join(tmpDir, 'cache'),
    ...overrides
  };
}

/** Run the published entrypoint and read its stdout as MCP messages. */
function startWrapper({ cwd, env }) {
  const child = cp.spawn(process.execPath, [wrapperBin], {
    cwd,
    env,
    stdio: ['pipe', 'pipe', 'pipe'],
    windowsHide: true
  });
  const received = [];
  const waiters = new Set();
  let stderr = '';
  const reader = createFrameReader(frame => {
    received.push({ message: JSON.parse(frame.text), at: performance.now(), framed: frame.framed });
    for (const waiter of [...waiters]) {
      waiter();
    }
  });
  child.stdout.on('data', chunk => reader.push(chunk));
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', chunk => {
    stderr += chunk;
  });
  const exited = new Promise(resolve => {
    child.on('close', (code, signal) => resolve({ code, signal }));
  });
  return {
    child,
    received,
    exited,
    get stderr() {
      return stderr;
    },
    send(message, framed = false) {
      child.stdin.write(encodeFrame(message, framed));
    },
    waitFor(predicate, timeoutMs, label) {
      return new Promise((resolve, reject) => {
        const check = () => {
          const found = received.find(entry => predicate(entry.message));
          if (found) {
            clearTimeout(timer);
            waiters.delete(check);
            resolve(found);
          }
        };
        const timer = setTimeout(() => {
          waiters.delete(check);
          reject(new Error(`timed out waiting for ${label}; stderr:\n${stderr}`));
        }, timeoutMs);
        waiters.add(check);
        check();
      });
    }
  };
}

/**
 * A loopback release mirror whose answers each test controls.
 *
 * Resolves to null, with the test marked skipped, when this process may not
 * listen on loopback at all. The public export runs its checks in a sandbox
 * that denies every network operation, loopback included, and these tests
 * cannot run there; everywhere else they run. Any other listen failure fails
 * the test.
 */
async function startMirror(t, handler) {
  const server = http.createServer(handler);
  try {
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', () => {
        server.off('error', reject);
        resolve();
      });
    });
  } catch (error) {
    if (error.code === 'EPERM') {
      t.skip('this process may not listen on loopback, as in the public export sandbox');
      return null;
    }
    throw error;
  }
  t.after(async () => {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  });
  return `http://127.0.0.1:${server.address().port}`;
}

function initializeRequest(id = 1) {
  return {
    jsonrpc: '2.0',
    id,
    method: 'initialize',
    params: {
      protocolVersion: MCP_PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: { name: 'first-launch-test', version: '1.0.0' }
    }
  };
}

function toolCall(id, name, args = {}) {
  return { jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } };
}

function textOf(result) {
  return result.content.map(part => part.text).join('\n');
}

test('MCP messages are read in both stdio framings, across chunk boundaries', () => {
  const frames = [];
  const reader = createFrameReader(frame => frames.push(frame));
  const line = '{"jsonrpc":"2.0","id":1,"method":"ping"}\n';
  const body = '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"note":"a\\nb é"}}';
  const framed = `Content-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`;
  const stream = Buffer.from(`\r\n${line}${framed}\n\n{"id":3}\r\n`);
  for (let offset = 0; offset < stream.length; offset += 7) {
    reader.push(stream.subarray(offset, offset + 7));
  }
  assert.deepEqual(
    frames.map(frame => [frame.framed, JSON.parse(frame.text).id]),
    [[false, 1], [true, 2], [false, 3]]
  );
  assert.equal(frames[0].raw.toString(), line);
  assert.equal(frames[1].raw.toString(), framed);
});

// The wrapper answers `initialize` before `kin mcp start` exists and then hands
// it the session, so it has to speak the version that server speaks.
test('the first-launch handshake speaks the protocol version kin mcp start speaks', async () => {
  const serverSource = await fs.readFile(
    new URL('../../../crates/kin-mcp/src/server.rs', import.meta.url),
    'utf8'
  );
  const declared = /const SUPPORTED_PROTOCOL_VERSION: &str = "([^"]+)";/.exec(serverSource);
  assert.ok(declared, 'crates/kin-mcp/src/server.rs no longer declares SUPPORTED_PROTOCOL_VERSION');
  assert.equal(MCP_PROTOCOL_VERSION, declared[1]);
});

/** The value of a Rust string literal, from its source text between the quotes. */
function rustStringValue(source) {
  let value = '';
  for (let index = 0; index < source.length; index += 1) {
    const char = source[index];
    if (char !== '\\') {
      value += char;
      continue;
    }
    index += 1;
    const escaped = source[index];
    if (escaped === '\n' || escaped === '\r') {
      // A line continuation: the newline and the next line's leading
      // whitespace are not part of the string.
      while (index + 1 < source.length && /\s/.test(source[index + 1])) {
        index += 1;
      }
    } else if (escaped === 'n') {
      value += '\n';
    } else if (escaped === 't') {
      value += '\t';
    } else if (escaped === '"' || escaped === '\\' || escaped === "'") {
      value += escaped;
    } else {
      throw new Error(`an escape this test does not read: \\${escaped}`);
    }
  }
  return value;
}

// The instructions texts `kin mcp start` picks from, by the name of their Rust
// constant. `instructions_for` in crates/kin-mcp/src/server.rs picks one of
// these for each profile.
const SERVER_INSTRUCTION_CONSTANTS = [
  'SERVER_INSTRUCTIONS',
  'SEARCH_SERVER_INSTRUCTIONS',
  'ROUTED_SERVER_INSTRUCTIONS',
  'ROUTED_QUERY_SERVER_INSTRUCTIONS',
  'LEGACY_SERVER_INSTRUCTIONS'
];

// MCP hands a server's instructions to the client once, in the answer to
// `initialize`, and a first launch gives that answer before `kin mcp start`
// exists. So the wrapper carries every text that server gives a profile, and
// each has to be the server's own, byte for byte. Which profile gets which is
// held from the other side, by a test in kin-cli's `commands/mcp.rs` that asks
// the server itself.
test('the first-launch handshake carries the instructions kin mcp start carries', async () => {
  const serverSource = await fs.readFile(
    new URL('../../../crates/kin-mcp/src/server.rs', import.meta.url),
    'utf8'
  );
  assert.deepEqual(
    Object.keys(INSTRUCTIONS_BY_NAME).sort(),
    [...SERVER_INSTRUCTION_CONSTANTS].sort(),
    'the wrapper carries exactly the texts the server picks from'
  );
  for (const name of SERVER_INSTRUCTION_CONSTANTS) {
    const declared = new RegExp(`const ${name}: &str = "((?:[^"\\\\]|\\\\[\\s\\S])*)";`).exec(
      serverSource
    );
    assert.ok(declared, `crates/kin-mcp/src/server.rs no longer declares ${name}`);
    assert.equal(INSTRUCTIONS_BY_NAME[name], rustStringValue(declared[1]), name);
  }
  // The texts differ, so a launch handed the wrong one cannot pass for right.
  assert.equal(
    new Set(Object.values(INSTRUCTIONS_BY_NAME)).size,
    SERVER_INSTRUCTION_CONSTANTS.length
  );
  // The control: the reader turns a line continuation into nothing and an
  // escaped quote into a quote, which is what the constants above are made of.
  assert.equal(rustStringValue('a \\\n    b \\"c\\"'), 'a b "c"');
});

test('a first launch answers the handshake while the release download is still pending', async t => {
  let asset;
  try {
    asset = resolveReleaseAsset(process.platform, process.arch);
  } catch {
    t.skip(`no Kin release is published for ${process.platform}/${process.arch}`);
    return;
  }
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'kin-mcp-first-launch-'));
  t.after(() => fs.rm(tmpDir, { recursive: true, force: true }));
  const tag = resolveReleaseTag(PACKAGE_VERSION);
  let archiveRequested = false;
  // The checksum is served at once. The archive announces 47 MiB, sends three,
  // and then never sends another byte, so the download stays in flight for as
  // long as the test runs.
  const baseUrl = await startMirror(t, (request, response) => {
    if (request.url === `/${tag}/${asset.archiveName}.sha256`) {
      response.end(`${'0'.repeat(64)}  ${asset.archiveName}\n`);
    } else if (request.url === `/${tag}/${asset.archiveName}`) {
      archiveRequested = true;
      response.writeHead(200, { 'content-length': String(47 * MIB) });
      response.write(Buffer.alloc(3 * MIB));
    } else {
      response.writeHead(404).end();
    }
  });
  if (baseUrl === null) return;
  const repoDir = path.join(tmpDir, 'repo');
  await fs.mkdir(path.join(repoDir, '.kin'), { recursive: true });
  const wrapper = startWrapper({
    cwd: repoDir,
    env: firstLaunchEnv(tmpDir, { KIN_MCP_RELEASE_BASE_URL: baseUrl })
  });
  t.after(() => wrapper.child.kill('SIGKILL'));

  const sentAt = performance.now();
  wrapper.send(initializeRequest(1), true);
  wrapper.send({ jsonrpc: '2.0', method: 'notifications/initialized' }, true);
  wrapper.send({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }, true);
  const initialized = await wrapper.waitFor(m => m.id === 1, HANDSHAKE_BOUND_MS, 'initialize');
  const listed = await wrapper.waitFor(m => m.id === 2, HANDSHAKE_BOUND_MS, 'tools/list');
  assert.ok(
    listed.at - sentAt < HANDSHAKE_BOUND_MS,
    `the handshake took ${Math.round(listed.at - sentAt)} ms`
  );
  assert.equal(initialized.framed, true, 'answered in the framing it was asked in');
  assert.equal(initialized.message.result.protocolVersion, MCP_PROTOCOL_VERSION);
  assert.deepEqual(initialized.message.result.capabilities, { tools: { listChanged: true } });
  assert.equal(initialized.message.result.serverInfo.name, 'kin-mcp');
  assert.equal(
    initialized.message.result.instructions,
    instructionsForProfile('agent-default'),
    'the session keeps these instructions, so they are the ones kin mcp start gives the ' +
      'profile it serves when none is named'
  );
  assert.deepEqual(
    listed.message.result.tools.map(tool => tool.name),
    [STARTUP_STATUS_TOOL],
    'only a tool the wrapper can answer is listed before Kin exists'
  );

  // The status tool says how far the download has come.
  let status = null;
  for (let attempt = 0; attempt < 50; attempt += 1) {
    const id = 100 + attempt;
    wrapper.send(toolCall(id, STARTUP_STATUS_TOOL), true);
    status = (await wrapper.waitFor(m => m.id === id, HANDSHAKE_BOUND_MS, 'the status')).message;
    if (textOf(status.result).includes('3 of 47 MB')) {
      break;
    }
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  assert.equal(archiveRequested, true, 'the archive download is in flight');
  assert.equal(status.result.isError, false);
  assert.ok(
    textOf(status.result).startsWith(
      `Kin is downloading ${asset.archiveName} for this machine (3 of 47 MB)`
    )
  );

  // A Kin tool called this early is told the same, not left waiting.
  wrapper.send(toolCall(3, 'semantic_search', { query: 'where is the config read' }), true);
  const early = (await wrapper.waitFor(m => m.id === 3, HANDSHAKE_BOUND_MS, 'the early call'))
    .message;
  assert.equal(early.result.isError, true);
  assert.match(textOf(early.result), /^Kin cannot answer semantic_search yet\. Kin is downloading/);
  assert.equal(wrapper.child.exitCode, null, 'the wrapper is still serving');
});

// `kin mcp start` picks its instructions by the profile it serves, and a client
// keeps the ones a first launch gives it for the whole session. So a first
// launch answers with the ones for the profile the server it starts will serve,
// resolved from KIN_MCP_TOOL_PROFILE the way that server resolves it. Before
// this, every first launch was handed the text only `benchmark` and
// `context-bench` are served.
test('a first launch hands out the instructions for the profile kin mcp start will serve', async t => {
  let asset;
  try {
    asset = resolveReleaseAsset(process.platform, process.arch);
  } catch {
    t.skip(`no Kin release is published for ${process.platform}/${process.arch}`);
    return;
  }
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'kin-mcp-first-launch-profile-'));
  t.after(() => fs.rm(tmpDir, { recursive: true, force: true }));
  const tag = resolveReleaseTag(PACKAGE_VERSION);
  // The download never finishes, so every answer is the first launch's own.
  const baseUrl = await startMirror(t, (request, response) => {
    if (request.url === `/${tag}/${asset.archiveName}.sha256`) {
      response.end(`${'0'.repeat(64)}  ${asset.archiveName}\n`);
    } else if (request.url === `/${tag}/${asset.archiveName}`) {
      response.writeHead(200, { 'content-length': String(47 * MIB) });
      response.write(Buffer.alloc(MIB));
    } else {
      response.writeHead(404).end();
    }
  });
  if (baseUrl === null) return;
  const repoDir = path.join(tmpDir, 'repo');
  await fs.mkdir(path.join(repoDir, '.kin'), { recursive: true });

  const cases = [
    [undefined, 'agent-default'],
    ['agent-routed', 'agent-routed'],
    [' Agent-Routed-Query ', 'agent-routed-query'],
    ['AGENT-SEARCH', 'agent-search'],
    ['context-bench', 'context-bench'],
    ['agent-defualt', 'agent-default']
  ];
  for (const [index, [value, served]] of cases.entries()) {
    assert.equal(servedToolProfile(value), served, JSON.stringify(value));
    const overrides = { KIN_MCP_RELEASE_BASE_URL: baseUrl };
    if (value !== undefined) {
      overrides.KIN_MCP_TOOL_PROFILE = value;
    }
    const wrapper = startWrapper({
      cwd: repoDir,
      env: firstLaunchEnv(path.join(tmpDir, `launch-${index}`), overrides)
    });
    try {
      wrapper.send(initializeRequest(1));
      const answer = await wrapper.waitFor(
        m => m.id === 1,
        HANDSHAKE_BOUND_MS,
        `initialize under ${JSON.stringify(value)}`
      );
      assert.equal(
        answer.message.result.instructions,
        instructionsForProfile(served),
        `KIN_MCP_TOOL_PROFILE=${JSON.stringify(value)} is served as ${served}`
      );
    } finally {
      wrapper.child.kill('SIGKILL');
      await wrapper.exited;
    }
  }
  // Every text the server picks from was handed out above, so none of them is
  // left unchecked on this path.
  assert.equal(
    new Set(cases.map(([, served]) => instructionsForProfile(served))).size,
    SERVER_INSTRUCTION_CONSTANTS.length
  );
});

test('a failed first-launch download is reported in the answer to every tool call', async t => {
  let asset;
  try {
    asset = resolveReleaseAsset(process.platform, process.arch);
  } catch {
    t.skip(`no Kin release is published for ${process.platform}/${process.arch}`);
    return;
  }
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'kin-mcp-first-launch-fail-'));
  t.after(() => fs.rm(tmpDir, { recursive: true, force: true }));
  // The mirror refuses only once the client has its session. A failure before
  // any client spoke is reported on stderr and ends the process, as it did
  // before there was a session to report it into.
  let handshakeDone;
  const handshake = new Promise(resolve => {
    handshakeDone = resolve;
  });
  const baseUrl = await startMirror(t, (request, response) => {
    handshake.then(() => response.writeHead(404, 'Not Found').end());
  });
  if (baseUrl === null) return;
  const repoDir = path.join(tmpDir, 'repo');
  await fs.mkdir(path.join(repoDir, '.kin'), { recursive: true });
  const wrapper = startWrapper({
    cwd: repoDir,
    env: firstLaunchEnv(tmpDir, { KIN_MCP_RELEASE_BASE_URL: baseUrl })
  });
  t.after(() => wrapper.child.kill('SIGKILL'));

  wrapper.send(initializeRequest(1));
  await wrapper.waitFor(m => m.id === 1, HANDSHAKE_BOUND_MS, 'initialize');
  handshakeDone();
  let answer = null;
  for (let attempt = 0; attempt < 50; attempt += 1) {
    const id = 10 + attempt;
    wrapper.send(toolCall(id, 'semantic_search', { query: 'anything' }));
    answer = (await wrapper.waitFor(m => m.id === id, HANDSHAKE_BOUND_MS, 'the answer')).message;
    if (textOf(answer.result).startsWith('kin-mcp could not provision')) {
      break;
    }
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  assert.equal(answer.result.isError, true);
  assert.match(textOf(answer.result), /could not provision a runnable Kin: .*404 Not Found/);
  assert.match(textOf(answer.result), /Fixes:/);
  assert.match(wrapper.stderr, /could not provision a runnable Kin/);
  assert.equal(
    (await fs.readdir(path.join(tmpDir, 'cache', resolveReleaseTag(PACKAGE_VERSION), asset.assetName)))
      .length,
    0,
    'a failed download leaves no binary behind'
  );

  wrapper.child.stdin.end();
  assert.deepEqual(await wrapper.exited, { code: 1, signal: null });
});

// A release archive laid out as the real one is, whose `kin` runs a fake Kin
// written in node. The fake answers `kin mcp start` over newline-delimited
// JSON-RPC and `kin init`, and each test steers it through the environment:
//   KIN_MCP_FAKE_SERVER_LOG       every argv and message it sees, one per line
//   KIN_MCP_FAKE_HOLD_INITIALIZE  a path; `initialize` is answered once it exists
//   KIN_MCP_FAKE_REFUSE_INITIALIZE=1  answer `initialize` with an error, stay up
//   KIN_MCP_FAKE_SILENT=1         answer nothing, stay up
//   KIN_MCP_FAKE_INIT_HOLD        a path; `kin init` finishes once it exists
//   KIN_MCP_FAKE_INIT_EXIT        the exit code `kin init` finishes with
const fakeKinSource = [
  "const fs = require('node:fs');",
  'const env = process.env;',
  "const log = line => fs.appendFileSync(env.KIN_MCP_FAKE_SERVER_LOG, JSON.stringify(line) + '\\n');",
  'log({ argv: process.argv.slice(2), pid: process.pid });',
  'const waitFor = (marker, then) => {',
  '  if (!marker || fs.existsSync(marker)) return then();',
  '  setTimeout(() => waitFor(marker, then), 20);',
  '};',
  "if (process.argv[2] === 'init') {",
  '  waitFor(env.KIN_MCP_FAKE_INIT_HOLD, () => {',
  "    process.stderr.write('fatal: the fake init stopped here\\n', () => {",
  "      process.exit(Number(env.KIN_MCP_FAKE_INIT_EXIT || '0'));",
  '    });',
  '  });',
  '} else {',
  "  const reply = message => process.stdout.write(JSON.stringify(message) + '\\n');",
  "  let buffer = '';",
  "  process.stdin.setEncoding('utf8');",
  "  process.stdin.on('data', chunk => {",
  '    buffer += chunk;',
  '    let newline;',
  "    while ((newline = buffer.indexOf('\\n')) >= 0) {",
  '      const line = buffer.slice(0, newline).trim();',
  '      buffer = buffer.slice(newline + 1);',
  '      if (!line) continue;',
  '      const message = JSON.parse(line);',
  '      log(message);',
  "      if (message.id === undefined || env.KIN_MCP_FAKE_SILENT === '1') continue;",
  "      if (message.method === 'initialize') {",
  "        if (env.KIN_MCP_FAKE_REFUSE_INITIALIZE === '1') {",
  "          reply({ jsonrpc: '2.0', id: message.id, error: { code: -32600, message: 'refused for the test' } });",
  '          continue;',
  '        }',
  '        const id = message.id;',
  "        waitFor(env.KIN_MCP_FAKE_HOLD_INITIALIZE, () => reply({ jsonrpc: '2.0', id, result: { protocolVersion: '2024-11-05', capabilities: { tools: { listChanged: false } }, serverInfo: { name: 'kin-mcp', version: 'fake' } } }));",
  "      } else if (message.method === 'tools/list') {",
  "        reply({ jsonrpc: '2.0', id: message.id, result: { tools: [{ name: 'semantic_search', description: 'fake', inputSchema: { type: 'object' } }] } });",
  "      } else if (message.method === 'tools/call') {",
  "        reply({ jsonrpc: '2.0', id: message.id, result: { content: [{ type: 'text', text: 'served by the extracted kin' }] } });",
  '      } else {',
  "        reply({ jsonrpc: '2.0', id: message.id, result: {} });",
  '      }',
  '    }',
  '  });',
  "  process.stdin.on('end', () => process.exit(0));",
  '}',
  ''
].join('\n');

/** Build the fake release archive for this host and return its bytes. */
async function buildFakeKinArchive(tmpDir, asset) {
  const fakeKin = path.join(tmpDir, 'fake-kin.cjs');
  await fs.writeFile(fakeKin, fakeKinSource);
  const staging = path.join(tmpDir, 'staging');
  const packageDir = path.join(staging, asset.assetName);
  await fs.mkdir(packageDir, { recursive: true });
  await fs.writeFile(
    path.join(packageDir, 'kin'),
    `#!/bin/sh\nexec "${process.execPath}" "${fakeKin}" "$@"\n`,
    { mode: 0o755 }
  );
  await fs.writeFile(path.join(packageDir, 'kin-daemon'), '#!/bin/sh\nexit 0\n', {
    mode: 0o755
  });
  cp.execFileSync('tar', ['-czf', asset.archiveName, asset.assetName], { cwd: staging });
  const archiveBytes = await fs.readFile(path.join(staging, asset.archiveName));
  const checksum = crypto.createHash('sha256').update(archiveBytes).digest('hex');
  return { archiveBytes, checksum };
}

/**
 * Serve the archive from a loopback mirror, holding its body until `release`
 * is called, so a test decides when the download lands.
 */
async function startArchiveMirror(t, asset, { archiveBytes, checksum }) {
  const tag = resolveReleaseTag(PACKAGE_VERSION);
  let release;
  const released = new Promise(resolve => {
    release = resolve;
  });
  const baseUrl = await startMirror(t, (request, response) => {
    if (request.url === `/${tag}/${asset.archiveName}.sha256`) {
      response.end(`${checksum}  ${asset.archiveName}\n`);
    } else if (request.url === `/${tag}/${asset.archiveName}`) {
      released.then(() => response.end(archiveBytes));
    } else {
      response.writeHead(404).end();
    }
  });
  if (baseUrl === null) return null;
  return { baseUrl, release };
}

async function readServerLog(serverLog) {
  try {
    return (await fs.readFile(serverLog, 'utf8'))
      .trim()
      .split('\n')
      .filter(Boolean)
      .map(line => JSON.parse(line));
  } catch {
    return [];
  }
}

async function waitForServerLog(serverLog, predicate, label, timeoutMs = 30_000) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const seen = await readServerLog(serverLog);
    if (seen.some(predicate)) {
      return seen;
    }
    if (Date.now() > deadline) {
      throw new Error(`the fake Kin never logged ${label}: ${JSON.stringify(seen)}`);
    }
    await new Promise(resolve => setTimeout(resolve, 20));
  }
}

function processIsAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

// The fake Kin is a shell script, so these run where the release archive is a
// tarball.
const onlyWithTarballs = { skip: process.platform === 'win32' };

// The whole first launch against a real archive: the handshake is answered
// while the archive is held back, and once it is released the wrapper starts
// the extracted `kin mcp start`, hands it the client's own `initialize`, and
// passes the rest of the session through. A request that arrives while that
// server is still coming up waits for it rather than being told Kin is not
// ready.
test(
  'a first launch hands the session to kin mcp start once the download lands',
  onlyWithTarballs,
  async t => {
    const asset = resolveReleaseAsset(process.platform, process.arch);
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'kin-mcp-first-launch-handoff-'));
    t.after(() => fs.rm(tmpDir, { recursive: true, force: true }));
    const serverLog = path.join(tmpDir, 'server.log');
    const initializeHold = path.join(tmpDir, 'answer-initialize');
    const mirror = await startArchiveMirror(t, asset, await buildFakeKinArchive(tmpDir, asset));
    if (mirror === null) return;

    const repoDir = path.join(tmpDir, 'repo');
    await fs.mkdir(path.join(repoDir, '.kin'), { recursive: true });
    const wrapper = startWrapper({
      cwd: repoDir,
      env: firstLaunchEnv(tmpDir, {
        KIN_MCP_RELEASE_BASE_URL: mirror.baseUrl,
        KIN_MCP_FAKE_SERVER_LOG: serverLog,
        KIN_MCP_FAKE_HOLD_INITIALIZE: initializeHold
      })
    });
    t.after(() => wrapper.child.kill('SIGKILL'));

    wrapper.send(initializeRequest(1));
    wrapper.send({ jsonrpc: '2.0', method: 'notifications/initialized' });
    wrapper.send({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} });
    await wrapper.waitFor(m => m.id === 1, HANDSHAKE_BOUND_MS, 'initialize');
    const startup = await wrapper.waitFor(m => m.id === 2, HANDSHAKE_BOUND_MS, 'tools/list');
    assert.deepEqual(startup.message.result.tools.map(tool => tool.name), [STARTUP_STATUS_TOOL]);

    // The download lands and the extracted server starts, but it has not yet
    // answered the replayed `initialize`. What arrives now waits for it.
    mirror.release();
    await waitForServerLog(serverLog, entry => entry.method === 'initialize', 'the replay');
    wrapper.send(toolCall(3, 'semantic_search', { query: 'anything' }));
    wrapper.send({ jsonrpc: '2.0', id: 4, method: 'tools/list', params: {} });
    wrapper.send(toolCall(5, STARTUP_STATUS_TOOL));
    const starting = await wrapper.waitFor(m => m.id === 5, HANDSHAKE_BOUND_MS, 'the status');
    assert.match(textOf(starting.message.result), /^Kin finished downloading and is starting/);
    await new Promise(resolve => setTimeout(resolve, 300));
    assert.equal(
      wrapper.received.some(entry => entry.message.id === 3 || entry.message.id === 4),
      false,
      'a request made while Kin starts waits for Kin rather than being refused'
    );

    await fs.writeFile(initializeHold, '');
    const answered = await wrapper.waitFor(m => m.id === 3, 10_000, 'the held call');
    assert.equal(textOf(answered.message.result), 'served by the extracted kin');
    const listed = await wrapper.waitFor(m => m.id === 4, 10_000, 'the held tools/list');
    assert.deepEqual(listed.message.result.tools.map(tool => tool.name), ['semantic_search']);
    await wrapper.waitFor(
      m => m.method === 'notifications/tools/list_changed',
      10_000,
      'the tool list change once Kin took over'
    );

    wrapper.send(toolCall(6, 'semantic_search', { query: 'anything' }));
    const forwarded = await wrapper.waitFor(m => m.id === 6, 10_000, 'the forwarded call');
    assert.equal(textOf(forwarded.message.result), 'served by the extracted kin');
    // A client that never refreshed its list can still ask the startup tool,
    // and the answer claims nothing about what that client lists.
    wrapper.send(toolCall(7, STARTUP_STATUS_TOOL));
    const ready = await wrapper.waitFor(m => m.id === 7, 10_000, 'the status after the hand-off');
    assert.match(textOf(ready.message.result), /^Kin is ready and serves its graph tools/);
    assert.match(textOf(ready.message.result), /If kin_startup_status is the only Kin tool/);

    wrapper.child.stdin.end();
    assert.deepEqual(await wrapper.exited, { code: 0, signal: null });

    const seen = await readServerLog(serverLog);
    assert.deepEqual(seen[0].argv, ['mcp', 'start']);
    const methods = seen.slice(1).map(message => message.method);
    assert.deepEqual(methods, [
      'initialize',
      'notifications/initialized',
      'tools/call',
      'tools/list',
      'tools/call'
    ]);
    const replayed = seen[1];
    assert.deepEqual(replayed.params, initializeRequest(1).params, "the client's own initialize");
    assert.notEqual(replayed.id, 1, 'the replay carries its own id');
    assert.deepEqual(
      seen.slice(3).map(message => message.id),
      [3, 4, 6],
      'every held and later request reaches Kin with its own id, in order'
    );
    const answeredIds = wrapper.received
      .filter(entry => entry.message.id !== undefined)
      .map(entry => entry.message.id)
      .sort((left, right) => left - right);
    assert.deepEqual(answeredIds, [1, 2, 3, 4, 5, 6, 7], "the replay's answer never reaches the client");
    assert.equal(
      existsSync(resolveCachedBinaryPath({ env: { KIN_MCP_CACHE_DIR: path.join(tmpDir, 'cache') } })),
      true,
      'the download stays cached for the next launch'
    );
  }
);

test(
  'a first launch stops kin mcp start when it refuses the replayed initialize',
  onlyWithTarballs,
  async t => {
    const asset = resolveReleaseAsset(process.platform, process.arch);
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'kin-mcp-first-launch-refused-'));
    t.after(() => fs.rm(tmpDir, { recursive: true, force: true }));
    const serverLog = path.join(tmpDir, 'server.log');
    const mirror = await startArchiveMirror(t, asset, await buildFakeKinArchive(tmpDir, asset));
    if (mirror === null) return;
    const repoDir = path.join(tmpDir, 'repo');
    await fs.mkdir(path.join(repoDir, '.kin'), { recursive: true });
    const wrapper = startWrapper({
      cwd: repoDir,
      env: firstLaunchEnv(tmpDir, {
        KIN_MCP_RELEASE_BASE_URL: mirror.baseUrl,
        KIN_MCP_FAKE_SERVER_LOG: serverLog,
        KIN_MCP_FAKE_REFUSE_INITIALIZE: '1'
      })
    });
    t.after(() => wrapper.child.kill('SIGKILL'));

    wrapper.send(initializeRequest(1));
    wrapper.send({ jsonrpc: '2.0', method: 'notifications/initialized' });
    await wrapper.waitFor(m => m.id === 1, HANDSHAKE_BOUND_MS, 'initialize');
    mirror.release();
    const seen = await waitForServerLog(serverLog, entry => entry.method === 'initialize', 'the replay');
    const serverPid = seen[0].pid;

    let answer = null;
    for (let attempt = 0; attempt < 100; attempt += 1) {
      const id = 10 + attempt;
      wrapper.send(toolCall(id, 'semantic_search', { query: 'anything' }));
      answer = (await wrapper.waitFor(m => m.id === id, 10_000, 'the answer')).message;
      if (textOf(answer.result).startsWith('kin mcp start refused')) {
        break;
      }
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    assert.equal(answer.result.isError, true);
    assert.match(textOf(answer.result), /refused the client's initialize: .*refused for the test/);
    for (let attempt = 0; attempt < 100 && processIsAlive(serverPid); attempt += 1) {
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    assert.equal(processIsAlive(serverPid), false, 'the refusing server is stopped, not left running');
    assert.equal(
      wrapper.received.some(entry => entry.message.error?.message === 'refused for the test'),
      false,
      "the refused replay's own answer never reaches the client"
    );

    wrapper.child.stdin.end();
    assert.deepEqual(await wrapper.exited, { code: 1, signal: null });
  }
);

test(
  'a first launch that runs kin init tells the agent why a failed init stopped it',
  onlyWithTarballs,
  async t => {
    const asset = resolveReleaseAsset(process.platform, process.arch);
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'kin-mcp-first-launch-init-'));
    t.after(() => fs.rm(tmpDir, { recursive: true, force: true }));
    const serverLog = path.join(tmpDir, 'server.log');
    const initHold = path.join(tmpDir, 'finish-init');
    const mirror = await startArchiveMirror(t, asset, await buildFakeKinArchive(tmpDir, asset));
    if (mirror === null) return;
    const repoDir = path.join(tmpDir, 'repo');
    await fs.mkdir(repoDir, { recursive: true });
    const wrapper = startWrapper({
      cwd: repoDir,
      env: firstLaunchEnv(tmpDir, {
        KIN_MCP_RELEASE_BASE_URL: mirror.baseUrl,
        KIN_MCP_FAKE_SERVER_LOG: serverLog,
        KIN_MCP_AUTO_INIT: '1',
        KIN_MCP_FAKE_INIT_HOLD: initHold,
        KIN_MCP_FAKE_INIT_EXIT: '3'
      })
    });
    t.after(() => wrapper.child.kill('SIGKILL'));

    wrapper.send(initializeRequest(1));
    await wrapper.waitFor(m => m.id === 1, HANDSHAKE_BOUND_MS, 'initialize');
    mirror.release();
    await waitForServerLog(serverLog, entry => entry.argv?.[0] === 'init', 'kin init');

    // While init runs, the status says so rather than that Kin is a moment away.
    wrapper.send(toolCall(2, STARTUP_STATUS_TOOL));
    const running = await wrapper.waitFor(m => m.id === 2, HANDSHAKE_BOUND_MS, 'the status');
    assert.match(textOf(running.message.result), /^Kin is running `kin init \.` in /);
    wrapper.send(toolCall(3, 'semantic_search', { query: 'anything' }));
    const early = await wrapper.waitFor(m => m.id === 3, HANDSHAKE_BOUND_MS, 'the early call');
    assert.match(textOf(early.message.result), /^Kin cannot answer semantic_search yet\. Kin is running `kin init \.`/);

    await fs.writeFile(initHold, '');
    let answer = null;
    for (let attempt = 0; attempt < 100; attempt += 1) {
      const id = 10 + attempt;
      wrapper.send(toolCall(id, 'semantic_search', { query: 'anything' }));
      answer = (await wrapper.waitFor(m => m.id === id, 10_000, 'the answer')).message;
      if (textOf(answer.result).startsWith('`kin init .` failed')) {
        break;
      }
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    assert.equal(answer.result.isError, true);
    assert.match(textOf(answer.result), /failed in .* \(exit 3\), so Kin cannot serve this repository yet/);
    assert.match(textOf(answer.result), /fatal: the fake init stopped here/);
    assert.match(textOf(answer.result), /Run `kin init \.` in that directory/);
    assert.match(wrapper.stderr, /kin init failed/);
    assert.equal(
      (await readServerLog(serverLog)).some(entry => entry.argv?.[0] === 'mcp'),
      false,
      'kin mcp start never runs after a failed init'
    );

    wrapper.child.stdin.end();
    assert.deepEqual(await wrapper.exited, { code: 1, signal: null });
  }
);

// Run in this process so the wait can be shortened: a server that never answers
// the replay must not leave the requests held for it waiting for good.
test(
  'a first launch gives up on a kin mcp start that never answers the replay',
  onlyWithTarballs,
  async t => {
    const asset = resolveReleaseAsset(process.platform, process.arch);
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'kin-mcp-first-launch-silent-'));
    t.after(() => fs.rm(tmpDir, { recursive: true, force: true }));
    const serverLog = path.join(tmpDir, 'server.log');
    const { archiveBytes, checksum } = await buildFakeKinArchive(tmpDir, asset);
    const baseUrl = mockReleaseFetch(t, PACKAGE_VERSION, asset.archiveName, archiveBytes, checksum);
    const repoDir = path.join(tmpDir, 'repo');
    await fs.mkdir(path.join(repoDir, '.kin'), { recursive: true });

    const stdin = new PassThrough();
    const stdout = new PassThrough();
    const received = [];
    const reader = createFrameReader(frame => received.push(JSON.parse(frame.text)));
    stdout.on('data', chunk => reader.push(chunk));
    const waitForId = async (id, label) => {
      for (let attempt = 0; attempt < 400; attempt += 1) {
        const found = received.find(message => message.id === id);
        if (found) return found;
        await new Promise(resolve => setTimeout(resolve, 25));
      }
      throw new Error(`timed out waiting for ${label}`);
    };

    const exitCode = runKinMcp([], {
      stdin,
      stdout,
      stderr: { write() {} },
      cwd: repoDir,
      startTimeoutMs: 500,
      env: firstLaunchEnv(tmpDir, {
        KIN_MCP_RELEASE_BASE_URL: baseUrl,
        KIN_MCP_FAKE_SERVER_LOG: serverLog,
        KIN_MCP_FAKE_SILENT: '1'
      })
    });

    stdin.write(encodeFrame(initializeRequest(1), false));
    await waitForId(1, 'initialize');
    const seen = await waitForServerLog(serverLog, entry => entry.method === 'initialize', 'the replay');
    stdin.write(encodeFrame(toolCall(2, 'semantic_search', { query: 'anything' }), false));
    const answer = await waitForId(2, 'the held call');
    assert.equal(answer.result.isError, true);
    assert.match(textOf(answer.result), /did not answer initialize within 500 ms/);
    for (let attempt = 0; attempt < 100 && processIsAlive(seen[0].pid); attempt += 1) {
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    assert.equal(processIsAlive(seen[0].pid), false, 'the silent server is stopped');

    stdin.end();
    assert.equal(await exitCode, 1);
  }
);
