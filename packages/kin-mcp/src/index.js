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

/**
 * The base URL the release archive and its checksum are both fetched from.
 *
 * They come from the same host by construction: `checksumUrl` is derived from
 * `archiveUrl`. Over plain http anyone on the path serves both, so the
 * integrity check compares their bytes against their digest, and what lands is
 * chmod 0755 and executed. https is required, with one exception: a loopback
 * address, where there is no network path to sit on and a local mirror is a
 * real thing people run.
 *
 * This closes the passive-network attacker only. An attacker who can set this
 * variable can still point it at an https host they control, because the
 * checksum travels beside the artifact; see docs/security/signing-and-update-trust.md.
 */
export function assertSecureReleaseBaseUrl(baseUrl) {
  let parsed;
  try {
    parsed = new URL(baseUrl);
  } catch {
    throw new Error(
      `KIN_MCP_RELEASE_BASE_URL is not a URL: ${baseUrl}`
    );
  }
  if (parsed.protocol === 'https:') {
    return baseUrl;
  }
  const host = parsed.hostname.replace(/^\[|\]$/g, '');
  const isLoopback =
    host === 'localhost' || host === '::1' || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host);
  if (parsed.protocol === 'http:' && isLoopback) {
    return baseUrl;
  }
  throw new Error(
    `refusing to download the Kin release over ${parsed.protocol}// from ${baseUrl}. ` +
      'The archive and its checksum come from this same base URL, so plain http lets anyone ' +
      'on the path serve both and the integrity check passes on their bytes. Use https, or a ' +
      'loopback address for a local mirror.'
  );
}

export function resolveReleaseTag(version = PACKAGE_VERSION) {
  return version.startsWith('v') ? version : `v${version}`;
}

export const PRIMARY_BINARY_NAME = 'kin';
export const DAEMON_BINARY_NAME = 'kin-daemon';

export function resolveReleaseAsset(platform = process.platform, arch = process.arch) {
  if (platform === 'darwin' && arch === 'arm64') {
    return {
      assetName: 'kin-macos-aarch64',
      archiveName: 'kin-macos-aarch64.tar.gz',
      binaryName: PRIMARY_BINARY_NAME,
      daemonBinaryName: DAEMON_BINARY_NAME
    };
  }
  if (platform === 'darwin' && arch === 'x64') {
    return {
      assetName: 'kin-macos-x86_64',
      archiveName: 'kin-macos-x86_64.tar.gz',
      binaryName: PRIMARY_BINARY_NAME,
      daemonBinaryName: DAEMON_BINARY_NAME
    };
  }
  if (platform === 'linux' && arch === 'x64') {
    return {
      assetName: 'kin-linux-x86_64',
      archiveName: 'kin-linux-x86_64.tar.gz',
      binaryName: PRIMARY_BINARY_NAME,
      daemonBinaryName: DAEMON_BINARY_NAME
    };
  }
  if (platform === 'linux' && arch === 'arm64') {
    return {
      assetName: 'kin-linux-aarch64',
      archiveName: 'kin-linux-aarch64.tar.gz',
      binaryName: PRIMARY_BINARY_NAME,
      daemonBinaryName: DAEMON_BINARY_NAME
    };
  }
  if (platform === 'win32' && arch === 'x64') {
    return {
      assetName: 'kin-windows-x86_64',
      archiveName: 'kin-windows-x86_64.zip',
      binaryName: `${PRIMARY_BINARY_NAME}.exe`,
      daemonBinaryName: `${DAEMON_BINARY_NAME}.exe`
    };
  }

  throw new Error(
    `kin-mcp does not have a published Kin binary for ${platform}/${arch} yet.`
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

  const daemonPath = resolveDaemonBinaryPath(binaryPath);
  if (
    (await isRunnable(binaryPath, platform)) &&
    (await isRunnable(daemonPath, platform))
  ) {
    return binaryPath;
  }

  await installKinBinary({ binaryPath, env, platform, arch, version });
  await assertDaemonProvisioned(binaryPath, platform);
  return binaryPath;
}

export async function runKinMcp(argv = [], options = {}) {
  const stdout = options.stdout || process.stdout;
  const stderr = options.stderr || process.stderr;
  const env = options.env || process.env;
  const platform = options.platform || process.platform;

  if (argv.includes('--help') || argv.includes('-h')) {
    stdout.write(renderHelp());
    return 0;
  }

  if (argv.includes('--version') || argv.includes('-v')) {
    stdout.write(`${PACKAGE_VERSION}\n`);
    return 0;
  }

  if (argv.includes('--print-bin') || argv.includes('--print-daemon-bin')) {
    let binaryPath;
    try {
      binaryPath = await ensureKinBinary(options);
    } catch (error) {
      stderr.write(`${guidedProvisioningFailure(error)}\n`);
      return 1;
    }
    const target = argv.includes('--print-daemon-bin')
      ? resolveDaemonBinaryPath(binaryPath)
      : binaryPath;
    stdout.write(`${target}\n`);
    return 0;
  }

  if (argv.length > 0) {
    stderr.write(
      'kin-mcp does not accept subcommands. It always runs `kin mcp start`.\n'
    );
    return 2;
  }

  let binaryPath;
  try {
    binaryPath = await ensureKinBinary(options);
  } catch (error) {
    stderr.write(`${guidedProvisioningFailure(error)}\n`);
    return 1;
  }

  const spawnOptions = {
    ...options,
    env: childEnv(env, binaryPath, platform)
  };

  const cwd = options.cwd || process.cwd();
  if (!await kinRepoExists(cwd)) {
    if (!isTruthyEnv(env.KIN_MCP_AUTO_INIT)) {
      // Start anyway. This wrapper used to exit 2 here, and the configuration
      // every client is handed points at this wrapper, so the advertised
      // agent-setup path produced a server that died on `initialize` before a
      // first-time user had any repository to bind. `kin mcp start` already
      // treats an unbound launch directory as the ordinary case: it serves
      // `initialize` and `tools/list`, re-resolves its repository on every
      // later tool call, and answers each tool with the instruction to run
      // `kin init`. Refusing here is the only thing that ever made this fatal.
      stderr.write(noRepositoryNotice(cwd));
    } else {
      stderr.write('No .kin/ found; KIN_MCP_AUTO_INIT=1, running kin init...\n');
      const initCode = await spawnKin(
        binaryPath,
        ['init', '.'],
        {
          ...spawnOptions,
          cwd,
          stdio: ['ignore', 'pipe', 'pipe']
        },
        { forwardOutputTo: stderr }
      );
      if (initCode !== 0) {
        stderr.write('kin init failed. Cannot start MCP server.\n');
        return initCode;
      }
    }
  }

  return spawnKin(binaryPath, ['mcp', 'start'], spawnOptions);
}

export function resolveDaemonBinaryPath(kinBinaryPath) {
  const suffix = path.extname(kinBinaryPath).toLowerCase() === '.exe' ? '.exe' : '';
  return path.join(path.dirname(kinBinaryPath), `${DAEMON_BINARY_NAME}${suffix}`);
}

export function childEnv(env, kinBinaryPath, platform = process.platform) {
  const next = { ...env };

  if (!next.KIN_MCP_TOOL_PROFILE) {
    next.KIN_MCP_TOOL_PROFILE = 'agent-default';
  }

  const usesManagedBinary = !(env.KIN_MCP_KIN_BINARY || env.KIN_BINARY_PATH);
  if (usesManagedBinary && !next.KIN_DAEMON_BIN) {
    next.KIN_DAEMON_BIN = resolveDaemonBinaryPath(kinBinaryPath);
  }

  return next;
}

function guidedProvisioningFailure(error) {
  const detail = error && error.message ? error.message : String(error);
  return [
    `kin-mcp could not provision a runnable Kin: ${detail}`,
    'Fixes:',
    '  - Install Kin directly and run `kin setup` to configure your agent, then point',
    '    this wrapper at it with KIN_MCP_KIN_BINARY=/path/to/kin.',
    '  - Or retry on a supported target (macOS, Linux, or Windows x64).',
    '    Native Windows carries semantic vector search but no filesystem projection;',
    '    use WSL2 when you need projection.',
    '  - Or override the release source with KIN_MCP_RELEASE_BASE_URL if you mirror releases.'
  ].join('\n');
}

export function isTruthyEnv(value) {
  return ['1', 'true', 'yes', 'on'].includes(String(value || '').trim().toLowerCase());
}

function renderHelp() {
  return `kin-mcp ${PACKAGE_VERSION}

Usage:
  kin-mcp
  kin-mcp --print-bin
  kin-mcp --print-daemon-bin
  kin-mcp --version

This wrapper downloads a matching Kin release archive on demand, extracts both
the kin CLI and the kin-daemon it depends on into a local cache, and then runs:

  kin mcp start

It defaults KIN_MCP_TOOL_PROFILE=agent-default so first-run agents see the small
curated tool surface, and points the kin CLI at the cached kin-daemon via
KIN_DAEMON_BIN so it never depends on a stale daemon on PATH.

Environment:
  KIN_MCP_KIN_BINARY   Use a specific kin binary (you manage its kin-daemon)
  KIN_BINARY_PATH      Alias for KIN_MCP_KIN_BINARY
  KIN_MCP_CACHE_DIR    Override the cache directory
  KIN_MCP_AUTO_INIT    Set to 1 to allow wrapper-initiated kin init
  KIN_MCP_TOOL_PROFILE Override the default agent-default tool profile
  KIN_MCP_RELEASE_BASE_URL
                       Override the release download base URL
`;
}

async function installKinBinary({ binaryPath, env, platform, arch, version }) {
  const { assetName, archiveName, binaryName, daemonBinaryName } = resolveReleaseAsset(
    platform,
    arch
  );
  const tag = resolveReleaseTag(version);
  const baseUrl = assertSecureReleaseBaseUrl(
    (env.KIN_MCP_RELEASE_BASE_URL || DEFAULT_RELEASE_BASE_URL).replace(/\/$/, '')
  );
  const archiveUrl = `${baseUrl}/${tag}/${archiveName}`;
  const checksumUrl = `${archiveUrl}.sha256`;

  await fsp.mkdir(path.dirname(binaryPath), { recursive: true });

  const checksumText = await fetchText(checksumUrl);
  const expectedSha = parseChecksum(checksumText);
  const archiveBytes = await fetchBytes(archiveUrl);
  const actualSha = sha256(archiveBytes);

  if (actualSha !== expectedSha) {
    throw new Error(
      `checksum mismatch for ${archiveName}: expected ${expectedSha}, got ${actualSha}`
    );
  }

  await installFromArchive({
    archiveBytes,
    archiveName,
    assetName,
    binaryName,
    daemonBinaryName,
    binaryPath,
    platform,
    env
  });
}

function mergeEnvironment(base, overrides) {
  const merged = { ...base };
  for (const [name, value] of Object.entries(overrides || {})) {
    for (const inherited of Object.keys(merged)) {
      if (inherited.toLowerCase() === name.toLowerCase()) {
        delete merged[inherited];
      }
    }
    merged[name] = value;
  }
  return merged;
}

function environmentValue(env, name) {
  const key = Object.keys(env).find(candidate => candidate.toLowerCase() === name.toLowerCase());
  return key === undefined ? undefined : env[key];
}

function windowsSystemTarPath(env) {
  const systemRoot = environmentValue(env, 'SystemRoot');
  if (!systemRoot) {
    throw new Error('native Windows ZIP extraction requires SystemRoot');
  }
  return path.win32.join(systemRoot, 'System32', 'tar.exe');
}

// Where a Unix system tool is allowed to come from.
//
// `execFile('tar', ...)` resolves through PATH, and PATH belongs to whoever
// started this process. A `tar` planted earlier in it unpacks the archive
// whose SHA-256 was just verified, so the integrity check ends up protecting
// bytes that somebody else's program reads. These directories are root-owned
// on macOS and Linux and SIP-protected on macOS. The Windows arm has named its
// extractor absolutely since it was written; this is the same rule on Unix.
const UNIX_TOOL_DIRECTORIES = ['/usr/bin', '/bin'];

// The absolute path of a Unix system tool, refused when it is in none of the
// trusted directories.
//
// Refusing rather than falling back to PATH: a fallback makes the guard
// advisory, and installFromArchive already reports an extractor that will not
// run.
function unixSystemToolPath(name) {
  for (const directory of UNIX_TOOL_DIRECTORIES) {
    const candidate = path.posix.join(directory, name);
    if (fs.existsSync(candidate)) return candidate;
  }
  throw new Error(
    `${name} was not found in ${UNIX_TOOL_DIRECTORIES.join(' or ')}; refusing to resolve it ` +
      'through PATH, where a planted binary would run in its place'
  );
}

function archiveExtraction(platform, env, archiveName) {
  if (platform === 'win32') {
    if (process.platform === 'win32') {
      return {
        executable: windowsSystemTarPath(env),
        args: ['-xf', archiveName, '-C', '.']
      };
    }
    // Cross-target tests on Unix exercise genuine ZIP bytes with the host's
    // deterministic system unzip. Production never installs Windows assets
    // on a Unix host.
    return {
      executable: '/usr/bin/unzip',
      args: ['-q', archiveName, '-d', '.']
    };
  }
  return {
    executable: unixSystemToolPath('tar'),
    args: ['-xf', archiveName, '-C', '.']
  };
}

async function installFromArchive({
  archiveBytes,
  archiveName,
  assetName,
  binaryName,
  daemonBinaryName,
  binaryPath,
  platform,
  env
}) {
  const tmpRoot = await fsp.mkdtemp(path.join(os.tmpdir(), 'kin-mcp-install-'));
  const archivePath = path.join(tmpRoot, archiveName);
  const installDir = path.dirname(binaryPath);
  const daemonPath = path.join(installDir, daemonBinaryName);
  const staged = [];

  try {
    await fsp.writeFile(archivePath, archiveBytes);
    const toolEnv = mergeEnvironment(process.env, env);
    const extraction = archiveExtraction(platform, toolEnv, archiveName);
    // The extractor is named absolutely on both platforms: System32 bsdtar on
    // Windows, never a Git/MSYS `tar` earlier in PATH, and /usr/bin/tar or
    // /bin/tar on Unix. Relative operands also avoid the GNU remote-host
    // interpretation of `C:\\...` paths.
    await execFile(extraction.executable, extraction.args, {
      cwd: tmpRoot,
      env: toolEnv
    });

    const kinStaged = await stageBinary({
      tmpRoot,
      assetName,
      sourceName: binaryName,
      destination: binaryPath,
      platform,
      required: true
    });
    staged.push(kinStaged);

    const daemonStaged = await stageBinary({
      tmpRoot,
      assetName,
      sourceName: daemonBinaryName,
      destination: daemonPath,
      platform,
      required: true,
      missingHint:
        'the published release archive is missing kin-daemon; the daemon is required for MCP'
    });
    staged.push(daemonStaged);

    for (const item of staged) {
      await fsp.rename(item.tmpPath, item.destination);
    }
  } catch (error) {
    await Promise.all(staged.map(item => fsp.unlink(item.tmpPath).catch(() => {})));
    throw new Error(
      `failed to install ${binaryName} from ${archiveName}: ${error.message}`
    );
  } finally {
    await fsp.rm(tmpRoot, { recursive: true, force: true });
  }
}

async function stageBinary({
  tmpRoot,
  assetName,
  sourceName,
  destination,
  platform,
  required,
  missingHint
}) {
  const extracted = platform === 'win32'
    ? path.join(tmpRoot, sourceName)
    : path.join(tmpRoot, assetName, sourceName);
  try {
    await fsp.access(extracted, fs.constants.R_OK);
  } catch {
    if (required) {
      throw new Error(missingHint || `archive is missing ${sourceName}`);
    }
    return null;
  }

  const tmpPath = `${destination}.download`;
  await fsp.copyFile(extracted, tmpPath);
  if (platform !== 'win32') {
    await fsp.chmod(tmpPath, 0o755);
  }
  return { destination, tmpPath };
}

function execFile(file, args, options = {}) {
  return new Promise((resolve, reject) => {
    cp.execFile(file, args, options, (error, stdout, stderr) => {
      if (error) {
        if (stderr) {
          error.message = `${error.message}: ${stderr.trim()}`;
        }
        reject(error);
        return;
      }
      resolve({ stdout, stderr });
    });
  });
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

/**
 * What a launch directory that is no Kin repository is told, on stderr.
 *
 * Exported so the wording is assertable without spawning a server, and stderr
 * rather than stdout because stdout is the protocol channel and a byte of prose
 * on it corrupts the first frame.
 */
export function noRepositoryNotice(cwd) {
  return [
    `kin-mcp: no .kin/ found in ${cwd}, so no repository is bound yet.`,
    'Starting anyway. The MCP transport comes up, `initialize` and `tools/list` are served,',
    'and a graph tool called before a repository exists answers by naming the gap and telling',
    'the caller to run `kin init .` rather than failing silently.',
    'Run `kin init .` in the repository you want served, or point this client\'s workspace',
    'roots at one. This server re-resolves its repository on later tool calls, so nothing here',
    'needs a restart. Set KIN_MCP_AUTO_INIT=1 to let this wrapper run `kin init .` for you.',
    ''
  ].join('\n');
}

async function kinRepoExists(cwd) {
  try {
    const stat = await fsp.stat(path.join(cwd, '.kin'));
    return stat.isDirectory();
  } catch {
    return false;
  }
}

async function assertRunnable(filePath, platform) {
  if (!(await isRunnable(filePath, platform))) {
    throw new Error(`kin binary not found or not executable: ${filePath}`);
  }
}

async function assertDaemonProvisioned(kinBinaryPath, platform) {
  const daemonPath = resolveDaemonBinaryPath(kinBinaryPath);
  if (!(await isRunnable(daemonPath, platform))) {
    throw new Error(
      `kin-daemon was not provisioned next to ${kinBinaryPath}; the MCP server cannot start without it`
    );
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

function spawnKin(binaryPath, args, options, { forwardOutputTo } = {}) {
  const env = options.env || process.env;

  return new Promise((resolve, reject) => {
    const child = cp.spawn(binaryPath, args, {
      cwd: options.cwd || process.cwd(),
      env,
      stdio: options.stdio || 'inherit'
    });

    if (forwardOutputTo) {
      forwardStream(child.stdout, forwardOutputTo);
      forwardStream(child.stderr, forwardOutputTo);
    }

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

function forwardStream(source, destination) {
  if (!source) {
    return;
  }

  source.on('data', chunk => {
    const ready = destination.write(chunk);
    if (ready === false && typeof destination.once === 'function') {
      source.pause();
      destination.once('drain', () => source.resume());
    }
  });
}
