// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

import cp from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';

import { instructionsForProfile, startFirstLaunchSession } from './first-launch.js';

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

/**
 * The Kin this wrapper can run without downloading one: an explicit binary, or
 * this version's cached `kin` with its `kin-daemon`. `null` when a download is
 * needed. Throws for an explicit binary that will not run and for a target no
 * release is published for, since no download can fix either.
 */
export async function cachedKinBinary({
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
  return null;
}

export async function ensureKinBinary({
  env = process.env,
  platform = process.platform,
  arch = process.arch,
  version = PACKAGE_VERSION,
  homeDir = os.homedir(),
  cacheRoot,
  onProgress
} = {}) {
  const cached = await cachedKinBinary({ env, platform, arch, version, homeDir, cacheRoot });
  if (cached) {
    return cached;
  }

  const binaryPath = resolveCachedBinaryPath({
    env,
    platform,
    arch,
    version,
    homeDir,
    cacheRoot
  });
  await installKinBinary({ binaryPath, env, platform, arch, version, onProgress });
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

  if (argv.includes('--stop')) {
    return stopKinDaemons(options, { stdout, stderr, env, platform });
  }

  if (argv.length > 0) {
    stderr.write(
      'kin-mcp does not accept subcommands. It always runs `kin mcp start`, ' +
        'or `kin-mcp --stop` to stop what it started.\n'
    );
    return 2;
  }

  let binaryPath;
  try {
    binaryPath = await cachedKinBinary(options);
  } catch (error) {
    stderr.write(`${guidedProvisioningFailure(error)}\n`);
    return 1;
  }

  // Nothing cached, so this launch downloads the release first. The client's
  // `initialize` is answered while that runs rather than after it: a client
  // with a short startup timeout otherwise gives up on the server before the
  // download ends. See first-launch.js.
  let firstLaunch = null;
  if (!binaryPath) {
    firstLaunch = startFirstLaunchSession({
      stdin: options.stdin || process.stdin,
      stdout,
      version: PACKAGE_VERSION,
      releaseName: resolveReleaseAsset(platform, options.arch || process.arch).archiveName,
      // The ones `kin mcp start` will give for the profile it serves: a client
      // keeps the instructions of this answer for the whole session.
      instructions: instructionsForProfile(servedToolProfile(env.KIN_MCP_TOOL_PROFILE)),
      startTimeoutMs: options.startTimeoutMs
    });
    try {
      binaryPath = await ensureKinBinary({ ...options, onProgress: firstLaunch.progress });
    } catch (error) {
      const guided = guidedProvisioningFailure(error);
      stderr.write(`${guided}\n`);
      return firstLaunch.fail(guided);
    }
    if (firstLaunch.closed) {
      // The client left during the download. The release stays cached, so
      // its next launch starts at once.
      return 0;
    }
    firstLaunch.downloaded();
  }

  const spawnOptions = {
    ...options,
    env: childEnv(env, binaryPath, platform)
  };

  const cwd = options.cwd || process.cwd();
  const repository = await findKinRepository(cwd, { env });
  if (repository && !samePath(repository, cwd)) {
    // A folder inside another Kin repository, with no repository of its own,
    // is served by that one. Say so before anything is answered from it.
    stderr.write(
      enclosingRepositoryNotice(cwd, repository, {
        profile: spawnOptions.env.KIN_MCP_TOOL_PROFILE
      })
    );
  } else if (!repository) {
    if (!isTruthyEnv(env.KIN_MCP_AUTO_INIT)) {
      // Start anyway. This wrapper used to exit 2 here, and the configuration
      // every client is handed points at this wrapper, so the advertised
      // agent-setup path produced a server that died on `initialize` before a
      // first-time user had any repository to bind. `kin mcp start` already
      // treats an unbound launch directory as the ordinary case: it serves
      // `initialize` and `tools/list`, re-resolves its repository on every
      // later tool call, and answers each tool with the instruction to run
      // `kin init`. Refusing here is the only thing that ever made this fatal.
      stderr.write(
        noRepositoryNotice(cwd, PACKAGE_VERSION, {
          profile: spawnOptions.env.KIN_MCP_TOOL_PROFILE
        })
      );
    } else {
      stderr.write('No .kin/ found; KIN_MCP_AUTO_INIT=1, running kin init...\n');
      firstLaunch?.initializing(cwd);
      const initOutput = outputTail(INIT_OUTPUT_TAIL_BYTES);
      const initCode = await spawnKin(
        binaryPath,
        ['init', '.'],
        {
          ...spawnOptions,
          cwd,
          stdio: ['ignore', 'pipe', 'pipe']
        },
        { forwardOutputTo: stderr, onOutput: initOutput.push }
      );
      if (initCode !== 0) {
        stderr.write('kin init failed. Cannot start MCP server.\n');
        if (firstLaunch) {
          // The client already has a session, so the failure is said there,
          // where the agent reads it, and not only on stderr.
          return firstLaunch.fail(autoInitFailure(cwd, initCode, initOutput.text()));
        }
        return initCode;
      }
    }
  }

  if (firstLaunch) {
    return firstLaunch.handOff(binaryPath, ['mcp', 'start'], { cwd, env: spawnOptions.env });
  }
  return spawnKin(binaryPath, ['mcp', 'start'], spawnOptions);
}

/**
 * `kin-mcp --stop`: stop the Kin daemons nothing is using, then say what stays
 * on disk and how to remove it.
 *
 * Removing `kin` from an editor's MCP config is the only uninstall step a
 * registry user knows about, and it stops nothing: the supervisor and each
 * repository's daemon keep running, and the binaries, Kin's home and the
 * embedding model stay in HOME with nothing naming them. This runs
 * `kin daemon stop --all --when-unused` under the environment the server runs
 * under, so it reaches the same daemons. It never takes one out from under a
 * client still using it: those are named, left running, and exit on their own
 * once they are free.
 *
 * It never downloads a Kin to do this. Fetching the release archive in order
 * to stop daemons would be the opposite of what was asked.
 */
async function stopKinDaemons(options, { stdout, env, platform }) {
  const binaryPath = await existingKinBinary({ ...options, env, platform });
  let code = 0;
  if (binaryPath) {
    code = await spawnKin(binaryPath, ['daemon', 'stop', '--all', '--when-unused'], {
      ...options,
      env: childEnv(env, binaryPath, platform),
      cwd: options.cwd || process.cwd(),
      stdio: options.stdio || 'inherit'
    });
  } else {
    stdout.write(
      'kin-mcp: no Kin binary is cached here, so there is nothing to stop daemons with. ' +
        'If a Kin you installed another way started them, run `kin daemon stop --all` with it.\n'
    );
  }
  stdout.write(
    renderFootprint(
      await resolveFootprint({ env, platform, homeDir: options.homeDir || os.homedir() }),
      platform
    )
  );
  return code;
}

/**
 * The Kin this wrapper can already run, without downloading one: an explicit
 * binary, this version's cached one, or the newest other cached version.
 */
async function existingKinBinary({
  env = process.env,
  platform = process.platform,
  arch = process.arch,
  version = PACKAGE_VERSION,
  homeDir = os.homedir(),
  cacheRoot
} = {}) {
  const configured = env.KIN_MCP_KIN_BINARY || env.KIN_BINARY_PATH;
  if (configured) {
    const resolved = path.resolve(configured);
    return (await isRunnable(resolved, platform)) ? resolved : null;
  }
  let asset;
  try {
    asset = resolveReleaseAsset(platform, arch);
  } catch {
    return null;
  }
  const root = cacheRoot || resolveCacheRoot(env, platform, homeDir);
  const own = path.join(root, resolveReleaseTag(version), asset.assetName, asset.binaryName);
  if (await isRunnable(own, platform)) {
    return own;
  }
  let tags = [];
  try {
    tags = await fsp.readdir(root);
  } catch {
    return null;
  }
  for (const tag of tags.sort().reverse()) {
    const candidate = path.join(root, tag, asset.assetName, asset.binaryName);
    if (await isRunnable(candidate, platform)) {
      return candidate;
    }
  }
  return null;
}

/** The directory the embedding model is cached in, mirroring the loader. */
export function embeddingModelCachePath(homeDir = os.homedir()) {
  return path.join(
    homeDir,
    '.cache',
    'huggingface',
    'hub',
    'models--nomic-ai--nomic-embed-text-v1.5'
  );
}

/**
 * What Kin leaves in HOME once its daemons have stopped, with each entry's
 * size on disk. Only entries that exist are returned.
 */
export async function resolveFootprint({
  env = process.env,
  platform = process.platform,
  homeDir = os.homedir()
} = {}) {
  const kinHome = path.resolve(env.KIN_HOME || env.KIN_DIR || path.join(homeDir, '.kin'));
  const candidates = [
    {
      path: resolveCacheRoot(env, platform, homeDir),
      what: 'the Kin binaries this wrapper downloaded'
    },
    {
      path: kinHome,
      what: "Kin's home: daemon records, logs and the embedding cache",
      // A Kin installed with the installer or npm lives here too, and deleting
      // the directory would pull it out from under that install.
      managedInstall: await isRunnable(
        path.join(kinHome, 'bin', platform === 'win32' ? 'kin.exe' : 'kin'),
        platform
      )
    },
    {
      path: embeddingModelCachePath(homeDir),
      what: 'the embedding model, fetched the first time Kin embeds a repository'
    }
  ];
  const present = [];
  for (const candidate of candidates) {
    const bytes = await directorySize(candidate.path);
    if (bytes !== null) {
      present.push({ ...candidate, bytes });
    }
  }
  return present;
}

/**
 * Bytes a directory holds, or `null` when it does not exist. Symlinks are not
 * followed, so the Hugging Face cache's snapshot links do not count its blobs
 * twice.
 */
async function directorySize(root) {
  let stat;
  try {
    stat = await fsp.lstat(root);
  } catch {
    return null;
  }
  if (!stat.isDirectory()) {
    return stat.isFile() ? stat.size : 0;
  }
  let total = 0;
  const pending = [root];
  while (pending.length > 0) {
    const dir = pending.pop();
    let entries;
    try {
      entries = await fsp.readdir(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        pending.push(full);
      } else if (entry.isFile()) {
        try {
          total += (await fsp.lstat(full)).size;
        } catch {
          // Gone between the listing and the stat; it no longer takes space.
        }
      }
    }
  }
  return total;
}

function formatSize(bytes) {
  const mb = bytes / (1024 * 1024);
  return mb < 1 ? 'under 1 MB' : `${Math.round(mb)} MB`;
}

/** The footprint as plain text: what stays, and the commands that remove it. */
export function renderFootprint(entries, platform = process.platform) {
  const remove = target =>
    platform === 'win32'
      ? `Remove-Item -Recurse -Force -LiteralPath '${target.replaceAll("'", "''")}'`
      : `rm -rf -- '${target.replaceAll("'", "'\\''")}'`;
  const lines = ['', 'What stays on this machine:'];
  for (const entry of entries) {
    lines.push(`  ${formatSize(entry.bytes).padStart(10)}  ${entry.path}`);
    lines.push(`              ${entry.what}`);
  }
  lines.push(
    '  Each repository you ran `kin init` in also keeps its graph in a .kin directory beside its code.'
  );
  lines.push('To remove them once the daemons have stopped:');
  for (const entry of entries) {
    if (entry.managedInstall) {
      lines.push(
        `  a Kin install also lives in ${entry.path}; remove it with \`kin setup uninstall --all\``
      );
    } else {
      lines.push(`  ${remove(entry.path)}`);
    }
  }
  lines.push(`  and ${remove('.kin')} in each repository you initialized.`);
  lines.push('');
  return lines.join('\n');
}

export function resolveDaemonBinaryPath(kinBinaryPath) {
  const suffix = path.extname(kinBinaryPath).toLowerCase() === '.exe' ? '.exe' : '';
  return path.join(path.dirname(kinBinaryPath), `${DAEMON_BINARY_NAME}${suffix}`);
}

export function childEnv(env, kinBinaryPath, platform = process.platform) {
  const next = { ...env };

  if (!next.KIN_MCP_TOOL_PROFILE) {
    next.KIN_MCP_TOOL_PROFILE = DEFAULT_TOOL_PROFILE;
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
  kin-mcp --stop
  kin-mcp --print-bin
  kin-mcp --print-daemon-bin
  kin-mcp --version

This wrapper downloads a matching Kin release archive on demand, extracts both
the kin CLI and the kin-daemon it depends on into a local cache, and then runs:

  kin mcp start

On the first launch, while that download runs, it answers the client's
initialize itself, with Kin's own instructions, and answers tools/list with one
tool, kin_startup_status, that reports the download's progress. When the
download finishes it hands the session to kin mcp start and sends
notifications/tools/list_changed so the client lists Kin's tools.

It defaults KIN_MCP_TOOL_PROFILE=agent-default so first-run agents see the small
curated tool surface, and points the kin CLI at the cached kin-daemon via
KIN_DAEMON_BIN so it never depends on a stale daemon on PATH.

The first tool call starts a background daemon for the repository, plus one
supervisor. The daemon exits on its own once nothing has used it for 30
minutes, and the supervisor a minute after its last daemon. kin-mcp --stop
stops the daemons nothing is using now, leaves any that are still in use
running and names them, and prints what Kin keeps on disk and the commands
that remove it.

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

async function installKinBinary({ binaryPath, env, platform, arch, version, onProgress }) {
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
  const archiveBytes = await fetchBytes(archiveUrl, { onProgress });
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

// The archive layout comes from the TARGET, the extractor from the HOST, and
// conflating the two is what broke the native Windows leg once already: a
// Windows host has no /usr/bin, and the cross-target tests unpack a linux
// archive on it. `host` is a parameter rather than a read of `process.platform`
// so every combination is testable from one machine.
export function archiveExtraction(platform, env, archiveName, host = process.platform) {
  if (platform === 'win32') {
    if (host === 'win32') {
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
  // A Unix archive. On a Unix host that is the absolute system tar; on a
  // Windows host, which only ever happens under a cross-target test, it is the
  // same System32 bsdtar the Windows arm above uses, and bsdtar reads .tar.gz.
  // Either way the extractor is named absolutely rather than found on PATH.
  return {
    executable: host === 'win32' ? windowsSystemTarPath(env) : unixSystemToolPath('tar'),
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

async function fetchBytes(url, { onProgress } = {}) {
  const response = await fetch(url, {
    headers: { 'user-agent': `kin-mcp/${PACKAGE_VERSION}` },
    signal: AbortSignal.timeout(120_000)
  });

  if (!response.ok) {
    throw new Error(`failed to download ${url}: ${response.status} ${response.statusText}`);
  }

  if (!onProgress || !response.body) {
    return Buffer.from(await response.arrayBuffer());
  }
  // Read in chunks so a first launch can say how far the download has come.
  const total = Number(response.headers.get('content-length')) || null;
  const chunks = [];
  let received = 0;
  onProgress({ received, total });
  for await (const chunk of response.body) {
    chunks.push(chunk);
    received += chunk.byteLength;
    onProgress({ received, total });
  }
  return Buffer.concat(chunks, received);
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

// Every tool profile `kin mcp start` accepts, the one it serves when none is
// named or the name is not a profile, and the ones that serve `kin_init`, by
// name or as the routed `init` command. Setting a folder up is a write, so only
// the profiles that write carry it, and a notice offers it only there. A test
// in kin-cli's `commands/mcp.rs` holds all three to the Rust registry.
const TOOL_PROFILES = new Set([
  'agent-default',
  'agent-query',
  'agent-search',
  'agent-routed',
  'agent-routed-query',
  'full',
  'benchmark',
  'context-bench'
]);
const DEFAULT_TOOL_PROFILE = 'agent-default';
const PROFILES_SERVING_INIT = new Set(['agent-default', 'agent-routed', 'full']);

/**
 * The profile `kin mcp start` serves for a KIN_MCP_TOOL_PROFILE value, resolved
 * the way it resolves one: trimmed and in any case, and the default profile when
 * the value is missing, empty or not a profile.
 */
export function servedToolProfile(profile) {
  const requested = typeof profile === 'string' ? profile.trim().toLowerCase() : '';
  return TOOL_PROFILES.has(requested) ? requested : DEFAULT_TOOL_PROFILE;
}

/**
 * Whether `profile` serves `kin_init`, once resolved as `kin mcp start`
 * resolves it (`servedToolProfile`). The default serves it.
 */
export function profileServesInit(profile) {
  return PROFILES_SERVING_INIT.has(servedToolProfile(profile));
}

/**
 * What a launch directory that is no Kin repository is told, on stderr.
 *
 * Exported so the wording is assertable without spawning a server, and stderr
 * rather than stdout because stdout is the protocol channel and a byte of prose
 * on it corrupts the first frame.
 */
export function noRepositoryNotice(cwd, version = PACKAGE_VERSION, { profile } = {}) {
  const setUp = profileServesInit(profile)
    ? 'To set this folder up, ask your agent to call kin_init, or run'
    : 'To set this folder up, run';
  return [
    `kin-mcp: ${cwd} is not a Kin repository, and neither is any folder above it, so no`,
    'repository is bound yet. Starting anyway: `initialize` and `tools/list` are served, and a',
    'graph tool called before a repository exists answers by naming the gap.',
    setUp,
    `\`npx -y @kinlab/kin@${version} init .\` in it; the folder must be a Git repository or empty.`,
    'This server re-resolves its repository on later tool calls, so nothing here needs a restart.',
    'Set KIN_MCP_AUTO_INIT=1 to let this wrapper run `kin init .` for you at launch.',
    ''
  ].join('\n');
}

/** How much of a failed `kin init`'s output the agent is shown. */
const INIT_OUTPUT_TAIL_BYTES = 2048;

/** Keep the last `limit` bytes written to it. */
function outputTail(limit) {
  let tail = Buffer.alloc(0);
  return {
    push(chunk) {
      const bytes = typeof chunk === 'string' ? Buffer.from(chunk) : chunk;
      tail = Buffer.concat([tail, bytes]);
      if (tail.length > limit) {
        tail = tail.subarray(tail.length - limit);
      }
    },
    text() {
      return tail.toString('utf8').trim();
    }
  };
}

/**
 * What an agent is told when `kin init` fails under KIN_MCP_AUTO_INIT.
 *
 * Exported so the wording is assertable without spawning a server.
 */
export function autoInitFailure(cwd, exitCode, output) {
  const lines = [
    `\`kin init .\` failed in ${cwd} (exit ${exitCode}), so Kin cannot serve this repository ` +
      'yet. This server ran it because KIN_MCP_AUTO_INIT is set.'
  ];
  if (output) {
    lines.push('The end of its output:', output);
  }
  lines.push(
    'Run `kin init .` in that directory to see the whole error, fix what it names, then ' +
      'reconnect the Kin server.'
  );
  return lines.join('\n');
}

/**
 * What a launch directory inside another Kin repository is told, on stderr.
 *
 * That repository serves it, which is right, and was silent, which was not: a
 * stranger's first answers came from a repository two levels up while this
 * notice said no repository was bound at all.
 */
export function enclosingRepositoryNotice(
  cwd,
  root,
  { profile, version = PACKAGE_VERSION } = {}
) {
  const setUp = profileServesInit(profile)
    ? 'repository and ask your agent to call kin_init, or run'
    : 'repository and run';
  return [
    `kin-mcp: ${cwd} is not a Kin repository of its own, so Kin serves the Kin repository at`,
    `${root}, which contains it. Answers can come from anywhere in that repository, and each`,
    'opens by saying which repository it came from. To have Kin serve this folder alone, make it a Git',
    `${setUp} \`npx -y @kinlab/kin@${version} init .\` in it.`,
    ''
  ].join('\n');
}

// The entries Kin's own install root carries, two of which settle that a
// `.kin` is the toolchain rather than a repository store. The same list and
// quorum as `kin_core::layout::is_managed_kin_home`.
const MANAGED_HOME_MARKERS = ['registry.toml', 'bin', 'lib', 'shell'];
const MANAGED_HOME_MARKER_QUORUM = 2;

async function pathExists(target) {
  try {
    await fsp.stat(target);
    return true;
  } catch {
    return false;
  }
}

async function isDirectory(target) {
  try {
    return (await fsp.stat(target)).isDirectory();
  } catch {
    return false;
  }
}

async function isManagedKinHome(candidate, { env = process.env, homeDir = os.homedir() } = {}) {
  let markers = 0;
  for (const name of MANAGED_HOME_MARKERS) {
    if (await pathExists(path.join(candidate, name))) markers += 1;
  }
  if (markers >= MANAGED_HOME_MARKER_QUORUM) return true;
  const homes = [path.join(homeDir, '.kin')];
  if (env.KIN_HOME) homes.push(path.resolve(env.KIN_HOME));
  for (const home of homes) {
    if (samePath(candidate, home)) {
      return !(await pathExists(path.join(candidate, 'manifest.json')));
    }
  }
  return false;
}

function realPath(target) {
  try {
    return fs.realpathSync(target);
  } catch {
    return path.resolve(target);
  }
}

function samePath(left, right) {
  return realPath(left) === realPath(right);
}

/**
 * The Kin repository `kin mcp start` would serve from `start`, or null.
 *
 * The walk `kin_core::KinLayout::discover` makes: up from `start` to the first
 * `.kin` that is not Kin's own install root, and never across a folder that is
 * a Git repository with no `.kin` of its own, unless KIN_ALLOW_PARENT_STORE is
 * set. Kept in step with it so this notice names the repository the server
 * will actually answer from.
 */
export async function findKinRepository(start, { env = process.env, homeDir = os.homedir() } = {}) {
  let current = realPath(start);
  let crossedBoundary = false;
  for (;;) {
    const candidate = path.join(current, '.kin');
    if ((await isDirectory(candidate)) && !(await isManagedKinHome(candidate, { env, homeDir }))) {
      if (crossedBoundary && !env.KIN_ALLOW_PARENT_STORE) return null;
      return current;
    }
    if (!crossedBoundary && (await pathExists(path.join(current, '.git')))) {
      crossedBoundary = true;
    }
    const parent = path.dirname(current);
    if (parent === current) return null;
    current = parent;
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

function spawnKin(binaryPath, args, options, { forwardOutputTo, onOutput } = {}) {
  const env = options.env || process.env;

  return new Promise((resolve, reject) => {
    const child = cp.spawn(binaryPath, args, {
      cwd: options.cwd || process.cwd(),
      env,
      stdio: options.stdio || 'inherit'
    });

    if (forwardOutputTo) {
      forwardStream(child.stdout, forwardOutputTo, onOutput);
      forwardStream(child.stderr, forwardOutputTo, onOutput);
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

function forwardStream(source, destination, onOutput) {
  if (!source) {
    return;
  }

  source.on('data', chunk => {
    onOutput?.(chunk);
    const ready = destination.write(chunk);
    if (ready === false && typeof destination.once === 'function') {
      source.pause();
      destination.once('drain', () => source.resume());
    }
  });
}
