// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

import cp from 'node:child_process';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { assertKinContract } from './contracts.js';

const HIDDEN_ROOT_ENTRIES = new Set(['.git', '.kin']);
const IMPLEMENTED_BACKEND_MODE = 'sourceRootBridge';
const GRAPH_BACKEND_MODE = 'graphNative';

export async function resolveContext(options = {}) {
  const { repoPath, backendMode = IMPLEMENTED_BACKEND_MODE } = options;
  if (!repoPath) {
    throw new Error('repoPath is required');
  }

  const repoRoot = await findKinRoot(repoPath);
  if (!repoRoot) {
    throw new Error(`Kin repository not found for ${repoPath}`);
  }

  const graphContext = await tryGraphServiceCommand(
    { ...options, repoPath: repoRoot, backendMode },
    'context',
    []
  );
  if (graphContext) {
    return assertKinContract('workspaceContext', graphContext);
  }

  const mode = await readRepoMode(repoRoot);
  const physicalRoot = await resolvePhysicalRoot(repoRoot, mode, backendMode);

  return assertKinContract('workspaceContext', {
    repoRoot,
    repoName: path.basename(repoRoot),
    mode,
    requestedBackendMode: backendMode,
    backendMode: IMPLEMENTED_BACKEND_MODE,
    physicalRoot
  });
}

export async function findKinRoot(startPath) {
  let current = path.resolve(startPath);

  try {
    const stat = await fsp.stat(current);
    if (stat.isFile()) {
      current = path.dirname(current);
    }
  } catch {
    current = path.dirname(current);
  }

  while (true) {
    if (await pathExists(path.join(current, '.kin'))) {
      return current;
    }

    const parent = path.dirname(current);
    if (parent === current) {
      return undefined;
    }
    current = parent;
  }
}

export async function readRepoMode(repoRoot) {
  const modePath = path.join(repoRoot, '.kin', 'mode');
  try {
    const mode = (await fsp.readFile(modePath, 'utf8')).trim();
    return mode === 'native' ? 'native' : 'compat';
  } catch {
    return 'compat';
  }
}

export async function statPath(options, virtualPath) {
  const graphResult = await tryGraphServiceCommand(options, 'stat', [
    '--path',
    displayVirtualPath(virtualPath)
  ]);
  if (graphResult) {
    return assertKinContract('fileStat', graphResult);
  }

  const { target } = await resolveVirtualPath(options, virtualPath);
  const stat = await fsp.stat(target);

  return assertKinContract('fileStat', {
    type: stat.isDirectory() ? 'directory' : 'file',
    ctimeMs: stat.ctimeMs,
    mtimeMs: stat.mtimeMs,
    size: stat.size
  });
}

export async function readDirectory(options, virtualPath) {
  const graphResult = await tryGraphServiceCommand(options, 'read-dir', [
    '--path',
    displayVirtualPath(virtualPath)
  ]);
  if (graphResult) {
    return assertKinContract('directoryList', graphResult);
  }

  const { context, target, normalizedVirtualPath } = await resolveVirtualPath(options, virtualPath);
  const entries = await fsp.readdir(target, { withFileTypes: true });

  return assertKinContract('directoryList', entries
    .filter(entry => !shouldHideEntry(normalizedVirtualPath, entry.name))
    .map(entry => ({
      name: entry.name,
      type: entry.isDirectory() ? 'directory' : 'file'
    })));
}

export async function readFile(options, virtualPath) {
  const graphResult = await tryGraphServiceCommand(options, 'read-file', [
    '--path',
    displayVirtualPath(virtualPath)
  ]);
  if (graphResult) {
    const payload = await assertKinContract('fileContent', graphResult);
    return Buffer.from(payload.content, payload.encoding || 'base64');
  }

  const { target } = await resolveVirtualPath(options, virtualPath);
  return fsp.readFile(target);
}

export async function writeFile(options, virtualPath, content, writeOptions = {}) {
  const graphResult = await tryGraphServiceCommand(
    options,
    'write-file',
    [
      '--path',
      displayVirtualPath(virtualPath),
      ...(writeOptions.create ? ['--create'] : []),
      ...(writeOptions.overwrite ? ['--overwrite'] : [])
    ],
    content
  );
  if (graphResult) {
    await assertKinContract('commandAck', graphResult);
    return;
  }

  const { target } = await resolveVirtualPath(options, virtualPath);
  const exists = await pathExists(target);
  const { create = false, overwrite = false } = writeOptions;

  if (!exists && !create) {
    throw new Error(`File does not exist: ${virtualPath}`);
  }
  if (exists && !overwrite) {
    throw new Error(`File exists and overwrite was not requested: ${virtualPath}`);
  }

  await fsp.mkdir(path.dirname(target), { recursive: true });
  await fsp.writeFile(target, content);
}

export async function createDirectory(options, virtualPath) {
  const graphResult = await tryGraphServiceCommand(options, 'mkdir', [
    '--path',
    displayVirtualPath(virtualPath)
  ]);
  if (graphResult) {
    await assertKinContract('commandAck', graphResult);
    return;
  }

  const { target } = await resolveVirtualPath(options, virtualPath);
  await fsp.mkdir(target, { recursive: true });
}

export async function deletePath(options, virtualPath, deleteOptions = {}) {
  const graphResult = await tryGraphServiceCommand(options, 'delete', [
    '--path',
    displayVirtualPath(virtualPath),
    ...(deleteOptions.recursive ? ['--recursive'] : [])
  ]);
  if (graphResult) {
    await assertKinContract('commandAck', graphResult);
    return;
  }

  const { target } = await resolveVirtualPath(options, virtualPath);
  await fsp.rm(target, {
    recursive: Boolean(deleteOptions.recursive),
    force: true
  });
}

export async function renamePath(options, fromVirtualPath, toVirtualPath, renameOptions = {}) {
  const graphResult = await tryGraphServiceCommand(options, 'rename', [
    '--from',
    displayVirtualPath(fromVirtualPath),
    '--to',
    displayVirtualPath(toVirtualPath),
    ...(renameOptions.overwrite ? ['--overwrite'] : [])
  ]);
  if (graphResult) {
    await assertKinContract('commandAck', graphResult);
    return;
  }

  const fromResolved = await resolveVirtualPath(options, fromVirtualPath);
  const toResolved = await resolveVirtualPath(options, toVirtualPath);
  const exists = await pathExists(toResolved.target);

  if (exists && !renameOptions.overwrite) {
    throw new Error(`Destination exists: ${toVirtualPath}`);
  }
  if (exists) {
    await fsp.rm(toResolved.target, { recursive: true, force: true });
  }

  await fsp.mkdir(path.dirname(toResolved.target), { recursive: true });
  await fsp.rename(fromResolved.target, toResolved.target);
}

export async function runKinStatus(options = {}) {
  const context = await resolveContext(options);
  const kinPath = await resolveKinCliPath(context.repoRoot, options.kinPath);

  if (!kinPath) {
    return {
      ok: false,
      ...context,
      kinPath: null,
      stdout: '',
      stderr: 'Kin CLI not found. Set a path explicitly or build the sibling kin repo.'
    };
  }

  const modeResult = cp.spawnSync(kinPath, ['mode', 'show'], {
    cwd: context.repoRoot,
    encoding: 'utf8'
  });
  const statusResult = cp.spawnSync(kinPath, ['status'], {
    cwd: context.repoRoot,
    encoding: 'utf8'
  });

  return {
    ok: modeResult.status === 0 && statusResult.status === 0,
    ...context,
    kinPath,
    stdout: [modeResult.stdout, statusResult.stdout].filter(Boolean).join('\n'),
    stderr: [modeResult.stderr, statusResult.stderr].filter(Boolean).join('\n')
  };
}

export async function resolveKinCliPath(repoRoot, configuredPath) {
  const requestedPath = configuredPath || process.env.KIN_BINARY_PATH || '';
  if (requestedPath && await pathExists(requestedPath)) {
    return requestedPath;
  }

  const siblingDebug = path.resolve(repoRoot, '..', 'kin', 'target', 'debug', 'kin');
  if (await pathExists(siblingDebug)) {
    return siblingDebug;
  }

  const siblingRelease = path.resolve(repoRoot, '..', 'kin', 'target', 'release', 'kin');
  if (await pathExists(siblingRelease)) {
    return siblingRelease;
  }

  const which = process.platform === 'win32' ? 'where' : 'which';
  const result = cp.spawnSync(which, ['kin'], { encoding: 'utf8' });
  if (result.status === 0) {
    const candidate = (result.stdout || '').split(/\r?\n/).find(Boolean);
    if (candidate) {
      return candidate.trim();
    }
  }

  return undefined;
}

async function resolveVirtualPath(options, virtualPath) {
  const context = await resolveContext(options);
  const normalizedVirtualPath = normalizeVirtualPath(virtualPath);
  assertAllowedVirtualPath(normalizedVirtualPath);

  const target = normalizedVirtualPath
    ? path.join(context.physicalRoot, normalizedVirtualPath)
    : context.physicalRoot;

  const resolved = path.resolve(target);
  if (!resolved.startsWith(path.resolve(context.physicalRoot))) {
    throw new Error(`Virtual path escapes the Kin workspace: ${virtualPath}`);
  }

  return { context, normalizedVirtualPath, target };
}

async function tryGraphServiceCommand(options, command, args = [], input) {
  const backendMode = options.backendMode || IMPLEMENTED_BACKEND_MODE;
  if (backendMode !== GRAPH_BACKEND_MODE) {
    return undefined;
  }

  const repoRoot = options.repoRoot || await findKinRoot(options.repoPath || process.cwd());
  if (!repoRoot) {
    throw new Error(`Kin repository not found for ${options.repoPath || process.cwd()}`);
  }

  const graphServiceUrl = options.graphServiceUrl || process.env.KIN_GRAPH_SERVICE_URL || '';
  if (graphServiceUrl) {
    return requestGraphServiceHttp(graphServiceUrl, command, args, input);
  }

  const graphServicePath = await resolveGraphServicePath(repoRoot, options.graphServicePath);
  if (!graphServicePath) {
    return undefined;
  }

  const finalArgs = [
    graphServicePath,
    command,
    '--repo',
    repoRoot,
    ...args
  ];

  const result = cp.spawnSync(process.execPath, finalArgs, {
    cwd: repoRoot,
    encoding: 'utf8',
    input
  });

  if (result.error) {
    return undefined;
  }

  const payloadText = (result.stdout || '').trim();
  if (!payloadText) {
    return undefined;
  }

  let payload;
  try {
    payload = JSON.parse(payloadText);
  } catch {
    return undefined;
  }

  if (result.status !== 0 || payload.ok === false) {
    return undefined;
  }

  return payload;
}

function normalizeVirtualPath(virtualPath) {
  const raw = `${virtualPath ?? ''}`.trim();
  if (!raw || raw === '/' || raw === '.') {
    return '';
  }

  return raw
    .replace(/\\/g, '/')
    .replace(/^\/+/, '')
    .replace(/\/+/g, '/');
}

function assertAllowedVirtualPath(virtualPath) {
  const firstSegment = virtualPath.split('/')[0];
  if (HIDDEN_ROOT_ENTRIES.has(firstSegment)) {
    throw new Error(`Virtual path is hidden from the Kin workspace: ${virtualPath}`);
  }
  if (virtualPath.startsWith('..') || virtualPath.includes('/../') || virtualPath.endsWith('/..')) {
    throw new Error(`Virtual path escapes the Kin workspace: ${virtualPath}`);
  }
}

function shouldHideEntry(normalizedVirtualPath, name) {
  return normalizedVirtualPath === '' && HIDDEN_ROOT_ENTRIES.has(name);
}

async function resolvePhysicalRoot(repoRoot, mode, backendMode) {
  const nativeSourceRoot = path.join(repoRoot, '.kin', 'source-root');
  if (mode === 'native') {
    if (await pathExists(nativeSourceRoot)) {
      return nativeSourceRoot;
    }
  }

  if (backendMode !== IMPLEMENTED_BACKEND_MODE) {
    return mode === 'native' && await pathExists(nativeSourceRoot)
      ? nativeSourceRoot
      : repoRoot;
  }

  return repoRoot;
}

async function resolveGraphServicePath(repoRoot, configuredPath) {
  const requestedPath = configuredPath || process.env.KIN_GRAPH_SERVICE_PATH || '';
  if (requestedPath && await pathExists(requestedPath)) {
    return requestedPath;
  }

  const workspacePackage = path.resolve(
    path.dirname(fileURLToPath(import.meta.url)),
    '..',
    '..',
    'graph-service',
    'bin',
    'kin-graph-service.js'
  );
  if (await pathExists(workspacePackage)) {
    return workspacePackage;
  }

  return undefined;
}

async function requestGraphServiceHttp(baseUrl, command, args, input) {
  const url = buildGraphServiceUrl(baseUrl, command, args);
  const method = graphServiceMethod(command);
  const response = await fetch(url, {
    method,
    body: method === 'PUT' ? input : undefined,
    signal: AbortSignal.timeout(2000)
  }).catch(() => null);

  if (!response || !response.ok) {
    return undefined;
  }

  return response.json();
}

function buildGraphServiceUrl(baseUrl, command, args) {
  const url = new URL(baseUrl);
  url.pathname = graphServicePathname(command);

  for (let i = 0; i < args.length; i += 1) {
    const key = args[i];
    const value = args[i + 1];
    if (!key.startsWith('--')) {
      continue;
    }

    const param = graphServiceQueryParam(key);
    if (value === undefined || value.startsWith('--')) {
      url.searchParams.set(param, '1');
      continue;
    }

    url.searchParams.set(param, value);
    i += 1;
  }

  return url;
}

function graphServiceMethod(command) {
  switch (command) {
    case 'write-file':
      return 'PUT';
    case 'mkdir':
    case 'rename':
      return 'POST';
    case 'delete':
      return 'DELETE';
    default:
      return 'GET';
  }
}

function graphServicePathname(command) {
  switch (command) {
    case 'context':
      return '/context';
    case 'stat':
      return '/stat';
    case 'read-dir':
      return '/read-dir';
    case 'read-file':
      return '/read-file';
    case 'write-file':
      return '/write-file';
    case 'mkdir':
      return '/mkdir';
    case 'delete':
      return '/delete';
    case 'rename':
      return '/rename';
    default:
      throw new Error(`Unsupported graph service command: ${command}`);
  }
}

function graphServiceQueryParam(flag) {
  switch (flag) {
    case '--path':
      return 'path';
    case '--from':
      return 'from';
    case '--to':
      return 'to';
    case '--create':
      return 'create';
    case '--overwrite':
      return 'overwrite';
    case '--recursive':
      return 'recursive';
    default:
      return flag.slice(2);
  }
}

function displayVirtualPath(virtualPath) {
  const raw = `${virtualPath ?? ''}`.trim();
  return !raw || raw === '.' ? '/' : raw;
}

async function pathExists(targetPath) {
  try {
    await fsp.access(targetPath, fs.constants.F_OK);
    return true;
  } catch {
    return false;
  }
}
