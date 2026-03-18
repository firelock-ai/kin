import fs from 'node:fs';
import fsp from 'node:fs/promises';
import http from 'node:http';
import path from 'node:path';
import { URL } from 'node:url';
import { assertKinContract } from './contracts.js';

const HOST = '127.0.0.1';
const HIDDEN_ROOT_ENTRIES = new Set(['.git', '.kin']);

export async function resolveContext(options = {}) {
  const { repoPath } = options;
  if (!repoPath) {
    throw new Error('repoPath is required');
  }

  const repoRoot = await findKinRoot(repoPath);
  if (!repoRoot) {
    throw new Error(`Kin repository not found for ${repoPath}`);
  }

  const mode = await readRepoMode(repoRoot);
  const projectionRoot = await resolveProjectionRoot(repoRoot, mode);

  return assertKinContract('workspaceContext', {
    repoRoot,
    repoName: path.basename(repoRoot),
    mode,
    requestedBackendMode: 'graphNative',
    backendMode: 'graphNative',
    projectionMode: mode === 'native' ? 'sourceRootProjection' : 'compatProjection',
    physicalRoot: projectionRoot
  });
}

export async function statPath(options, virtualPath) {
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
  const { normalizedVirtualPath, target } = await resolveVirtualPath(options, virtualPath);
  const entries = await fsp.readdir(target, { withFileTypes: true });

  return assertKinContract('directoryList', entries
    .filter(entry => !shouldHideEntry(normalizedVirtualPath, entry.name))
    .map(entry => ({
      name: entry.name,
      type: entry.isDirectory() ? 'directory' : 'file'
    })));
}

export async function readFile(options, virtualPath) {
  const { target } = await resolveVirtualPath(options, virtualPath);
  return fsp.readFile(target);
}

export async function writeFile(options, virtualPath, content, writeOptions = {}) {
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
  const { target } = await resolveVirtualPath(options, virtualPath);
  await fsp.mkdir(target, { recursive: true });
}

export async function deletePath(options, virtualPath, deleteOptions = {}) {
  const { target } = await resolveVirtualPath(options, virtualPath);
  await fsp.rm(target, {
    recursive: Boolean(deleteOptions.recursive),
    force: true
  });
}

export async function renamePath(options, fromVirtualPath, toVirtualPath, renameOptions = {}) {
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

export async function createServer(options = {}) {
  const baseContext = await resolveContext(options);
  const host = options.host || HOST;
  const port = Number.parseInt(`${options.port ?? 0}`, 10) || 0;

  const server = http.createServer(async (request, response) => {
    try {
      const requestUrl = new URL(request.url || '/', `http://${host}`);
      if (request.method === 'GET' && requestUrl.pathname === '/health') {
        return json(response, 200, {
          ok: true,
          status: 'ok',
          backendMode: 'graphNative',
          repoRoot: baseContext.repoRoot
        });
      }
      if (request.method === 'GET' && requestUrl.pathname === '/context') {
        return json(response, 200, baseContext);
      }
      if (request.method === 'GET' && requestUrl.pathname === '/stat') {
        return json(response, 200, await statPath(options, requestUrl.searchParams.get('path') || '/'));
      }
      if (request.method === 'GET' && requestUrl.pathname === '/read-dir') {
        return json(response, 200, await readDirectory(options, requestUrl.searchParams.get('path') || '/'));
      }
      if (request.method === 'GET' && requestUrl.pathname === '/read-file') {
        const content = await readFile(options, requestUrl.searchParams.get('path') || '/');
        return json(response, 200, await assertKinContract('fileContent', {
          encoding: 'base64',
          content: Buffer.from(content).toString('base64')
        }));
      }
      if (request.method === 'PUT' && requestUrl.pathname === '/write-file') {
        const content = await readRequestBody(request);
        await writeFile(options, requestUrl.searchParams.get('path') || '/', content, {
          create: truthy(requestUrl.searchParams.get('create')),
          overwrite: truthy(requestUrl.searchParams.get('overwrite'))
        });
        return json(response, 200, await assertKinContract('commandAck', { ok: true }));
      }
      if (request.method === 'POST' && requestUrl.pathname === '/mkdir') {
        await createDirectory(options, requestUrl.searchParams.get('path') || '/');
        return json(response, 200, await assertKinContract('commandAck', { ok: true }));
      }
      if (request.method === 'DELETE' && requestUrl.pathname === '/delete') {
        await deletePath(options, requestUrl.searchParams.get('path') || '/', {
          recursive: truthy(requestUrl.searchParams.get('recursive'))
        });
        return json(response, 200, await assertKinContract('commandAck', { ok: true }));
      }
      if (request.method === 'POST' && requestUrl.pathname === '/rename') {
        await renamePath(
          options,
          requestUrl.searchParams.get('from') || '/',
          requestUrl.searchParams.get('to') || '/',
          { overwrite: truthy(requestUrl.searchParams.get('overwrite')) }
        );
        return json(response, 200, await assertKinContract('commandAck', { ok: true }));
      }

      json(response, 404, { ok: false, error: `Unknown route: ${request.method} ${requestUrl.pathname}` });
    } catch (error) {
      json(response, 500, {
        ok: false,
        error: error instanceof Error ? error.message : String(error)
      });
    }
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => resolve());
  });

  const address = server.address();
  const actualPort = typeof address === 'object' && address ? address.port : port;
  const url = `http://${host}:${actualPort}`;

  return {
    server,
    url,
    context: baseContext,
    close: async () => new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()))
  };
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

async function resolveVirtualPath(options, virtualPath) {
  const context = await resolveContext(options);
  const normalizedVirtualPath = normalizeVirtualPath(virtualPath);
  assertAllowedVirtualPath(normalizedVirtualPath);

  return {
    context,
    normalizedVirtualPath,
    target: normalizedVirtualPath
      ? path.join(context.physicalRoot, normalizedVirtualPath)
      : context.physicalRoot
  };
}

async function resolveProjectionRoot(repoRoot, mode) {
  const nativeSourceRoot = path.join(repoRoot, '.kin', 'source-root');
  if (mode === 'native' && await pathExists(nativeSourceRoot)) {
    return nativeSourceRoot;
  }
  return repoRoot;
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
  if (virtualPath.startsWith('..')) {
    throw new Error(`Virtual path escapes the Kin workspace: ${virtualPath}`);
  }
}

function shouldHideEntry(normalizedVirtualPath, name) {
  return normalizedVirtualPath === '' && HIDDEN_ROOT_ENTRIES.has(name);
}

async function readRequestBody(request) {
  const chunks = [];
  for await (const chunk of request) {
    chunks.push(Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}

function truthy(value) {
  return value === '1' || value === 'true' || value === 'yes';
}

function json(response, statusCode, payload) {
  response.statusCode = statusCode;
  response.setHeader('content-type', 'application/json');
  response.end(`${JSON.stringify(payload, null, 2)}\n`);
}

async function pathExists(targetPath) {
  try {
    await fsp.access(targetPath, fs.constants.F_OK);
    return true;
  } catch {
    return false;
  }
}
