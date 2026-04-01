// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';

import {
  createDirectory,
  findKinRoot,
  readDirectory,
  readFile,
  readRepoMode,
  resolveContext,
  statPath,
  writeFile
} from '../src/index.js';

async function startGraphServiceStub(repoRoot) {
  const state = new Map();

  const server = http.createServer(async (request, response) => {
    const requestUrl = new URL(request.url, 'http://127.0.0.1');
    const send = payload => {
      response.statusCode = 200;
      response.setHeader('content-type', 'application/json');
      response.end(`${JSON.stringify(payload)}\n`);
    };

    if (requestUrl.pathname === '/context') {
      send({
        repoRoot,
        repoName: path.basename(repoRoot),
        mode: 'native',
        requestedBackendMode: 'graphNative',
        backendMode: 'graphNative',
        projectionMode: 'stub',
        physicalRoot: path.join(repoRoot, '.kin', 'source-root')
      });
      return;
    }

    if (requestUrl.pathname === '/read-dir') {
      send([{ name: 'from-service.ts', type: 'file' }]);
      return;
    }

    if (requestUrl.pathname === '/read-file') {
      const content = state.get(requestUrl.searchParams.get('path')) || 'export const service = true;\n';
      send({
        encoding: 'base64',
        content: Buffer.from(content).toString('base64')
      });
      return;
    }

    if (requestUrl.pathname === '/write-file') {
      const chunks = [];
      for await (const chunk of request) {
        chunks.push(Buffer.from(chunk));
      }
      state.set(requestUrl.searchParams.get('path'), Buffer.concat(chunks).toString('utf8'));
      send({ ok: true });
      return;
    }

    if (requestUrl.pathname === '/stat') {
      send({ type: 'file', ctimeMs: 1, mtimeMs: 1, size: 10 });
      return;
    }

    if (requestUrl.pathname === '/mkdir' || requestUrl.pathname === '/delete' || requestUrl.pathname === '/rename') {
      send({ ok: true });
      return;
    }

    response.statusCode = 404;
    response.end();
  });

  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  return {
    url: `http://127.0.0.1:${address.port}`,
    close: async () => new Promise(resolve => server.close(resolve))
  };
}

async function makeRepo({ mode = 'compat' } = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'kin-fs-adapter-'));
  await fs.mkdir(path.join(root, '.kin', 'source-root'), { recursive: true });
  await fs.writeFile(path.join(root, '.kin', 'mode'), `${mode}\n`);
  await fs.writeFile(path.join(root, '.gitkeep'), '');
  await fs.mkdir(path.join(root, '.git'), { recursive: true });
  await fs.writeFile(path.join(root, '.git', 'HEAD'), 'ref: refs/heads/main\n');
  await fs.writeFile(path.join(root, 'README.md'), 'control-root\n');
  await fs.writeFile(path.join(root, '.kin', 'source-root', 'main.ts'), 'export const value = 1;\n');
  await fs.mkdir(path.join(root, '.kin', 'source-root', 'src'), { recursive: true });
  await fs.writeFile(path.join(root, '.kin', 'source-root', 'src', 'app.ts'), 'export const app = true;\n');
  await fs.writeFile(path.join(root, 'plain.txt'), 'compat text\n');
  return root;
}

test('findKinRoot discovers from nested paths', async () => {
  const repoRoot = await makeRepo({ mode: 'native' });
  const nested = path.join(repoRoot, '.kin', 'source-root', 'src', 'app.ts');

  const discovered = await findKinRoot(nested);
  assert.equal(discovered, repoRoot);
});

test('readRepoMode reads native mode', async () => {
  const repoRoot = await makeRepo({ mode: 'native' });
  assert.equal(await readRepoMode(repoRoot), 'native');
});

test('resolveContext maps native mode to source-root bridge', async () => {
  const repoRoot = await makeRepo({ mode: 'native' });
  const context = await resolveContext({ repoPath: repoRoot, backendMode: 'graphNative' });

  assert.equal(context.mode, 'native');
  assert.equal(context.requestedBackendMode, 'graphNative');
  assert.equal(context.backendMode, 'sourceRootBridge');
  assert.equal(context.physicalRoot, path.join(repoRoot, '.kin', 'source-root'));
});

test('resolveContext uses graph service when configured for graphNative mode', async () => {
  const repoRoot = await makeRepo({ mode: 'native' });
  const graphService = await startGraphServiceStub(repoRoot);

  try {
    const context = await resolveContext({
      repoPath: repoRoot,
      backendMode: 'graphNative',
      graphServiceUrl: graphService.url
    });

    assert.equal(context.backendMode, 'graphNative');
    assert.equal(context.projectionMode, 'stub');
  } finally {
    await graphService.close();
  }
});

test('readDirectory hides control-root entries from the virtual root', async () => {
  const repoRoot = await makeRepo({ mode: 'compat' });
  const entries = await readDirectory({ repoPath: repoRoot }, '/');

  const names = entries.map(entry => entry.name);
  assert.ok(!names.includes('.git'));
  assert.ok(!names.includes('.kin'));
  assert.ok(names.includes('README.md'));
});

test('readFile rejects hidden virtual paths', async () => {
  const repoRoot = await makeRepo({ mode: 'compat' });

  await assert.rejects(
    readFile({ repoPath: repoRoot }, '.kin/mode'),
    /hidden from the Kin workspace/
  );
});

test('writeFile writes into native source-root instead of control root', async () => {
  const repoRoot = await makeRepo({ mode: 'native' });

  await writeFile(
    { repoPath: repoRoot },
    'src/new.ts',
    Buffer.from('export const created = true;\n'),
    { create: true, overwrite: true }
  );

  const created = await fs.readFile(path.join(repoRoot, '.kin', 'source-root', 'src', 'new.ts'), 'utf8');
  assert.match(created, /created = true/);
});

test('createDirectory and statPath operate on the visible workspace', async () => {
  const repoRoot = await makeRepo({ mode: 'native' });

  await createDirectory({ repoPath: repoRoot }, 'docs');
  const stat = await statPath({ repoPath: repoRoot }, 'docs');

  assert.equal(stat.type, 'directory');
});

test('readFile and writeFile can flow through the graph service', async () => {
  const repoRoot = await makeRepo({ mode: 'native' });
  const graphService = await startGraphServiceStub(repoRoot);

  try {
    await writeFile(
      {
        repoPath: repoRoot,
        backendMode: 'graphNative',
        graphServiceUrl: graphService.url
      },
      '/src/created.ts',
      Buffer.from('export const created = true;\n'),
      { create: true, overwrite: true }
    );

    const content = await readFile(
      {
        repoPath: repoRoot,
        backendMode: 'graphNative',
        graphServiceUrl: graphService.url
      },
      '/src/created.ts'
    );

    assert.match(Buffer.from(content).toString('utf8'), /created = true/);
  } finally {
    await graphService.close();
  }
});

test('resolveContext rejects invalid graph service workspace payloads', async () => {
  const repoRoot = await makeRepo({ mode: 'native' });
  const server = http.createServer((request, response) => {
    if (request.url?.startsWith('/context')) {
      response.statusCode = 200;
      response.setHeader('content-type', 'application/json');
      response.end(`${JSON.stringify({ repoRoot })}\n`);
      return;
    }
    response.statusCode = 404;
    response.end();
  });

  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  const graphServiceUrl = `http://127.0.0.1:${address.port}`;

  try {
    await assert.rejects(
      resolveContext({
        repoPath: repoRoot,
        backendMode: 'graphNative',
        graphServiceUrl
      }),
      /workspaceContext validation failed/
    );
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});
