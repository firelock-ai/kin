// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Firelock, LLC

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { createServer, readDirectory, readFile, resolveContext, writeFile } from '../src/index.js';

async function makeRepo({ mode = 'native' } = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'kin-graph-service-'));
  await fs.mkdir(path.join(root, '.kin', 'source-root', 'src'), { recursive: true });
  await fs.writeFile(path.join(root, '.kin', 'mode'), `${mode}\n`);
  await fs.writeFile(path.join(root, '.kin', 'source-root', 'src', 'app.ts'), 'export const value = 1;\n');
  await fs.writeFile(path.join(root, 'README.md'), 'control-root\n');
  await fs.mkdir(path.join(root, '.git'), { recursive: true });
  return root;
}

test('resolveContext reports graphNative backend', async () => {
  const repoRoot = await makeRepo();
  const context = await resolveContext({ repoPath: repoRoot });

  assert.equal(context.backendMode, 'graphNative');
  assert.equal(context.mode, 'native');
  assert.equal(context.projectionMode, 'sourceRootProjection');
});

test('readDirectory hides control files from the virtual root', async () => {
  const repoRoot = await makeRepo({ mode: 'compat' });
  const entries = await readDirectory({ repoPath: repoRoot }, '/');
  const names = entries.map(entry => entry.name);

  assert.ok(!names.includes('.git'));
  assert.ok(!names.includes('.kin'));
  assert.ok(names.includes('README.md'));
});

test('service serves file operations over HTTP', async () => {
  const repoRoot = await makeRepo();
  const handle = await createServer({ repoPath: repoRoot, port: 0 });

  try {
    const health = await fetch(`${handle.url}/health`).then(r => r.json());
    assert.equal(health.status, 'ok');

    const readDir = await fetch(`${handle.url}/read-dir?path=/src`).then(r => r.json());
    assert.equal(readDir[0].name, 'app.ts');

    await fetch(`${handle.url}/write-file?path=/src/created.ts&create=1&overwrite=1`, {
      method: 'PUT',
      body: 'export const created = true;\n'
    });

    const payload = await fetch(`${handle.url}/read-file?path=/src/created.ts`).then(r => r.json());
    const created = Buffer.from(payload.content, payload.encoding).toString('utf8');
    assert.match(created, /created = true/);
  } finally {
    await handle.close();
  }
});

test('direct readFile/writeFile uses projected root', async () => {
  const repoRoot = await makeRepo();
  await writeFile({ repoPath: repoRoot }, '/src/direct.ts', Buffer.from('export const direct = true;\n'), {
    create: true,
    overwrite: true
  });

  const content = await readFile({ repoPath: repoRoot }, '/src/direct.ts');
  assert.match(Buffer.from(content).toString('utf8'), /direct = true/);
});
