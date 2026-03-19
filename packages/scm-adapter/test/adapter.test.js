// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Firelock, LLC

import test from 'node:test';
import assert from 'node:assert/strict';

import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import fsSync from 'node:fs';
import { buildResourceGroups, parseStatusOutput, resolveContext, runCommand } from '../src/index.js';

async function makeRepo({ mode = 'native' } = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'kin-scm-adapter-'));
  await fs.mkdir(path.join(root, '.kin'), { recursive: true });
  await fs.writeFile(path.join(root, '.kin', 'mode'), `${mode}\n`);
  await fs.mkdir(path.join(root, '.git'), { recursive: true });
  return root;
}

test('parseStatusOutput extracts branch, head, and entity count', () => {
  const parsed = parseStatusOutput(`
On branch: main
Head: abc123
Entities: 42
`);

  assert.deepEqual(parsed, {
    branch: 'main',
    head: 'abc123',
    entityCount: 42
  });
});

test('buildResourceGroups emits daemon fallback details when daemon is offline', () => {
  const groups = buildResourceGroups({
    ok: true,
    mode: 'native',
    summary: {
      branch: 'main',
      head: 'abc123',
      entityCount: 42
    },
    daemon: {
      connected: false,
      changes: null,
      sessions: [],
      intents: [],
      partialFailures: []
    },
    stderr: '',
    stdout: 'On branch: main'
  });

  assert.equal(groups[0].id, 'summary');
  assert.equal(groups[1].id, 'changes');
  assert.equal(groups[1].items[0].description, 'Not connected');
  assert.equal(groups[2].id, 'sessions');
  assert.equal(groups[3].id, 'intents');
});

test('buildResourceGroups surfaces daemon endpoint failures instead of empty clean state', () => {
  const groups = buildResourceGroups({
    ok: true,
    mode: 'native',
    summary: {
      branch: 'main',
      head: 'abc123',
      entityCount: 42
    },
    daemon: {
      connected: true,
      changes: {
        base_change: 'abc123',
        entity_adds: 0,
        entity_mods: 0,
        entity_removes: 0,
        relation_adds: 0,
        relation_removes: 0
      },
      sessions: [],
      intents: [],
      partialFailures: [
        { endpoint: 'session', status: 503, error: '503 Service Unavailable' },
        { endpoint: 'intent', status: null, error: 'Connection failed' }
      ]
    },
    stderr: '',
    stdout: 'On branch: main'
  });

  assert.equal(groups[2].items[0].description, 'Unavailable');
  assert.equal(groups[3].items[0].description, 'Unavailable');
  assert.equal(groups[4].id, 'daemon-diagnostics');
  assert.equal(groups[4].items.length, 2);
});

test('resolveContext normalizes missing kinPath to null for contract compatibility', async () => {
  const repoRoot = await makeRepo({ mode: 'native' });
  const context = await resolveContext({
    repoPath: repoRoot,
    kinPath: path.join(repoRoot, 'missing-kin')
  });

  assert.equal(context.kinPath, null);
  assert.equal(context.mode, 'native');
});

test('runCommand returns contract-compatible output for kin cli invocations', async () => {
  const repoRoot = await makeRepo({ mode: 'native' });
  const fakeKinPath = path.join(repoRoot, 'fake-kin');
  await fs.writeFile(fakeKinPath, '#!/bin/sh\nprintf \"trace output\\n\"\n', { mode: 0o755 });
  if (!fsSync.existsSync(fakeKinPath)) {
    throw new Error('failed to create fake kin binary');
  }

  const result = await runCommand({
    repoPath: repoRoot,
    kinPath: fakeKinPath
  }, ['trace', 'Router::route']);

  assert.equal(result.ok, true);
  assert.equal(result.command, fakeKinPath);
  assert.deepEqual(result.args, ['trace', 'Router::route']);
  assert.match(result.stdout, /trace output/);
});
