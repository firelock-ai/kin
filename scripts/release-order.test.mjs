// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import {
  mkdtempSync,
  rmSync,
  symlinkSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import test from 'node:test';

import {
  assertNotRollback,
  compareSemver,
  parseSemver,
  releaseChannel,
  resolveGitHubLatest,
  resolveNpmChannel,
} from './release-order.mjs';

function response(status, body, headers = {}) {
  const normalized = new Map(Object.entries(headers).map(([key, value]) => [key.toLowerCase(), value]));
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: (name) => normalized.get(name.toLowerCase()) ?? null },
    text: async () => JSON.stringify(body),
  };
}

test('orders stable and prerelease versions according to SemVer', () => {
  assert.equal(compareSemver('1.2.3', '1.2.3'), 0);
  assert.equal(compareSemver('1.2.4', '1.2.3'), 1);
  assert.equal(compareSemver('1.2.3-alpha.10', '1.2.3-alpha.2'), 1);
  assert.equal(compareSemver('1.2.3-alpha', '1.2.3'), -1);
  assert.equal(compareSemver('1.2.3-rc.1', '1.2.3-beta.9'), 1);
});

test('rejects invalid versions and unsupported channels', () => {
  assert.throws(() => parseSemver('1.2'), /invalid/);
  assert.throws(() => parseSemver('1.2.3-alpha.01'), /leading zeroes/);
  assert.throws(() => releaseChannel('1.2.3-preview.1'), /unsupported/);
});

test('maps release channels and prevents rollback', () => {
  assert.equal(releaseChannel('1.2.3'), 'latest');
  assert.equal(releaseChannel('1.2.3-beta.2'), 'beta');
  assert.doesNotThrow(() => assertNotRollback('1.2.3', '1.2.3'));
  assert.doesNotThrow(() => assertNotRollback('1.2.4', '1.2.3'));
  assert.throws(() => assertNotRollback('1.2.2', '1.2.3', 'npm latest'), /refusing to roll/);
});

test('CLI enforces channel and rollback policy through a symlinked path', () => {
  const directory = mkdtempSync(join(tmpdir(), 'kin-release-order-'));
  const linkedEntry = join(directory, 'release-order.mjs');
  try {
    symlinkSync(fileURLToPath(new URL('./release-order.mjs', import.meta.url)), linkedEntry);
    const channel = execFileSync(process.execPath, [linkedEntry, 'channel', '1.2.3'], {
      encoding: 'utf8',
    });
    assert.equal(channel.trim(), 'latest');

    const rollback = spawnSync(
      process.execPath,
      [linkedEntry, 'assert-not-rollback', '1.2.2', '1.2.3', 'npm latest'],
      { encoding: 'utf8' },
    );
    assert.notEqual(rollback.status, 0);
    assert.match(rollback.stderr, /refusing to roll it back/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('reads npm channel authority from successful package metadata', async () => {
  const fetchImpl = async () => response(200, {
    'dist-tags': { latest: '1.2.3', beta: '1.3.0-beta.2' },
  });
  assert.equal(await resolveNpmChannel('@kinlab/kin', 'latest', { fetchImpl }), '1.2.3');
  assert.equal(await resolveNpmChannel('@kinlab/kin', 'alpha', { fetchImpl }), '<none>');
});

test('retries transient npm authority failures and fails closed on package 404', async () => {
  let calls = 0;
  const retryFetch = async () => {
    calls += 1;
    return calls === 1
      ? response(503, { error: 'unavailable' })
      : response(200, { 'dist-tags': { latest: '1.2.4' } });
  };
  assert.equal(await resolveNpmChannel('@kinlab/kin', 'latest', {
    fetchImpl: retryFetch,
    sleepImpl: async () => {},
  }), '1.2.4');
  assert.equal(calls, 2);
  await assert.rejects(
    resolveNpmChannel('@kinlab/kin', 'latest', {
      fetchImpl: async () => response(404, { error: 'not found' }),
    }),
    /HTTP 404/,
  );
  await assert.rejects(
    resolveNpmChannel('@kinlab/kin', 'latest', {
      fetchImpl: async () => response(200, {}),
    }),
    /no valid dist-tags authority/,
  );
});

test('distinguishes an absent GitHub Latest release from API failure', async () => {
  assert.equal(await resolveGitHubLatest('firelock-ai/kin', 'token', {
    fetchImpl: async () => response(404, { message: 'Not Found' }),
  }), '<none>');
  await assert.rejects(
    resolveGitHubLatest('firelock-ai/kin', 'token', {
      fetchImpl: async () => response(401, { message: 'Bad credentials' }),
    }),
    /HTTP 401/,
  );
});
