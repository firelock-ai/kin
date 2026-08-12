// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  VFS_CORE,
  VFS_REPOSITORY,
  compareVfsCore,
  fetchPinnedLock,
  lockPackages,
  readPinnedVfsCommit,
} from './check-kin-vfs-compat.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PIN_A = 'a'.repeat(40);
const PIN_B = 'b'.repeat(40);

const releaseYamlWith = (checkoutRef, expectedCommit) => `
jobs:
  build:
    steps:
      - name: Checkout kin-vfs
        uses: actions/checkout@0000000000000000000000000000000000000000 # v7.0.0
        with:
          repository: ${VFS_REPOSITORY}
          path: kin-vfs
          # Release inputs must never move under an unchanged Kin tag.
          ref: ${checkoutRef}
          persist-credentials: false

      - name: Generate artifact provenance manifest
        env:
          EXPECTED_VFS_COMMIT: ${expectedCommit}
        run: node ./provenance.mjs
`;

const lockWith = (entries) =>
  entries
    .map(
      ({ name, version, source }) =>
        `[[package]]\nname = "${name}"\nversion = "${version}"\n` +
        (source === null ? '' : `source = "${source}"\n`),
    )
    .join('\n');

const REGISTRY = 'sparse+https://kinlab.ai/registry/cargo/';

test('reads a single agreeing pin from every site that records one', () => {
  assert.equal(readPinnedVfsCommit(releaseYamlWith(PIN_A, PIN_A)), PIN_A);
});

test('refuses a half-updated pin where the checkout moved and the proof did not', () => {
  assert.throws(
    () => readPinnedVfsCommit(releaseYamlWith(PIN_B, PIN_A)),
    /disagreeing .* pins/,
  );
});

test('refuses a release workflow that records no pin at all', () => {
  assert.throws(
    () => readPinnedVfsCommit('jobs:\n  build:\n    steps: []\n'),
    /records no .* pin/,
  );
});

test('refuses a checkout of the pinned repository with no ref', () => {
  const floating = `
jobs:
  build:
    steps:
      - name: Checkout kin-vfs
        with:
          repository: ${VFS_REPOSITORY}
          path: kin-vfs
`;
  assert.throws(() => readPinnedVfsCommit(floating), /records no ref/);
});

test('refuses a pin that is not a full commit sha', () => {
  assert.throws(() => readPinnedVfsCommit(releaseYamlWith('main', 'main')), /not a 40-character/);
});

test('reads the real release workflow and finds one pin', () => {
  const releaseYaml = fs.readFileSync(
    path.join(ROOT, '.github', 'workflows', 'release.yml'),
    'utf8',
  );
  const commit = readPinnedVfsCommit(releaseYaml);
  assert.match(commit, /^[0-9a-f]{40}$/);
});

test('parses lock entries the way the release workflow does', () => {
  const entries = lockPackages(
    lockWith([
      { name: VFS_CORE, version: '0.3.0', source: REGISTRY },
      { name: 'lru', version: '0.16.4', source: REGISTRY },
    ]),
  );
  assert.deepEqual(entries, [
    { name: VFS_CORE, version: '0.3.0', source: REGISTRY },
    { name: 'lru', version: '0.16.4', source: REGISTRY },
  ]);
});

test('accepts a lock pair that agrees', () => {
  assert.equal(
    compareVfsCore(
      lockWith([{ name: VFS_CORE, version: '0.3.0', source: REGISTRY }]),
      lockWith([{ name: VFS_CORE, version: '0.3.0', source: null }]),
    ),
    '0.3.0',
  );
});

// The shape this gate exists to catch, taken from kin#788: its first commit
// moved Kin's lock to kin-vfs-core 0.4.2 while the release pin still built
// 0.3.0. Landed alone that commit passed every required context and would have
// failed the release after the tag existed.
test('refuses the lock-moved-pin-did-not shape', () => {
  assert.throws(
    () =>
      compareVfsCore(
        lockWith([{ name: VFS_CORE, version: '0.4.2', source: REGISTRY }]),
        lockWith([{ name: VFS_CORE, version: '0.3.0', source: null }]),
      ),
    /resolves kin-vfs-core 0\.4\.2, but the pinned kin-vfs checkout builds 0\.3\.0/,
  );
});

test('refuses a lock pair it cannot resolve to exactly one entry each', () => {
  assert.throws(
    () => compareVfsCore(lockWith([{ name: 'lru', version: '0.16.4', source: REGISTRY }]),
      lockWith([{ name: VFS_CORE, version: '0.3.0', source: null }])),
    /found 0 and 1/,
  );
});

test('fails closed when the pinned lock cannot be read', async () => {
  await assert.rejects(
    () =>
      fetchPinnedLock(PIN_A, {
        fetchImpl: async () => ({ ok: false, status: 404, statusText: 'Not Found' }),
      }),
    /HTTP 404 Not Found/,
  );
});

test('fails closed when the transport itself throws', async () => {
  await assert.rejects(
    () =>
      fetchPinnedLock(PIN_A, {
        fetchImpl: async () => {
          throw new Error('getaddrinfo ENOTFOUND');
        },
      }),
    /could not reach/,
  );
});

test('fails closed on a successful response carrying no lock packages', async () => {
  await assert.rejects(
    () =>
      fetchPinnedLock(PIN_A, {
        fetchImpl: async () => ({ ok: true, status: 200, text: async () => '' }),
      }),
    /no lock packages/,
  );
});
