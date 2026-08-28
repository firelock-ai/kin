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
  collectVfsPinSites,
  lockPackages,
  readPinSources,
  readPinnedVfsCommit,
} from './check-kin-vfs-compat.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PIN_A = 'a'.repeat(40);
const PIN_B = 'b'.repeat(40);

// Escapes every RegExp metacharacter, backslash included. A class of only `.`
// and `/` leaves a backslash in the input free to open an escape sequence in
// the compiled pattern, so the match quietly stops meaning what the literal
// says instead of failing.
const escapeRegExp = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

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

const RELEASE = '.github/workflows/release.yml';
const RC_BUILD = '.github/workflows/rc-build.yml';
const AUTHORITY = 'scripts/test-release-workflow-authority.py';
const asSources = (text, file = RELEASE) => [{ path: file, text }];

// The authority script records the pin as a quoted literal inside a Python
// tuple, which is why the reader accepts an optional quote around the value.
const authorityPyWith = (commit) => `
    for policy in (
        "uses: ./.github/workflows/install-proof.yml",
        "expected_vfs_commit: ${commit}",
    ):
        require(install_proof_job, policy, "mandatory public install proof")
`;

test('reads a single agreeing pin from every site that records one', () => {
  assert.equal(readPinnedVfsCommit(asSources(releaseYamlWith(PIN_A, PIN_A))), PIN_A);
});

test('refuses a half-updated pin where the checkout moved and the proof did not', () => {
  assert.throws(
    () => readPinnedVfsCommit(asSources(releaseYamlWith(PIN_B, PIN_A))),
    /disagreeing .* pins/,
  );
});

test('refuses a release workflow that records no pin at all', () => {
  assert.throws(
    () => readPinnedVfsCommit(asSources('jobs:\n  build:\n    steps: []\n')),
    /no .* pin was found/,
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
  assert.throws(() => readPinnedVfsCommit(asSources(floating)), /records no ref/);
});

test('refuses a pin that is not a full commit sha', () => {
  assert.throws(() => readPinnedVfsCommit(asSources(releaseYamlWith('main', 'main'))), /not a 40-character/);
});

test('reads the real release workflow and finds one pin', () => {
  const releaseYaml = fs.readFileSync(
    path.join(ROOT, '.github', 'workflows', 'release.yml'),
    'utf8',
  );
  const commit = readPinnedVfsCommit(asSources(releaseYaml));
  assert.match(commit, /^[0-9a-f]{40}$/);
});

test('reads the pin out of rc-build.yml, which the old gate never opened', () => {
  const sites = collectVfsPinSites(releaseYamlWith(PIN_A, PIN_A), RC_BUILD);
  assert.equal(sites.length, 2, 'a checkout ref and an expected commit');
  assert.ok(
    sites.every(({ site }) => site.startsWith(RC_BUILD)),
    `every site must name its file: ${JSON.stringify(sites)}`,
  );
});

test('reads the pin out of the authority script quoted literal', () => {
  const sites = collectVfsPinSites(authorityPyWith(PIN_A), AUTHORITY);
  assert.deepEqual(sites, [{ sha: PIN_A, site: `${AUTHORITY} expected_vfs_commit` }]);
});

test('refuses a pin that release.yml moved and rc-build.yml did not', () => {
  assert.throws(
    () => readPinnedVfsCommit([
      { path: RELEASE, text: releaseYamlWith(PIN_A, PIN_A) },
      { path: RC_BUILD, text: releaseYamlWith(PIN_B, PIN_B) },
    ]),
    (error) => {
      assert.match(error.message, /disagreeing/);
      assert.match(error.message, new RegExp(escapeRegExp(RC_BUILD)));
      return true;
    },
    'the failure must name rc-build.yml, or an operator cannot tell which home lagged',
  );
});

test('refuses a pin the authority script alone did not follow', () => {
  assert.throws(
    () => readPinnedVfsCommit([
      { path: RELEASE, text: releaseYamlWith(PIN_A, PIN_A) },
      { path: AUTHORITY, text: authorityPyWith(PIN_B) },
    ]),
    new RegExp(escapeRegExp(AUTHORITY)),
  );
});

test('accepts every home agreeing across all three files', () => {
  assert.equal(
    readPinnedVfsCommit([
      { path: RELEASE, text: releaseYamlWith(PIN_A, PIN_A) },
      { path: RC_BUILD, text: releaseYamlWith(PIN_A, PIN_A) },
      { path: AUTHORITY, text: authorityPyWith(PIN_A) },
    ]),
    PIN_A,
    'the agreeing case must still pass, or the arms above only prove it refuses',
  );
});

// The values that are NOT pin sites. Every one of these was read out of the
// real tree: an input declaration, a caller opting out, shell plumbing and a
// regex literal all spell the key the same way and carry no sha.
test('ignores expected_vfs_commit spellings that record no sha', () => {
  for (const text of [
    '      expected_vfs_commit: ""\n',
    '      expected_vfs_commit:\n',
    "          REVIEWED_VFS_COMMIT: ${{ inputs.expected_vfs_commit || '' }}\n",
    '          expected_vfs_commit="$REVIEWED_VFS_COMMIT"\n',
    '    re.findall(r"expected_vfs_commit:\\s*([0-9a-f]{40})", release)\n',
  ]) {
    assert.deepEqual(
      collectVfsPinSites(text, '.github/workflows/ci.yml'),
      [],
      `must not be read as a pin site: ${text.trim()}`,
    );
  }
});

test('the real tree records one pin across every file that holds one', async () => {
  const sources = await readPinSources(ROOT);
  const sites = sources.flatMap(({ path: file, text }) => collectVfsPinSites(text, file));
  const files = [...new Set(sites.map(({ site }) => site.split(' ')[0]))].sort();
  assert.ok(sites.length >= 8, `expected at least the eight known homes, found ${sites.length}`);
  assert.deepEqual(files, [RC_BUILD, RELEASE, AUTHORITY].sort());
  assert.equal(new Set(sites.map(({ sha }) => sha)).size, 1, 'every home agrees');
  assert.ok(
    !sources.some(({ path: file }) => file.includes('check-kin-vfs-compat')),
    'the gate must not scan its own source, which carries its own patterns',
  );
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
