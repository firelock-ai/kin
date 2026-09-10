// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  REGISTRY_URL,
  VFS_CORE,
  VFS_REPOSITORY,
  compareVersions,
  decide,
  fetchRegistryLatest,
  latestInstallable,
  main,
  parseIndex,
  parseVersion,
  pinnedCoreVersion,
  sparseIndexPath,
} from './wave-kin-vfs-core-hold.mjs';

const PIN = 'a'.repeat(40);
const INDEX_URL = `${REGISTRY_URL}/registry/cargo/${sparseIndexPath(VFS_CORE)}`;

const row = (version, yanked = false) =>
  JSON.stringify({
    name: VFS_CORE,
    vers: version,
    yanked,
    cksum: '0'.repeat(64),
    deps: [],
    features: {},
  });

const indexBody = (...rows) => `${rows.join('\n')}\n`;

const lockWith = (entries) =>
  entries
    .map(
      ({ name, version, source }) =>
        `[[package]]\nname = "${name}"\nversion = "${version}"\n` +
        (source === null ? '' : `source = "${source}"\n`),
    )
    .join('\n');

const releaseYamlWith = (commit) => `
jobs:
  build:
    steps:
      - name: Checkout kin-vfs
        uses: actions/checkout@0000000000000000000000000000000000000000 # v7.0.0
        with:
          repository: ${VFS_REPOSITORY}
          ref: ${commit}
          persist-credentials: false

      - name: Generate artifact provenance manifest
        env:
          EXPECTED_VFS_COMMIT: ${commit}
        run: node ./provenance.mjs
`;

// One stub for both reads main makes: the pinned kin-vfs lock from the GitHub
// contents API, and the sparse index from the Kin registry. Routing on the URL
// rather than on call order means a change that reorders them still exercises
// the same responses instead of silently swapping them.
const stubFetch = ({ lock, index, indexStatus = 200 }) => {
  const seen = [];
  const impl = async (url) => {
    seen.push(url);
    if (url.startsWith('https://api.github.com/')) {
      return { ok: true, status: 200, statusText: 'OK', text: async () => lock };
    }
    if (url === INDEX_URL) {
      if (indexStatus !== 200) {
        return {
          ok: false,
          status: indexStatus,
          statusText: 'Not Found',
          text: async () => '',
        };
      }
      return { ok: true, status: 200, statusText: 'OK', text: async () => index };
    }
    throw new Error(`unexpected fetch of ${url}`);
  };
  impl.seen = seen;
  return impl;
};

// A tree carrying only what readPinSources needs, so main's discovery runs for
// real rather than through a stub of the thing this exists to share.
const treeWithPin = (commit) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'wave-vfs-hold-'));
  fs.mkdirSync(path.join(root, '.github', 'workflows'), { recursive: true });
  fs.writeFileSync(
    path.join(root, '.github', 'workflows', 'release.yml'),
    releaseYamlWith(commit),
    'utf8',
  );
  return root;
};

// ---------------------------------------------------------------------------
// The rule itself. These two are the arms the whole change rests on: an
// obvious mutation of `decide` (always roll, always hold, or `!==` for `===`)
// takes one of them red.
// ---------------------------------------------------------------------------

test('rolls when the registry latest is exactly what the pinned checkout builds', () => {
  const verdict = decide({
    registryLatest: '0.4.24',
    pinnedVersion: '0.4.24',
    pinnedCommit: PIN,
  });
  assert.equal(verdict.roll, true);
  assert.match(verdict.reason, /0\.4\.24/);
});

test('holds when the registry has published past the pinned checkout', () => {
  const verdict = decide({
    registryLatest: '0.4.25',
    pinnedVersion: '0.4.24',
    pinnedCommit: PIN,
  });
  assert.equal(verdict.roll, false);
  assert.match(verdict.reason, /newest installable version is 0\.4\.25/);
  assert.match(verdict.reason, /builds 0\.4\.24/);
  assert.match(verdict.reason, /release\.yml/);
});

test('holds when the pin was moved ahead of the registry', () => {
  const verdict = decide({
    registryLatest: '0.4.24',
    pinnedVersion: '0.4.25',
    pinnedCommit: PIN,
  });
  assert.equal(verdict.roll, false);
});

test('holds when the registry publishes no installable version at all', () => {
  const verdict = decide({
    registryLatest: null,
    pinnedVersion: '0.4.24',
    pinnedCommit: PIN,
  });
  assert.equal(verdict.roll, false);
  assert.match(verdict.reason, /no installable/);
});

// The exact state of 2026-09-10 that produced kin#1665's red required context:
// kin-vfs published 0.4.25 while the pin still built 0.4.24. A regression that
// re-enables the roll in that state takes this red.
test('holds on the kin#1665 state that reds Fast gate lint and policy', () => {
  assert.equal(
    decide({ registryLatest: '0.4.25', pinnedVersion: '0.4.24', pinnedCommit: PIN }).roll,
    false,
  );
});

// ---------------------------------------------------------------------------
// Yank authority, which decides what "latest" even means.
// ---------------------------------------------------------------------------

test('the newest yanked version is not the version the pin has to match', () => {
  assert.equal(
    latestInstallable([
      { version: '0.4.24', yanked: false },
      { version: '0.4.25', yanked: true },
    ]),
    '0.4.24',
  );
});

test('every version yanked is no installable version', () => {
  assert.equal(latestInstallable([{ version: '0.4.24', yanked: true }]), null);
});

test('latest is by SemVer precedence, not by row order or string order', () => {
  assert.equal(
    latestInstallable([
      { version: '0.4.10', yanked: false },
      { version: '0.4.9', yanked: false },
    ]),
    '0.4.10',
  );
});

// ---------------------------------------------------------------------------
// Version ordering, the piece a string comparison would get wrong.
// ---------------------------------------------------------------------------

test('orders double-digit patches above single-digit ones', () => {
  assert.equal(compareVersions('0.4.10', '0.4.9') > 0, true);
});

test('orders a release above its own prereleases', () => {
  assert.equal(compareVersions('0.4.25', '0.4.25-rc.1') > 0, true);
  assert.equal(compareVersions('0.4.25-rc.2', '0.4.25-rc.1') > 0, true);
  assert.equal(compareVersions('0.4.25-rc.1', '0.4.25-rc.1') === 0, true);
});

test('ignores build metadata in precedence', () => {
  assert.equal(compareVersions('0.4.25+abc', '0.4.25') === 0, true);
});

test('refuses a version the registry should never have served', () => {
  assert.throws(() => parseVersion('0.4'), /invalid SemVer/);
  assert.throws(() => parseVersion('0.04.1'), /invalid SemVer/);
});

// ---------------------------------------------------------------------------
// Where the index lives. Getting this wrong reads a 404 as "unpublished" and
// holds forever, which is quiet, so it is asserted rather than assumed.
// ---------------------------------------------------------------------------

test('mirrors the sparse-index layout for every name length', () => {
  assert.equal(sparseIndexPath('a'), '1/a');
  assert.equal(sparseIndexPath('ab'), '2/ab');
  assert.equal(sparseIndexPath('abc'), '3/a/abc');
  assert.equal(sparseIndexPath('kin-vfs-core'), 'ki/n-/kin-vfs-core');
  assert.equal(sparseIndexPath('KIN-DB'), 'ki/n-/kin-db');
});

// ---------------------------------------------------------------------------
// Reading the index. Strict, because a row this cannot read is a registry
// answer it cannot claim to have understood.
// ---------------------------------------------------------------------------

test('reads a well-formed index', () => {
  const records = parseIndex(indexBody(row('0.4.24'), row('0.4.25', true)), {
    crate: VFS_CORE,
    source: INDEX_URL,
  });
  assert.deepEqual(records, [
    { name: VFS_CORE, version: '0.4.24', yanked: false },
    { name: VFS_CORE, version: '0.4.25', yanked: true },
  ]);
});

test('refuses a row that is not JSON', () => {
  assert.throws(
    () => parseIndex('{not json\n', { crate: VFS_CORE, source: INDEX_URL }),
    /invalid JSON/,
  );
});

test('refuses a row for another crate', () => {
  const foreign = JSON.stringify({
    name: 'kin-db',
    vers: '0.7.0',
    yanked: false,
    cksum: '0'.repeat(64),
    deps: [],
    features: {},
  });
  assert.throws(
    () => parseIndex(`${foreign}\n`, { crate: VFS_CORE, source: INDEX_URL }),
    /does not match/,
  );
});

test('refuses a row with no yank authority', () => {
  const missing = JSON.stringify({ name: VFS_CORE, vers: '0.4.24' });
  assert.throws(
    () => parseIndex(`${missing}\n`, { crate: VFS_CORE, source: INDEX_URL }),
    /missing boolean 'yanked'/,
  );
});

test('refuses an empty successful body rather than reading it as no versions', () => {
  assert.throws(
    () => parseIndex('\n\n', { crate: VFS_CORE, source: INDEX_URL }),
    /empty successful response/,
  );
});

// ---------------------------------------------------------------------------
// Transport. Fails closed: only a 404 is an answer.
// ---------------------------------------------------------------------------

test('a 404 is an unpublished crate, which holds', async () => {
  const impl = stubFetch({ lock: '', index: '', indexStatus: 404 });
  assert.equal(await fetchRegistryLatest(VFS_CORE, { fetchImpl: impl }), null);
});

test('a 500 is not a roll and not a hold, it is a failed step', async () => {
  const impl = stubFetch({ lock: '', index: '', indexStatus: 500 });
  await assert.rejects(
    fetchRegistryLatest(VFS_CORE, { fetchImpl: impl }),
    /HTTP 500/,
  );
});

test('an unreachable registry is a failed step', async () => {
  await assert.rejects(
    fetchRegistryLatest(VFS_CORE, {
      fetchImpl: async () => {
        throw new Error('ECONNRESET');
      },
    }),
    /could not read registry index .*ECONNRESET/,
  );
});

// ---------------------------------------------------------------------------
// The pinned side, read the way the compat gate reads it.
// ---------------------------------------------------------------------------

test('reads the pinned checkout version from its own local lock entry', () => {
  const lock = lockWith([
    { name: VFS_CORE, version: '0.4.24', source: null },
    { name: 'lru', version: '0.12.0', source: 'registry+https://crates.io' },
  ]);
  assert.equal(pinnedCoreVersion(lock), '0.4.24');
});

test('refuses a pinned lock that does not carry exactly one local kin-vfs-core', () => {
  assert.throws(() => pinnedCoreVersion(lockWith([])), /found 0/);
  assert.throws(
    () =>
      pinnedCoreVersion(
        lockWith([
          { name: VFS_CORE, version: '0.4.24', source: null },
          { name: VFS_CORE, version: '0.4.25', source: null },
        ]),
      ),
    /found 2/,
  );
});

// ---------------------------------------------------------------------------
// End to end, through the real pin discovery, writing the outputs the workflow
// branches on. A workflow reading a key this never writes would hold forever
// and never say so, so the key names are asserted here.
// ---------------------------------------------------------------------------

test('holds end to end and writes the outputs the receiver branches on', async () => {
  const root = treeWithPin(PIN);
  const written = [];
  const verdict = await main({
    root,
    env: {},
    fetchImpl: stubFetch({
      lock: lockWith([{ name: VFS_CORE, version: '0.4.24', source: null }]),
      index: indexBody(row('0.4.24'), row('0.4.25')),
    }),
    log: () => {},
    writeOutput: async (text) => written.push(text),
  });
  assert.equal(verdict.roll, false);
  const text = written.join('');
  assert.match(text, /^kin_vfs_core_roll=false$/m);
  assert.match(text, /^kin_vfs_core_pinned=0\.4\.24$/m);
  assert.match(text, /^kin_vfs_core_registry=0\.4\.25$/m);
  assert.match(text, /^kin_vfs_core_reason=holding kin-vfs-core at the pin: /m);
  assert.equal(text.split('\n').filter((line) => line !== '').length, 4);
});

test('rolls end to end when the registry and the pin agree', async () => {
  const root = treeWithPin(PIN);
  const written = [];
  const verdict = await main({
    root,
    env: {},
    fetchImpl: stubFetch({
      lock: lockWith([{ name: VFS_CORE, version: '0.4.25', source: null }]),
      index: indexBody(row('0.4.24'), row('0.4.25')),
    }),
    log: () => {},
    writeOutput: async (text) => written.push(text),
  });
  assert.equal(verdict.roll, true);
  assert.match(written.join(''), /^kin_vfs_core_roll=true$/m);
});

test('reads the pin through the shared discovery, so a floating ref refuses', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'wave-vfs-hold-'));
  fs.mkdirSync(path.join(root, '.github', 'workflows'), { recursive: true });
  fs.writeFileSync(
    path.join(root, '.github', 'workflows', 'release.yml'),
    releaseYamlWith('main'),
    'utf8',
  );
  await assert.rejects(
    main({
      root,
      env: {},
      fetchImpl: async () => {
        throw new Error('should never reach the network');
      },
      log: () => {},
      writeOutput: async () => {},
    }),
    /not a 40-character commit sha/,
  );
});

test('a reason never carries a newline, which would forge a second output key', () => {
  const verdict = decide({
    registryLatest: '0.4.25',
    pinnedVersion: '0.4.24',
    pinnedCommit: PIN,
  });
  assert.equal(/[\r\n]/.test(verdict.reason), false);
});
