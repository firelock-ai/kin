// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

import assert from 'node:assert/strict';
import test from 'node:test';

import { assertNotRollback, compareSemver, parseSemver, releaseChannel } from './release-order.mjs';

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
