// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

// The vendored proof tooling is a byte-identical copy of the umbrella's, and
// this is the check that keeps the manifest honest: an edit to a vendored file
// that does not move VENDORED.json fails here, so a local fix cannot fork the
// copy silently. The lock shim beside them is written for this tree and is
// held to its contract instead.

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const MANIFEST = JSON.parse(fs.readFileSync(path.join(HERE, 'VENDORED.json'), 'utf8'));
const SHIM = path.join(HERE, 'bin', 'kin-lane');

const sha256 = (file) => createHash('sha256').update(fs.readFileSync(file)).digest('hex');

test('the manifest names the umbrella commit and every vendored file', () => {
  assert.equal(MANIFEST.source_repository, 'firelock-ai/kin-ecosystem');
  assert.match(MANIFEST.source_commit, /^[0-9a-f]{40}$/);
  const expected = [
    'bin/kin-acceptance-suite',
    'bin/kin-evidence-publish',
    'bin/kin-release-preflight',
    'bin/kin-release-preflight.d/Dockerfile',
    'bin/kin-release-preflight.d/proof-flow.sh',
    'bin/kin-release-preflight.d/validate.mjs',
  ];
  assert.deepEqual(Object.keys(MANIFEST.files).sort(), expected);
});

test('every vendored file carries the bytes the manifest records', () => {
  for (const [relative, entry] of Object.entries(MANIFEST.files)) {
    const file = path.join(HERE, relative);
    assert.ok(fs.existsSync(file), `${relative} is missing`);
    assert.match(entry.sha256, /^[0-9a-f]{64}$/);
    assert.equal(sha256(file), entry.sha256, `${relative} drifted from VENDORED.json`);
    assert.equal(entry.source, relative);
  }
});

test('the executables are executable', () => {
  for (const relative of ['bin/kin-release-preflight', 'bin/kin-evidence-publish', 'bin/kin-acceptance-suite', 'bin/kin-release-preflight.d/proof-flow.sh', 'bin/kin-lane']) {
    const mode = fs.statSync(path.join(HERE, relative)).mode;
    assert.ok(mode & 0o111, `${relative} is not executable`);
  }
});

test('the lock shim keeps the acquire, holder and release contract the preflight relies on', () => {
  const locks = fs.mkdtempSync(path.join(os.tmpdir(), 'kin-shim-'));
  const env = { ...process.env, KIN_RELEASE_PROOF_LOCKS: locks };
  const run = (...args) => spawnSync('bash', [SHIM, ...args], { env, encoding: 'utf8' });

  // Acquire, then read the holder back: this is the read the preflight refuses
  // to run a leg without.
  assert.equal(run('acquire', 'daemon', 'release-proof', '--pid', '123', 'release preflight').status, 0);
  assert.equal(run('holder', 'daemon').stdout.trim(), 'release-proof');
  // The same lane may re-acquire; another lane may not.
  assert.equal(run('acquire', 'daemon', 'release-proof').status, 0);
  const contended = run('acquire', 'daemon', 'other-lane');
  assert.notEqual(contended.status, 0);
  assert.match(contended.stderr, /daemon is held by release-proof/);
  // A release by the wrong lane is refused; by the holder it clears the table.
  const wrong = run('release', 'daemon', 'other-lane');
  assert.notEqual(wrong.status, 0);
  assert.match(wrong.stderr, /held by 'release-proof', not 'other-lane'/);
  assert.equal(run('release', 'daemon', 'release-proof').status, 0);
  assert.equal(run('holder', 'daemon').stdout.trim(), '');
  assert.equal(run('release', 'daemon', 'release-proof').status, 0);
  assert.notEqual(run('frobnicate').status, 0);
});

test('the preflight resolves the shim beside itself rather than the fleet tool', () => {
  const preflight = fs.readFileSync(path.join(HERE, 'bin', 'kin-release-preflight'), 'utf8');
  assert.match(preflight, /KIN_LANE="\$BIN_DIR\/kin-lane"/);
  assert.match(preflight, /\[ -x "\$KIN_LANE" \] \|\| die/);
  // And it copies itself before running, which is why `bash -n` on the vendored
  // copy is a meaningful check here rather than a formality.
  assert.equal(execFileSync('bash', ['-n', path.join(HERE, 'bin', 'kin-release-preflight')], { encoding: 'utf8' }), '');
  assert.equal(execFileSync('bash', ['-n', path.join(HERE, 'bin', 'kin-release-preflight.d', 'proof-flow.sh')], { encoding: 'utf8' }), '');
  assert.equal(execFileSync('bash', ['-n', SHIM], { encoding: 'utf8' }), '');
});
