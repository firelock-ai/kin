// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

import assert from 'node:assert/strict';
import test from 'node:test';

import {
  classifyPath,
  evaluateVersionChange,
  expectedVersion,
  readManifestVersion,
  requestedBump,
} from './check-release-version.mjs';

test('reads a workspace version', () => {
  assert.equal(
    readManifestVersion('[workspace.package]\nversion = "0.3.7"\n'),
    '0.3.7',
  );
});

test('classifies shipped inputs as release-affecting', () => {
  for (const path of [
    'Cargo.toml',
    'Cargo.lock',
    'crates/kin-cli/src/main.rs',
    'packages/kin/index.js',
    'scripts/install.sh',
    'Dockerfile',
    '.cargo/config.toml',
  ]) {
    assert.equal(classifyPath(path), 'release', path);
  }
});

test('classifies policy, docs, and test inputs as non-release', () => {
  for (const path of [
    '.github/workflows/ci.yml',
    'README.md',
    'docs/release-bot.md',
    'crates/kin-cli/tests/repository_tag.rs',
    'scripts/test-release-workflow-authority.py',
    'crates/kin-core/src/snapshots/fixture.json',
  ]) {
    assert.equal(classifyPath(path), 'non-release', path);
  }
});

test('release-affecting changes require the next patch by default', () => {
  const result = evaluateVersionChange({
    baseVersion: '0.3.6',
    headVersion: '0.3.6',
    changedPaths: ['crates/kin-cli/src/main.rs'],
  });
  assert.equal(result.expected, '0.3.7');
  assert.equal(result.failures.length, 1);
});

test('the exact next patch passes', () => {
  const result = evaluateVersionChange({
    baseVersion: '0.3.6',
    headVersion: '0.3.7',
    changedPaths: ['Cargo.toml', 'crates/kin-cli/src/main.rs'],
  });
  assert.deepEqual(result.failures, []);
});

test('docs-only work passes without a bump', () => {
  const result = evaluateVersionChange({
    baseVersion: '0.3.6',
    headVersion: '0.3.6',
    changedPaths: ['README.md', '.github/workflows/ci.yml'],
  });
  assert.deepEqual(result.failures, []);
});

test('minor and major intent are explicit', () => {
  assert.equal(requestedBump('release:minor'), 'minor');
  assert.equal(expectedVersion('0.3.6', 'minor'), '0.4.0');
  assert.equal(requestedBump('release/major'), 'major');
  assert.equal(expectedVersion('0.3.6', 'major'), '1.0.0');
});

test('skipped versions fail closed', () => {
  const result = evaluateVersionChange({
    baseVersion: '0.3.6',
    headVersion: '0.3.8',
    changedPaths: ['Cargo.toml'],
  });
  assert.equal(result.failures.length, 1);
});
