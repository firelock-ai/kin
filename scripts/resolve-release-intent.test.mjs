// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { execFileSync } from 'node:child_process';

import { resolveReleaseIntent } from './resolve-release-intent.mjs';

// Fixture commits are throwaway history, so the developer host's commit
// hygiene hooks must not run against them.
function git(root, args, input) {
  const hooks = path.join(root, '.git', 'fixture-hooks-disabled');
  return execFileSync('git', ['-c', `core.hooksPath=${hooks}`, ...args], {
    cwd: root,
    encoding: 'utf8',
    input,
  });
}

// A repository whose first-parent history is the only place intent can live.
function repository(messages) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kin-release-intent-'));
  git(root, ['init', '--quiet', '--initial-branch=main']);
  git(root, ['config', 'user.name', 'Test']);
  git(root, ['config', 'user.email', 'test@example.invalid']);
  git(root, ['commit', '--allow-empty', '--quiet', '-m', 'base']);
  git(root, ['tag', 'v1.2.3']);
  for (const message of messages) {
    git(root, ['commit', '--allow-empty', '--quiet', '-F', '-'], message);
  }
  return root;
}

test('absent evidence resolves to patch', () => {
  const root = repository(['first change', 'second change']);
  const result = resolveReleaseIntent({ root, baseRef: 'v1.2.3', headRef: 'HEAD' });
  assert.equal(result.intent, 'patch');
  assert.deepEqual(result.evidence, []);
});

test('the highest intent in the range wins regardless of order', () => {
  const root = repository([
    'a change\n\nKin-Release-Intent: major\n',
    'another change\n\nKin-Release-Intent: minor\n',
  ]);
  assert.equal(resolveReleaseIntent({ root, baseRef: 'v1.2.3' }).intent, 'major');
});

test('a later commit without evidence cannot lower a resolved intent', () => {
  const root = repository(['a change\n\nKin-Release-Intent: minor\n', 'a routine change']);
  const result = resolveReleaseIntent({ root, baseRef: 'v1.2.3' });
  assert.equal(result.intent, 'minor');
  assert.equal(result.evidence.length, 1);
});

test('growing the range never lowers the intent', () => {
  const root = repository(['a change\n\nKin-Release-Intent: minor\n']);
  const before = resolveReleaseIntent({ root, baseRef: 'v1.2.3' }).intent;
  git(root, ['commit', '--allow-empty', '--quiet', '-m', 'later change']);
  const after = resolveReleaseIntent({ root, baseRef: 'v1.2.3' }).intent;
  assert.equal(before, 'minor');
  assert.equal(after, 'minor');
});

test('a mention outside the trailer footer is refused, not ignored', () => {
  const root = repository(['Kin-Release-Intent: major is what this wants\n\nbody text\n']);
  assert.throws(
    () => resolveReleaseIntent({ root, baseRef: 'v1.2.3' }),
    /malformed or non-footer Kin-Release-Intent evidence/,
  );
});

test('duplicate trailers are refused', () => {
  const root = repository([
    'a change\n\nKin-Release-Intent: minor\nKin-Release-Intent: major\n',
  ]);
  assert.throws(
    () => resolveReleaseIntent({ root, baseRef: 'v1.2.3' }),
    /duplicate Kin-Release-Intent trailers/,
  );
});

test('an unsupported intent is refused', () => {
  const root = repository(['a change\n\nKin-Release-Intent: enormous\n']);
  assert.throws(
    () => resolveReleaseIntent({ root, baseRef: 'v1.2.3' }),
    /invalid Kin-Release-Intent: enormous/,
  );
});

test('a base that is not an ancestor is refused', () => {
  const root = repository(['a change']);
  git(root, ['checkout', '--quiet', '-b', 'other', 'v1.2.3']);
  git(root, ['commit', '--allow-empty', '--quiet', '-m', 'divergent']);
  assert.throws(
    () => resolveReleaseIntent({ root, baseRef: 'main', headRef: 'other' }),
    /main is not an ancestor of other/,
  );
});

test('only first-parent history is evidence', () => {
  const root = repository(['mainline change']);
  git(root, ['checkout', '--quiet', '-b', 'side', 'v1.2.3']);
  git(root, ['commit', '--allow-empty', '--quiet', '-F', '-'], 'side work\n\nKin-Release-Intent: major\n');
  git(root, ['checkout', '--quiet', 'main']);
  git(root, ['merge', '--quiet', '--no-ff', '-m', 'merge side', 'side']);
  assert.equal(resolveReleaseIntent({ root, baseRef: 'v1.2.3' }).intent, 'patch');
});
