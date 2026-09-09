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

const malformed = 'change\n\nKin-Release-Intent: patch\n\n---------\n\nSigned-off-by: Test <test@example.invalid>\n';
function attested(root, changes = {}) {
  return { schema: 'kin.release-intent-attestations.v1', attestations: [{
    sha: git(root, ['rev-parse', 'HEAD']).trim(), intent: 'patch',
    reason: 'The recorded patch intent precedes the footer divider.', ...changes,
  }] };
}

test('an explicit full-SHA attestation resolves the divider case and records its reason', () => {
  const root = repository([malformed]);
  const attestations = attested(root);
  const result = resolveReleaseIntent({ root, baseRef: 'v1.2.3', attestations });
  assert.equal(result.intent, 'patch');
  assert.deepEqual(result.evidence, [{ commit: attestations.attestations[0].sha,
    intent: 'patch', source: 'attestation', reason: attestations.attestations[0].reason }]);
  assert.throws(() => resolveReleaseIntent({ root, baseRef: 'v1.2.3' }), /malformed or non-footer/);
});

test('a separately appended sign-off makes the earlier intent require attestation', () => {
  const footer = 'Kin-Release-Intent: patch\nSigned-off-by: Test <test@example.invalid>\n';
  const readable = repository(['change\n\n' + footer]);
  assert.equal(resolveReleaseIntent({ root: readable, baseRef: 'v1.2.3' }).evidence[0].intent, 'patch');
  const root = repository(['change\n\n' + footer + '\nSigned-off-by: Test <test@example.invalid>\n']);
  assert.throws(() => resolveReleaseIntent({ root, baseRef: 'v1.2.3' }), /malformed or non-footer/);
  const result = resolveReleaseIntent({ root, baseRef: 'v1.2.3', attestations: attested(root) });
  assert.equal(result.evidence[0].source, 'attestation');
  assert.equal(result.intent, 'patch');
});

test('attestations cannot replace readable, duplicate, invalid or absent intent', () => {
  for (const message of [
    'change\n\nKin-Release-Intent: major\n',
    'change\n\nKin-Release-Intent: patch\nKin-Release-Intent: minor\n',
    'change\n\nKin-Release-Intent: enormous\n',
    'change without any intent mention',
    'Kin-Release-Intent: patch in prose\n\nbody\n\nKin-Release-Intent: major\n',
  ]) {
    const root = repository([message]);
    assert.throws(() => resolveReleaseIntent({ root, baseRef: 'v1.2.3',
      attestations: attested(root) }), /attestation requires unreadable trailer evidence/);
  }
});

test('attestation schema, full SHA, intent, reason and uniqueness are required', () => {
  const root = repository([malformed]);
  for (const change of [{ sha: 'bffd6adda' }, { sha: 'x'.repeat(40) },
    { intent: 'enormous' }, { reason: '' }, { reason: '   ' }]) {
    assert.throws(() => resolveReleaseIntent({ root, baseRef: 'v1.2.3',
      attestations: attested(root, change) }), /attestation requires/);
  }
  const document = attested(root);
  document.attestations.push(document.attestations[0]);
  assert.throws(() => resolveReleaseIntent({ root, baseRef: 'v1.2.3', attestations: document }), /duplicate attestation/);
  assert.throws(() => resolveReleaseIntent({ root, baseRef: 'v1.2.3', attestations: {} }), /invalid release intent attestation document/);
});

test('an attestation for another commit does not repair unreadable evidence', () => {
  const root = repository([malformed]);
  assert.throws(() => resolveReleaseIntent({ root, baseRef: 'v1.2.3',
    attestations: attested(root, { sha: 'a'.repeat(40) }) }), /malformed or non-footer/);
});

test('a repaired patch does not lower a readable major in the same range', () => {
  const root = repository([malformed]);
  const attestations = attested(root);
  git(root, ['commit', '--allow-empty', '--quiet', '-F', '-'], 'change\n\nKin-Release-Intent: major\n');
  assert.equal(resolveReleaseIntent({ root, baseRef: 'v1.2.3', attestations }).intent, 'major');
});

test('the committed historical attestation binds only the recorded full SHA', () => {
  const document = JSON.parse(fs.readFileSync(new URL('./release-intent-attestations.json', import.meta.url), 'utf8'));
  assert.equal(document.schema, 'kin.release-intent-attestations.v1');
  for (const expected of [
    'bffd6adda2eb46a37d0481a8b1aba8ef8759ce54',
    '72414aa80531e7adee1ab360eacb28d56a621c6a',
    '9e45cc6c89b12c72e519c86517ac38a8a79a7cea',
    'c67efaa2c737ab0b7ac15d0057c8a3ec5a8041cc',
    '1b11fda4c870245f2575363adcf1031699580969',
    '8525c7751716b1c5304cd2d62da1aa8235e2e077',
    '48bafa7911ccde08f64c14a002a8a991ffefd7a2',
  ]) {
    const entry = document.attestations.find(({ sha }) => sha === expected);
    assert.equal(entry?.intent, 'patch', expected);
    assert.match(entry.reason, /FIR-3412/);
  }
});

test('attestation cannot invent, change or disambiguate malformed raw intent', () => {
  for (const message of [
    malformed.replace('Intent: patch', 'Intent: enormous'),
    malformed.replace('Intent: patch', 'Intent: major'),
    malformed.replace('Intent: patch', 'Intent: patch\nKin-Release-Intent: minor'),
    malformed.replace('Intent: patch', 'Intent: patch\nKin-Release-Intent: patch'),
    malformed.replace('Intent: patch', 'Intent patch'),
  ]) {
    const root = repository([message]);
    assert.throws(() => resolveReleaseIntent({ root, baseRef: 'v1.2.3', attestations: attested(root) }),
      /attestation requires one explicit valid intent/);
  }
});
