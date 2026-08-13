// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import {
  CapabilityProofError,
  REQUIRED_CHECK_IDS,
  assertReadinessCoherent,
  coverageRegime,
  validateHealthReport,
  verifyReport,
} from './verify-capability-proof.mjs';

const SCRIPT = fileURLToPath(new URL('./verify-capability-proof.mjs', import.meta.url));

function report({ readiness = 'healthy', overrides = {}, healthy = null } = {}) {
  const checks = REQUIRED_CHECK_IDS.map((id) => ({
    id,
    label: id,
    status: id === 'semantic_query_readiness' ? readiness : 'healthy',
    detail: '',
    ...(overrides[id] ?? {}),
  }));
  const blocking = checks.some(
    (check) =>
      check.status === 'missing' ||
      check.status === 'misconfigured' ||
      (check.id === 'semantic_query_readiness' && check.status === 'stale'),
  );
  return { healthy: healthy === null ? !blocking : healthy, checks };
}

const settled = { state: 'observed', source: 'live_query_graph', indexed: 18, pending: 0, total: 18 };
const working = { state: 'observed', source: 'live_query_graph', indexed: 4, pending: 14, total: 18 };
const nothing = { state: 'observed', source: 'live_query_graph', indexed: 0, pending: 0, total: 0 };
const unobserved = { state: 'unobserved', reason: 'graph_mutation_in_flight' };

function expectFailure(fn, pattern) {
  assert.throws(fn, (error) => {
    assert.ok(error instanceof CapabilityProofError, `wrong error type: ${error}`);
    assert.match(error.message, pattern);
    return true;
  });
}

test('a settled store with healthy readiness satisfies the contract', () => {
  const { readiness } = verifyReport(report(), settled, 'kin-health.json');
  assert.equal(readiness, 'healthy');
});

// The v0.5.18 fence, reproduced. This is the assertion the whole canary exists
// for: it fails on main's branch build instead of at tag time on a tag nothing
// can repair.
test('readiness pending on a settled store fails, which is the v0.5.18 fence', () => {
  expectFailure(
    () => verifyReport(report({ readiness: 'pending' }), settled, 'kin-embedded-health.json'),
    /pending on a settled store/,
  );
});

test('readiness pending against a store with nothing to embed fails', () => {
  expectFailure(
    () => verifyReport(report({ readiness: 'pending' }), nothing, 'kin-health.json'),
    /no amount of waiting resolves it/,
  );
});

test('unsupported against a store with nothing to embed is the honest answer', () => {
  const { readiness } = verifyReport(report({ readiness: 'unsupported' }), nothing, 'kin-health.json');
  assert.equal(readiness, 'unsupported');
});

test('pending while a first pass is genuinely filling is correct and passes', () => {
  const { readiness } = verifyReport(report({ readiness: 'pending' }), working, 'kin-health.json');
  assert.equal(readiness, 'pending');
});

test('an unobserved coverage window concludes nothing about readiness', () => {
  for (const readiness of ['pending', 'healthy', 'unsupported']) {
    const { checks } = { checks: validateHealthReport(report({ readiness }), 'p') };
    assert.equal(assertReadinessCoherent(checks, unobserved, 'p'), readiness);
  }
});

test('an aggregate that disagrees with its own checks fails', () => {
  const lying = report({ overrides: { repo_init: { status: 'missing' } }, healthy: true });
  expectFailure(
    () => verifyReport(lying, settled, 'kin-health.json'),
    /aggregate healthy=true disagrees with checks/,
  );
});

test('a stale readiness must drag the aggregate unhealthy, exactly as the proof requires', () => {
  const honest = report({ readiness: 'stale' });
  assert.equal(honest.healthy, false);
  expectFailure(
    () => verifyReport(report({ readiness: 'stale', healthy: true }), settled, 'p'),
    /disagrees with checks/,
  );
});

test('a renamed or removed check id fails before a tag exists', () => {
  const renamed = report();
  renamed.checks = renamed.checks.map((check) =>
    check.id === 'semantic_query_readiness'
      ? { ...check, id: 'semantic_query_state' }
      : check,
  );
  expectFailure(
    () => verifyReport(renamed, settled, 'kin-health.json'),
    /requires health checks this build does not report: semantic_query_readiness/,
  );
});

test('a status outside the build vocabulary is a rename, not a new state', () => {
  expectFailure(
    () => verifyReport(report({ readiness: 'ready' }), settled, 'p'),
    /not a status this build's health vocabulary defines/,
  );
});

test('duplicate check ids are refused rather than silently deduplicated', () => {
  const duplicated = report();
  duplicated.checks.push({ ...duplicated.checks[0] });
  expectFailure(() => verifyReport(duplicated, settled, 'p'), /duplicate health-check ids/);
});

test('a hard failure fails even when the aggregate honestly agrees', () => {
  const broken = report({ overrides: { setup_ledger: { status: 'misconfigured' } } });
  assert.equal(broken.healthy, false);
  expectFailure(() => verifyReport(broken, settled, 'p'), /hard failures: setup_ledger/);
});

test('a malformed report is refused rather than read as empty', () => {
  expectFailure(() => verifyReport({}, settled, 'p'), /checks is missing or malformed/);
  expectFailure(() => verifyReport(null, settled, 'p'), /checks is missing or malformed/);
});

test('an unreadable coverage is refused rather than treated as an empty store', () => {
  expectFailure(() => verifyReport(report(), undefined, 'p'), /carries no state/);
  expectFailure(
    () => verifyReport(report(), { state: 'observed', source: 'live_query_graph' }, 'p'),
    /carries no whole total/,
  );
});

test('the command line passes a good capture and fails the fence capture', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kin-capability-'));
  const statusPath = path.join(dir, 'kin-status.json');
  const goodPath = path.join(dir, 'good-health.json');
  const fencePath = path.join(dir, 'fence-health.json');
  fs.writeFileSync(statusPath, JSON.stringify({ embedding_coverage: settled }));
  fs.writeFileSync(goodPath, JSON.stringify(report()));
  fs.writeFileSync(fencePath, JSON.stringify(report({ readiness: 'pending' })));

  const passed = execFileSync(
    'node',
    [SCRIPT, '--status', statusPath, '--report', goodPath],
    { encoding: 'utf8' },
  );
  assert.match(passed, /capability contract holds/);

  assert.throws(
    () => execFileSync('node', [SCRIPT, '--status', statusPath, '--report', fencePath], { stdio: 'pipe' }),
    (error) => {
      assert.match(error.stderr.toString(), /pending on a settled store/);
      assert.equal(error.status, 1);
      return true;
    },
  );
});

test('the command line refuses to run with nothing to check', () => {
  assert.throws(() => execFileSync('node', [SCRIPT], { stdio: 'pipe' }));
});

test('the regimes are named from the coverage the daemon actually publishes', () => {
  assert.equal(coverageRegime(settled), 'settled');
  assert.equal(coverageRegime(working), 'working');
  assert.equal(coverageRegime(nothing), 'nothing-to-embed');
  assert.equal(coverageRegime(unobserved), 'unobserved');
  assert.equal(coverageRegime(undefined), 'unobserved');
});

// The canary's own anti-vacuity guard. A run whose coverage never became
// observable judged readiness against nothing, and a pass there would be a check
// that cannot fail rather than evidence that anything works.
test('require-observed refuses a run that proved nothing', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kin-capability-vacuous-'));
  const statusPath = path.join(dir, 'kin-status.json');
  const reportPath = path.join(dir, 'health.json');
  fs.writeFileSync(statusPath, JSON.stringify({ embedding_coverage: unobserved }));
  fs.writeFileSync(reportPath, JSON.stringify(report({ readiness: 'pending' })));

  const tolerated = execFileSync('node', [SCRIPT, '--status', statusPath, '--report', reportPath], {
    encoding: 'utf8',
  });
  assert.match(tolerated, /unobserved regime/);

  assert.throws(
    () =>
      execFileSync(
        'node',
        [SCRIPT, '--status', statusPath, '--report', reportPath, '--require-observed'],
        { stdio: 'pipe' },
      ),
    (error) => {
      assert.match(error.stderr.toString(), /judged readiness against nothing/);
      return true;
    },
  );
});
