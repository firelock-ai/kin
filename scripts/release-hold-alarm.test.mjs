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
  ALARM_TITLE,
  DEFAULT_THRESHOLD,
  MARKER_SCHEMA,
  decide,
} from './release-hold-alarm.mjs';

const SCRIPT = fileURLToPath(new URL('./release-hold-alarm.mjs', import.meta.url));

function held({ drift = 9, blocking = 'v0.5.18', latest = 'v0.5.17' } = {}) {
  return {
    schema: MARKER_SCHEMA,
    state: 'held',
    reason: 'tag_not_finalized',
    detail: `highest tag ${blocking} is not finalized GitHub Latest ${latest}`,
    blocking_tag: blocking,
    latest_tag: latest,
    base_tag: blocking,
    drift,
    run_id: '31727271358',
    run_url: 'https://github.com/firelock-ai/kin/actions/runs/31727271358',
    main_sha: '6eae51d0000000000000000000000000000000ab',
    failed_release_run_id: '31478318322',
    failed_release_run_url: 'https://github.com/firelock-ai/kin/actions/runs/31478318322',
    observed_at: '2026-08-12T09:00:00Z',
  };
}

function clear() {
  return {
    schema: MARKER_SCHEMA,
    state: 'clear',
    reason: '',
    detail: 'release drift resolved, train proceeding',
    drift: 3,
    run_id: '31727271359',
    observed_at: '2026-08-12T09:15:00Z',
  };
}

const OPEN_ISSUE = { number: 4242, title: ALARM_TITLE };

test('a hold with drift below the threshold stays quiet', () => {
  const markers = [held(), held(), held()];
  const decision = decide({ markers, issue: null });
  assert.equal(decision.action, 'quiet');
  assert.equal(decision.reason, 'below_threshold');
  assert.equal(decision.consecutive, 3);
});

test('a hold with drift at the threshold opens exactly one issue', () => {
  const markers = [held(), held(), held(), held()];
  const decision = decide({ markers, issue: null });
  assert.equal(decision.action, 'open');
  assert.equal(decision.title, ALARM_TITLE);
  assert.equal(decision.consecutive, DEFAULT_THRESHOLD);
  assert.match(decision.body, /Blocking tag: `v0\.5\.18`/);
  assert.match(decision.body, /9 commits beyond/);
  assert.match(decision.body, /31478318322/);
});

test('a persisting hold updates the issue it already opened instead of opening a second', () => {
  const markers = [held(), held(), held(), held(), held(), held()];
  const decision = decide({ markers, issue: OPEN_ISSUE });
  assert.equal(decision.action, 'update');
  assert.equal(decision.issue, 4242);
  assert.equal(decision.title, ALARM_TITLE);
});

test('the title carries no tag and no count, so it never forks into a second issue', () => {
  const four = [held(), held(), held(), held()];
  const opened = decide({ markers: four, issue: null });
  const later = decide({
    markers: [held({ drift: 31, blocking: 'v0.6.4' }), ...four],
    issue: OPEN_ISSUE,
  });
  assert.equal(opened.title, later.title);
  assert.doesNotMatch(opened.title, /v0\.5\.18|[0-9]/);
});

test('a mint closes the issue on the train own all-clear', () => {
  const decision = decide({ markers: [clear(), held(), held(), held(), held()], issue: OPEN_ISSUE });
  assert.equal(decision.action, 'close');
  assert.equal(decision.issue, 4242);
  assert.match(decision.comment, /minting again/);
});

test('a healthy rail with no open issue says nothing at all', () => {
  const decision = decide({ markers: [clear(), clear()], issue: null });
  assert.equal(decision.action, 'quiet');
  assert.equal(decision.reason, 'rail_healthy');
});

test('a hold with zero drift stays quiet however long it lasts', () => {
  const idle = { ...held(), drift: 0 };
  const decision = decide({ markers: [idle, idle, idle, idle, idle, idle], issue: null });
  assert.equal(decision.action, 'quiet');
  assert.equal(decision.reason, 'held_without_drift');
});

test('one clear cycle inside the window breaks the streak', () => {
  const markers = [held(), held(), clear(), held(), held()];
  const decision = decide({ markers, issue: null });
  assert.equal(decision.action, 'quiet');
  assert.equal(decision.consecutive, 2);
});

test('an unreadable newest marker neither opens an alarm nor closes one', () => {
  const unreadable = { unreadable: true, run_id: '1' };
  const withoutIssue = decide({ markers: [unreadable, held(), held(), held(), held()], issue: null });
  assert.equal(withoutIssue.action, 'quiet');
  assert.equal(withoutIssue.reason, 'newest_marker_unreadable');
  const withIssue = decide({ markers: [unreadable, held(), held(), held(), held()], issue: OPEN_ISSUE });
  assert.equal(withIssue.action, 'quiet');
  assert.equal(withIssue.reason, 'newest_marker_unreadable');
});

test('an unreadable marker inside the window breaks the streak rather than counting as a hold', () => {
  const markers = [held(), held(), { unreadable: true }, held(), held()];
  const decision = decide({ markers, issue: null });
  assert.equal(decision.action, 'quiet');
  assert.equal(decision.consecutive, 2);
});

test('an empty history is unknown, not healthy', () => {
  const decision = decide({ markers: [], issue: OPEN_ISSUE });
  assert.equal(decision.action, 'quiet');
  assert.equal(decision.reason, 'newest_marker_unreadable');
});

test('a marker from a schema this reader does not know is unreadable, not held', () => {
  const future = { ...held(), schema: 'kin.release-hold.v2' };
  const decision = decide({ markers: [future, held(), held(), held(), held()], issue: null });
  assert.equal(decision.reason, 'newest_marker_unreadable');
});

test('a held marker whose drift is not a whole count is unreadable rather than zero', () => {
  for (const drift of [null, undefined, 'nine', -1, 1.5]) {
    const decision = decide({ markers: [{ ...held(), drift }], issue: null });
    assert.equal(decision.reason, 'newest_marker_unreadable', `drift=${String(drift)}`);
  }
});

test('an absent failed Release run is reported as absent rather than invented', () => {
  const marker = { ...held(), failed_release_run_id: null, failed_release_run_url: null };
  const decision = decide({ markers: [marker, marker, marker, marker], issue: null });
  assert.equal(decision.action, 'open');
  assert.match(decision.body, /No failed Release run was found/);
  assert.doesNotMatch(decision.body, /null/);
});

test('the threshold is configurable and honoured', () => {
  const markers = [held(), held()];
  assert.equal(decide({ markers, issue: null, threshold: 2 }).action, 'open');
  assert.equal(decide({ markers, issue: null, threshold: 3 }).action, 'quiet');
});

test('the body names both exits and never uses an em dash', () => {
  const markers = [held(), held(), held(), held()];
  const { body } = decide({ markers, issue: null });
  assert.match(body, /abandoned-release-tags\.json/);
  assert.match(body, /Release Recovery retry the tag/);
  assert.doesNotMatch(body, /—/);
});

test('the command line agrees with the exported decision', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kin-release-hold-'));
  const markersPath = path.join(dir, 'markers.json');
  const issuePath = path.join(dir, 'issue.json');
  const markers = [held(), held(), held(), held()];
  fs.writeFileSync(markersPath, JSON.stringify(markers));
  fs.writeFileSync(issuePath, JSON.stringify(OPEN_ISSUE));

  const opened = JSON.parse(
    execFileSync('node', [SCRIPT, '--markers', markersPath, '--issue', 'none'], { encoding: 'utf8' }),
  );
  assert.equal(opened.action, 'open');

  const updated = JSON.parse(
    execFileSync('node', [SCRIPT, '--markers', markersPath, '--issue', issuePath], { encoding: 'utf8' }),
  );
  assert.equal(updated.action, 'update');
  assert.equal(updated.issue, 4242);
});

test('the command line refuses a threshold it cannot honour', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kin-release-hold-'));
  const markersPath = path.join(dir, 'markers.json');
  fs.writeFileSync(markersPath, JSON.stringify([held()]));
  assert.throws(() =>
    execFileSync('node', [SCRIPT, '--markers', markersPath, '--threshold', '0'], { stdio: 'pipe' }),
  );
});
