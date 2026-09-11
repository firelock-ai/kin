// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { execFileSync, spawnSync } from 'node:child_process';
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

// A hold whose blocking tag does not exist. The train writes `tag_staged` only
// after fetching every tag and failing to resolve this one, so the reason code
// is the whole discriminator and no other field has to be consulted.
function staged({ drift = 7, blocking = 'v0.7.3', latest = 'v0.7.2' } = {}) {
  return {
    ...held({ drift, blocking, latest }),
    reason: 'tag_staged',
    detail: `${blocking} is already staged on main; tag reconciliation owns the next transition`,
    base_tag: latest,
    failed_release_run_id: null,
    failed_release_run_url: null,
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

test('a tag that was never cut says so, and points at the publisher rather than at two exits that need a tag', () => {
  const markers = [staged(), staged(), staged(), staged()];
  const { body } = decide({ markers, issue: null });
  assert.match(body, /`v0\.7\.3` was never cut/);
  assert.match(body, /release-cut\.yml --jq \.state/);
  assert.match(body, /evidence\/<sha>\/preflight\.json/);
  // The sentence that sent a reader down two dead ends. Its absence is the
  // whole behaviour, so it is asserted rather than left to the eye.
  assert.doesNotMatch(body, /There are two ways out/);
  assert.doesNotMatch(body, /Release Recovery retry the tag/);
  assert.doesNotMatch(body, /—/);
});

test('a tag that exists still gets both original exits, so the staged branch cannot swallow the body everyone reads', () => {
  const markers = [held(), held(), held(), held()];
  const { body } = decide({ markers, issue: null });
  assert.match(body, /There are two ways out/);
  assert.match(body, /Release Recovery retry the tag/);
  assert.match(body, /abandoned-release-tags\.json/);
  assert.doesNotMatch(body, /was never cut/);
  assert.doesNotMatch(body, /release-cut\.yml/);
});

test('an existing tag whose failed Release run could not be found is not mistaken for a tag that was never cut', () => {
  // The trap this guards. A `tag_not_finalized` marker can also carry a null
  // failed run id, because the train's lookup is allowed to come back empty.
  // Keying the branch on that null instead of on the reason code would hand
  // this marker the staged body and tell a captain a real tag does not exist.
  const marker = { ...held(), failed_release_run_id: null, failed_release_run_url: null };
  const { body } = decide({ markers: [marker, marker, marker, marker], issue: null });
  assert.match(body, /No failed Release run was found/);
  assert.doesNotMatch(body, /was never cut/);
  assert.doesNotMatch(body, /release-cut\.yml/);
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

function finalOutcomeScript() {
  const workflow = fs.readFileSync(new URL('../.github/workflows/release-train.yml', import.meta.url), 'utf8');
  const section = workflow.split("      - name: Record this cycle's final outcome\n")[1]?.split("      # Uploaded on every path")[0];
  assert.ok(section, 'the final outcome step must exist');
  assert.match(section, /id: report/);
  assert.match(section, /if: always\(\)/);
  assert.match(section, /RECONCILE_STATUS: \$\{\{ job.status \}\}/);
  assert.match(workflow, /marker: \$\{\{ steps.report.outputs.marker \}\}/);
  assert.match(workflow, /CURRENT_MARKER: \$\{\{ needs.reconcile.outputs.marker \}\}/);
  return section.split('        run: |\n')[1].split('\n').map(line => line.replace(/^          /, '')).join('\n');
}

for (const previous of [null, clear(), held()]) {
  test(`a nonzero step produces an actionable final marker after ${previous?.state ?? 'no marker'}`, () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kin-release-outcome-'));
    try {
      const markerPath = path.join(root, 'release-hold-marker.json');
      if (previous) fs.writeFileSync(markerPath, JSON.stringify(previous));
      const failed = spawnSync('bash', ['-c', 'set -e; exit 4']);
      assert.equal(failed.status, 4);
      const output = path.join(root, 'output');
      const outcome = spawnSync('bash', ['-c', finalOutcomeScript()], { encoding: 'utf8', env: {
        ...process.env, RUNNER_TEMP: root, GITHUB_OUTPUT: output,
        RECONCILE_STATUS: failed.status === 0 ? 'success' : 'failure',
        REPO: 'firelock-ai/kin', GITHUB_RUN_ID: '123', GITHUB_SERVER_URL: 'https://github.com',
      } });
      assert.equal(outcome.status, 0, outcome.stderr);
      const marker = JSON.parse(fs.readFileSync(markerPath, 'utf8'));
      assert.equal(marker.state, 'failed');
      assert.equal(marker.drift, null);
      assert.match(fs.readFileSync(output, 'utf8'), /"state":"failed"/);
      const decision = decide({ markers: [marker], issue: null });
      assert.equal(decision.action, 'open');
      assert.equal(decision.reason, 'reconcile_failed');
      assert.match(decision.body, /actions\/runs\/123/);
      assert.doesNotMatch(decision.body, /runs concluded success/);
      const existing = decide({ markers: [marker], issue: OPEN_ISSUE });
      assert.equal(existing.action, 'update');
      assert.equal(existing.issue, OPEN_ISSUE.number);
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
  });
}

test('a successful final outcome preserves the observed marker', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kin-release-outcome-'));
  try {
    const marker = clear();
    fs.writeFileSync(path.join(root, 'release-hold-marker.json'), JSON.stringify(marker));
    execFileSync('bash', ['-c', finalOutcomeScript()], { env: {
      ...process.env, RUNNER_TEMP: root, GITHUB_OUTPUT: path.join(root, 'output'), RECONCILE_STATUS: 'success',
    } });
    assert.deepEqual(JSON.parse(fs.readFileSync(path.join(root, 'release-hold-marker.json'), 'utf8')), marker);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('the workflow opens and updates crash alarms with a loud accurate diagnostic', () => {
  const workflow = fs.readFileSync(new URL('../.github/workflows/release-train.yml', import.meta.url), 'utf8');
  const arm = workflow.split('          case "$action" in\n')[1]?.split('          esac')[0];
  assert.ok(arm, 'alarm dispatch case must exist');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kin-release-alarm-'));
  try {
    const marker = { schema: MARKER_SCHEMA, state: 'failed', reason: 'reconcile_failed', run_id: '123', drift: null };
    for (const issue of [null, OPEN_ISSUE]) {
      const decision = decide({ markers: [marker], issue });
      const filename = path.join(root, 'decision.json');
      fs.writeFileSync(filename, JSON.stringify(decision));
      const script = 'set -euo pipefail\ngh() { printf "%s\\n" "$*" >> "$work/gh-calls"; }\n' +
        'case "$action" in\n' + arm + '\nesac\n';
      const result = spawnSync('bash', ['-c', script], { encoding: 'utf8', env: {
        ...process.env, work: root, decision: filename, action: decision.action, reason: decision.reason,
        REPO: 'firelock-ai/kin', title: ALARM_TITLE,
      } });
      assert.equal(result.status, 1, result.stdout + result.stderr);
      assert.equal(result.stderr, '');
      assert.match(result.stdout, /::error::Release rail.*reconcile_failed/);
      assert.doesNotMatch(result.stdout, /consecutive cycles|blocking tag|two ways out/);
      assert.match(fs.readFileSync(path.join(root, 'gh-calls'), 'utf8'), issue ? /issue edit 4242/ : /issue create/);
    }
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('the alarm job result overrides missing or stale markers after finalizer or upload failure', () => {
  const workflow = fs.readFileSync(new URL('../.github/workflows/release-train.yml', import.meta.url), 'utf8');
  const section = workflow.split('      - name: Gather this cycle')[1]?.split('          prior_ids=')[0];
  assert.ok(section, 'alarm history step must exist');
  assert.match(section, /RECONCILE_RESULT: \$\{\{ needs.reconcile.result \}\}/);
  const script = section.split('        run: |\n')[1].split('\n').map(line => line.replace(/^          /, '')).join('\n');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kin-release-result-'));
  try {
    for (const result of ['failure', 'cancelled', 'success']) {
      for (const previous of ['', JSON.stringify(clear())]) {
        execFileSync('bash', ['-c', script], { env: {
          ...process.env, RUNNER_TEMP: root, RECONCILE_RESULT: result, CURRENT_MARKER: previous,
          GITHUB_RUN_ID: '123', GITHUB_SERVER_URL: 'https://github.com', REPO: 'firelock-ai/kin',
        } });
        const marker = JSON.parse(fs.readFileSync(path.join(root, 'release-hold-history/current.json'), 'utf8'));
        if (result === 'success') {
          assert.equal(marker.state ?? 'unreadable', previous ? 'clear' : 'unreadable');
        } else {
          assert.equal(marker.state, 'failed');
          assert.equal(decide({ markers: [marker], issue: OPEN_ISSUE }).action, 'update');
        }
      }
    }
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

// The v0.7.15 release, replayed from the markers the train actually wrote.
// Measured from each run's own `release-hold-marker` artifact: the bump merged
// at 21:32:11Z and these four staged markers were observed between 21:43:36Z
// and 21:53:09Z, 9m33s end to end, because every one of those cycles was a
// `workflow_run` firing on a completed CI run somewhere in the fleet. The cut
// had not chosen a candidate yet, and its candidate build alone takes about
// fifty minutes. The fourth of them opened kin#1750.
function stagedV0715({ drift, runId, observedAt, mainSha }) {
  return {
    ...staged({ drift, blocking: 'v0.7.15', latest: 'v0.7.13' }),
    detail: 'v0.7.15 is already staged on main; tag reconciliation owns the next transition',
    run_id: runId,
    run_url: `https://github.com/firelock-ai/kin/actions/runs/${runId}`,
    main_sha: mainSha,
    observed_at: observedAt,
  };
}

const V0715_STAGED_SEQUENCE = [
  stagedV0715({ drift: 44, runId: '34651465000', observedAt: '2026-09-11T21:53:09Z', mainSha: '42f0a1e0e00000000000000000000000000000ab' }),
  stagedV0715({ drift: 44, runId: '34651353446', observedAt: '2026-09-11T21:52:03Z', mainSha: '42f0a1e0e00000000000000000000000000000ab' }),
  stagedV0715({ drift: 44, runId: '34651339407', observedAt: '2026-09-11T21:51:28Z', mainSha: '42f0a1e0e00000000000000000000000000000ab' }),
  stagedV0715({ drift: 43, runId: '34650711251', observedAt: '2026-09-11T21:43:36Z', mainSha: '27a542c7600000000000000000000000000000ab' }),
];

test('the v0.7.15 staged wait stays quiet while the cut is switched on', () => {
  const decision = decide({ markers: V0715_STAGED_SEQUENCE, issue: null, cutState: 'active' });
  assert.equal(decision.action, 'quiet');
  assert.equal(decision.reason, 'staged_in_progress');
});

test('the same sequence opened an issue before the cut state was consulted', () => {
  // The falsification: today's counting, which is what an omitted cut state
  // still reproduces exactly, reaches the threshold on this very sequence.
  const decision = decide({ markers: V0715_STAGED_SEQUENCE, issue: null });
  assert.equal(decision.action, 'open');
  assert.equal(decision.reason, 'hold_established');
  assert.equal(decision.consecutive, DEFAULT_THRESHOLD);
});

test('a staged hold still alarms when the cut is switched off', () => {
  // 2026-09-07: the staged tag was never going to be minted because
  // release-cut.yml was disabled, and the alarm was right to ring.
  for (const cutState of ['disabled_manually', 'disabled_inactivity', 'unreadable', null]) {
    const decision = decide({ markers: V0715_STAGED_SEQUENCE, issue: null, cutState });
    assert.equal(decision.action, 'open', `cut state ${cutState} must still alarm`);
    assert.equal(decision.reason, 'hold_established');
  }
});

test('an active cut does not quiet a hold that is not staged', () => {
  const markers = [held(), held(), held(), held()];
  const decision = decide({ markers, issue: null, cutState: 'active' });
  assert.equal(decision.action, 'open');
  assert.equal(decision.reason, 'hold_established');
  assert.equal(decision.consecutive, DEFAULT_THRESHOLD);
});

test('a staged cycle breaks a streak of declined mints rather than extending it', () => {
  const markers = [V0715_STAGED_SEQUENCE[0], held(), held(), held(), held()];
  const decision = decide({ markers, issue: null, cutState: 'active' });
  assert.equal(decision.action, 'quiet');
  assert.equal(decision.reason, 'staged_in_progress');
});

test('a staged hold leaves an open alarm exactly where it is', () => {
  // Only the train's own all-clear closes one. A staged hold is not an
  // all-clear, so it neither closes nor updates.
  const decision = decide({ markers: V0715_STAGED_SEQUENCE, issue: OPEN_ISSUE, cutState: 'active' });
  assert.equal(decision.action, 'quiet');
  assert.equal(decision.reason, 'staged_in_progress');
});
