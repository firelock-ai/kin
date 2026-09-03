// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

import assert from 'node:assert/strict';
import fs from 'node:fs';
import { execFileSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { ALARM_TITLE, PENDING_MARKER } from './release-promotion-plan.mjs';
import {
  NO_OPEN_ISSUE,
  renderAlarm,
  renderPromotions,
  run,
  stripPendingNotice,
} from './read-promotion-plan.mjs';

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'kin-promotion-'));

const HELD_BODY = `${PENDING_MARKER}
> **First-contact proof pending.** This release cleared the machine preflight on its
> own bytes.

## What changed

- a real release note a human wrote
`;

test('renderPromotions emits one tab-separated line per release', () => {
  assert.equal(
    renderPromotions({ promote: [{ tag: 'v0.6.5', driver: 'local' }, { tag: 'v0.6.6' }] }),
    'v0.6.5\tlocal\nv0.6.6\tunrecorded',
  );
  assert.equal(renderPromotions({ promote: [] }), '');
  assert.equal(renderPromotions({}), '');
});

test('renderAlarm writes the body and returns the decision with its title', () => {
  const dir = tmp();
  const body = path.join(dir, 'alarm.md');
  const line = renderAlarm(
    { alarm: 'open', openIssue: null, overdue: [{ tag: 'v0.6.6', reason: 'pending', minutes: 400 }] },
    body,
  );
  const [action, number, title] = line.split('\t');
  assert.equal(action, 'open');
  // Never empty. Bash collapses runs of a tab set as IFS, so an empty field
  // here would shift the title into the number when the workflow reads this
  // line back and `gh issue create --title ""` would follow.
  assert.equal(number, NO_OPEN_ISSUE);
  assert.notEqual(number, '');
  // The title travels with the decision, because it is the only thing that
  // makes a later run comment on this issue instead of opening a second one.
  assert.equal(title, ALARM_TITLE);
  assert.match(fs.readFileSync(body, 'utf8'), /v0\.6\.6/);

  const quiet = path.join(dir, 'quiet.md');
  assert.equal(renderAlarm({ alarm: 'none', openIssue: null, overdue: [] }, quiet).split('\t')[0], 'none');
  assert.equal(fs.readFileSync(quiet, 'utf8'), '');
});

test('stripPendingNotice removes the block this chain wrote and nothing else', () => {
  const stripped = stripPendingNotice(HELD_BODY);
  assert.doesNotMatch(stripped, /First-contact proof pending/);
  assert.doesNotMatch(stripped, new RegExp(PENDING_MARKER.replace(/[-[\]{}()*+?.,\\^$|#]/g, '\\$&')));
  // The human's own notes survive. A strip that took the whole body would lose
  // the release notes, which is a worse failure than leaving the notice.
  assert.match(stripped, /a real release note a human wrote/);
  assert.match(stripped, /## What changed/);
});

test('stripPendingNotice leaves a body that never carried the notice alone', () => {
  const plain = '## What changed\n\n- nothing to do with proof\n';
  assert.equal(stripPendingNotice(plain), plain);
  assert.equal(stripPendingNotice(''), '');
});

// The property the "quote or blank" bound actually provides, stated as the
// only thing that can distinguish it: stripping the notice returns the body
// BYTE FOR BYTE, not merely a body with the notice text gone.
//
// This assertion replaced a weaker one. The first version checked that the
// notice text was absent and the author's own quoted line survived, and a
// mutant that stopped consuming the blank line separating the notice from the
// body passed it: the notice was still gone and the quote was still there, and
// only a stray leading newline separated the two answers. A round trip is the
// input only this clause can get right.
test('stripPendingNotice returns the original body byte for byte', () => {
  // Exactly the shape release.yml writes: the marker, the quoted block, one
  // blank line, then the release notes as they were.
  const notes = '## Notes\n\n> a quote the author wrote\n';
  const written = `${PENDING_MARKER}\n> **First-contact proof pending.** one\n> two\n\n${notes}`;
  assert.equal(stripPendingNotice(written), notes);
});

test('run refuses a command it does not know rather than doing nothing', async () => {
  await assert.rejects(run(['publish']), /unknown command "publish"/);
  await assert.rejects(run([]), /unknown command ""/);
  await assert.rejects(run(['alarm']), /needs --body/);
});

test('run reads the plan the workflow names in the environment', async () => {
  const dir = tmp();
  const plan = path.join(dir, 'plan.json');
  fs.writeFileSync(plan, JSON.stringify({ promote: [{ tag: 'v1.2.3', driver: 'account' }] }));
  const previous = process.env.KIN_PROMOTION_PLAN;
  process.env.KIN_PROMOTION_PLAN = plan;
  try {
    assert.equal(await run(['promotions']), 'v1.2.3\taccount\n');
  } finally {
    if (previous === undefined) delete process.env.KIN_PROMOTION_PLAN;
    else process.env.KIN_PROMOTION_PLAN = previous;
  }
});

// The read this line is written for, run for real. bash 3.2 and bash 5 both
// treat a tab set as IFS as whitespace and collapse runs of it, which is the
// defect the sentinel exists to prevent; this asserts the shipped line survives
// that read rather than asserting a property of the string in isolation.
test('the alarm line survives the shell read the workflow performs', () => {
  const dir = tmp();
  const body = path.join(dir, 'alarm.md');
  const line = renderAlarm({ alarm: 'open', openIssue: null, overdue: [] }, body);
  const script = path.join(dir, 'read.sh');
  fs.writeFileSync(script, "IFS=$'\\t' read -r action number title < \"$1\"\nprintf '%s|%s|%s' \"$action\" \"$number\" \"$title\"\n");
  const decision = path.join(dir, 'decision.txt');
  fs.writeFileSync(decision, `${line}\n`);
  const read = execFileSync('bash', [script, decision], { encoding: 'utf8' });
  assert.equal(read, `open|${NO_OPEN_ISSUE}|${ALARM_TITLE}`);
});

test('renderAlarm refuses to act on an issue the plan does not name', () => {
  const dir = tmp();
  for (const alarm of ['update', 'close']) {
    assert.throws(
      () => renderAlarm({ alarm, openIssue: null, overdue: [] }, path.join(dir, `${alarm}.md`)),
      /names none, so there is nothing to act on/,
    );
  }
});
