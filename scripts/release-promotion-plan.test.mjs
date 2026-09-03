// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  ALARM_TITLE,
  DEFAULT_ALARM_AFTER_MINUTES,
  PENDING_MARKER,
  buildBody,
  buildPlan,
  main,
  planPromotion,
  resolveTagCommit,
  selectCandidates,
} from './release-promotion-plan.mjs';

const NOW = Date.parse('2026-09-03T00:00:00Z');
const ago = (minutes) => new Date(NOW - minutes * 60000).toISOString();

const release = (over = {}) => ({
  tag_name: 'v0.6.5',
  draft: false,
  prerelease: true,
  published_at: ago(10),
  body: `${PENDING_MARKER}\n> first-contact proof pending`,
  ...over,
});

test('selectCandidates takes exactly the shape this design creates', () => {
  const picked = selectCandidates([
    release(),
    // Already Latest. Nothing to do, and promoting it again would be a no-op
    // that still rewrites its body.
    release({ tag_name: 'v0.6.4', prerelease: false }),
    // A draft is not published, so it is not a claim yet.
    release({ tag_name: 'v0.6.6', draft: true }),
    // A prerelease TAG is meant to stay a prerelease. Promoting one would be
    // the bug this promoter could introduce, not the gap it closes.
    release({ tag_name: 'v0.6.7-rc.1' }),
    // Not a version tag at all.
    release({ tag_name: 'nightly' }),
  ]);
  assert.deepEqual(picked.map((entry) => entry.tag), ['v0.6.5']);
  assert.equal(picked[0].held, true);
});

test('selectCandidates refuses a listing it cannot read rather than returning nothing', () => {
  // An empty array and an unreadable answer are different findings. Returning
  // [] for the second would report "nothing to promote" on a broken read,
  // which is the check-that-cannot-fail shape.
  assert.throws(() => selectCandidates(null), /did not come back as an array/);
  assert.throws(() => selectCandidates({ releases: [] }), /did not come back as an array/);
  assert.deepEqual(selectCandidates([]), []);
});

test('selectCandidates marks a stable prerelease this design did not hold', () => {
  const [entry] = selectCandidates([release({ body: 'hand-marked for another reason' })]);
  assert.equal(entry.held, false);
});

test('planPromotion promotes only a proven release this design held', () => {
  const plan = planPromotion(
    [
      { tag: 'v0.6.5', held: true, proven: true, driver: 'local', publishedAt: ago(10) },
      { tag: 'v0.6.6', held: true, proven: false, reason: 'stranger.env does not exist', publishedAt: ago(10) },
      { tag: 'v0.6.7', held: false, proven: true, publishedAt: ago(10) },
    ],
    { now: NOW },
  );
  assert.deepEqual(plan.promote, [{ tag: 'v0.6.5', driver: 'local' }]);
  assert.deepEqual(plan.waiting.map((e) => e.tag), ['v0.6.6']);
  // Proven, but not held by this design. The promoter finishes what the release
  // chain started; it never overrules a person who marked a release by hand.
  assert.deepEqual(plan.foreign.map((e) => e.tag), ['v0.6.7']);
});

test('planPromotion refuses a judgement that names no tag', () => {
  assert.throws(() => planPromotion([{ held: true, proven: true }]), /names no tag/);
  assert.throws(() => planPromotion([null]), /names no tag/);
});

test('planPromotion alarms only after the threshold, and only on a real wait', () => {
  const fresh = planPromotion(
    [{ tag: 'v0.6.6', held: true, proven: false, reason: 'pending', publishedAt: ago(5) }],
    { now: NOW },
  );
  assert.equal(fresh.alarm, 'none');
  assert.deepEqual(fresh.overdue, []);

  const old = planPromotion(
    [{ tag: 'v0.6.6', held: true, proven: false, reason: 'pending', publishedAt: ago(DEFAULT_ALARM_AFTER_MINUTES + 1) }],
    { now: NOW },
  );
  assert.equal(old.alarm, 'open');
  assert.deepEqual(old.overdue.map((e) => e.tag), ['v0.6.6']);

  const already = planPromotion(
    [{ tag: 'v0.6.6', held: true, proven: false, reason: 'pending', publishedAt: ago(DEFAULT_ALARM_AFTER_MINUTES + 1) }],
    { now: NOW, openIssue: { number: 7 } },
  );
  assert.equal(already.alarm, 'update');
});

// An unreadable publication time must not buy silence. This is the direction
// the check could have failed safe-looking and been wrong: treating "no
// timestamp" as "just published" hides a release that has waited for days.
test('planPromotion treats an unreadable publication time as overdue', () => {
  for (const publishedAt of [null, '', 'not-a-date']) {
    const plan = planPromotion(
      [{ tag: 'v0.6.6', held: true, proven: false, reason: 'pending', publishedAt }],
      { now: NOW },
    );
    assert.equal(plan.alarm, 'open', `publishedAt ${JSON.stringify(publishedAt)} should be overdue`);
    assert.equal(plan.overdue[0].minutes, null);
  }
});

test('planPromotion closes an open alarm only when nothing is waiting at all', () => {
  const stillInsideWindow = planPromotion(
    [{ tag: 'v0.6.6', held: true, proven: false, reason: 'pending', publishedAt: ago(5) }],
    { now: NOW, openIssue: { number: 7 } },
  );
  // Waiting but not overdue. Closing here would reopen the same issue an hour
  // later, which trains a reader to ignore it.
  assert.equal(stillInsideWindow.alarm, 'none');

  const nothingWaiting = planPromotion(
    [{ tag: 'v0.6.5', held: true, proven: true, publishedAt: ago(5) }],
    { now: NOW, openIssue: { number: 7 } },
  );
  assert.equal(nothingWaiting.alarm, 'close');

  const noneAtAll = planPromotion([], { now: NOW, openIssue: { number: 7 } });
  assert.equal(noneAtAll.alarm, 'close');
});

test('buildBody names every overdue tag and what the gate said about it', () => {
  const body = buildBody([
    { tag: 'v0.6.6', reason: 'evidence/abc/stranger.env does not exist', minutes: 400 },
    { tag: 'v0.6.7', reason: 'records incomplete stranger arm(s) brown', minutes: null },
  ]);
  assert.match(body, /v0\.6\.6/);
  assert.match(body, /v0\.6\.7/);
  assert.match(body, /does not exist/);
  assert.match(body, /incomplete stranger arm/);
  assert.match(body, /400 min/);
  assert.match(body, /unknown/);
  assert.match(body, /closes itself/);
});

// The reason is data. It comes from whatever the proof gate said about a record
// on an append-only branch, and two characters in it break the table it lands
// in. CodeQL found the first version of this escaping incomplete on the pull
// request that introduced it, so the inputs here are the ones that broke it.
test('buildBody renders a gate refusal into one table cell whatever it contains', () => {
  const row = (reason) =>
    buildBody([{ tag: 'v1.0.0', reason, minutes: 400 }])
      .split('\n')
      .find((line) => line.startsWith('| `v1.0.0`'));

  // A bare pipe: one escape, one cell.
  assert.equal(row('a | b'), '| `v1.0.0` | 400 min | a \\| b |');

  // A backslash BEFORE a pipe. Escaping the pipe alone turns this into a
  // literal backslash followed by an unescaped delimiter, and the row silently
  // gains a column. Both characters have to be escaped in one pass.
  assert.equal(row('a\\|b'), '| `v1.0.0` | 400 min | a\\\\\\|b |');

  // A newline inside a table row ends the row.
  assert.equal(row('line one\nline two'), '| `v1.0.0` | 400 min | line one line two |');

  // Every rendered row has exactly the four pipes of a three-column row, so a
  // cell can never smuggle in a fifth.
  for (const reason of ['a | b', 'a\\|b', 'line one\nline two', '|||', '\\\\']) {
    const rendered = row(reason);
    const unescaped = rendered.replace(/\\./g, '');
    assert.equal(
      unescaped.split('|').length - 1,
      4,
      `reason ${JSON.stringify(reason)} rendered ${JSON.stringify(rendered)}`,
    );
  }
});

test('the alarm title names the condition and never a tag', () => {
  assert.equal(ALARM_TITLE, 'Release published without first-contact proof');
  assert.doesNotMatch(ALARM_TITLE, /v\d/);
});

// ── reading the rail ──────────────────────────────────────────────────────

const stubApi = (routes) => async (path) => {
  for (const [fragment, value] of Object.entries(routes)) {
    if (path.includes(fragment)) {
      if (value instanceof Error) throw value;
      return value;
    }
  }
  throw new Error(`GET ${path} failed: HTTP 404 Not Found`);
};

test('resolveTagCommit dereferences an annotated tag', async () => {
  const lightweight = await resolveTagCommit(
    'v0.6.5',
    stubApi({ '/git/ref/tags/': { object: { type: 'commit', sha: 'a'.repeat(40) } } }),
  );
  assert.equal(lightweight, 'a'.repeat(40));

  // An annotated tag's ref points at a TAG object, whose sha is not a commit.
  // Keying the evidence lookup on it would ask about a sha no preflight ever
  // judged, and the refusal would read as "unproven" rather than as a bug.
  const annotated = await resolveTagCommit(
    'v0.6.6',
    stubApi({
      '/git/ref/tags/': { object: { type: 'tag', sha: 'c'.repeat(40) } },
      '/git/tags/': { object: { sha: 'b'.repeat(40) } },
    }),
  );
  assert.equal(annotated, 'b'.repeat(40));

  await assert.rejects(
    resolveTagCommit('v0.6.7', stubApi({ '/git/ref/tags/': { object: { type: 'commit', sha: 'nope' } } })),
    /does not resolve to a commit sha/,
  );
});

const listing = (over = {}) => ({
  '/releases?': [release(over)],
  '/git/ref/tags/': { object: { type: 'commit', sha: 'a'.repeat(40) } },
  '/issues?': [],
});

test('buildPlan promotes a held release the gate now passes', async () => {
  const plan = await buildPlan({
    repository: 'firelock-ai/kin',
    api: stubApi(listing()),
    judge: async () => ({ stranger: { driver: { endpoint: 'local' } } }),
    now: NOW,
  });
  assert.deepEqual(plan.promote, [{ tag: 'v0.6.5', driver: 'local' }]);
  assert.equal(plan.judgements[0].sha, 'a'.repeat(40));
});

// The reason a gate gives is the first thing a reader needs, so it has to
// survive into the plan rather than being flattened to "not proven".
test('buildPlan carries the gate refusal verbatim and never fails the sweep', async () => {
  const plan = await buildPlan({
    repository: 'firelock-ai/kin',
    api: stubApi(listing()),
    judge: async () => {
      throw new Error('evidence/aaa/stranger.env does not exist on the release-evidence branch');
    },
    now: NOW,
  });
  assert.deepEqual(plan.promote, []);
  assert.equal(plan.waiting.length, 1);
  assert.match(plan.waiting[0].reason, /stranger\.env does not exist/);
});

// A tag that will not resolve is a wait with a reason, not a red sweep. This
// promoter ticks four times an hour and a red run on a rail that is behaving
// trains a reader to ignore it.
test('buildPlan turns an unresolvable tag into a wait, not a failure', async () => {
  const plan = await buildPlan({
    repository: 'firelock-ai/kin',
    api: stubApi({ '/releases?': [release()], '/issues?': [] }),
    judge: async () => {
      throw new Error('the judge must not be reached for an unresolvable tag');
    },
    now: NOW,
  });
  assert.deepEqual(plan.promote, []);
  assert.match(plan.waiting[0].reason, /HTTP 404 Not Found/);
});

// The one read that must NOT fail soft. A truncated listing looks exactly like
// a short one, and a promoter that silently read only the newest hundred
// releases would go quiet at the moment the list outgrew them.
test('buildPlan refuses a release listing that filled a whole page', async () => {
  await assert.rejects(
    buildPlan({
      repository: 'firelock-ai/kin',
      api: stubApi({ '/releases?': Array.from({ length: 100 }, () => release()) }),
      judge: async () => ({}),
      now: NOW,
    }),
    /filled a whole page/,
  );
  // The control: ninety-nine is an answer, and it must be read as one.
  const short = await buildPlan({
    repository: 'firelock-ai/kin',
    api: stubApi({
      '/releases?': Array.from({ length: 99 }, () => release()),
      '/git/ref/tags/': { object: { type: 'commit', sha: 'a'.repeat(40) } },
      '/issues?': [],
    }),
    judge: async () => ({ stranger: { driver: { endpoint: 'account' } } }),
    now: NOW,
  });
  assert.equal(short.promote.length, 99);
});

test('buildPlan finds the open alarm by its exact title and nothing else', async () => {
  const withIssue = await buildPlan({
    repository: 'firelock-ai/kin',
    api: stubApi({
      ...listing({ published_at: ago(DEFAULT_ALARM_AFTER_MINUTES + 1) }),
      '/issues?': [{ number: 12, title: ALARM_TITLE }],
    }),
    judge: async () => {
      throw new Error('pending');
    },
    now: NOW,
  });
  assert.equal(withIssue.openIssue, 12);
  assert.equal(withIssue.alarm, 'update');

  // A near-miss title must not be adopted, or a rename would silently comment
  // on somebody else's issue forever.
  const other = await buildPlan({
    repository: 'firelock-ai/kin',
    api: stubApi({
      ...listing({ published_at: ago(DEFAULT_ALARM_AFTER_MINUTES + 1) }),
      '/issues?': [{ number: 12, title: `${ALARM_TITLE} (v0.6.6)` }],
    }),
    judge: async () => {
      throw new Error('pending');
    },
    now: NOW,
  });
  assert.equal(other.openIssue, null);
  assert.equal(other.alarm, 'open');
});

test('buildPlan refuses without a repository', async () => {
  await assert.rejects(
    buildPlan({ api: stubApi({}), judge: async () => ({}) }),
    /no repository given/,
  );
});

// The promoter reaches GitHub Latest, so it must require everything and must
// not inherit that decision from the environment. A stray KIN_RELEASE_REQUIRE
// would otherwise promote a release on the machine proof alone, which is the
// exact failure the two-tier design exists to prevent.
//
// The input has to be the one case where the two modes DISAGREE: a preflight
// record that exists and a stranger record that does not. An absent preflight
// throws in both modes, so a test built on one would pass whichever mode ran
// and prove nothing.
test('the promoter asks the gate for every record, whatever the environment says', async () => {
  const SHA = 'a'.repeat(40);
  const ARCHIVE = '1'.repeat(64);
  const preflight = {
    schema: 'kin.release-preflight.v1',
    verdict: 'PASS',
    allow_dirty: false,
    legs: [
      {
        name: 'linux (arm64, debian 12, archive)',
        verdict: 'PASS',
        result: { expected: { commit: SHA }, archive: { sha256: ARCHIVE } },
      },
    ],
  };
  const previous = process.env.KIN_RELEASE_REQUIRE;
  process.env.KIN_RELEASE_REQUIRE = 'preflight';
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kin-promoter-'));
  const out = path.join(dir, 'plan.json');
  try {
    await main({
      repository: 'firelock-ai/kin',
      token: 'x',
      out,
      log: () => {},
      fetchImpl: async (url) => {
        const answer = (body) => ({
          ok: true,
          status: 200,
          statusText: 'OK',
          json: async () => body,
          text: async () => (typeof body === 'string' ? body : JSON.stringify(body)),
        });
        if (url.includes('/releases?')) return answer([release()]);
        if (url.includes('/git/ref/tags/')) return answer({ object: { type: 'commit', sha: SHA } });
        if (url.includes('/issues?')) return answer([]);
        if (url.includes('preflight.json')) return answer(JSON.stringify(preflight));
        return { ok: false, status: 404, statusText: 'Not Found', text: async () => '' };
      },
    });
  } finally {
    if (previous === undefined) delete process.env.KIN_RELEASE_REQUIRE;
    else process.env.KIN_RELEASE_REQUIRE = previous;
  }
  const plan = JSON.parse(fs.readFileSync(out, 'utf8'));
  // Under 'preflight' this release would have been proven and promoted. Under
  // 'all', which is what the promoter must ask for, it waits.
  assert.deepEqual(plan.promote, []);
  assert.match(plan.waiting[0].reason, /stranger\.env does not exist/);
});
