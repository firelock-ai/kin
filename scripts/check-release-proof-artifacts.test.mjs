// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

import assert from 'node:assert/strict';
import test from 'node:test';

import {
  EVIDENCE_REF,
  PREFLIGHT_RECORD,
  PREFLIGHT_SCHEMA,
  STRANGER_RECORD,
  evidencePath,
  fetchEvidence,
  judgePreflight,
  judgeStranger,
  main,
  parseRunEnv,
  resolveCandidateSha,
} from './check-release-proof-artifacts.mjs';

const SHA = 'a'.repeat(40);
const OTHER_SHA = 'b'.repeat(40);
const ARCHIVE_A = '1'.repeat(64);
const ARCHIVE_B = '2'.repeat(64);
const ARCHIVE_UNJUDGED = '3'.repeat(64);
const REPO = 'firelock-ai/kin';

// Shaped on a real record: .kin-coord/preflight/20260820T112905Z/preflight.json
// carried schema kin.release-preflight.v1, verdict PASS, citable false, lane
// DEV-LOCAL, allow_dirty false, and three legs whose expected.commit all
// agreed while each carried its own archive sha256.
const preflightRecord = (over = {}) => ({
  schema: PREFLIGHT_SCHEMA,
  verdict: 'PASS',
  citable: false,
  lane: 'DEV-LOCAL',
  allow_dirty: false,
  legs: [
    {
      name: 'linux (arm64, debian 12, archive)',
      verdict: 'PASS',
      result: { expected: { commit: SHA }, archive: { sha256: ARCHIVE_A } },
    },
    {
      name: 'host (macos-aarch64, archive)',
      verdict: 'PASS',
      result: { expected: { commit: SHA }, archive: { sha256: ARCHIVE_B } },
    },
  ],
  ...over,
});

const strangerEnv = (over = {}) => ({
  archive_name: 'kin-linux-aarch64.tar.gz',
  archive_sha256: ARCHIVE_A,
  finished_at: '2026-08-18T21:53:25Z',
  ...over,
});

const throwsWith = (fn, fragment) =>
  assert.throws(fn, (error) => {
    assert.match(error.message, fragment);
    return true;
  });

test('evidencePath keys on an exact commit sha and refuses a loose ref', () => {
  assert.equal(
    evidencePath(SHA, PREFLIGHT_RECORD),
    `evidence/${SHA}/${PREFLIGHT_RECORD}`,
  );
  for (const loose of ['main', 'HEAD', 'v0.5.44', SHA.slice(0, 7), '']) {
    throwsWith(() => evidencePath(loose, PREFLIGHT_RECORD), /not a 40-character commit sha/);
  }
});

test('parseRunEnv reads the stranger key=value record', () => {
  const parsed = parseRunEnv(
    [
      '# a comment',
      '',
      'archive_name=kin-linux-aarch64.tar.gz',
      `archive_sha256=${ARCHIVE_A}`,
      'vm_capacity=5 vCPU, 12884901888 bytes',
      'continue_mission=',
      'image_id=sha256:881ca213=weird',
    ].join('\n'),
  );
  assert.equal(parsed.archive_name, 'kin-linux-aarch64.tar.gz');
  assert.equal(parsed.archive_sha256, ARCHIVE_A);
  assert.equal(parsed.vm_capacity, '5 vCPU, 12884901888 bytes');
  assert.equal(parsed.continue_mission, '');
  // Values may contain '=': split on the first one only.
  assert.equal(parsed.image_id, 'sha256:881ca213=weird');
});

test('judgePreflight accepts a well-formed record and returns its archives', () => {
  assert.deepEqual(judgePreflight(preflightRecord(), SHA), {
    archives: [ARCHIVE_A, ARCHIVE_B],
  });
});

// Regression guard. kin-release-preflight hardcodes citable false and lane
// DEV-LOCAL on every run it will ever emit, so a gate requiring citability is
// a check that cannot pass: it would hold every release forever. This test
// fails the moment someone reintroduces that rule.
test('judgePreflight accepts the DEV-LOCAL non-citable record every real run emits', () => {
  const record = preflightRecord({ citable: false, lane: 'DEV-LOCAL' });
  assert.doesNotThrow(() => judgePreflight(record, SHA));
});

test('judgePreflight refuses a record that is not a preflight record', () => {
  throwsWith(() => judgePreflight(null, SHA), /did not parse as a preflight record/);
  throwsWith(() => judgePreflight([], SHA), /did not parse as a preflight record/);
  throwsWith(
    () => judgePreflight(preflightRecord({ schema: 'kin.something-else.v1' }), SHA),
    /carries schema "kin\.something-else\.v1", not kin\.release-preflight\.v1/,
  );
});

test('judgePreflight refuses a candidate that did not clear preflight', () => {
  throwsWith(
    () => judgePreflight(preflightRecord({ verdict: 'FAIL' }), SHA),
    /records verdict FAIL, not PASS/,
  );
  throwsWith(
    () => judgePreflight(preflightRecord({ verdict: undefined }), SHA),
    /records verdict <none>, not PASS/,
  );
});

test('judgePreflight refuses a run that judged uncommitted changes', () => {
  throwsWith(
    () => judgePreflight(preflightRecord({ allow_dirty: true }), SHA),
    /was run with allow_dirty/,
  );
});

test('judgePreflight refuses a record that judged nothing', () => {
  throwsWith(() => judgePreflight(preflightRecord({ legs: [] }), SHA), /records no legs/);
  throwsWith(
    () => judgePreflight(preflightRecord({ legs: undefined }), SHA),
    /records no legs/,
  );
});

// The fabricated-artifact control: a real, well-formed, PASSING record that is
// simply about a different build. Existence alone must not satisfy the gate.
test('judgePreflight refuses a real record that is about a different commit', () => {
  throwsWith(
    () => judgePreflight(preflightRecord(), OTHER_SHA),
    new RegExp(`judged commit ${SHA}, not ${OTHER_SHA}`),
  );
  const mixed = preflightRecord();
  mixed.legs[1].result.expected.commit = OTHER_SHA;
  throwsWith(
    () => judgePreflight(mixed, SHA),
    /leg "host \(macos-aarch64, archive\)" judged commit b+, not a+/,
  );
});

test('judgePreflight refuses a failing leg under a passing overall verdict', () => {
  const record = preflightRecord();
  record.legs[1].verdict = 'FAIL';
  throwsWith(() => judgePreflight(record, SHA), /leg "host .*" records verdict FAIL, not PASS/);
});

test('judgePreflight refuses a leg with no archive to link a stranger run to', () => {
  const record = preflightRecord();
  delete record.legs[0].result.archive;
  throwsWith(() => judgePreflight(record, SHA), /records no archive sha256/);
  const short = preflightRecord();
  short.legs[0].result.archive.sha256 = 'not-a-sha';
  throwsWith(() => judgePreflight(short, SHA), /records no archive sha256/);
});

test('judgeStranger accepts a run on bytes a preflight leg judged', () => {
  assert.deepEqual(judgeStranger(strangerEnv(), SHA, [ARCHIVE_A, ARCHIVE_B]), {
    archive: ARCHIVE_A,
  });
});

test('judgeStranger refuses a record that names no bytes or never finished', () => {
  throwsWith(
    () => judgeStranger(strangerEnv({ archive_sha256: '' }), SHA, [ARCHIVE_A]),
    /carries no archive_sha256/,
  );
  throwsWith(
    () => judgeStranger(strangerEnv({ finished_at: '' }), SHA, [ARCHIVE_A]),
    /carries no finished_at/,
  );
});

// The chain, not two existence checks: a stranger run that really happened but
// on some other build must not satisfy this candidate's gate.
test('judgeStranger refuses a real run on bytes no preflight leg judged', () => {
  throwsWith(
    () => judgeStranger(strangerEnv({ archive_sha256: ARCHIVE_UNJUDGED }), SHA, [
      ARCHIVE_A,
      ARCHIVE_B,
    ]),
    /the stranger ran, but not on these bytes/,
  );
});

const stubFetch = (routes) => async (url) => {
  for (const [fragment, response] of Object.entries(routes)) {
    if (url.includes(fragment)) {
      return response;
    }
  }
  return { ok: false, status: 404, statusText: 'Not Found', text: async () => '' };
};

const ok = (body) => ({ ok: true, status: 200, statusText: 'OK', text: async () => body });

test('fetchEvidence reads a record off the evidence branch', async () => {
  let seen = '';
  const text = await fetchEvidence(SHA, PREFLIGHT_RECORD, {
    repository: REPO,
    fetchImpl: async (url) => {
      seen = url;
      return ok('{}');
    },
  });
  assert.equal(text, '{}');
  assert.match(seen, new RegExp(`/repos/${REPO}/contents/evidence/${SHA}/${PREFLIGHT_RECORD}`));
  assert.match(seen, new RegExp(`ref=${EVIDENCE_REF}`));
});

test('fetchEvidence reports absence as an unrecorded candidate', async () => {
  await assert.rejects(
    fetchEvidence(SHA, PREFLIGHT_RECORD, {
      repository: REPO,
      fetchImpl: async () => ({ ok: false, status: 404, statusText: 'Not Found' }),
    }),
    /the proof loop has not recorded this candidate/,
  );
});

// Fails closed: an unreadable answer is not agreement.
test('fetchEvidence fails closed on transport and server failure', async () => {
  await assert.rejects(
    fetchEvidence(SHA, PREFLIGHT_RECORD, {
      repository: REPO,
      fetchImpl: async () => {
        throw new Error('socket hang up');
      },
    }),
    /could not reach firelock-ai\/kin .*socket hang up/,
  );
  await assert.rejects(
    fetchEvidence(SHA, PREFLIGHT_RECORD, {
      repository: REPO,
      fetchImpl: async () => ({ ok: false, status: 500, statusText: 'Server Error' }),
    }),
    /could not read .*HTTP 500 Server Error/,
  );
});

test('main proceeds when both records exist for the exact candidate', async () => {
  const lines = [];
  const result = await main({
    sha: SHA,
    repository: REPO,
    env: {},
    log: (line) => lines.push(line),
    fetchImpl: stubFetch({
      [PREFLIGHT_RECORD]: ok(JSON.stringify(preflightRecord())),
      [STRANGER_RECORD]: ok(`archive_sha256=${ARCHIVE_A}\nfinished_at=2026-08-18T21:53:25Z\n`),
    }),
  });
  assert.equal(result.archive, ARCHIVE_A);
  assert.deepEqual(result.archives, [ARCHIVE_A, ARCHIVE_B]);
  assert.match(lines.join('\n'), /Verified release proof artifacts/);
});

test('main holds a candidate with no preflight record', async () => {
  await assert.rejects(
    main({
      sha: SHA,
      repository: REPO,
      env: {},
      log: () => {},
      fetchImpl: stubFetch({}),
    }),
    /the proof loop has not recorded this candidate/,
  );
});

test('main holds a candidate whose preflight ran but whose stranger did not', async () => {
  await assert.rejects(
    main({
      sha: SHA,
      repository: REPO,
      env: {},
      log: () => {},
      fetchImpl: stubFetch({
        [PREFLIGHT_RECORD]: ok(JSON.stringify(preflightRecord())),
      }),
    }),
    new RegExp(`evidence/${SHA}/${STRANGER_RECORD} does not exist`),
  );
});

test('main holds when the records exist but describe a different build', async () => {
  await assert.rejects(
    main({
      sha: OTHER_SHA,
      repository: REPO,
      env: {},
      log: () => {},
      fetchImpl: stubFetch({
        [PREFLIGHT_RECORD]: ok(JSON.stringify(preflightRecord())),
        [STRANGER_RECORD]: ok(`archive_sha256=${ARCHIVE_A}\nfinished_at=2026-08-18T21:53:25Z\n`),
      }),
    }),
    /the record exists but is about a different build/,
  );
});

test('main reports unparseable evidence rather than reading it as absent', async () => {
  await assert.rejects(
    main({
      sha: SHA,
      repository: REPO,
      env: {},
      log: () => {},
      fetchImpl: stubFetch({ [PREFLIGHT_RECORD]: ok('not json at all') }),
    }),
    /is not valid JSON/,
  );
});

const jsonOk = (body) => ({
  ok: true,
  status: 200,
  statusText: 'OK',
  json: async () => body,
});

const RC_HEAD = 'c'.repeat(40);

// Shaped on the real v0.5.44 line: tag commit a4ffe620 is kin#986's squash, and
// the preflight for it judged the release-next head, a different sha.
test('resolveCandidateSha bridges a squash to the branch head that was proven', async () => {
  let seen = '';
  const head = await resolveCandidateSha(SHA, {
    repository: REPO,
    fetchImpl: async (url) => {
      seen = url;
      return jsonOk([
        { number: 986, merge_commit_sha: SHA, head: { sha: RC_HEAD } },
      ]);
    },
  });
  assert.equal(head, RC_HEAD);
  assert.match(seen, new RegExp(`/repos/${REPO}/commits/${SHA}/pulls`));
});

// A hand-pushed tag has no originating pull request. That is precisely the
// "unforeseen path" the promote gate exists to catch, so it must refuse.
test('resolveCandidateSha refuses a commit no merged pull request produced', async () => {
  await assert.rejects(
    resolveCandidateSha(SHA, { repository: REPO, fetchImpl: async () => jsonOk([]) }),
    /no merged pull request produced/,
  );
  // An open pull request that merely touches the commit is not its merge.
  await assert.rejects(
    resolveCandidateSha(SHA, {
      repository: REPO,
      fetchImpl: async () =>
        jsonOk([{ number: 1, merge_commit_sha: OTHER_SHA, head: { sha: RC_HEAD } }]),
    }),
    /no merged pull request produced/,
  );
});

test('resolveCandidateSha refuses to guess between two claimants', async () => {
  await assert.rejects(
    resolveCandidateSha(SHA, {
      repository: REPO,
      fetchImpl: async () =>
        jsonOk([
          { number: 1, merge_commit_sha: SHA, head: { sha: RC_HEAD } },
          { number: 2, merge_commit_sha: SHA, head: { sha: OTHER_SHA } },
        ]),
    }),
    /claimed as the merge commit of more than one pull request \(#1, #2\)/,
  );
});

test('resolveCandidateSha fails closed on transport and server failure', async () => {
  await assert.rejects(
    resolveCandidateSha(SHA, {
      repository: REPO,
      fetchImpl: async () => {
        throw new Error('socket hang up');
      },
    }),
    /could not reach .*socket hang up/,
  );
  await assert.rejects(
    resolveCandidateSha(SHA, {
      repository: REPO,
      fetchImpl: async () => ({ ok: false, status: 403, statusText: 'Forbidden' }),
    }),
    /could not resolve the pull request behind .*HTTP 403 Forbidden/,
  );
});

test('resolveCandidateSha refuses a loose ref', async () => {
  await assert.rejects(
    resolveCandidateSha('main', { repository: REPO, fetchImpl: async () => jsonOk([]) }),
    /not a 40-character commit sha/,
  );
});

test('main bridges a landed commit to the candidate that was proven', async () => {
  const lines = [];
  const result = await main({
    resolveFromCommit: SHA,
    repository: REPO,
    env: {},
    log: (line) => lines.push(line),
    fetchImpl: async (url) => {
      if (url.includes('/pulls')) {
        return jsonOk([{ number: 986, merge_commit_sha: SHA, head: { sha: RC_HEAD } }]);
      }
      if (url.includes(PREFLIGHT_RECORD)) {
        const record = preflightRecord();
        record.legs.forEach((leg) => {
          leg.result.expected.commit = RC_HEAD;
        });
        return ok(JSON.stringify(record));
      }
      return ok(`archive_sha256=${ARCHIVE_A}\nfinished_at=2026-08-18T21:53:25Z\n`);
    },
  });
  assert.equal(result.sha, RC_HEAD);
  assert.match(lines.join('\n'), new RegExp(`Resolved candidate ${RC_HEAD} from landed commit ${SHA}`));
});

test('main refuses when neither a candidate nor a commit to bridge is given', async () => {
  await assert.rejects(
    main({ repository: REPO, env: {}, log: () => {}, fetchImpl: async () => ok('') }),
    /no candidate given/,
  );
});
