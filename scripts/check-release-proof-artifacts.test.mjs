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
  BUMP_BRANCH,
  DRIVER_ENDPOINT_FIELD,
  EVIDENCE_REF,
  LEGACY_DRIVER_ENDPOINT_FIELD,
  PREFLIGHT_RECORD,
  PREFLIGHT_SCHEMA,
  PROVENANCE_ASSET,
  REFERENCE_DRIVER_ENDPOINT,
  REQUIRE_MODES,
  STRANGER_RECORD,
  describeDriver,
  evidencePath,
  fetchEvidence,
  judgePreflight,
  judgeReleaseProvenance,
  judgeStranger,
  main,
  parseRunEnv,
  readDriverEndpoint,
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
  arms: 'green,brown,vcs',
  arms_complete: 'green,brown,vcs',
  arms_incomplete: '',
  ...over,
});

const strangerRecordText = (over = {}) =>
  `${Object.entries(strangerEnv(over)).map(([key, value]) => `${key}=${value}`).join('\n')}\n`;

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

test('parseRunEnv refuses a duplicated proof-record key', () => {
  throwsWith(
    () => parseRunEnv('arms_incomplete=green\narms_incomplete=\n'),
    /repeats key "arms_incomplete", so its evidence is ambiguous/,
  );
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
    arms: ['green', 'brown', 'vcs'],
    // The fixture is a record from before bin/kin-stranger wrote a driver key,
    // which is what every already-published record on the evidence branch looks
    // like. Unrecorded, not assumed to be the account.
    driver: { endpoint: null, field: null, reference: false },
  });
});

test('judgeStranger carries the driver its record names', () => {
  const local = judgeStranger(
    strangerEnv({ [DRIVER_ENDPOINT_FIELD]: 'local', [LEGACY_DRIVER_ENDPOINT_FIELD]: 'local' }),
    SHA,
    [ARCHIVE_A],
  );
  assert.deepEqual(local.driver, {
    endpoint: 'local',
    field: DRIVER_ENDPOINT_FIELD,
    reference: false,
  });
  const account = judgeStranger(
    strangerEnv({ [DRIVER_ENDPOINT_FIELD]: REFERENCE_DRIVER_ENDPOINT }),
    SHA,
    [ARCHIVE_A],
  );
  assert.equal(account.driver.reference, true);
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

test('judgeStranger refuses missing, partial, and internally inconsistent arm coverage', () => {
  throwsWith(
    () => judgeStranger(strangerEnv({ arms: 'green,brown' }), SHA, [ARCHIVE_A]),
    /omits required stranger arm\(s\) vcs/,
  );
  throwsWith(
    () => judgeStranger(strangerEnv({ arms_incomplete: 'green,brown,vcs' }), SHA, [ARCHIVE_A]),
    /records incomplete stranger arm\(s\) green, brown, vcs/,
  );
  throwsWith(
    () => judgeStranger(
      strangerEnv({ arms_complete: '', arms_incomplete: 'green,brown,vcs' }),
      SHA,
      [ARCHIVE_A],
    ),
    /records incomplete stranger arm\(s\) green, brown, vcs/,
  );
  throwsWith(
    () => judgeStranger(strangerEnv({ arms_complete: 'green,brown' }), SHA, [ARCHIVE_A]),
    /does not mark requested arm\(s\) vcs complete/,
  );
  throwsWith(
    () => judgeStranger(strangerEnv({ arms_complete: '', arms_incomplete: '' }), SHA, [ARCHIVE_A]),
    /does not mark requested arm\(s\) green, brown, vcs complete/,
  );
  throwsWith(
    () => judgeStranger(strangerEnv({ arms_complete: 'green,brown,vcs,other' }), SHA, [ARCHIVE_A]),
    /marks undeclared arm\(s\) other complete/,
  );
  throwsWith(
    () => judgeStranger(strangerEnv({ arms_incomplete: 'other' }), SHA, [ARCHIVE_A]),
    /marks undeclared arm\(s\) other incomplete/,
  );
  throwsWith(
    () => judgeStranger(strangerEnv({ arms_complete: 'green,brown,vcs,vcs' }), SHA, [ARCHIVE_A]),
    /repeats an arm in arms_complete/,
  );
  throwsWith(
    () => judgeStranger(strangerEnv({ arms: 'green,green,brown,vcs' }), SHA, [ARCHIVE_A]),
    /repeats an arm in arms/,
  );
  throwsWith(
    () => judgeStranger(strangerEnv({ arms_incomplete: 'green,green' }), SHA, [ARCHIVE_A]),
    /repeats an arm in arms_incomplete/,
  );
});

test('judgeStranger refuses a record that never declares its coverage fields', () => {
  const withoutRequested = strangerEnv();
  delete withoutRequested.arms;
  throwsWith(
    () => judgeStranger(withoutRequested, SHA, [ARCHIVE_A]),
    /carries no arms, so its arm coverage is unknown/,
  );

  const withoutCompleted = strangerEnv();
  delete withoutCompleted.arms_complete;
  throwsWith(
    () => judgeStranger(withoutCompleted, SHA, [ARCHIVE_A]),
    /carries no arms_complete, so its arm coverage is unknown/,
  );

  const withoutIncomplete = strangerEnv();
  delete withoutIncomplete.arms_incomplete;
  throwsWith(
    () => judgeStranger(withoutIncomplete, SHA, [ARCHIVE_A]),
    /carries no arms_incomplete, so its arm coverage is unknown/,
  );
});

// ── which driver produced the record ──────────────────────────────────────
//
// A local-model stranger and an account stranger write the same keys, the same
// arms and the same archive sha256. Everything below exists so those two
// records cannot reach an operator as the same sentence.

test('readDriverEndpoint reads the current key, the legacy key, and neither', () => {
  assert.deepEqual(
    readDriverEndpoint(strangerEnv({ [DRIVER_ENDPOINT_FIELD]: 'local' }), SHA),
    { endpoint: 'local', field: DRIVER_ENDPOINT_FIELD, reference: false },
  );
  // Every record published before bin/kin-stranger learned driver_endpoint
  // carries only `endpoint`. Reading it is what stops this gate calling the
  // whole existing evidence branch unrecorded.
  assert.deepEqual(
    readDriverEndpoint(strangerEnv({ [LEGACY_DRIVER_ENDPOINT_FIELD]: 'account' }), SHA),
    {
      endpoint: 'account',
      field: LEGACY_DRIVER_ENDPOINT_FIELD,
      reference: true,
    },
  );
  assert.deepEqual(readDriverEndpoint(strangerEnv(), SHA), {
    endpoint: null,
    field: null,
    reference: false,
  });
});

test('readDriverEndpoint refuses a record that disagrees with itself', () => {
  throwsWith(
    () => readDriverEndpoint(
      strangerEnv({
        [DRIVER_ENDPOINT_FIELD]: 'account',
        [LEGACY_DRIVER_ENDPOINT_FIELD]: 'local',
      }),
      SHA,
    ),
    /disagrees with itself about which driver produced it/,
  );
});

// A key that is present and empty is worse than a key that is missing: only the
// second is obviously unanswered. Both keys are checked, because a record that
// answers with nothing under either name is the same failure.
test('readDriverEndpoint refuses a key that claims to answer and does not', () => {
  throwsWith(
    () => readDriverEndpoint(strangerEnv({ [DRIVER_ENDPOINT_FIELD]: '' }), SHA),
    new RegExp(`carries an empty ${DRIVER_ENDPOINT_FIELD}`),
  );
  throwsWith(
    () => readDriverEndpoint(strangerEnv({ [DRIVER_ENDPOINT_FIELD]: '   ' }), SHA),
    new RegExp(`carries an empty ${DRIVER_ENDPOINT_FIELD}`),
  );
  throwsWith(
    () => readDriverEndpoint(strangerEnv({ [LEGACY_DRIVER_ENDPOINT_FIELD]: '' }), SHA),
    new RegExp(`carries an empty ${LEGACY_DRIVER_ENDPOINT_FIELD}`),
  );
});

test('describeDriver says weaker for anything but the reference endpoint', () => {
  assert.match(
    describeDriver({ endpoint: REFERENCE_DRIVER_ENDPOINT, reference: true }),
    new RegExp(`on the ${REFERENCE_DRIVER_ENDPOINT} endpoint`),
  );
  const local = describeDriver({ endpoint: 'local', reference: false });
  assert.match(local, /WEAKER stranger/);
  // The exact claim that does NOT carry over from a weaker driver, spelled out
  // rather than left to the reader: findings stand, an empty finding list does
  // not. A sentence that only said "weaker" would let a quiet local run be read
  // as a clean build.
  assert.match(local, /an empty finding list from it does not/);
  assert.match(
    describeDriver({ endpoint: null, field: null, reference: false }),
    /does not name/,
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
      [STRANGER_RECORD]: ok(strangerRecordText()),
    }),
  });
  assert.equal(result.archive, ARCHIVE_A);
  assert.deepEqual(result.archives, [ARCHIVE_A, ARCHIVE_B]);
  assert.match(lines.join('\n'), /Verified release proof artifacts/);
});

test('main refuses a duplicate key that tries to hide an incomplete stranger arm', async () => {
  const duplicateIncomplete = `${strangerRecordText({ arms_incomplete: 'green' })}arms_incomplete=\n`;
  await assert.rejects(
    main({
      sha: SHA,
      repository: REPO,
      env: {},
      log: () => {},
      fetchImpl: stubFetch({
        [PREFLIGHT_RECORD]: ok(JSON.stringify(preflightRecord())),
        [STRANGER_RECORD]: ok(duplicateIncomplete),
      }),
    }),
    /repeats key "arms_incomplete", so its evidence is ambiguous/,
  );
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

// ── the two require modes ─────────────────────────────────────────────────
//
// Until 2026-09-02 a missing stranger.env meant no tag, forever, with no signal
// but a hold alarm. The founder's instruction was to make the stranger
// non-blocking without letting a release claim coverage it does not have, and
// these cases are the line between those two.

test('require preflight proceeds on the machine proof and reports the gap', async () => {
  const lines = [];
  const result = await main({
    sha: SHA,
    repository: REPO,
    require: 'preflight',
    env: {},
    log: (line) => lines.push(line),
    fetchImpl: stubFetch({
      [PREFLIGHT_RECORD]: ok(JSON.stringify(preflightRecord())),
    }),
  });
  assert.equal(result.sha, SHA);
  assert.deepEqual(result.archives, [ARCHIVE_A, ARCHIVE_B]);
  assert.equal(result.stranger.state, 'pending');
  // No archive, because no stranger ran on one. A pending result that carried
  // the preflight's archive would let a caller believe bytes had been through
  // the arms.
  assert.equal(result.archive, null);
  assert.deepEqual(result.stranger.arms, []);
  const said = lines.join('\n');
  assert.match(said, /FIRST-CONTACT PROOF IS PENDING/);
  assert.match(said, /may not be described as first-contact proven/);
});

// The narrowing is one condition wide. Under 'preflight' a stranger record that
// EXISTS is judged exactly as it always was, so relaxing the tag gate cannot be
// used to ship a record that is wrong rather than missing.
test('require preflight still judges a stranger record that exists', async () => {
  await assert.rejects(
    main({
      sha: SHA,
      repository: REPO,
      require: 'preflight',
      env: {},
      log: () => {},
      fetchImpl: stubFetch({
        [PREFLIGHT_RECORD]: ok(JSON.stringify(preflightRecord())),
        [STRANGER_RECORD]: ok(strangerRecordText({ arms_incomplete: 'brown' })),
      }),
    }),
    /records incomplete stranger arm\(s\) brown/,
  );
  await assert.rejects(
    main({
      sha: SHA,
      repository: REPO,
      require: 'preflight',
      env: {},
      log: () => {},
      // Three reads now, not two. A stranger record naming bytes no preflight
      // leg judged sends the gate to the release surface for a second receipt,
      // and this candidate has no release: an empty listing is what says so.
      // Without the route the stub's default 404 would fail closed and this
      // assertion would pass on a transport error instead of on the refusal it
      // is about.
      fetchImpl: stubFetch({
        [PREFLIGHT_RECORD]: ok(JSON.stringify(preflightRecord())),
        [STRANGER_RECORD]: ok(strangerRecordText({ archive_sha256: ARCHIVE_UNJUDGED })),
        '/releases?': jsonOk([]),
      }),
    }),
    /the stranger ran, but not on these bytes/,
  );
});

// "We could not tell" must never become "proceed". fetchEvidence flags a 404
// and deliberately flags nothing else, and this is the case that proves the
// relaxation keys on that flag rather than on any failure to read.
test('require preflight fails closed on an unreadable stranger record', async () => {
  await assert.rejects(
    main({
      sha: SHA,
      repository: REPO,
      require: 'preflight',
      env: {},
      log: () => {},
      fetchImpl: stubFetch({
        [PREFLIGHT_RECORD]: ok(JSON.stringify(preflightRecord())),
        [STRANGER_RECORD]: {
          ok: false,
          status: 500,
          statusText: 'Internal Server Error',
          text: async () => '',
        },
      }),
    }),
    /HTTP 500 Internal Server Error/,
  );
});

// The preflight half is not relaxed at all. A candidate with no machine proof
// is refused in both modes, because that record is the one this gate can always
// have before a tag exists.
test('require preflight still refuses a candidate with no preflight record', async () => {
  await assert.rejects(
    main({
      sha: SHA,
      repository: REPO,
      require: 'preflight',
      env: {},
      log: () => {},
      fetchImpl: stubFetch({}),
    }),
    /the proof loop has not recorded this candidate/,
  );
});

test('main defaults to requiring both records', async () => {
  assert.deepEqual([...REQUIRE_MODES], ['all', 'preflight']);
  // No require given: the historical contract, so a caller written before this
  // mode existed is judged the way it always was.
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

test('main refuses an unknown require mode rather than picking one', async () => {
  await assert.rejects(
    main({
      sha: SHA,
      repository: REPO,
      require: 'stranger-only',
      env: {},
      log: () => {},
      fetchImpl: stubFetch({
        [PREFLIGHT_RECORD]: ok(JSON.stringify(preflightRecord())),
      }),
    }),
    /unknown require mode "stranger-only"/,
  );
});

test('a complete run reports its state and its driver to the caller', async () => {
  const lines = [];
  const result = await main({
    sha: SHA,
    repository: REPO,
    require: 'preflight',
    env: {},
    log: (line) => lines.push(line),
    fetchImpl: stubFetch({
      [PREFLIGHT_RECORD]: ok(JSON.stringify(preflightRecord())),
      [STRANGER_RECORD]: ok(strangerRecordText({ [DRIVER_ENDPOINT_FIELD]: 'local' })),
    }),
  });
  assert.equal(result.stranger.state, 'complete');
  assert.equal(result.stranger.driver.endpoint, 'local');
  assert.match(lines.join('\n'), /WEAKER stranger/);
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
        [STRANGER_RECORD]: ok(strangerRecordText()),
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
        { number: 986, merge_commit_sha: SHA, head: { sha: RC_HEAD, ref: BUMP_BRANCH } },
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
        jsonOk([{ number: 1, merge_commit_sha: OTHER_SHA, head: { sha: RC_HEAD, ref: BUMP_BRANCH } }]),
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
          { number: 1, merge_commit_sha: SHA, head: { sha: RC_HEAD, ref: BUMP_BRANCH } },
          { number: 2, merge_commit_sha: SHA, head: { sha: OTHER_SHA, ref: BUMP_BRANCH } },
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

// The bridge exists for tags cut before the candidate became a main commit,
// and every one of those resolves through the release train's bump branch:
// checked against v0.5.44, v0.5.45 and v0.5.46, whose tag commits are the
// squashes of kin#986, kin#991 and kin#1001, all from automation/release-next.
// Under the current scheme an ordinary main commit is the squash of a feature
// pull request whose head never carried a record, so bridging to it would send
// the promote gate looking somewhere nothing was ever proven.
test('resolveCandidateSha refuses to bridge outside the release train', async () => {
  await assert.rejects(
    resolveCandidateSha(SHA, {
      repository: REPO,
      fetchImpl: async () =>
        jsonOk([
          {
            number: 1049,
            merge_commit_sha: SHA,
            head: { sha: RC_HEAD, ref: 'feature/some-ordinary-branch' },
          },
        ]),
    }),
    /not from automation\/release-next; only the release train's bump branch/,
  );
});

test('resolveCandidateSha still separates absence from a wrong branch', async () => {
  await assert.rejects(
    resolveCandidateSha(SHA, {
      repository: REPO,
      fetchImpl: async () => jsonOk([]),
    }),
    /no merged pull request produced/,
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
        return jsonOk([{ number: 986, merge_commit_sha: SHA, head: { sha: RC_HEAD, ref: BUMP_BRANCH } }]);
      }
      if (url.includes(PREFLIGHT_RECORD)) {
        const record = preflightRecord();
        record.legs.forEach((leg) => {
          leg.result.expected.commit = RC_HEAD;
        });
        return ok(JSON.stringify(record));
      }
      return ok(strangerRecordText());
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

// The promote gate passes both keys now that the mint tags the candidate
// itself. The direct key is the answer, and the bridge must not even be asked:
// a landed commit resolves through /pulls to the head of whatever feature pull
// request produced it, which has no records and never did.
test('main answers from the direct key without asking about pull requests', async () => {
  const asked = [];
  const result = await main({
    sha: SHA,
    resolveFromCommit: SHA,
    repository: REPO,
    env: {},
    log: () => {},
    fetchImpl: async (url) => {
      asked.push(url);
      if (url.includes(PREFLIGHT_RECORD)) {
        return ok(JSON.stringify(preflightRecord()));
      }
      return ok(strangerRecordText());
    },
  });
  assert.equal(result.sha, SHA);
  assert.equal(
    asked.filter((url) => url.includes('/pulls')).length,
    0,
    'the direct key resolved, so nothing may bridge',
  );
});

// A tag cut before the rekey points at the squash of a version bump pull
// request, and its records sit under that pull request's head. Release
// Recovery can still re-run one, so absence under the direct key falls
// through to the bridge exactly once.
test('main bridges when the direct key is absent and a commit is given', async () => {
  const lines = [];
  const result = await main({
    sha: SHA,
    resolveFromCommit: SHA,
    repository: REPO,
    env: {},
    log: (line) => lines.push(line),
    fetchImpl: async (url) => {
      if (url.includes('/pulls')) {
        return jsonOk([{ number: 986, merge_commit_sha: SHA, head: { sha: RC_HEAD, ref: BUMP_BRANCH } }]);
      }
      if (url.includes(`evidence/${SHA}/`)) {
        return { ok: false, status: 404, statusText: 'Not Found' };
      }
      if (url.includes(PREFLIGHT_RECORD)) {
        const record = preflightRecord();
        record.legs.forEach((leg) => {
          leg.result.expected.commit = RC_HEAD;
        });
        return ok(JSON.stringify(record));
      }
      return ok(strangerRecordText());
    },
  });
  assert.equal(result.sha, RC_HEAD);
  assert.match(lines.join('\n'), new RegExp(`No preflight record under ${SHA}`));
});

// The bridge widens the search, so only a definite absence may trigger it. An
// unreadable answer means we could not tell, and a check that widens when it
// cannot tell is a check that reports success for the wrong reason.
test('main never bridges past a record it could not read', async () => {
  for (const unreadable of [
    { ok: false, status: 500, statusText: 'Server Error' },
    { ok: false, status: 403, statusText: 'Forbidden' },
  ]) {
    let bridged = false;
    await assert.rejects(
      main({
        sha: SHA,
        resolveFromCommit: SHA,
        repository: REPO,
        env: {},
        log: () => {},
        fetchImpl: async (url) => {
          if (url.includes('/pulls')) {
            bridged = true;
            return jsonOk([{ number: 986, merge_commit_sha: SHA, head: { sha: RC_HEAD, ref: BUMP_BRANCH } }]);
          }
          return unreadable;
        },
      }),
      new RegExp(`could not read .*HTTP ${unreadable.status}`),
    );
    assert.equal(bridged, false, 'an unreadable record must never widen the search');
  }
});

// The mint passes the direct key alone, so absence there is terminal. Nothing
// about a main commit's own pull request could name a proven candidate.
test('main holds on absence when no commit to bridge from is given', async () => {
  let bridged = false;
  await assert.rejects(
    main({
      sha: SHA,
      repository: REPO,
      env: {},
      log: () => {},
      fetchImpl: async (url) => {
        if (url.includes('/pulls')) {
          bridged = true;
        }
        return { ok: false, status: 404, statusText: 'Not Found' };
      },
    }),
    /the proof loop has not recorded this candidate/,
  );
  assert.equal(bridged, false);
});

// ── the release's own receipt ─────────────────────────────────────────────
//
// The second link, and the reason there had to be one. A preflight leg judges
// an rc-build archive; release.yml rebuilds at the tag, so the archive a
// developer downloads from a release is never a preflight leg. Requiring the
// preflight link alone made the released-byte proof of any release unable to
// lift that release's own pending notice. Measured on v0.6.7 on 2026-09-04:
// three complete arms on the public Linux aarch64 archive
// f23d321d3ab5bc425063aa50ba2e70a9f0efcbfe164521fcaf343b4efff4d2c0, refused as
// "not on these bytes" while release-provenance.json for that exact commit
// listed it as artifacts[1].archive.sha256.

// Bytes that exist only in the release, never among the preflight legs, which
// is the whole shape of the case.
const RELEASED_ARCHIVE = '4'.repeat(64);
const RELEASE_TAG = 'v9.9.9';
const ASSET_URL = `https://api.github.com/repos/${REPO}/releases/assets/1`;

// Shaped on the real v0.6.7 asset: schema_version 2, the commit at kin.commit
// rather than at a top-level `commit`, and repeated on every artifact beside
// the archive sha256 the release shipped.
const provenanceRecord = (over = {}) => ({
  schema_version: 2,
  release_tag: RELEASE_TAG,
  kin: { commit: SHA, cargo_lock_sha256: '0'.repeat(64) },
  artifacts: [
    {
      artifact: 'kin-linux-aarch64',
      target: 'aarch64-unknown-linux-musl',
      kin: { commit: SHA },
      archive: { name: 'kin-linux-aarch64.tar.gz', sha256: RELEASED_ARCHIVE, size_bytes: 1 },
    },
  ],
  ...over,
});

const releaseListing = (over = {}) => [
  {
    tag_name: RELEASE_TAG,
    draft: false,
    assets: [
      { name: 'checksums-sha256.txt', url: `${ASSET_URL}0` },
      { name: PROVENANCE_ASSET, url: ASSET_URL },
    ],
    ...over,
  },
];

// Every route main() needs to reach the release receipt. Overridable one at a
// time so each refusal below changes exactly one thing.
const releaseRoutes = ({
  stranger = strangerRecordText({ archive_sha256: RELEASED_ARCHIVE }),
  listing = releaseListing(),
  ref = jsonOk({ object: { type: 'commit', sha: SHA } }),
  asset = ok(JSON.stringify(provenanceRecord())),
} = {}) => ({
  [PREFLIGHT_RECORD]: ok(JSON.stringify(preflightRecord())),
  [STRANGER_RECORD]: ok(stranger),
  '/releases/assets/': asset,
  '/releases?': jsonOk(listing),
  '/git/ref/tags/': ref,
});

test('main accepts a stranger run on the bytes the release of that commit shipped', async () => {
  const lines = [];
  const result = await main({
    sha: SHA,
    repository: REPO,
    env: {},
    log: (line) => lines.push(line),
    fetchImpl: stubFetch(releaseRoutes()),
  });
  // The preflight legs do not contain these bytes and are not supposed to.
  assert.equal(preflightRecord().legs.some((leg) => leg.result.archive.sha256 === RELEASED_ARCHIVE), false);
  assert.equal(result.archive, RELEASED_ARCHIVE);
  assert.equal(result.stranger.state, 'complete');
  assert.equal(result.stranger.link, 'release-provenance');
  assert.deepEqual(result.stranger.arms, ['green', 'brown', 'vcs']);
  assert.match(lines.join('\n'), new RegExp(`linked to this candidate by release ${RELEASE_TAG}`));
});

// The preflight link is untouched, and it still answers without asking the
// release surface anything. A second receipt that got consulted on the ordinary
// path would put a network read, and a network failure, in front of every
// release the gate already proves.
test('main links a run on preflight bytes without reading the release surface', async () => {
  let asked = '';
  const result = await main({
    sha: SHA,
    repository: REPO,
    env: {},
    log: () => {},
    fetchImpl: async (url) => {
      if (url.includes('/releases') || url.includes('/git/ref/tags/')) {
        asked = url;
      }
      return stubFetch({
        [PREFLIGHT_RECORD]: ok(JSON.stringify(preflightRecord())),
        [STRANGER_RECORD]: ok(strangerRecordText()),
      })(url);
    },
  });
  assert.equal(result.archive, ARCHIVE_A);
  assert.equal(result.stranger.link, 'preflight');
  assert.equal(asked, '', `the gate read ${asked} when the preflight legs already answered`);
});

// Neither receipt names these bytes, so the stranger ran on some other build
// and this candidate is not proven. The refusal must name BOTH sets it checked,
// or a reader is sent to look at half of what was consulted.
test('main refuses a run on bytes neither the preflight nor the release names', async () => {
  await assert.rejects(
    main({
      sha: SHA,
      repository: REPO,
      env: {},
      log: () => {},
      fetchImpl: stubFetch(
        releaseRoutes({ stranger: strangerRecordText({ archive_sha256: ARCHIVE_UNJUDGED }) }),
      ),
    }),
    (error) => {
      assert.match(error.message, /the stranger ran, but not on these bytes/);
      assert.match(error.message, new RegExp(`no preflight leg for ${SHA} judged`));
      assert.match(error.message, new RegExp(`release ${RELEASE_TAG} shipped`));
      return true;
    },
  );
});

// A release whose tag resolves to this candidate while its own receipt is about
// another build is tampering, not absence, so it refuses rather than being
// skipped in favour of the next release.
test('main refuses a release provenance that is about another commit', async () => {
  await assert.rejects(
    main({
      sha: SHA,
      repository: REPO,
      env: {},
      log: () => {},
      fetchImpl: stubFetch(
        releaseRoutes({
          asset: ok(JSON.stringify(provenanceRecord({ kin: { commit: OTHER_SHA } }))),
        }),
      ),
    }),
    /records commit b{40}, not a{40}; the release exists but its provenance is about a different build/,
  );
  // The same refusal one level down: the top of the record agrees while the
  // artifact carrying the bytes does not.
  await assert.rejects(
    main({
      sha: SHA,
      repository: REPO,
      env: {},
      log: () => {},
      fetchImpl: stubFetch(
        releaseRoutes({
          asset: ok(
            JSON.stringify(
              provenanceRecord({
                artifacts: [
                  {
                    artifact: 'kin-linux-aarch64',
                    kin: { commit: OTHER_SHA },
                    archive: { sha256: RELEASED_ARCHIVE },
                  },
                ],
              }),
            ),
          ),
        }),
      ),
    }),
    /artifact "kin-linux-aarch64" records commit b{40}, not a{40}/,
  );
});

// A real release of this exact commit, read successfully, that simply does not
// ship the bytes the stranger ran. Existence of a receipt is not the test; the
// archive appearing in it is.
test('main refuses when the release of the candidate ships other bytes', async () => {
  await assert.rejects(
    main({
      sha: SHA,
      repository: REPO,
      env: {},
      log: () => {},
      fetchImpl: stubFetch(
        releaseRoutes({
          asset: ok(
            JSON.stringify(
              provenanceRecord({
                artifacts: [
                  {
                    artifact: 'kin-linux-x86_64',
                    kin: { commit: SHA },
                    archive: { sha256: ARCHIVE_B },
                  },
                ],
              }),
            ),
          ),
        }),
      ),
    }),
    (error) => {
      assert.match(error.message, /the stranger ran, but not on these bytes/);
      assert.match(error.message, new RegExp(`release ${RELEASE_TAG} shipped \\(${ARCHIVE_B}\\)`));
      return true;
    },
  );
});

// No release of this candidate at all. The refusal has to say the release
// surface was searched and came back empty, rather than reporting as though
// only the preflight was ever asked.
test('main names the empty release surface when nothing shipped these bytes', async () => {
  await assert.rejects(
    main({
      sha: SHA,
      repository: REPO,
      env: {},
      log: () => {},
      fetchImpl: stubFetch(
        releaseRoutes({
          stranger: strangerRecordText({ archive_sha256: ARCHIVE_UNJUDGED }),
          listing: [],
        }),
      ),
    }),
    new RegExp(`no published release of ${SHA} carries a ${PROVENANCE_ASSET}`),
  );
});

// Fails closed, the same way an unreadable evidence record does. A release
// listing that could not be read must not be reported as a listing with no
// release in it: this search can only ever ADD an acceptance, and an answer we
// could not read must not be turned into a sentence about what exists.
test('main fails closed when the release surface cannot be read', async () => {
  await assert.rejects(
    main({
      sha: SHA,
      repository: REPO,
      env: {},
      log: () => {},
      fetchImpl: stubFetch({
        [PREFLIGHT_RECORD]: ok(JSON.stringify(preflightRecord())),
        [STRANGER_RECORD]: ok(strangerRecordText({ archive_sha256: RELEASED_ARCHIVE })),
        '/releases?': { ok: false, status: 502, statusText: 'Bad Gateway' },
      }),
    }),
    /could not list the releases of firelock-ai\/kin: HTTP 502 Bad Gateway/,
  );
});

// A draft is not published, so nothing about it is a claim yet, and a release
// carrying no receipt cannot be the second link. Both are skipped rather than
// read, and the search goes on to the release that can answer.
//
// The draft's own receipt is about another build and sits at its own asset URL,
// so a gate that stopped skipping drafts would take it FIRST, being newest, and
// refuse. Without that the draft would carry the same bytes as the release
// below it and the test would pass either way.
test('findReleaseProvenance skips a draft and a release with no receipt', async () => {
  const result = await main({
    sha: SHA,
    repository: REPO,
    env: {},
    log: () => {},
    fetchImpl: stubFetch({
      // First, because the stub answers on the first fragment that matches and
      // the shared '/releases/assets/' route below would otherwise swallow this
      // URL and hand the draft the good record.
      '/releases/assets/1-draft': ok(
        JSON.stringify(provenanceRecord({ kin: { commit: OTHER_SHA } })),
      ),
      ...releaseRoutes({
        listing: [
          {
            tag_name: 'v9.9.9-draft',
            draft: true,
            assets: [{ name: PROVENANCE_ASSET, url: `${ASSET_URL}-draft` }],
          },
          {
            tag_name: 'v9.9.8',
            draft: false,
            assets: [{ name: 'checksums-sha256.txt', url: `${ASSET_URL}-other` }],
          },
          ...releaseListing(),
        ],
      }),
    }),
  });
  assert.equal(result.stranger.link, 'release-provenance');
});

// A release whose tag resolves to some other commit is not this candidate's,
// whatever its receipt says. The foreign receipt here claims the candidate at
// kin.commit and lists the very archive the stranger ran, so a gate that
// stopped comparing the tag's commit would read it and ACCEPT. The candidate's
// own release is absent, so the right answer is a refusal, and the foreign
// asset must never be fetched at all; the tag ref must, or the skip was never
// exercised.
test('findReleaseProvenance skips a release whose tag resolves to another commit', async () => {
  const seen = [];
  const foreignAsset = `${ASSET_URL}-foreign`;
  await assert.rejects(
    main({
      sha: SHA,
      repository: REPO,
      env: {},
      log: () => {},
      fetchImpl: async (url) => {
        seen.push(url);
        return stubFetch({
          [foreignAsset]: ok(JSON.stringify(provenanceRecord())),
          '/git/ref/tags/v9.9.10': jsonOk({ object: { type: 'commit', sha: OTHER_SHA } }),
          ...releaseRoutes({
            listing: [
              {
                tag_name: 'v9.9.10',
                draft: false,
                assets: [{ name: PROVENANCE_ASSET, url: foreignAsset }],
              },
            ],
          }),
        })(url);
      },
    }),
    new RegExp(`no published release of ${SHA} carries a ${PROVENANCE_ASSET}`),
  );
  assert.equal(
    seen.some((url) => url.includes('/git/ref/tags/v9.9.10')),
    true,
    'the foreign tag was never resolved, so the skip was not exercised',
  );
  assert.equal(seen.includes(foreignAsset), false, "the foreign release's receipt was read");
});

// A receipt the release surface says exists and then does not serve. Fails
// closed in BOTH require modes, with the transport answer in the message and
// without the absence flag: the flag is what lets a caller widen on a missing
// stranger record, and a missing release receipt must never be read that way,
// or "we could not tell" becomes "no receipt, so judge on the preflight alone".
test('main fails closed when the release provenance asset is missing', async () => {
  for (const requireMode of REQUIRE_MODES) {
    await assert.rejects(
      main({
        sha: SHA,
        repository: REPO,
        require: requireMode,
        env: {},
        log: () => {},
        fetchImpl: stubFetch(
          releaseRoutes({ asset: { ok: false, status: 404, statusText: 'Not Found' } }),
        ),
      }),
      (error) => {
        assert.match(
          error.message,
          new RegExp(`could not read ${PROVENANCE_ASSET} from release ${RELEASE_TAG}: HTTP 404 Not Found`),
        );
        assert.doesNotMatch(
          error.message,
          /has not recorded this candidate|does not exist on the release-evidence branch/,
        );
        assert.equal(
          error.evidenceAbsent,
          undefined,
          `under require ${requireMode} a missing receipt wore the absence flag a caller may act on`,
        );
        return true;
      },
    );
  }
});

// A rejected request, as distinct from an HTTP failure above: the listing
// never answered at all. It refuses with the release-surface context in the
// message, so an operator reading a blocked promotion sees which read died
// rather than a bare socket error.
test('main fails closed when the release listing cannot be reached', async () => {
  await assert.rejects(
    main({
      sha: SHA,
      repository: REPO,
      env: {},
      log: () => {},
      fetchImpl: async (url) => {
        if (url.includes('/releases?')) {
          throw new Error('socket hang up');
        }
        return stubFetch(releaseRoutes())(url);
      },
    }),
    /could not reach GitHub to list the releases of firelock-ai\/kin: socket hang up/,
  );
});

// The same door for a transport failure on the asset alone: the listing and
// the tag answered, the bytes did not arrive. Not agreement, not absence.
test('main fails closed when the release provenance asset cannot be reached', async () => {
  await assert.rejects(
    main({
      sha: SHA,
      repository: REPO,
      env: {},
      log: () => {},
      fetchImpl: async (url) => {
        if (url.includes('/releases/assets/')) {
          throw new Error('socket hang up');
        }
        return stubFetch(releaseRoutes())(url);
      },
    }),
    new RegExp(`could not reach GitHub to read ${PROVENANCE_ASSET} from release ${RELEASE_TAG}: socket hang up`),
  );
});

test('judgeReleaseProvenance refuses a record that is not one', () => {
  throwsWith(
    () => judgeReleaseProvenance(null, SHA, RELEASE_TAG),
    /did not parse as a release provenance record/,
  );
  throwsWith(
    () => judgeReleaseProvenance([], SHA, RELEASE_TAG),
    /did not parse as a release provenance record/,
  );
  throwsWith(
    () => judgeReleaseProvenance(provenanceRecord({ artifacts: [] }), SHA, RELEASE_TAG),
    /lists no artifacts, so it names no released bytes/,
  );
  throwsWith(
    () =>
      judgeReleaseProvenance(
        provenanceRecord({
          artifacts: [{ artifact: 'kin-linux-aarch64', kin: { commit: SHA }, archive: {} }],
        }),
        SHA,
        RELEASE_TAG,
      ),
    /records no archive sha256/,
  );
});

test('the gate runs from a copy reached through a symlinked directory', () => {
  // release-tag.yml copies this file to $RUNNER_TEMP and runs it there. The
  // entry-point test used to compare `import.meta.url` against
  // `pathToFileURL(process.argv[1])`, and Node resolves symlinks for the first
  // and not the second, so a copy invoked through one exited 0 having judged
  // nothing. Measured before the fix: run from the checkout the gate exits 1
  // with `::error::no repository given`, and run from a symlinked copy it exits
  // 0 with zero bytes on both streams.
  //
  // Run with no repository so `main()` is reached and refuses on its own
  // missing input. The distinction being drawn is between a process that ran
  // and one that never started, and only the second is silent. This file
  // imports nothing relative, so a lone copy resolves and the entry point is
  // the only variable; a module-resolution error would otherwise write to
  // stderr and satisfy the assertion without proving anything.
  const gate = path.join(
    path.dirname(fileURLToPath(import.meta.url)),
    'check-release-proof-artifacts.mjs',
  );
  const real = fs.mkdtempSync(path.join(os.tmpdir(), 'kin-proof-gate-'));
  const link = `${real}-link`;
  fs.symlinkSync(real, link, 'dir');
  const copy = path.join(link, 'check-release-proof-artifacts.mjs');
  fs.copyFileSync(gate, copy);

  const env = { ...process.env };
  delete env.GITHUB_REPOSITORY;
  let output = '';
  try {
    output = execFileSync(process.execPath, [copy], {
      cwd: real,
      encoding: 'utf8',
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch (error) {
    output = `${error.stdout ?? ''}${error.stderr ?? ''}`;
  }
  assert.notEqual(output, '', 'the gate produced no output, so it never ran');
  assert.match(output, /no repository given/);
});
