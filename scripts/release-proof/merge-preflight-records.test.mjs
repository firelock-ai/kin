// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { PREFLIGHT_SCHEMA, judgePreflight } from '../check-release-proof-artifacts.mjs';
import { HOSTED_LANE, admitLegRecord, main, mergeRecords, parseArgs } from './merge-preflight-records.mjs';

const SHA = 'a'.repeat(40);
const OTHER_SHA = 'b'.repeat(40);
const SCRIPT = fileURLToPath(new URL('./merge-preflight-records.mjs', import.meta.url));

// Shaped on the record the local preflight published for f2854caf on
// 2026-08-30: schema kin.release-preflight.v1, verdict PASS, citable false,
// lane DEV-LOCAL, allow_dirty false, and legs whose result.expected.commit all
// name the candidate while each carries its own archive sha256.
function leg(target, archive, over = {}) {
  return {
    name: `host (${target.slice(4)}, archive)`,
    kind: 'host',
    target,
    archive: `/tmp/kpf-rc/${target}.tar.gz`,
    verdict: 'PASS',
    magic_repro: 'PASS (25 pass, 0 fail, 0 unreadable of 25)',
    result_path: `/tmp/kpf-rc/legs/host/result.json`,
    result: {
      expected: { commit: SHA, lock_sha256: 'c'.repeat(64), allow_dirty: false },
      archive: { path: `/tmp/kpf-rc/${target}.tar.gz`, sha256: archive },
    },
    ...over,
  };
}

function record(legs, over = {}) {
  return {
    schema: PREFLIGHT_SCHEMA,
    citable: false,
    lane: 'DEV-LOCAL',
    run: '20260902T200000Z',
    host: 'Darwin 25.4.0 arm64',
    lock_lane: 'release-proof',
    verdict: 'PASS',
    allow_dirty: false,
    cpu_embed: true,
    tooling: { source: '/w @ HEAD', validator_ported_from_sha256: '0'.repeat(64), workflow_sha256_at_ref: '0'.repeat(64) },
    provenance: [`archive: ${legs.map((entry) => entry.target).join(',')}`],
    skipped: [],
    legs,
    run_root: '/tmp/kpf-rc',
    log: '/tmp/kpf-rc/preflight.log',
    ...over,
  };
}

const macos = () => record([leg('kin-macos-aarch64', '1'.repeat(64))], { run: '20260902T200001Z', host: 'Darwin' });
const arm = () => record([leg('kin-linux-aarch64', '2'.repeat(64))], { run: '20260902T200002Z', host: 'Linux aarch64' });
const x86 = () => record([leg('kin-linux-x86_64', '3'.repeat(64))], { run: '20260902T200003Z', host: 'Linux x86_64' });

const entries = (...records) => records.map((entry, index) => ({ where: `record ${index}`, record: entry }));

test('three passing leg records merge into one record the mint accepts', () => {
  const { merged, archives } = mergeRecords(entries(macos(), arm(), x86()), SHA);
  assert.equal(merged.schema, PREFLIGHT_SCHEMA);
  assert.equal(merged.verdict, 'PASS');
  assert.equal(merged.lane, HOSTED_LANE);
  assert.equal(merged.citable, false);
  assert.equal(merged.allow_dirty, false);
  assert.equal(merged.cpu_embed, true);
  assert.deepEqual(merged.legs.map((entry) => entry.target), ['kin-linux-aarch64', 'kin-linux-x86_64', 'kin-macos-aarch64']);
  assert.deepEqual(archives, ['2'.repeat(64), '3'.repeat(64), '1'.repeat(64)]);
  // The gate that reads the published record agrees with the one the merge ran.
  assert.deepEqual(judgePreflight(merged, SHA).archives, archives);
  assert.equal(merged.merged_from.length, 3);
});

test('the merge is deterministic whatever order the records arrive in', () => {
  const forward = JSON.stringify(mergeRecords(entries(macos(), arm(), x86()), SHA).merged);
  const backward = JSON.stringify(mergeRecords(entries(x86(), arm(), macos()), SHA).merged);
  assert.equal(forward, backward);
});

test('a leg record about another commit is refused, and the refusal names the file', () => {
  const foreign = macos();
  foreign.legs[0].result.expected.commit = OTHER_SHA;
  const bad = { where: 'kin-release-preflight-kin-macos-aarch64/preflight.json', record: foreign };
  const good = { where: 'kin-release-preflight-kin-linux-aarch64/preflight.json', record: arm() };
  assert.throws(() => mergeRecords([bad, good], SHA), /judged commit b{40}, not a{40}/);
  // The mint's gate re-checks the commit on the merged record, so removing the
  // per-record check still refuses. What only the per-record check can give is
  // WHICH artifact was wrong: three legs arrive from three runners and a
  // refusal naming only the leg sends a captain to read all three. Assert the
  // source file is in the message, which is the half the gate cannot supply.
  assert.throws(
    () => mergeRecords([bad, good], SHA),
    /kin-release-preflight-kin-macos-aarch64\/preflight\.json/,
  );
});

test('a failing leg record cannot hide behind passing ones', () => {
  const failing = arm();
  failing.verdict = 'FAIL';
  assert.throws(() => mergeRecords(entries(macos(), failing, x86()), SHA), /record 1 records verdict FAIL/);
  const failingLeg = arm();
  failingLeg.legs[0].verdict = 'FAIL';
  assert.throws(() => mergeRecords(entries(macos(), failingLeg), SHA), /leg "host \(linux-aarch64, archive\)" records verdict FAIL/);
});

test('an unreadable verdict is refused, never read as PASS', () => {
  const unreadable = x86();
  unreadable.verdict = 'UNREADABLE';
  assert.throws(() => mergeRecords(entries(unreadable), SHA), /records verdict UNREADABLE, not PASS/);
});

test('allow_dirty, a wrong schema and an empty leg list refuse', () => {
  const dirty = macos();
  dirty.allow_dirty = true;
  assert.throws(() => mergeRecords(entries(dirty), SHA), /allow_dirty/);
  const schema = macos();
  schema.schema = 'kin.release-preflight.v0';
  assert.throws(() => mergeRecords(entries(schema), SHA), /carries schema "kin.release-preflight.v0"/);
  const empty = macos();
  empty.legs = [];
  assert.throws(() => mergeRecords(entries(empty), SHA), /records no legs/);
});

test('two records judging the same archive target are ambiguous', () => {
  assert.throws(() => mergeRecords(entries(macos(), macos()), SHA), /two leg records judged kin-macos-aarch64/);
});

test('one archive sha256 claimed by two targets is refused', () => {
  const twin = arm();
  twin.legs[0].result.archive.sha256 = '1'.repeat(64);
  // Named in the merge's own deterministic order, not the order they arrived.
  assert.throws(() => mergeRecords(entries(macos(), twin), SHA), /claimed by kin-linux-aarch64 and kin-macos-aarch64/);
  assert.throws(() => mergeRecords(entries(twin, macos()), SHA), /claimed by kin-linux-aarch64 and kin-macos-aarch64/);
});

test('records from different tooling do not merge into one answer', () => {
  const other = arm();
  other.tooling = { ...other.tooling, validator_ported_from_sha256: 'f'.repeat(64) };
  assert.throws(() => mergeRecords(entries(macos(), other), SHA), /different tooling/);
});

test('a leg without an archive sha256 is refused by the gate inside the merge', () => {
  const bare = macos();
  delete bare.legs[0].result.archive;
  assert.throws(() => mergeRecords(entries(bare), SHA), /records no archive sha256/);
});

test('cpu_embed is true only when every leg embedded on the CPU', () => {
  const metal = macos();
  metal.cpu_embed = false;
  assert.equal(mergeRecords(entries(metal, arm()), SHA).merged.cpu_embed, false);
});

test('admitLegRecord names the record it refuses', () => {
  assert.throws(() => admitLegRecord(null, SHA, 'leg-a.json'), /leg-a.json is not a preflight record object/);
  assert.throws(() => admitLegRecord([], SHA, 'leg-a.json'), /leg-a.json is not a preflight record object/);
});

test('parseArgs refuses a loose sha and a missing output', () => {
  assert.throws(() => {
    const exit = process.exit;
    process.exit = (code) => { throw new Error(`exit ${code}`); };
    try {
      parseArgs(['--candidate', 'abc', '--out', 'x', 'a.json']);
    } finally {
      process.exit = exit;
    }
  }, /exit 2/);
});

test('the command line merges files, writes the record and exits 1 on a refusal', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kin-merge-'));
  const files = [macos(), arm(), x86()].map((entry, index) => {
    const file = path.join(dir, `leg-${index}.json`);
    fs.writeFileSync(file, JSON.stringify(entry));
    return file;
  });
  const out = path.join(dir, 'preflight.json');
  const stdout = execFileSync(process.execPath, [SCRIPT, '--candidate', SHA, '--out', out, ...files], { encoding: 'utf8' });
  assert.match(stdout, /merged 3 leg\(s\)/);
  const written = JSON.parse(fs.readFileSync(out, 'utf8'));
  assert.equal(written.verdict, 'PASS');
  assert.equal(written.legs.length, 3);
  // Identical bytes on a second run, which is what lets a re-publish be a no-op.
  const again = path.join(dir, 'again.json');
  execFileSync(process.execPath, [SCRIPT, '--candidate', SHA, '--out', again, ...files.slice().reverse()]);
  assert.equal(fs.readFileSync(again, 'utf8'), fs.readFileSync(out, 'utf8'));

  let failed = null;
  try {
    execFileSync(process.execPath, [SCRIPT, '--candidate', OTHER_SHA, '--out', path.join(dir, 'no.json'), ...files], { encoding: 'utf8', stdio: 'pipe' });
  } catch (error) {
    failed = error;
  }
  assert.ok(failed, 'a merge for the wrong candidate must fail');
  assert.equal(failed.status, 1);
  assert.match(String(failed.stderr), /judged commit a{40}, not b{40}/);
  assert.equal(fs.existsSync(path.join(dir, 'no.json')), false);

  const programmatic = main(['--candidate', SHA, '--out', path.join(dir, 'main.json'), ...files], { log: () => {} });
  assert.equal(programmatic.legs.length, 3);
});
