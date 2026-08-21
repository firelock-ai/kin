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
  BEGIN_MARKER,
  END_MARKER,
  mergeBody,
  renderRegion,
} from './release-train-body.mjs';

const SCRIPT = fileURLToPath(new URL('./release-train-body.mjs', import.meta.url));

// The exact sentence the train writes, so a fixture cannot drift into proving
// something about a sentence the workflow never sends.
const GENERIC =
  'Automated, coalescing Kin release PR. It carries the lockstep Cargo/npm version, exact internal path pin, workspace-only lockfile movement, and generated notes for every reviewed first-parent change since the prior stable tag.';

// The two sections tonight's release doctrine requires, shortened but shaped
// like the ones a captain wrote on kin#1001.
const ABOVE = '## What this release carries\n\nSeven reviewed changes landed on main since v0.5.45.';
const BELOW =
  '## What this release did not test\n\nThe stranger ran the greenfield arm only on these bytes.\n\n## Known limitation\n\nReceiver recall over two hops is incomplete at history depth.';

function region(text = GENERIC) {
  return `${BEGIN_MARKER}\n${text}\n${END_MARKER}`;
}

test('a body with no region gets one at the top and keeps every operator byte', () => {
  const current = `${ABOVE}\n\n${BELOW}`;
  const result = mergeBody({ current, region: GENERIC });
  assert.equal(result.changed, true);
  assert.equal(result.status, 'region-added');
  assert.equal(result.body, `${region()}\n\n${ABOVE}\n\n${BELOW}`);
  assert.ok(result.body.endsWith(`${ABOVE}\n\n${BELOW}`));
});

test('operator text above and below the region survives byte for byte', () => {
  const current = `${ABOVE}\n\n${region('stale generated text')}\n\n${BELOW}`;
  const result = mergeBody({ current, region: GENERIC });
  assert.equal(result.changed, true);
  assert.equal(result.status, 'region-replaced');
  assert.equal(result.body, `${ABOVE}\n\n${region()}\n\n${BELOW}`);
  // The claim is about bytes, so state it about bytes: everything outside the
  // region is unchanged, not merely present.
  const [beforeOld, afterOld] = [
    current.slice(0, current.indexOf(BEGIN_MARKER)),
    current.slice(current.indexOf(END_MARKER) + END_MARKER.length),
  ];
  const [beforeNew, afterNew] = [
    result.body.slice(0, result.body.indexOf(BEGIN_MARKER)),
    result.body.slice(result.body.indexOf(END_MARKER) + END_MARKER.length),
  ];
  assert.equal(beforeNew, beforeOld);
  assert.equal(afterNew, afterOld);
});

test('a body that is only the region and already current is left alone', () => {
  const current = region();
  const result = mergeBody({ current, region: GENERIC });
  assert.equal(result.changed, false);
  assert.equal(result.status, 'region-replaced');
  assert.equal(result.body, current);
});

test('a region-only body still updates when the generated text drifts', () => {
  const current = region('older generated text');
  const result = mergeBody({ current, region: GENERIC });
  assert.equal(result.changed, true);
  assert.equal(result.body, region());
});

test('the train-authored opening line is adopted as the region rather than duplicated', () => {
  const current = `${GENERIC}\n\n${ABOVE}`;
  const result = mergeBody({ current, region: GENERIC });
  assert.equal(result.status, 'legacy-region-adopted');
  assert.equal(result.body, `${region()}\n\n${ABOVE}`);
  assert.equal(result.body.split(GENERIC).length - 1, 1);
});

test('an opening line that only resembles the train sentence is operator text and stays put', () => {
  const nearMiss = `${GENERIC.slice(0, -1)}!`;
  const current = `${nearMiss}\n\n${ABOVE}`;
  const result = mergeBody({ current, region: GENERIC });
  assert.equal(result.status, 'region-added');
  assert.equal(result.body, `${region()}\n\n${nearMiss}\n\n${ABOVE}`);
  assert.ok(result.body.includes(nearMiss));
});

test('an empty body becomes the region alone, which is the create path', () => {
  const result = mergeBody({ current: '', region: GENERIC });
  assert.equal(result.changed, true);
  assert.equal(result.body, region());
});

test('a second pass over a merged body changes nothing', () => {
  const once = mergeBody({ current: `${ABOVE}\n\n${BELOW}`, region: GENERIC });
  const twice = mergeBody({ current: once.body, region: GENERIC });
  assert.equal(twice.changed, false);
  assert.equal(twice.body, once.body);
});

test('web-edited CRLF operator text keeps its line endings', () => {
  const current = `## Known limitation\r\n\r\nReceiver recall is incomplete.\r\n`;
  const result = mergeBody({ current, region: GENERIC });
  assert.ok(result.body.endsWith(current));
  assert.equal(result.body.includes('\r\n'), true);
});

test('a half-marked body is refused rather than guessed at', () => {
  for (const [label, current] of [
    ['begin with no end', `${BEGIN_MARKER}\n${GENERIC}\n\n${ABOVE}`],
    ['end with no begin', `${GENERIC}\n${END_MARKER}\n\n${ABOVE}`],
    ['markers in the wrong order', `${END_MARKER}\n${GENERIC}\n${BEGIN_MARKER}`],
    ['a repeated region', `${region()}\n\n${ABOVE}\n\n${region()}`],
  ]) {
    const result = mergeBody({ current, region: GENERIC });
    assert.equal(result.status, 'unmergeable', label);
    assert.equal(result.changed, false, label);
    assert.equal(result.body, null, label);
    assert.match(result.detail, /marker/, label);
  }
});

test('an empty region is refused, because a body cannot be reconciled against nothing', () => {
  assert.throws(() => mergeBody({ current: ABOVE, region: '   \n' }), /non-empty/);
});

test('renderRegion trims its own whitespace and never nests markers', () => {
  assert.equal(renderRegion(`\n\n${GENERIC}\n\n`), region());
});

test('the command line writes the merged body and reports what it did', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'release-train-body-'));
  const regionPath = path.join(dir, 'region.md');
  const currentPath = path.join(dir, 'current.json');
  const outPath = path.join(dir, 'next.md');
  const current = `${ABOVE}\n\n${region('older generated text')}\n\n${BELOW}`;
  fs.writeFileSync(regionPath, `${GENERIC}\n`);
  fs.writeFileSync(currentPath, JSON.stringify({ body: current }));

  const stdout = execFileSync(process.execPath, [
    SCRIPT,
    '--region',
    regionPath,
    '--current-json',
    currentPath,
    '--out',
    outPath,
  ]);
  const result = JSON.parse(stdout.toString());
  assert.equal(result.changed, true);
  assert.equal(result.status, 'region-replaced');
  assert.equal(fs.readFileSync(outPath, 'utf8'), `${ABOVE}\n\n${region()}\n\n${BELOW}`);

  // No --current-json is the create path, and it must produce the region alone.
  const createOut = path.join(dir, 'create.md');
  const created = JSON.parse(
    execFileSync(process.execPath, [SCRIPT, '--region', regionPath, '--out', createOut]).toString(),
  );
  assert.equal(created.changed, true);
  assert.equal(fs.readFileSync(createOut, 'utf8'), region());
});

test('the script still runs when its path reaches node through a symlink', () => {
  // Every macOS $TMPDIR is a symlink, and the release train copies this file
  // into $RUNNER_TEMP before running it. Comparing import.meta.url against a
  // raw argv path made the program body never execute: no output, exit 0, and
  // a caller reading an empty merge result as a failed jq parse.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'release-train-body-link-'));
  const linked = path.join(dir, 'release-train-body.mjs');
  fs.symlinkSync(SCRIPT, linked);
  const regionPath = path.join(dir, 'region.md');
  const outPath = path.join(dir, 'next.md');
  fs.writeFileSync(regionPath, GENERIC);
  const stdout = execFileSync(process.execPath, [
    linked,
    '--region',
    regionPath,
    '--out',
    outPath,
  ]).toString();
  assert.notEqual(stdout.trim(), '');
  assert.equal(JSON.parse(stdout).changed, true);
  assert.equal(fs.readFileSync(outPath, 'utf8'), region());
});

test('a pull-request payload with no body string fails loud rather than blanking the body', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'release-train-body-'));
  const regionPath = path.join(dir, 'region.md');
  const currentPath = path.join(dir, 'current.json');
  fs.writeFileSync(regionPath, GENERIC);
  fs.writeFileSync(currentPath, JSON.stringify({}));
  assert.throws(
    () =>
      execFileSync(process.execPath, [
        SCRIPT,
        '--region',
        regionPath,
        '--current-json',
        currentPath,
        '--out',
        path.join(dir, 'next.md'),
      ]),
    /carries no body string/,
  );
});
