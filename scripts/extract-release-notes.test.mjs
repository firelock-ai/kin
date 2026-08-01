// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import {
  abandonedAncestors,
  composeNotes,
  extractSection,
  loadAbandonments,
} from './extract-release-notes.mjs';

const SCRIPT = fileURLToPath(new URL('./extract-release-notes.mjs', import.meta.url));

const CHANGELOG = [
  '# Changelog',
  '',
  '## [Unreleased]',
  '',
  '- nothing yet',
  '',
  '## [0.4.5] - 2026-08-01',
  '',
  '- the published one',
  '',
  '## [0.4.4] - 2026-07-31',
  '',
  '- the abandoned one',
  '',
  '## [0.3.6] - 2026-07-26',
  '',
  '- an older release',
  '',
].join('\n');

function record(entries) {
  return JSON.stringify({ schema_version: 1, abandoned: entries });
}

const CHAIN = record([
  { tag: 'v0.4.3', superseded_by: 'v0.4.4' },
  { tag: 'v0.4.4', superseded_by: 'v0.4.5' },
]);

function runScript(args, { cwd } = {}) {
  return spawnSync(process.execPath, [SCRIPT, ...args], { cwd, encoding: 'utf8' });
}

function withTempDir(body) {
  const dir = mkdtempSync(join(tmpdir(), 'extract-release-notes-'));
  try {
    return body(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test('a version with no abandoned predecessors emits exactly its own section', () => {
  const composed = composeNotes(CHANGELOG, '0.3.6', new Map());

  assert.equal(composed.notes, extractSection(CHANGELOG, '0.3.6'));
  assert.deepEqual(composed.rolledUp, []);
  assert.deepEqual(composed.missing, []);
});

test('a version carries forward the section of the tag it supersedes', () => {
  const composed = composeNotes(CHANGELOG, '0.4.5', loadAbandonments(CHAIN));

  assert.deepEqual(composed.rolledUp, ['v0.4.4', 'v0.4.3']);
  assert.match(composed.notes, /## \[0\.4\.5\]/);
  assert.match(composed.notes, /the published one/);
  assert.match(composed.notes, /## \[0\.4\.4\]/);
  assert.match(composed.notes, /the abandoned one/);
  // The roll-up stops at the abandoned chain and does not sweep in the last
  // tag that actually published.
  assert.doesNotMatch(composed.notes, /## \[0\.3\.6\]/);
  assert.doesNotMatch(composed.notes, /an older release/);
});

test('sections are ordered newest first and separated by a blank line', () => {
  const composed = composeNotes(CHANGELOG, '0.4.5', loadAbandonments(CHAIN));

  assert.ok(
    composed.notes.indexOf('## [0.4.5]') < composed.notes.indexOf('## [0.4.4]'),
    'the version being published must lead its superseded sections',
  );
  assert.match(composed.notes, /- the published one\n\n## Carried forward/);
  assert.match(composed.notes, /collected here\.\n\n## \[0\.4\.4\]/);
});

test('carried-forward sections say why a superseded heading is in these notes', () => {
  const composed = composeNotes(CHANGELOG, '0.4.5', loadAbandonments(CHAIN));

  // A bare `## [0.4.4]` under the 0.4.5 release reads as though 0.4.4 shipped.
  // The whole reason its content is here is that it did not.
  assert.match(composed.notes, /## Carried forward from v0\.4\.4/);
  assert.match(composed.notes, /superseded before its release completed/);
  // Number must agree across the whole sentence, not just its opening clause.
  assert.match(composed.notes, /the notes recorded for it are collected here/);
  assert.doesNotMatch(composed.notes, /for them are collected/);
  // v0.4.5 carries a live public prerelease with assets, so the notice must not
  // claim anything was never published or is shipping for the first time.
  assert.doesNotMatch(composed.notes, /never published|for the first time/);
  assert.deepEqual(composed.carried, ['v0.4.4']);
});

test('the notice names every tag actually carried, not every tag walked', () => {
  // v0.4.3 is in the chain but has no section, so it contributes nothing and
  // must not be announced as carried forward.
  const composed = composeNotes(CHANGELOG, '0.4.5', loadAbandonments(CHAIN));

  assert.deepEqual(composed.rolledUp, ['v0.4.4', 'v0.4.3']);
  assert.deepEqual(composed.carried, ['v0.4.4']);
  assert.doesNotMatch(composed.notes, /Carried forward from v0\.4\.4, v0\.4\.3/);
});

test('no carried-forward notice appears when nothing was carried', () => {
  const composed = composeNotes(CHANGELOG, '0.3.6', new Map());

  assert.doesNotMatch(composed.notes, /Carried forward/);
});

test('the notice reads as plural only when several tags are carried', () => {
  const changelog = [
    '# Changelog',
    '',
    '## [2.0.2] - 2026-08-01',
    '',
    '- the published one',
    '',
    '## [2.0.1] - 2026-07-31',
    '',
    '- one abandoned',
    '',
    '## [2.0.0] - 2026-07-30',
    '',
    '- another abandoned',
    '',
  ].join('\n');
  const forked = loadAbandonments(
    record([
      { tag: 'v2.0.0', superseded_by: 'v2.0.2' },
      { tag: 'v2.0.1', superseded_by: 'v2.0.2' },
    ]),
  );

  const composed = composeNotes(changelog, '2.0.2', forked);

  assert.deepEqual(composed.carried, ['v2.0.1', 'v2.0.0']);
  assert.match(composed.notes, /## Carried forward from v2\.0\.1, v2\.0\.0/);
  assert.match(composed.notes, /tags were superseded before their releases completed/);
  assert.doesNotMatch(composed.notes, /never published|for the first time/);
});

test('an abandoned predecessor with no changelog section is reported, not invented', () => {
  const composed = composeNotes(CHANGELOG, '0.4.5', loadAbandonments(CHAIN));

  // v0.4.3 is abandoned and has no section of its own. This is the real shape
  // of the record in this repository.
  assert.deepEqual(composed.missing, ['0.4.3']);
});

test('a missing section for the version itself still carries its superseded sections', () => {
  const changelog = ['# Changelog', '', '## [0.4.4] - 2026-07-31', '', '- the abandoned one', ''].join('\n');
  const composed = composeNotes(changelog, '0.4.5', loadAbandonments(CHAIN));

  assert.match(composed.notes, /the abandoned one/);
  assert.ok(composed.missing.includes('0.4.5'));
});

test('nothing found at all reports no notes rather than an empty string', () => {
  const composed = composeNotes('# Changelog\n', '0.4.5', loadAbandonments(CHAIN));

  assert.equal(composed.notes, null);
});

test('the chain is walked transitively rather than one hop', () => {
  const deep = loadAbandonments(
    record([
      { tag: 'v1.0.0', superseded_by: 'v1.0.1' },
      { tag: 'v1.0.1', superseded_by: 'v1.0.2' },
      { tag: 'v1.0.2', superseded_by: 'v1.0.3' },
    ]),
  );

  assert.deepEqual(abandonedAncestors(deep, '1.0.3'), ['v1.0.2', 'v1.0.1', 'v1.0.0']);
});

test('an unrelated abandoned tag is not rolled into a version it never preceded', () => {
  const ancestors = abandonedAncestors(loadAbandonments(CHAIN), '0.9.0');

  assert.deepEqual(ancestors, []);
});

test('several abandoned tags naming one successor all contribute', () => {
  const forked = loadAbandonments(
    record([
      { tag: 'v2.0.0', superseded_by: 'v2.0.2' },
      { tag: 'v2.0.1', superseded_by: 'v2.0.2' },
    ]),
  );

  assert.deepEqual(abandonedAncestors(forked, '2.0.2'), ['v2.0.1', 'v2.0.0']);
});

test('a record pointing in a circle terminates instead of hanging', () => {
  const circular = new Map([
    ['v3.0.0', 'v3.0.1'],
    ['v3.0.1', 'v3.0.0'],
  ]);

  const ancestors = abandonedAncestors(circular, '3.0.1');

  assert.deepEqual(ancestors, ['v3.0.0']);
});

test('a malformed record is refused rather than resolving to an empty chain', () => {
  assert.throws(() => loadAbandonments('{'), /not valid JSON/);
  assert.throws(() => loadAbandonments('[]'), /must be a JSON object/);
  assert.throws(() => loadAbandonments(JSON.stringify({ abandoned: [] })), /schema_version 1/);
  assert.throws(() => loadAbandonments(JSON.stringify({ schema_version: 1 })), /'abandoned' array/);
  assert.throws(() => loadAbandonments(record([{ tag: '0.4.4', superseded_by: 'v0.4.5' }])), /not a vX\.Y\.Z release tag/);
  assert.throws(() => loadAbandonments(record([{ tag: 'v0.4.4', superseded_by: 'latest' }])), /successor that is not/);
  assert.throws(() => loadAbandonments(record([{ tag: 'v0.4.4', superseded_by: 'v0.4.4' }])), /cannot supersede itself/);
  assert.throws(
    () => loadAbandonments(record([{ tag: 'v0.4.4', superseded_by: 'v0.4.5' }, { tag: 'v0.4.4', superseded_by: 'v0.4.6' }])),
    /abandoned more than once/,
  );
});

test('the repository record parses and chains v0.4.3 through v0.4.4', () => {
  const raw = readFileSync(new URL('./abandoned-release-tags.json', import.meta.url), 'utf8');
  const abandonments = loadAbandonments(raw);

  assert.deepEqual(abandonedAncestors(abandonments, '0.4.5'), ['v0.4.4', 'v0.4.3']);
});

test('end to end, the script rolls the superseded section into the output file', () => {
  withTempDir((dir) => {
    const input = join(dir, 'CHANGELOG.md');
    const output = join(dir, 'release-notes.md');
    const abandoned = join(dir, 'abandoned.json');
    writeFileSync(input, CHANGELOG);
    writeFileSync(abandoned, CHAIN);

    const result = runScript([
      '--version', '0.4.5',
      '--input', input,
      '--output', output,
      '--abandoned', abandoned,
    ]);

    assert.equal(result.status, 0, result.stderr);
    const notes = readFileSync(output, 'utf8');
    assert.match(notes, /## \[0\.4\.5\]/);
    assert.match(notes, /## \[0\.4\.4\]/);
    assert.match(result.stderr, /rolling up sections for abandoned v0\.4\.4, v0\.4\.3/);
  });
});

test('end to end, an empty record reproduces the single-section output byte for byte', () => {
  withTempDir((dir) => {
    const input = join(dir, 'CHANGELOG.md');
    const withRecord = join(dir, 'with.md');
    const withoutRecord = join(dir, 'without.md');
    const empty = join(dir, 'empty.json');
    writeFileSync(input, CHANGELOG);
    writeFileSync(empty, record([]));

    const rolled = runScript(['--version', '0.4.5', '--input', input, '--output', withRecord, '--abandoned', empty]);
    assert.equal(rolled.status, 0, rolled.stderr);

    writeFileSync(withoutRecord, extractSection(CHANGELOG, '0.4.5'));

    assert.equal(readFileSync(withRecord, 'utf8'), readFileSync(withoutRecord, 'utf8'));
  });
});

test('end to end, an explicitly named record that is absent fails loud', () => {
  withTempDir((dir) => {
    const input = join(dir, 'CHANGELOG.md');
    writeFileSync(input, CHANGELOG);

    const result = runScript([
      '--version', '0.4.5',
      '--input', input,
      '--output', join(dir, 'out.md'),
      '--abandoned', join(dir, 'nope.json'),
    ]);

    assert.equal(result.status, 1);
    assert.match(result.stderr, /ENOENT/);
  });
});

test('end to end, a malformed record fails the run instead of publishing thin notes', () => {
  withTempDir((dir) => {
    const input = join(dir, 'CHANGELOG.md');
    const abandoned = join(dir, 'abandoned.json');
    writeFileSync(input, CHANGELOG);
    writeFileSync(abandoned, '{ "schema_version": 1, "abandoned": [ { "tag": "nope" } ] }');

    const result = runScript([
      '--version', '0.4.5',
      '--input', input,
      '--output', join(dir, 'out.md'),
      '--abandoned', abandoned,
    ]);

    assert.equal(result.status, 1);
    assert.match(result.stderr, /not a vX\.Y\.Z release tag/);
  });
});

test('end to end, the script still writes its notes when invoked through a symlink', () => {
  withTempDir((dir) => {
    // `import.meta.url` is a realpath. An entry-point guard that does not
    // resolve the same way compares false through a symlink, main() never
    // runs, and the process exits 0 having written nothing. The release rail
    // would publish empty notes and report success.
    const linked = join(dir, 'extract-release-notes.mjs');
    symlinkSync(SCRIPT, linked);

    const input = join(dir, 'CHANGELOG.md');
    const output = join(dir, 'release-notes.md');
    const abandoned = join(dir, 'abandoned.json');
    writeFileSync(input, CHANGELOG);
    writeFileSync(abandoned, CHAIN);

    const result = spawnSync(
      process.execPath,
      [linked, '--version', '0.4.5', '--input', input, '--output', output, '--abandoned', abandoned],
      { encoding: 'utf8' },
    );

    assert.equal(result.status, 0, result.stderr);
    const notes = readFileSync(output, 'utf8');
    assert.match(notes, /## \[0\.4\.5\]/);
    assert.match(notes, /## \[0\.4\.4\]/);
  });
});

test('end to end, a missing changelog still falls back to auto-generated notes', () => {
  withTempDir((dir) => {
    const output = join(dir, 'release-notes.md');

    const result = runScript([
      '--version', '0.4.5',
      '--input', join(dir, 'absent.md'),
      '--output', output,
    ]);

    assert.equal(result.status, 0, result.stderr);
    assert.equal(readFileSync(output, 'utf8'), '');
    assert.match(result.stderr, /changelog not found/);
  });
});
